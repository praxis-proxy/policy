// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// 5-phase plugin execution engine.
//
// Dispatches plugins in strict phase order:
//   SEQUENTIAL → TRANSFORM → AUDIT → CONCURRENT → FIRE_AND_FORGET
//
// Each phase has different authority (block/modify) and scheduling
// (serial/parallel/background). The executor reads all scheduling
// decisions from PluginRef.trusted_config — never from the plugin.
//
// Extensions are passed separately from the payload and capability-
// filtered per plugin before dispatch. Extension modifications are
// merged back independently from payload modifications.
//
// Error handling respects the plugin's on_error setting:
//   - Fail: propagate error, halt pipeline
//   - Ignore: log error, continue pipeline
//   - Disable: log error, mark plugin disabled, continue
//
// A plugin panic is contained in every awaited phase (serial, transform,
// audit, concurrent): it is caught on the spawned task and routed through
// on_error, the same way error and timeout already were. Fire-and-forget
// panics are contained by spawn; they cannot change a verdict already
// returned.
//
// Containment costs a payload clone per plugin per hook. Audit used to
// take `&payload` and spawn nothing; it is no longer free. The spawn is
// load-bearing: it carries the timeout and abort-on-drop cancellation
// as well as the panic containment.

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::timeout;
use tokio_util::task::AbortOnDropHandle;
use tracing::{error, warn};

use crate::audit::AttachedSink;
use crate::context::{PluginContext, PluginContextTable};
use crate::decision::{DecisionLog, PluginAction, Verdict};
use crate::effect::{DurableEffectLog, EffectLogSlot, EffectSink, EffectStream};
use crate::error::PluginError;
use crate::extensions::filter_extensions;
use crate::hooks::payload::{Extensions, PluginPayload, WriteToken};
use crate::plugin::OnError;
use crate::registry::{AnyHookHandler, HookEntry, group_by_mode};

/// Configuration for the executor.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum execution time per plugin in seconds.
    pub timeout_seconds: u64,

    /// Whether to halt on the first deny in concurrent mode.
    pub short_circuit_on_deny: bool,

    /// Hash the payload at pipeline entry for audit content provenance.
    /// Off by default, since hashing sits on the request path.
    pub capture_content_provenance: bool,

    /// Prefix for the audit stream ids, so records from one process are
    /// attributable to it. `Some("gw-1")` gives `"gw-1:decision"` and
    /// `"gw-1:effect"`; `None` leaves the bare labels.
    ///
    /// The type suffix always survives, so each stream stays independently
    /// gap-free and its completeness claim holds. A consumer recovering the
    /// type must split on the last colon, since a namespace may contain one.
    pub audit_stream_namespace: Option<String>,

    /// Override the audit epoch, the executor's generation identifier.
    ///
    /// `None` uses boot time, which advances on its own and is correct with no
    /// configuration. A host that overrides it owns the invariant that the
    /// value strictly increases on every load, including reloads: the stream
    /// counters restart with each executor, so a repeated epoch collides with
    /// the previous generation's records and a verifier can no longer tell a
    /// reset from a loss.
    pub audit_epoch: Option<u64>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            short_circuit_on_deny: true,
            capture_content_provenance: false,
            audit_stream_namespace: None,
            audit_epoch: None,
        }
    }
}

/// Result of invoking a handler inside a spawned task so a panic cannot
/// unwind [`Executor::execute`].
enum ContainedOutcome {
    Success(Box<dyn Any + Send + Sync>, PluginContext),
    Error(Box<PluginError>, PluginContext),
    Timeout(PluginContext),
    Panic(String),
    /// `JoinHandle` produced no usable outcome. Treated as a deny in
    /// blocking phases rather than guessed as allow.
    Lost,
}

/// Timeout the invoke, and catch a panic, by running it on a task.
///
/// Serial and audit used to `.await` the handler inline. A panic then
/// left `on_error` unconsulted and skipped later audit plugins. Concurrent
/// already contained panics via `JoinError::is_panic`; this is the same
/// containment for the other awaited phases.
///
/// The payload is cloned into the task because `tokio::spawn` needs
/// `'static`. Concurrent already cloned; serial, transform, and audit
/// now match it. Audit used to take `&payload` and spawn nothing.
///
/// The join handle aborts on drop. If the request is cancelled (timeout,
/// disconnect, shutdown) the plugin task is cancelled instead of running
/// detached until its inner timeout fires.
async fn invoke_contained(
    handler: Arc<dyn AnyHookHandler>,
    payload: Box<dyn PluginPayload>,
    extensions: Extensions,
    mut ctx: PluginContext,
    timeout_dur: Duration,
) -> ContainedOutcome {
    let handle = AbortOnDropHandle::new(tokio::spawn(async move {
        let result = timeout(
            timeout_dur,
            handler.invoke(&*payload, &extensions, &mut ctx),
        )
        .await;
        (result, ctx)
    }));
    match handle.await {
        Ok((Ok(Ok(value)), ctx)) => ContainedOutcome::Success(value, ctx),
        Ok((Ok(Err(err)), ctx)) => ContainedOutcome::Error(err, ctx),
        Ok((Err(_), ctx)) => ContainedOutcome::Timeout(ctx),
        Err(join) => {
            if join.is_panic() {
                ContainedOutcome::Panic(join.to_string())
            } else {
                ContainedOutcome::Lost
            }
        },
    }
}

/// Aggregate result from a full hook invocation across all phases.
///
/// Wraps the final payload, extensions, any violation, and the
/// context table. Immutable by design — policy decisions cannot be
/// tampered with after the executor returns them.
///
/// The caller should pass `context_table` into the next hook
/// invocation to preserve per-plugin local state across hooks in
/// the same request lifecycle.
///
/// Background tasks are returned separately as [`BackgroundTasks`]
/// to keep the policy result immutable.
///
/// `#[non_exhaustive]`: this result type keeps gaining fields as the
/// engine grows, so it is sealed against external struct-literal
/// construction and exhaustive destructuring — hosts read it, they don't
/// build it. Construct via [`Self::allowed_with`] / [`Self::denied`] plus
/// the `with_*` builders. New fields can then be added without breaking
/// downstream readers.
#[derive(Debug)]
#[non_exhaustive]
pub struct PipelineResult {
    /// Whether the pipeline should continue processing.
    /// `false` means a plugin denied — the pipeline was halted.
    pub continue_processing: bool,

    /// The final payload after all modifications (type-erased).
    /// `None` if the pipeline was denied before any modifications.
    ///
    /// Note this is `Some` on **every** allowed pipeline, carrying the
    /// final payload whether or not a plugin touched it. To learn
    /// whether anything actually changed, read [`Self::payload_modified`]
    /// — do not compare payload contents, and do not read `is_some()` as
    /// "was modified".
    pub modified_payload: Option<Box<dyn PluginPayload>>,

    /// Whether any plugin's payload modification was accepted into
    /// `modified_payload` above.
    ///
    /// Set by the phases that can modify (sequential, transform) at the
    /// moment a handler's payload replaces the current one, so it
    /// reflects what the executor actually applied: a plugin lacking the
    /// modify capability, or one running in a read-only phase, does not
    /// set it.
    ///
    /// This exists because the fact is knowable only here. A caller
    /// comparing payloads afterwards cannot: the payload types are
    /// type-erased with no equality, and content-shaped comparisons
    /// (e.g. a message's text) are blind to whichever parts they don't
    /// read.
    pub payload_modified: bool,

    /// The final extensions the pipeline ran with.
    ///
    /// `Some` from both constructors whether or not a plugin changed anything:
    /// [`Self::allowed_with`] and [`Self::denied`] each carry the extensions
    /// they were handed, and `payload_modified` is what reports a change. So
    /// `None` reaches a consumer only from a result a host built itself, and
    /// means there is no engine state to read rather than that none changed.
    pub modified_extensions: Option<Extensions>,

    /// The violation that caused a deny, if any.
    pub violation: Option<crate::error::PluginViolation>,

    /// Errors from plugins that ran with `on_error: ignore` or
    /// `on_error: disable`. These plugins didn't halt the pipeline
    /// (their `on_error` policy said to continue), but the caller
    /// should still know the errors happened so it can log them in
    /// a structured way, retry the affected plugin, or alert.
    /// Empty when no plugin errored on a non-halt path.
    /// Fire-and-forget errors live in `BackgroundTasks` instead.
    pub errors: Vec<crate::error::PluginErrorRecord>,

    /// Optional metadata aggregated from plugins (telemetry, diagnostics).
    pub metadata: Option<serde_json::Value>,

    /// Plugin contexts indexed by plugin ID. Thread this into the
    /// next hook invocation to preserve per-plugin `local_state`.
    pub context_table: PluginContextTable,

    /// What each plugin did and how the pipeline ruled. Built by the
    /// executor and handed to audit sinks; never reaches plugins through
    /// `PluginContext`.
    pub decision_log: DecisionLog,
}

impl PipelineResult {
    /// Pipeline completed — all plugins allowed.
    pub fn allowed_with(
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: PluginContextTable,
    ) -> Self {
        Self {
            continue_processing: true,
            modified_payload: Some(payload),
            payload_modified: false,
            modified_extensions: Some(extensions),
            violation: None,
            errors: Vec::new(),
            metadata: None,
            context_table,
            decision_log: DecisionLog::new(),
        }
    }

    /// Record that a plugin's payload modification was applied. Chained
    /// off [`Self::allowed_with`] by the executor, mirroring
    /// [`Self::with_errors`].
    pub fn with_payload_modified(mut self, modified: bool) -> Self {
        self.payload_modified = modified;
        self
    }

    /// Pipeline was denied by a plugin.
    pub fn denied(
        violation: crate::error::PluginViolation,
        extensions: Extensions,
        context_table: PluginContextTable,
    ) -> Self {
        Self {
            continue_processing: false,
            modified_payload: None,
            payload_modified: false,
            modified_extensions: Some(extensions),
            violation: Some(violation),
            errors: Vec::new(),
            metadata: None,
            context_table,
            decision_log: DecisionLog::new(),
        }
    }

    /// Attach the executor's decision log to a constructed result.
    pub fn with_decision_log(mut self, decision_log: DecisionLog) -> Self {
        self.decision_log = decision_log;
        self
    }

    /// Replace the errors vec on a constructed `PipelineResult`. Used by
    /// the executor to attach errors collected from `on_error: ignore`
    /// / `on_error: disable` plugins.
    pub fn with_errors(mut self, errors: Vec<crate::error::PluginErrorRecord>) -> Self {
        self.errors = errors;
        self
    }

    /// Whether this result represents a denial.
    pub fn is_denied(&self) -> bool {
        !self.continue_processing
    }
}

/// Handles to fire-and-forget background tasks spawned by the executor.
///
/// Returned separately from [`PipelineResult`] so that the policy
/// result stays immutable. If not awaited, tasks complete on their
/// own in the background. Call `wait_for_background_tasks()` when you
/// need to ensure tasks have finished (tests, graceful shutdown,
/// audit flush).
pub struct BackgroundTasks {
    tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
}

impl BackgroundTasks {
    /// Create an empty set of background tasks.
    pub fn empty() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Create from a list of (`plugin_name`, handle) pairs.
    fn from_handles(tasks: Vec<(String, tokio::task::JoinHandle<()>)>) -> Self {
        Self { tasks }
    }

    /// Whether there are any background tasks.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Number of background tasks.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Wait for all fire-and-forget background tasks to complete.
    ///
    /// Returns a list of errors from any tasks that panicked.
    /// An empty list means all tasks completed successfully.
    ///
    /// Consumes `self` — each task handle can only be awaited once.
    ///
    /// If not called, background tasks still complete on their own.
    /// Use this for tests, graceful shutdown, or when you need to
    /// ensure audit/logging tasks have flushed before proceeding.
    pub async fn wait_for_background_tasks(self) -> Vec<crate::error::PluginError> {
        let mut errors = Vec::new();
        for (plugin_name, handle) in self.tasks {
            if let Err(e) = handle.await {
                errors.push(crate::error::PluginError::Execution {
                    plugin_name,
                    message: format!("background task panicked: {e}"),
                    source: None,
                    code: None,
                    details: std::collections::HashMap::new(),
                    proto_error_code: None,
                });
            }
        }
        errors
    }
}

impl fmt::Debug for BackgroundTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackgroundTasks")
            .field("count", &self.tasks.len())
            .finish()
    }
}

/// 5-phase plugin execution engine.
///
/// Dispatches hooks through the phase pipeline:
///
/// ```text
/// SEQUENTIAL → TRANSFORM → AUDIT → CONCURRENT → FIRE_AND_FORGET
/// ```
///
/// The executor's only state is its config and the attached audit sinks;
/// all per-request state comes from the arguments. One executor instance
/// can serve multiple concurrent hook invocations.
#[derive(Clone)]
pub struct Executor {
    config: ExecutorConfig,

    /// Observation-only sinks invoked at the verdict of every pipeline run.
    /// Set when the engine builds the runtime snapshot, empty otherwise.
    /// They receive the decision log but cannot influence the outcome.
    audit_handlers: Vec<AttachedSink>,

    /// Where an irreversible effect gets recorded. `None` when the operator
    /// configured neither a log nor a sink, in which case a plugin's effects
    /// run unrecorded and the slot costs no allocation per invocation.
    effect_sink: Option<Arc<EffectSink>>,

    /// Audit stream identity. `epoch` scopes the counters so a restart is
    /// distinguishable from records going missing. The counters are `Arc` so a
    /// copy-on-write snapshot mutation keeps writing to the same stream rather
    /// than restarting it.
    epoch: u64,
    decision_seq: Arc<AtomicU64>,
    effect_seq: Arc<AtomicU64>,
    emission_seq: Arc<AtomicU64>,
    stream_namespace: Option<String>,
}

/// Compose a stream id from an optional namespace and the per-type label.
fn compose_stream_id(namespace: Option<&str>, kind: &str) -> String {
    match namespace {
        Some(ns) => format!("{ns}:{kind}"),
        None => kind.to_owned(),
    }
}

impl Executor {
    /// Create a new executor with the given configuration.
    pub fn new(config: ExecutorConfig) -> Self {
        // Boot time in Unix nanoseconds unless a host supplies one. It needs
        // no persistence and a new executor always gets a larger value, which
        // is what lets a verifier tell a counter reset from a loss.
        let epoch = config.audit_epoch.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        });
        let stream_namespace = config.audit_stream_namespace.clone();
        Self {
            config,
            audit_handlers: Vec::new(),
            effect_sink: None,
            epoch,
            decision_seq: Arc::new(AtomicU64::new(0)),
            effect_seq: Arc::new(AtomicU64::new(0)),
            emission_seq: Arc::new(AtomicU64::new(0)),
            stream_namespace,
        }
    }

    /// This generation's audit epoch. The engine reads it across a reload to
    /// check the epoch actually increased.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Stamp this decision's stream identity and sequence numbers.
    ///
    /// A no-op when no sink is attached. The counters have to be dense over
    /// the records that were actually emitted, so burning one on a record
    /// nobody receives would show up downstream as a record that went missing.
    fn stamp_decision_stream(&self, decisions: &mut DecisionLog) {
        if self.audit_handlers.is_empty() {
            return;
        }
        decisions.set_stream(
            self.epoch,
            compose_stream_id(self.stream_namespace.as_deref(), "decision"),
            self.decision_seq.fetch_add(1, Ordering::Relaxed),
            self.emission_seq.fetch_add(1, Ordering::Relaxed),
        );
    }

    /// Install the durable log that irreversible effects are written to.
    ///
    /// Without one, effects still reach any audit sink but are not crash-safe:
    /// nothing survives a restart, so recovery has nothing to reconcile.
    #[must_use]
    pub fn with_effect_log(mut self, effect_log: Arc<dyn DurableEffectLog>) -> Self {
        self.rebuild_effect_sink(Some(effect_log));
        self
    }

    /// Install the durable effect log through a snapshot mutation, the
    /// engine's programmatic path. Mirrors [`Self::set_audit_handlers`].
    pub fn set_effect_log(&mut self, effect_log: Arc<dyn DurableEffectLog>) {
        self.rebuild_effect_sink(Some(effect_log));
    }

    /// The installed effect log, for the engine to run recovery at startup.
    pub fn effect_log(&self) -> Option<Arc<dyn DurableEffectLog>> {
        self.effect_sink.as_ref().and_then(|s| s.log())
    }

    /// Tell the audit sinks what a recovery sweep settled.
    ///
    /// Reconciliation is the only place an effect's terminal state is decided
    /// by something other than the plugin that caused it, and the record
    /// saying so is compacted away as soon as it is written. Emitting here is
    /// what makes the answer reach anyone: a mint that spent a restart
    /// unaccounted for becomes a mint someone can see was confirmed.
    ///
    /// Stamped from the live sink, so these carry this process's epoch and
    /// take their place in the current stream rather than reappearing under
    /// the sequence numbers of the run that crashed.
    ///
    /// There is no request behind a recovery sweep, so sinks see default
    /// extensions. The record is self-describing, which is what a reconciler
    /// works from too.
    pub(crate) async fn emit_reconciled(&self, resolved: Vec<crate::effect::EffectRecord>) {
        let Some(sink) = self.effect_sink.as_ref() else {
            return;
        };
        for record in resolved {
            sink.notify(record, &Extensions::default()).await;
        }
    }

    /// Rebuild the shared sink from the current log and audit handlers.
    ///
    /// The sink is a projection of both, so anything that changes either has
    /// to re-run this or plugins keep being handed the previous pairing.
    fn rebuild_effect_sink(&mut self, log: Option<Arc<dyn DurableEffectLog>>) {
        let sink = EffectSink::new(
            log,
            self.audit_handlers.clone(),
            EffectStream {
                epoch: self.epoch,
                stream_id: compose_stream_id(self.stream_namespace.as_deref(), "effect"),
                stream_seq: Arc::clone(&self.effect_seq),
                emission_seq: Arc::clone(&self.emission_seq),
                handler_timeout: Duration::from_secs(self.config.timeout_seconds),
            },
        );
        self.effect_sink = if sink.is_empty() {
            None
        } else {
            Some(Arc::new(sink))
        };
    }

    /// Attach observation-only audit sinks, invoked at the verdict of every
    /// pipeline run. Used by the engine when it builds the runtime snapshot.
    pub fn with_audit_handlers(mut self, audit_handlers: Vec<AttachedSink>) -> Self {
        self.audit_handlers = audit_handlers;
        let log = self.effect_log();
        self.rebuild_effect_sink(log);
        self
    }

    /// Replace the attached audit sinks. The engine calls this after a
    /// registry mutation so a sink registered programmatically is attached
    /// on the same terms as one that arrived through config.
    pub fn set_audit_handlers(&mut self, audit_handlers: Vec<AttachedSink>) {
        self.audit_handlers = audit_handlers;
        let log = self.effect_log();
        self.rebuild_effect_sink(log);
    }

    /// Seed a decision log for an invocation that resolved to zero plugins, so
    /// the audit stream carries one record per invocation rather than falling
    /// silent where nothing was configured.
    ///
    /// Returns an empty log when no sink is attached, so an unaudited host
    /// pays only a length check. The engine calls this at its zero-plugin
    /// short-circuits, which return before reaching `execute`, and at the
    /// route-resolution denial, which has no pipeline to build one.
    ///
    /// The verdict is not set here. Nothing between this and the emit can
    /// change what a zero-plugin invocation rules, but the contract is that
    /// only [`Self::emit_decision`] finalizes, so there is one place where a
    /// record's verdict is decided rather than two that have to agree.
    pub(crate) fn entry_decisions(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
    ) -> DecisionLog {
        let mut decisions = DecisionLog::new();
        self.capture_entry_provenance(&mut decisions, payload, extensions);
        decisions
    }

    /// Finalize a decision log with the verdict the caller is actually
    /// returning, stamp it into the audit stream, and hand it to every sink.
    ///
    /// This is the single emit point, and it belongs to the engine rather than
    /// to `execute`, because the verdict is not final until the engine's
    /// assertion contract has run. Emitting from inside `execute` recorded an
    /// allow that `apply_assertions` could still turn into a deny, and said
    /// nothing at all about a request denied before the pipeline started.
    ///
    /// A no-op when no sink is attached.
    pub(crate) async fn emit_decision(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &mut DecisionLog,
        verdict: Verdict,
    ) {
        if self.audit_handlers.is_empty() {
            return;
        }
        decisions.finalize(verdict);
        self.stamp_decision_stream(decisions);
        self.emit_audit(payload, extensions, decisions).await;
    }

    /// Record what this invocation started from: its place in the trace, the
    /// taint it arrived with, and optionally a hash of its content.
    ///
    /// The input side of a node's provenance has to be captured before any
    /// plugin runs, because a sink comparing it against the final state is
    /// what shows the pipeline's effect on the request.
    ///
    /// A no-op when no sink is attached, so provenance costs an unaudited host
    /// nothing.
    fn capture_entry_provenance(
        &self,
        decisions: &mut DecisionLog,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
    ) {
        // Nothing will read it, so do not build it. Deriving a span means two
        // fresh UUIDs and two allocations, which is not a price an unaudited
        // host should pay on every request. The steps and the verdict are
        // recorded either way, because the phases record them as they run.
        if self.audit_handlers.is_empty() {
            return;
        }
        let request = extensions.request.as_ref();
        decisions.set_span(crate::decision::Span::for_request(
            request.and_then(|r| r.trace_id.as_deref()),
            request.and_then(|r| r.span_id.as_deref()),
        ));
        if let Some(sec) = extensions.security.as_ref() {
            let mut labels: Vec<String> = sec.labels.iter().cloned().collect();
            // Sorted so two records of the same labels compare equal.
            labels.sort_unstable();
            decisions.set_input_labels(labels);
        }
        if self.config.capture_content_provenance {
            decisions.set_input_hash(
                payload
                    .audit_bytes()
                    .map(|b| crate::hooks::payload::content_hash(&b)),
            );
        }
    }

    /// Hand the finalized decision to every audit sink, once per pipeline run.
    async fn emit_audit(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    ) {
        use futures::FutureExt as _;
        use std::panic::AssertUnwindSafe;

        if self.audit_handlers.is_empty() {
            return;
        }

        // The verdict is already decided, so a sink must not be able to crash
        // or hang the request it is only observing. Each call is bounded by
        // the plugin timeout and its panics contained; a sink that fails is
        // logged and skipped. A lost audit record is a problem in itself, but
        // not one that justifies failing the request.
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
        for sink in &self.audit_handlers {
            // `extensions` here is the executor's working copy: the host's
            // transport is installed on it and the credential slots are
            // unfiltered, because each plugin that ran was filtered on the way
            // in and this is what they were filtered from. A sink is filtered
            // on the same terms, against its own declared capabilities, and
            // the filtered view's effect slot is detached so a sink cannot act
            // under the name of a plugin it is watching.
            let view = sink.view(extensions);
            let call =
                AssertUnwindSafe(sink.handler().handle(payload, &view, decisions)).catch_unwind();
            match timeout(timeout_dur, call).await {
                Ok(Ok(())) => {},
                Ok(Err(_panic)) => {
                    error!(
                        "audit sink '{}' panicked during emit, contained",
                        sink.name()
                    );
                },
                Err(_elapsed) => {
                    error!(
                        "audit sink '{}' exceeded {}s during emit, skipped",
                        sink.name(),
                        timeout_dur.as_secs()
                    );
                },
            }
        }
    }

    /// Execute a hook invocation through the 5-phase pipeline.
    ///
    /// # Arguments
    ///
    /// * `entries` — `HookEntries` for this hook, sorted by priority.
    /// * `payload` — The typed payload (type-erased as `Box<dyn PluginPayload>`).
    /// * `extensions` — The full extensions (filtered per plugin before dispatch).
    /// * `context_table` — Optional context table from a previous hook invocation.
    ///   If `None`, fresh contexts are created for each plugin.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `PipelineResult` — immutable policy result with payload,
    ///   extensions, violation, and context table. Its `decision_log` carries
    ///   what every phase recorded, finalized with the verdict the pipeline
    ///   reached.
    /// - `BackgroundTasks` — handles to fire-and-forget tasks. Call
    ///   `wait_for_background_tasks()` to await them, or drop to let
    ///   them complete in the background.
    ///
    /// Nothing is emitted to audit sinks here. The pipeline's verdict is not
    /// the caller's verdict yet — the engine's assertion contract runs after
    /// this returns and can still deny — so the log is built here and emitted
    /// by the engine once the verdict is settled. A host driving this directly
    /// rather than through `PolicyEngine` owns that emit.
    pub async fn execute(
        &self,
        entries: &[HookEntry],
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
        task_tracker: &tokio_util::task::TaskTracker,
    ) -> (PipelineResult, BackgroundTasks) {
        let (result, tasks, _refused) = self
            .execute_audited(entries, payload, extensions, context_table, task_tracker)
            .await;
        (result, tasks)
    }

    /// [`Self::execute`], plus the payload as it stood at the verdict when the
    /// pipeline denied.
    ///
    /// A denial carries no payload out — that is the contract, and a caller
    /// must not act on a message the pipeline refused. The audit emit is the
    /// exception that still needs it: a record of a denial that cannot say
    /// what was denied is most of the way to useless. So the payload comes
    /// back beside the result rather than inside it, and only the engine's
    /// emit sees it. `None` on an allow, where the result carries it already.
    pub(crate) async fn execute_audited(
        &self,
        entries: &[HookEntry],
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
        task_tracker: &tokio_util::task::TaskTracker,
    ) -> (
        PipelineResult,
        BackgroundTasks,
        Option<Box<dyn PluginPayload>>,
    ) {
        let mut ctx_table = context_table.unwrap_or_default();

        if entries.is_empty() {
            // A hook resolving to zero plugins is normal (nothing configured
            // for this entity). The engine short-circuits these before
            // reaching here; this covers a direct `execute(&[], ..)`.
            let mut decisions = self.entry_decisions(&*payload, &extensions);
            decisions.finalize(Verdict::Allow);
            return (
                PipelineResult::allowed_with(payload, extensions, ctx_table)
                    .with_decision_log(decisions),
                BackgroundTasks::empty(),
                None,
            );
        }

        // Group entries by mode (from trusted_config)
        let (sequential, transform, audit, concurrent, fire_and_forget) = group_by_mode(entries);

        let mut current_payload = payload;
        let mut current_extensions = extensions;
        // Accumulator for errors from `on_error: ignore` / `on_error:
        // disable` plugins across all phases. Surfaced to the caller
        // via `PipelineResult.errors` so swallowed failures stay
        // observable. Halt-condition errors (Fail, deny) skip this and
        // become the violation directly.
        let mut errors: Vec<crate::error::PluginErrorRecord> = Vec::new();
        // Sticky across both modifying phases: true once any handler's
        // payload has been accepted. Reported on the result so callers
        // read an exact signal instead of comparing payload contents.
        let mut payload_modified = false;
        // A later resolver may construct a fresh payload rather than clone the
        // previous one. Keep declines sticky independently of that payload.
        let mut credential_declined = current_payload
            .as_any()
            .downcast_ref::<crate::identity::IdentityPayload>()
            .is_some_and(crate::identity::IdentityPayload::credential_declined);

        // What each plugin did and how the pipeline ruled. Threaded through
        // the phases, finalized at each return point, and attached to the
        // result for audit sinks.
        let mut decisions = self.entry_decisions(&*current_payload, &current_extensions);

        if let Some(v) = self
            .run_serial_phase(
                &sequential,
                &mut current_payload,
                &mut current_extensions,
                &mut ctx_table,
                true, // can_block
                true, // can_modify
                "SEQUENTIAL",
                &mut errors,
                &mut decisions,
                &mut payload_modified,
                &mut credential_declined,
            )
            .await
        {
            decisions.finalize(Verdict::Deny(v.clone()));
            return (
                PipelineResult::denied(v, current_extensions, ctx_table)
                    .with_errors(errors)
                    .with_decision_log(decisions),
                BackgroundTasks::empty(),
                Some(current_payload),
            );
        }

        // Phase 2: TRANSFORM — serial, chained, can modify, cannot block.
        // can_block=false means denials are suppressed (returns None).
        self.run_serial_phase(
            &transform,
            &mut current_payload,
            &mut current_extensions,
            &mut ctx_table,
            false, // can_block
            true,  // can_modify
            "TRANSFORM",
            &mut errors,
            &mut decisions,
            &mut payload_modified,
            &mut credential_declined,
        )
        .await;

        self.run_ref_phase(
            &audit,
            &*current_payload,
            &current_extensions,
            &ctx_table,
            "AUDIT",
            &mut errors,
        )
        .await;

        if let Some(violation) = self
            .run_concurrent_phase(
                &concurrent,
                &*current_payload,
                &current_extensions,
                &ctx_table,
                &mut errors,
                &mut decisions,
            )
            .await
        {
            decisions.finalize(Verdict::Deny(violation.clone()));
            return (
                PipelineResult::denied(violation, current_extensions, ctx_table)
                    .with_errors(errors)
                    .with_decision_log(decisions),
                BackgroundTasks::empty(),
                Some(current_payload),
            );
        }

        // A credential resolver may decline a value so that another
        // population's resolver can inspect it. Once all resolvers have run,
        // an unmatched value cannot be treated as an authenticated request.
        if let Some(identity) = current_payload
            .as_any()
            .downcast_ref::<crate::identity::IdentityPayload>()
            && credential_declined
            && identity.subject.is_none()
            && identity.client.is_none()
            && identity.caller_workload.is_none()
        {
            let violation = crate::error::PluginViolation::new(
                "auth.unrecognized_credential",
                "no identity resolver recognized the presented credential",
            );
            decisions.finalize(Verdict::Deny(violation.clone()));
            return (
                PipelineResult::denied(violation, current_extensions, ctx_table)
                    .with_errors(errors)
                    .with_decision_log(decisions),
                BackgroundTasks::empty(),
                Some(current_payload),
            );
        }

        // Phase 5: FIRE_AND_FORGET — background, read-only, ignore results.
        // FAF errors don't go in PipelineResult.errors — they're delivered
        // via BackgroundTasks::wait_for_background_tasks() instead.
        let bg_handles = self.spawn_fire_and_forget(
            &fire_and_forget,
            &*current_payload,
            &current_extensions,
            &ctx_table,
            task_tracker,
        );

        decisions.finalize(Verdict::Allow);
        (
            PipelineResult::allowed_with(current_payload, current_extensions, ctx_table)
                .with_errors(errors)
                .with_decision_log(decisions)
                .with_payload_modified(payload_modified),
            BackgroundTasks::from_handles(bg_handles),
            None,
        )
    }

    /// Run a serial phase — plugins execute one at a time, each seeing
    /// the (possibly modified) payload from the previous.
    ///
    /// The framework retains ownership of the payload. The handler runs
    /// on a spawned task so a panic cannot unwind [`Executor::execute`],
    /// which means the payload is cloned into the task on every invoke
    /// (sequential and transform). Modified payloads in the result
    /// replace the current payload.
    ///
    /// `payload_modified` is set to `true` when a handler's payload is
    /// accepted, and never cleared — this is the only place that fact is
    /// observable, so it's reported out rather than left to be guessed
    /// from the resulting payload's contents.
    ///
    /// Each plugin's context is looked up in the context table (preserving
    /// `local_state` from previous hooks) or created fresh. After execution,
    /// `global_state` changes are merged back so the next plugin sees them.
    #[allow(clippy::too_many_arguments)] // internal phase helper — args have distinct types and meaning
    async fn run_serial_phase(
        &self,
        entries: &[HookEntry],
        payload: &mut Box<dyn PluginPayload>,
        extensions: &mut Extensions,
        ctx_table: &mut PluginContextTable,
        can_block: bool,
        can_modify: bool,
        phase_label: &str,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
        decisions: &mut DecisionLog,
        payload_modified: &mut bool,
        credential_declined: &mut bool,
    ) -> Option<crate::error::PluginViolation> {
        for entry in entries {
            // Borrow names/ids on the happy path — allocate only when
            // building a violation or stashing the local_state back into
            // the table. Previously `name.to_string()` + `id.to_string()`
            // ran unconditionally on every plugin per invoke.
            let plugin_name = entry.plugin_ref.name();
            let plugin_id = entry.plugin_ref.id();
            let on_error = entry.plugin_ref.trusted_config().on_error;
            let phase = entry.plugin_ref.trusted_config().mode;
            // What this plugin did, recorded once after it runs, or inline
            // on the paths that return before the end of the loop body.
            let mut action = PluginAction::Allowed;

            // Snapshot this plugin's context — clones its stored
            // local_state and seeds global_state from the canonical store.
            // Take-and-commit would drop that local_state if the task
            // panics (no context comes back). Snapshot leaves the previous
            // map in the table until a successful store.
            let ctx = ctx_table.snapshot_context(plugin_id);

            // Filter extensions per plugin based on declared capabilities.
            // Produces a filtered view with None for ungated slots.
            // Also sets write tokens for plugins with write capabilities.
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let mut filtered = filter_extensions(extensions, &capabilities);

            // Set write tokens based on capabilities
            if capabilities.contains("write_headers") {
                filtered.http_write_token = Some(WriteToken::new());
            }
            if capabilities.contains("append_labels") {
                filtered.labels_write_token = Some(WriteToken::new());
            }
            if capabilities.contains("append_delegation") {
                filtered.delegation_write_token = Some(WriteToken::new());
            }
            // Effects are permitted here because a serial plugin runs to
            // completion and its result is honored. The slot is only built
            // when something would record the effect; otherwise the default
            // already permits it and records nothing.
            filtered.effect_log = if !phase.permits_effects() {
                EffectLogSlot::not_permitted(phase, plugin_name)
            } else if let Some(sink) = &self.effect_sink {
                EffectLogSlot::recorded(Arc::clone(sink), plugin_name)
            } else {
                EffectLogSlot::unrecorded()
            };

            // Spawn + timeout so a panic is `ContainedOutcome::Panic`
            // rather than unwinding `execute`. The payload is cloned into
            // the task (`'static`); modifications still return through
            // `ErasedResultFields.modified_payload`.
            //
            // A panic between recording an effect's intent and recording its
            // outcome must not unwind the request future: containment lets
            // `on_error` decide, keeps the pipeline's bookkeeping intact, and
            // leaves the orphaned intent for recovery instead of losing the
            // request.
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
            let contained = invoke_contained(
                Arc::clone(&entry.handler),
                payload.clone_boxed(),
                filtered,
                ctx,
                timeout_dur,
            )
            .await;

            let mut ctx_after: Option<PluginContext> = None;
            match contained {
                ContainedOutcome::Success(result_box, ctx) => {
                    ctx_after = Some(ctx);
                    if let Some(mut erased) = extract_erased(result_box) {
                        if !erased.continue_processing && can_block {
                            // A blocking result always halts; synthesize a violation
                            // when the plugin did not provide one.
                            let mut v = erased.violation.take().unwrap_or_else(|| {
                                crate::error::PluginViolation::new(
                                    "plugin_deny",
                                    format!("Plugin '{plugin_name}' denied"),
                                )
                            });
                            v.plugin_name = Some(plugin_name.to_owned());
                            decisions.record(
                                plugin_name,
                                phase,
                                PluginAction::Denied(Box::new(v.clone())),
                            );
                            return Some(v);
                        }

                        // A stop signalled from a phase that cannot block
                        // (Transform) is suppressed: the pipeline proceeds.
                        // It is recorded as the plugin's actual intent rather
                        // than as an allow, and its modifications are skipped,
                        // since it asked to halt rather than to shape.
                        let deny_ignored = !erased.continue_processing && !can_block;
                        if deny_ignored {
                            let mut v = erased.violation.take().unwrap_or_else(|| {
                                crate::error::PluginViolation::new(
                                    "plugin_deny",
                                    format!("Plugin '{plugin_name}' denied"),
                                )
                            });
                            v.plugin_name = Some(plugin_name.to_owned());
                            action = PluginAction::DenyIgnored(Box::new(v));
                        }

                        // Accept modifications
                        if can_modify && !deny_ignored {
                            if let Some(mp) = erased.modified_payload {
                                if let Some(identity) = mp
                                    .as_any()
                                    .downcast_ref::<crate::identity::IdentityPayload>()
                                {
                                    *credential_declined |= identity.credential_declined();
                                }
                                *payload = mp;
                                action = PluginAction::ModifiedPayload;
                                *payload_modified = true;
                            }
                            if let Some(mut owned) = erased.modified_extensions {
                                let mut immutable_ok = false;
                                if extensions.validate_immutable(&owned) {
                                    // `merge_owned` enforces the tiers per
                                    // *field*, gated on the write tokens that
                                    // `owned` carries. It is not a slot swap: a
                                    // field with no token keeps its canonical
                                    // value, so an ungated edit is dropped
                                    // rather than merged. Previously this arm
                                    // was reached by a bare `else` that merged
                                    // the plugin's whole capability-filtered
                                    // view over canonical state — a plugin with
                                    // no security capability could wipe the
                                    // pipeline's labels by returning `custom`.
                                    //
                                    // The monotonic label check that used to
                                    // live here moved into `merge_security`,
                                    // where it applies unconditionally instead
                                    // of only when `read_labels` was held.
                                    //
                                    // Authority is re-derived from *this*
                                    // plugin's declared capabilities rather than
                                    // read off the returned value. A handler is
                                    // free to build its `OwnedExtensions` any
                                    // way it likes — praxis-policy-apl-runtime's synthetic route
                                    // handler returns `cow_copy()` of a freshly
                                    // accumulated `Extensions`, whose tokens
                                    // `Clone` deliberately drops — so tokens
                                    // surviving the round trip is a statement
                                    // about plumbing, not about permission. The
                                    // capability set is the real grant, and it
                                    // cannot be widened by the return value.
                                    owned.http_write_token = capabilities
                                        .contains("write_headers")
                                        .then(WriteToken::new);
                                    owned.labels_write_token = capabilities
                                        .contains("append_labels")
                                        .then(WriteToken::new);
                                    owned.delegation_write_token = capabilities
                                        .contains("append_delegation")
                                        .then(WriteToken::new);
                                    immutable_ok = true;
                                }
                                // Monotonic security labels: a plugin that can see
                                // labels (`read_labels`) may only add them, never
                                // remove. A plugin without `read_labels` saw an empty
                                // label set in its filtered view, so an absent label
                                // there is not a removal.
                                let labels_ok = !capabilities.contains("read_labels")
                                    || match (&extensions.security, &owned.security) {
                                        (Some(orig), Some(new)) => {
                                            new.labels.is_superset(&orig.labels)
                                        },
                                        _ => true,
                                    };

                                // Candidate-constraint authority: the folded routing
                                // constraint is the policy engine's output. Only a
                                // holder of `write_candidate_constraint` may create,
                                // change, or remove it; any other plugin that alters
                                // the slot (by value) is rejected. A plugin that
                                // leaves it untouched passes (the common case).
                                let constraint_ok =
                                    extensions.candidate_constraint_write_ok(&owned, &capabilities);

                                if !immutable_ok {
                                    warn!(
                                        "{} plugin '{}' violated immutable tier — \
                                         modified an immutable extension slot. \
                                         Extension changes rejected.",
                                        phase_label, plugin_name
                                    );
                                } else if !labels_ok {
                                    warn!(
                                        "{} plugin '{}' violated monotonic tier — \
                                         removed a security label. \
                                         Extension changes rejected.",
                                        phase_label, plugin_name
                                    );
                                } else if !constraint_ok {
                                    warn!(
                                        "{} plugin '{}' lacks `write_candidate_constraint` \
                                         — attempted to modify the policy engine's routing \
                                         constraint. Extension changes rejected.",
                                        phase_label, plugin_name
                                    );
                                } else {
                                    extensions.merge_owned(owned);
                                    if action == PluginAction::Allowed {
                                        action = PluginAction::ModifiedExtensions;
                                    }
                                }
                            }
                        }

                        // Plugin writes to ctx.global_state are committed back
                        // to the canonical store via store_context() below.
                    } else {
                        // A handler that boxed the wrong type used to be
                        // treated as Allow. An unreadable result is an
                        // execution error: Fail halts, Ignore/Disable are
                        // the documented knobs.
                        error!(
                            "{} plugin '{}' returned unexpected result type",
                            phase_label, plugin_name
                        );
                        let e = crate::error::PluginError::Execution {
                            plugin_name: plugin_name.to_owned(),
                            message: "handler returned unexpected result type".into(),
                            source: None,
                            code: None,
                            details: std::collections::HashMap::new(),
                            proto_error_code: None,
                        };
                        action = PluginAction::Error(e.to_string());
                        match on_error {
                            OnError::Fail if can_block => {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_error",
                                    format!("Plugin '{plugin_name}' failed: {e}"),
                                );
                                v.plugin_name = Some(plugin_name.to_owned());
                                decisions.record(plugin_name, phase, action.clone());
                                return Some(v);
                            },
                            OnError::Fail => {
                                errors.push((&e).into());
                            },
                            OnError::Ignore => {
                                errors.push((&e).into());
                            },
                            OnError::Disable => {
                                errors.push((&e).into());
                                entry.plugin_ref.disable();
                            },
                        }
                    }
                    // If no modifications — payload unchanged
                },
                ContainedOutcome::Error(e, ctx) => {
                    error!("{} plugin '{}' failed: {}", phase_label, plugin_name, e);
                    action = PluginAction::Error(e.to_string());
                    match on_error {
                        OnError::Fail if can_block => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_error",
                                format!("Plugin '{plugin_name}' failed: {e}"),
                            );
                            v.plugin_name = Some(plugin_name.to_owned());
                            decisions.record(plugin_name, phase, action.clone());
                            return Some(v);
                        },
                        // Any non-halt outcome (Fail-in-non-blocking-phase,
                        // Ignore, Disable): record the error so the caller
                        // sees it in PipelineResult.errors instead of
                        // having to read the warn-log.
                        OnError::Fail => {
                            warn!(
                                "{} plugin '{}' on_error=fail in non-blocking phase — not halting",
                                phase_label, plugin_name,
                            );
                            errors.push((&e).into());
                        },
                        OnError::Ignore => {
                            errors.push((&e).into());
                        },
                        OnError::Disable => {
                            warn!(
                                "{} plugin '{}' disabled after error",
                                phase_label, plugin_name
                            );
                            errors.push((&e).into());
                            entry.plugin_ref.disable();
                        },
                    }
                    ctx_after = Some(ctx);
                },
                ContainedOutcome::Timeout(ctx) => {
                    error!("{} plugin '{}' timed out", phase_label, plugin_name);
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.to_owned(),
                        timeout_ms: u64::try_from(timeout_dur.as_millis()).unwrap_or(u64::MAX),
                        proto_error_code: None,
                    };
                    action = PluginAction::Error("timed out".to_owned());
                    match on_error {
                        OnError::Fail if can_block => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_timeout",
                                format!("Plugin '{plugin_name}' timed out"),
                            );
                            v.plugin_name = Some(plugin_name.to_owned());
                            decisions.record(plugin_name, phase, action.clone());
                            return Some(v);
                        },
                        OnError::Fail => {
                            warn!(
                                "{} plugin '{}' on_error=fail (timeout) in non-blocking phase — not halting",
                                phase_label, plugin_name,
                            );
                            errors.push((&timeout_err).into());
                        },
                        OnError::Ignore => {
                            errors.push((&timeout_err).into());
                        },
                        OnError::Disable => {
                            warn!(
                                "{} plugin '{}' disabled after timeout",
                                phase_label, plugin_name
                            );
                            errors.push((&timeout_err).into());
                            entry.plugin_ref.disable();
                        },
                    }
                    ctx_after = Some(ctx);
                },
                ContainedOutcome::Panic(s) => {
                    error!(
                        "{} plugin '{}' task panicked: {}",
                        phase_label, plugin_name, s
                    );
                    let panic_err = crate::error::PluginError::Execution {
                        plugin_name: plugin_name.to_owned(),
                        message: format!("task panicked: {s}"),
                        source: None,
                        code: Some("panic".into()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    };
                    action = PluginAction::Error(format!("task panicked: {s}"));
                    match on_error {
                        OnError::Fail if can_block => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_panic",
                                format!("Plugin '{plugin_name}' task panicked: {s}"),
                            );
                            v.plugin_name = Some(plugin_name.to_owned());
                            decisions.record(plugin_name, phase, action.clone());
                            return Some(v);
                        },
                        OnError::Fail => {
                            warn!(
                                "{} plugin '{}' on_error=fail (panic) in non-blocking phase — not halting",
                                phase_label, plugin_name,
                            );
                            errors.push((&panic_err).into());
                        },
                        OnError::Ignore => {
                            errors.push((&panic_err).into());
                        },
                        OnError::Disable => {
                            warn!(
                                "{} plugin '{}' disabled after panic",
                                phase_label, plugin_name
                            );
                            errors.push((&panic_err).into());
                            entry.plugin_ref.disable();
                        },
                    }
                },
                ContainedOutcome::Lost => {
                    action = PluginAction::Error("task ended without a result".to_owned());
                    if can_block {
                        let mut v = crate::error::PluginViolation::new(
                            "executor_invariant",
                            format!(
                                "Plugin '{plugin_name}' task ended without a result; cannot attribute an allow"
                            ),
                        );
                        v.plugin_name = Some(plugin_name.to_owned());
                        decisions.record(plugin_name, phase, action.clone());
                        return Some(v);
                    }
                    warn!(
                        "{} plugin '{}' task was lost in a non-blocking phase — not halting",
                        phase_label, plugin_name,
                    );
                    let lost_err = crate::error::PluginError::Execution {
                        plugin_name: plugin_name.to_owned(),
                        message: "task ended without a result".into(),
                        source: None,
                        code: Some("lost".into()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    };
                    errors.push((&lost_err).into());
                    if matches!(on_error, OnError::Disable) {
                        warn!(
                            "{} plugin '{}' disabled after lost task",
                            phase_label, plugin_name
                        );
                        entry.plugin_ref.disable();
                    }
                },
            }

            // Record what this plugin did. The halting paths above record
            // inline and return before reaching here.
            decisions.record(plugin_name, phase, action);

            // Commit this plugin's context back to the table — replaces the
            // canonical global_state with its (possibly modified) copy and
            // stores the local_state for the next hook invocation. A panic
            // or lost task returns no context; the snapshot above left the
            // previous local_state in the table.
            if let Some(ctx) = ctx_after {
                ctx_table.store_context(plugin_id, ctx);
            }
        }

        None // no denial
    }

    /// Run a read-only phase — plugins receive `&payload` inside the task;
    /// results are discarded.
    ///
    /// The handler still runs on a spawned task, so the payload is cloned
    /// per plugin. Audit used to take `&payload` and spawn nothing; it
    /// now pays the same containment cost as serial.
    async fn run_ref_phase(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
        phase_label: &str,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
    ) {
        for entry in entries {
            let plugin_name = entry.plugin_ref.name().to_owned();
            let plugin_id = entry.plugin_ref.id();
            let on_error = entry.plugin_ref.trusted_config().on_error;
            // Read-only phase — snapshot the plugin's local_state and the
            // canonical global_state, no merge-back.
            let ctx = ctx_table.snapshot_context(plugin_id);
            // Filter extensions per plugin — read-only, no write tokens.
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let mut filtered = filter_extensions(extensions, &capabilities);
            // Refused here: this phase's work is cancelled or discarded
            // when the pipeline short-circuits, and an external act is not.
            filtered.effect_log = EffectLogSlot::not_permitted(
                entry.plugin_ref.trusted_config().mode,
                entry.plugin_ref.name(),
            );
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

            let contained = invoke_contained(
                Arc::clone(&entry.handler),
                payload.clone_boxed(),
                filtered,
                ctx,
                timeout_dur,
            )
            .await;

            // Audit cannot block, so OnError::Fail can't halt — but
            // OnError::Disable must still take a repeatedly-failing plugin
            // out of rotation. Panic is contained the same way serial and
            // concurrent contain it.
            match contained {
                ContainedOutcome::Success(_, _) => {},
                ContainedOutcome::Error(e, _) => {
                    warn!(
                        "{} plugin '{}' error (ignored): {}",
                        phase_label, plugin_name, e
                    );
                    errors.push((&e).into());
                    if matches!(on_error, OnError::Disable) {
                        warn!(
                            "{} plugin '{}' disabled after error",
                            phase_label, plugin_name
                        );
                        entry.plugin_ref.disable();
                    }
                },
                ContainedOutcome::Timeout(_) => {
                    warn!(
                        "{} plugin '{}' timed out (ignored)",
                        phase_label, plugin_name
                    );
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.clone(),
                        timeout_ms: u64::try_from(timeout_dur.as_millis()).unwrap_or(u64::MAX),
                        proto_error_code: None,
                    };
                    errors.push((&timeout_err).into());
                    if matches!(on_error, OnError::Disable) {
                        warn!(
                            "{} plugin '{}' disabled after timeout",
                            phase_label, plugin_name
                        );
                        entry.plugin_ref.disable();
                    }
                },
                ContainedOutcome::Panic(s) => {
                    warn!(
                        "{} plugin '{}' panicked (ignored): {}",
                        phase_label, plugin_name, s
                    );
                    let panic_err = crate::error::PluginError::Execution {
                        plugin_name: plugin_name.clone(),
                        message: format!("task panicked: {s}"),
                        source: None,
                        code: Some("panic".into()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    };
                    errors.push((&panic_err).into());
                    if matches!(on_error, OnError::Disable) {
                        warn!(
                            "{} plugin '{}' disabled after panic",
                            phase_label, plugin_name
                        );
                        entry.plugin_ref.disable();
                    }
                },
                ContainedOutcome::Lost => {
                    warn!(
                        "{} plugin '{}' task ended without a result (ignored)",
                        phase_label, plugin_name
                    );
                    let lost_err = crate::error::PluginError::Execution {
                        plugin_name: plugin_name.clone(),
                        message: "task ended without a result".into(),
                        source: None,
                        code: Some("lost".into()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    };
                    errors.push((&lost_err).into());
                    if matches!(on_error, OnError::Disable) {
                        warn!(
                            "{} plugin '{}' disabled after lost task",
                            phase_label, plugin_name
                        );
                        entry.plugin_ref.disable();
                    }
                },
            }
        }
    }

    /// Run the concurrent phase — plugins execute truly in parallel.
    /// Returns the first violation if any plugin denies.
    ///
    /// Built on `praxis_policy_orchestration::run_branches`, the workspace's
    /// shared "N async branches with abort-on-deny + per-branch timeout"
    /// primitive (same crate praxis-policy-apl-core's `Effect::Parallel` consumes).
    /// Each branch returns a small `BranchData` carrying the plugin's
    /// effective outcome (allow / deny / error). The orchestrator's
    /// `is_deny` predicate inspects that — including the per-plugin
    /// `on_error == Fail` case, which is treated as a halting outcome
    /// so that an erroring/timing-out/panicking Fail-mode plugin
    /// short-circuits the remaining branches the same way an explicit
    /// deny does. Post-loop, we walk the outcomes in input order and
    /// apply each plugin's `on_error` policy (Ignore / Disable) to
    /// non-halting failures.
    async fn run_concurrent_phase(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
        errors: &mut Vec<crate::error::PluginErrorRecord>,
        decisions: &mut DecisionLog,
    ) -> Option<crate::error::PluginViolation> {
        use praxis_policy_orchestration::{
            BranchConfig, BranchOutcome, ErasedBranch, run_branches,
        };

        if entries.is_empty() {
            return None;
        }

        // Per-branch outcome. Carries just enough for post-loop policy
        // application — plugin name / on_error are looked up via
        // `entries[idx]` so we don't have to clone them into the
        // future's captures.
        enum BranchData {
            Allow,
            Deny(Option<crate::error::PluginViolation>),
            Error(Box<PluginError>),
        }

        // Clone the payload once so each spawned task can borrow from
        // an owned, 'static copy. Each task gets its own Arc'd clone.
        let shared_payload: Arc<Box<dyn PluginPayload>> = Arc::new(payload.clone_boxed());
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

        // Snapshot per-entry on_error decisions BEFORE moving into
        // futures — `is_deny` needs them at runtime to decide whether
        // an Error outcome halts (Fail) or is logged (Ignore/Disable).
        let on_error_by_idx: Vec<OnError> = entries
            .iter()
            .map(|e| e.plugin_ref.trusted_config().on_error)
            .collect();

        // Build branch futures. Each does the timing-bounded handler
        // invoke and extracts the type-erased result, returning a
        // `BranchData` that the orchestrator's `is_deny` predicate can
        // inspect without further type knowledge.
        let mut branches: Vec<ErasedBranch<BranchData>> = Vec::with_capacity(entries.len());
        for entry in entries {
            let handler = Arc::clone(&entry.handler);
            let payload_clone = Arc::clone(&shared_payload);
            let plugin_id = entry.plugin_ref.id();
            // Snapshot the plugin's local_state and the canonical global_state.
            // Concurrent plugins do not merge back — each task owns its copy.
            let mut ctx = ctx_table.snapshot_context(plugin_id);
            let plugin_name = entry.plugin_ref.name().to_owned();

            // Filter per plugin — each may have different capabilities.
            // Read-only, no write tokens. Wrap in Arc for 'static spawn.
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let filtered = Arc::new({
                let mut f = filter_extensions(extensions, &capabilities);
                // Refused here: this phase's work is cancelled or discarded
                // when the pipeline short-circuits, and an external act is not.
                f.effect_log = EffectLogSlot::not_permitted(
                    entry.plugin_ref.trusted_config().mode,
                    entry.plugin_ref.name(),
                );
                f
            });

            branches.push(Box::pin(async move {
                match handler.invoke(&**payload_clone, &filtered, &mut ctx).await {
                    Ok(result_box) => match extract_erased(result_box) {
                        Some(erased) if !erased.continue_processing => {
                            let violation = erased.violation.map(|mut v| {
                                v.plugin_name = Some(plugin_name);
                                v
                            });
                            BranchData::Deny(violation)
                        },
                        Some(_) => BranchData::Allow,
                        None => BranchData::Error(Box::new(PluginError::Execution {
                            plugin_name,
                            message: "handler returned unexpected result type".into(),
                            source: None,
                            code: None,
                            details: std::collections::HashMap::new(),
                            proto_error_code: None,
                        })),
                    },
                    Err(e) => BranchData::Error(e),
                }
            }));
        }

        let cfg = BranchConfig {
            timeout_per_branch: Some(timeout_dur),
            short_circuit_on_deny: self.config.short_circuit_on_deny,
        };

        // `is_deny` halts on explicit Deny only. It can't halt on
        // Error/Timeout/Panic because the predicate sees only the
        // value, not the branch index, so it can't read the per-entry
        // `on_error` policy. Halting on those failures is handled in
        // the post-loop: the first Fail-policy failure becomes the
        // returned violation, and any in-flight tasks drop when the
        // JoinSet inside `run_branches` goes out of scope.
        //
        // The original implementation called `set.abort_all()` on
        // Fail-class errors too. The behavioural difference: the
        // post-loop now waits for all branches to finish (or hit
        // their own timeout) before returning. For the slow-plugin
        // abort test that's fine — that test exercises the Deny
        // path, which still goes through `is_deny` + abort_all.
        let outcomes = run_branches(branches, cfg, |v: &BranchData| {
            matches!(v, BranchData::Deny(_))
        })
        .await;

        // Post-loop: walk outcomes in input order applying per-plugin
        // policy. First halting outcome wins.
        let mut first_violation: Option<crate::error::PluginViolation> = None;

        // `entries`, `on_error_by_idx`, and `outcomes` are built one-to-one
        // above and `run_branches` returns exactly one outcome per branch, so
        // this cannot trip today. It is checked rather than assumed because the
        // failure is silent and favours the caller: pairing an outcome with the
        // wrong entry applies the wrong plugin's `on_error`, which turns a
        // configured Fail into an Ignore, and pairing off the end drops the
        // outcome entirely. Adding a `continue` to the branch-building loop is
        // all it would take. Deny instead of guessing which plugin denied.
        if outcomes.len() != entries.len() || on_error_by_idx.len() != entries.len() {
            let mut v = crate::error::PluginViolation::new(
                "executor_invariant",
                format!(
                    "concurrent dispatch produced {} outcomes and {} on_error entries for {} \
                     plugins; cannot attribute results",
                    outcomes.len(),
                    on_error_by_idx.len(),
                    entries.len()
                ),
            );
            v.plugin_name = None;
            return Some(v);
        }

        for ((entry, &on_error), outcome) in
            entries.iter().zip(on_error_by_idx.iter()).zip(outcomes)
        {
            let plugin_name = entry.plugin_ref.name();

            // Record what this branch did, in input order. Done before the
            // policy match below, which may return on the first halting
            // outcome and would otherwise drop the record.
            // A concurrent branch may deny without supplying a violation, and
            // only the first denial becomes the verdict. Both the record and
            // the verdict resolve it the same way so a plugin's objection
            // reads identically wherever it is consumed from.
            let deny_violation = |opt_v: Option<crate::error::PluginViolation>| {
                let mut v = opt_v.unwrap_or_else(|| {
                    crate::error::PluginViolation::new(
                        "concurrent_deny",
                        format!("Plugin '{plugin_name}' denied"),
                    )
                });
                v.plugin_name = Some(plugin_name.to_owned());
                v
            };

            let action = match &outcome {
                BranchOutcome::Completed(BranchData::Allow) => PluginAction::Allowed,
                BranchOutcome::Completed(BranchData::Deny(opt_v)) => {
                    PluginAction::Denied(Box::new(deny_violation(opt_v.clone())))
                },
                BranchOutcome::Completed(BranchData::Error(e)) => {
                    PluginAction::Error(e.to_string())
                },
                BranchOutcome::TimedOut => PluginAction::Error("timed out".to_owned()),
                BranchOutcome::Panicked(s) => PluginAction::Error(format!("panicked: {s}")),
                // Cancelled because another branch short-circuited the phase:
                // an intentional abort, not a crash.
                BranchOutcome::Aborted => PluginAction::Aborted,
            };
            decisions.record(plugin_name, entry.plugin_ref.trusted_config().mode, action);

            match outcome {
                BranchOutcome::Completed(BranchData::Allow) => {},
                BranchOutcome::Completed(BranchData::Deny(opt_v)) => {
                    if first_violation.is_none() {
                        first_violation = Some(deny_violation(opt_v));
                    }
                },
                BranchOutcome::Completed(BranchData::Error(e)) => match on_error {
                    OnError::Fail => {
                        if first_violation.is_none() {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_error",
                                format!("Plugin '{plugin_name}' failed: {e}"),
                            );
                            v.plugin_name = Some(plugin_name.to_owned());
                            first_violation = Some(v);
                        }
                    },
                    OnError::Ignore => {
                        warn!("CONCURRENT plugin '{}' error (ignored): {}", plugin_name, e);
                        errors.push((&*e).into());
                    },
                    OnError::Disable => {
                        warn!("CONCURRENT plugin '{}' disabled after error", plugin_name);
                        errors.push((&*e).into());
                        entry.plugin_ref.disable();
                    },
                },
                BranchOutcome::TimedOut => {
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.to_owned(),
                        timeout_ms: u64::try_from(timeout_dur.as_millis()).unwrap_or(u64::MAX),
                        proto_error_code: None,
                    };
                    match on_error {
                        OnError::Fail => {
                            if first_violation.is_none() {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_timeout",
                                    format!("Plugin '{plugin_name}' timed out"),
                                );
                                v.plugin_name = Some(plugin_name.to_owned());
                                first_violation = Some(v);
                            }
                        },
                        OnError::Ignore => {
                            warn!("CONCURRENT plugin '{}' timed out (ignored)", plugin_name);
                            errors.push((&timeout_err).into());
                        },
                        OnError::Disable => {
                            warn!("CONCURRENT plugin '{}' disabled after timeout", plugin_name);
                            errors.push((&timeout_err).into());
                            entry.plugin_ref.disable();
                        },
                    }
                },
                BranchOutcome::Panicked(s) => {
                    error!("CONCURRENT plugin '{}' task panicked: {}", plugin_name, s);
                    let panic_err = crate::error::PluginError::Execution {
                        plugin_name: plugin_name.to_owned(),
                        message: format!("task panicked: {s}"),
                        source: None,
                        code: Some("panic".into()),
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    };
                    match on_error {
                        OnError::Fail => {
                            if first_violation.is_none() {
                                let mut v = crate::error::PluginViolation::new(
                                    "plugin_panic",
                                    format!("Plugin '{plugin_name}' task panicked: {s}"),
                                );
                                v.plugin_name = Some(plugin_name.to_owned());
                                first_violation = Some(v);
                            }
                        },
                        OnError::Ignore => {
                            warn!("CONCURRENT plugin '{}' panicked (ignored)", plugin_name);
                            errors.push((&panic_err).into());
                        },
                        OnError::Disable => {
                            warn!("CONCURRENT plugin '{}' disabled after panic", plugin_name);
                            errors.push((&panic_err).into());
                            entry.plugin_ref.disable();
                        },
                    }
                },
                BranchOutcome::Aborted => {
                    // Cancelled because an earlier branch hit a halt
                    // condition under short_circuit_on_deny. Intentional
                    // — no error to record.
                },
            }
        }

        first_violation
    }

    /// Spawn fire-and-forget handlers as background tasks.
    ///
    /// Each handler runs in its own `tokio::spawn` — the pipeline does
    /// not wait for them. Errors and timeouts are logged but have no
    /// effect on the pipeline result.
    ///
    /// Returns the plugin name and join handle for each spawned task
    /// so they can be stored on `PipelineResult` for optional awaiting
    /// via `wait_for_background_tasks()`.
    fn spawn_fire_and_forget(
        &self,
        entries: &[HookEntry],
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx_table: &PluginContextTable,
        task_tracker: &tokio_util::task::TaskTracker,
    ) -> Vec<(String, tokio::task::JoinHandle<()>)> {
        if entries.is_empty() {
            return Vec::new();
        }

        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

        let mut handles = Vec::with_capacity(entries.len());

        for entry in entries {
            let plugin_name = entry.plugin_ref.name().to_owned();
            let handler = Arc::clone(&entry.handler);
            let owned_payload = payload.clone_boxed();
            // Snapshot per plugin so fire-and-forget tasks see their stored
            // local_state from prior hooks, not just an empty context.
            let mut ctx = ctx_table.snapshot_context(entry.plugin_ref.id());
            let dur = timeout_dur;
            let name_for_log = plugin_name.clone();

            // Filter per plugin, read-only, no write tokens
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let filtered = Arc::new({
                let mut f = filter_extensions(extensions, &capabilities);
                // Refused here: this phase's work is cancelled or discarded
                // when the pipeline short-circuits, and an external act is not.
                f.effect_log = EffectLogSlot::not_permitted(
                    entry.plugin_ref.trusted_config().mode,
                    entry.plugin_ref.name(),
                );
                f
            });

            // Spawn through TaskTracker so `PolicyEngine::shutdown()`
            // can drain in-flight fire-and-forget tasks before tearing
            // down. The returned JoinHandle is the same shape as
            // tokio::spawn's, so callers using BackgroundTasks still
            // wait_for_background_tasks() over their own handles.
            let handle = task_tracker.spawn(async move {
                let result =
                    timeout(dur, handler.invoke(&*owned_payload, &filtered, &mut ctx)).await;

                match result {
                    Ok(Ok(_)) => {}, // discard
                    Ok(Err(e)) => {
                        warn!(
                            "FIRE_AND_FORGET plugin '{}' error (ignored): {}",
                            name_for_log, e
                        );
                    },
                    Err(_) => {
                        warn!(
                            "FIRE_AND_FORGET plugin '{}' timed out (ignored)",
                            name_for_log
                        );
                    },
                }
            });

            handles.push((plugin_name, handle));
        }

        handles
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new(ExecutorConfig::default())
    }
}

// SerialResult removed — run_serial_phase now returns Option<Violation> directly.

/// Common fields extracted from a type-erased `PluginResult`.
///
/// Handlers return `Box<dyn Any>` which wraps this struct. The
/// executor extracts it via [`extract_erased()`] to read the
/// control flow fields without knowing the concrete payload type.
pub struct ErasedResultFields {
    /// Whether the pipeline continues past this handler.
    pub continue_processing: bool,
    /// The payload the handler produced, when it changed one.
    pub modified_payload: Option<Box<dyn PluginPayload>>,
    /// The extensions the handler produced, when it changed them.
    pub modified_extensions: Option<crate::hooks::payload::OwnedExtensions>,
    /// The violation, when the handler denied.
    pub violation: Option<crate::error::PluginViolation>,
}

/// Extract erased result fields from a type-erased handler result.
///
/// Takes ownership of the Box — the executor consumes the result.
/// Logs a warning if the downcast fails (indicates a handler returned
/// the wrong type — a framework bug, not a plugin error). Callers treat
/// `None` as an execution error so a deny that cannot be read cannot
/// become Allow.
pub fn extract_erased(result: Box<dyn Any + Send + Sync>) -> Option<ErasedResultFields> {
    if let Ok(b) = result.downcast::<ErasedResultFields>() {
        Some(*b)
    } else {
        warn!("extract_erased: downcast failed — handler returned unexpected type");
        None
    }
}

/// Convert a typed `PluginResult<P>` into `ErasedResultFields`.
///
/// Called by `TypedHandlerAdapter` to bridge between the typed
/// result and the executor's type-erased dispatch.
pub fn erase_result<P: crate::hooks::PluginPayload>(
    result: crate::hooks::PluginResult<P>,
) -> Box<dyn Any + Send + Sync> {
    Box::new(ErasedResultFields {
        continue_processing: result.continue_processing,
        modified_payload: result
            .modified_payload
            .map(|p| -> Box<dyn PluginPayload> { Box::new(p) }),
        modified_extensions: result.modified_extensions,
        violation: result.violation,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::hooks::PluginResult;

    #[derive(Debug, Clone)]
    #[allow(
        dead_code,
        reason = "test fixture — typed shape is the point, not field reads"
    )]
    struct TestPayload {
        value: String,
    }
    crate::impl_plugin_payload!(TestPayload);

    #[test]
    fn test_erase_result_allow() {
        let result: PluginResult<TestPayload> = PluginResult::allow();
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(fields.continue_processing);
        assert!(fields.violation.is_none());
        assert!(fields.modified_payload.is_none());
    }

    #[test]
    fn test_erase_result_deny() {
        let result: PluginResult<TestPayload> =
            PluginResult::deny(crate::error::PluginViolation::new("test", "denied"));
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(!fields.continue_processing);
        assert_eq!(fields.violation.as_ref().unwrap().code, "test");
    }

    #[test]
    fn test_erase_result_modify_payload() {
        let result: PluginResult<TestPayload> = PluginResult::modify_payload(TestPayload {
            value: "modified".into(),
        });
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(fields.continue_processing);
        assert!(fields.modified_payload.is_some());
    }

    #[test]
    fn test_erase_result_modify_extensions() {
        let mut security = crate::extensions::SecurityExtension::default();
        security.add_label("PII");
        let ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };
        let owned = ext.cow_copy();
        let result: PluginResult<TestPayload> = PluginResult::modify_extensions(owned);
        let erased = erase_result(result);
        let fields = extract_erased(erased).unwrap();
        assert!(fields.continue_processing);
        assert!(fields.modified_extensions.is_some());
        let sec = fields
            .modified_extensions
            .as_ref()
            .unwrap()
            .security
            .as_ref()
            .unwrap();
        assert!(sec.has_label("PII"));
    }

    #[test]
    fn test_pipeline_result_allowed() {
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let result =
            PipelineResult::allowed_with(payload, Extensions::default(), PluginContextTable::new());
        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
        assert!(result.violation.is_none());
        assert!(
            !result.payload_modified,
            "carrying a payload is not the same as a plugin having changed it"
        );
    }

    #[test]
    fn test_pipeline_result_denied() {
        let violation = crate::error::PluginViolation::new("test", "denied");
        let result =
            PipelineResult::denied(violation, Extensions::default(), PluginContextTable::new());
        assert!(!result.continue_processing);
        assert!(result.modified_payload.is_none());
        assert!(result.violation.is_some());
    }

    #[tokio::test]
    async fn test_executor_empty_entries() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        let (result, _) = executor
            .execute(&[], payload, Extensions::default(), None, &tracker)
            .await;
        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
    }

    // =====================================================================
    // Concurrent phase: failure mode by on_error policy
    // =====================================================================
    //
    // A concurrent plugin can fail three ways (return an error, exceed its
    // timeout, panic) and each is governed by that plugin's `on_error`. That is
    // a nine-cell matrix and none of it was covered. It decides whether a
    // failing plugin halts the pipeline or is stepped over, so a wrong cell
    // either blocks legitimate traffic or lets an enforcement plugin fail open.
    //
    // The shape asserted per cell: `Fail` halts and attributes the violation to
    // the plugin; `Ignore` continues and records the error for a programmatic
    // reader; `Disable` continues, records, and marks the plugin so it stops
    // being dispatched.

    use crate::fault_testing::{InjectedFailure, fault_entry};
    use crate::plugin::PluginMode;

    fn concurrent_entry(
        name: &str,
        on_error: OnError,
        failure: InjectedFailure,
    ) -> crate::registry::HookEntry {
        fault_entry(name, PluginMode::Concurrent, on_error, failure)
    }

    /// One concurrent plugin with the given failure and policy. Returns the
    /// pipeline result plus the entry so a test can check `is_disabled`.
    async fn run_one(
        failure: InjectedFailure,
        on_error: OnError,
    ) -> (PipelineResult, crate::registry::HookEntry) {
        // A short timeout so the Hang case does not stall the suite.
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 1,
            short_circuit_on_deny: true,
            ..Default::default()
        });
        let entry = concurrent_entry("mock", on_error, failure);
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (result, _bg) = executor
            .execute(
                std::slice::from_ref(&entry),
                payload,
                Extensions::default(),
                None,
                &tracker,
            )
            .await;
        (result, entry)
    }

    /// The control. Without it, every assertion below could hold for a reason
    /// unrelated to the failure being injected.
    #[tokio::test]
    async fn a_concurrent_plugin_that_succeeds_allows() {
        let (r, entry) = run_one(InjectedFailure::None, OnError::Fail).await;
        assert!(r.continue_processing, "no failure, so no halt");
        assert!(r.errors.is_empty(), "and nothing to report");
        assert!(!entry.plugin_ref.is_disabled());
    }

    /// A handler that boxed the wrong type used to be treated as Allow,
    /// so a deny that could not be read was dropped. Fail-closed: the
    /// unreadable result is an execution error and `on_error: fail`
    /// halts.
    #[tokio::test]
    async fn a_concurrent_unreadable_result_under_fail_is_fail_closed() {
        let (r, _) = run_one(InjectedFailure::WrongType, OnError::Fail).await;
        assert!(!r.continue_processing, "an unreadable result must halt");
        let v = r.violation.expect("a violation is required to halt");
        assert_eq!(v.code, "plugin_error");
        assert_eq!(v.plugin_name.as_deref(), Some("mock"));
    }

    #[tokio::test]
    async fn a_concurrent_unreadable_result_under_ignore_continues() {
        let (r, entry) = run_one(InjectedFailure::WrongType, OnError::Ignore).await;
        assert!(
            r.continue_processing,
            "on_error: ignore is the documented hatch"
        );
        assert_eq!(r.errors.len(), 1);
        assert!(!entry.plugin_ref.is_disabled());
    }

    #[tokio::test]
    async fn a_serial_unreadable_result_under_fail_is_fail_closed() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 1,
            short_circuit_on_deny: true,
            ..Default::default()
        });
        let entry = fault_entry(
            "mock",
            PluginMode::Sequential,
            OnError::Fail,
            InjectedFailure::WrongType,
        );
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (r, _bg) = executor
            .execute(
                std::slice::from_ref(&entry),
                payload,
                Extensions::default(),
                None,
                &tracker,
            )
            .await;
        assert!(!r.continue_processing, "an unreadable result must halt");
        let v = r.violation.expect("a violation is required to halt");
        assert_eq!(v.code, "plugin_error");
        assert_eq!(v.plugin_name.as_deref(), Some("mock"));
    }

    // ---- returned error ---------------------------------------------------

    #[tokio::test]
    async fn a_concurrent_error_under_fail_halts_and_names_the_plugin() {
        let (r, _) = run_one(InjectedFailure::Error, OnError::Fail).await;
        assert!(!r.continue_processing, "on_error: fail must halt");
        let v = r.violation.expect("a violation is required to halt");
        assert_eq!(v.code, "plugin_error");
        assert_eq!(
            v.plugin_name.as_deref(),
            Some("mock"),
            "the violation must attribute the failure"
        );
    }

    /// `Ignore` has to surface the error to a programmatic reader even though it
    /// continues. Logging alone would make the failure invisible to a caller.
    #[tokio::test]
    async fn a_concurrent_error_under_ignore_continues_but_is_recorded() {
        let (r, entry) = run_one(InjectedFailure::Error, OnError::Ignore).await;
        assert!(r.continue_processing, "on_error: ignore must not halt");
        assert_eq!(r.errors.len(), 1, "and must still report the error");
        assert!(
            !entry.plugin_ref.is_disabled(),
            "ignore does not disable the plugin"
        );
    }

    #[tokio::test]
    async fn a_concurrent_error_under_disable_continues_and_disables() {
        let (r, entry) = run_one(InjectedFailure::Error, OnError::Disable).await;
        assert!(r.continue_processing, "on_error: disable must not halt");
        assert_eq!(r.errors.len(), 1);
        assert!(
            entry.plugin_ref.is_disabled(),
            "the plugin must be marked so it stops being dispatched"
        );
    }

    // ---- timeout ----------------------------------------------------------

    #[tokio::test]
    async fn a_concurrent_timeout_under_fail_halts_as_a_timeout() {
        let (r, _) = run_one(InjectedFailure::Hang, OnError::Fail).await;
        assert!(!r.continue_processing);
        let v = r.violation.expect("a violation is required to halt");
        assert_eq!(
            v.code, "plugin_timeout",
            "a timeout must be distinguishable from a returned error"
        );
        assert_eq!(v.plugin_name.as_deref(), Some("mock"));
    }

    #[tokio::test]
    async fn a_concurrent_timeout_under_ignore_continues_but_is_recorded() {
        let (r, entry) = run_one(InjectedFailure::Hang, OnError::Ignore).await;
        assert!(r.continue_processing);
        assert_eq!(r.errors.len(), 1);
        assert!(!entry.plugin_ref.is_disabled());
    }

    #[tokio::test]
    async fn a_concurrent_timeout_under_disable_continues_and_disables() {
        let (r, entry) = run_one(InjectedFailure::Hang, OnError::Disable).await;
        assert!(r.continue_processing);
        assert_eq!(r.errors.len(), 1);
        assert!(entry.plugin_ref.is_disabled());
    }

    // ---- panic ------------------------------------------------------------
    //
    // A panicking branch must not take the process down, and must be
    // attributable. This is the cell most likely to be wrong, because the
    // panic unwinds inside a spawned task rather than returning a value.

    #[tokio::test]
    async fn a_concurrent_panic_under_fail_halts_as_a_panic() {
        let (r, _) = run_one(InjectedFailure::Panic, OnError::Fail).await;
        assert!(!r.continue_processing);
        let v = r.violation.expect("a violation is required to halt");
        assert_eq!(
            v.code, "plugin_panic",
            "a panic must be distinguishable from an error and a timeout"
        );
        assert_eq!(v.plugin_name.as_deref(), Some("mock"));
    }

    #[tokio::test]
    async fn a_concurrent_panic_under_ignore_continues_but_is_recorded() {
        let (r, entry) = run_one(InjectedFailure::Panic, OnError::Ignore).await;
        assert!(
            r.continue_processing,
            "a panicking plugin under ignore must not halt the pipeline"
        );
        assert_eq!(r.errors.len(), 1);
        assert!(!entry.plugin_ref.is_disabled());
    }

    #[tokio::test]
    async fn a_concurrent_panic_under_disable_continues_and_disables() {
        let (r, entry) = run_one(InjectedFailure::Panic, OnError::Disable).await;
        assert!(r.continue_processing);
        assert_eq!(r.errors.len(), 1);
        assert!(entry.plugin_ref.is_disabled());
    }

    /// With several failures at once the first Fail-policy one wins, and the
    /// Ignore-policy ones are still recorded rather than dropped. Otherwise a
    /// pipeline with one strict and one lenient plugin would lose the lenient
    /// one's diagnostics.
    #[tokio::test]
    async fn the_first_fail_policy_failure_wins_and_ignored_ones_are_still_recorded() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 1,
            short_circuit_on_deny: true,
            ..Default::default()
        });
        let entries = vec![
            concurrent_entry("lenient", OnError::Ignore, InjectedFailure::Error),
            concurrent_entry("strict", OnError::Fail, InjectedFailure::Error),
        ];
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (r, _bg) = executor
            .execute(&entries, payload, Extensions::default(), None, &tracker)
            .await;

        assert!(!r.continue_processing, "the strict plugin halts");
        assert_eq!(
            r.violation.expect("violation").plugin_name.as_deref(),
            Some("strict"),
            "and the halt is attributed to it, not the lenient one"
        );
        assert_eq!(
            r.errors.len(),
            1,
            "the lenient plugin's error is still reported"
        );
    }

    // ---- BackgroundTasks accessors ----------------------------------------

    #[tokio::test]
    async fn an_empty_pipeline_reports_no_background_tasks() {
        let executor = Executor::default();
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
        let (_r, bg) = executor
            .execute(&[], payload, Extensions::default(), None, &tracker)
            .await;
        assert!(bg.is_empty());
        assert_eq!(bg.len(), 0);
        assert!(
            format!("{bg:?}").contains("BackgroundTasks"),
            "Debug is what a failing assertion prints"
        );
        assert!(bg.wait_for_background_tasks().await.is_empty());
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod audit_seam_tests {
    //! The audit seam: every verdict reaches the sinks.
    //!
    //! The gap these cover is that an observation-only plugin runs as a
    //! post-hook and so only ever sees traffic that was allowed through. A
    //! blocked call produced no record at all. The load-bearing cases here are
    //! the deny ones; the allow cases exist so a passing deny test cannot be
    //! passing for an unrelated reason.

    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::audit::AuditHandler;
    use crate::decision::DecisionStep;
    use crate::error::PluginViolation;
    use crate::hooks::PluginResult;
    use crate::plugin::{Plugin, PluginConfig, PluginMode};
    use crate::registry::PluginRef;

    #[derive(Debug, Clone)]
    #[allow(dead_code, reason = "test payload: the typed shape is the point")]
    struct P(String);
    crate::impl_plugin_payload!(P);

    /// What a sink was handed, kept so a test can assert on it after the
    /// pipeline has returned.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<(bool, Vec<DecisionStep>)>>,
    }

    impl Recorder {
        fn calls(&self) -> Vec<(bool, Vec<DecisionStep>)> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AuditHandler for Recorder {
        async fn handle(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            decisions: &DecisionLog,
        ) {
            self.seen
                .lock()
                .unwrap()
                .push((decisions.is_denied(), decisions.steps().to_vec()));
        }
    }

    /// A sink that panics. The verdict is already decided when it runs, so it
    /// must not be able to take the request down with it.
    struct PanickingSink;

    #[async_trait]
    impl AuditHandler for PanickingSink {
        async fn handle(&self, _p: &dyn PluginPayload, _e: &Extensions, _d: &DecisionLog) {
            panic!("sink blew up");
        }
    }

    /// What a mock plugin does when invoked.
    #[derive(Clone, Copy)]
    enum Act {
        Allow,
        Deny,
        ModifyPayload,
        Error,
    }

    struct MockPlugin(PluginConfig);

    #[async_trait]
    impl Plugin for MockPlugin {
        fn config(&self) -> &PluginConfig {
            &self.0
        }
    }

    struct MockHandler(Act);

    #[async_trait]
    impl AnyHookHandler for MockHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            Ok(match self.0 {
                Act::Allow => erase_result(PluginResult::<P>::allow()),
                Act::Deny => erase_result(PluginResult::<P>::deny(PluginViolation::new(
                    "blocked", "nope",
                ))),
                Act::ModifyPayload => {
                    erase_result(PluginResult::modify_payload(P("changed".into())))
                },
                Act::Error => {
                    return Err(Box::new(PluginError::Execution {
                        plugin_name: "mock".into(),
                        message: "boom".into(),
                        source: None,
                        code: None,
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    }));
                },
            })
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    fn entry(name: &str, mode: PluginMode, act: Act) -> HookEntry {
        let cfg = PluginConfig {
            name: name.into(),
            mode,
            on_error: OnError::Ignore,
            ..Default::default()
        };
        HookEntry {
            plugin_ref: Arc::new(PluginRef::new(Arc::new(MockPlugin(cfg.clone())), cfg)),
            handler: Arc::new(MockHandler(act)),
        }
    }

    /// A sink declaring no capabilities, which is what an audit plugin that
    /// only records verdicts needs.
    fn sink(handler: Arc<dyn AuditHandler>) -> AttachedSink {
        AttachedSink::new(handler, std::collections::HashSet::new())
    }

    /// Run the pipeline and emit the way `PolicyEngine::finish` does.
    ///
    /// `execute` builds the decision log and stops there, because the verdict
    /// is not final until the engine's assertion contract has run. Tests that
    /// assert on what a sink saw have to drive the emit themselves.
    async fn execute_and_emit(
        executor: &Executor,
        entries: &[HookEntry],
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
    ) -> PipelineResult {
        let tracker = tokio_util::task::TaskTracker::new();
        let (mut result, _bg, refused) = executor
            .execute_audited(entries, payload, extensions, None, &tracker)
            .await;
        let verdict = match result.violation.as_ref() {
            Some(v) => Verdict::Deny(v.clone()),
            None => Verdict::Allow,
        };
        let carried = result.modified_payload.take();
        let ext = result.modified_extensions.take().unwrap_or_default();
        if let Some(p) = carried.as_deref().or(refused.as_deref()) {
            executor
                .emit_decision(p, &ext, &mut result.decision_log, verdict)
                .await;
        }
        result.modified_extensions = Some(ext);
        result.modified_payload = carried;
        result
    }

    async fn run(entries: &[HookEntry], sinks: Vec<AttachedSink>) -> (PipelineResult, DecisionLog) {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            short_circuit_on_deny: true,
            ..Default::default()
        })
        .with_audit_handlers(sinks);
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        let result = execute_and_emit(&executor, entries, payload, Extensions::default()).await;
        let log = result.decision_log.clone();
        (result, log)
    }

    #[tokio::test]
    async fn an_allowed_run_emits_one_record_with_a_step_per_plugin() {
        let rec = Arc::new(Recorder::default());
        let entries = [
            entry("a", PluginMode::Sequential, Act::Allow),
            entry("b", PluginMode::Sequential, Act::Allow),
        ];
        let (result, _) = run(&entries, vec![sink(rec.clone())]).await;

        assert!(result.continue_processing);
        let calls = rec.calls();
        assert_eq!(calls.len(), 1, "exactly one record per invocation");
        let (denied, steps) = &calls[0];
        assert!(!denied);
        assert_eq!(
            steps
                .iter()
                .map(|s| s.plugin_name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"],
            "steps are in execution order"
        );
    }

    /// The reason the seam exists. A post-hook observer never runs on this
    /// path, so before the verdict emit a blocked call produced no record.
    #[tokio::test]
    async fn a_denied_run_still_emits_a_record_naming_the_denying_plugin() {
        let rec = Arc::new(Recorder::default());
        let entries = [
            entry("first", PluginMode::Sequential, Act::Allow),
            entry("blocker", PluginMode::Sequential, Act::Deny),
            entry("never", PluginMode::Sequential, Act::Allow),
        ];
        let (result, log) = run(&entries, vec![sink(rec.clone())]).await;

        assert!(result.is_denied());
        let calls = rec.calls();
        assert_eq!(calls.len(), 1);
        let (denied, steps) = &calls[0];
        assert!(
            denied,
            "the sink sees the deny, not just the allowed traffic"
        );
        assert_eq!(
            steps
                .iter()
                .map(|s| s.plugin_name.as_str())
                .collect::<Vec<_>>(),
            ["first", "blocker"],
            "the plugin after the short-circuit never ran, so it has no step"
        );
        match &steps[1].action {
            PluginAction::Denied(v) => assert_eq!(v.code, "blocked"),
            other => panic!("expected a deny step, got {other:?}"),
        }
        assert!(matches!(log.verdict(), Some(Verdict::Deny(v)) if v.code == "blocked"));
    }

    #[tokio::test]
    async fn a_concurrent_deny_emits_a_record() {
        let rec = Arc::new(Recorder::default());
        let entries = [entry("gate", PluginMode::Concurrent, Act::Deny)];
        let (result, _) = run(&entries, vec![sink(rec.clone())]).await;

        assert!(result.is_denied());
        let calls = rec.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0);
        assert!(matches!(calls[0].1[0].action, PluginAction::Denied(_)));
    }

    /// Transform cannot block, so the deny is suppressed and the pipeline
    /// proceeds. Recording it as `Allowed` would tell a consumer the plugin
    /// permitted the request when it asked to stop it.
    #[tokio::test]
    async fn a_block_from_transform_is_recorded_as_deny_ignored() {
        let rec = Arc::new(Recorder::default());
        let entries = [entry("shaper", PluginMode::Transform, Act::Deny)];
        let (result, _) = run(&entries, vec![sink(rec.clone())]).await;

        assert!(result.continue_processing, "transform cannot block");
        let calls = rec.calls();
        // The verdict is an allow and names nothing, so this step is the only
        // place the objection survives. A bare marker would record that a
        // plugin objected without recording what it objected to.
        match &calls[0].1[0].action {
            PluginAction::DenyIgnored(v) => {
                assert_eq!(v.code, "blocked");
                assert_eq!(v.reason, "nope");
                assert_eq!(v.plugin_name.as_deref(), Some("shaper"));
            },
            other => panic!("expected a suppressed deny, got {other:?}"),
        }
    }

    /// Only the first concurrent denial becomes the verdict. The others are
    /// still real objections, and each step carries its own reason rather than
    /// every branch pointing at whichever one happened to land first.
    #[tokio::test]
    async fn every_concurrent_denial_keeps_its_own_reason() {
        let rec = Arc::new(Recorder::default());
        let entries = [
            entry("gate_a", PluginMode::Concurrent, Act::Deny),
            entry("gate_b", PluginMode::Concurrent, Act::Deny),
        ];
        let (result, _) = run(&entries, vec![sink(rec.clone())]).await;

        assert!(result.is_denied());
        let calls = rec.calls();
        let denials: Vec<&str> = calls[0]
            .1
            .iter()
            .filter_map(|s| match &s.action {
                PluginAction::Denied(v) => v.plugin_name.as_deref(),
                _ => None,
            })
            .collect();
        assert_eq!(
            denials,
            ["gate_a", "gate_b"],
            "each denying branch is attributed to itself"
        );
    }

    #[tokio::test]
    async fn a_payload_modification_is_recorded_as_such() {
        let rec = Arc::new(Recorder::default());
        let entries = [entry("shaper", PluginMode::Transform, Act::ModifyPayload)];
        let (_, _) = run(&entries, vec![sink(rec.clone())]).await;

        assert_eq!(rec.calls()[0].1[0].action, PluginAction::ModifiedPayload);
    }

    #[tokio::test]
    async fn a_plugin_error_is_recorded_as_an_error_step() {
        let rec = Arc::new(Recorder::default());
        let entries = [entry("flaky", PluginMode::Sequential, Act::Error)];
        let (result, _) = run(&entries, vec![sink(rec.clone())]).await;

        assert!(result.continue_processing, "on_error: ignore continues");
        assert!(matches!(rec.calls()[0].1[0].action, PluginAction::Error(_)));
    }

    /// A hook that resolves to no plugins still produces a record, so a
    /// consumer counting records per invocation does not read "nothing
    /// configured" as a dropped record.
    #[tokio::test]
    async fn a_zero_plugin_run_emits_one_allow_record() {
        let rec = Arc::new(Recorder::default());
        let (_, _) = run(&[], vec![sink(rec.clone())]).await;

        let calls = rec.calls();
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].0);
        assert!(calls[0].1.is_empty());
    }

    #[tokio::test]
    async fn a_panicking_sink_does_not_disturb_the_verdict() {
        let rec = Arc::new(Recorder::default());
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];
        let (result, _) = run(
            &entries,
            vec![sink(Arc::new(PanickingSink)), sink(rec.clone())],
        )
        .await;

        assert!(result.continue_processing, "the request survives the sink");
        assert_eq!(
            rec.calls().len(),
            1,
            "a later sink still runs after an earlier one panics"
        );
    }

    /// No sink attached is the default, and it must cost nothing beyond the
    /// verdict itself still being recorded on the result.
    #[tokio::test]
    async fn with_no_sink_the_pipeline_still_carries_its_decision_log() {
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];
        let (_, log) = run(&entries, Vec::new()).await;

        assert!(matches!(log.verdict(), Some(Verdict::Allow)));
        assert_eq!(log.steps().len(), 1);
    }

    // =====================================================================
    // Effects, as the executor wires them
    // =====================================================================
    //
    // The slot tests in `effect` cover the bracket itself. These cover the
    // part only the executor decides: which phase gets which slot.

    /// Performs an effect and reports whether it was allowed to act.
    struct EffectPlugin {
        cfg: PluginConfig,
        acted: Arc<std::sync::atomic::AtomicBool>,
        refused: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl Plugin for EffectPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    #[async_trait]
    impl AnyHookHandler for EffectPlugin {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            let effect = crate::effect::EffectRecord::prepared("token_mint", "d", "k-1");
            let acted = Arc::clone(&self.acted);
            let outcome: Result<(), Box<PluginError>> = extensions
                .perform_effect(&effect, || async move {
                    acted.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                })
                .await;
            if outcome.is_err() {
                self.refused
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(erase_result(PluginResult::<P>::allow()))
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    /// Runs one effect-performing plugin in `mode`, returning
    /// (acted, refused, records written).
    async fn run_effect_in(mode: PluginMode) -> (bool, bool, Vec<crate::effect::EffectRecord>) {
        #[derive(Debug, Default)]
        struct SpyLog(Mutex<Vec<crate::effect::EffectRecord>>);

        #[async_trait]
        impl crate::effect::DurableEffectLog for SpyLog {
            async fn append(
                &self,
                effect: &crate::effect::EffectRecord,
            ) -> Result<(), Box<PluginError>> {
                self.0.lock().unwrap().push(effect.clone());
                Ok(())
            }
        }

        let log = Arc::new(SpyLog::default());
        let acted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cfg = PluginConfig {
            name: "minter".into(),
            mode,
            on_error: OnError::Ignore,
            ..Default::default()
        };
        let entry = HookEntry {
            plugin_ref: Arc::new(PluginRef::new(
                Arc::new(EffectPlugin {
                    cfg: cfg.clone(),
                    acted: Arc::clone(&acted),
                    refused: Arc::clone(&refused),
                }),
                cfg,
            )),
            handler: Arc::new(EffectPlugin {
                cfg: PluginConfig::default(),
                acted: Arc::clone(&acted),
                refused: Arc::clone(&refused),
            }),
        };

        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            short_circuit_on_deny: true,
            ..Default::default()
        })
        .with_effect_log(log.clone());
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        let (_r, bg) = executor
            .execute(
                std::slice::from_ref(&entry),
                payload,
                Extensions::default(),
                None,
                &tracker,
            )
            .await;
        bg.wait_for_background_tasks().await;

        let seen = log.0.lock().unwrap().clone();
        (
            acted.load(std::sync::atomic::Ordering::SeqCst),
            refused.load(std::sync::atomic::Ordering::SeqCst),
            seen,
        )
    }

    #[tokio::test]
    async fn a_sequential_plugin_may_act_and_the_act_is_recorded() {
        let (acted, refused, seen) = run_effect_in(PluginMode::Sequential).await;

        assert!(acted, "a serial plugin runs to completion, so it may act");
        assert!(!refused);
        assert_eq!(seen.len(), 2, "intent then outcome");
        assert_eq!(seen[0].plugin_name.as_deref(), Some("minter"));
    }

    /// The phase rule is not part of auditing and does not switch off with it.
    ///
    /// An operator who wants no auditing installs no sink and configures no
    /// log. That silences the records. It does not make it sound for a
    /// concurrent branch to mint a credential the pipeline will discard, so
    /// the refusal stands either way.
    #[tokio::test]
    async fn the_phase_rule_holds_with_auditing_switched_off() {
        let acted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cfg = PluginConfig {
            name: "minter".into(),
            mode: PluginMode::Concurrent,
            on_error: OnError::Ignore,
            ..Default::default()
        };
        let entry = HookEntry {
            plugin_ref: Arc::new(PluginRef::new(
                Arc::new(EffectPlugin {
                    cfg: cfg.clone(),
                    acted: Arc::clone(&acted),
                    refused: Arc::clone(&refused),
                }),
                cfg,
            )),
            handler: Arc::new(EffectPlugin {
                cfg: PluginConfig::default(),
                acted: Arc::clone(&acted),
                refused: Arc::clone(&refused),
            }),
        };

        // No sink, no effect log: auditing is entirely off.
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        });
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        let (_r, bg) = executor
            .execute(
                std::slice::from_ref(&entry),
                payload,
                Extensions::default(),
                None,
                &tracker,
            )
            .await;
        bg.wait_for_background_tasks().await;

        assert!(
            !acted.load(std::sync::atomic::Ordering::SeqCst),
            "the act must not run just because nobody is recording"
        );
        assert!(refused.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A concurrent branch is cancelled when another branch short-circuits the
    /// phase, so an act there could happen for work the pipeline threw away.
    #[tokio::test]
    async fn a_concurrent_plugin_is_refused_and_does_not_act() {
        let (acted, refused, seen) = run_effect_in(PluginMode::Concurrent).await;

        assert!(!acted, "the act must not run");
        assert!(
            refused,
            "and the plugin is told why, rather than silently no-oping"
        );
        assert!(seen.is_empty());
    }

    #[tokio::test]
    async fn an_audit_phase_plugin_is_refused() {
        let (acted, refused, _) = run_effect_in(PluginMode::Audit).await;

        assert!(!acted);
        assert!(refused);
    }

    #[tokio::test]
    async fn a_fire_and_forget_plugin_is_refused() {
        let (acted, refused, _) = run_effect_in(PluginMode::FireAndForget).await;

        assert!(
            !acted,
            "this phase runs after the verdict is already returned"
        );
        assert!(refused);
    }

    /// Without panic containment a panicking serial plugin unwinds the request
    /// future, which loses the verdict and, once effects exist, strands an
    /// intent with nothing to reconcile it against.
    #[tokio::test]
    async fn a_panicking_serial_plugin_is_contained_and_named() {
        struct Panicker(PluginConfig);

        #[async_trait]
        impl Plugin for Panicker {
            fn config(&self) -> &PluginConfig {
                &self.0
            }
        }

        #[async_trait]
        impl AnyHookHandler for Panicker {
            async fn invoke(
                &self,
                _p: &dyn PluginPayload,
                _e: &Extensions,
                _c: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                panic!("simulated panic in a serial plugin");
            }

            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let cfg = PluginConfig {
            name: "boom".into(),
            mode: PluginMode::Sequential,
            on_error: OnError::Fail,
            ..Default::default()
        };
        let entry = HookEntry {
            plugin_ref: Arc::new(PluginRef::new(Arc::new(Panicker(cfg.clone())), cfg.clone())),
            handler: Arc::new(Panicker(cfg)),
        };
        let rec = Arc::new(Recorder::default());
        let (result, _) = run(std::slice::from_ref(&entry), vec![sink(rec.clone())]).await;

        let violation = result
            .violation
            .expect("a panic under on_error: fail denies");
        assert_eq!(
            violation.code, "plugin_panic",
            "a crash is distinguishable from an ordinary plugin error"
        );
        assert_eq!(
            rec.calls().len(),
            1,
            "and the verdict still reaches the audit sinks"
        );
    }

    // =====================================================================
    // Provenance captured at entry
    // =====================================================================

    /// Both are captured before any plugin runs, because a sink comparing
    /// entry against exit is what shows the pipeline's effect. Capture them
    /// afterwards and the two sides are identical and say nothing.
    #[tokio::test]
    async fn entry_provenance_records_the_span_and_the_taint_it_arrived_with() {
        use crate::extensions::{RequestExtension, SecurityExtension};

        let rec = Arc::new(Recorder::default());
        let mut security = SecurityExtension::default();
        security.add_label("PII");
        let extensions = Extensions {
            request: Some(Arc::new(RequestExtension {
                trace_id: Some("trace-abc".to_owned()),
                span_id: Some("upstream".to_owned()),
                ..Default::default()
            })),
            security: Some(Arc::new(security)),
            ..Default::default()
        };

        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(rec.clone())]);
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];
        let result = execute_and_emit(&executor, &entries, payload, extensions).await;

        let log = result.decision_log;
        let span = log.span().expect("the executor stamps a span");
        assert_eq!(span.trace_id, "trace-abc");
        assert_eq!(span.parent_span_id.as_deref(), Some("upstream"));
        assert_eq!(log.input_labels(), ["PII"]);
        assert_eq!(rec.calls().len(), 1);
    }

    /// An unaudited host builds no provenance at all. Deriving a span costs
    /// two fresh UUIDs and two allocations per request, which nobody should
    /// pay for a record no sink will read.
    #[tokio::test]
    async fn with_no_sink_no_provenance_is_built() {
        use crate::extensions::{RequestExtension, SecurityExtension};

        let mut security = SecurityExtension::default();
        security.add_label("PII");
        let extensions = Extensions {
            request: Some(Arc::new(RequestExtension {
                trace_id: Some("trace-abc".to_owned()),
                ..Default::default()
            })),
            security: Some(Arc::new(security)),
            ..Default::default()
        };

        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            capture_content_provenance: true,
            ..Default::default()
        });
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        let (result, _bg) = executor
            .execute(&entries, payload, extensions, None, &tracker)
            .await;

        let log = result.decision_log;
        assert!(log.span().is_none(), "no span is derived");
        assert!(log.input_labels().is_empty(), "no taint is captured");
        assert!(log.input_hash().is_none(), "and nothing is hashed");
        // What the phases record as they run is still there, because it costs
        // nothing extra.
        assert_eq!(log.steps().len(), 1);
        assert!(log.verdict().is_some());
    }

    /// Hashing sits on the request path, so an operator who did not ask for it
    /// pays nothing and the record carries no content reference at all.
    #[tokio::test]
    async fn content_is_not_hashed_unless_it_was_asked_for() {
        // A sink is attached, so provenance is built. What this asserts is
        // that the content knob alone decides whether a hash is part of it.
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];
        let (result, _bg) = executor
            .execute(&entries, payload, Extensions::default(), None, &tracker)
            .await;

        assert!(result.decision_log.input_hash().is_none());
        assert!(
            result.decision_log.span().is_some(),
            "the rest of the provenance was still built, so this is the knob"
        );
    }

    /// The payload here does not opt into hashing, so even with provenance on
    /// there is nothing to hash. Enabling the knob must not invent a digest.
    #[tokio::test]
    async fn a_payload_that_cannot_be_hashed_records_no_digest() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            capture_content_provenance: true,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];
        let (result, _bg) = executor
            .execute(&entries, payload, Extensions::default(), None, &tracker)
            .await;

        assert!(result.decision_log.input_hash().is_none());
    }

    #[tokio::test]
    async fn an_opted_in_payload_is_hashed_when_provenance_is_on() {
        use crate::cmf::{Message, MessagePayload, Role};

        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            capture_content_provenance: true,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);
        let tracker = tokio_util::task::TaskTracker::new();
        let payload: Box<dyn PluginPayload> = Box::new(MessagePayload {
            message: Message::with_content(Role::User, Vec::new()),
        });
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];
        let (result, _bg) = executor
            .execute(&entries, payload, Extensions::default(), None, &tracker)
            .await;

        let hash = result
            .decision_log
            .input_hash()
            .expect("an opted-in payload is hashed");
        assert!(hash.starts_with("sha256:"), "got {hash}");
    }

    // =====================================================================
    // Audit stream sequencing
    // =====================================================================
    //
    // The counters make two different claims. `stream_seq` is gap-free within
    // its stream, so a gap is a lost record. `emission_seq` is shared with the
    // effect stream, so the two can be merged back into the order they
    // happened. A consumer that cannot rely on either has no way to tell a
    // dropped record from a quiet period, which is the whole point.

    async fn run_with(executor: &Executor, entries: &[HookEntry]) -> PipelineResult {
        let payload: Box<dyn PluginPayload> = Box::new(P("in".into()));
        execute_and_emit(executor, entries, payload, Extensions::default()).await
    }

    #[tokio::test]
    async fn decision_sequence_numbers_are_dense_and_ordered() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];

        let mut seqs = Vec::new();
        for _ in 0..5 {
            let log = run_with(&executor, &entries).await.decision_log;
            seqs.push(log.stream_seq().expect("a stamped record"));
        }

        assert_eq!(seqs, [0, 1, 2, 3, 4], "no gaps, so no record looks lost");
    }

    #[tokio::test]
    async fn every_stamped_record_carries_the_stream_it_belongs_to() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];

        let log = run_with(&executor, &entries).await.decision_log;

        assert_eq!(log.stream_id(), Some("decision"));
        assert_eq!(log.epoch(), Some(executor.epoch()));
        assert_eq!(log.emission_seq(), Some(0));
    }

    /// A namespace attributes records to one process, and the type suffix has
    /// to survive it, or the two streams merge and neither stays gap-free.
    #[tokio::test]
    async fn a_namespace_prefixes_the_stream_but_keeps_the_type() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            audit_stream_namespace: Some("gw-1".to_owned()),
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];

        let log = run_with(&executor, &entries).await.decision_log;

        assert_eq!(log.stream_id(), Some("gw-1:decision"));
    }

    /// Counting a record nobody received would look downstream exactly like a
    /// record that went missing.
    #[tokio::test]
    async fn nothing_is_counted_when_no_sink_will_receive_it() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        });
        let entries = [entry("a", PluginMode::Sequential, Act::Allow)];

        run_with(&executor, &entries).await;
        run_with(&executor, &entries).await;

        // Attaching a sink now starts the stream at zero, because the earlier
        // invocations emitted nothing and so consumed no sequence number.
        let mut executor = executor;
        executor.set_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);
        let log = run_with(&executor, &entries).await.decision_log;

        assert_eq!(log.stream_seq(), Some(0));
    }

    /// A denied run is a record like any other, so it takes its place in the
    /// stream rather than leaving a hole where a block happened.
    #[tokio::test]
    async fn a_deny_consumes_a_sequence_number_like_an_allow() {
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(Arc::new(Recorder::default()))]);

        let allowed = [entry("a", PluginMode::Sequential, Act::Allow)];
        let denied = [entry("b", PluginMode::Sequential, Act::Deny)];

        let first = run_with(&executor, &allowed).await.decision_log;
        let second = run_with(&executor, &denied).await.decision_log;
        let third = run_with(&executor, &allowed).await.decision_log;

        assert_eq!(
            [
                first.stream_seq().unwrap(),
                second.stream_seq().unwrap(),
                third.stream_seq().unwrap()
            ],
            [0, 1, 2]
        );
    }

    /// The shared counter is what lets a reader interleave the two streams.
    /// If effects had their own, a merged view could not be ordered.
    #[tokio::test]
    async fn decisions_and_effects_share_one_ordering_counter() {
        #[derive(Debug, Default)]
        struct SpyLog(Mutex<Vec<crate::effect::EffectRecord>>);

        #[async_trait]
        impl crate::effect::DurableEffectLog for SpyLog {
            async fn append(
                &self,
                effect: &crate::effect::EffectRecord,
            ) -> Result<(), Box<PluginError>> {
                self.0.lock().unwrap().push(effect.clone());
                Ok(())
            }
        }

        /// A sink that keeps the effect records it was handed. The stream
        /// position lives on what a sink sees, so that is where it is read.
        #[derive(Default)]
        struct EffectSpy(Mutex<Vec<crate::effect::EffectRecord>>);

        #[async_trait]
        impl AuditHandler for EffectSpy {
            async fn handle(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _decisions: &DecisionLog,
            ) {
            }

            async fn on_effect(
                &self,
                effect: &crate::effect::EffectRecord,
                _extensions: &Extensions,
            ) {
                self.0.lock().unwrap().push(effect.clone());
            }
        }

        let log = Arc::new(SpyLog::default());
        let spy = Arc::new(EffectSpy::default());
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(spy.clone())])
        .with_effect_log(log.clone());

        let acted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cfg = PluginConfig {
            name: "minter".into(),
            mode: PluginMode::Sequential,
            on_error: OnError::Ignore,
            ..Default::default()
        };
        let entry = HookEntry {
            plugin_ref: Arc::new(PluginRef::new(
                Arc::new(EffectPlugin {
                    cfg: cfg.clone(),
                    acted: Arc::clone(&acted),
                    refused: Arc::clone(&refused),
                }),
                cfg,
            )),
            handler: Arc::new(EffectPlugin {
                cfg: PluginConfig::default(),
                acted,
                refused,
            }),
        };

        let decision = run_with(&executor, std::slice::from_ref(&entry))
            .await
            .decision_log;
        let effects = spy.0.lock().unwrap().clone();

        // The mint recorded an intent and an outcome, taking emission 0 and 1,
        // and the decision that contained them was emitted after, taking 2.
        assert_eq!(effects.len(), 2);
        assert_eq!(effects[0].emission_seq, Some(0));
        assert_eq!(effects[1].emission_seq, Some(1));
        assert_eq!(decision.emission_seq(), Some(2));

        // Each stream still counts from zero in its own right.
        assert_eq!(effects[0].stream_seq, Some(0));
        assert_eq!(effects[1].stream_seq, Some(1));
        assert_eq!(decision.stream_seq(), Some(0));
        assert_eq!(effects[0].stream_id.as_deref(), Some("effect"));

        // The durable record carries no position, because the position is a
        // property of the stream a sink reconstructs and not of the write-ahead
        // record of what was attempted.
        let written = log.0.lock().unwrap().clone();
        assert_eq!(written.len(), 2);
        assert!(written.iter().all(|r| r.stream_seq.is_none()));
    }

    /// A refused write must not leave a hole in the stream.
    ///
    /// `begin_effect` is fail-closed, so a log that cannot take the intent
    /// correctly stops the act. Stamping before the append still spent a
    /// sequence number on it, and nothing was ever emitted under that number —
    /// so an ordinary disk error produced a gap, which a consumer holding the
    /// history is required to surface as a crashed emitter, a dropped record,
    /// or tampering.
    #[tokio::test]
    async fn a_refused_append_does_not_consume_a_sequence_number() {
        #[derive(Debug)]
        struct FlakyLog(std::sync::atomic::AtomicUsize);

        #[async_trait]
        impl crate::effect::DurableEffectLog for FlakyLog {
            async fn append(
                &self,
                _effect: &crate::effect::EffectRecord,
            ) -> Result<(), Box<PluginError>> {
                if self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                    return Err(Box::new(PluginError::Config {
                        message: "the disk said no".into(),
                    }));
                }
                Ok(())
            }
        }

        #[derive(Default)]
        struct EffectSpy(Mutex<Vec<crate::effect::EffectRecord>>);

        #[async_trait]
        impl AuditHandler for EffectSpy {
            async fn handle(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _decisions: &DecisionLog,
            ) {
            }

            async fn on_effect(
                &self,
                effect: &crate::effect::EffectRecord,
                _extensions: &Extensions,
            ) {
                self.0.lock().unwrap().push(effect.clone());
            }
        }

        let spy = Arc::new(EffectSpy::default());
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 5,
            ..Default::default()
        })
        .with_audit_handlers(vec![sink(spy.clone())])
        .with_effect_log(Arc::new(FlakyLog(std::sync::atomic::AtomicUsize::new(0))));

        let acted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cfg = PluginConfig {
            name: "minter".into(),
            mode: PluginMode::Sequential,
            on_error: OnError::Ignore,
            ..Default::default()
        };
        let entry = HookEntry {
            plugin_ref: Arc::new(PluginRef::new(
                Arc::new(EffectPlugin {
                    cfg: cfg.clone(),
                    acted: Arc::clone(&acted),
                    refused: Arc::clone(&refused),
                }),
                cfg,
            )),
            handler: Arc::new(EffectPlugin {
                cfg: PluginConfig::default(),
                acted,
                refused,
            }),
        };

        // The first append is refused, so the intent is never recorded and the
        // act never runs. The second invocation's intent lands.
        run_with(&executor, std::slice::from_ref(&entry)).await;
        run_with(&executor, std::slice::from_ref(&entry)).await;

        let effects = spy.0.lock().unwrap().clone();
        assert!(
            !effects.is_empty(),
            "the second invocation reached the sink"
        );
        assert_eq!(
            effects[0].stream_seq,
            Some(0),
            "the stream opens at 0: the refused write took no number with it"
        );
        let seqs: Vec<u64> = effects.iter().filter_map(|r| r.stream_seq).collect();
        assert!(
            seqs.windows(2).all(|w| w[1] == w[0] + 1),
            "and stays dense: {seqs:?}"
        );
    }
}
