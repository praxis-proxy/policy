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

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tracing::{error, warn};

use crate::context::PluginContextTable;
use crate::error::PluginError;
use crate::extensions::filter_extensions;
use crate::hooks::payload::{Extensions, PluginPayload, WriteToken};
use crate::plugin::OnError;
use crate::registry::{HookEntry, group_by_mode};

/// Configuration for the executor.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum execution time per plugin in seconds.
    pub timeout_seconds: u64,

    /// Whether to halt on the first deny in concurrent mode.
    pub short_circuit_on_deny: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            short_circuit_on_deny: true,
        }
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

    /// The final extensions after all modifications.
    /// `None` if no plugin modified extensions.
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
        }
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
/// The executor is stateless — all state comes from the arguments.
/// One executor instance can serve multiple concurrent hook invocations.
#[derive(Clone)]
pub struct Executor {
    config: ExecutorConfig,
}

impl Executor {
    /// Create a new executor with the given configuration.
    pub fn new(config: ExecutorConfig) -> Self {
        Self { config }
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
    ///   extensions, violation, and context table.
    /// - `BackgroundTasks` — handles to fire-and-forget tasks. Call
    ///   `wait_for_background_tasks()` to await them, or drop to let
    ///   them complete in the background.
    pub async fn execute(
        &self,
        entries: &[HookEntry],
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
        task_tracker: &tokio_util::task::TaskTracker,
    ) -> (PipelineResult, BackgroundTasks) {
        let mut ctx_table = context_table.unwrap_or_default();

        if entries.is_empty() {
            return (
                PipelineResult::allowed_with(payload, extensions, ctx_table),
                BackgroundTasks::empty(),
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
                &mut payload_modified,
            )
            .await
        {
            return (
                PipelineResult::denied(v, current_extensions, ctx_table).with_errors(errors),
                BackgroundTasks::empty(),
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
            &mut payload_modified,
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
            )
            .await
        {
            return (
                PipelineResult::denied(violation, current_extensions, ctx_table)
                    .with_errors(errors),
                BackgroundTasks::empty(),
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

        (
            PipelineResult::allowed_with(current_payload, current_extensions, ctx_table)
                .with_errors(errors)
                .with_payload_modified(payload_modified),
            BackgroundTasks::from_handles(bg_handles),
        )
    }

    /// Run a serial phase — plugins execute one at a time, each seeing
    /// the (possibly modified) payload from the previous.
    ///
    /// The framework retains ownership of the payload. Handlers receive
    /// a borrow and clone only if they modify. Modified payloads in
    /// the result replace the current payload.
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
        payload_modified: &mut bool,
    ) -> Option<crate::error::PluginViolation> {
        for entry in entries {
            // Borrow names/ids on the happy path — allocate only when
            // building a violation or stashing the local_state back into
            // the table. Previously `name.to_string()` + `id.to_string()`
            // ran unconditionally on every plugin per invoke.
            let plugin_name = entry.plugin_ref.name();
            let plugin_id = entry.plugin_ref.id();
            let on_error = entry.plugin_ref.trusted_config().on_error;

            // Take this plugin's context out of the table — pulls its stored
            // local_state and seeds global_state from the canonical store.
            // Replaces the previous values().last() seed, which was
            // non-deterministic across HashMap iteration orders.
            let mut ctx = ctx_table.take_context(plugin_id);

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

            // Execute with timeout — handler borrows payload, gets filtered extensions
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
            let result = timeout(
                timeout_dur,
                entry.handler.invoke(&**payload, &filtered, &mut ctx),
            )
            .await;

            match result {
                Ok(Ok(result_box)) => {
                    if let Some(erased) = extract_erased(result_box) {
                        if !erased.continue_processing
                            && can_block
                            && let Some(mut v) = erased.violation
                        {
                            v.plugin_name = Some(plugin_name.to_owned());
                            return Some(v);
                        }

                        // Accept modifications
                        if can_modify {
                            if let Some(mp) = erased.modified_payload {
                                *payload = mp;
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
                                }
                            }
                        }

                        // Plugin writes to ctx.global_state are committed back
                        // to the canonical store via store_context() below.
                    }
                    // If extract failed or no modifications — payload unchanged
                },
                Ok(Err(e)) => {
                    error!("{} plugin '{}' failed: {}", phase_label, plugin_name, e);
                    match on_error {
                        OnError::Fail if can_block => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_error",
                                format!("Plugin '{plugin_name}' failed: {e}"),
                            );
                            v.plugin_name = Some(plugin_name.to_owned());
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
                },
                Err(_) => {
                    error!("{} plugin '{}' timed out", phase_label, plugin_name);
                    let timeout_err = crate::error::PluginError::Timeout {
                        plugin_name: plugin_name.to_owned(),
                        timeout_ms: u64::try_from(timeout_dur.as_millis()).unwrap_or(u64::MAX),
                        proto_error_code: None,
                    };
                    match on_error {
                        OnError::Fail if can_block => {
                            let mut v = crate::error::PluginViolation::new(
                                "plugin_timeout",
                                format!("Plugin '{plugin_name}' timed out"),
                            );
                            v.plugin_name = Some(plugin_name.to_owned());
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
                },
            }

            // Commit this plugin's context back to the table — replaces the
            // canonical global_state with its (possibly modified) copy and
            // stores the local_state for the next hook invocation. The
            // global_state move is free; only the local_state insert allocates.
            ctx_table.store_context(plugin_id, ctx);
        }

        None // no denial
    }

    /// Run a read-only phase — plugins receive &payload, results discarded.
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
            let mut ctx = ctx_table.snapshot_context(plugin_id);
            // Filter extensions per plugin — read-only, no write tokens.
            let capabilities: std::collections::HashSet<String> = entry
                .plugin_ref
                .trusted_config()
                .capabilities
                .iter()
                .cloned()
                .collect();
            let filtered = filter_extensions(extensions, &capabilities);
            let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

            let result = timeout(
                timeout_dur,
                entry.handler.invoke(payload, &filtered, &mut ctx),
            )
            .await;

            // Audit / fire-and-forget cannot block, so OnError::Fail can't
            // halt the pipeline — but OnError::Disable must still take a
            // repeatedly-failing plugin out of rotation. The previous code
            // ignored on_error entirely, so Disable plugins kept failing
            // forever no matter how many invocations errored. All non-halt
            // failures also push a record into PipelineResult.errors.
            match result {
                Ok(Ok(_)) => {}, // read-only — discard result and ext_clone
                Ok(Err(e)) => {
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
                Err(_) => {
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
            let filtered = Arc::new(filter_extensions(extensions, &capabilities));

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
                        // `Some(..)` with continue_processing=true, OR
                        // `None` (downcast failed — historically logged
                        // and treated as Allow) both fall through.
                        _ => BranchData::Allow,
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

            match outcome {
                BranchOutcome::Completed(BranchData::Allow) => {},
                BranchOutcome::Completed(BranchData::Deny(opt_v)) => {
                    let violation = opt_v.unwrap_or_else(|| {
                        let mut v = crate::error::PluginViolation::new(
                            "concurrent_deny",
                            format!("Plugin '{plugin_name}' denied"),
                        );
                        v.plugin_name = Some(plugin_name.to_owned());
                        v
                    });
                    if first_violation.is_none() {
                        first_violation = Some(violation);
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
            let filtered = Arc::new(filter_extensions(extensions, &capabilities));

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
/// the wrong type — a framework bug, not a plugin error).
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

    use crate::context::PluginContext;
    use crate::plugin::{Plugin, PluginConfig, PluginMode};
    use crate::registry::{AnyHookHandler, PluginRef};
    use async_trait::async_trait;

    /// How a mock branch fails.
    #[derive(Clone, Copy)]
    enum Failure {
        Error,
        Hang,
        Panic,
        None,
    }

    struct MockPlugin(PluginConfig);

    #[async_trait]
    impl Plugin for MockPlugin {
        fn config(&self) -> &PluginConfig {
            &self.0
        }
    }

    struct MockHandler(Failure);

    #[async_trait]
    impl AnyHookHandler for MockHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            match self.0 {
                Failure::Error => Err(Box::new(PluginError::Execution {
                    plugin_name: "mock".into(),
                    message: "simulated failure".into(),
                    source: None,
                    code: None,
                    details: std::collections::HashMap::new(),
                    proto_error_code: None,
                })),
                // Longer than any timeout these tests configure, so the
                // executor's per-branch timeout is what ends it.
                Failure::Hang => {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    Ok(erase_result(PluginResult::<TestPayload>::allow()))
                },
                Failure::Panic => panic!("simulated panic inside a branch"),
                Failure::None => Ok(erase_result(PluginResult::<TestPayload>::allow())),
            }
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    fn concurrent_entry(name: &str, on_error: OnError, failure: Failure) -> HookEntry {
        let cfg = PluginConfig {
            name: name.into(),
            mode: PluginMode::Concurrent,
            on_error,
            ..Default::default()
        };
        HookEntry {
            plugin_ref: Arc::new(PluginRef::new(
                Arc::new(MockPlugin(cfg.clone())),
                cfg.clone(),
            )),
            handler: Arc::new(MockHandler(failure)),
        }
    }

    /// One concurrent plugin with the given failure and policy. Returns the
    /// pipeline result plus the entry so a test can check `is_disabled`.
    async fn run_one(failure: Failure, on_error: OnError) -> (PipelineResult, HookEntry) {
        // A short timeout so the Hang case does not stall the suite.
        let executor = Executor::new(ExecutorConfig {
            timeout_seconds: 1,
            short_circuit_on_deny: true,
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
        let (r, entry) = run_one(Failure::None, OnError::Fail).await;
        assert!(r.continue_processing, "no failure, so no halt");
        assert!(r.errors.is_empty(), "and nothing to report");
        assert!(!entry.plugin_ref.is_disabled());
    }

    // ---- returned error ---------------------------------------------------

    #[tokio::test]
    async fn a_concurrent_error_under_fail_halts_and_names_the_plugin() {
        let (r, _) = run_one(Failure::Error, OnError::Fail).await;
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
        let (r, entry) = run_one(Failure::Error, OnError::Ignore).await;
        assert!(r.continue_processing, "on_error: ignore must not halt");
        assert_eq!(r.errors.len(), 1, "and must still report the error");
        assert!(
            !entry.plugin_ref.is_disabled(),
            "ignore does not disable the plugin"
        );
    }

    #[tokio::test]
    async fn a_concurrent_error_under_disable_continues_and_disables() {
        let (r, entry) = run_one(Failure::Error, OnError::Disable).await;
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
        let (r, _) = run_one(Failure::Hang, OnError::Fail).await;
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
        let (r, entry) = run_one(Failure::Hang, OnError::Ignore).await;
        assert!(r.continue_processing);
        assert_eq!(r.errors.len(), 1);
        assert!(!entry.plugin_ref.is_disabled());
    }

    #[tokio::test]
    async fn a_concurrent_timeout_under_disable_continues_and_disables() {
        let (r, entry) = run_one(Failure::Hang, OnError::Disable).await;
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
        let (r, _) = run_one(Failure::Panic, OnError::Fail).await;
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
        let (r, entry) = run_one(Failure::Panic, OnError::Ignore).await;
        assert!(
            r.continue_processing,
            "a panicking plugin under ignore must not halt the pipeline"
        );
        assert_eq!(r.errors.len(), 1);
        assert!(!entry.plugin_ref.is_disabled());
    }

    #[tokio::test]
    async fn a_concurrent_panic_under_disable_continues_and_disables() {
        let (r, entry) = run_one(Failure::Panic, OnError::Disable).await;
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
        });
        let entries = vec![
            concurrent_entry("lenient", OnError::Ignore, Failure::Error),
            concurrent_entry("strict", OnError::Fail, Failure::Error),
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
