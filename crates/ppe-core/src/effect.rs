// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Irreversible external effects, and the write-ahead log that records them.
//
// A decision record says what the engine ruled. It does not say what a
// plugin *did* to the outside world on the way: a token minted at an IdP,
// an approval granted. Those are irreversible and outlive the request, so
// recording them after the fact is not enough. A process that dies between
// "about to mint" and "minted" leaves no trace either way.
//
// The protocol is two-phase. A plugin durably records its intent before it
// acts, and records the outcome after. If the intent cannot be recorded the
// act does not happen (fail-closed), so a completed act always has a record.
// If the process dies in between, recovery finds the intent with no outcome
// and reconciles it against the participant.
//
// All of it is opt-in. With no log configured a plugin's effects run exactly
// as they would have, recording nothing.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::error::PluginError;

/// Where an effect is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    /// Intent durably recorded; nothing external has happened yet.
    Prepared,
    /// The external act completed.
    Confirmed,
    /// The external act provably did not happen.
    Rejected,
    /// The outcome is not known: the process died after the act, or the call
    /// failed in a way that does not say whether it landed. Resolved by
    /// reconciling against the participant via [`EffectRecord::key`].
    Unknown,
}

/// A record of one irreversible external effect.
///
/// The causing plugin fills the descriptive fields. The framework stamps
/// `plugin_name`, so a record cannot claim to come from a plugin that did not
/// produce it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EffectRecord {
    /// Machine-readable kind, e.g. `"token_mint"`, `"approval_grant"`.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// Reconciliation key, threaded into the external call so an `Unknown`
    /// outcome can be resolved against the participant later.
    ///
    /// Must be **unique per attempt**. Recovery resolves keys across the whole
    /// log, so a key reused across retries lets an earlier attempt's terminal
    /// record mask a later attempt's orphaned intent, and the later attempt is
    /// then treated as complete when nobody knows whether it happened.
    pub key: String,
    /// Where in its lifecycle this record is.
    pub state: EffectState,
    /// Structured, effect-specific detail (audience, scopes, ttl).
    pub details: HashMap<String, serde_json::Value>,
    /// Which plugin caused the effect. Stamped by the framework, never
    /// self-reported.
    pub plugin_name: Option<String>,

    /// The executor generation this record was emitted in, as Unix
    /// nanoseconds. Ordered, so a larger value marks a restart and a verifier
    /// can tell a counter reset from records that went missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,

    /// The per-type stream this record belongs to, which scopes `stream_seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Completeness counter, gap-free within `(epoch, stream_id)`. A gap means
    /// an effect record was lost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_seq: Option<u64>,

    /// Ordering counter, shared with the decision stream, so effects and
    /// decisions can be interleaved back into the order they happened. Sparse
    /// for a reader of one stream, which is not a loss signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emission_seq: Option<u64>,
}

impl EffectRecord {
    /// A fresh record of intent, before the act. `key` is the reconciliation
    /// key that rides into the external call.
    pub fn prepared(
        kind: impl Into<String>,
        description: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            key: key.into(),
            state: EffectState::Prepared,
            details: HashMap::new(),
            plugin_name: None,
            epoch: None,
            stream_id: None,
            stream_seq: None,
            emission_seq: None,
        }
    }

    /// Attach a structured detail.
    #[must_use]
    pub fn with_detail(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Move to another lifecycle state.
    #[must_use]
    pub fn into_state(mut self, state: EffectState) -> Self {
        self.state = state;
        self
    }
}

/// Resolves an effect left `Unknown` by asking an authoritative ledger whether
/// the act identified by [`EffectRecord::key`] actually happened.
///
/// The record is self-describing, so a reconciler reads its fields and performs
/// a keyed lookup. It needs no knowledge of which plugin caused the effect.
/// Returning [`EffectState::Unknown`] leaves the record for a later sweep.
///
/// Most participants expose no lookup by mint key, which is why
/// [`LogUnknownsReconciler`] is the default.
#[async_trait]
pub trait EffectReconciler: Send + Sync {
    /// Decide the terminal state of one unresolved effect.
    async fn reconcile(&self, effect: &EffectRecord) -> EffectState;
}

/// The default reconciler: there is no ledger to query, so it logs each
/// unresolved effect and leaves it `Unknown` for an operator.
///
/// This is the correct behaviour for a participant with no keyed lookup, which
/// today is all of them. Claiming `Rejected` instead would assert that a mint
/// did not happen when nobody knows.
#[derive(Debug, Default)]
pub struct LogUnknownsReconciler;

#[async_trait]
impl EffectReconciler for LogUnknownsReconciler {
    async fn reconcile(&self, effect: &EffectRecord) -> EffectState {
        tracing::warn!(
            effect_key = %effect.key,
            kind = %effect.kind,
            plugin = effect.plugin_name.as_deref().unwrap_or("?"),
            "effect left unresolved after a restart and no ledger can confirm it; \
             leaving it unknown for investigation"
        );
        EffectState::Unknown
    }
}

/// A durable, append-only sink for effect records: the write-ahead log.
///
/// `append` must not return `Ok` until the record is on stable storage. An
/// `Err` means the caller must not perform the act, which is what makes the
/// write-ahead guarantee real.
///
/// Implemented by a host that wants effects recorded somewhere other than a
/// file. [`FileEffectLog`] is the built-in implementation.
#[async_trait]
pub trait DurableEffectLog: Send + Sync + std::fmt::Debug {
    /// Durably record one effect.
    ///
    /// # Errors
    ///
    /// Returns an error when the record could not be persisted. The caller
    /// treats this as fail-closed and does not act.
    async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>>;

    /// Recover after a restart: drop completed effects and reconcile the
    /// unresolved ones, recording each resolved outcome durably.
    ///
    /// The default is a no-op, for logs with no recoverable on-disk state.
    ///
    /// # Errors
    ///
    /// Returns an error when the log cannot be read or rewritten.
    async fn recover_and_reconcile(
        &self,
        _reconciler: &dyn EffectReconciler,
    ) -> Result<RecoveryOutcome, Box<PluginError>> {
        Ok(RecoveryOutcome::default())
    }
}

/// What a recovery sweep settled and what it could not.
///
/// `resolved` exists because the answer reconciliation produced is otherwise
/// unobservable: it is appended and compacted away in the same call, so
/// nothing outside the log ever learns that the mint nobody could account for
/// turned out to have landed. The caller emits these to the audit sinks, which
/// is the only place that answer reaches anyone.
#[derive(Debug, Default)]
pub struct RecoveryOutcome {
    /// Effects reconciliation moved to a terminal state, in the order it
    /// settled them. Already durable when this returns.
    pub resolved: Vec<EffectRecord>,
    /// Effects still unresolved, retained in the log for a later sweep.
    pub unresolved: Vec<EffectRecord>,
}

/// Appends between automatic compactions. Effects are rare, so this bounds the
/// file without paying a rewrite per write.
const DEFAULT_COMPACTION_THRESHOLD: usize = 1024;

/// A file-backed write-ahead log. Each record is one JSON line, `fsync`'d
/// before `append` returns, so an intent is on stable storage before the act.
///
/// The append and `fsync` run on a blocking thread: a synchronous `fsync` must
/// never stall an async worker. The file is opened per append, which is fine
/// because effects are rare.
#[derive(Debug, Clone)]
pub struct FileEffectLog {
    path: Arc<std::path::PathBuf>,
    /// Serializes appends. `O_APPEND` makes each write land at the end of the
    /// file, but `write_all`'s partial-write loop leaves a window where two
    /// writers could interleave one record with another. One writer at a time
    /// closes it and gives recovery a deterministic order to read back.
    /// Cloned handles share the lock, because they share the file.
    write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Appends since the last compaction, shared across cloned handles.
    appends_since_compaction: Arc<AtomicUsize>,
    /// Auto-compaction fires after this many appends. `0` disables it, leaving
    /// compaction to an explicit recovery.
    compaction_threshold: usize,
}

impl FileEffectLog {
    /// A log appending to `path`, creating the file if it does not exist.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            appends_since_compaction: Arc::new(AtomicUsize::new(0)),
            compaction_threshold: DEFAULT_COMPACTION_THRESHOLD,
        }
    }

    /// Override the append count that triggers automatic compaction. `0`
    /// disables it.
    #[must_use]
    pub fn with_compaction_threshold(mut self, threshold: usize) -> Self {
        self.compaction_threshold = threshold;
        self
    }
}

#[async_trait]
impl DurableEffectLog for FileEffectLog {
    async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>> {
        let mut line = serde_json::to_vec(effect)
            .map_err(|e| wal_error("serialize effect record", Some(Box::new(e))))?;
        line.push(b'\n');

        let path = Arc::clone(&self.path);
        // The lock is released before any compaction below: `recover` takes
        // the same lock, so holding it across the call would deadlock.
        {
            let _guard = self.write_lock.lock().await;
            tokio::task::spawn_blocking(move || -> Result<(), Box<PluginError>> {
                use std::io::Write as _;
                // Whether this call is what brings the file into existence.
                // `fsync` on a file does not make its directory entry durable,
                // so without the extra sync below a crash right after the
                // first append can leave no file at all, and the intent this
                // call promised to record would be gone while the act it
                // guarded had already happened.
                let creating = !path.exists();
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path.as_ref())
                    .map_err(|e| wal_error("open the log", Some(Box::new(e))))?;
                file.write_all(&line)
                    .map_err(|e| wal_error("write a record", Some(Box::new(e))))?;
                // The durability barrier. The record is on stable storage
                // before this returns, and therefore before the caller acts.
                file.sync_all()
                    .map_err(|e| wal_error("fsync the log", Some(Box::new(e))))?;
                if creating {
                    sync_parent_dir(path.as_ref())?;
                }
                Ok(())
            })
            .await
            .map_err(|e| wal_error("the append task failed", Some(Box::new(e))))??;
        }

        // Bound the file. A compaction failure is logged rather than returned:
        // the record above is already durable, so the append succeeded, and
        // reporting failure here would stop an act that has every right to
        // proceed.
        if self.compaction_threshold != 0 {
            let n = self
                .appends_since_compaction
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            if n >= self.compaction_threshold {
                self.appends_since_compaction.store(0, Ordering::Relaxed);
                if let Err(e) = self.recover().await {
                    tracing::warn!("effect log auto-compaction failed: {e}");
                }
            }
        }

        Ok(())
    }

    async fn recover_and_reconcile(
        &self,
        reconciler: &dyn EffectReconciler,
    ) -> Result<RecoveryOutcome, Box<PluginError>> {
        let summary = self.recover().await?;
        let mut outcome = RecoveryOutcome::default();
        for rec in summary.unresolved {
            match reconciler.reconcile(&rec).await {
                state @ (EffectState::Confirmed | EffectState::Rejected) => {
                    let settled = rec.into_state(state);
                    self.append(&settled).await?;
                    // Returned rather than dropped: the compaction below
                    // erases the pair, so this record is the only trace of
                    // what reconciliation concluded, and the caller emits it.
                    outcome.resolved.push(settled);
                },
                // Still unresolved. Keep it for the next sweep.
                _ => outcome.unresolved.push(rec),
            }
        }
        if !outcome.resolved.is_empty() {
            // A second pass drops the pairs the reconciler just completed.
            self.recover().await?;
        }
        Ok(outcome)
    }
}

/// `fsync` the directory holding `path`, making a file creation or a rename in
/// it durable.
///
/// A file's own `fsync` covers its contents, not the directory entry that
/// names it. Both callers here change what the directory holds.
fn sync_parent_dir(path: &std::path::Path) -> Result<(), Box<PluginError>> {
    // A bare filename has an empty parent, which is the current directory.
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| wal_error("fsync the log's directory", Some(Box::new(e))))
}

/// The error a durable-write failure surfaces. `begin_effect` treats any error
/// from the log as fail-closed, so this is what stops an act from proceeding.
fn wal_error(
    what: &str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
) -> Box<PluginError> {
    PluginError::Execution {
        plugin_name: "effect-log".into(),
        message: format!("effect log: could not {what}"),
        source,
        code: Some("effect_log_failed".into()),
        details: HashMap::new(),
        proto_error_code: None,
    }
    .boxed()
}

/// What one recovery sweep found.
#[derive(Debug, Default)]
pub struct RecoverySummary {
    /// Effects that completed, an intent matched by a terminal record, and
    /// were dropped from the log.
    pub compacted: usize,
    /// Effects with no terminal record: an intent whose act may or may not
    /// have happened, or an explicit unknown. Each needs reconciling against
    /// the participant via its `key`. These are retained in the rewritten log.
    pub unresolved: Vec<EffectRecord>,
}

impl FileEffectLog {
    /// Read the log, drop completed effects, and rewrite the file with only
    /// the unresolved records.
    ///
    /// This is both the crash-recovery entry point and the compaction that
    /// bounds the file. Idempotent, and a missing file is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error when the log cannot be read, parsed, or rewritten.
    pub async fn recover(&self) -> Result<RecoverySummary, Box<PluginError>> {
        let path = Arc::clone(&self.path);
        // Held across the read and the rewrite so no append lands in between
        // and is lost to the rename.
        let _guard = self.write_lock.lock().await;
        tokio::task::spawn_blocking(move || -> Result<RecoverySummary, Box<PluginError>> {
            let raw = match std::fs::read(path.as_ref()) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RecoverySummary::default());
                },
                Err(e) => return Err(wal_error("read the log", Some(Box::new(e)))),
            };

            // Every complete append ends in a newline, so anything after the
            // last one is an append a crash interrupted part-way through
            // `write_all`. That is not corruption and must not stop recovery:
            // the record it would have written was never acknowledged, so the
            // act it guarded never proceeded, and the rewrite below drops it.
            //
            // Cut on bytes rather than reading the file as text first. A torn
            // write can land mid-character, and `read_to_string` on a file
            // ending in half a UTF-8 sequence fails the same permanent way a
            // parse error used to: recovery never completes, so reconciliation
            // never runs and compaction never bounds the file, while appends
            // keep succeeding because they never read it.
            let complete = match raw.iter().rposition(|b| *b == b'\n') {
                Some(end) => raw.get(..=end).unwrap_or_default(),
                // No newline anywhere: an empty file, or one holding nothing
                // but a single interrupted append.
                None => &[],
            };
            if complete.len() != raw.len() {
                tracing::warn!(
                    bytes = raw.len() - complete.len(),
                    "effect log: discarding an unterminated final line, an append a crash \
                     interrupted before it was acknowledged"
                );
            }
            // Past the tail, the file is what this process wrote and fsync'd.
            // A line that will not decode or parse here means it was damaged
            // after the fact, and recovery refuses rather than silently
            // dropping records that account for irreversible acts.
            let data = std::str::from_utf8(complete)
                .map_err(|e| wal_error("decode the log", Some(Box::new(e))))?;

            let mut records: Vec<EffectRecord> = Vec::new();
            for (i, line) in data.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let rec = serde_json::from_str(line)
                    .map_err(|e| wal_error(&format!("parse line {}", i + 1), Some(Box::new(e))))?;
                records.push(rec);
            }

            // A key is resolved when some record for it reached a terminal
            // state. Everything else is unresolved.
            //
            // This matches across the whole file, which is why `key` has to be
            // unique per attempt: a plugin reusing one key across retries would
            // let an earlier attempt's terminal record mask a later attempt's
            // orphaned intent, and recovery would skip the one act nobody can
            // account for.
            let resolved: std::collections::HashSet<&str> = records
                .iter()
                .filter(|r| matches!(r.state, EffectState::Confirmed | EffectState::Rejected))
                .map(|r| r.key.as_str())
                .collect();

            // Keep the latest record per unresolved key, in first-seen order.
            let mut unresolved: Vec<EffectRecord> = Vec::new();
            let mut pos: HashMap<String, usize> = HashMap::new();
            for r in &records {
                if resolved.contains(r.key.as_str()) {
                    continue;
                }
                if let Some(slot) = pos.get(&r.key).and_then(|&i| unresolved.get_mut(i)) {
                    *slot = r.clone();
                } else {
                    pos.insert(r.key.clone(), unresolved.len());
                    unresolved.push(r.clone());
                }
            }
            let compacted = resolved.len();

            // Write the survivors to a temp file, fsync, then rename over the
            // original. The rename is atomic, so a crash mid-compaction leaves
            // either the old log or the new one, never a truncated one.
            let tmp = path.with_extension("recover.tmp");
            {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&tmp)
                    .map_err(|e| wal_error("open the temp log", Some(Box::new(e))))?;
                for r in &unresolved {
                    let mut line = serde_json::to_vec(r)
                        .map_err(|e| wal_error("serialize during compaction", Some(Box::new(e))))?;
                    line.push(b'\n');
                    f.write_all(&line)
                        .map_err(|e| wal_error("write the temp log", Some(Box::new(e))))?;
                }
                f.sync_all()
                    .map_err(|e| wal_error("fsync the temp log", Some(Box::new(e))))?;
            }
            std::fs::rename(&tmp, path.as_ref())
                .map_err(|e| wal_error("rename the temp log", Some(Box::new(e))))?;
            // A rename is atomic but not automatically durable. Without this,
            // a crash can undo the compaction and bring the old file back.
            // That is safe, because recovery is idempotent and would simply
            // sweep it again, but it also leaves the temp file behind and the
            // compaction silently not applied.
            sync_parent_dir(path.as_ref())?;

            Ok(RecoverySummary {
                compacted,
                unresolved,
            })
        })
        .await
        .map_err(|e| wal_error("the recovery task failed", Some(Box::new(e))))?
    }
}

/// What an executor offers a plugin that performs an effect: the optional
/// write-ahead log and the audit sinks that observe effects.
///
/// Built once per executor and shared by `Arc`, because attaching it costs a
/// clone per plugin per request and effects are rare.
#[derive(Default)]
pub struct EffectSink {
    log: Option<Arc<dyn DurableEffectLog>>,
    handlers: Vec<crate::audit::AttachedSink>,
    /// Stream identity for effect records. The counters are shared with the
    /// executor: `emission_seq` in particular is the same counter decisions
    /// use, which is what lets the two streams be interleaved back into the
    /// order they happened.
    epoch: u64,
    stream_id: String,
    stream_seq: Arc<AtomicU64>,
    emission_seq: Arc<AtomicU64>,
    /// How long a sink gets before it is skipped, matching the decision path.
    handler_timeout: std::time::Duration,
}

/// The stream identity an executor hands its effect sink.
///
/// Kept separate from the log and the handlers so the counters stay shared
/// with the executor. Recreating them per sink would restart the sequences and
/// break the completeness claim.
pub struct EffectStream {
    /// Executor generation, as Unix nanoseconds.
    pub epoch: u64,
    /// The composed per-type stream id for effects.
    pub stream_id: String,
    /// Effect completeness counter, gap-free within `(epoch, stream_id)`.
    pub stream_seq: Arc<AtomicU64>,
    /// Ordering counter shared with the decision stream.
    pub emission_seq: Arc<AtomicU64>,
    /// Per-sink budget before a slow sink is skipped.
    pub handler_timeout: std::time::Duration,
}

impl std::fmt::Debug for EffectSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectSink")
            .field("log", &self.log.is_some())
            .field("handlers", &self.handlers.len())
            .finish()
    }
}

impl EffectSink {
    /// A sink recording to `log` and notifying `handlers`. Either may be
    /// empty: a host that configured a log but no sink still gets durability,
    /// and one that configured sinks but no log still gets the events.
    pub fn new(
        log: Option<Arc<dyn DurableEffectLog>>,
        handlers: Vec<crate::audit::AttachedSink>,
        stream: EffectStream,
    ) -> Self {
        Self {
            log,
            handlers,
            epoch: stream.epoch,
            stream_id: stream.stream_id,
            stream_seq: stream.stream_seq,
            emission_seq: stream.emission_seq,
            handler_timeout: stream.handler_timeout,
        }
    }

    /// Whether this sink would record anything at all.
    pub fn is_empty(&self) -> bool {
        self.log.is_none() && self.handlers.is_empty()
    }

    /// The durable log, for the engine to run recovery against.
    pub fn log(&self) -> Option<Arc<dyn DurableEffectLog>> {
        self.log.clone()
    }

    /// Stamp a record into this stream and hand it to every sink.
    ///
    /// Writes nothing: each caller has its own durability story.
    /// `Extensions::emit_effect` appends first, because a sink must never see
    /// an act the log rejected. Recovery has already appended by the time it
    /// gets here.
    pub(crate) async fn notify(
        &self,
        mut record: EffectRecord,
        extensions: &crate::hooks::payload::Extensions,
    ) {
        self.stamp(&mut record);
        self.dispatch(&record, extensions).await;
    }

    /// Place a record in this stream. The counters are the executor's, so a
    /// record cannot put itself anywhere it likes.
    fn stamp(&self, record: &mut EffectRecord) {
        record.epoch = Some(self.epoch);
        record.stream_id = Some(self.stream_id.clone());
        record.stream_seq = Some(self.stream_seq.fetch_add(1, Ordering::Relaxed));
        record.emission_seq = Some(self.emission_seq.fetch_add(1, Ordering::Relaxed));
    }

    /// Hand one already-stamped record to every attached sink.
    async fn dispatch(
        &self,
        record: &EffectRecord,
        extensions: &crate::hooks::payload::Extensions,
    ) {
        // Isolated the way the decision emit is. This runs inside
        // `perform_effect`, between recording the intent and the act, so a
        // sink that panicked or hung here would take down the mint it is only
        // observing.
        use futures::FutureExt as _;
        for observer in &self.handlers {
            // `extensions` is the acting plugin's view, and it carries that
            // plugin's live effect slot. Handing it over would let a sink append
            // records under the name of the plugin it is watching, which for a
            // log whose purpose is accounting is worse than a missing record.
            // Filtering rebuilds the view against the sink's own capabilities
            // and leaves the effect slot detached.
            let view = observer.view(extensions);
            let call = std::panic::AssertUnwindSafe(observer.handler().on_effect(record, &view))
                .catch_unwind();
            match tokio::time::timeout(self.handler_timeout, call).await {
                Ok(Ok(())) => {},
                Ok(Err(_panic)) => {
                    tracing::error!(
                        "audit sink '{}' panicked observing an effect, contained",
                        observer.name()
                    );
                },
                Err(_elapsed) => {
                    tracing::error!(
                        "audit sink '{}' exceeded {}s observing an effect, skipped",
                        observer.name(),
                        self.handler_timeout.as_secs()
                    );
                },
            }
        }
    }
}

/// Whether the plugin holding these extensions may perform an irreversible
/// effect, and where the record goes if it does.
///
/// The payload is private and the type is deliberately not `Clone`. A plugin
/// that could take the `Arc` out, or clone the slot from the `&Extensions` it
/// is lent, could append records outside any invocation and under a
/// `plugin_name` it chose. For a log whose purpose is accounting for
/// irreversible acts, a forged record is worse than a missing one: a gap is
/// visible, a forgery is not.
///
/// The field on `Extensions` has to stay public, because functional-update
/// construction (`..Default::default()`) is used at hundreds of sites and Rust
/// forbids it when any field is invisible. A public *field* need not imply a
/// public *payload*, and the missing `Clone` is what closes the rest: without
/// it there is no way to take a copy out of the borrowed `Extensions` a plugin
/// is lent, so the slot cannot outlive the invocation it was built for.
///
/// ```compile_fail
/// use praxis_policy_core::effect::EffectLogSlot;
/// use praxis_policy_core::hooks::payload::Extensions;
/// let ext = Extensions::default();
/// let _stashed: EffectLogSlot = ext.effect_log.clone();
/// ```
#[derive(Debug, Default)]
pub struct EffectLogSlot(EffectLogState);

#[derive(Debug, Default)]
enum EffectLogState {
    /// Not the extensions a handler was given: a copy, or one built by hand.
    ///
    /// The default, and what `Extensions::clone` produces. Effects are refused
    /// here because a copy is detached from the invocation that authorized
    /// them. Without this, a plugin in a phase that may not act could clone
    /// its extensions and perform the act through the copy, and a plugin that
    /// may act could clone away the recording. The executor sets a real state
    /// on every view it hands a plugin, so this is only ever reached through a
    /// copy.
    #[default]
    Detached,
    /// Effects may be performed and nothing records them. What a host that
    /// configured no auditing gets: a plugin's effects run exactly as they
    /// would have.
    Unrecorded,
    /// Effects may be performed and are recorded.
    Recorded {
        sink: Arc<EffectSink>,
        /// Stamped onto every record, so attribution comes from the executor
        /// rather than from whatever the plugin put in the record.
        plugin_name: Arc<str>,
    },
    /// Effects may not be performed from this phase.
    NotPermitted {
        mode: crate::plugin::PluginMode,
        /// Named in the error, so an operator is told which plugin to move
        /// rather than being pointed at the framework.
        plugin_name: Arc<str>,
    },
}

impl EffectLogSlot {
    /// Effects permitted, nothing recording them.
    #[must_use]
    pub fn unrecorded() -> Self {
        Self(EffectLogState::Unrecorded)
    }

    /// Effects permitted and recorded, attributed to `plugin_name`.
    #[must_use]
    pub fn recorded(sink: Arc<EffectSink>, plugin_name: &str) -> Self {
        Self(EffectLogState::Recorded {
            sink,
            plugin_name: Arc::from(plugin_name),
        })
    }

    /// Effects refused, because this phase cannot perform them soundly.
    #[must_use]
    pub fn not_permitted(mode: crate::plugin::PluginMode, plugin_name: &str) -> Self {
        Self(EffectLogState::NotPermitted {
            mode,
            plugin_name: Arc::from(plugin_name),
        })
    }

    /// Whether an effect performed here would be recorded anywhere.
    #[must_use]
    pub fn is_recorded(&self) -> bool {
        matches!(self.0, EffectLogState::Recorded { .. })
    }
}

/// The error a plugin gets for performing an effect through a copy of its
/// extensions rather than the ones it was handed.
fn detached_error() -> Box<PluginError> {
    PluginError::Execution {
        plugin_name: "effect".into(),
        message: "these extensions are a copy, not the ones this handler was given, so the \
                  effect cannot be attributed to an invocation or recorded against it. \
                  Perform effects on the `&Extensions` passed to `handle`."
            .into(),
        source: None,
        code: Some("effect_extensions_detached".into()),
        details: HashMap::new(),
        proto_error_code: None,
    }
    .boxed()
}

/// The error a plugin gets for performing an effect from a phase that cannot
/// support one. It names the fix, because the alternative is a mint that runs
/// with no record and no complaint.
fn phase_error(mode: crate::plugin::PluginMode, plugin_name: &str) -> Box<PluginError> {
    PluginError::Execution {
        plugin_name: plugin_name.to_owned(),
        message: format!(
            "cannot perform an irreversible effect from {mode:?} mode. Work in this phase is \
             cancelled or discarded when the pipeline short-circuits, and an external act \
             cannot be taken back, so set this plugin's `mode:` to sequential or transform, \
             where it runs to completion and its result is honored."
        ),
        source: None,
        code: Some("effect_phase_not_permitted".into()),
        details: HashMap::new(),
        proto_error_code: None,
    }
    .boxed()
}

impl crate::hooks::payload::Extensions {
    /// Record the intent to perform an irreversible effect, before performing
    /// it.
    ///
    /// Fail-closed when a log is configured: an error means the intent is not
    /// on stable storage, so the caller must not act. With no log configured
    /// this records nothing and returns `Ok`, which is what makes auditing
    /// optional rather than load-bearing.
    ///
    /// Prefer [`Self::perform_effect`], which brackets the act so the protocol
    /// cannot be skipped or reordered.
    ///
    /// # Errors
    ///
    /// Returns an error when this phase may not perform effects, or when a
    /// configured log could not durably record the intent.
    pub async fn begin_effect(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>> {
        self.emit_effect(effect, EffectState::Prepared).await
    }

    /// Record how an effect turned out.
    ///
    /// Unlike [`Self::begin_effect`] this is not fail-closed: the act has
    /// already happened, so a write failure here cannot un-happen it. The
    /// record stays unresolved for recovery to reconcile, and the caller is
    /// free to log and carry on.
    ///
    /// # Errors
    ///
    /// Returns an error when this phase may not perform effects, or when a
    /// configured log could not record the outcome.
    pub async fn complete_effect(
        &self,
        effect: &EffectRecord,
        state: EffectState,
    ) -> Result<(), Box<PluginError>> {
        self.emit_effect(effect, state).await
    }

    /// Perform an irreversible external act under write-ahead recording.
    ///
    /// Brackets `act` between a fail-closed [`Self::begin_effect`] and a
    /// best-effort [`Self::complete_effect`], so a caller cannot skip,
    /// reorder, or forget the protocol.
    ///
    /// - If the intent cannot be recorded, `act` never runs.
    /// - On success the effect is recorded `Confirmed`.
    /// - On failure it is recorded `Unknown`, not `Rejected`. A call that
    ///   errored may still have landed at the participant, with the response
    ///   lost on the way back, so recovery reconciles it by `key` instead of
    ///   asserting it did not happen.
    ///
    /// # Errors
    ///
    /// Returns the write-ahead failure when the intent could not be recorded,
    /// otherwise whatever `act` returned.
    pub async fn perform_effect<F, Fut, T>(
        &self,
        effect: &EffectRecord,
        act: F,
    ) -> Result<T, Box<PluginError>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Box<PluginError>>>,
    {
        self.begin_effect(effect).await?;

        let outcome = act().await;

        let terminal = if outcome.is_ok() {
            EffectState::Confirmed
        } else {
            EffectState::Unknown
        };
        if let Err(e) = self.complete_effect(effect, terminal).await {
            tracing::warn!(
                effect_key = %effect.key,
                "the outcome of an effect was not recorded: {e}"
            );
        }

        outcome
    }

    /// Write one lifecycle record, then tell the audit sinks about it.
    async fn emit_effect(
        &self,
        effect: &EffectRecord,
        state: EffectState,
    ) -> Result<(), Box<PluginError>> {
        let (sink, plugin_name) = match &self.effect_log.0 {
            EffectLogState::Unrecorded => return Ok(()),
            EffectLogState::Detached => return Err(detached_error()),
            EffectLogState::NotPermitted { mode, plugin_name } => {
                return Err(phase_error(*mode, plugin_name));
            },
            EffectLogState::Recorded { sink, plugin_name } => (sink, plugin_name),
        };

        let mut record = effect.clone().into_state(state);
        // Attribution comes from the executor, so a record cannot claim to come
        // from a plugin that did not produce it.
        record.plugin_name = Some(plugin_name.to_string());

        // Durability first. A sink that saw the event while the log rejected
        // it would report an act the write-ahead guarantee says never happened.
        if let Some(log) = &sink.log {
            log.append(&record).await?;
        }

        // Stamped only now, because taking a sequence number is a promise to
        // emit the record that holds it.
        //
        // `stream_seq` is dense per (epoch, stream_id) and opens at 0, and a
        // consumer holding the history is required to treat a gap as a crashed
        // emitter, a dropped record, or tampering rather than renumber around
        // it. Stamping before the append broke that for an ordinary reason: a
        // refused write is fail-closed, so the act correctly does not happen —
        // but the number was already spent and nothing was ever emitted under
        // it, leaving a hole a verifier has to read as evidence of something
        // far worse than the disk error it actually was.
        //
        // The cost is that the durable record carries no stream position. That
        // is the right side to lose it on: the log is the write-ahead record of
        // what was attempted, recovery re-stamps whatever it resolves into the
        // live stream anyway, and the position only means anything in the
        // stream a sink is reconstructing.
        sink.stamp(&mut record);
        sink.dispatch(&record, self).await;
        Ok(())
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
mod tests {
    use std::sync::atomic::AtomicU32;

    use serde_json::json;

    use super::*;

    /// A distinct path per test. No temp-dir crate is pulled in for this.
    fn wal_path(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ppe_{tag}_{}_{n}.ndjson", std::process::id()))
    }

    /// Removes the log and its compaction temp file when the test ends,
    /// including on a panic.
    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_extension("recover.tmp"));
        }
    }

    fn lines(path: &std::path::Path) -> Vec<EffectRecord> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("a well-formed record"))
            .collect()
    }

    #[test]
    fn a_prepared_record_starts_as_intent_and_names_no_plugin() {
        let e = EffectRecord::prepared("token_mint", "exchange for workday-api", "k-1")
            .with_detail("audience", "workday-api")
            .with_detail("scopes", json!(["read_compensation"]));

        assert_eq!(e.kind, "token_mint");
        assert_eq!(e.key, "k-1");
        assert_eq!(e.state, EffectState::Prepared);
        assert_eq!(e.details["audience"], "workday-api");
        // The framework stamps this, so a plugin-built record carries nothing.
        assert!(e.plugin_name.is_none());
    }

    #[tokio::test]
    async fn an_appended_record_is_on_disk_when_append_returns() {
        let path = wal_path("append");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path);

        log.append(&EffectRecord::prepared("token_mint", "d", "k-1"))
            .await
            .unwrap();

        // The whole write-ahead guarantee is that this holds the instant
        // append returns, before the caller performs the act.
        let on_disk = lines(&path);
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].key, "k-1");
        assert_eq!(on_disk[0].state, EffectState::Prepared);
    }

    #[tokio::test]
    async fn a_completed_effect_is_dropped_and_an_orphan_is_kept() {
        let path = wal_path("recover");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        // One effect that ran to completion.
        let done = EffectRecord::prepared("token_mint", "d", "done");
        log.append(&done).await.unwrap();
        log.append(&done.clone().into_state(EffectState::Confirmed))
            .await
            .unwrap();
        // One that recorded intent and never reported an outcome, which is
        // what a crash between the two writes leaves behind.
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let summary = log.recover().await.unwrap();

        assert_eq!(summary.compacted, 1);
        assert_eq!(summary.unresolved.len(), 1);
        assert_eq!(summary.unresolved[0].key, "orphan");
        // And the rewritten file holds only the survivor.
        assert_eq!(lines(&path).len(), 1);
        assert_eq!(lines(&path)[0].key, "orphan");
    }

    #[tokio::test]
    async fn a_rejected_outcome_counts_as_resolved() {
        let path = wal_path("rejected");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        let e = EffectRecord::prepared("token_mint", "d", "k-1");
        log.append(&e).await.unwrap();
        log.append(&e.into_state(EffectState::Rejected))
            .await
            .unwrap();

        let summary = log.recover().await.unwrap();
        assert_eq!(summary.compacted, 1);
        assert!(summary.unresolved.is_empty());
    }

    #[tokio::test]
    async fn recovering_a_log_that_was_never_written_is_a_no_op() {
        let path = wal_path("missing");
        let _c = Cleanup(path.clone());

        let summary = FileEffectLog::new(&path).recover().await.unwrap();

        assert_eq!(summary.compacted, 0);
        assert!(summary.unresolved.is_empty());
    }

    #[tokio::test]
    async fn recovery_is_idempotent() {
        let path = wal_path("idempotent");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let first = log.recover().await.unwrap();
        let second = log.recover().await.unwrap();

        assert_eq!(first.unresolved.len(), 1);
        assert_eq!(
            second.unresolved.len(),
            1,
            "a second sweep finds the same orphan"
        );
        assert_eq!(lines(&path).len(), 1, "and does not duplicate it");
    }

    /// A reconciler that answers the same way for every effect.
    struct Fixed(EffectState);

    #[async_trait]
    impl EffectReconciler for Fixed {
        async fn reconcile(&self, _effect: &EffectRecord) -> EffectState {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn a_reconciled_effect_is_recorded_and_compacted_away() {
        let path = wal_path("reconcile_ok");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let still = log
            .recover_and_reconcile(&Fixed(EffectState::Confirmed))
            .await
            .unwrap();

        assert!(
            still.unresolved.is_empty(),
            "the ledger answered, so nothing is left open"
        );
        assert_eq!(
            still.resolved.len(),
            1,
            "and the answer is returned, for the caller to emit"
        );
        assert!(
            lines(&path).is_empty(),
            "and the resolved pair is compacted out"
        );
    }

    /// The default case: nothing can confirm the act, so the record stays open
    /// rather than being written off as if it never happened.
    #[tokio::test]
    async fn an_unresolvable_effect_is_kept_not_marked_rejected() {
        let path = wal_path("reconcile_unknown");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let still = log
            .recover_and_reconcile(&LogUnknownsReconciler)
            .await
            .unwrap();

        assert_eq!(still.unresolved.len(), 1);
        assert_eq!(still.unresolved[0].key, "orphan");
        assert!(still.resolved.is_empty());
        assert_eq!(
            lines(&path).len(),
            1,
            "and it survives in the log for a later sweep"
        );
    }

    // =================================================================
    // A crash mid-append
    // =================================================================
    //
    // `write_all` loops, so a crash can land between two of its writes and
    // leave a final line with no newline, cut anywhere — including mid-
    // character, which makes the file as a whole not valid UTF-8. Recovery
    // used to refuse the whole file on either, and because a refusal is logged
    // and stepped over at startup, the log was then permanently stuck:
    // reconciliation never ran again and compaction never bounded the file,
    // while appends kept succeeding because appending never reads it.

    /// Append a raw fragment the way an interrupted `write_all` would leave
    /// one: no trailing newline.
    fn append_torn(path: &std::path::Path, fragment: &[u8]) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the log");
        f.write_all(fragment).expect("write the fragment");
    }

    #[tokio::test]
    async fn a_torn_final_line_is_dropped_rather_than_failing_recovery() {
        let path = wal_path("torn_tail");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();
        // Half a record, which is what the crash left behind.
        append_torn(&path, br#"{"key":"half-written","kind":"token_"#);

        let summary = log.recover().await.expect("recovery completes");

        assert_eq!(
            summary.unresolved.len(),
            1,
            "the acknowledged record is still accounted for"
        );
        assert_eq!(summary.unresolved[0].key, "orphan");
        assert_eq!(
            lines(&path).len(),
            1,
            "and the rewrite drops the fragment, so the next sweep is clean"
        );
    }

    /// A torn write can land mid-character, leaving the file invalid UTF-8.
    /// Reading it as text first failed the same permanent way a parse error
    /// did, so the cut is made on bytes.
    #[tokio::test]
    async fn a_torn_final_line_cut_mid_character_is_also_dropped() {
        let path = wal_path("torn_utf8");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();
        // The first byte of a three-byte sequence and nothing after it.
        append_torn(&path, b"{\"key\":\"\xe2");

        let summary = log.recover().await.expect("recovery completes");

        assert_eq!(summary.unresolved.len(), 1);
        assert_eq!(summary.unresolved[0].key, "orphan");
    }

    /// Only the tail is forgiven. A line that will not parse anywhere else was
    /// acknowledged and then damaged, and recovery refuses rather than
    /// silently dropping a record that accounts for an irreversible act.
    #[tokio::test]
    async fn a_malformed_line_that_is_not_the_tail_still_fails_recovery() {
        let path = wal_path("corrupt_middle");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "first"))
            .await
            .unwrap();
        append_torn(&path, b"this was never a record\n");
        log.append(&EffectRecord::prepared("token_mint", "d", "second"))
            .await
            .unwrap();

        let err = log.recover().await.expect_err("corruption is refused");
        assert!(
            format!("{err}").contains("parse line"),
            "and it says which line: {err}"
        );
    }

    /// The torn tail is not mistaken for a resolved effect. An interrupted
    /// append was never acknowledged, so the act it guarded never ran, and
    /// dropping it leaves nothing to reconcile.
    #[tokio::test]
    async fn a_torn_intent_leaves_nothing_to_reconcile() {
        let path = wal_path("torn_only");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        append_torn(&path, br#"{"key":"never-acknowledged"#);

        let outcome = log
            .recover_and_reconcile(&LogUnknownsReconciler)
            .await
            .expect("recovery completes");

        assert!(outcome.unresolved.is_empty());
        assert!(outcome.resolved.is_empty());
    }

    #[tokio::test]
    async fn concurrent_appends_do_not_interleave() {
        let path = wal_path("concurrent");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        let mut tasks = Vec::new();
        for i in 0..32 {
            let log = log.clone();
            tasks.push(tokio::spawn(async move {
                log.append(&EffectRecord::prepared("token_mint", "d", format!("k-{i}")))
                    .await
                    .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        // Every record parses, which is the property the write lock buys: a
        // torn line would fail to deserialize and take recovery down with it.
        let on_disk = lines(&path);
        assert_eq!(on_disk.len(), 32);
        let keys: std::collections::HashSet<&str> =
            on_disk.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys.len(), 32, "no record was lost or duplicated");
    }

    #[tokio::test]
    async fn crossing_the_threshold_compacts_without_failing_the_append() {
        let path = wal_path("autocompact");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(2);

        let e = EffectRecord::prepared("token_mint", "d", "k-1");
        log.append(&e).await.unwrap();
        log.append(&e.clone().into_state(EffectState::Confirmed))
            .await
            .unwrap();

        // The second append crosses the threshold and compacts the completed
        // pair away. The append itself still reports success.
        assert!(lines(&path).is_empty());
    }

    /// `fsync` on a file covers its contents, not the directory entry naming
    /// it. The first append is the one that creates the entry, so without a
    /// directory sync a crash there loses the file entirely, taking with it
    /// the intent that had already licensed the act.
    #[tokio::test]
    async fn the_first_append_into_a_new_directory_survives() {
        let dir = std::env::temp_dir().join(format!("ppe_newdir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("effects.ndjson");
        let log = FileEffectLog::new(&path);

        log.append(&EffectRecord::prepared("token_mint", "d", "k-1"))
            .await
            .unwrap();

        assert_eq!(lines(&path).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bare filename has an empty parent, which is not a directory that can
    /// be opened. It has to resolve to the current directory instead.
    #[test]
    fn a_bare_filename_syncs_the_current_directory() {
        sync_parent_dir(std::path::Path::new("Cargo.toml"))
            .expect("a path with no directory component must still sync");
    }

    #[test]
    fn a_path_with_a_directory_syncs_that_directory() {
        sync_parent_dir(&wal_path("dirsync")).expect("a real directory syncs");
    }

    #[tokio::test]
    async fn a_log_that_cannot_be_written_fails_closed() {
        // A path under a plain file cannot be opened, so the append fails.
        // What matters is that it reports the failure rather than swallowing
        // it: the caller reads an error here as "do not act".
        let blocker = wal_path("blocker");
        let _c = Cleanup(blocker.clone());
        std::fs::write(&blocker, b"not a directory").unwrap();
        let log = FileEffectLog::new(blocker.join("nested.ndjson"));

        let result = log
            .append(&EffectRecord::prepared("token_mint", "d", "k-1"))
            .await;

        assert!(result.is_err(), "an unwritable log must not report success");
    }

    // =================================================================
    // The bracket on Extensions
    // =================================================================

    use crate::hooks::payload::Extensions;

    /// A log that refuses every write, standing in for a full disk.
    #[derive(Debug)]
    struct RefusingLog;

    #[async_trait]
    impl DurableEffectLog for RefusingLog {
        async fn append(&self, _effect: &EffectRecord) -> Result<(), Box<PluginError>> {
            Err(wal_error("write anything", None))
        }
    }

    /// A log that records what it was asked to write.
    #[derive(Debug, Default)]
    struct SpyLog(std::sync::Mutex<Vec<EffectRecord>>);

    impl SpyLog {
        fn seen(&self) -> Vec<EffectRecord> {
            self.0.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DurableEffectLog for SpyLog {
        async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>> {
            self.0.lock().unwrap().push(effect.clone());
            Ok(())
        }
    }

    /// A stream for tests: counters start at zero and nothing shares them.
    fn test_stream() -> EffectStream {
        EffectStream {
            epoch: 42,
            stream_id: "effect".to_owned(),
            stream_seq: Arc::new(AtomicU64::new(0)),
            emission_seq: Arc::new(AtomicU64::new(0)),
            handler_timeout: std::time::Duration::from_secs(5),
        }
    }

    fn ext_with(slot: EffectLogSlot) -> Extensions {
        Extensions {
            effect_log: slot,
            ..Default::default()
        }
    }

    fn recorded_ext(log: Arc<dyn DurableEffectLog>, plugin: &str) -> Extensions {
        ext_with(EffectLogSlot::recorded(
            Arc::new(EffectSink::new(Some(log), Vec::new(), test_stream())),
            plugin,
        ))
    }

    /// Auditing off must not change what a plugin does. This is the case an
    /// operator gets by default, and the delegator has to keep working in it.
    #[tokio::test]
    async fn with_nothing_recording_the_act_still_runs() {
        let ext = ext_with(EffectLogSlot::unrecorded());
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        let out: i32 = ext
            .perform_effect(&effect, || async { Ok(7) })
            .await
            .unwrap();

        assert_eq!(out, 7);
        assert!(!ext.effect_log.is_recorded());
    }

    #[tokio::test]
    async fn a_successful_act_is_recorded_as_intent_then_confirmed() {
        let log = Arc::new(SpyLog::default());
        let ext = recorded_ext(log.clone(), "delegator");
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        ext.perform_effect(&effect, || async { Ok(()) })
            .await
            .unwrap();

        let seen = log.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].state, EffectState::Prepared);
        assert_eq!(seen[1].state, EffectState::Confirmed);
        // Attribution comes from the executor, not from the record the plugin
        // built, which carried no name at all.
        assert_eq!(seen[0].plugin_name.as_deref(), Some("delegator"));
        assert!(effect.plugin_name.is_none());
    }

    /// A failed call may still have landed at the participant, so the outcome
    /// is unknown rather than rejected. Recording it as rejected would assert
    /// that no token was minted when nobody can say.
    #[tokio::test]
    async fn a_failed_act_is_recorded_unknown_not_rejected() {
        let log = Arc::new(SpyLog::default());
        let ext = recorded_ext(log.clone(), "delegator");
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        let result: Result<(), _> = ext
            .perform_effect(&effect, || async {
                Err(PluginError::Config {
                    message: "idp unreachable".into(),
                }
                .boxed())
            })
            .await;

        assert!(result.is_err(), "the caller still sees its own failure");
        let seen = log.seen();
        assert_eq!(seen[1].state, EffectState::Unknown);
    }

    /// The write-ahead guarantee: no durable intent, no act.
    #[tokio::test]
    async fn an_unrecordable_intent_stops_the_act() {
        let ext = recorded_ext(Arc::new(RefusingLog), "delegator");
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let ran_in = Arc::clone(&ran);
        let result: Result<(), _> = ext
            .perform_effect(&effect, || async move {
                ran_in.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await;

        assert!(result.is_err());
        assert!(
            !ran.load(Ordering::Relaxed),
            "the act must not run when its intent was not recorded"
        );
    }

    /// A phase whose work gets cancelled or discarded cannot perform an act
    /// that cannot be taken back. The error names the fix rather than letting
    /// the mint run unrecorded.
    #[tokio::test]
    async fn a_phase_that_cannot_support_effects_refuses_them() {
        let ext = ext_with(EffectLogSlot::not_permitted(
            crate::plugin::PluginMode::Concurrent,
            "minter",
        ));
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let ran_in = Arc::clone(&ran);
        let result: Result<(), _> = ext
            .perform_effect(&effect, || async move {
                ran_in.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await;

        let err = result.unwrap_err().to_string();
        assert!(!ran.load(Ordering::Relaxed), "the act must not run");
        assert!(
            err.contains("sequential or transform"),
            "the error should name the fix, got: {err}"
        );
    }

    /// Cloning `Extensions` must not carry the slot: a clone that kept it
    /// could outlive the invocation and write records under a plugin name
    /// that is no longer the one running.
    #[test]
    fn cloning_extensions_drops_the_effect_slot() {
        let ext = recorded_ext(Arc::new(SpyLog::default()), "delegator");
        assert!(ext.effect_log.is_recorded());

        assert!(!ext.clone().effect_log.is_recorded());
    }

    /// The slot being non-`Clone` stops a plugin copying it directly, but
    /// `Extensions` itself is cloneable and has to stay that way. If a copy
    /// permitted effects, a plugin in a phase that may not act could clone its
    /// way around the gate, and one that may act could clone away the
    /// recording. A copy refuses instead.
    #[tokio::test]
    async fn a_copy_of_the_extensions_cannot_perform_an_effect() {
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        for (label, original) in [
            (
                "a refused phase",
                ext_with(EffectLogSlot::not_permitted(
                    crate::plugin::PluginMode::Concurrent,
                    "minter",
                )),
            ),
            (
                "a permitted, recorded phase",
                recorded_ext(Arc::new(SpyLog::default()), "delegator"),
            ),
        ] {
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let ran_in = Arc::clone(&ran);
            let result: Result<(), _> = original
                .clone()
                .perform_effect(&effect, || async move {
                    ran_in.store(true, Ordering::Relaxed);
                    Ok(())
                })
                .await;

            assert!(result.is_err(), "{label}: a copy must refuse");
            assert!(
                !ran.load(Ordering::Relaxed),
                "{label}: the act must not run through a copy"
            );
        }
    }

    /// A hand-built `Extensions` is a copy for this purpose too: the executor
    /// sets a real state on every view it hands a plugin, so anything else is
    /// detached from an invocation.
    #[tokio::test]
    async fn a_default_extensions_cannot_perform_an_effect() {
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        let result: Result<(), _> = Extensions::default()
            .perform_effect(&effect, || async { Ok(()) })
            .await;

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("passed to `handle`"),
            "the error should name where effects belong, got: {err}"
        );
    }

    /// Modes are the single answer to which phases may act, so the executor
    /// and any config check agree rather than each deciding for itself.
    #[test]
    fn only_the_serial_modes_permit_effects() {
        use crate::plugin::PluginMode;
        assert!(PluginMode::Sequential.permits_effects());
        assert!(PluginMode::Transform.permits_effects());
        assert!(!PluginMode::Audit.permits_effects());
        assert!(!PluginMode::Concurrent.permits_effects());
        assert!(!PluginMode::FireAndForget.permits_effects());
        assert!(!PluginMode::Disabled.permits_effects());
    }

    /// Retries append a second unresolved record under the same key. Recovery
    /// keeps the latest, so a sweep reports the current state of the attempt
    /// rather than the intent it started from.
    #[tokio::test]
    async fn the_latest_record_wins_for_an_unresolved_key() {
        let path = wal_path("latest");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        let e = EffectRecord::prepared("token_mint", "d", "k-1");
        log.append(&e).await.unwrap();
        log.append(&e.clone().into_state(EffectState::Unknown))
            .await
            .unwrap();

        let summary = log.recover().await.unwrap();

        assert_eq!(summary.unresolved.len(), 1, "one key, one record");
        assert_eq!(summary.unresolved[0].state, EffectState::Unknown);
    }

    /// A torn trailing write leaves a blank line. Recovery reads past it
    /// instead of failing and stranding every record in the file.
    #[tokio::test]
    async fn blank_lines_in_the_log_are_skipped() {
        let path = wal_path("blank");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "k-1"))
            .await
            .unwrap();
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"\n\n").unwrap();
        }

        let summary = log.recover().await.unwrap();

        assert_eq!(summary.unresolved.len(), 1);
    }

    /// A host implementing the trait for a sink with no readable back-end gets
    /// a recovery that reports nothing rather than having to write one.
    #[tokio::test]
    async fn a_log_without_recoverable_state_recovers_nothing() {
        #[derive(Debug)]
        struct AppendOnly;

        #[async_trait]
        impl DurableEffectLog for AppendOnly {
            async fn append(&self, _effect: &EffectRecord) -> Result<(), Box<PluginError>> {
                Ok(())
            }
        }

        let left = AppendOnly
            .recover_and_reconcile(&LogUnknownsReconciler)
            .await
            .unwrap();

        assert!(left.unresolved.is_empty());
    }
}
