// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The DecisionLog: the executor's record of what each plugin did to a
// request and how the pipeline ruled on it.
//
// A plugin observing a request cannot see the pipeline's verdict. Allow,
// deny and modify live in the executor's control flow (`PluginResult` and
// the short-circuit return), not in `Extensions`, so an observation-only
// plugin sees allowed post-hook traffic and nothing else. The DecisionLog
// captures that control flow so an audit sink can serialize it.
//
// It is built by the executor and handed only to audit handlers. It is not
// placed on `PluginContext`: every plugin can read that, and a plugin that
// could read the log could tailor its behaviour to what has already been
// recorded about it.
//
// It records what happened (which plugin, which phase, which action), not
// copies of payloads.

use crate::error::PluginViolation;
use crate::plugin::PluginMode;

/// What a single plugin did to the request, as the executor saw it.
///
/// Derived from the plugin's returned `PluginResult`, never self-reported.
#[derive(Debug, Clone, PartialEq)]
pub enum PluginAction {
    /// Ran and let the request continue unchanged.
    Allowed,
    /// Blocked the request, carrying its own violation.
    ///
    /// The terminal [`Verdict::Deny`] carries the violation the pipeline ruled
    /// on, which is this one in a serial phase. A concurrent phase can have
    /// several branches deny at once and only the first becomes the verdict,
    /// so without a violation here the other objections would be recorded as
    /// bare markers with no reason attached to them.
    Denied(Box<PluginViolation>),
    /// Replaced the payload, and the executor accepted the replacement.
    ModifiedPayload,
    /// Wrote to an extension slot it was capable of writing.
    ModifiedExtensions,
    /// Signalled a block from a phase that cannot block (Transform), so the
    /// deny was suppressed and the pipeline continued.
    ///
    /// Recorded as its own action rather than as [`PluginAction::Allowed`]:
    /// a consumer mapping actions to a disposition must not read a suppressed
    /// block as the plugin having permitted the request.
    ///
    /// Carries the violation the plugin returned. Enforcement did not happen
    /// here, so this record is the only place the objection survives: the
    /// verdict is an allow and names nothing.
    DenyIgnored(Box<PluginViolation>),
    /// Cancelled mid-flight because another concurrent branch short-circuited
    /// the phase. Distinct from [`PluginAction::Error`] so an intentional
    /// abort does not read as a crash.
    Aborted,
    /// Failed, carrying the error as the executor rendered it. Whether this
    /// halts the pipeline is decided by the plugin's `on_error`, so an
    /// `Error` step may be followed by more steps.
    Error(String),
}

/// One entry in the log: a plugin, the phase it ran in, and what it did.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionStep {
    /// The plugin instance name, from `PluginConfig.name`.
    pub plugin_name: String,
    /// The phase this plugin ran in.
    pub phase: PluginMode,
    /// What it did.
    pub action: PluginAction,
}

/// The pipeline's terminal ruling on a request.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// The request was allowed through. Any modifications along the way are
    /// in [`DecisionLog::steps`].
    Allow,
    /// The request was blocked, carrying the violation the executor stamped
    /// with the deciding plugin's name.
    Deny(PluginViolation),
}

impl Verdict {
    /// True if this verdict blocked the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }
}

/// The W3C trace context for one pipeline invocation: this interception's
/// identity in the decision graph.
///
/// `span_id` is this interception's own span, `parent_span_id` is the upstream
/// call that caused it, and `trace_id` correlates the whole run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// The trace this invocation belongs to (W3C trace-id, 32 hex chars).
    pub trace_id: String,
    /// This interception's own span (W3C span-id, 16 hex chars).
    pub span_id: String,
    /// The span of the upstream call that caused this one, and so the causal
    /// edge. `None` when the request carried no trace context, making this a
    /// trace root.
    pub parent_span_id: Option<String>,
}

impl Span {
    /// Derive an interception's span from the request's trace context.
    ///
    /// A child-span model: a fresh `span_id` for this interception, the
    /// request's `span_id` as the causal parent, and the request's `trace_id`
    /// carried through, or a freshly originated one when the request carries
    /// none.
    #[must_use]
    pub fn for_request(trace_id: Option<&str>, parent_span_id: Option<&str>) -> Self {
        Self {
            trace_id: trace_id.map_or_else(new_trace_id, str::to_owned),
            span_id: new_span_id(),
            parent_span_id: parent_span_id.map(str::to_owned),
        }
    }
}

/// A freshly originated W3C trace-id: 16 bytes as 32 lowercase hex chars.
fn new_trace_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A freshly originated W3C span-id: 8 bytes as 16 lowercase hex chars, the
/// first half of a UUID's hex.
fn new_span_id() -> String {
    // The first 8 of a UUID's 16 bytes, hex-encoded. Taking bytes rather than
    // slicing the hex string keeps this free of any assumption about where a
    // character boundary falls.
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The executor's record of one pipeline invocation: the ordered steps the
/// plugins took and the terminal verdict.
///
/// `verdict` is `None` while the pipeline is still running and is set once,
/// at a return point. An audit sink is only ever handed a finalized log.
#[derive(Debug, Clone, Default)]
pub struct DecisionLog {
    steps: Vec<DecisionStep>,
    verdict: Option<Verdict>,
    span: Option<Span>,
    input_labels: Vec<String>,
    input_hash: Option<String>,
    epoch: Option<u64>,
    stream_id: Option<String>,
    stream_seq: Option<u64>,
    emission_seq: Option<u64>,
}

impl DecisionLog {
    /// A fresh log for one pipeline invocation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append what a plugin did. Called by the executor as each plugin
    /// returns, so the order is execution order.
    pub fn record(
        &mut self,
        plugin_name: impl Into<String>,
        phase: PluginMode,
        action: PluginAction,
    ) {
        self.steps.push(DecisionStep {
            plugin_name: plugin_name.into(),
            phase,
            action,
        });
    }

    /// Set the terminal verdict, once, at the pipeline's return point and
    /// before the log reaches any audit handler.
    pub fn finalize(&mut self, verdict: Verdict) {
        self.verdict = Some(verdict);
    }

    /// Attach this invocation's trace context, set by the executor at pipeline
    /// entry from the request.
    pub fn set_span(&mut self, span: Span) {
        self.span = Some(span);
    }

    /// This invocation's trace context, if the executor set one.
    pub fn span(&self) -> Option<&Span> {
        self.span.as_ref()
    }

    /// Record the taint labels the request arrived with, the input side of
    /// this node's provenance. Diffed against the final labels, it gives the
    /// taint the pipeline added.
    pub fn set_input_labels(&mut self, labels: Vec<String>) {
        self.input_labels = labels;
    }

    /// The taint labels present at pipeline entry.
    pub fn input_labels(&self) -> &[String] {
        &self.input_labels
    }

    /// Record the content hash of the payload at entry. Set only when content
    /// provenance is enabled, since hashing sits on the request path.
    pub fn set_input_hash(&mut self, hash: Option<String>) {
        self.input_hash = hash;
    }

    /// The content hash of the payload at entry, if it was captured.
    pub fn input_hash(&self) -> Option<&str> {
        self.input_hash.as_deref()
    }

    /// Stamp the audit stream identity and the two sequence numbers, assigned
    /// by the executor at emission.
    ///
    /// The counters make two different claims and neither substitutes for the
    /// other.
    ///
    /// - `epoch` is the executor's boot time in Unix nanoseconds, captured
    ///   once. It scopes the counters, so a verifier can tell a counter reset
    ///   (a new, larger epoch) from records that went missing (a gap inside
    ///   one epoch). Being ordered, `(epoch, emission_seq)` totally orders
    ///   records across restarts.
    /// - `stream_id` is the per-type stream this record belongs to.
    /// - `stream_seq` is a **completeness** claim: gap-free within
    ///   `(epoch, stream_id)`, so a gap means a record was lost.
    /// - `emission_seq` is an **ordering** claim only: monotonic across
    ///   decisions and effects together, so the two can be interleaved back
    ///   into the order they happened. A consumer reading one stream sees it
    ///   sparse by design, and those gaps are the other stream's records
    ///   rather than a loss.
    pub fn set_stream(
        &mut self,
        epoch: u64,
        stream_id: String,
        stream_seq: u64,
        emission_seq: u64,
    ) {
        self.epoch = Some(epoch);
        self.stream_id = Some(stream_id);
        self.stream_seq = Some(stream_seq);
        self.emission_seq = Some(emission_seq);
    }

    /// The executor generation this record was emitted in.
    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    /// The per-type stream this record belongs to, which scopes `stream_seq`.
    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    /// Completeness counter, gap-free within `(epoch, stream_id)`.
    pub fn stream_seq(&self) -> Option<u64> {
        self.stream_seq
    }

    /// Ordering counter, monotonic across decisions and effects in the epoch.
    pub fn emission_seq(&self) -> Option<u64> {
        self.emission_seq
    }

    /// The ordered steps taken this invocation.
    pub fn steps(&self) -> &[DecisionStep] {
        &self.steps
    }

    /// The terminal verdict, or `None` if the pipeline has not returned yet.
    pub fn verdict(&self) -> Option<&Verdict> {
        self.verdict.as_ref()
    }

    /// True once finalized with a deny.
    pub fn is_denied(&self) -> bool {
        self.verdict.as_ref().is_some_and(Verdict::is_deny)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_log_has_no_steps_and_no_verdict() {
        let log = DecisionLog::new();
        assert!(log.steps().is_empty());
        assert!(log.verdict().is_none());
        assert!(!log.is_denied());
    }

    #[test]
    fn steps_are_kept_in_the_order_they_were_recorded() {
        let mut log = DecisionLog::new();
        log.record("first", PluginMode::Sequential, PluginAction::Allowed);
        log.record(
            "second",
            PluginMode::Transform,
            PluginAction::ModifiedPayload,
        );
        log.record(
            "third",
            PluginMode::Concurrent,
            PluginAction::Denied(Box::new(PluginViolation::new("blocked", "no"))),
        );

        let names: Vec<&str> = log.steps().iter().map(|s| s.plugin_name.as_str()).collect();
        assert_eq!(names, ["first", "second", "third"]);
        assert_eq!(log.steps()[1].phase, PluginMode::Transform);
        assert!(matches!(log.steps()[2].action, PluginAction::Denied(_)));
    }

    #[test]
    fn a_finalized_deny_reports_denied_and_carries_the_violation() {
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Deny(PluginViolation::new("blocked", "no")));

        assert!(log.is_denied());
        match log.verdict() {
            Some(Verdict::Deny(v)) => assert_eq!(v.code, "blocked"),
            other => panic!("expected a deny, got {other:?}"),
        }
    }

    #[test]
    fn a_finalized_allow_is_not_a_deny() {
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Allow);

        assert!(!log.is_denied());
        assert!(matches!(log.verdict(), Some(Verdict::Allow)));
    }

    /// A suppressed block must not be read as consent, and it is the only
    /// record of the objection: the verdict is an allow and names nothing, so
    /// losing the violation here loses the reason entirely.
    #[test]
    fn deny_ignored_is_distinct_from_allowed_and_keeps_its_reason() {
        let action = PluginAction::DenyIgnored(Box::new(PluginViolation::new(
            "pii_present",
            "unredactable field",
        )));
        assert_ne!(action, PluginAction::Allowed);
        match &action {
            PluginAction::DenyIgnored(v) => {
                assert_eq!(v.code, "pii_present");
                assert_eq!(v.reason, "unredactable field");
            },
            other => panic!("expected DenyIgnored, got {other:?}"),
        }
        assert_ne!(PluginAction::Aborted, PluginAction::Error(String::new()));
    }

    /// A request carrying trace context becomes a child of the call that
    /// caused it, not a new root. Losing that edge breaks the only link
    /// between an interception and the request it was intercepting.
    #[test]
    fn a_request_with_trace_context_produces_a_child_span() {
        let span = Span::for_request(Some("trace-abc"), Some("upstream-span"));

        assert_eq!(span.trace_id, "trace-abc", "the trace carries through");
        assert_eq!(span.parent_span_id.as_deref(), Some("upstream-span"));
        assert_ne!(
            span.span_id, "upstream-span",
            "this interception gets its own span, not the parent's"
        );
        assert_eq!(span.span_id.len(), 16, "a W3C span-id is 16 hex chars");
    }

    /// Nothing upstream sent trace context, so this interception starts a
    /// trace rather than being dropped from the graph.
    #[test]
    fn a_request_with_no_trace_context_starts_a_root() {
        let span = Span::for_request(None, None);

        assert!(span.parent_span_id.is_none(), "a root has no causal parent");
        assert_eq!(span.trace_id.len(), 32, "a W3C trace-id is 32 hex chars");
        assert_ne!(
            Span::for_request(None, None).trace_id,
            span.trace_id,
            "each root is its own trace"
        );
    }

    #[test]
    fn provenance_is_absent_until_the_executor_captures_it() {
        let log = DecisionLog::new();

        assert!(log.span().is_none());
        assert!(log.input_labels().is_empty());
        assert!(log.input_hash().is_none());
    }

    #[test]
    fn captured_provenance_reads_back() {
        let mut log = DecisionLog::new();
        log.set_span(Span::for_request(Some("t"), None));
        log.set_input_labels(vec!["PII".to_owned()]);
        log.set_input_hash(Some("sha256:abc".to_owned()));

        assert_eq!(log.span().map(|s| s.trace_id.as_str()), Some("t"));
        assert_eq!(log.input_labels(), ["PII"]);
        assert_eq!(log.input_hash(), Some("sha256:abc"));
    }
}
