// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Demo: the decision-audit sink, the half of this plugin that consumes
// the engine's audit seam. A sink-mode emitter (no `hooks:` listed, so
// it attaches as an `AuditHandler`) receives the executor's finalized
// `DecisionLog` at every pipeline verdict and turns it into an OCSF
// event. This example feeds it the five rulings that matter and
// pretty-prints what lands in the audit stream:
//
//   1. Allow                every plugin let the request through
//   2. Allow-after-modify   a redactor rewrote the payload (Modified)
//   3. Deny                 the PDP blocked it (violation -> status)
//   4. Suppressed deny      a Transform-phase plugin signalled deny and
//                           was ignored by role (`deny_ignored`), plus a
//                           concurrent branch cancelled (`aborted`).
//                           Terminal verdict Allow: the record a
//                           post-hook observer could never produce.
//   5. Mandate draw         the request presents a delegated mandate;
//                           the event carries the request id at
//                           unmapped."cmf.request.request_id", the same
//                           correlation id a signed draw receipt names,
//                           so a receipt-in-hand reconciles against the
//                           OCSF stream.
//
//   cargo run -p praxis-policy-plugin-ocsf-audit --example decision_sink_demo
//
// Timestamps and stream stamps are fixed so the output is deterministic.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use praxis_policy_plugin_ocsf_audit::OcsfAuditEmitter;

use praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use praxis_policy_core::decision::{DecisionLog, PluginAction, Span, Verdict};
use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::extensions::{
    DelegationExtension, DelegationHop, Extensions, RequestExtension, SecurityExtension,
    SubjectExtension,
};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

/// Sink-mode emitter: `hooks` is empty, which is what makes the factory
/// attach this instance as a decision-audit sink (`as_audit_handler()`)
/// instead of a post-hook observer.
fn sink() -> OcsfAuditEmitter {
    let config = PluginConfig {
        name: "ocsf-decision-sink-demo".into(),
        kind: "audit/ocsf".into(),
        hooks: vec![],
        mode: PluginMode::Audit,
        priority: 50,
        on_error: OnError::Fail,
        config: Some(json!({
            "chain": false,
            "product_name": "AI Identity OCSF Audit",
            "vendor_name": "AI Identity",
        })),
        ..Default::default()
    };
    OcsfAuditEmitter::new(config).expect("valid demo config")
}

/// The request under judgement: an agent invoking the `get_compensation`
/// HR tool on behalf of alice@corp.com.
fn tool_request() -> (MessagePayload, Extensions) {
    let payload = MessagePayload {
        message: Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "call-042".into(),
                    name: "get_compensation".into(),
                    arguments: HashMap::from([("employee_id".to_owned(), json!("EMP-001234"))]),
                    namespace: Some("hr".into()),
                },
            }],
        ),
    };

    let mut sec = SecurityExtension::default();
    let mut subj = SubjectExtension::default();
    subj.id = Some("alice@corp.com".into());
    subj.roles.insert("hr".into());
    sec.subject = Some(subj);
    sec.labels.insert("PII".into());

    let ext = Extensions {
        security: Some(Arc::new(sec)),
        ..Default::default()
    };
    (payload, ext)
}

/// Case 5's request: the same tool call, but presented under a delegated
/// mandate: alice delegated `read_compensation` to agent-7, and the
/// enforcement request carries the correlation id a signed draw receipt
/// will name. (`revocation_id` needs no event field: the receipt names
/// which token copy acted; the correlation id joins receipt to record.)
fn mandate_request() -> (MessagePayload, Extensions) {
    let (payload, base) = tool_request();
    let delegation = DelegationExtension {
        delegated: true,
        depth: 1,
        origin_subject_id: Some("alice@corp.com".into()),
        actor_subject_id: Some("agent-7".into()),
        chain: vec![DelegationHop {
            subject_id: "agent-7".into(),
            audience: Some("hr-mcp".into()),
            scopes_granted: vec!["read_compensation".into()],
            ttl_seconds: Some(300),
            ..Default::default()
        }],
        ..Default::default()
    };
    let request = RequestExtension {
        request_id: Some("corr-7f3e2a91".into()),
        environment: Some("production".into()),
        ..Default::default()
    };
    let ext = Extensions {
        delegation: Some(Arc::new(delegation)),
        request: Some(Arc::new(request)),
        ..base
    };
    (payload, ext)
}

/// Build a finalized `DecisionLog` the way the executor would: ordered
/// per-plugin steps, a terminal verdict, the invocation span, and the
/// seam's completeness/ordering stamps.
fn finalized(
    steps: Vec<(&str, PluginMode, PluginAction)>,
    verdict: Verdict,
    stream_seq: u64,
    emission_seq: u64,
) -> DecisionLog {
    let mut log = DecisionLog::new();
    for (name, mode, action) in steps {
        log.record(name, mode, action);
    }
    log.set_span(Span {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: format!("00f067aa0ba9{emission_seq:04}"),
        parent_span_id: Some("00f067aa0ba90200".into()),
    });
    log.set_stream(
        1_755_648_000_000_000_000,
        "gw-1/boot-7".into(),
        stream_seq,
        emission_seq,
    );
    log.finalize(verdict);
    log
}

fn main() {
    let e = sink();
    let (payload, ext) = tool_request();

    // 1. Clean allow: PDP and PII scan both passed.
    let allow = finalized(
        vec![
            ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
            ("pii-scan", PluginMode::Sequential, PluginAction::Allowed),
        ],
        Verdict::Allow,
        41,
        41,
    );

    // 2. Allow after modification: the redactor rewrote the payload.
    let modified = finalized(
        vec![
            ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
            (
                "pii-redactor",
                PluginMode::Transform,
                PluginAction::ModifiedPayload,
            ),
        ],
        Verdict::Allow,
        42,
        42,
    );

    // 3. Deny: the PDP blocked the call. The violation the executor
    //    stamped rides into status_code / status_detail.
    let mut violation = PluginViolation::new(
        "policy_denied",
        "cedar-pdp: subject lacks permission read_compensation on hr/get_compensation",
    );
    violation.plugin_name = Some("cedar-pdp".into());
    let denied = finalized(
        vec![(
            "cedar-pdp",
            PluginMode::Sequential,
            PluginAction::Denied(Box::new(PluginViolation::new(
                "missing_permission",
                "no grant covers this tool",
            ))),
        )],
        Verdict::Deny(violation),
        43,
        43,
    );

    // 4. The subtle record: a Transform-phase plugin signalled deny and
    //    was suppressed by role (deny_ignored, never re-coded as allow),
    //    and a concurrent branch was cancelled (aborted, distinct from
    //    error). Terminal verdict: Allow. "Every suppressed transform
    //    deny" is one SIEM query on these step actions.
    let suppressed = finalized(
        vec![
            ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
            (
                "injection-guard",
                PluginMode::Transform,
                PluginAction::DenyIgnored(Box::new(PluginViolation::new("policy_deny", "blocked"))),
            ),
            (
                "secondary-scan",
                PluginMode::Transform,
                PluginAction::Aborted,
            ),
        ],
        Verdict::Allow,
        44,
        44,
    );

    // 5. Mandate draw: allowed under delegated authority, with the
    //    draw-receipt join key on the record.
    let mandate_draw = finalized(
        vec![
            (
                "mandate-check",
                PluginMode::Sequential,
                PluginAction::Allowed,
            ),
            ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
        ],
        Verdict::Allow,
        45,
        45,
    );
    let (m_payload, m_ext) = mandate_request();

    let cases = [
        (
            "1 — Allow (clean)",
            &allow,
            &payload,
            &ext,
            "2026-08-21T03:20:00.000Z",
        ),
        (
            "2 — Allow after modification",
            &modified,
            &payload,
            &ext,
            "2026-08-21T03:20:01.000Z",
        ),
        (
            "3 — Deny (policy violation)",
            &denied,
            &payload,
            &ext,
            "2026-08-21T03:20:02.000Z",
        ),
        (
            "4 — Suppressed deny + aborted branch",
            &suppressed,
            &payload,
            &ext,
            "2026-08-21T03:20:03.000Z",
        ),
        (
            "5 — Mandate draw (receipt join key)",
            &mandate_draw,
            &m_payload,
            &m_ext,
            "2026-08-21T03:20:04.000Z",
        ),
    ];

    for (title, log, pl, xt, ts) in cases {
        let ev = e.build_decision(Some(pl), xt, log, ts);
        println!("// ===== Decision {title} =====");
        println!("{}", serde_json::to_string_pretty(&ev).unwrap());
        println!();
    }

    // The receipt side of the join, for the reader: a signed draw receipt
    // carries the same correlation id, so
    // receipt.correlation_id == unmapped."cmf.request.request_id" above.
    println!(
        "// join: receipt.correlation_id == corr-7f3e2a91 == event 5 unmapped.\"cmf.request.request_id\""
    );
}
