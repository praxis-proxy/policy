// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Demo stream driver, the machine-readable sibling of
// `decision_sink_demo`. That example is written to be *read*: pretty
// JSON under `// =====` headers, fixed stamps, chaining off. This one is
// written to be *consumed*: one compact JSON object per line (NDJSON) on
// stdout, with the seam's stream stamps and the signing mode taken from
// the environment so a runner can drive more than one process and get a
// genuine epoch boundary between them.
//
//   DEMO_EPOCH        u64 epoch stamp            (default 1755648000000000000)
//   DEMO_BASE_SEQ     u64 first stream_seq       (default 0: an epoch opens at 0)
//   DEMO_STREAM_ID    stream id                  (default "gw-1:decision",
//                     the "<namespace>:<kind>" shape the engine stamps when
//                     the host sets engine_settings.audit_stream_namespace,
//                     so these records share a stream with the one
//                     `panic_drive` produces)
//   DEMO_CASES        comma list of case numbers (default "1,2,3,4,5")
//   DEMO_SIGNING_KEY  PKCS#8 P-256 PEM path; when set, chain + DSSE
//   DEMO_KEY_ID       JWKS kid stamped on each record
//   DEMO_HOLD         when "1", park after the last record instead of
//                     exiting, so a runner can kill -9 a live process
//                     rather than simulating the loss of one
//   DEMO_AGENT_ID     ai_agent.uid                (default "agent-7")
//   DEMO_CONVERSATION_ID
//                     the run id -> metadata.correlation_uid; stable
//                     across the restart, since a restarted producer is
//                     the same conversation (default "run-4bf92f35")
//   DEMO_SESSION_ID   ai_agent.instance_uid       (default
//                     "sess-gw-1-boot-7")
//
// Cases 1-5 are the same five rulings `decision_sink_demo` documents.
// Case 6 is the fail-closed panic record as this driver constructs it: a
// plugin that panicked under catch_unwind, surfacing as violation code
// `plugin_panic` on a terminal deny. `panic_drive.rs` drives a real one
// through the engine; this is the reference shape of that record.
//
//   cargo run -p praxis-policy-plugin-ocsf-audit --example demo_stream

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
use std::io::Write as _;
use std::sync::Arc;

use serde_json::json;

use praxis_policy_plugin_ocsf_audit::OcsfAuditEmitter;

use praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use praxis_policy_core::decision::{DecisionLog, PluginAction, Span, Verdict};
use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::extensions::{
    AgentExtension, DelegationExtension, DelegationHop, Extensions, RequestExtension,
    SecurityExtension, SubjectExtension,
};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn sink() -> OcsfAuditEmitter {
    let mut cfg = json!({
        "chain": false,
        "product_name": "AI Identity OCSF Audit",
        "vendor_name": "AI Identity",
    });

    // A key turns on the whole integrity seam: chained fingerprints plus
    // a DSSE signature over the canonical bytes. Without one the records
    // stay unsigned, which the offline validator will report as a finding
    // rather than pretend it verified.
    if let Ok(key_path) = std::env::var("DEMO_SIGNING_KEY") {
        cfg["chain"] = json!(true);
        cfg["signing"] = json!("dsse");
        cfg["signing_key_pem_path"] = json!(key_path);
        cfg["signing_key_id"] = json!(env_str("DEMO_KEY_ID", "demo-key-2026-08"));
        // A signed record without an authority is unverifiable: the key
        // is what signed, the authority is the stable party a verifier
        // checks the resolved key against. AID-EMIT-1 section 6 rejects
        // the former without the latter.
        cfg["authority_uid"] = json!(env_str("DEMO_AUTHORITY", "org-f3576cf6"));
        // Each process owns its own chain. Without a distinct uid the
        // restarted producer restarts the attestation counter too, and
        // its first record collides with the first record of the epoch
        // before it, which a verifier reads as an idempotent replay and
        // refuses to chain.
        cfg["chain_uid"] = json!(env_str("DEMO_CHAIN_UID", "demo-chain-org-f3576cf6"));
    }

    let config = PluginConfig {
        name: "ocsf-decision-sink-demo".into(),
        kind: "audit/ocsf".into(),
        hooks: vec![],
        mode: PluginMode::Audit,
        priority: 50,
        on_error: OnError::Fail,
        config: Some(cfg),
        ..Default::default()
    };
    OcsfAuditEmitter::new(config).expect("valid demo config")
}

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

    // Agent identity. Without this the records name no agent at all:
    // `ai_agent` is absent, and so is `metadata.correlation_uid`, which
    // ocsf.rs maps from `conversation_id` (the run is the
    // multi-event-stable key; `request_id` identifies one request and
    // correlates nothing). A consumer handed those records has to fall
    // back to something per-event.
    //
    // The agent is the one already named in the delegation chain of the
    // mandate draw, `agent-7` acting for alice@corp.com, so the two
    // objects agree instead of one knowing the agent and the other not.
    // The run id is stable across the kill and the epoch boundary: a
    // restarted producer is the same conversation, which is the property
    // that makes it worth correlating on.
    let agent = AgentExtension {
        agent_id: Some(env_str("DEMO_AGENT_ID", "agent-7")),
        conversation_id: Some(env_str("DEMO_CONVERSATION_ID", "run-4bf92f35")),
        session_id: Some(env_str("DEMO_SESSION_ID", "sess-gw-1-boot-7")),
        ..Default::default()
    };

    let ext = Extensions {
        security: Some(Arc::new(sec)),
        agent: Some(Arc::new(agent)),
        ..Default::default()
    };
    (payload, ext)
}

/// The mandate draw carries `request_id`: the id a signed draw receipt
/// names, and the key a receipt-to-record query joins on.
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

fn finalized(
    steps: Vec<(&str, PluginMode, PluginAction)>,
    verdict: Verdict,
    epoch: u64,
    stream_id: &str,
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
    log.set_stream(epoch, stream_id.into(), stream_seq, emission_seq);
    log.finalize(verdict);
    log
}

fn main() {
    let epoch = env_u64("DEMO_EPOCH", 1_755_648_000_000_000_000);
    let base_seq = env_u64("DEMO_BASE_SEQ", 0);
    let stream_id = env_str("DEMO_STREAM_ID", "gw-1:decision");
    let cases: Vec<u32> = env_str("DEMO_CASES", "1,2,3,4,5")
        .split(',')
        .filter_map(|c| c.trim().parse().ok())
        .collect();

    let e = sink();
    let (payload, ext) = tool_request();
    let (m_payload, m_ext) = mandate_request();

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for (i, case) in cases.iter().enumerate() {
        let seq = base_seq + u64::try_from(i).expect("case index fits in u64");
        let ts = format!("2026-08-21T03:20:{i:02}.000Z");

        let (log, pl, xt) = match case {
            // 1. Clean allow: PDP and PII scan both passed.
            1 => (
                finalized(
                    vec![
                        ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
                        ("pii-scan", PluginMode::Sequential, PluginAction::Allowed),
                    ],
                    Verdict::Allow,
                    epoch,
                    &stream_id,
                    seq,
                    seq,
                ),
                &payload,
                &ext,
            ),

            // 2. Allow after modification: the redactor rewrote the payload.
            2 => (
                finalized(
                    vec![
                        ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
                        (
                            "pii-redactor",
                            PluginMode::Transform,
                            PluginAction::ModifiedPayload,
                        ),
                    ],
                    Verdict::Allow,
                    epoch,
                    &stream_id,
                    seq,
                    seq,
                ),
                &payload,
                &ext,
            ),

            // 3. Deny: the violation rides into status_code/status_detail.
            3 => {
                let mut violation = PluginViolation::new(
                    "policy_denied",
                    "cedar-pdp: subject lacks permission read_compensation on hr/get_compensation",
                );
                violation.plugin_name = Some("cedar-pdp".into());
                (
                    finalized(
                        vec![(
                            "cedar-pdp",
                            PluginMode::Sequential,
                            PluginAction::Denied(Box::new(PluginViolation::new(
                                "missing_permission",
                                "no grant covers this tool",
                            ))),
                        )],
                        Verdict::Deny(violation),
                        epoch,
                        &stream_id,
                        seq,
                        seq,
                    ),
                    &payload,
                    &ext,
                )
            },

            // 4. Suppressed deny + aborted branch, terminal verdict Allow:
            //    the record a post-hook observer could not produce.
            4 => (
                finalized(
                    vec![
                        ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
                        (
                            "injection-guard",
                            PluginMode::Transform,
                            PluginAction::DenyIgnored(Box::new(PluginViolation::new(
                                "policy_deny",
                                "blocked",
                            ))),
                        ),
                        (
                            "secondary-scan",
                            PluginMode::Transform,
                            PluginAction::Aborted,
                        ),
                    ],
                    Verdict::Allow,
                    epoch,
                    &stream_id,
                    seq,
                    seq,
                ),
                &payload,
                &ext,
            ),

            // 5. Mandate draw, carrying the draw-receipt join key.
            5 => (
                finalized(
                    vec![
                        (
                            "mandate-check",
                            PluginMode::Sequential,
                            PluginAction::Allowed,
                        ),
                        ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
                    ],
                    Verdict::Allow,
                    epoch,
                    &stream_id,
                    seq,
                    seq,
                ),
                &m_payload,
                &m_ext,
            ),

            // 6. Fail-closed plugin panic: caught under catch_unwind and
            //    finalized as a deny whose code survives to status_code,
            //    distinguishable from an ordinary plugin_error.
            6 => {
                let mut violation = PluginViolation::new(
                    "plugin_panic",
                    "Plugin 'minter' failed: task panicked: simulated",
                );
                violation.plugin_name = Some("minter".into());
                (
                    finalized(
                        vec![(
                            "minter",
                            PluginMode::Sequential,
                            PluginAction::Error("task panicked: simulated".into()),
                        )],
                        Verdict::Deny(violation),
                        epoch,
                        &stream_id,
                        seq,
                        seq,
                    ),
                    &payload,
                    &ext,
                )
            },

            other => panic!("unknown demo case {other}"),
        };

        let ev = e.build_decision(Some(pl), xt, &log, &ts);
        writeln!(out, "{}", serde_json::to_string(&ev).unwrap()).expect("write record");
        out.flush().expect("flush record");
    }

    if env_str("DEMO_HOLD", "0") == "1" {
        hold();
    }
}

/// Park with the records already flushed, so a runner can kill -9 a live
/// process and show that what reached the sink survived the loss of the
/// producer, rather than simulating the restart.
fn hold() -> ! {
    loop {
        std::thread::park();
    }
}
