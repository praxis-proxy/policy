// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Demo: content provenance digests, the `unmapped."cpex.content"` block
// AID-EMIT-1 section 9.2 describes. A decision record never carries the
// payload; it carries two digests of it, one taken at pipeline entry and
// one at emission, so a reader can tell whether the pipeline altered the
// content without the audit trail holding either version. Four records:
//
//   1. Unchanged      - nothing altered the request: equal digests under
//                       the deployment key.
//   2. Redacted       - the request arrived carrying an SSN and a redactor
//                       rewrote it: different digests, same key id, and
//                       the SSN is nowhere in the record.
//   3. Rotated key    - record 1's request again, under a rotated key:
//                       a different key id, so a reader knows not to
//                       compare these digests with record 1's. Within the
//                       record they still agree.
//   4. Unkeyed        - record 1's request under the explicit development
//                       setting `content_provenance_key: unkeyed`: plain
//                       `sha256:<hex>`, the form a reader should treat as
//                       a confirmation oracle for short or templated
//                       content.
//
//   cargo run -p praxis-policy-plugin-ocsf-audit --example provenance_demo
//
// The digests are the engine's. They are computed by its own `ContentKey`,
// under keys resolved through its secret store from the two demo values
// below, exactly the function the executor calls at entry and at emission;
// this example only feeds it the bytes and places the result on the log
// the way the executor does.
//
// Everything a verifier needs to recompute the digests is printed as
// `// verify` lines: the demo keys, the key-id label, and the canonical
// audit bytes of each payload. Timestamps, span ids and stream stamps are
// fixed, so a re-run reproduces the output byte for byte.

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

use praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use praxis_policy_core::decision::{DecisionLog, PluginAction, Span, Verdict};
use praxis_policy_core::extensions::{Extensions, SecurityExtension, SubjectExtension};
use praxis_policy_core::hooks::payload::{ContentKey, PluginPayload as _};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};
use praxis_policy_core::secrets::{SecretProviderRegistry, SecretStore, SecretsConfig};
use praxis_policy_plugin_ocsf_audit::OcsfAuditEmitter;

/// The deployment key, as an operator would generate it with
/// `openssl rand -base64 48`. A demo value: it is printed below so the
/// vector can be recomputed, which is the opposite of what a real key is
/// for. The engine refuses anything shorter than 32 bytes.
const DEMO_KEY: &str = "QWlJZGVudGl0eS1kZW1vLXByb3ZlbmFuY2Uta2V5LTIwMjYtMTAtMDEtYQ==";

/// The key after one rotation. Different bytes, so a different key id.
const DEMO_KEY_ROTATED: &str = "QWlJZGVudGl0eS1kZW1vLXByb3ZlbmFuY2Uta2V5LTIwMjYtMTAtMDEtYg==";

/// What the engine MACs to derive a key id (the first 8 bytes of the
/// result, hex). Fixed in the engine so the id is stable across restarts
/// and changes only when the key does.
const KEY_ID_LABEL: &str = "praxis-policy/content-provenance/key-id";

/// Sink-mode emitter: `hooks` is EMPTY, so the factory would attach this
/// instance as a decision-audit sink rather than a post-hook observer.
fn sink() -> OcsfAuditEmitter {
    let config = PluginConfig {
        name: "ocsf-provenance-demo".into(),
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

/// The request as it reached the pipeline. `ssn` is the field a redactor
/// exists to take out; it is a demo value, not a person's.
fn entry_request(with_ssn: bool) -> MessagePayload {
    let mut arguments = HashMap::from([("employee_id".to_owned(), json!("EMP-001234"))]);
    if with_ssn {
        arguments.insert("ssn".to_owned(), json!("000-00-0000"));
    }
    MessagePayload {
        message: Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "call-051".into(),
                    name: "get_compensation".into(),
                    arguments,
                    namespace: Some("hr".into()),
                },
            }],
        ),
    }
}

/// The request after the redactor: the same call with the SSN replaced.
fn redacted_request() -> MessagePayload {
    let mut payload = entry_request(false);
    if let Some(ContentPart::ToolCall { content }) = payload.message.content.first_mut() {
        content
            .arguments
            .insert("ssn".to_owned(), json!("[REDACTED]"));
    }
    payload
}

fn subject() -> Extensions {
    let mut sec = SecurityExtension::default();
    let mut subj = SubjectExtension::default();
    subj.id = Some("alice@corp.com".into());
    subj.roles.insert("hr".into());
    sec.subject = Some(subj);
    sec.labels.insert("PII".into());
    Extensions {
        security: Some(Arc::new(sec)),
        ..Default::default()
    }
}

/// A finalized `DecisionLog` the way the executor would build it: ordered
/// per-plugin steps, a terminal verdict, the invocation span, the stream
/// stamps, and the two content digests.
fn finalized(
    steps: Vec<(&str, PluginMode, PluginAction)>,
    input_hash: Option<String>,
    output_hash: Option<String>,
    seq: u64,
) -> DecisionLog {
    let mut log = DecisionLog::new();
    for (name, mode, action) in steps {
        log.record(name, mode, action);
    }
    log.set_span(Span {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        span_id: format!("00f067aa0ba9{seq:04}"),
        parent_span_id: Some("00f067aa0ba90200".into()),
    });
    log.set_stream(1_755_648_000_000_000_000, "gw-1/boot-7".into(), seq, seq);
    log.set_input_hash(input_hash);
    // The engine records the emission digest on the log too, so the sink
    // never hashes and never holds the key.
    log.set_output_hash(output_hash);
    log.finalize(Verdict::Allow);
    log
}

/// A digest scheme as the host provides it: a name for the output, and
/// the function that turns canonical audit bytes into a digest string.
struct Scheme {
    name: &'static str,
    digest: Box<dyn Fn(&[u8]) -> Option<String>>,
}

/// The three schemes: the deployment key, the rotated key, and the
/// explicit unkeyed setting. The keys go through the engine's secret
/// store, `file` backend, the way `engine_settings.content_provenance_key`
/// resolves them at startup, and `ContentKey::keyed` enforces the 32-byte
/// minimum the engine enforces. The two key files are written to a
/// scratch directory for the duration of the resolve and removed after.
async fn schemes() -> Vec<Scheme> {
    let dir = std::env::temp_dir().join(format!("ocsf-provenance-demo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory for the demo keys");
    std::fs::write(dir.join("provenance_key"), DEMO_KEY).expect("write the demo key");
    std::fs::write(dir.join("provenance_key_rotated"), DEMO_KEY_ROTATED)
        .expect("write the rotated demo key");
    let config: SecretsConfig = serde_json::from_value(json!({
        "providers": { "local": { "kind": "file", "base_dir": dir } },
        "values": {
            "provenance_key": { "provider": "local", "ref": "provenance_key" },
            "provenance_key_rotated": { "provider": "local", "ref": "provenance_key_rotated" }
        }
    }))
    .expect("a well-formed secrets block");
    let resolved =
        SecretStore::resolve(&config, &SecretProviderRegistry::with_builtin_backends()).await;
    std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
    let store = resolved.expect("both demo values resolve from the key files");

    let keyed = |name: &str| {
        let secret = store.secret(name).expect("declared above");
        ContentKey::keyed(secret).expect("the demo keys are long enough")
    };
    let a = keyed("provenance_key");
    let b = keyed("provenance_key_rotated");
    vec![
        Scheme {
            name: "keyed (provenance_key)",
            digest: Box::new(move |bytes| a.digest(bytes)),
        },
        Scheme {
            name: "keyed (provenance_key_rotated)",
            digest: Box::new(move |bytes| b.digest(bytes)),
        },
        Scheme {
            name: "unkeyed",
            digest: Box::new(|bytes| ContentKey::Unkeyed.digest(bytes)),
        },
    ]
}

/// Sequential steps that all allowed, by plugin name.
fn allowed(steps: &[&'static str]) -> Vec<(&'static str, PluginMode, PluginAction)> {
    steps
        .iter()
        .map(|s| (*s, PluginMode::Sequential, PluginAction::Allowed))
        .collect()
}

fn audit_bytes(payload: &MessagePayload) -> Vec<u8> {
    payload
        .audit_bytes()
        .expect("MessagePayload opts in to audit bytes")
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let e = sink();
    let ext = subject();
    let schemes = schemes().await;
    let (key_a, key_b, unkeyed) = (&schemes[0], &schemes[1], &schemes[2]);

    let clean = entry_request(false);
    let with_ssn = entry_request(true);
    let redacted = redacted_request();
    let clean_bytes = audit_bytes(&clean);
    let with_ssn_bytes = audit_bytes(&with_ssn);
    let redacted_bytes = audit_bytes(&redacted);

    // 1. Unchanged: entry and emission digest the same bytes under the
    //    deployment key.
    let unchanged = finalized(
        allowed(&["cedar-pdp", "pii-scan"]),
        (key_a.digest)(&clean_bytes),
        (key_a.digest)(&clean_bytes),
        46,
    );

    // 2. Redacted: the redactor rewrote the payload between the two
    //    digests. Same key id, different digests, and the SSN is in
    //    neither the record nor the digest.
    let mut redaction = allowed(&["cedar-pdp"]);
    redaction.push((
        "pii-redactor",
        PluginMode::Transform,
        PluginAction::ModifiedPayload,
    ));
    let redacted_log = finalized(
        redaction,
        (key_a.digest)(&with_ssn_bytes),
        (key_a.digest)(&redacted_bytes),
        47,
    );

    // 3. Rotated key: record 1 again after the operator rotated the bytes
    //    behind `provenance_key`. The key id changes; the content did not.
    let rotated = finalized(
        allowed(&["cedar-pdp", "pii-scan"]),
        (key_b.digest)(&clean_bytes),
        (key_b.digest)(&clean_bytes),
        48,
    );

    // 4. Unkeyed: record 1 under `content_provenance_key: unkeyed`.
    let plain = finalized(
        allowed(&["cedar-pdp", "pii-scan"]),
        (unkeyed.digest)(&clean_bytes),
        (unkeyed.digest)(&clean_bytes),
        49,
    );

    let cases = [
        (
            "1 - Unchanged",
            &unchanged,
            &clean,
            key_a,
            "2026-10-01T18:00:00.000Z",
        ),
        (
            "2 - Redacted",
            &redacted_log,
            &redacted,
            key_a,
            "2026-10-01T18:00:01.000Z",
        ),
        (
            "3 - Rotated key",
            &rotated,
            &clean,
            key_b,
            "2026-10-01T18:00:02.000Z",
        ),
        (
            "4 - Unkeyed",
            &plain,
            &clean,
            unkeyed,
            "2026-10-01T18:00:03.000Z",
        ),
    ];

    for (title, log, payload, scheme, ts) in cases {
        let ev = e.build_decision(Some(payload), &ext, log, ts);
        println!("// ===== Decision {title} =====");
        println!("// scheme: {}", scheme.name);
        println!("{}", serde_json::to_string_pretty(&ev).unwrap());
        println!();
    }

    // What a verifier needs to recompute every digest above without this
    // crate: the keys, the key-id label, and the exact bytes digested.
    //   keyed:   hmac-sha256:<hex(HMAC-SHA256(key, label)[..8])>:<hex(HMAC-SHA256(key, bytes))>
    //   unkeyed: sha256:<hex(SHA-256(bytes))>
    println!("// verify: provenance_key          = {DEMO_KEY}");
    println!("// verify: provenance_key_rotated  = {DEMO_KEY_ROTATED}");
    println!("// verify: key_id_label            = {KEY_ID_LABEL}");
    for (name, bytes) in [
        ("entry, records 1/3/4", &clean_bytes),
        ("entry, record 2", &with_ssn_bytes),
        ("emission, record 2", &redacted_bytes),
    ] {
        println!(
            "// verify: audit_bytes ({name}) = {}",
            String::from_utf8_lossy(bytes)
        );
    }
}
