// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A real plugin panic, driven through the engine.
//
// `demo_stream.rs` case 6 constructs a plugin_panic DecisionLog and hands
// it to the mapper. This one does not: it declares a plugin whose handler
// panics and this crate's OCSF sink in a policy config, loads that config
// through `PolicyEngine` the way a production host does, and lets the
// seam produce the record. The panic is contained by the executor's
// `catch_unwind`, surfaces as `PluginError::Execution { code: "panic" }`,
// becomes a `plugin_panic` violation on a terminal deny, and reaches this
// crate through the audit seam like any other verdict. Nothing about the
// record is written by hand.
//
// Why the engine path, and not `Executor::new` directly: the README wires
// the plugin the production way (`kind: audit/ocsf` in YAML, the factory
// builds the emitter, `Plugin::as_audit_handler` attaches it), and this is
// the one example that runs the YAML surface, factory instantiation, the
// attach of an audit-only sink, and `initialize`, `invoke_named`,
// `shutdown` as a host would.
//
// It is also what gives the record its stream identity. The executor owns
// the decision stream's identity, and the host names it:
// `engine_settings.audit_stream_namespace` (a YAML key) prefixes the
// per-type labels, so the decision stream becomes `gw-1:decision`;
// `engine_settings.audit_epoch` (deliberately code-only, `serde(skip)`,
// since a static file value cannot stay monotonic across boots) lets the
// host supply the epoch. The engine bridges both into the executor the
// same way it bridges `plugin_timeout`, so the YAML path and the direct
// path stamp identically. With the namespace set and the epoch supplied,
// this record lands on the same stream as `demo_stream`'s, in a later
// epoch, at stream_seq 0: one stream across a restart.
//
// The stamps ride inside the hashed bytes, so they are the executor's to
// write, not the sink's to edit afterwards. The host names the stream
// before the first record; it never rewrites one.
//
//   DEMO_EPOCH        host-supplied audit epoch (u64). Unset: the
//                     executor's wall-clock boot epoch, as in production.
//   DEMO_STREAM_NS    audit_stream_namespace (default "gw-1"), so the
//                     decision stream is "<ns>:decision"
//   DEMO_SIGNING_KEY  PKCS#8 P-256 PEM path; when set, chain + DSSE
//   DEMO_KEY_ID       JWKS kid stamped on the record
//   DEMO_AUTHORITY    attestation authority_uid
//   DEMO_CHAIN_UID    attestation chain uid
//   DEMO_AGENT_ID     ai_agent.uid              (default "agent-7")
//   DEMO_CONVERSATION_ID
//                     run id -> metadata.correlation_uid
//                                               (default "run-4bf92f35")
//   DEMO_SESSION_ID   ai_agent.instance_uid     (default "sess-gw-1-boot-7")
//
// The record is emitted by the configured OCSF destination, which is
// stderr, so a runner collects it with `2>`, keeping it off the stdout
// NDJSON of `demo_stream`.
//
//   cargo run -p praxis-policy-plugin-ocsf-audit --example panic_drive 2>panic.ndjson

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

use praxis_policy_plugin_ocsf_audit::{KIND as OCSF_KIND, OcsfAuditFactory};

use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall};
use praxis_policy_core::config::parse_config;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::extensions::{
    AgentExtension, Extensions, SecurityExtension, SubjectExtension,
};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::AnyHookHandler;

/// `kind:` the demo config declares for the plugin that panics.
const PANICKING_KIND: &str = "demo/panicking";

/// The host's plugin config, as an operator would write it. Two plugins:
/// the one that comes apart, and this crate's sink with no `hooks:`, which
/// is what makes the factory hand back an audit-only sink that the engine
/// attaches at the verdict path (`as_audit_handler`). A post-hook observer
/// would never see this record: the request is denied, so it never reaches
/// a post hook. That asymmetry is the reason the audit seam exists.
///
/// `mode: sequential` + `on_error: fail` is what makes the panic terminal:
/// the executor's blocking branch turns a contained panic into a
/// `plugin_panic` violation and denies. In a non-blocking phase the same
/// panic would be recorded as an error and the request would continue,
/// which is a different (also real) behaviour and not the one this
/// example is about.
///
/// `audit_stream_namespace` is a YAML value on purpose: it is a stable host
/// identity, so it belongs in the file. The epoch does not; see `main`.
/// `dispatch: hooks` is required: the default is policy dispatch, which
/// refuses a hook-listed plugin with a `priority:`.
fn config_yaml(namespace: &str) -> String {
    format!(
        "
engine_settings:
  dispatch: hooks
  audit_stream_namespace: {namespace}

plugins:
  - name: minter
    kind: {PANICKING_KIND}
    hooks:
      - cmf.tool_pre_invoke
    mode: sequential
    priority: 10
    on_error: fail

  - name: ocsf-decision-sink-demo
    kind: {OCSF_KIND}
    # no `hooks:` -> audit-only sink mode (sees denials)
    mode: audit
    priority: 50
    on_error: fail
    capabilities:
      - read_subject
      - read_agent
      - read_delegation
      - read_labels
"
    )
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// A plugin that panics. That is the whole point of it.
struct PanickingPlugin {
    cfg: PluginConfig,
}

impl Plugin for PanickingPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for PanickingPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Not `PluginResult::deny(...)`, which would be an orderly refusal
        // and is what `demo_stream` cases 3 and 4 cover. This is the
        // ungraceful case:
        // the plugin comes apart mid-decision and the platform has to hold
        // the line without its cooperation.
        panic!("simulated mint failure");
    }
}

/// Factory for `demo/panicking`, shaped like the crate's own
/// `OcsfAuditFactory`: one `TypedHandlerAdapter<CmfHook, _>` per hook the
/// config lists. This is the contract a host registers before
/// `load_config`, and the reason the engine never needs to know the
/// concrete plugin type.
struct PanickingFactory;

impl PluginFactory for PanickingFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(PanickingPlugin {
            cfg: config.clone(),
        });
        let handlers: Vec<(&'static str, Arc<dyn AnyHookHandler>)> = config
            .hooks
            .iter()
            .map(|h| {
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
                (leaked, adapter)
            })
            .collect();
        Ok(PluginInstance { plugin, handlers })
    }
}

/// The sink's `config:` block. Built in code rather than in the YAML above
/// only because the signing key path comes from the environment; the shape
/// is exactly what the README shows an operator writing.
fn sink_config() -> serde_json::Value {
    let mut cfg = json!({
        "chain": false,
        "product_name": "AI Identity OCSF Audit",
        "vendor_name": "AI Identity",
    });

    if let Ok(key_path) = std::env::var("DEMO_SIGNING_KEY") {
        cfg["chain"] = json!(true);
        cfg["signing"] = json!("dsse");
        cfg["signing_key_pem_path"] = json!(key_path);
        cfg["signing_key_id"] = json!(env_str("DEMO_KEY_ID", "demo-key-2026-08"));
        cfg["authority_uid"] = json!(env_str("DEMO_AUTHORITY", "org-f3576cf6"));
        cfg["chain_uid"] = json!(env_str("DEMO_CHAIN_UID", "demo-chain-boot-7-e3"));
    }
    cfg
}

fn request() -> (MessagePayload, Extensions) {
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

    // Same agent and run as `demo_stream`: agent-7 and the run id are what
    // a consumer correlates all six records on.
    let agent = AgentExtension {
        agent_id: Some(env_str("DEMO_AGENT_ID", "agent-7")),
        conversation_id: Some(env_str("DEMO_CONVERSATION_ID", "run-4bf92f35")),
        session_id: Some(env_str("DEMO_SESSION_ID", "sess-gw-1-boot-7")),
        ..Default::default()
    };

    (
        payload,
        Extensions {
            security: Some(Arc::new(sec)),
            agent: Some(Arc::new(agent)),
            ..Default::default()
        },
    )
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let namespace = env_str("DEMO_STREAM_NS", "gw-1");
    let host_epoch: Option<u64> = std::env::var("DEMO_EPOCH")
        .ok()
        .map(|v| v.parse().expect("DEMO_EPOCH must be a u64"));

    // 1. Parse the operator's YAML. The namespace rides in the file.
    let mut cfg = parse_config(&config_yaml(&namespace)).expect("demo config parses");

    // 2. The epoch is set in code, after parsing, and only here. It is
    //    `serde(skip)` in the engine so that a value written in the YAML is
    //    ignored rather than pinned: an epoch must strictly increase per
    //    executor generation for a verifier to tell a restart from record
    //    loss, and a static file value cannot do that. The host that
    //    supplies one owns that monotonicity; here the demo runner does,
    //    by handing each process a larger epoch than the last.
    cfg.engine_settings.audit_epoch = host_epoch;

    // 3. The sink's config block, with the signing key from the environment.
    let sink = cfg
        .plugins
        .iter_mut()
        .find(|p| p.kind == OCSF_KIND)
        .expect("the demo config declares the ocsf sink");
    sink.config = Some(sink_config());

    // 4. Factories, then load, then initialize: the host lifecycle. The
    //    engine instantiates both plugins through their factories, copies
    //    the stream identity into the executor it builds, and attaches the
    //    sink through `as_audit_handler` because it listed no hooks.
    let engine = PolicyEngine::default();
    engine.register_factory(OCSF_KIND, Box::new(OcsfAuditFactory));
    engine.register_factory(PANICKING_KIND, Box::new(PanickingFactory));
    engine.load_config(cfg).expect("demo config loads");
    engine.initialize().await.expect("plugins initialize");

    // 5. Dispatch, exactly as a CMF host would for a tool call.
    let (payload, ext) = request();
    let (result, _bg) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    engine.shutdown().await;

    // The record has already been emitted by the audit seam at this point.
    // Assert the shape the demo claims, so a silent behaviour change
    // upstream fails here rather than on stage.
    assert!(
        result.is_denied(),
        "a panicking sequential plugin with on_error=fail must deny"
    );
    let violation = match result.decision_log.verdict() {
        Some(praxis_policy_core::decision::Verdict::Deny(v)) => v,
        other => panic!("expected a deny verdict, got {other:?}"),
    };
    assert_eq!(
        violation.code, "plugin_panic",
        "a contained panic must surface as plugin_panic, not plugin_error"
    );
    assert_eq!(
        violation.plugin_name.as_deref(),
        Some("minter"),
        "the violation names the plugin that panicked"
    );

    // And the stream identity the host asked for is the one the executor
    // stamped, inside the hashed bytes, by the executor, before the record
    // was signed. This is the assertion that makes "one stream across a
    // restart" a checked fact.
    let expected_stream = format!("{namespace}:decision");
    assert_eq!(
        result.decision_log.stream_id(),
        Some(expected_stream.as_str()),
        "the engine must bridge audit_stream_namespace into the executor"
    );
    if let Some(epoch) = host_epoch {
        assert_eq!(
            result.decision_log.epoch(),
            Some(epoch),
            "the engine must bridge the programmatic audit_epoch into the executor"
        );
    }

    eprintln!(
        "// verify: real panic driven through the engine path: verdict deny, violation {}, \
         plugin {}, stream {} epoch {}",
        violation.code,
        violation.plugin_name.as_deref().unwrap_or("?"),
        result.decision_log.stream_id().unwrap_or("?"),
        result
            .decision_log
            .epoch()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "?".into()),
    );
}
