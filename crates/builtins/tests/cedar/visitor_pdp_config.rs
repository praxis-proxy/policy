// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end integration: a unified-config YAML that
//
//   1. declares a `cedar-direct` PDP under `global.pdp[]`,
//   2. embeds Cedar policy text inline in that declaration,
//   3. attaches a `cedar:(...)` policy step to a route,
//
// must flow a real authorization decision from the praxis-policy-core dispatcher
// through `AplConfigVisitor` → `PdpFactory` → `CedarDirectResolver` →
// Cedar's `Authorizer` → back into the route handler's deny/allow split.
//
// This proves the *wiring* end-to-end. The cedar-direct unit tests in
// `basic_allow_deny.rs` already cover the resolver in isolation; what's
// special here is that the resolver was never instantiated in Rust by
// the test — the visitor built it from YAML at `load_config_yaml` time
// because the host registered `CedarDirectPdpFactory` via
// `AplOptions.pdp_factories`. If this test passes, an operator who
// drops a `cedar-direct` block into their config gets the same behavior
// without writing any glue.

#![allow(
    missing_docs,
    clippy::field_reassign_with_default,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::collections::HashSet;
use std::sync::Arc;

use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, ToolCall};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::extensions::{
    LlmRequestDocument, MetaExtension, SecurityExtension, SubjectExtension, SubjectType,
};
use praxis_policy_core::hooks::payload::Extensions;

use praxis_policy_apl_runtime::{AplOptions, DispatchCache, MemorySessionStore, register_apl};
use praxis_policy_builtins::pdps::cedar_direct::CedarDirectPdpFactory;

// The configuration the visitor walks. Single Cedar permit policy that
// only fires for principals carrying the `reader` role; everything else
// hits Cedar's default-deny path.
const YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
        @id("reader-permit")
        permit(principal, action == Action::"read", resource)
        when { principal.roles.contains("reader") };
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cedar:
            action: 'Action::"read"'
            resource:
              type: Document
              id: doc-42
"#;

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut m = MetaExtension::default();
    m.entity_type = Some("tool".to_owned());
    m.entity_name = Some(name.to_owned());
    m
}

/// Build a `SecurityExtension` with the given subject id and roles. The
/// bag-builder lifts these into `subject.id` / `role.<name>` keys, which
/// `entities.rs` reads when constructing the Cedar principal. Anything
/// the policy needs about the principal must come through this surface.
fn security_with_roles(id: &str, roles: &[&str]) -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some(id.to_owned()),
            subject_type: Some(SubjectType::User),
            roles: roles
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<HashSet<_>>(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn build_manager() -> Arc<PolicyEngine> {
    build_manager_with_yaml(YAML)
        .await
        .expect("load_config_yaml")
}

async fn build_manager_with_yaml(
    yaml: &str,
) -> Result<Arc<PolicyEngine>, Box<dyn std::error::Error + Send + Sync>> {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            // The factory is the load-bearing wiring under test: the
            // visitor sees `kind: cedar-direct` in YAML and finds this
            // factory by key.
            pdp_factories: vec![Arc::new(CedarDirectPdpFactory::new())],
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(yaml)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{e}").into() })?;
    mgr.initialize()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{e}").into() })?;
    Ok(mgr)
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "fetch doc-42"),
    }
}

// =====================================================================
// Scenarios
// =====================================================================

/// Principal `alice` carries `role.reader=true`, which the permit policy
/// requires. End-to-end: visitor built the resolver from YAML, route
/// handler dispatched the `cedar:` step into that resolver, Cedar
/// returned Allow, the pipeline continues.
#[tokio::test]
async fn config_declared_cedar_pdp_allows_reader() {
    let mgr = build_manager().await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "reader-permit should allow alice; got violation = {:?}",
        result.violation
    );
}

/// Principal `bob` carries no roles, so the permit's guard
/// (`principal.roles.contains("reader")`) is false and no other policy
/// fires. Cedar default-denies; the route handler maps that to a
/// pipeline-halting violation with `code = cedar.default_deny`.
#[tokio::test]
async fn config_declared_cedar_pdp_denies_non_reader() {
    let mgr = build_manager().await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("bob", &[]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "missing reader role should default-deny",
    );
    let v = result
        .violation
        .expect("deny path must surface a violation");
    assert_eq!(
        v.code, "cedar.default_deny",
        "default-deny path should use the cedar-direct sentinel code; got {}",
        v.code
    );
}

// Structured input: the request document on `llm:` routes and native `args` on
// `tool:` routes, sanitized into the Cedar context.

/// A unique string that must never reach a deny reason or diagnostic.
const MARKER: &str = "SECRET-MARKER";

/// One Cedar policy set on one route, with the given extra step lines.
fn route_yaml(selector: &str, policy: &str, step_extra: &str) -> String {
    let policy = policy
        .lines()
        .map(|l| format!("        {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
{policy}
routes:
  - {selector}
    authorization:
      pre_invocation:
        - cedar:
            action: 'Action::\"read\"'
            resource:
              type: Document
              id: doc-42
{step_extra}"
    )
}

async fn run_llm(policy: &str, document: Option<serde_json::Value>) -> PipelineResult {
    let mgr = build_manager_with_yaml(&route_yaml("llm: gpt-4o", policy, ""))
        .await
        .expect("load_config_yaml");
    let ext = Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("llm".to_owned()),
            entity_name: Some("gpt-4o".to_owned()),
            ..Default::default()
        })),
        security: Some(Arc::new(security_with_roles("alice", &[]))),
        llm_request: document.map(LlmRequestDocument::new),
        ..Default::default()
    };
    let payload = MessagePayload {
        message: Message::text(Role::User, format!("prompt {MARKER}")),
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_input", payload, ext, None)
        .await;
    result
}

async fn run_tool(policy: &str, arguments: serde_json::Value) -> PipelineResult {
    let mgr = build_manager_with_yaml(&route_yaml("tool: classify", policy, ""))
        .await
        .expect("load_config_yaml");
    let serde_json::Value::Object(arguments) = arguments else {
        panic!("tool-call arguments must be an object");
    };
    let payload = MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".to_owned(),
                    name: "classify".to_owned(),
                    arguments: arguments.into_iter().collect(),
                    namespace: None,
                },
            }],
        ),
    };
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("classify"))),
        security: Some(Arc::new(security_with_roles("alice", &[]))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, ext, None)
        .await;
    result
}

fn assert_allowed(result: &PipelineResult) {
    assert!(
        result.continue_processing,
        "expected allow; got violation = {:?}",
        result.violation
    );
}

/// Asserts a deny and returns its code and the violation rendered whole.
fn denied(result: &PipelineResult) -> (String, String) {
    assert!(!result.continue_processing, "expected deny");
    let violation = result
        .violation
        .as_ref()
        .expect("deny must carry a violation");
    (violation.code.clone(), format!("{violation:?}"))
}

const PERMIT_FUNCTION_TOOLS: &str = r#"@id("function-tools")
permit(principal, action, resource)
when { context.llm.request.tools.contains({"type": "function"}) };"#;

const FORBID_WEB_SEARCH: &str = r#"@id("allow-all")
permit(principal, action, resource);
@id("no-web-search")
forbid(principal, action, resource)
when {
    context has llm && context.llm has request && context.llm.request has tools &&
    context.llm.request.tools.contains({"type": "web_search"})
};"#;

#[tokio::test]
async fn record_set_contains_permits_a_matching_tool() {
    let document = serde_json::json!({"tools": [{"type": "function"}]});
    assert_allowed(&run_llm(PERMIT_FUNCTION_TOOLS, Some(document)).await);

    let document = serde_json::json!({"tools": [{"type": "code"}]});
    let (code, _) = denied(&run_llm(PERMIT_FUNCTION_TOOLS, Some(document)).await);
    assert_eq!(code, "cedar.default_deny");
}

#[tokio::test]
async fn record_set_contains_forbids_a_matching_tool() {
    let document = serde_json::json!({
        "tools": [{"type": "function"}, {"type": "web_search"}],
    });
    let (code, _) = denied(&run_llm(FORBID_WEB_SEARCH, Some(document)).await);
    assert_eq!(code, "no-web-search");

    let document = serde_json::json!({"tools": [{"type": "function"}]});
    assert_allowed(&run_llm(FORBID_WEB_SEARCH, Some(document)).await);
}

/// Cedar compares whole records, so one extra field slips past `contains`.
/// Deny-lists over tools must use OPA or CEL instead.
#[tokio::test]
async fn record_set_contains_misses_a_tool_with_an_extra_field() {
    let document = serde_json::json!({
        "tools": [{"type": "web_search", "name": "search"}],
    });
    assert_allowed(&run_llm(FORBID_WEB_SEARCH, Some(document)).await);
}

/// An entity escape in the document would make `contains` compare against an
/// entity, not a record. The step denies before Cedar runs, even though the
/// only relevant rule is a guarded `forbid` next to a permit-all.
#[tokio::test]
async fn an_escape_key_in_the_document_withholds_it_and_denies() {
    let policy = r#"@id("allow-all")
permit(principal, action, resource);
@id("no-admin-tool")
forbid(principal, action, resource)
when {
    context.llm has request && context.llm.request has tools &&
    context.llm.request.tools.contains({"type": "admin"})
};"#;
    let document = serde_json::json!({
        "tools": [
            {"type": "function"},
            {"__entity": {"type": "User", "id": "admin"}},
        ],
    });
    let (code, violation) = denied(&run_llm(policy, Some(document)).await);
    assert_eq!(code, "cedar.input_withheld");
    assert!(!violation.contains("admin"), "{violation}");
}

/// A `null` field is dropped, so `has` is false. A float becomes its string.
#[tokio::test]
async fn null_is_absent_and_a_float_is_a_string() {
    let policy = r#"permit(principal, action, resource)
when {
    !(context.llm.request has stop) &&
    context.llm.request.temperature == "0.7"
};"#;
    let document = serde_json::json!({"stop": null, "temperature": 0.7});
    assert_allowed(&run_llm(policy, Some(document)).await);
}

/// Arrays become sets, so duplicates collapse and order is lost.
#[tokio::test]
async fn duplicate_array_elements_collapse() {
    let policy = "permit(principal, action, resource)
when { context.args.ids == [2, 1] };";
    assert_allowed(&run_tool(policy, serde_json::json!({"ids": [1, 1, 2]})).await);
}

/// With no document, a policy reading `context.llm.request` errors, and the
/// error denies.
#[tokio::test]
async fn a_missing_document_denies_a_policy_that_reads_it() {
    let policy = r#"permit(principal, action, resource)
when { context.llm.request.model == "gpt-4o" };"#;
    denied(&run_llm(policy, None).await);
    let document = serde_json::json!({"model": "gpt-4o"});
    assert_allowed(&run_llm(policy, Some(document)).await);
}

/// A type error on a payload attribute names the policy and a category only.
#[tokio::test]
async fn a_type_error_on_a_payload_attribute_omits_the_value() {
    let policy = r#"@id("limit-cap")
permit(principal, action, resource)
when { context.args.limit > 5 };"#;
    let (_, violation) = denied(&run_tool(policy, serde_json::json!({"limit": MARKER})).await);
    assert!(!violation.contains(MARKER), "{violation}");
    assert!(
        violation.contains("policy `limit-cap`: type error"),
        "{violation}"
    );
}

/// Cedar's extension errors quote their argument. The reason drops it.
#[tokio::test]
async fn an_extension_error_on_a_payload_value_omits_the_value() {
    let policy = r#"@id("loopback-only")
permit(principal, action, resource)
when { ip(context.args.addr).isLoopback() };"#;
    let (_, violation) = denied(&run_tool(policy, serde_json::json!({"addr": MARKER})).await);
    assert!(!violation.contains(MARKER), "{violation}");
    assert!(
        violation.contains("policy `loopback-only`: extension function failed"),
        "{violation}"
    );
}

async fn load_error(yaml: &str) -> String {
    match build_manager_with_yaml(yaml).await {
        Ok(_) => panic!("config load must fail"),
        Err(e) => e.to_string(),
    }
}

/// `llm` and `args` in an operator `context:` would collide with structured
/// input, so config load rejects them, in a reaction step too.
#[tokio::test]
async fn a_reserved_operator_context_key_fails_load() {
    let policy = "permit(principal, action, resource);";
    let top = "            context:\n              llm: operator-value\n";
    let err = load_error(&route_yaml("tool: classify", policy, top)).await;
    assert!(err.contains("routes.tool:classify"), "{err}");
    assert!(err.contains("may not define `llm`"), "{err}");
    assert!(!err.contains("operator-value"), "{err}");

    let reaction = "            on_allow:
              - cedar:
                  action: 'Action::\"read\"'
                  resource: { type: Document, id: doc-42 }
                  context: { args: {} }
";
    let err = load_error(&route_yaml("tool: classify", policy, reaction)).await;
    assert!(err.contains("may not define `args`"), "{err}");
}
