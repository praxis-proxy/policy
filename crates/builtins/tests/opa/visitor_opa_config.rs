// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end integration: a unified-config YAML that
//
//   1. declares an `opa` PDP under `global.pdp[]` with Rego module(s),
//   2. attaches an `opa: { query: "..." }` policy step to a route,
//
// must flow a real decision from the praxis-policy-core dispatcher through
// `AplConfigVisitor` → `PdpFactory` → `OpaResolver` → the regorus engine →
// back into the route handler's allow/deny split.
//
// This proves the wiring end-to-end. The crate's unit tests cover the
// bag→input mapping, config parsing, and the decision contract in isolation;
// what's special here is that the resolver was never instantiated in Rust by
// the test — the visitor built it from YAML at `load_config_yaml` time because
// the host registered `OpaPdpFactory` via `AplOptions.pdp_factories`. If this
// passes, an operator who drops an `opa` block into their config gets the same
// behavior without writing any glue.

#![allow(
    clippy::expect_used,
    clippy::panic,
    missing_docs,
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
use praxis_policy_builtins::pdps::opa::OpaPdpFactory;

// A boolean allow-rule policy declared globally; the route queries it. The bag
// the cmf BagBuilder lifts from the SecurityExtension exposes `subject.id`,
// which the policy reads as `input.subject.id`.
const YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: opa
      modules:
        - |
          package authz
          default allow := false
          allow if input.subject.id == "alice"
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - opa:
            query: data.authz.allow
"#;

fn meta_for_tool(name: &str) -> MetaExtension {
    MetaExtension {
        entity_type: Some("tool".to_owned()),
        entity_name: Some(name.to_owned()),
        ..Default::default()
    }
}

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

/// Build a engine from arbitrary YAML; returns the load error so negative
/// tests can inspect it.
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
            // The factory is the load-bearing wiring under test: the visitor
            // sees `kind: opa` in YAML and finds this factory by key.
            pdp_factories: vec![Arc::new(OpaPdpFactory::new())],
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

/// `alice` satisfies the Rego `allow` rule → the query is `true` → Allow.
/// End-to-end: the visitor built the resolver from YAML, the route handler
/// dispatched the `opa:` step into it, regorus returned `true`, the pipeline
/// continues.
#[tokio::test]
async fn config_declared_opa_pdp_allows_matching_subject() {
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
        "alice should satisfy the Rego allow rule; got violation = {:?}",
        result.violation
    );
}

/// `eve` does not match; the `allow` rule has a `default` of false → the query
/// is `false` → Deny halts the pipeline with a violation.
#[tokio::test]
async fn config_declared_opa_pdp_denies_non_matching_subject() {
    let mgr = build_manager().await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("eve", &["reader"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "eve should fail the subject.id check and be denied",
    );
    assert!(
        result.violation.is_some(),
        "deny path must surface a violation",
    );
}

/// A malformed OPA PDP config (`on_error: maybe`) must be rejected at
/// `load_config_yaml` rather than discovered on first request. The
/// visitor → `OpaPdpFactory::build` → `OpaResolver::from_config` chain surfaces
/// `BuildError::ConfigShape` as a `PluginError`, which bubbles out of load.
#[tokio::test]
async fn malformed_on_error_is_rejected_at_load() {
    const BAD_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: opa
      on_error: maybe
      modules:
        - "package authz\ndefault allow := false\n"
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - opa:
            query: data.authz.allow
"#;
    let err = match build_manager_with_yaml(BAD_YAML).await {
        Ok(_) => panic!("malformed on_error must fail load_config_yaml"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("on_error") && msg.contains("maybe"),
        "load error should name the bad field and value; got: {msg}",
    );
}

/// An `opa:` step with no `query` is an author bug the parser accepts opaquely;
/// the resolver only learns of it at request time. It must surface as a clean
/// Deny that halts the pipeline, never a panic.
#[tokio::test]
async fn missing_query_at_request_time_denies_without_panicking() {
    const NO_QUERY_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: opa
      modules:
        - "package authz\ndefault allow := false\n"
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - opa:
            on_deny:
              - deny
"#;
    let mgr = build_manager_with_yaml(NO_QUERY_YAML)
        .await
        .expect("an opa step without query is accepted at parse/load time");

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "a missing-query opa step must halt the pipeline, not allow through",
    );
    assert!(
        result.violation.is_some(),
        "missing-query dispatch error must surface as a violation",
    );
}

/// The deny-set idiom works end-to-end: a `deny[msg]` set-valued query allows
/// when empty and denies when non-empty. This is the dominant OPA authoring
/// style, so proving it through the real dispatcher matters.
#[tokio::test]
async fn deny_set_idiom_end_to_end() {
    const DENY_SET_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: opa
      modules:
        - |
          package authz
          deny contains msg if {
              input.subject.id != "alice"
              msg := "subject not on the allowlist"
          }
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - opa:
            query: data.authz.deny
"#;
    let mgr = build_manager_with_yaml(DENY_SET_YAML)
        .await
        .expect("load_config_yaml");

    // alice → empty deny set → allow.
    let (allow, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            Extensions {
                meta: Some(Arc::new(meta_for_tool("get_document"))),
                security: Some(Arc::new(security_with_roles("alice", &[]))),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(
        allow.continue_processing,
        "empty deny set must allow; got violation = {:?}",
        allow.violation
    );

    // eve → non-empty deny set → deny.
    let (deny, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            Extensions {
                meta: Some(Arc::new(meta_for_tool("get_document"))),
                security: Some(Arc::new(security_with_roles("eve", &[]))),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(
        !deny.continue_processing && deny.violation.is_some(),
        "non-empty deny set must halt with a violation",
    );
}

/// External `data` declared in the config is loaded into the engine's `data`
/// root and readable by policy — an operator can port a policy that splits
/// logic (modules) from lookup tables (data) with no rewrite.
#[tokio::test]
async fn external_data_is_readable_end_to_end() {
    const DATA_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: opa
      modules:
        - |
          package authz
          default allow := false
          allow if "reader" in data.roles[input.subject.id]
      data:
        roles:
          alice: [reader]
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - opa:
            query: data.authz.allow
"#;
    let mgr = build_manager_with_yaml(DATA_YAML)
        .await
        .expect("load_config_yaml");

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            Extensions {
                meta: Some(Arc::new(meta_for_tool("get_document"))),
                security: Some(Arc::new(security_with_roles("alice", &[]))),
                ..Default::default()
            },
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "alice has the reader role in the data document and should be allowed; \
         got violation = {:?}",
        result.violation
    );
}

// Structured input: the request document on `llm:` routes and native `args` on
// `tool:` routes.

/// A unique string that must never reach a deny reason or diagnostic.
const MARKER: &str = "zz-marker-7f3a";

/// One OPA module on one route, queried at `query`.
fn route_yaml(selector: &str, module: &str, query: &str) -> String {
    let module = module
        .lines()
        .map(|l| format!("          {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: opa
      modules:
        - |
{module}
routes:
  - {selector}
    authorization:
      pre_invocation:
        - opa:
            query: {query}
"
    )
}

fn llm_ext(document: Option<serde_json::Value>) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("llm".to_owned()),
            entity_name: Some("gpt-4o".to_owned()),
            ..Default::default()
        })),
        security: Some(Arc::new(security_with_roles("alice", &[]))),
        llm_request: document.map(LlmRequestDocument::new),
        ..Default::default()
    }
}

async fn run_llm(module: &str, query: &str, document: Option<serde_json::Value>) -> PipelineResult {
    let mgr = build_manager_with_yaml(&route_yaml("llm: gpt-4o", module, query))
        .await
        .expect("load_config_yaml");
    let payload = MessagePayload {
        message: Message::text(Role::User, format!("prompt {MARKER}")),
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_input", payload, llm_ext(document), None)
        .await;
    result
}

async fn run_tool(module: &str, query: &str, arguments: serde_json::Value) -> PipelineResult {
    let mgr = build_manager_with_yaml(&route_yaml("tool: classify", module, query))
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

/// Asserts a deny and returns its violation rendered for leak checks.
fn denied_violation(result: &PipelineResult) -> String {
    assert!(!result.continue_processing, "expected deny");
    let violation = result
        .violation
        .as_ref()
        .expect("deny must carry a violation");
    format!("{violation:?}")
}

const FORBIDDEN_TOOL: &str = r#"package authz
default allow := false
allow if {
    input.llm.request
    not forbidden
}
forbidden if {
    some t in input.llm.request.tools
    t.function.name == "transfer_funds"
}"#;

fn tool(name: &str) -> serde_json::Value {
    serde_json::json!({"type": "function", "function": {"name": name}})
}

#[tokio::test]
async fn llm_request_forbidden_tool_in_second_position_denies() {
    let document = serde_json::json!({
        "model": "gpt-4o",
        "tools": [tool("search"), tool("transfer_funds")],
    });
    let result = run_llm(FORBIDDEN_TOOL, "data.authz.allow", Some(document)).await;
    denied_violation(&result);
}

#[tokio::test]
async fn llm_request_with_only_permitted_tools_allows() {
    let document = serde_json::json!({
        "model": "gpt-4o",
        "tools": [tool("search"), tool("lookup")],
    });
    let result = run_llm(FORBIDDEN_TOOL, "data.authz.allow", Some(document)).await;
    assert_allowed(&result);
}

/// With no request document, the boolean and object shapes deny, while a
/// deny set over the missing document is empty and allows. Policies that
/// use a deny set must check that the document is present.
#[tokio::test]
async fn absent_document_by_decision_shape() {
    let boolean = r#"package authz
allow if input.llm.request.model == "gpt-4o""#;
    denied_violation(&run_llm(boolean, "data.authz.allow", None).await);

    let object = r#"package authz
decision := {"allow": true} if input.llm.request.model == "gpt-4o""#;
    denied_violation(&run_llm(object, "data.authz.decision", None).await);

    let deny_set = r#"package authz
deny contains "model not allowed" if input.llm.request.model != "gpt-4o""#;
    assert_allowed(&run_llm(deny_set, "data.authz.deny", None).await);

    let guarded = r#"package authz
deny contains "request document missing" if not input.llm.request
deny contains "model not allowed" if input.llm.request.model != "gpt-4o""#;
    denied_violation(&run_llm(guarded, "data.authz.deny", None).await);
}

/// A query that hands back the request document itself carries no decision,
/// and the deny it produces names only the result's type.
#[tokio::test]
async fn degenerate_request_document_result_omits_contents() {
    let module = "package authz\nleak := input.llm.request";
    let document = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": MARKER}],
    });
    let violation = denied_violation(&run_llm(module, "data.authz.leak", Some(document)).await);
    assert!(!violation.contains(MARKER), "{violation}");
    assert!(!violation.contains("messages"), "{violation}");
    assert!(
        violation.contains("no boolean `allow` field (found none)"),
        "{violation}"
    );
}

/// A builtin type error over a payload value denies with a fixed category.
#[tokio::test]
async fn runtime_error_on_request_value_uses_fixed_reason() {
    let module = r#"package authz
allow if upper(input.llm.request.tools) == "X""#;
    let document = serde_json::json!({"tools": [tool(MARKER)]});
    let violation = denied_violation(&run_llm(module, "data.authz.allow", Some(document)).await);
    assert!(!violation.contains(MARKER), "{violation}");
    assert!(
        violation.contains("OPA eval error: policy runtime error"),
        "{violation}"
    );
}

/// Structured `args` keeps numbers, order, duplicates, and explicit nulls.
#[tokio::test]
async fn tool_args_arrive_as_native_json() {
    let module = r#"package authz
default allow := false
allow if {
    input.args.region == "eu"
    input.args.ids == [2, 1, 1]
    1 in input.args.ids
    not string_id
    input.args.note == null
    count(input.args.items) == 2
    input.args.items[1].classification == "secret"
}
string_id if "1" in input.args.ids"#;
    let result = run_tool(
        module,
        "data.authz.allow",
        serde_json::json!({
            "region": "eu",
            "ids": [2, 1, 1],
            "note": null,
            "items": [{"classification": "public"}, {"classification": "secret"}],
        }),
    )
    .await;
    assert_allowed(&result);
}

/// `not input.args.note` no longer holds when the client sends `null`.
#[tokio::test]
async fn tool_args_explicit_null_is_present() {
    let module = "package authz\ndefault allow := false\nallow if not input.args.note";
    let result = run_tool(
        module,
        "data.authz.allow",
        serde_json::json!({"note": null}),
    )
    .await;
    denied_violation(&result);

    let result = run_tool(module, "data.authz.allow", serde_json::json!({})).await;
    assert_allowed(&result);
}
