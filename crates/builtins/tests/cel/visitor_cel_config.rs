// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end integration: a unified-config YAML that
//
//   1. declares a `cel` PDP under `global.pdp[]`,
//   2. attaches a `cel:(expr: "...")` policy step to a route,
//
// must flow a real decision from the praxis-policy-core dispatcher through
// `AplConfigVisitor` → `PdpFactory` → `CelResolver` → the `cel`
// interpreter → back into the route handler's allow/deny split.
//
// This proves the *wiring* end-to-end. The crate's unit tests cover the
// bag→activation mapping and the resolver in isolation; what's special
// here is that the resolver was never instantiated in Rust by the test —
// the visitor built it from YAML at `load_config_yaml` time because the
// host registered `CelPdpFactory` via `AplOptions.pdp_factories`. If this
// passes, an operator who drops a `cel` block into their config gets the
// same behavior without writing any glue.

#![allow(
    missing_docs,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
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

use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, ToolCall};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::extensions::{
    HttpExtension, LlmRequestDocument, MetaExtension, RequestExtension, SecurityExtension,
    SubjectExtension, SubjectType,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HttpHook, HttpPayload};

use praxis_policy_apl_runtime::{AplOptions, DispatchCache, MemorySessionStore, register_apl};
use praxis_policy_builtins::pdps::cel::CelPdpFactory;

// The config the visitor walks. A `cel:` step whose expression reads the
// common attribute vocabulary (`subject.id`, `role.*`) the cmf BagBuilder
// lifts from the SecurityExtension. `has(role.reader)` guards the optional
// role namespace so a principal with no roles evaluates to a clean `false`
// (Deny) rather than an undeclared-variable error.
const YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cel
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cel:
            expr: |
              subject.id == "alice" && has(role.reader) && role.reader
  - tool: check_admin
    authorization:
      pre_invocation:
        - cel:
            expr: has(role.admin) && role.admin
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

/// Build a engine from arbitrary YAML; returns the load error so
/// negative tests can inspect it. Mirrors `build_manager` but lets
/// tests swap the config text under test.
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
            // sees `kind: cel` in YAML and finds this factory by key.
            pdp_factories: vec![Arc::new(CelPdpFactory::new())],
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

/// `alice` with `role.reader=true` satisfies the CEL predicate → Allow.
/// End-to-end: visitor built the resolver from YAML, route handler
/// dispatched the `cel:` step into it, CEL returned `true`, pipeline
/// continues.
#[tokio::test]
async fn config_declared_cel_pdp_allows_matching_subject() {
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
        "alice+reader should satisfy the CEL predicate; got violation = {:?}",
        result.violation
    );
}

/// `eve` is not `alice` → the CEL predicate is `false` → Deny halts the
/// pipeline. (Short-circuit `&&` means the missing `role` namespace is
/// never touched.)
#[tokio::test]
async fn config_declared_cel_pdp_denies_non_matching_subject() {
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

/// A dotted role is an atomic membership name, not a nested CEL namespace.
/// The CMF bridge keeps it in `subject.roles` but must not emit
/// `role.admin.readonly`, which CEL would interpret as `role.admin` existing.
#[tokio::test]
async fn config_declared_cel_pdp_rejects_dotted_role_as_atomic_alias() {
    let mgr = build_manager().await;
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("check_admin"))),
        security: Some(Arc::new(security_with_roles("alice", &["admin.readonly"]))),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "admin.readonly must not satisfy the role.admin CEL alias guard",
    );
    assert!(
        result.violation.is_some(),
        "deny path must surface a violation"
    );
}

/// A malformed CEL PDP config (`on_error: maybe`) must be rejected at
/// `load_config_yaml` rather than discovered on first request. The
/// visitor → `CelPdpFactory::build` → `CelResolver::from_config` chain
/// surfaces `BuildError::ConfigShape` as a `praxis_policy_core::PluginError`,
/// which bubbles out of load.
#[tokio::test]
async fn malformed_on_error_is_rejected_at_load() {
    const BAD_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cel
      on_error: maybe
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cel:
            expr: |
              subject.id == "alice"
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

/// `on_error: allow` at the config level flips an eval error (here, an
/// undeclared-variable reference) to Allow end-to-end. Pins the
/// fail-open knob travels from YAML → factory → resolver → router →
/// route-handler decision the same way as the unit-level resolver test.
#[tokio::test]
async fn on_error_allow_yaml_flips_eval_error_to_allow_end_to_end() {
    const ALLOW_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cel
      on_error: allow
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cel:
            expr: |
              nonexistent.field == "value"
"#;
    let mgr = build_manager_with_yaml(ALLOW_YAML)
        .await
        .expect("on_error: allow config must load cleanly");

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
        "eval error under on_error=allow must surface as Allow; got violation = {:?}",
        result.violation,
    );
}

/// A `cel:` step with no `expr` (the author wrote reactions but forgot
/// the predicate) is an author bug that the parser accepts opaquely —
/// the resolver only learns of it at request time. It must surface as a
/// clean Deny ("PDP error") that halts the pipeline, never a panic.
/// Complements the unit-level `missing_expr_is_dispatch_error` by
/// proving the error travels through the real dispatcher.
#[tokio::test]
async fn missing_expr_at_request_time_denies_without_panicking() {
    const NO_EXPR_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cel
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cel:
            on_deny:
              - deny
"#;
    let mgr = build_manager_with_yaml(NO_EXPR_YAML)
        .await
        .expect("a cel step without expr is accepted at parse/load time");

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
        "a missing-expr cel step must halt the pipeline, not allow through",
    );
    assert!(
        result.violation.is_some(),
        "missing-expr dispatch error must surface as a violation",
    );
}

/// A `cel:` predicate that reads the `meta` namespace
/// (`meta.entity_name`) proves the cmf `BagBuilder` lifts `MetaExtension`
/// into the bag and the activation exposes it to CEL — the other
/// integration cases only exercise `subject.*` / `role.*` from the
/// `SecurityExtension`. Gates the tool by name end-to-end.
#[tokio::test]
async fn cel_reads_meta_entity_name_from_bag() {
    const META_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cel
routes:
  - tool: get_document
    authorization:
      pre_invocation:
        - cel:
            expr: |
              meta.entity_name == "get_document"
"#;
    let mgr = build_manager_with_yaml(META_YAML)
        .await
        .expect("load_config_yaml");

    // Matching tool name → predicate true → Allow.
    let allow_ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_document"))),
        security: Some(Arc::new(security_with_roles("alice", &["reader"]))),
        ..Default::default()
    };
    let (allow, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), allow_ext, None)
        .await;
    assert!(
        allow.continue_processing,
        "meta.entity_name == \"get_document\" must reach CEL and allow; got violation = {:?}",
        allow.violation,
    );
}

// Structured input: the request document on `llm:` routes and native `args` on
// `tool:` routes.

/// A unique string that must never reach a deny reason or diagnostic.
const MARKER: &str = "SECRET-MARKER";

/// One route whose policy is `steps`, each already indented as a list item.
fn route_yaml(selector: &str, steps: &str) -> String {
    format!(
        "
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cel
routes:
  - {selector}
    authorization:
      pre_invocation:
{steps}
"
    )
}

/// A single `cel:` step with `expr` and optional extra args.
fn cel_step(expr: &str, extra: &str) -> String {
    format!("        - cel:\n            expr: '{expr}'\n{extra}")
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

async fn run_llm(steps: &str, document: Option<serde_json::Value>) -> PipelineResult {
    let mgr = build_manager_with_yaml(&route_yaml("llm: gpt-4o", steps))
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

async fn run_tool(steps: &str, arguments: serde_json::Value) -> PipelineResult {
    let mgr = build_manager_with_yaml(&route_yaml("tool: classify", steps))
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

fn tool(name: &str) -> serde_json::Value {
    serde_json::json!({"type": "function", "function": {"name": name}})
}

const FORBIDDEN_TOOL: &str =
    r#"!llm.request.tools.exists(t, has(t.function) && t.function.name == "transfer_funds")"#;

#[tokio::test]
async fn llm_request_forbidden_tool_in_second_position_denies() {
    let document = serde_json::json!({
        "model": "gpt-4o",
        "tools": [tool("search"), tool("transfer_funds")],
    });
    let result = run_llm(&cel_step(FORBIDDEN_TOOL, ""), Some(document)).await;
    let violation = denied_violation(&result);
    assert!(
        violation.contains("CEL expression evaluated to false"),
        "{violation}"
    );
}

#[tokio::test]
async fn llm_request_with_only_permitted_tools_allows() {
    let document = serde_json::json!({
        "model": "gpt-4o",
        "tools": [tool("search"), {"type": "web_search_20250305"}],
    });
    let result = run_llm(&cel_step(FORBIDDEN_TOOL, ""), Some(document)).await;
    assert_allowed(&result);
}

/// An allowlist of tool types, passed as an extra `cel:` argument.
#[tokio::test]
async fn llm_request_tool_type_allowlist() {
    let expr = "llm.request.tools.all(t, allowed.exists(p, t.type.matches(p)))";
    let document = serde_json::json!({
        "tools": [{"type": "web_search_20250305"}, {"type": "function", "function": {}}],
    });
    let without = cel_step(expr, "            allowed: ['^function$']\n");
    let violation = denied_violation(&run_llm(&without, Some(document.clone())).await);
    assert!(
        violation.contains("CEL expression evaluated to false"),
        "{violation}"
    );

    let with = cel_step(
        expr,
        "            allowed: ['^function$', '^web_search_[0-9]+$']\n",
    );
    assert_allowed(&run_llm(&with, Some(document)).await);
}

/// With no document, a rule over `llm.request` denies under the default
/// `on_error`. A `has()` guard handles a field missing from a document.
#[tokio::test]
async fn absent_document_denies_and_absent_field_is_guarded() {
    let expr = "size(llm.request.tools) == 0";
    denied_violation(&run_llm(&cel_step(expr, ""), None).await);

    let guarded = "!has(llm.request.tools) || size(llm.request.tools) == 0";
    let document = serde_json::json!({"model": "gpt-4o"});
    assert_allowed(&run_llm(&cel_step(guarded, ""), Some(document)).await);
}

/// Items are native maps, and an APL predicate on the flattened bag still
/// runs on the same route.
#[tokio::test]
async fn tool_args_list_of_objects_with_apl_predicate() {
    let steps = format!(
        "        - 'require(args.region == \"eu\")'\n{}",
        cel_step(
            r#"!args.items.exists(i, has(i.classification) && i.classification == "secret")"#,
            ""
        )
    );
    let items = serde_json::json!([{"name": "a"}, {"classification": "secret"}]);
    let violation = denied_violation(
        &run_tool(&steps, serde_json::json!({"region": "eu", "items": items})).await,
    );
    assert!(
        violation.contains("CEL expression evaluated to false"),
        "{violation}"
    );

    let public = serde_json::json!([{"name": "a"}, {"classification": "public"}]);
    assert_allowed(
        &run_tool(
            &steps,
            serde_json::json!({"region": "eu", "items": public.clone()}),
        )
        .await,
    );
    let violation = denied_violation(
        &run_tool(&steps, serde_json::json!({"region": "us", "items": public})).await,
    );
    assert!(
        !violation.contains("CEL expression"),
        "the APL predicate must deny before the CEL step: {violation}"
    );
}

/// Structured `args` keeps JSON types, order, duplicates, and explicit nulls.
#[tokio::test]
async fn tool_args_arrive_as_native_values() {
    let expr = "size(args.dupes) == 2 && args.nothing == null && args.empty == {} \
                && args.one == 1 && 13 in args.ids && !(\"13\" in args.ids) \
                && has(args.note)";
    let result = run_tool(
        &cel_step(expr, ""),
        serde_json::json!({
            "dupes": [1, 1],
            "nothing": null,
            "empty": {},
            "one": 1,
            "ids": [13],
            "note": null,
        }),
    )
    .await;
    assert_allowed(&result);
}

/// Reasons and diagnostics name no payload value or client-chosen key, for a
/// false result, a non-bool result, and a type error.
#[tokio::test]
async fn deny_paths_omit_payload_values() {
    const CAUSES: [&str; 3] = [
        "CEL expression evaluated to false",
        "CEL expression must return bool, got list(1)",
        "CEL eval error: unsupported binary operator `add` on string and int",
    ];
    let document = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": MARKER}],
        "hidden_key": MARKER,
    });
    let llm_exprs = [
        "llm.request.model == \"other\"",
        "llm.request.messages",
        "llm.request.messages[0].content + 1 == 2",
    ];
    for (expr, cause) in llm_exprs.into_iter().zip(CAUSES) {
        let violation =
            denied_violation(&run_llm(&cel_step(expr, ""), Some(document.clone())).await);
        assert!(violation.contains(cause), "{expr}: {violation}");
        assert!(!violation.contains(MARKER), "{expr}: {violation}");
        assert!(!violation.contains("hidden_key"), "{expr}: {violation}");
    }

    let args = serde_json::json!({"hidden_key": MARKER, "items": [MARKER]});
    let tool_exprs = [
        "size(args.items) == 0",
        "args.items",
        "args.items[0] + 1 == 2",
    ];
    for (expr, cause) in tool_exprs.into_iter().zip(CAUSES) {
        let violation = denied_violation(&run_tool(&cel_step(expr, ""), args.clone()).await);
        assert!(violation.contains(cause), "{expr}: {violation}");
        assert!(!violation.contains(MARKER), "{expr}: {violation}");
        assert!(!violation.contains("hidden_key"), "{expr}: {violation}");
    }
}

// Kuadrant request.id through the real CEL factory and APL visitor.
// This belongs in the builtins harness: runtime must not depend back on
// builtins, because that cycle breaks cargo package verification.

const REQUEST_ID_COMPAT: &str = r#"
engine_settings:
  dispatch: policy
  kuadrant_compat: true
global:
  pdp:
    - kind: cel
routes:
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - cel:
            expr: "request.id == 'req-abc'"
"#;

async fn http_request_id_allows(
    mgr: &PolicyEngine,
    host_id: Option<&str>,
    header_id: Option<&str>,
) -> bool {
    let ext = Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some(ENTITY_HTTP.to_owned()),
            entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
            ..Default::default()
        })),
        http: Some(Arc::new(HttpExtension {
            method: Some("GET".to_owned()),
            path: Some("/x".to_owned()),
            request_headers: header_id
                .into_iter()
                .map(|id| ("x-request-id".to_owned(), id.to_owned()))
                .collect(),
            ..Default::default()
        })),
        request: host_id.map(|id| {
            Arc::new(RequestExtension {
                request_id: Some(id.to_owned()),
                ..Default::default()
            })
        }),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None)
        .await;
    result.continue_processing
}

#[tokio::test]
async fn kuadrant_request_id_uses_host_metadata() {
    let mgr = build_manager_with_yaml(REQUEST_ID_COMPAT)
        .await
        .expect("load compat policy");

    for (host_id, header_id, expected) in [
        (Some("req-abc"), None, true),
        (Some("other"), None, false),
        (None, None, false),
        (None, Some("req-abc"), false),
        (Some("other"), Some("req-abc"), false),
        (Some("req-abc"), Some("other"), true),
    ] {
        assert_eq!(
            http_request_id_allows(&mgr, host_id, header_id).await,
            expected,
            "authorization must follow host ID {host_id:?}, not header {header_id:?}"
        );
    }
}

#[tokio::test]
async fn kuadrant_request_id_without_compat_fails_closed() {
    let yaml = REQUEST_ID_COMPAT.replace("kuadrant_compat: true", "kuadrant_compat: false");
    let mgr = build_manager_with_yaml(&yaml)
        .await
        .expect("load native policy");

    assert!(
        !http_request_id_allows(&mgr, Some("req-abc"), None).await,
        "without compat, request.id is absent and authorization must deny"
    );
}

#[tokio::test]
async fn kuadrant_request_attributes_require_explicit_presence_checks() {
    // A missing namespace is an error under on_error=deny; a missing field in
    // an existing namespace can still grant permission through !has().
    for (expr, expected) in [
        (
            "!(request.id == 'blocked')",
            [false, false, true, false, true],
        ),
        (
            "has(request.id) && request.id != '' && request.id != 'blocked'",
            [false, false, false, false, true],
        ),
        ("!has(request.protocol)", [false, false, true, true, true]),
        (
            "has(request.protocol) && request.protocol != ''",
            [false, false, false, false, false],
        ),
    ] {
        let yaml = REQUEST_ID_COMPAT.replace("request.id == 'req-abc'", expr);
        let mgr = build_manager_with_yaml(&yaml)
            .await
            .expect("load policy with explicit attribute requirements");
        for ((host_id, header_id), expected) in [
            (None, None),
            (None, Some("req-abc")),
            (Some(""), None),
            (Some("blocked"), None),
            (Some("req-abc"), None),
        ]
        .into_iter()
        .zip(expected)
        {
            assert_eq!(
                http_request_id_allows(&mgr, host_id, header_id).await,
                expected,
                "{expr}: host ID {host_id:?}, header ID {header_id:?}"
            );
        }
    }
}

#[tokio::test]
async fn kuadrant_request_id_toggle_takes_effect_on_reload() {
    let mgr = build_manager_with_yaml(REQUEST_ID_COMPAT)
        .await
        .expect("load compat policy");
    assert!(mgr.kuadrant_compat());
    assert!(http_request_id_allows(&mgr, Some("req-abc"), None).await);

    let native_yaml = REQUEST_ID_COMPAT.replace("kuadrant_compat: true", "kuadrant_compat: false");
    for (yaml, expected) in [(native_yaml.as_str(), false), (REQUEST_ID_COMPAT, true)] {
        mgr.load_config_yaml(yaml).expect("reload policy");
        mgr.initialize().await.expect("initialize reloaded policy");
        assert_eq!(mgr.kuadrant_compat(), expected);
        assert_eq!(
            http_request_id_allows(&mgr, Some("req-abc"), None).await,
            expected,
            "reload must replace the config resolver and apply kuadrant_compat={expected}"
        );
    }
}
