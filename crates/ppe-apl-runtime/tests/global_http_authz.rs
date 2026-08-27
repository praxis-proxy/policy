// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end: a `global` APL policy is evaluated for a generic
// (non-MCP/A2A) HTTP request that carries no entity. The visitor installs
// a catch-all handler under (ENTITY_HTTP, ENTITY_NAME_GLOBAL,
// HOOK_HTTP_REQUEST); the host fires that hook with `meta` set to the
// reserved coordinates and an `http` extension carrying the request line.
// This is the entity-less authorization path for an L7 proxy. It also exercises
// (http.method in the bag) and custom denyWith via the route
// `response:` block surfaced on the violation details.

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
use std::sync::Arc;

use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::{PluginError as CoreError, PluginViolation};
use praxis_policy_core::extensions::{Extensions, HttpExtension, MetaExtension};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, HttpHook, HttpPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::AnyHookHandler;

use praxis_policy_apl_cmf::constants::{DETAIL_HTTP_BODY, DETAIL_HTTP_HEADERS, DETAIL_HTTP_STATUS};
use praxis_policy_apl_runtime::{AplOptions, register_apl};

async fn manager_with(yaml: &str) -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

/// A generic-HTTP request: reserved entity coordinates + an `http`
/// extension carrying the request method.
fn http_request(method: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(ENTITY_HTTP.to_owned());
    meta.entity_name = Some(ENTITY_NAME_GLOBAL.to_owned());
    let http = HttpExtension {
        method: Some(method.to_owned()),
        ..Default::default()
    };
    Extensions {
        meta: Some(Arc::new(meta)),
        http: Some(Arc::new(http)),
        ..Default::default()
    }
}

/// The same request with a path on it, which is what a host supplies once it
/// carries the request line. A configuration declaring no `http:` route must
/// not read it differently for being there.
fn http_request_with_path(method: &str, path: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(ENTITY_HTTP.to_owned());
    meta.entity_name = Some(ENTITY_NAME_GLOBAL.to_owned());
    let http = HttpExtension {
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        ..Default::default()
    };
    Extensions {
        meta: Some(Arc::new(meta)),
        http: Some(Arc::new(http)),
        ..Default::default()
    }
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "hi"),
    }
}

/// An MCP tool-call request: `meta` naming a `tool` entity, no `http` ext.
fn tool_request(name: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_owned());
    meta.entity_name = Some(name.to_owned());
    Extensions {
        meta: Some(Arc::new(meta)),
        ..Default::default()
    }
}

/// An MCP tool-call request that also carries an `http` extension — the
/// shape a host produces when it enriches an entity request with the HTTP
/// request line so one policy can combine `http.*` and entity attributes.
fn tool_request_with_http(name: &str, method: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_owned());
    meta.entity_name = Some(name.to_owned());
    let http = HttpExtension {
        method: Some(method.to_owned()),
        ..Default::default()
    };
    Extensions {
        meta: Some(Arc::new(meta)),
        http: Some(Arc::new(http)),
        ..Default::default()
    }
}

// APL predicate:action form: deny when the method is not GET. (Comparisons
// use this form; `require(...)` is truthiness-only.)
const GET_ONLY: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    pre_invocation:
      - "http.method != 'GET': deny"
"#;

// The return half: a post-phase step at global scope, which only the
// response hook can carry. Authorization is an admission check and has
// nothing to say once the upstream has answered.
const POST_ONLY: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    post_invocation:
      - "http.method != 'GET': deny"
"#;

#[tokio::test]
async fn a_global_post_phase_policy_is_annotated_under_the_response_hook() {
    let mgr = manager_with(POST_ONLY).await;
    assert!(
        mgr.has_hooks_for(HOOK_HTTP_RESPONSE),
        "a post-phase global policy must install the response handler",
    );
    assert!(
        !mgr.has_hooks_for(HOOK_HTTP_REQUEST),
        "a post-only global policy gains no request handler",
    );

    let (allowed, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, http_request("GET"), None)
        .await;
    assert!(
        allowed.continue_processing,
        "GET must pass; violation = {:?}",
        allowed.violation
    );

    let (denied, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, http_request("POST"), None)
        .await;
    assert!(
        !denied.continue_processing,
        "the post-phase policy must evaluate on the response hook"
    );
}

// Both halves declared. The gap this closes: a regression that dropped the
// request handler when a post block was present would be an authorization
// bypass, and every other test here declares only one phase.
const BOTH_PHASES: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    pre_invocation:
      - "http.method == 'POST': deny"
    post_invocation:
      - "http.method == 'TRACE': deny"
"#;

#[tokio::test]
async fn both_http_halves_install_and_evaluate_independently() {
    let mgr = manager_with(BOTH_PHASES).await;
    assert!(
        mgr.has_hooks_for(HOOK_HTTP_REQUEST),
        "the request handler must survive a policy that also declares post steps",
    );
    assert!(mgr.has_hooks_for(HOOK_HTTP_RESPONSE));

    // The request half still enforces its own rule and not the post one.
    let (denied_pre, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request("POST"), None)
        .await;
    assert!(!denied_pre.continue_processing, "POST denied on the way in");

    let (allowed_pre, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request("TRACE"), None)
        .await;
    assert!(
        allowed_pre.continue_processing,
        "TRACE is the post rule; the request half must not apply it",
    );

    // And the response half enforces its rule and not the pre one.
    let (denied_post, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, http_request("TRACE"), None)
        .await;
    assert!(
        !denied_post.continue_processing,
        "TRACE denied on the way out"
    );

    let (allowed_post, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, http_request("POST"), None)
        .await;
    assert!(
        allowed_post.continue_processing,
        "POST is the pre rule; the response half must not apply it",
    );
}

#[tokio::test]
async fn a_pre_only_global_policy_installs_no_response_handler() {
    let mgr = manager_with(GET_ONLY).await;
    assert!(mgr.has_hooks_for(HOOK_HTTP_REQUEST));
    assert!(
        !mgr.has_hooks_for(HOOK_HTTP_RESPONSE),
        "a policy that only authorizes gains no response handler",
    );

    // And firing the request hook alone behaves exactly as before.
    let (res, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request("POST"), None)
        .await;
    assert!(!res.continue_processing);
}

#[tokio::test]
async fn global_policy_allows_matching_http_request() {
    let mgr = manager_with(GET_ONLY).await;
    let (res, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request("GET"), None)
        .await;
    assert!(
        res.continue_processing,
        "GET must be allowed by the global policy; violation = {:?}",
        res.violation
    );
}

#[tokio::test]
async fn global_policy_denies_nonmatching_http_request() {
    let mgr = manager_with(GET_ONLY).await;
    let (res, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request("POST"), None)
        .await;
    assert!(
        !res.continue_processing,
        "POST must be denied by the global policy"
    );
}

/// A route-level `response:` block (transpiled `denyWith`) surfaces custom
/// status/body/headers on the violation `details` map when the global
/// policy denies.
#[tokio::test]
async fn global_policy_deny_carries_custom_response() {
    const YAML: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    pre_invocation:
      - "http.method != 'GET': deny"
  response:
    status: 403
    body: "{\"error\":\"forbidden\"}"
    headers:
      X-Reason: "method-not-allowed"
"#;
    let mgr = manager_with(YAML).await;
    let (res, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request("DELETE"), None)
        .await;
    assert!(!res.continue_processing, "DELETE must be denied");
    let v = res.violation.expect("deny must surface a violation");
    assert_eq!(
        v.details.get(DETAIL_HTTP_STATUS),
        Some(&serde_json::json!(403))
    );
    assert_eq!(
        v.details.get(DETAIL_HTTP_BODY),
        Some(&serde_json::json!("{\"error\":\"forbidden\"}"))
    );
    assert_eq!(
        v.details.get(DETAIL_HTTP_HEADERS),
        Some(&serde_json::json!({ "X-Reason": "method-not-allowed" }))
    );
}

/// A `global` `response:` (the entity-less HTTP catch-all denyWith) must NOT
/// be inherited by an entity route. A denied MCP tool call gets the plain
/// violation shape — no `http.*` details leaked from the global block.
#[tokio::test]
async fn global_response_does_not_leak_onto_entity_denial() {
    const YAML: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    pre_invocation:
      - "require(authenticated)"
  response:
    status: 403
    body: "{\"error\":\"global\"}"
routes:
  - tool: locked
    apl:
      pre_invocation:
        - "require(authenticated)"
"#;
    let mgr = manager_with(YAML).await;
    let (res, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            tool_request("locked"),
            None,
        )
        .await;
    assert!(!res.continue_processing, "tool policy must deny");
    let v = res.violation.expect("deny must surface a violation");
    assert!(
        !v.details.contains_key(DETAIL_HTTP_STATUS)
            && !v.details.contains_key(DETAIL_HTTP_BODY)
            && !v.details.contains_key(DETAIL_HTTP_HEADERS),
        "global response leaked onto entity denial: {:?}",
        v.details
    );
}

/// Entity routes are granted `read_headers`, so a tool route's rule can read
/// `http.*` from an enriched request. The route denies when the HTTP method
/// is GET: a GET tool request is denied only if `http.method` actually reached
/// the entity bag, which proves the capability grant. A POST request (the
/// predicate is false) passes, confirming the method is genuinely read.
#[tokio::test]
async fn entity_route_reads_http_attributes() {
    const YAML: &str = r#"
plugin_settings:
  routing_enabled: true
routes:
  - tool: echo
    apl:
      pre_invocation:
        - "http.method == 'GET': deny"
"#;
    let mgr = manager_with(YAML).await;

    let (denied, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            tool_request_with_http("echo", "GET"),
            None,
        )
        .await;
    assert!(
        !denied.continue_processing,
        "GET tool request must be denied — proves http.method reached the entity bag (read_headers granted)",
    );

    let (allowed, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            tool_request_with_http("echo", "POST"),
            None,
        )
        .await;
    assert!(
        allowed.continue_processing,
        "POST tool request must pass (http.method == 'GET' is false); violation = {:?}",
        allowed.violation,
    );
}

/// A route-scoped `response:` still decorates that route's own denial — the
/// feature works per-route; only silent inheritance was removed.
#[tokio::test]
async fn route_scoped_response_still_decorates_entity_denial() {
    const YAML: &str = r#"
plugin_settings:
  routing_enabled: true
routes:
  - tool: locked
    apl:
      pre_invocation:
        - "require(authenticated)"
    response:
      status: 401
      body: "route"
"#;
    let mgr = manager_with(YAML).await;
    let (res, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload(),
            tool_request("locked"),
            None,
        )
        .await;
    assert!(!res.continue_processing, "tool policy must deny");
    let v = res.violation.expect("deny must surface a violation");
    assert_eq!(
        v.details.get(DETAIL_HTTP_STATUS),
        Some(&serde_json::json!(401))
    );
    assert_eq!(
        v.details.get(DETAIL_HTTP_BODY),
        Some(&serde_json::json!("route"))
    );
}

// =====================================================================
// A request line on a configuration that declares no `http:` route
// =====================================================================

/// A request carrying a path is governed by the same global policy as one
/// without, since nothing in this configuration selects on a path.
#[tokio::test]
async fn a_request_carrying_a_path_is_governed_by_the_global_policy_unchanged() {
    let mgr = manager_with(GET_ONLY).await;

    for path in ["/v1/files/q3.pdf", "/healthz", "/"] {
        let (allowed, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request_with_path("GET", path),
                None,
            )
            .await;
        assert!(
            allowed.continue_processing,
            "GET {path} must be allowed; violation = {:?}",
            allowed.violation
        );

        let (denied, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_REQUEST,
                HttpPayload,
                http_request_with_path("POST", path),
                None,
            )
            .await;
        assert!(
            !denied.continue_processing,
            "POST {path} must be denied, exactly as it is with no path at all"
        );
    }
}

/// The path the host populated is what a global rule reads. Nothing normalizes
/// it on the way to the attribute bag.
#[tokio::test]
async fn a_global_rule_reads_the_path_the_host_populated() {
    const YAML: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    pre_invocation:
      - "http.path == '/admin/./x': deny"
"#;
    let mgr = manager_with(YAML).await;

    let (denied, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            http_request_with_path("GET", "/admin/./x"),
            None,
        )
        .await;
    assert!(
        !denied.continue_processing,
        "the rule matches the path as written, dot segment included"
    );

    let (allowed, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            http_request_with_path("GET", "/admin/x"),
            None,
        )
        .await;
    assert!(
        allowed.continue_processing,
        "and the resolved spelling is a different string to a policy author;          violation = {:?}",
        allowed.violation
    );
}

/// A path no route could have answered for is not denied over. Nothing here
/// selects on a path, so there is nothing for an unreadable one to defeat.
#[tokio::test]
async fn an_unreadable_path_still_allows_when_no_route_selects_on_one() {
    let mgr = manager_with(GET_ONLY).await;

    let (res, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            http_request_with_path("GET", "/a/%zz"),
            None,
        )
        .await;
    assert!(
        res.continue_processing,
        "the global policy still decides; violation = {:?}",
        res.violation
    );
}

// =====================================================================
// A route installs only the halves it declares
// =====================================================================

/// A plugin that denies, so a scenario can see whether the response-side
/// plugin chain ran at all. An empty post handler installed over a route
/// would suppress it, and the difference is invisible to `has_hooks_for`.
struct ResponseGate {
    cfg: PluginConfig,
}

#[async_trait::async_trait]
impl Plugin for ResponseGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<HttpHook> for ResponseGate {
    async fn handle(
        &self,
        _payload: &HttpPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<HttpPayload> {
        PluginResult::deny(PluginViolation::new(
            "policy.forbidden",
            "response-gate fired",
        ))
    }
}

struct ResponseGateFactory;
impl PluginFactory for ResponseGateFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(ResponseGate {
            cfg: config.clone(),
        });
        let adapter: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin,
            handlers: vec![(HOOK_HTTP_RESPONSE, adapter)],
        })
    }
}

async fn manager_with_response_gate(yaml: &str) -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory("response-gate", Box::new(ResponseGateFactory));
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

// A pre-only global policy plus an always-on response-side plugin. The
// plugin sits in the `all` group so it is activated whether or not a route
// matched, which is what makes the two configurations comparable.
const RESPONSE_CHAIN_NO_ROUTE: &str = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: response-gate
    kind: response-gate
    hooks: [http.response]
global:
  policies:
    all:
      plugins: [response-gate]
  apl:
    pre_invocation:
      - "http.method != 'GET': deny"
"#;

// The same configuration with a catch-all route added. The route declares no
// body of its own, so it inherits the global pre-only policy and has nothing
// to say on the response half.
const RESPONSE_CHAIN_WITH_CATCHALL: &str = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: response-gate
    kind: response-gate
    hooks: [http.response]
global:
  policies:
    all:
      plugins: [response-gate]
  apl:
    pre_invocation:
      - "http.method != 'GET': deny"
routes:
  - http:
      path_prefix: /
"#;

/// Adding a body-less catch-all route must not change what governs the
/// response half. A route that installs an empty post handler short-circuits
/// the response-side plugin chain and turns a denial into a silent allow.
/// `has_hooks_for` cannot witness this, since the plugin is itself registered
/// for the response hook, so the denial is the assertion.
#[tokio::test]
async fn a_bodyless_catchall_route_resolves_the_same_response_chain() {
    for (label, yaml) in [
        ("no route", RESPONSE_CHAIN_NO_ROUTE),
        ("catch-all route", RESPONSE_CHAIN_WITH_CATCHALL),
    ] {
        let mgr = manager_with_response_gate(yaml).await;
        let (res, _bg) = mgr
            .invoke_named::<HttpHook>(
                HOOK_HTTP_RESPONSE,
                HttpPayload,
                http_request_with_path("GET", "/v1/files/q3.pdf"),
                None,
            )
            .await;
        assert!(
            !res.continue_processing,
            "{label}: the response-side plugin chain must run and deny",
        );
        let v = res
            .violation
            .unwrap_or_else(|| panic!("{label}: deny must surface a violation"));
        assert_eq!(v.code, "policy.forbidden", "{label}: whose denial it is");
    }
}

// A route that declares both halves itself, so neither guard may skip.
const ROUTE_BOTH_HALVES: &str = r#"
plugin_settings:
  routing_enabled: true
routes:
  - http:
      path_prefix: /
    apl:
      pre_invocation:
        - "http.method == 'POST': deny"
      post_invocation:
        - "http.method == 'TRACE': deny"
"#;

/// A route declaring both halves still installs both, and each half enforces
/// only its own rule.
#[tokio::test]
async fn a_route_declaring_both_halves_installs_both() {
    let mgr = manager_with(ROUTE_BOTH_HALVES).await;
    assert!(mgr.has_hooks_for(HOOK_HTTP_REQUEST));
    assert!(mgr.has_hooks_for(HOOK_HTTP_RESPONSE));

    let (denied_pre, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            http_request_with_path("POST", "/anything"),
            None,
        )
        .await;
    assert!(
        !denied_pre.continue_processing,
        "the route's request half denies POST"
    );

    let (allowed_pre, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            http_request_with_path("TRACE", "/anything"),
            None,
        )
        .await;
    assert!(
        allowed_pre.continue_processing,
        "TRACE is the post rule; violation = {:?}",
        allowed_pre.violation
    );

    let (denied_post, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_RESPONSE,
            HttpPayload,
            http_request_with_path("TRACE", "/anything"),
            None,
        )
        .await;
    assert!(
        !denied_post.continue_processing,
        "the route's response half denies TRACE"
    );

    let (allowed_post, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_RESPONSE,
            HttpPayload,
            http_request_with_path("POST", "/anything"),
            None,
        )
        .await;
    assert!(
        allowed_post.continue_processing,
        "POST is the pre rule; violation = {:?}",
        allowed_post.violation
    );
}

// A body-less route over a pre-only global body. Layer seeding still stacks
// `global` into the route, so the request half is governed.
const BODYLESS_ROUTE_OVER_GLOBAL: &str = r#"
plugin_settings:
  routing_enabled: true
global:
  apl:
    pre_invocation:
      - "http.method != 'GET': deny"
routes:
  - http:
      path_prefix: /
"#;

/// A route with no `apl:` block still receives the global policy on the half
/// that declares steps, and gains no handler on the half that does not.
#[tokio::test]
async fn a_bodyless_route_still_receives_the_global_policy() {
    let mgr = manager_with(BODYLESS_ROUTE_OVER_GLOBAL).await;
    assert!(
        mgr.has_hooks_for(HOOK_HTTP_REQUEST),
        "the inherited global pre-phase policy installs the request handler",
    );
    assert!(
        !mgr.has_hooks_for(HOOK_HTTP_RESPONSE),
        "and nothing in either layer declares response steps",
    );

    let (denied, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            http_request_with_path("POST", "/v1/files/q3.pdf"),
            None,
        )
        .await;
    assert!(
        !denied.continue_processing,
        "the global rule governs the route's request half"
    );

    let (allowed, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            http_request_with_path("GET", "/v1/files/q3.pdf"),
            None,
        )
        .await;
    assert!(
        allowed.continue_processing,
        "GET still passes; violation = {:?}",
        allowed.violation
    );
}
