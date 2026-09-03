// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end: a generic HTTP request matches a route by its request line.
//
// Every scenario below drives a real engine the way a host does: unified
// config YAML through `load_config_yaml`, the APL visitor installing route
// handlers, then `invoke_named` on the HTTP hooks with `meta` set to the
// reserved coordinates and the request line on the `http` slot. What the
// scenarios check is which policy governed the request and which plugins
// fired, not how resolution reached that answer.
//
// The entity-less path this builds on is covered by `global_http_authz.rs`,
// whose assertions are the compatibility evidence that a configuration
// declaring no `http:` route resolves as it always has.
//
// One thing worth knowing before reading the `/healthz` scenarios: the visitor
// stacks the global layer into every route before deciding whether a route
// declares any phase, so a route with no policy block still receives a handler
// carrying the global policy whenever a global body exists. An exact route
// "inherits nothing" only in the structural sense, meaning no sibling route's
// body or plugin list reaches it. That is why the worked example keeps its JWT
// plugin on the catch-all route rather than under `global:`.

#![allow(
    missing_docs,
    clippy::needless_raw_string_hashes,
    clippy::field_reassign_with_default,
    clippy::needless_raw_strings,
    trivial_casts,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::{PolicyEngine, VIOLATION_UNREADABLE_REQUEST_PATH};
use praxis_policy_core::error::PluginError as CoreError;
use praxis_policy_core::extensions::{
    Extensions, HttpExtension, MetaExtension, SecurityExtension, SubjectExtension,
};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::trait_def::{HookHandler, HookTypeDef as _, PluginResult};
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, HttpHook, HttpPayload};
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::AnyHookHandler;

use praxis_policy_apl_core::step::{PdpFactory, PdpResolver};
use praxis_policy_apl_core::{AttributeBag, Decision, PdpCall, PdpDecision, PdpDialect, PdpError};
use praxis_policy_apl_runtime::{AplOptions, register_apl};

// =====================================================================
// What a scenario observes
// =====================================================================

/// One plugin invocation, with the two request values a scenario asserts on.
/// Both come from the extensions the plugin was handed, so they also witness
/// that resolution left them alone.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    plugin: String,
    path: Option<String>,
    entity_name: Option<String>,
}

type Ledger = Arc<Mutex<Vec<Seen>>>;

fn record(ledger: &Ledger, plugin: &str, ext: &Extensions) {
    ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Seen {
            plugin: plugin.to_owned(),
            path: ext.http.as_ref().and_then(|http| http.path.clone()),
            entity_name: ext.meta.as_ref().and_then(|meta| meta.entity_name.clone()),
        });
}

/// The plugin names that fired, in order.
fn fired(ledger: &Ledger) -> Vec<String> {
    ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|seen| seen.plugin.clone())
        .collect()
}

fn observations(ledger: &Ledger) -> Vec<Seen> {
    ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn clear(ledger: &Ledger) {
    ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

// =====================================================================
// Test plugins
// =====================================================================

/// A plugin that records and allows. Registers on whichever hooks its config
/// declares, so one fixture can bind it to either HTTP half or to an entity
/// hook. It handles both families because the two carry different payloads and
/// a fixture in this file uses both.
struct RecordingGate {
    cfg: PluginConfig,
    ledger: Ledger,
}

#[async_trait]
impl Plugin for RecordingGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<HttpHook> for RecordingGate {
    async fn handle(
        &self,
        _payload: &HttpPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<HttpPayload> {
        record(&self.ledger, &self.cfg.name, ext);
        PluginResult::allow()
    }
}

impl HookHandler<CmfHook> for RecordingGate {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        record(&self.ledger, &self.cfg.name, ext);
        PluginResult::allow()
    }
}

/// Which family a hook name belongs to. The two HTTP names carry
/// `HttpPayload`; everything else in this file carries a CMF message.
fn is_http_hook(hook: &str) -> bool {
    hook == HOOK_HTTP_REQUEST || hook == HOOK_HTTP_RESPONSE
}

struct RecordingGateFactory(Ledger);

impl PluginFactory for RecordingGateFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(RecordingGate {
            cfg: config.clone(),
            ledger: Arc::clone(&self.0),
        });
        let handlers = config
            .hooks
            .iter()
            .map(|hook| {
                let name: &'static str = Box::leak(hook.clone().into_boxed_str());
                // The handler has to match the payload the hook name carries,
                // so the adapter is picked per name rather than per plugin.
                let adapter: Arc<dyn AnyHookHandler> = if is_http_hook(name) {
                    Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&plugin)))
                } else {
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)))
                };
                (name, adapter)
            })
            .collect();
        Ok(PluginInstance { plugin, handlers })
    }
}

/// An identity resolver that records and passes the payload through. Stands in
/// for a real authentication plugin: what the scenarios need from it is which
/// list dispatched it, not what it would have proved about a token.
struct RecordingResolver {
    cfg: PluginConfig,
    ledger: Ledger,
}

#[async_trait]
impl Plugin for RecordingResolver {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<IdentityHook> for RecordingResolver {
    async fn handle(
        &self,
        _payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        record(&self.ledger, &self.cfg.name, ext);
        PluginResult::allow()
    }
}

struct RecordingResolverFactory(Ledger);

impl PluginFactory for RecordingResolverFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(RecordingResolver {
            cfg: config.clone(),
            ledger: Arc::clone(&self.0),
        });
        let adapter: Arc<dyn AnyHookHandler> = Arc::new(
            TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(&plugin)),
        );
        Ok(PluginInstance {
            plugin,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, adapter)],
        })
    }
}

/// An allow-everything CEL resolver. The transpiled fixture declares a `cel:`
/// PDP, and what this file checks about that fixture is that its global policy
/// still governs generic HTTP traffic, not what its expressions decide.
struct AllowCel;

#[async_trait]
impl PdpResolver for AllowCel {
    fn dialect(&self) -> PdpDialect {
        PdpDialect::Cel
    }
    async fn evaluate(
        &self,
        _call: &PdpCall,
        _bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        Ok(PdpDecision {
            decision: Decision::Allow,
            diagnostics: vec![],
        })
    }
}

struct AllowCelFactory;

impl PdpFactory for AllowCelFactory {
    fn kind(&self) -> &str {
        "cel"
    }
    fn build(
        &self,
        _config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Arc::new(AllowCel))
    }
}

// =====================================================================
// Harness
// =====================================================================

/// An initialized engine for `yaml`, plus the ledger its plugins write to.
async fn engine_with(yaml: &str) -> (Arc<PolicyEngine>, Ledger) {
    let ledger: Ledger = Arc::new(Mutex::new(Vec::new()));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "test/record",
        Box::new(RecordingGateFactory(Arc::clone(&ledger))),
    );
    mgr.register_factory(
        "test/identity",
        Box::new(RecordingResolverFactory(Arc::clone(&ledger))),
    );
    // The transpiled fixture names the real JWT plugin's kind; the recording
    // resolver stands in for it so the fixture stays the demo's document.
    mgr.register_factory(
        "identity/jwt",
        Box::new(RecordingResolverFactory(Arc::clone(&ledger))),
    );
    register_apl(
        &mgr,
        AplOptions {
            pdp_factories: vec![Arc::new(AllowCelFactory)],
            ..AplOptions::in_process()
        },
    );
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    (mgr, ledger)
}

/// The message a configuration is rejected with.
fn load_failure(yaml: &str) -> String {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(yaml)
        .expect_err("the configuration must be rejected")
        .to_string()
}

/// A generic HTTP request as a host presents one: the reserved entity
/// coordinates, and the request line on its own slot.
fn request(method: &str, path: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(ENTITY_HTTP.to_owned());
    meta.entity_name = Some(ENTITY_NAME_GLOBAL.to_owned());
    Extensions {
        meta: Some(Arc::new(meta)),
        http: Some(Arc::new(HttpExtension {
            method: Some(method.to_owned()),
            path: Some(path.to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// The same request with an authenticated subject attached, which is what a
/// host presents once identity resolution has run.
fn authenticated_request(method: &str, path: &str) -> Extensions {
    let mut ext = request(method, path);
    ext.security = Some(Arc::new(SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some("alice".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }));
    ext
}

/// The response half of one exchange: the same request line the host presented
/// on the way in, plus the status the upstream returned.
fn response(method: &str, path: &str, status: u16) -> Extensions {
    let mut ext = request(method, path);
    ext.http = Some(Arc::new(HttpExtension {
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        status: Some(status),
        ..Default::default()
    }));
    ext
}

/// An HTTP request carrying a method but no path. This is the shape a host
/// produces before it has attached the request line, and the shape that
/// resolves no `http:` route however many are declared.
fn request_without_path(method: &str) -> Extensions {
    let mut ext = request(method, "/unused");
    ext.http = Some(Arc::new(HttpExtension {
        method: Some(method.to_owned()),
        ..Default::default()
    }));
    ext
}

fn tool_request(name: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_owned());
    meta.entity_name = Some(name.to_owned());
    Extensions {
        meta: Some(Arc::new(meta)),
        ..Default::default()
    }
}

fn entity_request(entity_type: &str, name: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(entity_type.to_owned());
    meta.entity_name = Some(name.to_owned());
    Extensions {
        meta: Some(Arc::new(meta)),
        ..Default::default()
    }
}

/// Fire one hook the way a host does, with the payload its family carries.
async fn fire(mgr: &PolicyEngine, hook: &str, ext: Extensions) -> bool {
    if is_http_hook(hook) {
        let (result, _bg) = mgr
            .invoke_named::<HttpHook>(hook, HttpPayload, ext, None)
            .await;
        return result.continue_processing;
    }
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            hook,
            MessagePayload {
                message: Message::text(Role::User, "hi"),
            },
            ext,
            None,
        )
        .await;
    result.continue_processing
}

async fn resolve_identity(mgr: &PolicyEngine, ext: Extensions) {
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            IdentityPayload::new("eyJ.fake.jwt", TokenSource::Bearer),
            ext,
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "identity resolution must not deny here; violation = {:?}",
        result.violation
    );
}

// =====================================================================
// Fixtures
// =====================================================================

/// The worked example from the requirements, verbatim in shape: a prefix route
/// with an authentication list and a policy body, an exact health route, and a
/// catch-all carrying the JWT plugin. The JWT plugin belongs to the catch-all
/// route and not to `global:` on purpose: under `global:` its policy would
/// stack into the health route too.
const WORKED_EXAMPLE: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: files-authn
    kind: test/identity
    hooks: [identity.resolve]
  - name: files-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: jwt
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /v1/files
    authentication:
      - files-authn
    authorization:
      pre_invocation:
        - "run(files-audit)"
  - http: /healthz
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - "run(jwt)"
"#;

/// A prefix route that layers everything a route can layer: the bundle it joins
/// contributes an `authorization:` layer, and the route adds its own body plus
/// its own `authentication:` step.
const LAYERED_PREFIX_ROUTE: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: files-authn
    kind: test/identity
    hooks: [identity.resolve]
  - name: group-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: route-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
groups:
  files-readers:
    authorization:
      pre_invocation:
        - "run(group-audit)"
routes:
  - http:
      path_prefix: /v1/files
    meta:
      tags: [files-readers]
    authentication:
      - files-authn
    authorization:
      pre_invocation:
        - "run(route-audit)"
"#;

/// Two prefixes plus a catch-all, so a path written as a traversal out of one
/// of them has somewhere else it could plausibly have landed.
const NESTED_PREFIXES: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: files-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: admin-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: catch-all-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(files-audit)"
  - http:
      path_prefix: /admin
    authorization:
      pre_invocation:
        - "run(admin-audit)"
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - "run(catch-all-audit)"
"#;

// =====================================================================
// The route a request resolves, and what layers onto it
// =====================================================================

/// A prefix route's bundle layer and its own body both reach a request that
/// matches its path, in that order.
#[tokio::test]
async fn a_prefix_route_layers_its_bundle_and_its_own_body() {
    let (mgr, ledger) = engine_with(LAYERED_PREFIX_ROUTE).await;

    resolve_identity(&mgr, request("GET", "/v1/files/q3.pdf")).await;
    assert_eq!(
        fired(&ledger),
        vec!["files-authn".to_owned()],
        "the route's authentication list must dispatch for a matching path"
    );

    clear(&ledger);
    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/v1/files/q3.pdf")).await);
    let mut ran = fired(&ledger);
    ran.sort();
    assert_eq!(
        ran,
        vec!["group-audit".to_owned(), "route-audit".to_owned()],
        "the group bundle and the route's own plugins both layer onto the match"
    );
}

/// An exact route inherits no sibling route's policy, while the catch-all
/// governs everything the exact routes do not name.
#[tokio::test]
async fn an_exact_route_inherits_nothing_while_the_catch_all_governs_the_rest() {
    let (mgr, ledger) = engine_with(WORKED_EXAMPLE).await;

    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/healthz")).await);
    assert!(
        fired(&ledger).is_empty(),
        "the health route declares nothing, so nothing runs for it; saw {:?}",
        fired(&ledger)
    );

    clear(&ledger);
    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/metrics")).await);
    assert_eq!(
        fired(&ledger),
        vec!["jwt".to_owned()],
        "a path no exact route names is governed by the catch-all"
    );
}

/// The worked example's prefix route runs its own authentication list and its
/// own body, and the catch-all's body does not reach it.
#[tokio::test]
async fn the_worked_examples_prefix_route_runs_its_own_authentication_and_body() {
    let (mgr, ledger) = engine_with(WORKED_EXAMPLE).await;

    resolve_identity(&mgr, request("GET", "/v1/files/q3.pdf")).await;
    assert_eq!(
        fired(&ledger),
        vec!["files-authn".to_owned()],
        "the prefix route's authentication list dispatches for a path it covers"
    );

    clear(&ledger);
    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/v1/files/q3.pdf")).await);
    assert_eq!(
        fired(&ledger),
        vec!["files-audit".to_owned()],
        "the more specific route's body governs, and the catch-all's does not          layer onto it"
    );
}

/// A declared method narrows the route: the same path under another method
/// resolves elsewhere.
#[tokio::test]
async fn a_method_narrowed_route_matches_only_the_methods_it_declares() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: files-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      method: GET
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(files-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/v1/files/q3.pdf")).await);
    assert_eq!(
        fired(&ledger),
        vec!["files-audit".to_owned()],
        "the declared method matches, so the route applies"
    );

    clear(&ledger);
    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("POST", "/v1/files/q3.pdf")).await);
    assert!(
        fired(&ledger).is_empty(),
        "the same path under another method must not reach the route; saw {:?}",
        fired(&ledger)
    );
}

/// Many distinct paths under one prefix share one cache entry per hook, and a
/// plugin still reads the individual request path and the entity name the host
/// set.
///
/// The count is read at `identity.resolve`, because an annotated hook returns
/// the compiled handler before route resolution caches anything, and
/// `http.request` is annotated here.
#[tokio::test]
async fn many_paths_under_one_prefix_share_a_cache_entry_and_keep_their_own_path() {
    let (mgr, ledger) = engine_with(LAYERED_PREFIX_ROUTE).await;

    for n in 0..25 {
        resolve_identity(&mgr, request("GET", &format!("/v1/files/report-{n}.pdf"))).await;
    }
    assert_eq!(
        mgr.routing_cache_size(),
        1,
        "the cache is keyed on the selector that matched, so its size follows \
         the configuration rather than the traffic"
    );

    clear(&ledger);
    for n in 0..25 {
        let path = format!("/v1/files/report-{n}.pdf");
        assert!(
            fire(&mgr, HOOK_HTTP_REQUEST, request("GET", &path)).await,
            "{path} must be allowed"
        );
    }

    let seen = observations(&ledger);
    assert_eq!(seen.len(), 50, "two plugins per request");
    assert!(
        seen.iter()
            .any(|s| s.path.as_deref() == Some("/v1/files/report-7.pdf")),
        "a plugin must still read the request's own path"
    );
    assert!(
        seen.iter()
            .all(|s| s.entity_name.as_deref() == Some(ENTITY_NAME_GLOBAL)),
        "and the entity name the host set, not the name resolution derived"
    );
}

// =====================================================================
// Dispatch
// =====================================================================

/// An `http:` route's policy body is the whole lineup: a plugin the body does
/// not name never runs, which is what the removed `plugins:` activation list
/// used to obscure.
#[tokio::test]
async fn an_http_route_reaches_only_the_plugins_its_body_names() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: body-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: chain-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(body-audit)"
  - http:
      path_prefix: /v1/archive
    authorization:
      pre_invocation:
        - "run(chain-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/v1/files/q3.pdf")).await);
    assert_eq!(
        fired(&ledger),
        vec!["body-audit".to_owned()],
        "chain-audit is declared and registered on the same hook, and reached by \
         another route's body, so what keeps it from firing here is that this \
         request matched a route whose body does not name it"
    );
}

/// A route declared with a trailing slash runs its body for the path it
/// declared and for nothing else. The annotation key and the resolved name are
/// both the path verbatim, so the body is reachable, and the spellings the
/// gateway router treats as other paths fall back to the global policy, which
/// this configuration leaves empty.
#[tokio::test]
async fn a_route_declared_with_a_trailing_slash_runs_its_body_for_that_spelling_only() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: body-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path: "/admin/"
    authorization:
      pre_invocation:
        - "run(body-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;
    assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/admin/")).await);
    assert_eq!(
        fired(&ledger),
        vec!["body-audit".to_owned()],
        "the body must run for the path the route declared"
    );

    for other in ["/admin", "/admin//"] {
        let (mgr, ledger) = engine_with(YAML).await;

        assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", other)).await);
        assert!(
            fired(&ledger).is_empty(),
            "`{other}` is another path to the router, so this route's body must \
             not run for it; saw {:?}",
            fired(&ledger)
        );
    }
}

/// A glob selector resolves request names to the annotation keyed by its pattern.
#[tokio::test]
async fn a_glob_entity_route_dispatches_its_body() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: body-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: "hr-*"
    authorization:
      pre_invocation:
        - "run(body-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request("hr-get-salary")).await);
    assert_eq!(
        fired(&ledger),
        vec!["body-audit".to_owned()],
        "the request name must resolve to the glob annotation"
    );
}

/// Every name matched by a glob shares its compiled body.
#[tokio::test]
async fn many_names_under_one_glob_share_its_body() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: body-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: "hr-*"
    authorization:
      pre_invocation:
        - "run(body-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    for name in ["hr-get-salary", "hr-adjust-comp"] {
        assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request(name)).await);
    }
    assert_eq!(
        fired(&ledger),
        vec!["body-audit".to_owned(), "body-audit".to_owned()],
        "every name the pattern covers reaches the one body it wrote"
    );
}

/// A bracket expression is a literal, not a character class.
///
/// `wildmatch` reads `*` and `?` and nothing else, so `hr-[a-z]` matches the
/// eight characters `hr-[a-z]` and no other name. That makes it an exact
/// selector: the annotation key and the request name agree whenever it matches,
/// which is why the glob detector does not look for `[`.
#[tokio::test]
async fn a_bracket_selector_is_matched_literally() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: body-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: "hr-[a-z]"
    authorization:
      pre_invocation:
        - "run(body-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    // The name a character class would have covered.
    assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request("hr-x")).await);
    assert!(fired(&ledger).is_empty(), "`hr-x` matches no route");

    // The literal spelling is what the selector names, and the exact lookup
    // finds its annotation with no glob resolution.
    clear(&ledger);
    assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request("hr-[a-z]")).await);
    assert_eq!(
        fired(&ledger),
        vec!["body-audit".to_owned()],
        "the literal name reaches the body"
    );
}

/// A name outside the glob reaches no body.
#[tokio::test]
async fn a_name_outside_the_glob_reaches_no_body() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: body-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: "hr-*"
    authorization:
      pre_invocation:
        - "run(body-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request("finance-close")).await);
    assert!(fired(&ledger).is_empty(), "the name matches no route");
}

/// An exact selector outranks a matching glob.
#[tokio::test]
async fn an_exact_entity_route_outranks_a_glob_that_also_matches() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: glob-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
  - name: exact-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: "hr-*"
    authorization:
      pre_invocation:
        - "run(glob-audit)"
  - tool: hr-get-salary
    authorization:
      pre_invocation:
        - "run(exact-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request("hr-get-salary")).await);
    assert_eq!(
        fired(&ledger),
        vec!["exact-audit".to_owned()],
        "the exact route must win"
    );

    clear(&ledger);
    assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request("hr-adjust-comp")).await);
    assert_eq!(
        fired(&ledger),
        vec!["glob-audit".to_owned()],
        "a name only the pattern covers still reaches the pattern's body"
    );
}

/// An exact route without policy still shadows a matching glob.
#[tokio::test]
async fn an_exact_route_with_no_body_shadows_a_glob_that_has_one() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: glob-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: "hr-*"
    authorization:
      pre_invocation:
        - "run(glob-audit)"
  - tool: hr-get-salary
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request("hr-get-salary")).await);
    assert!(
        fired(&ledger).is_empty(),
        "the glob body must not replace the more specific route's empty body"
    );
}

/// A list selector still dispatches per element.
#[tokio::test]
async fn a_list_selector_dispatches_per_element() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: body-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: [alpha, beta]
    authorization:
      pre_invocation:
        - "run(body-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    for name in ["alpha", "beta"] {
        assert!(fire(&mgr, "cmf.tool_pre_invoke", tool_request(name)).await);
    }
    assert_eq!(
        fired(&ledger),
        vec!["body-audit".to_owned(), "body-audit".to_owned()],
        "every element of the list reaches the same compiled body"
    );
}

/// Both halves of one exchange resolve the same route, so a contract attached
/// to a route governs both directions.
#[tokio::test]
async fn both_halves_of_one_exchange_resolve_the_same_route() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "http.method == 'POST': deny"
      post_invocation:
        - "http.method == 'TRACE': deny"
"#;
    let (mgr, _ledger) = engine_with(YAML).await;

    assert!(
        !fire(&mgr, HOOK_HTTP_REQUEST, request("POST", "/v1/files/q3.pdf")).await,
        "the request half resolves the route and applies its request rule"
    );
    assert!(
        fire(
            &mgr,
            HOOK_HTTP_REQUEST,
            request("TRACE", "/v1/files/q3.pdf")
        )
        .await,
        "and not the response rule"
    );
    assert!(
        !fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            request("TRACE", "/v1/files/q3.pdf")
        )
        .await,
        "the response half resolves the same route and applies its response rule"
    );
    assert!(
        fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            request("POST", "/v1/files/q3.pdf")
        )
        .await,
        "and not the request rule"
    );
}

/// A response-phase rule decides on the status the upstream returned.
#[tokio::test]
async fn a_post_phase_rule_denies_on_an_upstream_server_error() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      post_invocation:
        - "http.status >= 500: deny"
"#;
    let (mgr, _ledger) = engine_with(YAML).await;

    assert!(
        !fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            response("GET", "/v1/files/q3.pdf", 502)
        )
        .await,
        "a 502 satisfies the rule, so the response is denied"
    );
    assert!(
        fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            response("GET", "/v1/files/q3.pdf", 200)
        )
        .await,
        "a 200 does not, so it passes"
    );
    assert!(
        !fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            response("GET", "/v1/files/q3.pdf", 500)
        )
        .await,
        "the boundary is inclusive, so a 500 is denied too"
    );
    assert!(
        fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            response("GET", "/v1/files/q3.pdf", 499)
        )
        .await,
        "and a 499 is not"
    );
}

/// An equality rule reads the status as a number, not as a string. This pins
/// the bag representation: were it a string, `== 502` would compare a string
/// against an integer literal and answer false for every status.
#[tokio::test]
async fn a_post_phase_rule_matches_a_status_by_equality() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      post_invocation:
        - "http.status == 502: deny"
"#;
    let (mgr, _ledger) = engine_with(YAML).await;

    assert!(
        !fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            response("GET", "/v1/files/q3.pdf", 502)
        )
        .await,
        "the status reaches the bag as a number the literal can equal"
    );
    assert!(
        fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            response("GET", "/v1/files/q3.pdf", 503)
        )
        .await,
        "and a different status does not match"
    );
}

/// The request half carries no status, and a rule reading one there does not
/// fire: a missing bag key makes a comparison false, so the deny does not
/// trigger. A response-phase rule guarding a request-phase concern therefore
/// admits the request rather than denying it, which is why a status rule
/// belongs under `post_invocation:`.
#[tokio::test]
async fn a_status_rule_on_the_request_half_does_not_fire() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "http.status >= 500: deny"
        - "http.method == 'TRACE': deny"
"#;
    let (mgr, _ledger) = engine_with(YAML).await;

    assert!(
        fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/v1/files/q3.pdf")).await,
        "no status exists yet, so the comparison is false and the rule is inert"
    );
    assert!(
        !fire(
            &mgr,
            HOOK_HTTP_REQUEST,
            request("TRACE", "/v1/files/q3.pdf")
        )
        .await,
        "the rule beside it still governs, so the block itself is live"
    );
}

/// A host that never populates a status behaves exactly as it did before the
/// field existed: the response half resolves the same route and its other
/// rules still decide.
#[tokio::test]
async fn a_response_without_a_status_is_governed_as_before() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      post_invocation:
        - "http.status >= 500: deny"
        - "http.method == 'TRACE': deny"
"#;
    let (mgr, _ledger) = engine_with(YAML).await;

    assert!(
        fire(&mgr, HOOK_HTTP_RESPONSE, request("GET", "/v1/files/q3.pdf")).await,
        "a host that sets no status is not denied by the status rule"
    );
    assert!(
        !fire(
            &mgr,
            HOOK_HTTP_RESPONSE,
            request("TRACE", "/v1/files/q3.pdf")
        )
        .await,
        "and the rule beside it decides exactly as it did before"
    );
}

/// An explicit catch-all route and the implicit global catch-all are distinct
/// handlers: the route governs what it resolves, and the implicit one governs
/// what resolves to no route.
#[tokio::test]
async fn an_explicit_catch_all_and_the_implicit_one_do_not_displace_each_other() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  authorization:
    pre_invocation:
      - "http.method == 'TRACE': deny"
routes:
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - "http.method == 'POST': deny"
"#;
    let (mgr, _ledger) = engine_with(YAML).await;

    assert!(
        !fire(&mgr, HOOK_HTTP_REQUEST, request("POST", "/anything")).await,
        "a request that resolves the route is governed by the route's own rule"
    );
    assert!(
        !fire(&mgr, HOOK_HTTP_REQUEST, request("TRACE", "/anything")).await,
        "and by the global layer the route stacks"
    );
    assert!(
        fire(&mgr, HOOK_HTTP_REQUEST, request_without_path("POST")).await,
        "a request that resolves no route does not pick up the route's rule"
    );
    assert!(
        !fire(&mgr, HOOK_HTTP_REQUEST, request_without_path("TRACE")).await,
        "but the implicit catch-all is still installed and still governs it"
    );
}

// =====================================================================
// Specificity and segment boundaries
// =====================================================================

/// The longer prefix wins whichever order the two are declared in.
#[tokio::test]
async fn the_longer_prefix_wins_in_either_declaration_order() {
    const BROAD_FIRST: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: broad-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: narrow-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /v1
    authorization:
      pre_invocation:
        - "run(broad-audit)"
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(narrow-audit)"
"#;
    const NARROW_FIRST: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: broad-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: narrow-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(narrow-audit)"
  - http:
      path_prefix: /v1
    authorization:
      pre_invocation:
        - "run(broad-audit)"
"#;
    for yaml in [BROAD_FIRST, NARROW_FIRST] {
        let (mgr, ledger) = engine_with(yaml).await;
        assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/v1/files/q3.pdf")).await);
        assert_eq!(
            fired(&ledger),
            vec!["narrow-audit".to_owned()],
            "prefix length decides, so moving a route in the file changes nothing"
        );
    }
}

/// A route narrowed by `method:` wins the methods it names whichever order the
/// two are declared in, so the narrower policy runs rather than whichever route
/// was written first.
#[tokio::test]
async fn a_method_narrowed_route_wins_its_methods_in_either_declaration_order() {
    const PLUGINS: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: open-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
  - name: delete-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
"#;
    const OPEN: &str = r#"  - http:
      path_prefix: /api
    authorization:
      pre_invocation:
        - "run(open-audit)"
"#;
    const NARROWED: &str = r#"  - http:
      path_prefix: /api
      method: DELETE
    authorization:
      pre_invocation:
        - "run(delete-audit)"
"#;

    for (first, second) in [(OPEN, NARROWED), (NARROWED, OPEN)] {
        let yaml = format!("{PLUGINS}routes:\n{first}{second}");
        let (mgr, ledger) = engine_with(&yaml).await;

        assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("DELETE", "/api/x")).await);
        assert_eq!(
            fired(&ledger),
            vec!["delete-audit".to_owned()],
            "the narrowed route governs DELETE wherever it sits in the file"
        );

        clear(&ledger);
        assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/api/x")).await);
        assert_eq!(
            fired(&ledger),
            vec!["open-audit".to_owned()],
            "a method the narrowing does not name still lands on the open route"
        );
    }
}

/// A prefix matches only at a segment boundary. These are the cases the host
/// router's own suite covers, run here through a real engine.
#[tokio::test]
async fn a_prefix_matches_only_at_a_segment_boundary() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: api-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /api
    authorization:
      pre_invocation:
        - "run(api-audit)"
"#;
    // Same table, twice: once for the prefix as written and once with a
    // trailing slash, which must be insignificant.
    const YAML_TRAILING_SLASH: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: api-audit
    kind: test/record
    hooks: [http.request]
    capabilities: [read_headers]
routes:
  - http:
      path_prefix: /api/
    authorization:
      pre_invocation:
        - "run(api-audit)"
"#;
    for yaml in [YAML, YAML_TRAILING_SLASH] {
        let (mgr, ledger) = engine_with(yaml).await;
        for (path, should_match) in [
            ("/api", true),
            ("/api/", true),
            ("/api/v1", true),
            ("/apikeys", false),
        ] {
            clear(&ledger);
            assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", path)).await);
            let ran = fired(&ledger);
            assert_eq!(
                ran.is_empty(),
                !should_match,
                "{path} against a /api prefix: expected match={should_match}, saw {ran:?}"
            );
        }
    }
}

/// Two routes that would resolve to the same name are rejected at load, which
/// is the only way a specificity tie could have arisen.
#[tokio::test]
async fn two_routes_resolving_to_one_name_are_rejected_at_load() {
    const SAME_SELECTOR: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
  - http:
      path_prefix: /v1/files
"#;
    let msg = load_failure(SAME_SELECTOR);
    assert!(
        msg.contains("/v1/files"),
        "the error must name the colliding name: {msg}"
    );

    // Different selector values that overlap in one element. A comparison of
    // what was written would pass this.
    const OVERLAPPING_LISTS: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http: [/a, /b]
  - http: [/b, /c]
"#;
    let msg = load_failure(OVERLAPPING_LISTS);
    assert!(
        msg.contains("/b"),
        "the error must name the element both routes contribute: {msg}"
    );
}

// =====================================================================
// Path handling
// =====================================================================

/// A traversal stays under the prefix it was written under, written either
/// plainly or percent-encoded. The gateway's router resolves no dot segment, so
/// it forwards these under `/v1/files`; resolving them here would apply the
/// `/admin` route's policy to traffic the gateway sends to the files cluster.
#[tokio::test]
async fn a_traversal_stays_under_the_prefix_it_was_written_under() {
    let (mgr, ledger) = engine_with(NESTED_PREFIXES).await;

    for path in [
        "/v1/files/../../admin",
        "/v1/files/%2e%2e/%2e%2e/admin",
        "/v1/files/.%2e/%2e./admin",
    ] {
        clear(&ledger);
        assert!(fire(&mgr, HOOK_HTTP_REQUEST, request("GET", path)).await);
        assert_eq!(
            fired(&ledger),
            vec!["files-audit".to_owned()],
            "{path} resolves the route the request is actually forwarded to"
        );
    }
}

/// An encoded separator stays inside its segment, so the request resolves to
/// the route the written path selects rather than one a decoded path would.
#[tokio::test]
async fn an_encoded_separator_stays_inside_its_segment() {
    let (mgr, ledger) = engine_with(NESTED_PREFIXES).await;

    assert!(
        fire(
            &mgr,
            HOOK_HTTP_REQUEST,
            request("GET", "/admin/x/..%2f..%2fv1%2fok")
        )
        .await
    );
    assert_eq!(
        fired(&ledger),
        vec!["admin-audit".to_owned()],
        "decoding that segment would have handed an admin path a public route, \
         and would have disagreed with the router that picked the upstream"
    );
}

/// A path that cannot be read is denied rather than falling through to the
/// catch-all, which is the most permissive route in the configuration.
#[tokio::test]
async fn an_unreadable_path_is_denied_rather_than_reaching_the_catch_all() {
    let (mgr, ledger) = engine_with(NESTED_PREFIXES).await;

    let (result, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            request("GET", "/v1/files/%zz"),
            None,
        )
        .await;
    assert!(!result.continue_processing, "an unreadable path must deny");
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, VIOLATION_UNREADABLE_REQUEST_PATH);
    assert_eq!(
        violation.proto_error_code,
        Some(400),
        "the request is malformed rather than forbidden"
    );
    assert!(
        fired(&ledger).is_empty(),
        "and nothing runs for it, least of all the catch-all; saw {:?}",
        fired(&ledger)
    );
}

// =====================================================================
// Load-time rejection of a malformed selector
// =====================================================================

/// Declaring two selectors on one route fails at load and names both.
#[tokio::test]
async fn a_route_declaring_two_selectors_is_rejected_naming_both() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http: /healthz
    tool: get_weather
"#;
    let msg = load_failure(YAML);
    assert!(
        msg.contains("http") && msg.contains("tool"),
        "the error must name both selectors: {msg}"
    );
}

/// A misspelled selector key fails at load naming the key, rather than
/// reporting the missing entity matcher it turns into once serde drops it.
#[tokio::test]
async fn a_misspelled_selector_key_is_rejected_naming_the_key() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - htp: /healthz
"#;
    let msg = load_failure(YAML);
    assert!(
        msg.contains("htp"),
        "the error must name the key as written: {msg}"
    );
}

// =====================================================================
// Authentication and the host contract
// =====================================================================

/// A route's authentication list applies when the host supplies the request
/// line at the identity hook, and the global list applies when it does not.
/// The second half is today's behavior and stays it.
#[tokio::test]
async fn a_route_authentication_list_needs_the_request_line_to_apply() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: global-authn
    kind: test/identity
    hooks: [identity.resolve]
  - name: files-authn
    kind: test/identity
    hooks: [identity.resolve]
global:
  authentication:
    - global-authn
routes:
  - http:
      path_prefix: /v1/files
    authentication:
      replace_inherited: true
      steps:
        - files-authn
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    resolve_identity(&mgr, request("GET", "/v1/files/q3.pdf")).await;
    assert_eq!(
        fired(&ledger),
        vec!["files-authn".to_owned()],
        "with a request line the route's list replaces the inherited one"
    );

    clear(&ledger);
    resolve_identity(&mgr, request_without_path("GET")).await;
    assert_eq!(
        fired(&ledger),
        vec!["global-authn".to_owned()],
        "without one no route resolves, so the global list runs, as it does today"
    );
}

// =====================================================================
// Compatibility
// =====================================================================

/// A configuration exercising all four entity selectors, one of them a glob,
/// resolves and dispatches with no `http:` route anywhere in sight.
#[tokio::test]
async fn a_configuration_of_entity_selectors_only_resolves_as_it_always_has() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: tool-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
  - name: glob-audit
    kind: test/record
    hooks: [cmf.tool_pre_invoke]
  - name: resource-audit
    kind: test/record
    hooks: [cmf.resource_pre_fetch]
  - name: prompt-audit
    kind: test/record
    hooks: [cmf.prompt_pre_invoke]
  - name: llm-audit
    kind: test/record
    hooks: [cmf.llm_input]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(tool-audit)"
  - tool: "hr-*"
    authorization:
      pre_invocation:
        - "run(glob-audit)"
  - resource: "file:///data.csv"
    authorization:
      pre_invocation:
        - "run(resource-audit)"
  - prompt: summarize
    authorization:
      pre_invocation:
        - "run(prompt-audit)"
  - llm: gpt-4
    authorization:
      pre_invocation:
        - "run(llm-audit)"
"#;
    let (mgr, ledger) = engine_with(YAML).await;

    for (hook, ext, expected) in [
        (
            "cmf.tool_pre_invoke",
            tool_request("get_weather"),
            "tool-audit",
        ),
        // Resolve the request name to the glob pattern used as the annotation key.
        (
            "cmf.tool_pre_invoke",
            tool_request("hr-get-salary"),
            "glob-audit",
        ),
        (
            "cmf.resource_pre_fetch",
            entity_request("resource", "file:///data.csv"),
            "resource-audit",
        ),
        (
            "cmf.prompt_pre_invoke",
            entity_request("prompt", "summarize"),
            "prompt-audit",
        ),
        ("cmf.llm_input", entity_request("llm", "gpt-4"), "llm-audit"),
    ] {
        clear(&ledger);
        assert!(fire(&mgr, hook, ext).await, "{hook} must be allowed");
        let want: Vec<String> = if expected.is_empty() {
            Vec::new()
        } else {
            vec![expected.to_owned()]
        };
        assert_eq!(
            fired(&ledger),
            want,
            "{hook} must dispatch exactly the route it always did"
        );
    }
}

/// `http:` routes that leave a gap send the traffic they do not cover to the
/// global policy, which is the overlap the selector exists to close. The
/// load-time report of that gap is asserted where the finding is produced.
#[tokio::test]
async fn traffic_no_http_route_covers_falls_back_to_the_global_policy() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  authorization:
    pre_invocation:
      - "http.method == 'TRACE': deny"
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "http.method == 'POST': deny"
"#;
    let (mgr, _ledger) = engine_with(YAML).await;

    assert!(
        !fire(&mgr, HOOK_HTTP_REQUEST, request("POST", "/v1/files/q3.pdf")).await,
        "the covered path is governed by its route"
    );
    assert!(
        fire(&mgr, HOOK_HTTP_REQUEST, request("POST", "/elsewhere")).await,
        "an uncovered path does not pick up the route's rule"
    );
    assert!(
        !fire(&mgr, HOOK_HTTP_REQUEST, request("TRACE", "/elsewhere")).await,
        "it is governed by the global policy instead"
    );
}

/// The transpiled authorization policy, the known consumer of the entity-less
/// HTTP path, still resolves. It declares a `global`-only policy and no route,
/// so nothing about the selector should reach it: the global authentication
/// list still dispatches at the identity hook, and the global authorization
/// block still governs a generic HTTP request on a path.
#[tokio::test]
async fn the_transpiled_authorization_policy_still_resolves_its_global_http_policy() {
    let yaml = include_str!("fixtures/authpolicy_transpiler_global_http.yaml");
    let (mgr, ledger) = engine_with(yaml).await;

    assert!(
        mgr.has_hooks_for(HOOK_HTTP_REQUEST),
        "the entity-less HTTP handler must still install"
    );

    resolve_identity(&mgr, request("GET", "/api/tools/run")).await;
    assert_eq!(
        observations(&ledger),
        vec![Seen {
            plugin: "keycloak-jwt".to_owned(),
            path: None,
            entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
        }],
        "the global authentication list dispatches, and the request still \
         arrives under the reserved name"
    );

    assert!(
        !fire(&mgr, HOOK_HTTP_REQUEST, request("GET", "/api/tools/run")).await,
        "an unauthenticated request is still denied by the global policy"
    );
    assert!(
        fire(
            &mgr,
            HOOK_HTTP_REQUEST,
            authenticated_request("GET", "/api/tools/run")
        )
        .await,
        "and an authenticated one still passes it"
    );
}

// =====================================================================
// The payload an HTTP route's plugins receive
// =====================================================================

/// Denial code the assertion fixture emits when the payload it was handed
/// belongs to another family.
const WRONG_PAYLOAD: &str = "test.wrong.payload.family";

/// Records, and denies when the payload it was handed is not the one its
/// declared hooks carry. Written against the erased interface on purpose: a
/// typed handler cannot observe the mistake, because the adapter would have
/// refused the dispatch before the handler ran, and what this asserts is
/// which payload reached the plugin rather than which one the adapter
/// accepted.
struct PayloadAssertion {
    cfg: PluginConfig,
    ledger: Ledger,
    /// True when every hook this plugin declares is an HTTP name.
    expects_http: bool,
}

#[async_trait]
impl Plugin for PayloadAssertion {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

#[async_trait]
impl AnyHookHandler for PayloadAssertion {
    async fn invoke(
        &self,
        payload: &dyn praxis_policy_core::hooks::payload::PluginPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<CoreError>> {
        record(&self.ledger, &self.cfg.name, ext);
        let matched = if self.expects_http {
            payload.as_any().is::<HttpPayload>()
        } else {
            payload.as_any().is::<MessagePayload>()
        };
        Ok(Box::new(praxis_policy_core::executor::ErasedResultFields {
            continue_processing: matched,
            modified_payload: None,
            modified_extensions: None,
            violation: (!matched).then(|| {
                praxis_policy_core::error::PluginViolation::new(
                    WRONG_PAYLOAD,
                    "the route's plugin was handed another family's payload",
                )
            }),
        }))
    }

    fn hook_type_name(&self) -> &'static str {
        if self.expects_http {
            HttpHook::NAME
        } else {
            CmfHook::NAME
        }
    }
}

struct PayloadAssertionFactory(Ledger);

impl PluginFactory for PayloadAssertionFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(PayloadAssertion {
            cfg: config.clone(),
            ledger: Arc::clone(&self.0),
            expects_http: config.hooks.iter().all(|hook| is_http_hook(hook)),
        });
        let handler: Arc<dyn AnyHookHandler> = plugin.clone();
        let handlers = config
            .hooks
            .iter()
            .map(|hook| {
                let name: &'static str = Box::leak(hook.clone().into_boxed_str());
                (name, Arc::clone(&handler))
            })
            .collect();
        Ok(PluginInstance { plugin, handlers })
    }
}

/// Appends a label through `modified_extensions`, the channel a handler on
/// this family has for changing anything: `HttpPayload` carries no fields,
/// so a header rewrite or a label rides the extensions.
struct HttpLabelWriter {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for HttpLabelWriter {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<HttpHook> for HttpLabelWriter {
    async fn handle(
        &self,
        _payload: &HttpPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<HttpPayload> {
        let mut owned = ext.cow_copy();
        let security = owned.security.get_or_insert_with(Default::default);
        security.add_label("HTTP-TOUCHED");
        PluginResult::modify_extensions(owned)
    }
}

struct HttpLabelWriterFactory;

impl PluginFactory for HttpLabelWriterFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(HttpLabelWriter {
            cfg: config.clone(),
        });
        let handler: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<HttpHook, _>::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin,
            handlers: vec![(HOOK_HTTP_REQUEST, handler)],
        })
    }
}

/// An engine carrying the two fixtures above alongside the recording gate.
async fn engine_with_payload_fixtures(yaml: &str) -> (Arc<PolicyEngine>, Ledger) {
    let ledger: Ledger = Arc::new(Mutex::new(Vec::new()));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "test/assert-payload",
        Box::new(PayloadAssertionFactory(Arc::clone(&ledger))),
    );
    mgr.register_factory("test/label-writer", Box::new(HttpLabelWriterFactory));
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    (mgr, ledger)
}

/// A plugin an HTTP route's policy step names is handed `HttpPayload`, so a
/// content-inspecting plugin there reads the exchange rather than a chat
/// message nothing filled.
#[tokio::test]
async fn a_plugin_on_an_http_route_receives_the_http_payload() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: payload-check
    kind: test/assert-payload
    hooks: [http.request]
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(payload-check)"
"#;
    let (mgr, ledger) = engine_with_payload_fixtures(YAML).await;

    let (result, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            request("GET", "/v1/files/q3.pdf"),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "the plugin denies when handed another family's payload; violation = {:?}",
        result.violation
    );
    assert_ne!(
        result.violation.map(|v| v.code),
        Some(WRONG_PAYLOAD.to_owned()),
    );
    assert_eq!(
        fired(&ledger),
        vec!["payload-check".to_owned()],
        "the route's policy step must have dispatched the plugin at all"
    );
}

/// The regression surface that matters most: an MCP route's plugin is still
/// handed `MessagePayload`, so nothing about the HTTP family moved what the
/// CMF path dispatches.
#[tokio::test]
async fn a_plugin_on_an_mcp_route_still_receives_the_message_payload() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: payload-check
    kind: test/assert-payload
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(payload-check)"
"#;
    let (mgr, ledger) = engine_with_payload_fixtures(YAML).await;

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            MessagePayload {
                message: Message::text(Role::User, "hi"),
            },
            tool_request("get_weather"),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "the plugin denies when handed another family's payload; violation = {:?}",
        result.violation
    );
    assert_eq!(fired(&ledger), vec!["payload-check".to_owned()]);
}

/// A plugin on an HTTP route mutating extensions still has its mutation
/// persisted, which is what a header rewrite rides: it goes through
/// `modified_extensions` rather than the payload.
#[tokio::test]
async fn an_extension_mutation_on_an_http_route_is_persisted() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: label-writer
    kind: test/label-writer
    hooks: [http.request]
    capabilities: [append_labels, read_headers]
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "run(label-writer)"
"#;
    let (mgr, _ledger) = engine_with_payload_fixtures(YAML).await;

    let (result, _bg) = mgr
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            request("GET", "/v1/files/q3.pdf"),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "the plugin allows; violation = {:?}",
        result.violation
    );
    let labels = result
        .modified_extensions
        .as_ref()
        .expect("the plugin's extension mutation must reach the result")
        .security
        .as_ref()
        .map(|s| s.labels.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        labels.iter().any(|l| l == "HTTP-TOUCHED"),
        "the plugin's extension mutation must reach the host; labels = {labels:?}"
    );
}

// =====================================================================
// A field stage on an HTTP route is refused at load
// =====================================================================

/// `HttpPayload` has no fields, so an `args:` block on an `http:` route
/// would address nothing. The load names the route and the block rather
/// than letting the stage read nothing at runtime.
#[tokio::test]
async fn an_args_block_on_an_http_route_is_refused_naming_the_route_and_the_block() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http:
      path_prefix: /v1/files
    args:
      city: "str | redact"
"#;
    let msg = load_failure(YAML);
    assert!(
        msg.contains("args") && msg.contains("prefix:/v1/files"),
        "the refusal must name the block and the route: {msg}"
    );
}

/// The same for the response half's field stage.
#[tokio::test]
async fn a_result_block_on_an_http_route_is_refused_naming_the_route_and_the_block() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - http: /healthz
    result:
      ssn: "str | redact"
"#;
    let msg = load_failure(YAML);
    assert!(
        msg.contains("result") && msg.contains("http:/healthz"),
        "the refusal must name the block and the route: {msg}"
    );
}

/// An entity route still accepts both field stages, so the refusal is scoped
/// to the family whose payload has no fields rather than to field stages.
#[tokio::test]
async fn an_entity_route_still_accepts_its_field_stages() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
routes:
  - tool: get_weather
    args:
      city: "str | redact"
    result:
      ssn: "str | redact"
"#;
    let (_mgr, _ledger) = engine_with(YAML).await;
}

/// A `global.defaults.http` block carrying `args:` is refused too. That scope
/// reaches HTTP routes and nothing else, so a stage declared there is as
/// unreadable as one on the route.
#[tokio::test]
async fn a_default_http_layer_declaring_a_field_stage_is_refused() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  defaults:
    http:
      args:
        city: "str | redact"
routes:
  - http: /healthz
"#;
    let msg = load_failure(YAML);
    assert!(
        msg.contains("args") && msg.contains("global.defaults.http"),
        "the refusal must name the block and the scope: {msg}"
    );
}

/// A `global:` block carrying `args:` is refused outright, by the wider rule
/// that `global:` accepts no field pipeline: it covers every entity route at
/// once rather than reaching a payload of its own.
#[tokio::test]
async fn a_global_field_stage_is_refused() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  args:
    city: "str | redact"
routes:
  - http:
      path_prefix: /v1/files
    authorization:
      pre_invocation:
        - "http.method == 'POST': deny"
"#;
    let msg = load_failure(YAML);
    assert!(
        msg.contains("args") && msg.contains("global"),
        "the refusal must name the block and the scope: {msg}"
    );
}
