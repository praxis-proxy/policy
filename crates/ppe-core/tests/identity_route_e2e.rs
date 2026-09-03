// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for the route-level `authentication:` block.
//
// Verifies the hook-specific binding semantics:
//   * A route's `authentication:` block is the authoritative dispatch list
//     for the `identity.resolve` hook on that route.
//   * The route's `plugins:` block (which means "per-route overrides"
//     in APL-driven routes, "per-route binding" otherwise) does NOT
//     bind plugins for the `identity.resolve` hook.
//   * Dispatch order matches the order steps are declared in
//     `authentication:`, NOT the plugins' chain-priority values.
//   * Per-step config overrides flow through the existing
//     `create_override_instance` pathway.
//
// Companion tests for IdentityHook *semantics* (payload threading,
// rejection, apply_to_extensions) live in `identity_e2e.rs`.

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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use praxis_policy_core::config;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{MetaExtension, SubjectExtension};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::AnyHookHandler;

// =====================================================================
// Test plugin: a recording identity resolver
// =====================================================================
//
// Each instance writes its own name to a shared `Vec<String>` ledger
// when invoked. That lets tests assert (a) which plugins fired and
// (b) in what order. Also stamps `subject.id` so the post-pipeline
// payload reflects who ran last — useful for verifying that the
// chain produced the expected accumulated state.

struct RecordingResolver {
    cfg: PluginConfig,
    name: String,
    ledger: Arc<Mutex<Vec<String>>>,
    /// Number of times this instance has been invoked. Used to verify
    /// that per-step config overrides actually produce a fresh instance
    /// rather than reusing the base.
    invocation_count: Arc<AtomicUsize>,
    /// Optional sink for what `Extensions` slots the plugin saw on
    /// invocation. Used by cap-gating tests. `None` when the test
    /// doesn't care about visibility.
    extensions_observation: Arc<Mutex<Option<IdentityExtensionsObservation>>>,
}

/// What an identity resolver saw in `Extensions` during invocation —
/// drives the cap-gating tests. Only includes slots the tests check
/// (security.subject id, labels).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IdentityExtensionsObservation {
    saw_subject_id: Option<String>,
    saw_labels: Vec<String>,
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
        payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        self.ledger.lock().unwrap().push(self.name.clone());
        self.invocation_count.fetch_add(1, Ordering::SeqCst);

        // Capability-gating observation. praxis-policy-core's executor calls
        // `filter_extensions(&ext, &caps)` BEFORE handing us `ext`,
        // so this snapshot reflects exactly what our declared
        // capabilities expose.
        *self.extensions_observation.lock().unwrap() = Some(IdentityExtensionsObservation {
            saw_subject_id: ext
                .security
                .as_ref()
                .and_then(|s| s.subject.as_ref())
                .and_then(|s| s.id.clone()),
            saw_labels: ext
                .security
                .as_ref()
                .map(|s| s.labels.iter().cloned().collect())
                .unwrap_or_default(),
        });

        let mut updated = payload.clone();
        updated.subject = Some(SubjectExtension {
            id: Some(self.name.clone()),
            ..Default::default()
        });
        PluginResult::modify_payload(updated)
    }
}

// =====================================================================
// Test factory — used to build plugin instances from a config block
// so route-level `config:` overrides can produce fresh instances via
// `create_override_instance`.
// =====================================================================

struct RecordingFactory {
    ledger: Arc<Mutex<Vec<String>>>,
    /// Count of *factory invocations* (i.e. instance constructions).
    /// Distinct from `invocation_count` on individual plugins —
    /// asserts that a config override produced a NEW instance.
    factory_calls: Arc<AtomicUsize>,
    /// Optional shared observation sink — when set, every plugin
    /// the factory builds writes its extensions-view snapshot here
    /// on invocation. The test holds the same Arc and reads it
    /// after dispatch. `None` means observations are off (existing
    /// tests don't need them and shouldn't pay the wiring cost).
    observation_sink: Option<Arc<Mutex<Option<IdentityExtensionsObservation>>>>,
}

impl PluginFactory for RecordingFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<PluginInstance, Box<praxis_policy_core::error::PluginError>> {
        self.factory_calls.fetch_add(1, Ordering::SeqCst);
        let plugin = Arc::new(RecordingResolver {
            cfg: config.clone(),
            name: config.name.clone(),
            ledger: Arc::clone(&self.ledger),
            invocation_count: Arc::new(AtomicUsize::new(0)),
            extensions_observation: self
                .observation_sink
                .clone()
                .unwrap_or_else(|| Arc::new(Mutex::new(None))),
        });
        let adapter: Arc<dyn AnyHookHandler> = Arc::new(
            TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(&plugin)),
        );
        Ok(PluginInstance {
            plugin: plugin as Arc<dyn Plugin>,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, adapter)],
        })
    }
}

// =====================================================================
// Test helpers
// =====================================================================

/// Build the request Extensions with `MetaExtension` set so route
/// filtering kicks in. Without `meta`, the filter falls through to
/// chain dispatch (all entries returned) — that's the wrong code
/// path to be testing.
fn ext_for_tool(tool_name: &str) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some(tool_name.to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn build_payload(token: &str) -> IdentityPayload {
    IdentityPayload::new(token, TokenSource::Bearer)
}

/// Standard set-up: `PolicyEngine` with the recording factory
/// registered, plus a shared ledger and factory-call counter the
/// test asserts on. Doesn't wire extensions observation —
/// existing tests don't need it.
fn manager_with_recording_factory() -> (Arc<PolicyEngine>, Arc<Mutex<Vec<String>>>, Arc<AtomicUsize>)
{
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "recording",
        Box::new(RecordingFactory {
            ledger: Arc::clone(&ledger),
            factory_calls: Arc::clone(&factory_calls),
            observation_sink: None,
        }),
    );
    (mgr, ledger, factory_calls)
}

/// Cap-gating-flavored set-up: also returns a shared `observation_sink`
/// the test holds onto so it can inspect what extensions the plugin
/// actually saw after invocation. Every plugin the factory builds
/// writes its observation to this shared Arc (latest wins).
fn manager_with_observing_factory() -> (
    Arc<PolicyEngine>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Option<IdentityExtensionsObservation>>>,
) {
    let ledger = Arc::new(Mutex::new(Vec::new()));
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let observation_sink: Arc<Mutex<Option<IdentityExtensionsObservation>>> =
        Arc::new(Mutex::new(None));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "recording",
        Box::new(RecordingFactory {
            ledger: Arc::clone(&ledger),
            factory_calls: Arc::clone(&factory_calls),
            observation_sink: Some(Arc::clone(&observation_sink)),
        }),
    );
    (mgr, ledger, observation_sink)
}

// =====================================================================
// Scenarios
// =====================================================================

/// Baseline: route's `authentication:` block dispatches the listed plugins,
/// in declared order, for `identity.resolve`. The ledger should
/// reflect the YAML order verbatim — proves the per-route binding +
/// preserved order story end-to-end.
#[tokio::test]
async fn route_identity_block_dispatches_in_declared_order() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    // Three identity plugins, all registered under `identity.resolve`. The route
    // declares them in an order no other signal could produce, so the ledger
    // reading back in that order is the binding working.
    //
    // This used to set priority 10/20/30 and declare them reversed, so the
    // ledger order proved declaration beat priority. `priority:` is a
    // policy-mode load error now, and the route block this test needs is itself
    // a hook-mode load error, so the contrast cannot be set up either way. It
    // is also no longer a contrast worth drawing: in policy mode there is no
    // priority for declaration order to beat.
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: jwt-a
    kind: recording
    hooks: [identity.resolve]
  - name: jwt-b
    kind: recording
    hooks: [identity.resolve]
  - name: jwt-c
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_weather
    authentication:
      - jwt-c
      - jwt-a
      - jwt-b
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "pipeline should allow; violation = {:?}",
        result.violation,
    );

    // Order matches the YAML's `authentication:` declaration, NOT plugin priority.
    let firings = ledger.lock().unwrap().clone();
    assert_eq!(firings, vec!["jwt-c", "jwt-a", "jwt-b"]);
}

/// `authentication:` is the only dispatch list a route declares. The `plugins:`
/// activation list that used to sit beside it — and mean something different on
/// the same route — is a load error, so the two can no longer be confused.
#[test]
fn a_route_cannot_declare_a_plugins_list_beside_authentication() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
  - name: rogue-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_weather
    authentication:
      - corp-jwt
    plugins:
      - rogue-jwt
"#;
    let message = config::parse_config(yaml)
        .expect_err("the activation list beside `authentication:` must fail")
        .to_string();
    assert!(message.contains("routes[0]"), "{message}");
    assert!(message.contains("run(name)"), "{message}");
}

/// A route with no `authentication:` block produces zero identity
/// dispatches even when the `entity_type` / `entity_name` match. The
/// plugin IS registered under identity.resolve, but no route
/// binds it, so the route-filter returns an empty entry list.
#[tokio::test]
async fn route_without_identity_block_dispatches_no_resolvers() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_weather
    # No authentication: block.
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // No identity plugins fired — `authentication:` was absent, so the
    // route binds nothing for the identity.resolve hook.
    assert!(ledger.lock().unwrap().is_empty());
}

/// A route declared for a different tool doesn't bind identity for
/// this request — proves scope/entity matching still works under
/// the new resolver path.
#[tokio::test]
async fn identity_route_filter_respects_entity_match() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_compensation
    authentication:
      - corp-jwt
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    // Request for a DIFFERENT tool — corp-jwt should not fire.
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("unrelated_tool"),
            None,
        )
        .await;
    assert!(result.continue_processing);
    assert!(
        ledger.lock().unwrap().is_empty(),
        "identity must NOT fire for a non-matching route",
    );
}

/// Per-step `config_override` produces a fresh plugin instance via
/// the existing `create_override_instance` pathway. The factory
/// call count goes up by one each time the route's identity step
/// is dispatched with an override — proves the wrapper around
/// `resolve_identity_plugins_for_route` correctly threads the
/// override through to `filter_entries_by_route`'s override branch.
#[tokio::test]
async fn per_step_config_override_produces_fresh_instance() {
    let (mgr, _ledger, factory_calls) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
    config:
      audience: default-aud

routes:
  - tool: get_weather
    authentication:
      - name: corp-jwt
        config:
          audience: route-specific-aud
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    // Sanity: factory was called once for the base plugin during
    // load_config. Track from here.
    let base_calls = factory_calls.load(Ordering::SeqCst);

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // One additional factory call for the override instance.
    assert_eq!(
        factory_calls.load(Ordering::SeqCst),
        base_calls + 1,
        "config_override should produce a new factory call",
    );
}

/// End-to-end inheritance: global.identity contributes to
/// the dispatch lineup for routes that declare no identity block of
/// their own. Verifies the dispatch path picks up the global layer.
#[tokio::test]
async fn global_identity_inherited_when_route_has_no_block() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

global:
  authentication:
    - corp-jwt

routes:
  - tool: get_weather
"#;
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);
    assert_eq!(
        ledger.lock().unwrap().clone(),
        vec!["corp-jwt"],
        "global identity should fire when the route declares none",
    );
}

/// Full stack — global + tag bundle + route — in declared order.
/// Proves the merge actually flows the layers through praxis-policy-core's
/// dispatch in the order the resolver guarantees.
#[tokio::test]
async fn global_tag_route_identity_stack_dispatches_in_order() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
  - name: workday-saml
    kind: recording
    hooks: [identity.resolve]
  - name: agent-context
    kind: recording
    hooks: [identity.resolve]

global:
  authentication:
    - corp-jwt
groups:
  finance:
    authentication:
      - workday-saml

routes:
  - tool: get_compensation
    meta:
      tags: [finance]
    authentication:
      - agent-context
"#;
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_compensation"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // Order: global → tag bundle → route. The ledger captures the
    // actual dispatch order (preserves the resolver's stacking).
    assert_eq!(
        ledger.lock().unwrap().clone(),
        vec!["corp-jwt", "workday-saml", "agent-context"],
    );
}

/// Route opts out via `replace_inherited: true` — inherited layers
/// (global, tag bundles) are dropped. Only the route's steps run.
#[tokio::test]
async fn replace_inherited_drops_inherited_layers_end_to_end() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
  - name: workday-saml
    kind: recording
    hooks: [identity.resolve]
  - name: legacy-basic-auth
    kind: recording
    hooks: [identity.resolve]

global:
  authentication:
    - corp-jwt
groups:
  finance:
    authentication:
      - workday-saml

routes:
  - tool: legacy_endpoint
    meta:
      tags: [finance]
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth
"#;
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("legacy_endpoint"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    // Only the route's step ran — global and tag-bundle layers
    // were dropped because `replace_inherited: true`.
    assert_eq!(ledger.lock().unwrap().clone(), vec!["legacy-basic-auth"],);
}

/// `replace_inherited: true` + `steps: []` — the explicit
/// "anonymous route, no identity" knob. Zero plugins fire even
/// though global identity is configured.
#[tokio::test]
async fn replace_inherited_with_empty_steps_yields_anonymous_route() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

global:
  authentication:
    - corp-jwt

routes:
  - tool: public_endpoint
    authentication:
      replace_inherited: true
      steps: []
"#;
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("public_endpoint"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    assert!(
        ledger.lock().unwrap().is_empty(),
        "anonymous-route opt-out should suppress global identity",
    );
}

/// Sanity that an empty Vec from the resolver (route has identity
/// but with `replace_inherited: true` and zero steps — the explicit
/// "opt out" knob) results in zero dispatches.
#[tokio::test]
async fn route_with_empty_identity_steps_dispatches_nothing() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

routes:
  - tool: get_weather
    authentication:
      replace_inherited: true
      steps: []
"#;
    let parsed = config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_weather"),
            None,
        )
        .await;
    assert!(result.continue_processing);
    assert!(ledger.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------
// `replace_inherited:` at bundle scope.
//
// A bundle's flag drops everything accumulated before it, the global
// layer and any earlier bundle, while the bundles after it and the
// route itself still append. Bundle order is `meta.tags` in declaration
// order then `groups:` in declaration order, so which bundle replaces is
// readable from the document.
// ---------------------------------------------------------------------

/// Two bundles where the second replaces. Written once and reused by the
/// order test, which only swaps the tag list.
const TWO_BUNDLES_SECOND_REPLACES: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]
  - name: workday-saml
    kind: recording
    hooks: [identity.resolve]
  - name: legacy-basic-auth
    kind: recording
    hooks: [identity.resolve]
  - name: agent-context
    kind: recording
    hooks: [identity.resolve]

global:
  authentication:
    - corp-jwt
groups:
  finance:
    authentication:
      - workday-saml
  legacy:
    authentication:
      replace_inherited: true
      steps:
        - legacy-basic-auth

routes:
  - tool: get_compensation
    meta:
      tags: [finance, legacy]
    authentication:
      - agent-context
"#;

/// Dispatch the identity hook for `get_compensation` under `yaml` and
/// return what actually fired, in order.
async fn identity_dispatch_order(yaml: &str) -> Vec<String> {
    let (mgr, ledger, _) = manager_with_recording_factory();
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("get_compensation"),
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "identity resolution should not halt the pipeline"
    );
    ledger.lock().unwrap().clone()
}

/// The second bundle sets the flag: the global layer and the first
/// bundle's step are gone, the replacing bundle's step and the route's
/// own remain.
#[tokio::test]
async fn bundle_replace_inherited_drops_the_layers_before_it_end_to_end() {
    assert_eq!(
        identity_dispatch_order(TWO_BUNDLES_SECOND_REPLACES).await,
        vec!["legacy-basic-auth", "agent-context"],
    );
}

/// The same two bundles in the other order resolve differently, and the
/// difference matches declaration order: `legacy` replaces the global
/// layer only, so `finance` survives behind it.
#[tokio::test]
async fn bundle_order_decides_what_replace_inherited_drops_end_to_end() {
    let reordered =
        TWO_BUNDLES_SECOND_REPLACES.replace("tags: [finance, legacy]", "tags: [legacy, finance]");
    assert_eq!(
        identity_dispatch_order(&reordered).await,
        vec!["legacy-basic-auth", "workday-saml", "agent-context"],
    );
}

/// A bundle with `replace_inherited: true` and `steps: []` is the
/// anonymous-route knob at bundle scope: it drops the inherited layers
/// and contributes nothing, so nothing authenticates the route.
#[tokio::test]
async fn bundle_replace_inherited_with_empty_steps_yields_anonymous_route() {
    let (mgr, ledger, _) = manager_with_recording_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: recording
    hooks: [identity.resolve]

global:
  authentication:
    - corp-jwt
groups:
  public:
    authentication:
      replace_inherited: true
      steps: []

routes:
  - tool: healthcheck
    groups: public
"#;
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool("healthcheck"),
            None,
        )
        .await;
    assert!(result.continue_processing);
    assert!(
        ledger.lock().unwrap().is_empty(),
        "an empty replacing bundle should leave the route with no resolvers",
    );
}

// ---------------------------------------------------------------------
// Capability gating on the identity dispatch path.
//
// Identity plugins go through praxis-policy-core's executor like every other
// hook family — meaning `filter_extensions(&ext, &caps)` runs before
// each handler invoke and narrows what the plugin sees to its
// declared capabilities. These tests pin that behavior for the
// route-level identity dispatch path.
//
// Identity is unusual in that resolvers typically WRITE state (subject,
// chain) rather than read it — but they still need read capabilities
// for any extension-derived context they consult during resolution
// (e.g., a `read_meta`-gated resolver that branches on entity tags).
// ---------------------------------------------------------------------

/// Build extensions seeded with subject + label so cap-gating tests
/// can verify what a resolver sees post-filter.
fn ext_for_tool_with_subject_and_label(
    tool_name: &str,
    subject_id: &str,
    label: &str,
) -> Extensions {
    use praxis_policy_core::extensions::SecurityExtension;
    let mut sec = SecurityExtension::default();
    sec.subject = Some(SubjectExtension {
        id: Some(subject_id.to_owned()),
        ..Default::default()
    });
    sec.add_label(label);
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some(tool_name.to_owned()),
            ..Default::default()
        })),
        security: Some(Arc::new(sec)),
        ..Default::default()
    }
}

/// Identity resolver declaring `read_subject` sees `subject.id` in
/// Extensions but NOT `security.labels` — the executor strips the
/// labels slot because the plugin doesn't hold `read_labels`.
#[tokio::test]
async fn identity_plugin_with_read_subject_sees_subject_but_not_labels() {
    let (mgr, _ledger, sink) = manager_with_observing_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: scoped-jwt
    kind: recording
    hooks: [identity.resolve]
    capabilities: [read_subject]

routes:
  - tool: get_weather
    authentication:
      - scoped-jwt
"#;
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    // Extensions populated with BOTH subject (id=alice) AND a label
    // (pii). The plugin should see subject only.
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool_with_subject_and_label("get_weather", "alice", "pii"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let obs = sink
        .lock()
        .unwrap()
        .clone()
        .expect("plugin should have recorded its view");

    assert_eq!(
        obs.saw_subject_id.as_deref(),
        Some("alice"),
        "read_subject cap should expose subject.id",
    );
    assert!(
        obs.saw_labels.is_empty(),
        "without read_labels, labels must be hidden — saw: {:?}",
        obs.saw_labels,
    );
}

/// Identity resolver with NO capabilities sees a fully-stripped
/// Extensions view. Negative case: confirms the executor's per-entry
/// filter actually hides slots when no cap is declared.
#[tokio::test]
async fn identity_plugin_without_caps_sees_stripped_extensions() {
    let (mgr, _ledger, sink) = manager_with_observing_factory();

    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: capless-jwt
    kind: recording
    hooks: [identity.resolve]
    # capabilities: []  (omitted entirely; same effect)

routes:
  - tool: get_weather
    authentication:
      - capless-jwt
"#;
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    mgr.load_config(parsed).expect("load");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            build_payload("eyJ.fake.jwt"),
            ext_for_tool_with_subject_and_label("get_weather", "alice", "pii"),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let obs = sink
        .lock()
        .unwrap()
        .clone()
        .expect("plugin should have recorded its view");

    assert!(
        obs.saw_subject_id.is_none(),
        "without read_subject, subject must be hidden — saw: {:?}",
        obs.saw_subject_id,
    );
    assert!(
        obs.saw_labels.is_empty(),
        "without read_labels, labels must be hidden",
    );
}

// ---------------------------------------------------------------------
// The load-time report for a bundle-scope drop.
//
// A route's own `replace_inherited:` is visible to whoever reads the
// route. A bundle's is not: the flag lives in a shared block somewhere
// else, and the route ends up authenticating less than its own
// declaration says. So the config load names every route that happens
// to, the way the delegation-without-identity alarm does.
// ---------------------------------------------------------------------

const REPLACED_ALARM: &str = "authentication_replaced_above_the_route";

/// Every event carrying an `alarm` field, flattened to `name=value`
/// pairs so one assertion can check the alarm, the route, and the section
/// it names.
///
/// Hand-rolled on `tracing` rather than pulled from
/// `tracing-subscriber`, matching
/// `praxis-policy-apl-runtime/tests/delegation_identity_warning.rs`: a
/// handful of fields off one event is not worth a new dependency tree.
struct AlarmCollector;

thread_local! {
    /// Where this thread's alarms go while a helper is collecting.
    static ALARM_SINK: std::cell::RefCell<Option<Arc<Mutex<Vec<String>>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Collect the alarms raised by `body` on this thread.
///
/// One global subscriber for the binary, chosen over `with_default` per call:
/// a thread-local dispatcher leaves the callsites to be registered by whichever
/// dispatcher reaches them first, and under `NoSubscriber` that verdict is
/// `never` and cached for the process.
fn alarm_events(body: impl FnOnce()) -> Vec<String> {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        // Ignore a failure: another harness may own the global default, and the
        // assertions below report the empty result either way.
        drop(tracing::subscriber::set_global_default(AlarmCollector));
    });

    let events = Arc::new(Mutex::new(Vec::new()));
    ALARM_SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&events)));
    body();
    ALARM_SINK.with(|sink| *sink.borrow_mut() = None);
    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

impl tracing::Subscriber for AlarmCollector {
    /// Never let a verdict be cached for these callsites.
    ///
    /// Callsite interest is global and cached, while `with_default` is
    /// thread-local. Another test in this binary loading a config without a
    /// subscriber registered these `warn!` sites under `NoSubscriber`, which
    /// caches `never`, and every later collector saw nothing. `sometimes`
    /// forces `enabled` to be asked per event, so the cache holds no verdict to
    /// poison. Installing this globally rather than per thread is the other
    /// half; see `alarm_events`.
    fn register_callsite(
        &self,
        _metadata: &tracing::Metadata<'_>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = FieldSink(Vec::new());
        event.record(&mut fields);
        let flattened = fields.0.join(" ");
        if !flattened.contains("alarm=") {
            return;
        }
        ALARM_SINK.with(|sink| {
            if let Some(events) = sink.borrow().as_ref() {
                events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(flattened);
            }
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct FieldSink(Vec<String>);

impl tracing::field::Visit for FieldSink {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push(format!("{}={}", field.name(), value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push(format!("{}={:?}", field.name(), value));
    }
}

/// Load `yaml` and return every alarm event the load itself raised.
fn alarms_raised_by_loading(yaml: &str) -> Vec<String> {
    let (mgr, _ledger, _) = manager_with_recording_factory();
    let parsed = praxis_policy_core::config::parse_config(yaml).expect("parse");
    alarm_events(|| {
        mgr.load_config(parsed).expect("load");
    })
}

/// One report per affected route, naming the route, the section that set
/// the flag, and the steps the route no longer runs.
#[test]
fn a_bundle_dropping_inherited_authentication_is_reported_at_load() {
    // Two routes join the replacing bundle; a third does not.
    let yaml = TWO_BUNDLES_SECOND_REPLACES.replace(
        "  - tool: get_compensation",
        "  - tool: get_headcount\n    groups: [finance]\n  - tool: get_compensation",
    );
    let reports: Vec<String> = alarms_raised_by_loading(&yaml)
        .into_iter()
        .filter(|e| e.contains(REPLACED_ALARM))
        .collect();

    assert_eq!(
        reports.len(),
        1,
        "one report per affected route: {reports:?}"
    );
    let report = &reports[0];
    assert!(report.contains("route=tool:get_compensation"), "{report}");
    assert!(report.contains("declared_in=groups.legacy"), "{report}");
    assert!(
        report.contains("corp-jwt") && report.contains("workday-saml"),
        "the report should name the steps the route lost: {report}",
    );
}

/// A route joining only the non-replacing bundle keeps its inherited
/// steps, so reporting it would be a false alarm.
#[test]
fn a_route_that_keeps_its_inherited_authentication_is_not_reported() {
    let yaml = TWO_BUNDLES_SECOND_REPLACES.replace("tags: [finance, legacy]", "tags: [finance]");
    assert!(
        !alarms_raised_by_loading(&yaml)
            .iter()
            .any(|e| e.contains(REPLACED_ALARM)),
    );
}
