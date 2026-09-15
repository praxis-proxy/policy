// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The audit seam, driven through the real engine.
//
// Two properties are what a sink is worth, and both are about the seam rather
// than about any one sink:
//
// The record matches the answer. A verdict a sink was told is what the caller
// was told — every invocation, at every return site, including the ones that
// deny before a plugin runs. A stream that reports an allow the caller never
// received is worse than no stream, because it reads as evidence.
//
// A sink observes and does nothing else. It reaches every request, so it is
// filtered like any other plugin: what it sees is what its own capabilities
// grant, and it cannot act — least of all under the name of a plugin it is
// watching.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use praxis_policy_core::audit::AuditHandler;
use praxis_policy_core::cmf::constants::HOOK_CMF_TOOL_PRE_INVOKE;
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::config;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::decision::{DecisionLog, Verdict};
use praxis_policy_core::effect::{EffectRecord, EffectState};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::executor::erase_result;
use praxis_policy_core::extensions::{
    HttpExtension, MetaExtension, RawCredentialsExtension, RawInboundToken, SecurityExtension,
    SubjectExtension, TokenKind, TokenRole,
};
use praxis_policy_core::hooks::payload::{Extensions, PluginPayload};
use praxis_policy_core::hooks::trait_def::PluginResult;
use praxis_policy_core::plugin::{Plugin, PluginConfig, PluginMode};
use praxis_policy_core::registry::AnyHookHandler;

// =====================================================================
// Harness
// =====================================================================

/// One verdict a sink was told about, flattened to what a test asserts on.
#[derive(Debug)]
struct Seen {
    denied: bool,
    /// The violation code, when the record carried a denial.
    code: Option<String>,
    /// Whether the sink's view carried the host's HTTP transport.
    had_transport: bool,
    /// Whether the sink's view carried inbound credential material.
    had_inbound_credentials: bool,
    /// Whether the sink's view carried the `http` slot, which is gated on
    /// `read_headers`.
    had_http: bool,
    /// How many steps the record carried, so a test can tell a record built
    /// from a real pipeline from one built at a short-circuit.
    steps: usize,
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<Seen>>,
    /// What `on_effect` was told, and whether the sink could act through the
    /// view it was handed.
    effects: Mutex<Vec<(String, EffectState)>>,
    effect_attempt: Mutex<Option<String>>,
}

impl Recorder {
    fn seen(&self) -> std::sync::MutexGuard<'_, Vec<Seen>> {
        self.seen.lock().unwrap()
    }
}

/// A sink that is also a plugin, which is the only way one is registered.
struct SinkPlugin {
    cfg: PluginConfig,
    rec: Arc<Recorder>,
}

#[async_trait]
impl Plugin for SinkPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }

    fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
        Some(self)
    }
}

#[async_trait]
impl AuditHandler for SinkPlugin {
    async fn handle(
        &self,
        _payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    ) {
        let (denied, code) = match decisions.verdict() {
            Some(Verdict::Deny(v)) => (true, Some(v.code.clone())),
            _ => (false, None),
        };
        self.rec.seen().push(Seen {
            denied,
            code,
            had_transport: extensions.http_transport.is_available(),
            had_inbound_credentials: extensions
                .raw_credentials
                .as_deref()
                .is_some_and(|c| !c.inbound_tokens.is_empty()),
            had_http: extensions.http.is_some(),
            steps: decisions.steps().len(),
        });
    }

    async fn on_effect(&self, effect: &EffectRecord, extensions: &Extensions) {
        self.rec
            .effects
            .lock()
            .unwrap()
            .push((effect.key.clone(), effect.state.clone()));
        // What a sink must not be able to do: write a record of its own
        // through the view it was handed for observing.
        let forged = EffectRecord::prepared("forged", "a sink acting", "forged-key");
        let outcome = extensions.begin_effect(&forged).await;
        *self.rec.effect_attempt.lock().unwrap() =
            Some(outcome.map_or_else(|e| format!("{e}"), |()| "the sink acted".to_owned()));
    }

    fn name(&self) -> &str {
        "recorder"
    }
}

/// A handler that does nothing, for a sink registered as a plugin. A sink is
/// collected off the registry, so it has to be registered as something.
struct Passthrough;

#[async_trait]
impl AnyHookHandler for Passthrough {
    async fn invoke(
        &self,
        _payload: &dyn PluginPayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        Ok(erase_result(PluginResult::<MessagePayload>::allow()))
    }

    fn hook_type_name(&self) -> &'static str {
        "cmf"
    }
}

/// A plugin that performs an irreversible effect, so a sink has one to observe.
struct Actor {
    cfg: PluginConfig,
    key: &'static str,
}

#[async_trait]
impl Plugin for Actor {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

#[async_trait]
impl AnyHookHandler for Actor {
    async fn invoke(
        &self,
        _payload: &dyn PluginPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        let effect = EffectRecord::prepared("token_mint", "a test mint", self.key);
        ext.perform_effect(&effect, || async { Ok(()) }).await?;
        Ok(erase_result(PluginResult::<MessagePayload>::allow()))
    }

    fn hook_type_name(&self) -> &'static str {
        "cmf"
    }
}

fn sink_config(capabilities: &[&str]) -> PluginConfig {
    PluginConfig {
        name: "recorder".to_owned(),
        kind: "builtin".to_owned(),
        hooks: vec![HOOK_CMF_TOOL_PRE_INVOKE.to_owned()],
        mode: PluginMode::Audit,
        capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
        ..Default::default()
    }
}

fn actor_config() -> PluginConfig {
    PluginConfig {
        name: "actor".to_owned(),
        kind: "builtin".to_owned(),
        hooks: vec![HOOK_CMF_TOOL_PRE_INVOKE.to_owned()],
        mode: PluginMode::Sequential,
        ..Default::default()
    }
}

async fn engine_with(yaml: &str) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    let parsed = config::parse_config(yaml).expect("the config loads");
    engine.load_config(parsed).expect("the config installs");
    engine.initialize().await.expect("initialize");
    engine
}

/// Register a sink and return what it records.
fn attach_sink(engine: &Arc<PolicyEngine>, capabilities: &[&str]) -> Arc<Recorder> {
    let rec = Arc::new(Recorder::default());
    let cfg = sink_config(capabilities);
    let plugin = Arc::new(SinkPlugin {
        cfg: cfg.clone(),
        rec: Arc::clone(&rec),
    });
    engine
        .register_raw::<CmfHook>(plugin, cfg, Arc::new(Passthrough))
        .expect("the sink registers");
    rec
}

/// Put an actor on the coordinates the request resolves to. Policy dispatch
/// runs nothing structurally, so an annotation is how a plugin runs at all,
/// which is what the APL runtime installs too.
fn attach_actor(engine: &Arc<PolicyEngine>, key: &'static str) {
    let cfg = actor_config();
    engine.annotate_route(
        "tool",
        "search",
        None,
        HOOK_CMF_TOOL_PRE_INVOKE,
        Arc::new(Actor {
            cfg: cfg.clone(),
            key,
        }),
        cfg,
    );
}

fn message() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "hello"),
    }
}

fn tool_meta(name: &str) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some(name.to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// A subject with an id but no tenant claim, which is what the contract below
/// denies on.
fn tenantless(mut ext: Extensions) -> Extensions {
    ext.security = Some(Arc::new(SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some("alice".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }));
    ext.http = Some(Arc::new(HttpExtension {
        request_headers: HashMap::new(),
        method: Some("POST".to_owned()),
        path: Some("/v1/files".to_owned()),
        ..Default::default()
    }));
    ext.raw_credentials = Some(Arc::new(RawCredentialsExtension {
        inbound_tokens: [(
            TokenRole::Client,
            RawInboundToken::new(
                "a-bearer-nobody-should-see",
                "authorization",
                TokenKind::Jwt,
            ),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    }));
    ext
}

/// A contract that denies when the subject has no tenant claim. The denial
/// happens in `apply_assertions`, after the pipeline has already allowed.
const DENYING_CONTRACT: &str = "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-auth-tenant-id
          from: claim.tenant
          on_missing: deny
";

const PLAIN: &str = "
engine_settings:
  dispatch: policy
";

// =====================================================================
// The record matches the answer
// =====================================================================

/// An assertion that denies after the pipeline allowed. The sink is told the
/// denial, not the allow the pipeline reached on its way there.
///
/// Emitting from inside the executor recorded the allow and stopped, so the
/// stream said a request was forwarded that the caller was refused.
#[tokio::test]
async fn an_assertion_denial_is_what_the_sink_is_told() {
    let engine = engine_with(DENYING_CONTRACT).await;
    let rec = attach_sink(&engine, &[]);

    let (result, _bg) = engine
        .invoke_named::<CmfHook>(
            HOOK_CMF_TOOL_PRE_INVOKE,
            message(),
            tenantless(tool_meta("search")),
            None,
        )
        .await;

    assert!(result.is_denied(), "the contract denies");
    let seen = rec.seen();
    assert_eq!(seen.len(), 1, "one record per invocation");
    assert!(
        seen[0].denied,
        "the sink is told the denial the caller got, not the allow the pipeline reached"
    );
    assert_eq!(seen[0].code.as_deref(), Some("auth.assertion_missing"));
}

/// The decision log a late denial carries is the pipeline's, not an empty one.
///
/// `deny_missing_assertion` builds a fresh result, and rebuilding used to drop
/// the steps with it — leaving the caller nothing on the one denial that has a
/// whole pipeline behind it.
#[tokio::test]
async fn a_late_denial_keeps_the_steps_that_led_to_it() {
    let engine = engine_with(DENYING_CONTRACT).await;
    let rec = attach_sink(&engine, &[]);
    attach_actor(&engine, "unused");

    let (result, _bg) = engine
        .invoke_named::<CmfHook>(
            HOOK_CMF_TOOL_PRE_INVOKE,
            message(),
            tenantless(tool_meta("search")),
            None,
        )
        .await;

    assert!(result.is_denied());
    assert!(
        !result.decision_log.steps().is_empty(),
        "the pipeline's steps survive the rebuild"
    );
    assert!(rec.seen()[0].steps > 0, "and the sink sees them");
}

/// A request denied because its route would not resolve. The pipeline never
/// runs, so there is no executor emit to inherit — and this used to be silent,
/// which loses exactly the requests most worth having a record of.
#[tokio::test]
async fn a_route_resolution_denial_still_reaches_the_sink() {
    let engine = engine_with(DENYING_CONTRACT).await;
    let rec = attach_sink(&engine, &[]);
    // An annotation, so the hook has an entry and the invocation reaches route
    // resolution rather than short-circuiting before it.
    attach_actor(&engine, "unused");

    // No `meta`, so nothing identifies the request and no route resolves,
    // while the configuration declares a policy written in terms of one.
    let (result, _bg) = engine
        .invoke_named::<CmfHook>(
            HOOK_CMF_TOOL_PRE_INVOKE,
            message(),
            Extensions::default(),
            None,
        )
        .await;

    assert!(result.is_denied(), "an unresolvable route denies");
    assert_eq!(
        result.violation.as_ref().map(|v| v.code.as_str()),
        Some("unidentified_request")
    );
    let seen = rec.seen();
    assert_eq!(seen.len(), 1, "and it is recorded rather than dropped");
    assert!(seen[0].denied, "as the denial it is");
}

/// The zero-plugin path still emits exactly one allow, which is what keeps the
/// stream dense at one record per invocation.
#[tokio::test]
async fn a_zero_plugin_invocation_emits_one_allow() {
    let engine = engine_with(PLAIN).await;
    let rec = attach_sink(&engine, &[]);

    let (result, _bg) = engine
        .invoke_named::<CmfHook>(
            "cmf.nothing.is.registered.here",
            message(),
            tool_meta("search"),
            None,
        )
        .await;

    assert!(!result.is_denied());
    let seen = rec.seen();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].denied);
}

// =====================================================================
// A sink observes and does nothing else
// =====================================================================

/// A sink declaring nothing sees the ungated slots and nothing more.
///
/// The extensions at the verdict are the executor's working copy: the host's
/// transport is installed on it and the credential slots are unfiltered,
/// because the plugins that ran were each filtered from it on the way in.
/// Handing that copy to a sink let it read inbound bearer material and reach
/// outside the process with no grant naming either.
#[tokio::test]
async fn a_sink_declaring_nothing_sees_neither_credentials_nor_the_transport() {
    let engine = engine_with(PLAIN).await;
    let rec = attach_sink(&engine, &[]);

    let (_result, _bg) = engine
        .invoke_named::<CmfHook>(
            HOOK_CMF_TOOL_PRE_INVOKE,
            message(),
            tenantless(tool_meta("search")),
            None,
        )
        .await;

    let seen = rec.seen();
    assert_eq!(seen.len(), 1);
    assert!(
        !seen[0].had_inbound_credentials,
        "no `read_inbound_credentials`, no bearer material"
    );
    assert!(
        !seen[0].had_transport,
        "no `perform_http`, no reaching outside the process"
    );
    assert!(!seen[0].had_http, "no `read_headers`, no header map");
}

/// The same sink, with the grants. Filtering is a gate, not a blanket refusal:
/// a sink that declares what it needs still gets it.
#[tokio::test]
async fn a_sink_that_declares_a_capability_is_given_that_slot() {
    let engine = engine_with(PLAIN).await;
    let rec = attach_sink(&engine, &["read_headers", "read_inbound_credentials"]);

    let (_result, _bg) = engine
        .invoke_named::<CmfHook>(
            HOOK_CMF_TOOL_PRE_INVOKE,
            message(),
            tenantless(tool_meta("search")),
            None,
        )
        .await;

    let seen = rec.seen();
    assert!(seen[0].had_http, "`read_headers` was declared");
    assert!(
        seen[0].had_inbound_credentials,
        "`read_inbound_credentials` was declared"
    );
    assert!(
        !seen[0].had_transport,
        "but `perform_http` was not, and is not implied by the others"
    );
}

/// A sink observing an effect is handed a view it cannot act through.
///
/// It used to receive the acting plugin's own extensions, carrying that
/// plugin's live effect slot — so a sink could append records under the name of
/// the plugin it was watching. For a log whose purpose is accounting for
/// irreversible acts, a forged record is worse than a missing one: a gap is
/// visible, a forgery is not.
#[tokio::test]
async fn a_sink_observing_an_effect_cannot_perform_one() {
    let engine = engine_with(PLAIN).await;
    let rec = attach_sink(&engine, &[]);
    attach_actor(&engine, "mint-1");

    let (_result, _bg) = engine
        .invoke_named::<CmfHook>(
            HOOK_CMF_TOOL_PRE_INVOKE,
            message(),
            tool_meta("search"),
            None,
        )
        .await;

    let effects = rec.effects.lock().unwrap();
    assert_eq!(
        effects.len(),
        2,
        "the sink sees the intent and the outcome: {effects:?}"
    );
    assert_eq!(effects[0], ("mint-1".to_owned(), EffectState::Prepared));
    assert_eq!(effects[1], ("mint-1".to_owned(), EffectState::Confirmed));

    let attempt = rec.effect_attempt.lock().unwrap();
    let attempt = attempt.as_deref().expect("the sink tried to act");
    assert!(
        attempt.contains("a copy, not the ones this handler was given"),
        "the sink's view refuses effects: {attempt}"
    );
}
