// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for the delegated-token cache, driven through the
// real handler against a scripted `HttpTransport`.
//
// The unit tests in `cache::store` prove the store coalesces, bounds and
// expires correctly against a synthetic mint. These prove the parts that
// only exist once the delegator is wired to it: that a hit actually
// avoids the exchange, that the subject gate is honoured, and — the one
// that matters — that two callers are never handed each other's
// credential.
//
// `ScriptedIdp::calls()` is the assertion doing the work in most of
// these. It counts exchanges that reached the `IdP`, which is a direct
// measurement of what the cache is for rather than a proxy for one.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::{Value, json};

use praxis_policy_core::delegation::{
    DelegationPayload, DelegationSubject, HOOK_TOKEN_DELEGATE, TargetType, TokenDelegateHook,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_delegator_oauth::OAuthDelegator;

const TOKEN_ENDPOINT: &str = "https://idp.test/oauth/token";

// =====================================================================
// A scripted IdP
// =====================================================================

/// Answers a token exchange with a credential derived from the subject
/// token it was given, so two callers get visibly different tokens.
///
/// `FakeTransport` keys its responses on a URL fragment, which cannot
/// tell one caller from another when both hit the same endpoint. That
/// distinction is the whole point of the isolation test below, so this
/// reads the request body instead.
#[derive(Debug, Default)]
struct ScriptedIdp {
    calls: AtomicUsize,
    /// Reject this many exchanges before minting anything, so a test can
    /// watch the delegator recover from an `IdP` that was refusing.
    reject_first: usize,
}

impl ScriptedIdp {
    fn new() -> Self {
        Self::default()
    }

    fn rejecting_first(count: usize) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reject_first: count,
        }
    }

    /// Exchanges that actually reached the `IdP`.
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl HttpTransport for ScriptedIdp {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let nth = self.calls.fetch_add(1, Ordering::SeqCst);
        if nth < self.reject_first {
            let body = json!({ "error": "invalid_grant" }).to_string();
            return Ok(HttpResponse::new(400, Bytes::from(body)));
        }

        // A client-credentials grant carries no `subject_token`, which is
        // the `this_workload` case: the delegator is the principal.
        let form = String::from_utf8_lossy(&req.body).into_owned();
        let subject = form_field(&form, "subject_token").unwrap_or_else(|| "gateway".to_owned());

        let body = json!({
            "access_token": format!("{subject}-minted"),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 300,
            "scope": "read:compensation",
        })
        .to_string();
        Ok(HttpResponse::new(200, Bytes::from(body)))
    }
}

/// Pull one field out of an `application/x-www-form-urlencoded` body.
///
/// No percent-decoding: every value these tests send is already safe in
/// a form body, and a decoder here would be test scaffolding with its
/// own bugs.
fn form_field(body: &str, name: &str) -> Option<String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

// =====================================================================
// Fixtures
// =====================================================================

/// A delegator config with an explicit `cache` block. `None` leaves the
/// cache at its default, which is off.
fn plugin_config(cache: Option<Value>) -> PluginConfig {
    let mut config = json!({
        "token_endpoint": TOKEN_ENDPOINT,
        "client_id": "gateway-client",
        "client_secret_source": { "kind": "literal", "secret": "test-secret" },
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "timeout_seconds": 2,
        "default_outbound_header": "Authorization",
    });
    if let Some(cache) = cache {
        config["cache"] = cache;
    }
    PluginConfig {
        name: "oauth-delegator".into(),
        kind: "test".into(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        // The exchange is an outbound call, so it needs `perform_http`.
        capabilities: ["perform_http".to_owned()].into(),
        config: Some(config),
        ..Default::default()
    }
}

/// Caching on for the given subject modes. No jitter, so the serve
/// window is exactly predictable.
fn cache_on(subjects: &[&str]) -> Value {
    json!({
        "enabled": true,
        "subjects": subjects,
        "max_entries": 100,
        "ttl_ceiling_seconds": 300,
        "staleness": { "fraction": 0.2, "floor_seconds": 30, "jitter_seconds": 0 },
    })
}

fn payload_for(bearer: &str) -> DelegationPayload {
    DelegationPayload::new(bearer, "get_compensation")
        .with_target_type(TargetType::Tool)
        .with_target_audience("https://hr.example.com")
        .with_required_permissions(vec!["read:compensation".to_owned()])
}

async fn build_manager(idp: &Arc<ScriptedIdp>, cache: Option<Value>) -> Arc<PolicyEngine> {
    let cfg = plugin_config(cache);
    let delegator = OAuthDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    let transport: Arc<dyn HttpTransport> = idp.clone();
    mgr.set_http_transport(transport);
    mgr.initialize().await.unwrap();
    mgr
}

/// Invoke, and return the minted token bytes plus where they came from.
async fn delegate(mgr: &Arc<PolicyEngine>, payload: DelegationPayload) -> (String, String) {
    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "delegation should succeed: violation = {:?}",
        result.violation,
    );
    let final_payload =
        DelegationPayload::from_pipeline_result(&result).expect("delegation payload present");
    let token = final_payload
        .delegated_token
        .as_ref()
        .expect("delegated_token populated");
    let source = final_payload
        .metadata
        .get("delegated_token_source")
        .and_then(Value::as_str)
        .expect("source metadata recorded")
        .to_owned();
    ((*token.token).clone(), source)
}

// =====================================================================
// Scenarios
// =====================================================================

/// The default. An operator who upgrades and changes nothing gets the
/// behaviour they had: one exchange per delegation.
#[tokio::test]
async fn caching_is_off_unless_configured() {
    let idp = Arc::new(ScriptedIdp::new());
    let mgr = build_manager(&idp, None).await;

    let (_, first) = delegate(&mgr, payload_for("alice-token")).await;
    let (_, second) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(first, "mint");
    assert_eq!(second, "mint", "an unconfigured cache must not cache");
    assert_eq!(idp.calls(), 2);
}

/// The point of the feature: the second delegation does not reach the
/// `IdP`.
#[tokio::test]
async fn a_second_delegation_is_served_from_cache() {
    let idp = Arc::new(ScriptedIdp::new());
    let mgr = build_manager(&idp, Some(cache_on(&["user"]))).await;

    let (first_token, first_source) = delegate(&mgr, payload_for("alice-token")).await;
    let (second_token, second_source) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(first_source, "mint");
    assert_eq!(second_source, "cache");
    assert_eq!(
        first_token, second_token,
        "the cached delegation must hand back the token that was minted"
    );
    assert_eq!(idp.calls(), 1, "the second delegation reached the IdP");
}

/// The one that matters. Two callers presenting different credentials
/// must never be handed each other's delegated token, however identical
/// the rest of the delegation is.
#[tokio::test]
async fn two_callers_are_never_handed_each_others_token() {
    let idp = Arc::new(ScriptedIdp::new());
    let mgr = build_manager(&idp, Some(cache_on(&["user"]))).await;

    // Alice populates the cache. Everything about Bob's delegation is
    // identical except the credential he holds.
    let (alice_token, _) = delegate(&mgr, payload_for("alice-token")).await;
    let (bob_token, bob_source) = delegate(&mgr, payload_for("bob-token")).await;

    assert_eq!(alice_token, "alice-token-minted");
    assert_eq!(
        bob_token, "bob-token-minted",
        "bob was served a credential minted for another principal"
    );
    assert_eq!(bob_source, "mint", "bob must not hit alice's entry");

    // Alice still hits her own entry rather than picking up Bob's.
    let (alice_again, alice_source) = delegate(&mgr, payload_for("alice-token")).await;
    assert_eq!(alice_again, "alice-token-minted");
    assert_eq!(alice_source, "cache");

    assert_eq!(idp.calls(), 2, "one exchange each, and no third");
}

/// A subject mode the operator did not list is not cached, even with the
/// cache on. This is what keeps `user`'s unbounded entry count out of a
/// deployment that only wanted the cheap `this_workload` win.
#[tokio::test]
async fn a_subject_mode_not_opted_in_is_not_cached() {
    let idp = Arc::new(ScriptedIdp::new());
    let mgr = build_manager(&idp, Some(cache_on(&["this_workload"]))).await;

    let (_, first) = delegate(&mgr, payload_for("alice-token")).await;
    let (_, second) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(first, "mint");
    assert_eq!(second, "mint", "user mode was not opted in");
    assert_eq!(idp.calls(), 2);
}

/// A rejected exchange must leave nothing behind. The next caller has to
/// reach the `IdP` rather than inherit the failure.
#[tokio::test]
async fn a_rejected_exchange_is_not_cached() {
    let idp = Arc::new(ScriptedIdp::rejecting_first(1));
    let mgr = build_manager(&idp, Some(cache_on(&["user"]))).await;

    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload_for("alice-token"),
            Extensions::default(),
            None,
        )
        .await;
    assert!(!result.continue_processing, "a rejected exchange must deny");

    // The IdP recovers. Nothing should have been memoized from the
    // failure, so this must reach it and succeed.
    let (token, source) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(token, "alice-token-minted");
    assert_eq!(source, "mint");
    assert_eq!(idp.calls(), 2, "the retry reached the IdP");
}

/// A delegation whose route carries an unrendered `resource_template` is
/// never cached, because the handler may one day render request
/// arguments into it. Degrades to a miss rather than to a token scoped
/// for somebody else's resource.
#[tokio::test]
async fn a_resource_template_forces_a_miss() {
    use praxis_policy_core::delegation::AttenuationConfig;

    let idp = Arc::new(ScriptedIdp::new());
    let mgr = build_manager(&idp, Some(cache_on(&["user"]))).await;

    let templated = || {
        payload_for("alice-token").with_route_attenuation(AttenuationConfig {
            capabilities: Vec::new(),
            resource_template: Some("https://hr.example.com/{{ args.employee_id }}".to_owned()),
            actions: Vec::new(),
            ttl_seconds: None,
        })
    };

    let (_, first) = delegate(&mgr, templated()).await;
    let (_, second) = delegate(&mgr, templated()).await;

    assert_eq!(first, "mint");
    assert_eq!(
        second, "mint",
        "a route that can render request arguments must not be cached"
    );
    assert_eq!(idp.calls(), 2);
}

/// `this_workload` has no inbound credential, so its anchor is empty by
/// design. It must still cache, and the delegator identity is what
/// isolates it.
#[tokio::test]
async fn this_workload_caches_despite_an_empty_anchor() {
    let idp = Arc::new(ScriptedIdp::new());
    let mgr = build_manager(&idp, Some(cache_on(&["this_workload"]))).await;

    let as_gateway = || {
        DelegationPayload::new("", "get_compensation")
            .with_subject(DelegationSubject::ThisWorkload)
            .with_target_audience("https://hr.example.com")
    };

    let (_, first) = delegate(&mgr, as_gateway()).await;
    let (token, second) = delegate(&mgr, as_gateway()).await;

    assert_eq!(first, "mint");
    assert_eq!(second, "cache");
    assert_eq!(token, "gateway-minted");
    assert_eq!(idp.calls(), 1);
}
