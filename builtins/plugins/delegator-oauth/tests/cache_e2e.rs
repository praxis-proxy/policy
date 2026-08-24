// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for the delegated-token cache, driven through the
// real handler against a `mockito` fake IdP.
//
// The unit tests in `cache::store` prove the store coalesces, bounds and
// expires correctly against a synthetic mint. These prove the parts that
// only exist once the delegator is wired to it: that a hit actually
// avoids the network, that the subject gate is honoured, and — the one
// that matters — that two callers are never handed each other's
// credential.
//
// `mock.expect(n)` is the assertion doing the work in most of these. It
// fails if the IdP was called a different number of times than the cache
// is supposed to allow, which is a direct measurement rather than a
// proxy for one.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::sync::Arc;

use praxis_policy_core::delegation::{
    DelegationPayload, DelegationSubject, HOOK_TOKEN_DELEGATE, TargetType, TokenDelegateHook,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_delegator_oauth::OAuthDelegator;

use mockito::{Matcher, Server};
use serde_json::{Value, json};

// =====================================================================
// Fixtures
// =====================================================================

/// A delegator config with an explicit `cache` block. `cache` is `None`
/// for the default (off) behaviour.
fn plugin_config(token_endpoint: &str, cache: Option<Value>) -> PluginConfig {
    let mut config = json!({
        "token_endpoint": token_endpoint,
        "client_id": "gateway-client",
        "client_secret_source": { "kind": "literal", "secret": "test-secret" },
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "timeout_seconds": 2,
        "default_outbound_header": "Authorization",
        "insecure_http": true,
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
        config: Some(config),
        ..Default::default()
    }
}

/// Caching on, for the subject modes each test needs. No jitter, so the
/// serve window is exactly predictable.
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

async fn build_manager(token_endpoint: &str, cache: Option<Value>) -> Arc<PolicyEngine> {
    let cfg = plugin_config(token_endpoint, cache);
    let delegator = OAuthDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

/// Invoke and return the minted token bytes plus where they came from.
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

/// A mock that answers any exchange with `access_token`, expecting
/// exactly `calls` requests.
fn mint_mock(server: &mut mockito::ServerGuard, access_token: &str, calls: usize) -> mockito::Mock {
    server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": access_token,
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                "scope": "read:compensation",
            })
            .to_string(),
        )
        .expect(calls)
        .create()
}

// =====================================================================
// Scenarios
// =====================================================================

/// The default. An operator who upgrades and changes nothing gets the
/// behaviour they had: one exchange per delegation.
#[tokio::test]
async fn caching_is_off_unless_configured() {
    let mut server = Server::new_async().await;
    let mock = mint_mock(&mut server, "minted-jwt", 2);
    let mgr = build_manager(&format!("{}/oauth/token", server.url()), None).await;

    let (_, first) = delegate(&mgr, payload_for("alice-token")).await;
    let (_, second) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(first, "mint");
    assert_eq!(second, "mint", "an unconfigured cache must not cache");
    mock.assert_async().await;
}

/// The point of the feature: the second delegation does not touch the
/// `IdP`. `expect(1)` is the assertion.
#[tokio::test]
async fn a_second_delegation_is_served_from_cache() {
    let mut server = Server::new_async().await;
    let mock = mint_mock(&mut server, "minted-jwt", 1);
    let mgr = build_manager(
        &format!("{}/oauth/token", server.url()),
        Some(cache_on(&["user"])),
    )
    .await;

    let (first_token, first_source) = delegate(&mgr, payload_for("alice-token")).await;
    let (second_token, second_source) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(first_source, "mint");
    assert_eq!(second_source, "cache");
    assert_eq!(
        first_token, second_token,
        "the cached delegation must hand back the token that was minted"
    );
    mock.assert_async().await;
}

/// The one that matters. Two callers presenting different credentials
/// must never be handed each other's delegated token, however identical
/// the rest of the delegation is.
///
/// Both mocks match on `subject_token`, so this also proves the
/// delegator sent the right credential for each caller rather than
/// merely returning a different string.
#[tokio::test]
async fn two_callers_are_never_handed_each_others_token() {
    let mut server = Server::new_async().await;

    let alice = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::UrlEncoded(
            "subject_token".into(),
            "alice-token".into(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "access_token": "alice-minted", "expires_in": 300 }).to_string())
        .expect(1)
        .create();

    let bob = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::UrlEncoded(
            "subject_token".into(),
            "bob-token".into(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "access_token": "bob-minted", "expires_in": 300 }).to_string())
        .expect(1)
        .create();

    let mgr = build_manager(
        &format!("{}/oauth/token", server.url()),
        Some(cache_on(&["user"])),
    )
    .await;

    // Alice populates the cache. Everything about Bob's delegation is
    // identical except the credential he holds.
    let (alice_token, _) = delegate(&mgr, payload_for("alice-token")).await;
    let (bob_token, bob_source) = delegate(&mgr, payload_for("bob-token")).await;

    assert_eq!(alice_token, "alice-minted");
    assert_eq!(
        bob_token, "bob-minted",
        "bob was served a credential minted for another principal"
    );
    assert_eq!(bob_source, "mint", "bob must not hit alice's entry");

    // Alice still hits her own entry rather than picking up Bob's.
    let (alice_again, alice_source) = delegate(&mgr, payload_for("alice-token")).await;
    assert_eq!(alice_again, "alice-minted");
    assert_eq!(alice_source, "cache");

    alice.assert_async().await;
    bob.assert_async().await;
}

/// A subject mode the operator did not list is not cached, even with the
/// cache on. This is what keeps `user`'s unbounded key space out of a
/// deployment that only wanted the cheap `this_workload` win.
#[tokio::test]
async fn a_subject_mode_not_opted_in_is_not_cached() {
    let mut server = Server::new_async().await;
    let mock = mint_mock(&mut server, "minted-jwt", 2);
    let mgr = build_manager(
        &format!("{}/oauth/token", server.url()),
        Some(cache_on(&["this_workload"])),
    )
    .await;

    let (_, first) = delegate(&mgr, payload_for("alice-token")).await;
    let (_, second) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(first, "mint");
    assert_eq!(second, "mint", "user mode was not opted in");
    mock.assert_async().await;
}

/// A rejected exchange must leave nothing behind. The next caller has to
/// reach the `IdP` rather than inherit the failure.
#[tokio::test]
async fn a_rejected_exchange_is_not_cached() {
    let mut server = Server::new_async().await;

    let rejected = server
        .mock("POST", "/oauth/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(json!({ "error": "invalid_grant" }).to_string())
        .expect(1)
        .create();

    let mgr = build_manager(
        &format!("{}/oauth/token", server.url()),
        Some(cache_on(&["user"])),
    )
    .await;

    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload_for("alice-token"),
            Extensions::default(),
            None,
        )
        .await;
    assert!(!result.continue_processing, "a rejected exchange must deny");
    rejected.assert_async().await;

    // The IdP recovers. Nothing should have been memoized from the
    // failure, so this must reach it and succeed.
    let recovered = mint_mock(&mut server, "minted-after-recovery", 1);
    let (token, source) = delegate(&mgr, payload_for("alice-token")).await;

    assert_eq!(token, "minted-after-recovery");
    assert_eq!(source, "mint");
    recovered.assert_async().await;
}

/// A delegation whose route carries an unrendered `resource_template`
/// is never cached, because the handler may one day render request
/// arguments into it. Degrades to a miss rather than to a token scoped
/// for somebody else's resource.
#[tokio::test]
async fn a_resource_template_forces_a_miss() {
    use praxis_policy_core::delegation::AttenuationConfig;

    let mut server = Server::new_async().await;
    let mock = mint_mock(&mut server, "minted-jwt", 2);
    let mgr = build_manager(
        &format!("{}/oauth/token", server.url()),
        Some(cache_on(&["user"])),
    )
    .await;

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
    mock.assert_async().await;
}

/// `this_workload` has no inbound credential, so its anchor is empty by
/// design. It must still cache, and the delegator identity is what
/// isolates it.
#[tokio::test]
async fn this_workload_caches_despite_an_empty_anchor() {
    let mut server = Server::new_async().await;
    let mock = mint_mock(&mut server, "gateway-minted", 1);
    let mgr = build_manager(
        &format!("{}/oauth/token", server.url()),
        Some(cache_on(&["this_workload"])),
    )
    .await;

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
    mock.assert_async().await;
}
