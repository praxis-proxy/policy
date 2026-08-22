// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for `OAuthDelegator` against a `mockito`-backed
// fake IdP. Exercises the full handler path:
// `mgr.invoke_named::<TokenDelegateHook>(...)` → delegator builds
// RFC 8693 form body → POSTs to mock IdP → mock returns response
// → delegator translates into a `RawDelegatedToken` → host
// extracts via `from_pipeline_result`.
//
// Scenarios:
//   * happy path — minted token populated with audience + scopes + expiry
//   * IdP returns 400 with `invalid_grant` — surfaces `delegation.idp_rejected`
//   * IdP unreachable — surfaces `delegation.idp_unreachable`
//   * Request body shape — mockito's matcher verifies we send the
//     correct RFC 8693 fields
//   * actor_token — present on the wire when the payload carries one
//     (Mode B), fully absent when it doesn't
//   * workload subject (Mode A) — the SVID authenticates the agent as
//     a client_assertion (leg 1), then the exchange runs on that base
//     token (leg 2); attributed `AsCallerWorkload`, not `AsThisWorkload`

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::sync::Arc;

use praxis_policy_core::http::{HttpTransport, HttpTransportError};
use praxis_policy_core::http_testing::FakeTransport;

use praxis_policy_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, DelegationSubject, HOOK_TOKEN_DELEGATE,
    TargetType, TokenDelegateHook,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::raw_credentials::{DelegationMode, TokenRole};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_delegator_oauth::OAuthDelegator;

use serde_json::json;

// =====================================================================
// Fixtures
// =====================================================================

fn plugin_config(token_endpoint: &str) -> PluginConfig {
    PluginConfig {
        name: "oauth-delegator".into(),
        kind: "test".into(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        // A token exchange is an outbound call, so the plugin declares
        // `perform_http`. Withholding it stops the exchange rather than
        // degrading it: a delegator that silently skipped its IdP call
        // would fail open.
        capabilities: ["perform_http".to_owned()].into(),
        config: Some(json!({
            "token_endpoint": token_endpoint,
            "client_id": "gateway-client",
            "client_secret_source": {
                "kind": "literal",
                "secret": "test-secret",
            },
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "timeout_seconds": 2,
            "default_outbound_header": "Authorization",
            // wiremock binds to http://127.0.0.1 — opt in to plaintext
            // for the test. Production deployments must omit this.
            "insecure_http": true,
        })),
        ..Default::default()
    }
}

fn build_payload(target: &str, audience: &str, scopes: &[&str]) -> DelegationPayload {
    DelegationPayload::new("caller-bearer-token-bytes", target)
        .with_target_type(TargetType::Tool)
        .with_target_audience(audience)
        .with_required_permissions(
            scopes
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        )
        .with_auth_enforced_by(AuthEnforcedBy::Target)
        .with_route_attenuation(AttenuationConfig {
            capabilities: vec!["audit".into()],
            resource_template: None,
            actions: Vec::new(),
            ttl_seconds: Some(120),
        })
}

/// Path the scripted `IdP` serves its token endpoint on.
const TOKEN_PATH: &str = "/oauth/token";

/// Token endpoint URL for the scripted transport. The host never
/// resolves — the transport is programmed, not dialled.
fn token_endpoint() -> String {
    format!("https://idp.example.test{TOKEN_PATH}")
}

/// An engine wired to `http`.
///
/// These tests exercise what the delegator sends and how it maps what
/// comes back. Wire mechanics belong to the transport and are tested
/// against real sockets where it lives. What a script buys here is the
/// half a mock server cannot reach: a timeout on demand, so the
/// non-idempotent retry rule is assertable without waiting on one.
async fn build_manager(http: &Arc<FakeTransport>) -> Arc<PolicyEngine> {
    let cfg = plugin_config(&token_endpoint());
    let delegator = OAuthDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    let transport: Arc<dyn HttpTransport> = http.clone();
    mgr.set_http_transport(transport);
    mgr.initialize().await.unwrap();
    mgr
}

/// A transport that answers the token endpoint with `status` and `body`.
fn idp(status: u16, body: &str) -> Arc<FakeTransport> {
    Arc::new(FakeTransport::new().json(TOKEN_PATH, status, body))
}

/// Percent-decode one `application/x-www-form-urlencoded` value.
fn form_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => out.push(b),
                    Err(_) => out.push(bytes[i]),
                }
                i += 3;
            },
            b => {
                out.push(b);
                i += 1;
            },
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether the form body the delegator sent mentions `key` at all.
///
/// Absence is the assertion in several cases — a `this_workload` grant
/// must not carry a `subject_token`, and a delegation with no actor must
/// not invent one — so it needs to be as easy to state as presence.
fn did_not_send(http: &FakeTransport, key: &str) -> bool {
    sent_field(http, key).is_none()
}

/// One field from the form body the delegator actually sent.
///
/// Asserting on the recorded request rather than on a server-side
/// matcher means a failure names the value that was wrong, instead of
/// reporting that a mock went unmatched.
fn sent_field(http: &FakeTransport, key: &str) -> Option<String> {
    let req = http.last_request()?;
    let body = String::from_utf8_lossy(&req.body).into_owned();
    body.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (form_decode(k) == key).then(|| form_decode(v))
    })
}

async fn invoke(
    mgr: &Arc<PolicyEngine>,
    payload: DelegationPayload,
) -> praxis_policy_core::executor::PipelineResult {
    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    result
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path: mock `IdP` responds with a fresh `access_token`; the
/// delegator translates it into a `RawDelegatedToken` populated
/// with the requested audience, the effective scopes, and an
/// expiry derived from `expires_in`.
#[tokio::test]
async fn happy_path_mints_delegated_token() {
    let http = idp(
        200,
        &json!({
            "access_token": "minted-downstream-jwt",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 300,
            "scope": "read:compensation audit",
        })
        .to_string(),
    );

    let mgr = build_manager(&http).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "happy path should mint a token: violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    let token = final_payload
        .delegated_token
        .as_ref()
        .expect("delegated_token populated");

    assert_eq!(&*token.token, "minted-downstream-jwt");
    assert_eq!(token.audience, "https://hr.example.com");
    assert_eq!(token.outbound_header, "Authorization");
    // Effective scopes come from the IdP's `scope` field.
    assert!(token.scopes.contains(&"read:compensation".to_owned()));
    assert!(token.scopes.contains(&"audit".to_owned()));

    // Mode is OnBehalfOfUser by default for RFC 8693 exchange.
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    // TTL respects the route hint (120s) — IdP's expires_in was 300,
    // but the route asked to cap at 120, so effective is 120.
    let ttl_left = (token.expires_at - chrono::Utc::now()).num_seconds();
    assert!(
        ttl_left <= 120 && ttl_left > 100,
        "ttl should reflect min(idp_ttl, route_hint); got {ttl_left}s",
    );

    // The RFC 8693 fields the exchange requires. Asserted on what was
    // actually sent, so a failure names the wrong value rather than
    // reporting an unmatched mock.
    assert_eq!(
        sent_field(&http, "grant_type").as_deref(),
        Some("urn:ietf:params:oauth:grant-type:token-exchange")
    );
    assert_eq!(
        sent_field(&http, "subject_token").as_deref(),
        Some("caller-bearer-token-bytes")
    );
    assert_eq!(
        sent_field(&http, "audience").as_deref(),
        Some("https://hr.example.com")
    );
    let sent = http.last_request().expect("a request was sent");
    assert_eq!(
        sent.headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/x-www-form-urlencoded")
    );
    assert!(
        sent.headers.contains_key("authorization"),
        "client credentials ride in the Authorization header"
    );
}

/// `IdP` returns a 400 with the standard `error` / `error_description`
/// shape — delegator surfaces `delegation.idp_rejected` carrying the
/// `IdP`'s machine-readable code.
#[tokio::test]
async fn idp_rejection_surfaces_error_code() {
    let http = idp(
        400,
        &json!({
            "error": "invalid_grant",
            "error_description": "subject_token is not active",
        })
        .to_string(),
    );

    let mgr = build_manager(&http).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read"]);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("invalid_grant"),
        "reason should include IdP's error code; got: {}",
        violation.reason,
    );
    assert!(
        violation.reason.contains("not active"),
        "reason should include the error_description; got: {}",
        violation.reason,
    );
}

/// `IdP` unreachable (mockito server stopped) — delegator surfaces
/// `delegation.idp_unreachable` rather than panicking.
#[tokio::test]
async fn idp_unreachable_surfaces_violation() {
    // Use a localhost URL that should be unreachable (no listener
    // on that port). The `127.0.0.1:1` port-1 trick: port 1 isn't
    // bound by typical systems and connection refusal is fast.
    // Unreachable on demand: a refused connection, scripted rather than
    // relying on port 1 being unbound.
    let http = Arc::new(
        FakeTransport::new().fail(TOKEN_PATH, HttpTransportError::Connect("refused".into())),
    );
    let mgr = build_manager(&http).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read"]);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    // Either `idp_unreachable` (connection refused) or `idp_timeout`
    // (if the OS decides to slow-fail) — both are valid outcomes
    // for "IdP isn't there." The test accepts either.
    assert!(
        violation.code == "delegation.idp_unreachable"
            || violation.code == "delegation.idp_timeout",
        "expected idp_unreachable or idp_timeout; got {}",
        violation.code,
    );
}

/// Empty bearer token — fails fast at the handler entry before
/// touching the network. Verifies the input-validation path.
#[tokio::test]
async fn empty_bearer_token_rejects_without_network() {
    // Programmed but never expected to answer: these cases must reject
    // before any request is issued.
    let http = idp(200, &ok_token_response());
    let mgr = build_manager(&http).await;
    let payload =
        DelegationPayload::new("", "tool").with_target_audience("https://downstream.example.com");

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains("empty bearer_token"));
}

/// Missing target audience — fails fast (RFC 8693 requires
/// `audience` for downstream scoping).
#[tokio::test]
async fn missing_audience_rejects_without_network() {
    // Programmed but never expected to answer: these cases must reject
    // before any request is issued.
    let http = idp(200, &ok_token_response());
    let mgr = build_manager(&http).await;
    let payload = DelegationPayload::new("some-token", "tool"); // no audience

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains("target_audience"));
}

/// `IdP` grants narrower scopes than requested — delegator emits the
/// documented `delegation.scope_too_broad` code rather than silently
/// proceeding. Without this check, a route that requested
/// `read+write` and got back only `read` would mint a token the
/// downstream call can't actually use, leaving the policy author
/// with no observable signal about *why* the call failed downstream.
#[tokio::test]
async fn idp_narrower_scope_surfaces_scope_too_broad() {
    let http = idp(
        200,
        &json!({
            "access_token": "narrower-token",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 300,
            // Asked for both, got only `read`.
            "scope": "read",
        })
        .to_string(),
    );

    let mgr = build_manager(&http).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read", "write"]);

    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "narrower IdP grant must NOT silently succeed",
    );
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.scope_too_broad");
    assert!(
        violation.reason.contains("write"),
        "reason should name the missing scope: {}",
        violation.reason,
    );

    assert_eq!(http.call_count_for(TOKEN_PATH), 1);
}

/// Sanity check: when the `IdP` grants exactly the requested set, the
/// scope check passes. Pins the "no false positive" half of the
/// `scope_too_broad` behaviour.
#[tokio::test]
async fn idp_exact_scope_match_succeeds() {
    let http = idp(
        200,
        &json!({
            "access_token": "ok-token",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 300,
            "scope": "read write",
        })
        .to_string(),
    );

    let mgr = build_manager(&http).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read", "write"]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "exact scope match should mint a token; violation = {:?}",
        result.violation,
    );
    assert_eq!(http.call_count_for(TOKEN_PATH), 1);
}

// =====================================================================
// RFC 8693 actor_token / subject-role attribution
// =====================================================================

/// Standard 200 response body, factored out so the actor tests can
/// focus on what they're actually asserting (the request side).
fn ok_token_response() -> String {
    json!({
        "access_token": "minted-downstream-jwt",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "expires_in": 300,
        "scope": "read:compensation",
    })
    .to_string()
}

/// Mode B — user subject + workload actor. The delegator must put the
/// SVID on the wire as RFC 8693 §2.1 `actor_token`, tagged with the
/// configured `actor_token_type`, alongside the user's `subject_token`.
/// This is the on-behalf-of-a-user shape, and the
/// minted token still speaks for the user.
#[tokio::test]
async fn actor_token_reaches_the_idp_when_the_payload_carries_one() {
    let http = idp(200, &ok_token_response());

    let mgr = build_manager(&http).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_actor(TokenRole::CallerWorkload, "workload.svid.bytes");

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "actor-token exchange should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    // Subject is the user, so the token still speaks for the user
    // even though a workload actor was recorded.
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    // If the actor fields hadn't been sent, the matcher above would
    // have failed to match and this assertion would fire.
    // The user remains the subject; the workload SVID rides along as the
    // actor. Conflating the two would attribute the call to the wrong
    // principal downstream.
    assert_eq!(
        sent_field(&http, "subject_token").as_deref(),
        Some("caller-bearer-token-bytes")
    );
    assert_eq!(
        sent_field(&http, "actor_token").as_deref(),
        Some("workload.svid.bytes")
    );
    assert_eq!(
        sent_field(&http, "actor_token_type").as_deref(),
        Some("urn:ietf:params:oauth:token-type:jwt")
    );
}

/// The negative half: a payload with no actor must produce a plain
/// single-token exchange. Asserted by rejecting any request whose body
/// mentions `actor_token` at all — a stray empty `actor_token=` field
/// would confuse strict `IdPs`, so "absent" has to mean absent.
#[tokio::test]
async fn absent_actor_leaves_no_actor_fields_on_the_wire() {
    let http = idp(200, &ok_token_response());

    let mgr = build_manager(&http).await;
    // No `.with_actor_token(...)` — the ordinary single-token case.
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "single-token exchange should still succeed; violation = {:?}",
        result.violation,
    );
    assert!(
        did_not_send(&http, "actor_token"),
        "no actor was configured, so none may appear on the wire"
    );
    assert!(did_not_send(&http, "actor_token_type"));
}

/// `subject: this_workload` — this instance holds the access to the
/// downstream (the "hold the tool credentials here" deployment)
/// and calls it as itself. There is no inbound credential to
/// exchange, so this must switch to an RFC 6749 §4.4
/// `client_credentials` grant rather than a token exchange: no
/// `subject_token`, and this instance's identity proven by the Basic
/// auth header it already sends.
#[tokio::test]
async fn this_workload_subject_uses_client_credentials_not_token_exchange() {
    let http = idp(200, &ok_token_response());

    let mgr = build_manager(&http).await;
    // Note the empty bearer token: for a this_workload subject that is the
    // expected state, not the "caller forgot the credential" error.
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::ThisWorkload)
        .with_target_audience("https://hr.example.com")
        .with_required_permissions(vec!["read:compensation".into()]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "this_workload-subject exchange should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    assert!(
        matches!(
            final_payload.delegation_mode,
            Some(DelegationMode::AsThisWorkload),
        ),
        "this_workload subject must be attributed to this instance, got {:?}",
        final_payload.delegation_mode,
    );
    assert_eq!(
        sent_field(&http, "grant_type").as_deref(),
        Some("client_credentials"),
        "there is no inbound credential to exchange, so this must be a \
         client_credentials grant"
    );
    assert_eq!(
        sent_field(&http, "audience").as_deref(),
        Some("https://hr.example.com")
    );
    assert!(
        did_not_send(&http, "subject_token"),
        "a client_credentials grant carries no subject_token"
    );
}

/// An empty bearer token is still an error for every subject that
/// *does* have an inbound credential. Pins the boundary: the
/// `this_workload`'s exemption must not silently swallow a genuinely missing
/// workload or user token.
#[tokio::test]
async fn empty_bearer_still_rejected_for_non_this_workload_subjects() {
    let http = idp(200, &ok_token_response());
    let mgr = build_manager(&http).await;
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::CallerWorkload)
        .with_target_audience("https://hr.example.com");

    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "a missing credential must still be an error for a workload subject",
    );
    assert_eq!(
        result.violation.expect("violation surfaced").code,
        "delegation.bad_request",
    );
}

/// `actor_token` is a token-exchange parameter with no meaning under
/// `client_credentials`, so a this_workload-subject call must not send it
/// even when the payload carries one — an `IdP` receiving both would be
/// getting a malformed request.
#[tokio::test]
async fn this_workload_subject_never_sends_actor_token() {
    let http = idp(200, &ok_token_response());

    let mgr = build_manager(&http).await;
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::ThisWorkload)
        .with_actor(TokenRole::CallerWorkload, "workload.svid.bytes")
        .with_target_audience("https://hr.example.com")
        .with_required_permissions(vec!["read:compensation".into()]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "should still mint; violation = {:?}",
        result.violation,
    );
    assert!(
        did_not_send(&http, "actor_token"),
        "this_workload is the subject; there is no separate actor"
    );
}

/// Mode A — the calling agent acts as itself. Its SVID is a *client
/// credential*, not a `subject_token`, so the delegator runs two legs:
///
///   leg 1  present the SVID as an RFC 7523 `client_assertion`
///          (`client_credentials`) → the agent's base `IdP` token;
///   leg 2  the ordinary exchange, run on that BASE token, scopes it
///          to the target audience.
///
/// This is what keeps this instance (holder of the leg-2 client secret),
/// not the agent, as the grantor of downstream authority. The minted
/// credential still speaks for the agent, so `delegation_mode` must be
/// `AsCallerWorkload` (the delegated-token cache keys off it) — and
/// specifically not `AsThisWorkload`, which is this instance's own identity.
///
/// Both legs are asserted: proving the SVID went out as a
/// `client_assertion` in leg 1 and that leg 2 exchanged the base token
/// — never the raw SVID as a `subject_token`.
#[tokio::test]
async fn workload_subject_authenticates_by_svid_then_exchanges() {
    // Two legs against the same endpoint, so the replies are queued in
    // order: leg 1 answers with the agent's base token, leg 2 with the
    // exchanged one. A mock server had to express this by matching on
    // request bodies; a queue says it directly, and the body assertions
    // move below where a failure can name the field that was wrong.
    let http = Arc::new(
        FakeTransport::new()
            .json(
                TOKEN_PATH,
                200,
                &json!({ "access_token": "agent-base-token", "expires_in": 300 }).to_string(),
            )
            .json(TOKEN_PATH, 200, &ok_token_response()),
    );

    let mgr = build_manager(&http).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_subject(DelegationSubject::CallerWorkload);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "two-leg workload delegation should mint a token; violation = {:?}",
        result.violation,
    );

    assert_eq!(
        http.call_count_for(TOKEN_PATH),
        2,
        "the workload path is two legs: authenticate, then exchange"
    );

    // Leg 2 is the last request, and it must carry the BASE token from
    // leg 1 as `subject_token`. This is the assertion that fails if leg
    // 1 is skipped, or if the raw SVID leaks through as the subject.
    assert_eq!(
        sent_field(&http, "grant_type").as_deref(),
        Some("urn:ietf:params:oauth:grant-type:token-exchange")
    );
    assert_eq!(
        sent_field(&http, "subject_token").as_deref(),
        Some("agent-base-token"),
        "leg 2 must exchange the base token, never the SVID"
    );
    assert_eq!(
        sent_field(&http, "audience").as_deref(),
        Some("https://hr.example.com")
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    assert!(
        matches!(
            final_payload.delegation_mode,
            Some(DelegationMode::AsCallerWorkload),
        ),
        "workload subject must be attributed to the calling agent, got {:?}",
        final_payload.delegation_mode,
    );

    // Both legs actually fired — the SVID authenticated the agent (leg
    // 1) and the exchange ran on the base token (leg 2).
}

/// A leg-1 rejection must not echo submitted credential material. Even
/// when the `IdP` hostilely parrots the SVID back in `error_description`, the
/// caller-visible violation carries only the OAuth error code — never the
/// `client_assertion` bytes.
#[tokio::test]
async fn leg1_rejection_does_not_leak_the_client_assertion() {
    let http = idp(
        400,
        &json!({
            "error": "invalid_client",
            "error_description": "assertion 'caller-bearer-token-bytes' is not valid",
        })
        .to_string(),
    );

    let mgr = build_manager(&http).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_subject(DelegationSubject::CallerWorkload);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing, "leg-1 rejection should deny");
    let violation = result.violation.expect("violation surfaced");
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        !violation.reason.contains("caller-bearer-token-bytes"),
        "violation must NOT echo the submitted SVID; got: {}",
        violation.reason,
    );
    assert!(
        violation.reason.contains("invalid_client"),
        "violation should carry the OAuth error code; got: {}",
        violation.reason,
    );
}

// =====================================================================
// Leg-1 failures other than a clean rejection
// =====================================================================

/// A payload for the two-leg workload shape, so the tests below all enter
/// through leg 1.
fn workload_payload() -> DelegationPayload {
    build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_subject(DelegationSubject::CallerWorkload)
}

async fn violation_for(
    payload: DelegationPayload,
    http: &Arc<FakeTransport>,
) -> praxis_policy_core::error::PluginViolation {
    let mgr = build_manager(http).await;
    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "this case must deny rather than mint a token"
    );
    result.violation.expect("a deny carries a violation")
}

/// Leg 1 against an endpoint with nothing listening. The agent cannot be
/// authenticated, so the whole delegation has to fail closed: minting on a
/// failed leg 1 would hand out a downstream token for an agent whose identity
/// was never established.
#[tokio::test]
async fn a_leg1_transport_failure_denies_the_whole_delegation() {
    // A refused connection, scripted. `Connect` specifically, not
    // `Timeout`: it proves nothing was sent, which is what makes leg 1's
    // failure unambiguous rather than an indeterminate mint.
    let http = Arc::new(
        FakeTransport::new().fail(TOKEN_PATH, HttpTransportError::Connect("refused".into())),
    );
    let violation = violation_for(workload_payload(), &http).await;
    assert_eq!(violation.code, "delegation.idp_unreachable");
    assert!(
        violation.reason.contains("workload client_assertion"),
        "the reason must say which leg failed, since both legs post to the \
         same endpoint: {}",
        violation.reason
    );
}

/// A leg-1 rejection whose body is not the OAuth error JSON at all. The status
/// is all there is to report, and reporting it is the point: an operator seeing
/// a bare `idp_rejected` with no detail cannot tell a 400 from a 503.
#[tokio::test]
async fn a_leg1_rejection_with_an_unparseable_body_still_reports_the_status() {
    let http = idp(503, "<html>gateway timeout</html>");

    let violation = violation_for(workload_payload(), &http).await;
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("503"),
        "the status is the only detail available and must appear: {}",
        violation.reason
    );
    assert!(
        !violation.reason.contains("gateway timeout"),
        "an unparseable body is not echoed, for the same reason \
         error_description is not: {}",
        violation.reason
    );
}

/// Leg 1 answering 200 with something that is not a token response. Treating a
/// missing `access_token` as success would carry an empty credential into leg 2
/// and produce a confusing leg-2 rejection instead of naming the real fault.
#[tokio::test]
async fn a_leg1_success_that_is_not_a_token_response_denies() {
    let http = idp(200, &json!({ "not_a_token": true }).to_string());

    let violation = violation_for(workload_payload(), &http).await;
    assert_eq!(violation.code, "delegation.bad_response");
    assert!(
        violation.reason.contains("workload client_assertion"),
        "the reason must attribute the bad response to leg 1: {}",
        violation.reason
    );
}

// =====================================================================
// Leg-2 error shapes
// =====================================================================

/// A leg-2 rejection carrying `error_description` surfaces both the code and
/// the description.
///
/// Note the asymmetry with leg 1, which deliberately drops the description
/// because an `IdP` may echo the submitted credential back in it. Leg 2 submits
/// the caller's bearer token as `subject_token`, so the same echo is possible
/// here. This test records what the code does today rather than endorsing it.
#[tokio::test]
async fn a_leg2_rejection_surfaces_the_error_description() {
    let http = idp(
        400,
        &json!({
            "error": "invalid_scope",
            "error_description": "read:compensation is not granted to this client",
        })
        .to_string(),
    );

    let violation = violation_for(
        build_payload(
            "get_compensation",
            "https://hr.example.com",
            &["read:compensation"],
        ),
        &http,
    )
    .await;
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("invalid_scope"),
        "the machine-readable code must appear: {}",
        violation.reason
    );
    assert!(
        violation.reason.contains("not granted to this client"),
        "and today the description is appended to it: {}",
        violation.reason
    );
}

/// A leg-2 rejection whose body is not OAuth error JSON falls back to the
/// status. Without the fallback the violation would carry an empty reason.
#[tokio::test]
async fn a_leg2_rejection_with_an_unparseable_body_falls_back_to_the_status() {
    let http = idp(500, "upstream exploded");

    let violation = violation_for(
        build_payload("get_compensation", "https://hr.example.com", &[]),
        &http,
    )
    .await;
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("500"),
        "the status must appear when nothing else is parseable: {}",
        violation.reason
    );
}

/// Leg 2 answering 200 with a body that carries no `access_token`. There is no
/// token to forward, so this has to deny rather than mint an empty credential.
#[tokio::test]
async fn a_leg2_success_with_no_access_token_denies() {
    let http = idp(200, &json!({ "token_type": "Bearer" }).to_string());

    let violation = violation_for(
        build_payload("get_compensation", "https://hr.example.com", &[]),
        &http,
    )
    .await;
    assert_eq!(violation.code, "delegation.bad_response");
}

// =====================================================================
// Lifetime and metadata of the minted token
// =====================================================================

/// Run the happy path with a chosen token response and attenuation, and return
/// the minted payload.
async fn mint_with(body: String, attenuation: Option<AttenuationConfig>) -> DelegationPayload {
    let http = idp(200, &body);

    let mut payload = DelegationPayload::new("caller-bearer-token-bytes", "get_compensation")
        .with_target_type(TargetType::Tool)
        .with_target_audience("https://hr.example.com")
        .with_auth_enforced_by(AuthEnforcedBy::Target);
    if let Some(att) = attenuation {
        payload = payload.with_route_attenuation(att);
    }

    let mgr = build_manager(&http).await;
    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "this case must mint a token; violation = {:?}",
        result.violation
    );
    DelegationPayload::from_pipeline_result(&result).expect("a minted payload")
}

fn attenuation_with_ttl(ttl: Option<u64>) -> AttenuationConfig {
    AttenuationConfig {
        capabilities: Vec::new(),
        resource_template: None,
        actions: Vec::new(),
        ttl_seconds: ttl,
    }
}

/// Route attenuation shortens the token's life but never extends it, and an
/// attenuation hint too large to be a duration must leave the `IdP`'s lifetime
/// alone rather than wrap into a negative one.
///
/// A negative lifetime is the failure worth guarding: the minted token would
/// already be expired, so every downstream call fails in a way that looks like
/// an `IdP` problem. The cast saturates for that reason, and nothing else here
/// would notice if it stopped.
#[tokio::test]
async fn attenuation_only_ever_shortens_the_minted_token_lifetime() {
    let body = json!({ "access_token": "t", "expires_in": 3600 }).to_string();

    let shortened = mint_with(body.clone(), Some(attenuation_with_ttl(Some(60)))).await;
    let ttl = shortened
        .delegated_token
        .expect("a token")
        .expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    assert!(
        (0..=60).contains(&ttl),
        "a 60s attenuation hint must shorten a 3600s grant, got {ttl}s"
    );

    // A hint larger than any real duration means "no further shortening".
    let absurd = mint_with(body.clone(), Some(attenuation_with_ttl(Some(u64::MAX)))).await;
    let ttl = absurd
        .delegated_token
        .expect("a token")
        .expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    assert!(
        ttl > 0,
        "an unrepresentable attenuation hint must not produce an \
         already-expired token, got {ttl}s"
    );
    assert!(
        ttl > 3000,
        "and must leave the IdP's own lifetime in place, got {ttl}s"
    );
}

/// An `IdP` that sends no `expires_in` gets a short default rather than an
/// unbounded lifetime, so a misconfigured `IdP` cannot cause long-lived tokens.
#[tokio::test]
async fn a_token_response_with_no_expiry_gets_a_short_default() {
    let minted = mint_with(json!({ "access_token": "t" }).to_string(), None).await;
    let ttl = minted
        .delegated_token
        .expect("a token")
        .expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    assert!(
        (0..=300).contains(&ttl),
        "an absent expires_in must default to at most 5 minutes, got {ttl}s"
    );
}

/// `issued_token_type` is recorded either way: echoed when the `IdP` sends one,
/// defaulted when it does not. Downstream reads this from metadata, so an
/// absent key and a defaulted key are different outcomes for it.
#[tokio::test]
async fn the_issued_token_type_is_recorded_whether_or_not_the_idp_sends_one() {
    let echoed = mint_with(
        json!({
            "access_token": "t",
            "expires_in": 300,
            "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
        .to_string(),
        None,
    )
    .await;
    assert_eq!(
        echoed.metadata.get("issued_token_type"),
        Some(&json!("urn:ietf:params:oauth:token-type:jwt")),
        "an explicit issued_token_type must be carried through"
    );

    let defaulted = mint_with(
        json!({ "access_token": "t", "expires_in": 300 }).to_string(),
        None,
    )
    .await;
    assert_eq!(
        defaulted.metadata.get("issued_token_type"),
        Some(&json!("urn:ietf:params:oauth:token-type:access_token")),
        "and an absent one must be defaulted rather than left unset"
    );
}

// =====================================================================
// the non-idempotency rule
// =====================================================================

/// A timed-out exchange is never repeated.
///
/// This is the assertion that stops duplicate credentials. RFC 8693
/// mints a fresh token per call, and a timeout cannot distinguish "never
/// arrived" from "arrived, and the reply was lost" — so a retry may
/// issue a second live token that nobody holds and nothing is tracking.
///
/// Only a scripted transport can state this: a mock server cannot time
/// out on demand, and a real one would cost seconds of wall clock to
/// assert something that must hold in microseconds.
#[tokio::test]
async fn a_timed_out_exchange_is_not_retried() {
    let http = Arc::new(FakeTransport::new().fail(TOKEN_PATH, HttpTransportError::Timeout));
    let mgr = build_manager(&http).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.expect("a deny carries a violation").code,
        "delegation.idp_timeout",
        "a timeout must surface as indeterminate, not as a clean rejection"
    );
    assert_eq!(
        http.call_count_for(TOKEN_PATH),
        1,
        "exactly one attempt: repeating a timed-out mint could issue a second token"
    );
}

/// A refused connection *is* retried, because nothing was ever sent.
///
/// The complement of the test above, and the reason the rule is about
/// delivery rather than about whether a failure looks transient.
#[tokio::test]
async fn a_refused_connection_is_retried() {
    let http = Arc::new(
        FakeTransport::new()
            .fail(TOKEN_PATH, HttpTransportError::Connect("refused".into()))
            .json(TOKEN_PATH, 200, &ok_token_response()),
    );
    let mgr = build_manager(&http).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "a refused connection sent nothing, so retrying cannot duplicate a mint: {:?}",
        result.violation
    );
    assert_eq!(http.call_count_for(TOKEN_PATH), 2);
}

/// Withholding `perform_http` stops the exchange rather than degrading it.
///
/// A delegator that silently skipped its `IdP` call would fail open: the
/// pipeline would continue with no delegated credential, and whatever
/// depends on that credential would decide for itself what to do.
#[tokio::test]
async fn without_perform_http_the_delegation_denies() {
    let cfg = {
        let mut c = plugin_config(&token_endpoint());
        c.capabilities.clear();
        c
    };
    let delegator = OAuthDelegator::new(cfg.clone()).expect("constructs");
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    let http = idp(200, &ok_token_response());
    let transport: Arc<dyn HttpTransport> = http.clone();
    mgr.set_http_transport(transport);
    mgr.initialize().await.unwrap();

    let result = invoke(
        &mgr,
        build_payload("get_compensation", "https://hr.example.com", &["read"]),
    )
    .await;

    assert!(!result.continue_processing, "no capability, no delegation");
    let v = result.violation.expect("a deny carries a violation");
    assert_eq!(v.code, "delegation.no_transport");
    assert!(
        v.reason.contains("perform_http"),
        "the message must name the capability to add: {}",
        v.reason
    );
    assert_eq!(
        http.call_count(),
        0,
        "a denied capability must stop the call, not merely ignore the result"
    );
}

/// A host that declines the call reports that, not a phantom network
/// failure.
///
/// `Rejected` means an egress policy, an SSRF guard, or an open circuit
/// stopped the request before it left the process. Nothing reached the
/// `IdP`, so it is *safe* to retry — and pointless, because it will fail
/// identically while each attempt feeds the host's breaker.
///
/// Collapsing it into `idp_unreachable` would be the expensive mistake:
/// an operator reads "never reached the `IdP`" and goes debugging DNS and
/// firewalls, when the answer is in their own egress config.
#[tokio::test]
async fn a_host_refusal_is_reported_as_egress_denied_and_not_retried() {
    let http = Arc::new(FakeTransport::new().fail(
        TOKEN_PATH,
        HttpTransportError::Rejected("circuit open".into()),
    ));
    let mgr = build_manager(&http).await;
    let violation = {
        let result = invoke(
            &mgr,
            build_payload("get_compensation", "https://hr.example.com", &["read"]),
        )
        .await;
        assert!(!result.continue_processing);
        result.violation.expect("a deny carries a violation")
    };

    assert_eq!(
        violation.code, "delegation.egress_denied",
        "a refusal by the host is not an unreachable IdP"
    );
    assert!(
        violation.reason.contains("circuit open"),
        "the host's reason must survive so an operator can act on it: {}",
        violation.reason
    );
    assert_eq!(
        http.call_count_for(TOKEN_PATH),
        1,
        "retrying into an open circuit is pointless and feeds the breaker"
    );
}
