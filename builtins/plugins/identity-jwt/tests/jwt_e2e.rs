// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for `JwtIdentityResolver` against a real RSA
// keypair + signed JWTs. Exercises the full handler path:
// `mgr.invoke_named::<IdentityHook>(...)` → resolver decodes /
// validates / maps claims → host extracts the populated
// `IdentityPayload` via `from_pipeline_result`.
//
// Scenarios:
//   * happy path: valid signed token resolves to a populated subject
//   * untrusted issuer (token signed correctly but `iss` not in config)
//   * expired token (`exp` in the past)
//   * audience mismatch
//   * signature tamper
//
// The keypair, minter, config builder and pipeline call live in `common`, which
// the claim-map suite shares.

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

mod common;

use common::{
    TEST_AUDIENCE, TEST_ISSUER, invoke, invoke_with_payload, mint_exact as mint_jwt, now_unix,
    plugin_config,
};
use std::collections::HashMap;

use praxis_policy_core::extensions::raw_credentials::{Credential, TokenKind, TokenRole};
use praxis_policy_core::identity::{IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;

use serde_json::json;

/// The config every scenario starts from: the test key, and the standard mapper
/// named explicitly so the default is not what is under test.
fn resolver_plugin_config() -> PluginConfig {
    plugin_config(json!({ "claim_mapper": "standard" }))
}

/// Role-aware variant of [`resolver_plugin_config`]. `role` and `header` are the
/// two knobs that decide which identity slot a resolver instance fills and where
/// it reads its token from, so a deployment expecting a user JWT *and* a workload
/// SVID wires two.
fn resolver_plugin_config_for(role: &str, header: &str) -> PluginConfig {
    plugin_config(json!({
        "claim_mapper": "standard",
        "role": role,
        "credential": { "kind": "header", "name": header },
    }))
}

async fn invoke_bearer(token: String) -> praxis_policy_core::executor::PipelineResult {
    invoke(resolver_plugin_config(), token, TokenSource::Bearer).await
}

/// A resolver reading its token from the given cookie name.
fn resolver_plugin_config_for_cookie(name: &str) -> PluginConfig {
    plugin_config(json!({
        "claim_mapper": "standard",
        "credential": { "kind": "cookie", "name": name },
    }))
}

/// A resolver reading its token from the given query parameter name.
fn resolver_plugin_config_for_query_param(name: &str) -> PluginConfig {
    plugin_config(json!({
        "claim_mapper": "standard",
        "credential": { "kind": "query_param", "name": name },
    }))
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path: valid signed token resolves to a populated subject,
/// raw token lands in `raw_credentials.inbound_tokens[User]`.
#[tokio::test]
async fn valid_jwt_resolves_subject() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
        "roles": ["hr", "reader"],
        "email": "alice@corp.com",
    }));

    let result = invoke_bearer(token.clone()).await;
    assert!(
        result.continue_processing,
        "valid token should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
    assert!(subject.roles.contains("hr"));
    assert!(subject.roles.contains("reader"));
    // `email` was not a reserved claim, lands under subject.claims
    assert_eq!(
        subject.claims.get("email"),
        Some(&serde_json::json!("alice@corp.com")),
    );

    // Raw token stashed for forwarding plugins.
    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let user_token = raw
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("user-role token present");
    assert_eq!(&*user_token.token, &token);
    assert!(matches!(user_token.kind, TokenKind::Jwt));
}

// ---------------------------------------------------------------------
// Cookie and query-parameter credential locations
// ---------------------------------------------------------------------

/// Same happy path as [`valid_jwt_resolves_subject`], but the token arrives
/// in a `Cookie` header instead of `Authorization`, through the real
/// pipeline (config → `PolicyEngine` → resolver → merged `IdentityPayload`).
#[tokio::test]
async fn valid_jwt_from_cookie_resolves_subject() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let mut headers = HashMap::new();
    headers.insert("cookie".to_owned(), format!("__Host-jwt={token}"));
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(
        result.continue_processing,
        "valid cookie-borne token should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
}

/// Same happy path, with the token arriving in the raw query string instead
/// of a header or cookie — the WebSocket/SSE case that cannot set headers.
#[tokio::test]
async fn valid_jwt_from_query_param_resolves_subject() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_raw_query_string(format!("access_token={token}"));

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(
        result.continue_processing,
        "valid query-param-borne token should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
}

/// The stashed `RawInboundToken` records where the credential actually came
/// from — a cookie, not the default `Authorization` header — so forwarding
/// plugins and audit logging see the true origin.
#[tokio::test]
async fn raw_inbound_token_records_cookie_origin() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let mut headers = HashMap::new();
    headers.insert("cookie".to_owned(), format!("__Host-jwt={token}"));
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(result.continue_processing, "{:?}", result.violation);

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let user_token = raw
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("user-role token present");
    assert_eq!(&*user_token.token, &token);
    assert_eq!(
        user_token.source,
        Credential::Cookie {
            name: "__Host-jwt".into()
        }
    );
}

/// Same as above, for the query-parameter location.
#[tokio::test]
async fn raw_inbound_token_records_query_param_origin() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_raw_query_string(format!("access_token={token}"));

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(result.continue_processing, "{:?}", result.violation);

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let user_token = raw
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("user-role token present");
    assert_eq!(&*user_token.token, &token);
    assert_eq!(
        user_token.source,
        Credential::QueryParam {
            name: "access_token".into()
        }
    );
}

// ---------------------------------------------------------------------
// Workload role — SPIFFE JWT-SVID ingress
// ---------------------------------------------------------------------

/// A resolver configured with `role: workload` is the ingress for the
/// caller's SPIFFE JWT-SVID. It must land the mapped identity in
/// `caller_workload` (the *calling agent*, distinct from the gateway's
/// own `this_workload`) and stash the raw bytes under
/// `TokenRole::CallerWorkload` — the slot a `delegate(...)` step reads from
/// when a route says `subject: workload` or `actor: workload`.
///
/// The stash is tagged `TokenKind::SpiffeJwt`, not the generic `Jwt`:
/// reaching this point means `map_workload` already accepted the
/// SPIFFE-shaped `sub`, so the wire format is known, and consumers
/// that branch on kind shouldn't have to re-parse the token to learn
/// what the resolver already established.
#[tokio::test]
async fn workload_svid_resolves_caller_workload_and_stashes_as_spiffe_jwt() {
    let svid = mint_jwt(json!({
        // SPIFFE JWT-SVID convention: the SPIFFE ID lives in `sub`.
        "sub": "spiffe://corp.example/ns/default/sa/payroll-agent",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke(
        resolver_plugin_config_for("workload", "X-Workload-Token"),
        svid.clone(),
        TokenSource::SpiffeJwtSvid,
    )
    .await;
    assert!(
        result.continue_processing,
        "valid SVID should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");

    // Lands in caller_workload — the inbound peer — not subject.
    let workload = identity
        .caller_workload
        .as_ref()
        .expect("caller_workload populated");
    assert_eq!(
        workload.spiffe_id.as_deref(),
        Some("spiffe://corp.example/ns/default/sa/payroll-agent"),
    );
    assert_eq!(workload.trust_domain.as_deref(), Some("corp.example"));
    assert!(
        identity.subject.is_none(),
        "a workload-role resolver must not populate the user slot",
    );

    // Stashed under the Workload role, tagged as a SPIFFE JWT-SVID,
    // and attributed to the header it arrived on.
    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let workload_token = raw
        .inbound_tokens
        .get(&TokenRole::CallerWorkload)
        .expect("workload-role token present");
    assert_eq!(&*workload_token.token, &svid);
    assert_eq!(
        workload_token.source,
        Credential::Header {
            name: "X-Workload-Token".into()
        }
    );
    assert!(
        matches!(workload_token.kind, TokenKind::SpiffeJwt),
        "workload SVID should be tagged SpiffeJwt, got {:?}",
        workload_token.kind,
    );
}

/// A `role: workload` resolver handed a perfectly valid *user* JWT
/// must refuse it rather than filing a non-SPIFFE identity into the
/// workload slot. Guards the boundary that makes `subject: workload`
/// meaningful: whatever is in that slot really is an attested
/// workload.
#[tokio::test]
async fn workload_role_rejects_a_non_spiffe_token() {
    let user_jwt = mint_jwt(json!({
        "sub": "alice@corp.com",  // no spiffe:// prefix
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke(
        resolver_plugin_config_for("workload", "X-Workload-Token"),
        user_jwt,
        TokenSource::SpiffeJwtSvid,
    )
    .await;

    assert!(
        !result.continue_processing,
        "a non-SPIFFE token must not resolve as a workload",
    );
    let violation = result.violation.expect("violation surfaced");
    assert_eq!(violation.code, "auth.mapping_failed");
}

/// The `spiffe_id` fallback must be prefix-checked too: a non-SPIFFE
/// `sub` combined with an arbitrary `spiffe_id` claim must NOT be
/// accepted as a workload. Without the guard on the fallback, this token
/// would be mislabeled `TokenKind::SpiffeJwt` and land in `caller_workload`.
#[tokio::test]
async fn workload_role_rejects_non_spiffe_sub_with_bogus_spiffe_id_claim() {
    let jwt = mint_jwt(json!({
        "sub": "alice@corp.com",          // not a SPIFFE ID
        "spiffe_id": "not-a-spiffe-id",   // arbitrary, non-SPIFFE fallback
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke(
        resolver_plugin_config_for("workload", "X-Workload-Token"),
        jwt,
        TokenSource::SpiffeJwtSvid,
    )
    .await;

    assert!(
        !result.continue_processing,
        "a non-SPIFFE sub must not be rescued by a bogus spiffe_id claim",
    );
    assert_eq!(
        result.violation.expect("violation surfaced").code,
        "auth.mapping_failed",
    );
}

/// The legit fallback still resolves: when `sub` isn't a SPIFFE ID but a
/// valid `spiffe://` lives in the `spiffe_id` claim, the workload is
/// accepted. Guards the fix from over-restricting.
#[tokio::test]
async fn workload_role_accepts_valid_spiffe_id_claim_fallback() {
    let jwt = mint_jwt(json!({
        "sub": "svc-account-123",                                 // not SPIFFE
        "spiffe_id": "spiffe://corp.example/ns/default/sa/agent", // valid SPIFFE fallback
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke(
        resolver_plugin_config_for("workload", "X-Workload-Token"),
        jwt,
        TokenSource::SpiffeJwtSvid,
    )
    .await;

    assert!(
        result.continue_processing,
        "a valid spiffe_id claim fallback must resolve the workload",
    );
}

/// Token correctly signed by the test key but its `iss` doesn't
/// match any trusted issuer in our config → `auth.untrusted_issuer`.
/// This is the path where the peek-at-iss step does its job.
#[tokio::test]
async fn untrusted_issuer_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        "iss": "https://hacker.example.com",  // not in trusted_issuers list
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));

    let result = invoke_bearer(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.untrusted_issuer");
}

/// `exp` claim is one hour in the past → `auth.token_expired`.
/// Leeway is 60s so a 1h-stale token is unambiguously rejected.
#[tokio::test]
async fn expired_token_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() - 3600,
    }));

    let result = invoke_bearer(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.token_expired");
}

/// `aud` doesn't match the configured audience → `auth.audience_mismatch`.
#[tokio::test]
async fn wrong_audience_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": "some-other-api",  // not the configured TEST_AUDIENCE
        "exp": now_unix() + 300,
    }));

    let result = invoke_bearer(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.audience_mismatch");
}

/// Tamper with the signature bytes → signature verification fails →
/// `auth.signature_invalid`. The load-bearing test for the security
/// story; if this passes, the cryptographic validation is wired
/// correctly through the whole pipeline.
#[tokio::test]
async fn tampered_signature_rejects() {
    let valid = mint_jwt(json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));
    // Flip a char in the middle of the signature segment. We
    // can't tamper with the *last* char because base64url
    // encoding of a 256-byte RSA-2048 signature requires its last
    // char to encode 4 trailing-bit zeros — only `{A, Q, g, w}`
    // satisfy that. A naive flip to an out-of-set char produces
    // invalid base64 (decoder error → `auth.malformed_header`)
    // rather than valid bytes that fail signature verification.
    // Middle-segment chars don't have the trailing-bit constraint.
    let parts: Vec<&str> = valid.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have three segments");
    let sig = parts[2];
    let mut sig_chars: Vec<char> = sig.chars().collect();
    let target_idx = sig_chars.len() / 2; // well into the middle
    let original = sig_chars[target_idx];
    // Pick a replacement that's different but in the same charset.
    let replacement = if original == 'A' { 'B' } else { 'A' };
    sig_chars[target_idx] = replacement;
    let new_sig: String = sig_chars.into_iter().collect();
    let tampered = format!("{}.{}.{}", parts[0], parts[1], new_sig);

    let result = invoke_bearer(tampered).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.signature_invalid");
}

/// Token with no `iss` claim at all → `auth.malformed_header` from
/// the peek step (we can't pick a trusted issuer without `iss`).
#[tokio::test]
async fn missing_iss_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        // no iss
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));

    let result = invoke_bearer(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.malformed_header");
}

// =====================================================================
// Header origin tracking
// =====================================================================

/// The default `Authorization` header path must record the credential
/// origin as `Credential::Header { name: "Authorization" }` on the
/// stashed raw token — the same provenance cookie and query-param
/// paths already assert.
#[tokio::test]
async fn raw_inbound_token_records_header_origin() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke_bearer(token.clone()).await;
    assert!(result.continue_processing, "{:?}", result.violation);

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let user_token = raw
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("user-role token present");
    assert_eq!(&*user_token.token, &token);
    assert_eq!(
        user_token.source,
        Credential::Header {
            name: "Authorization".into()
        }
    );
}

// =====================================================================
// Named header via the headers map (primary path, not raw_token fallback)
// =====================================================================

/// When a resolver is configured with a custom header name, the token
/// must be found in `payload.headers()["x-user-token"]` — the primary
/// extraction path. This exercises the header-map lookup directly rather
/// than the `raw_token()` fallback that `invoke()` would hit.
#[tokio::test]
async fn custom_header_extracts_from_headers_map() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let mut headers = HashMap::new();
    headers.insert("x-user-token".to_owned(), format!("Bearer {token}"));
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let cfg = plugin_config(json!({
        "claim_mapper": "standard",
        "credential": { "kind": "header", "name": "X-User-Token" },
    }));
    let result = invoke_with_payload(cfg, payload).await;
    assert!(
        result.continue_processing,
        "token in named header should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));

    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let user_token = raw
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("user-role token present");
    assert_eq!(
        user_token.source,
        Credential::Header {
            name: "X-User-Token".into()
        }
    );
}

// =====================================================================
// Cross-location mismatch
// =====================================================================

/// Config says `credential: cookie`, but the request has no `Cookie`
/// header at all — the token is only in `Authorization`. The resolver
/// must reject with `auth.missing_credential`, not fall through.
#[tokio::test]
async fn cookie_config_rejects_when_no_cookie_header_present() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    // Token in Authorization header only — no Cookie header.
    let mut headers = HashMap::new();
    headers.insert("authorization".to_owned(), format!("Bearer {token}"));
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(
        !result.continue_processing,
        "a cookie resolver must not read from Authorization",
    );
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.missing_credential");
}

/// Config says `credential: query_param`, but the host supplied no
/// query string. The resolver must reject with `auth.missing_credential`.
#[tokio::test]
async fn query_param_config_rejects_when_no_query_string_present() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    // Token only in Authorization — no query string set.
    let mut headers = HashMap::new();
    headers.insert("authorization".to_owned(), format!("Bearer {token}"));
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(
        !result.continue_processing,
        "a query-param resolver must not read from Authorization",
    );
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.missing_credential");
}

// =====================================================================
// Empty credential values
// =====================================================================

/// A cookie with an empty value (`__Host-jwt=`) is present-but-empty.
/// The resolver must reject with `auth.empty_credential`, which is
/// distinct from `auth.missing_credential` (name not found at all).
#[tokio::test]
async fn empty_cookie_value_rejects_with_empty_credential() {
    let mut headers = HashMap::new();
    headers.insert("cookie".to_owned(), "__Host-jwt=".to_owned());
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.empty_credential");
}

/// A query parameter with an empty value (`access_token=`) is
/// present-but-empty → `auth.empty_credential`.
#[tokio::test]
async fn empty_query_param_value_rejects_with_empty_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_raw_query_string("access_token=".to_owned());

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.empty_credential");
}

// =====================================================================
// Cookie / query-param parse failures through the full pipeline
// =====================================================================

/// A `Cookie` header with a duplicate name → `auth.ambiguous_credential`.
/// The unit tests in `http_credential.rs` cover the parser; this checks
/// the error-code mapping in `extract_token()` end-to-end.
#[tokio::test]
async fn duplicate_cookie_name_rejects_with_ambiguous_credential() {
    let mut headers = HashMap::new();
    headers.insert(
        "cookie".to_owned(),
        "__Host-jwt=token1; __Host-jwt=token2".to_owned(),
    );
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.ambiguous_credential");
}

/// A query string with a duplicate parameter name →
/// `auth.ambiguous_credential`.
#[tokio::test]
async fn duplicate_query_param_name_rejects_with_ambiguous_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_raw_query_string("access_token=a&access_token=b".to_owned());

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.ambiguous_credential");
}

/// A `Cookie` header containing a control character (header-smuggling
/// defense) → `auth.malformed_credential`.
#[tokio::test]
async fn cookie_with_control_char_rejects_with_malformed_credential() {
    let mut headers = HashMap::new();
    headers.insert(
        "cookie".to_owned(),
        "__Host-jwt=token\r\nInjected: header".to_owned(),
    );
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.malformed_credential");
}

/// A query string containing a control character →
/// `auth.malformed_credential`.
#[tokio::test]
async fn query_string_with_control_char_rejects_with_malformed_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_raw_query_string("access_token=tok\nen".to_owned());

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.malformed_credential");
}

/// Named cookie not found among the parsed cookies →
/// `auth.missing_credential` (different from no `Cookie` header at all,
/// which is the same code but a different reason string).
#[tokio::test]
async fn cookie_name_not_found_rejects_with_missing_credential() {
    let mut headers = HashMap::new();
    headers.insert("cookie".to_owned(), "other=value".to_owned());
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.missing_credential");
}

/// Named query parameter not found in the parsed query string →
/// `auth.missing_credential`.
#[tokio::test]
async fn query_param_name_not_found_rejects_with_missing_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_raw_query_string("other=value".to_owned());

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.missing_credential");
}

// =====================================================================
// Multi-value cookie / query-string selection
// =====================================================================

/// A real browser sends many cookies in one header. The resolver must
/// pick the configured name out of a multi-cookie header and ignore
/// the rest.
#[tokio::test]
async fn cookie_selected_from_multi_cookie_header() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let mut headers = HashMap::new();
    headers.insert(
        "cookie".to_owned(),
        format!("session=abc123; __Host-jwt={token}; theme=dark"),
    );
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);

    let result =
        invoke_with_payload(resolver_plugin_config_for_cookie("__Host-jwt"), payload).await;
    assert!(
        result.continue_processing,
        "the correct cookie should be selected from a multi-cookie header: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
}

/// A query string with multiple parameters. The resolver must pick the
/// configured name and ignore the rest.
#[tokio::test]
async fn query_param_selected_from_multi_param_query_string() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let payload = IdentityPayload::new("", TokenSource::Bearer)
        .with_raw_query_string(format!("page=2&access_token={token}&limit=50"));

    let result = invoke_with_payload(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
    )
    .await;
    assert!(
        result.continue_processing,
        "the correct param should be selected from a multi-param query string: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
}

// =====================================================================
// Client role — OAuth client-credential ingress
// =====================================================================

/// A resolver configured with `role: client` must land the mapped
/// identity in `client` (the OAuth client/application slot) and stash
/// the raw bytes under `TokenRole::Client`.
#[tokio::test]
async fn client_role_resolves_client_and_stashes_token() {
    let token = mint_jwt(json!({
        "sub": "gateway-app",
        "client_id": "gateway-app",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
        "scope": "read write",
    }));

    let result = invoke(
        resolver_plugin_config_for("client", "Authorization"),
        token.clone(),
        TokenSource::Bearer,
    )
    .await;
    assert!(
        result.continue_processing,
        "valid client token should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");

    let client = identity.client.as_ref().expect("client populated");
    assert_eq!(client.client_id, "gateway-app");
    assert!(
        identity.subject.is_none(),
        "a client-role resolver must not populate the user slot",
    );
    assert!(
        identity.caller_workload.is_none(),
        "a client-role resolver must not populate the workload slot",
    );

    let raw = identity
        .raw_credentials
        .as_ref()
        .expect("raw_credentials populated");
    let client_token = raw
        .inbound_tokens
        .get(&TokenRole::Client)
        .expect("client-role token present");
    assert_eq!(&*client_token.token, &token);
    assert_eq!(
        client_token.source,
        Credential::Header {
            name: "Authorization".into()
        }
    );
    assert!(
        matches!(client_token.kind, TokenKind::Jwt),
        "client token should be tagged Jwt, got {:?}",
        client_token.kind,
    );
}

/// A `role: client` resolver handed a token with no `client_id` (and
/// no `azp`) must reject — guards the boundary so whatever is in the
/// client slot really has a client identity.
#[tokio::test]
async fn client_role_rejects_token_without_client_id() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        // no client_id, no azp
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke(
        resolver_plugin_config_for("client", "Authorization"),
        token,
        TokenSource::Bearer,
    )
    .await;
    assert!(
        !result.continue_processing,
        "a token with no client_id must not resolve as a client",
    );
    let violation = result.violation.expect("violation surfaced");
    assert_eq!(violation.code, "auth.mapping_failed");
}
