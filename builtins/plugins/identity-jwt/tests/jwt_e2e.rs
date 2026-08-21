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

use common::{TEST_AUDIENCE, TEST_ISSUER, invoke, mint_exact as mint_jwt, now_unix, plugin_config};

use praxis_policy_core::extensions::raw_credentials::{TokenKind, TokenRole};
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
        "header": header,
    }))
}

async fn invoke_bearer(token: String) -> praxis_policy_core::executor::PipelineResult {
    invoke(resolver_plugin_config(), token, TokenSource::Bearer).await
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
    assert_eq!(workload_token.source_header, "X-Workload-Token");
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
