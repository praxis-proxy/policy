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

use crate::common;

use common::{
    TEST_AUDIENCE, TEST_ISSUER, extensions_with_query, invoke, invoke_with_payload,
    invoke_with_payload_and_ext, mint_exact as mint_jwt, now_unix, plugin_config,
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

async fn invoke_workload(token: String) -> praxis_policy_core::executor::PipelineResult {
    let payload = IdentityPayload::new(token, TokenSource::SpiffeJwtSvid)
        .with_source_header("X-Workload-Token");
    invoke_with_payload(
        resolver_plugin_config_for("workload", "X-Workload-Token"),
        payload,
    )
    .await
}

fn resolver_plugin_config_for_cookie(name: &str) -> PluginConfig {
    plugin_config(json!({
        "claim_mapper": "standard",
        "credential": { "kind": "cookie", "name": name },
    }))
}

fn resolver_plugin_config_for_query_param(name: &str) -> PluginConfig {
    let mut cfg = plugin_config(json!({
        "claim_mapper": "standard",
        "credential": { "kind": "query_param", "name": name },
    }));
    cfg.capabilities.insert("read_query".to_owned());
    cfg
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    assert_eq!(
        subject.claims.get("email"),
        Some(&serde_json::json!("alice@corp.com")),
    );

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

#[tokio::test]
async fn valid_jwt_from_query_param_resolves_subject() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let payload = IdentityPayload::new("", TokenSource::Bearer);
    let ext = extensions_with_query(Some(format!("access_token={token}")));

    let result = invoke_with_payload_and_ext(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
        ext,
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

#[tokio::test]
async fn raw_inbound_token_records_query_param_origin() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let payload = IdentityPayload::new("", TokenSource::Bearer);
    let ext = extensions_with_query(Some(format!("access_token={token}")));

    let result = invoke_with_payload_and_ext(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
        ext,
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

#[tokio::test]
async fn workload_svid_resolves_caller_workload_and_stashes_as_spiffe_jwt() {
    let svid = mint_jwt(json!({
        "sub": "spiffe://corp.example/ns/default/sa/payroll-agent",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke_workload(svid.clone()).await;
    assert!(
        result.continue_processing,
        "valid SVID should resolve: violation = {:?}",
        result.violation,
    );

    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("payload should be present");

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

#[tokio::test]
async fn workload_role_rejects_a_non_spiffe_token() {
    let user_jwt = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke_workload(user_jwt).await;

    assert!(
        !result.continue_processing,
        "a non-SPIFFE token must not resolve as a workload",
    );
    let violation = result.violation.expect("violation surfaced");
    assert_eq!(violation.code, "auth.mapping_failed");
}

#[tokio::test]
async fn workload_role_rejects_non_spiffe_sub_with_bogus_spiffe_id_claim() {
    let jwt = mint_jwt(json!({
        "sub": "alice@corp.com",
        "spiffe_id": "not-a-spiffe-id",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke_workload(jwt).await;

    assert!(
        !result.continue_processing,
        "a non-SPIFFE sub must not be rescued by a bogus spiffe_id claim",
    );
    assert_eq!(
        result.violation.expect("violation surfaced").code,
        "auth.mapping_failed",
    );
}

#[tokio::test]
async fn workload_role_accepts_valid_spiffe_id_claim_fallback() {
    let jwt = mint_jwt(json!({
        "sub": "svc-account-123",
        "spiffe_id": "spiffe://corp.example/ns/default/sa/agent",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let result = invoke_workload(jwt).await;

    assert!(
        result.continue_processing,
        "a valid spiffe_id claim fallback must resolve the workload",
    );
}

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

#[tokio::test]
async fn tampered_signature_rejects() {
    let valid = mint_jwt(json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));
    let parts: Vec<&str> = valid.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have three segments");
    let sig = parts[2];
    let mut sig_chars: Vec<char> = sig.chars().collect();
    let target_idx = sig_chars.len() / 2; // well into the middle
    let original = sig_chars[target_idx];
    let replacement = if original == 'A' { 'B' } else { 'A' };
    sig_chars[target_idx] = replacement;
    let new_sig: String = sig_chars.into_iter().collect();
    let tampered = format!("{}.{}.{}", parts[0], parts[1], new_sig);

    let result = invoke_bearer(tampered).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.signature_invalid");
}

#[tokio::test]
async fn missing_iss_rejects() {
    let token = mint_jwt(json!({
        "sub": "alice",
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
    }));

    let result = invoke_bearer(token).await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("rejection should surface");
    assert_eq!(v.code, "auth.malformed_credential");
}

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

#[tokio::test]
async fn legacy_header_config_resolves_named_header() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));
    let headers = HashMap::from([("x-user-token".to_owned(), format!("Bearer {token}"))]);
    let payload = IdentityPayload::new("", TokenSource::Bearer).with_headers(headers);
    let config = plugin_config(json!({ "header": "X-User-Token" }));

    let result = invoke_with_payload(config, payload).await;
    assert!(
        result.continue_processing,
        "legacy header config denied: {:?}",
        result.violation
    );
    let identity = IdentityPayload::from_pipeline_result(&result).expect("resolved identity");
    assert_eq!(
        identity
            .subject
            .as_ref()
            .and_then(|subject| subject.id.as_deref()),
        Some("alice@corp.com")
    );
    assert_eq!(
        identity
            .raw_credentials
            .as_ref()
            .and_then(|raw| raw.inbound_tokens.get(&TokenRole::User))
            .map(|raw| &raw.source),
        Some(&Credential::Header {
            name: "X-User-Token".to_owned()
        })
    );
}

#[tokio::test]
async fn cookie_config_rejects_when_no_cookie_header_present() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

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

#[tokio::test]
async fn query_param_config_rejects_when_no_query_string_present() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

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

#[tokio::test]
async fn empty_query_param_value_rejects_with_empty_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer);
    let ext = extensions_with_query(Some("access_token=".to_owned()));

    let result = invoke_with_payload_and_ext(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
        ext,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.empty_credential");
}

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

#[tokio::test]
async fn duplicate_query_param_name_rejects_with_ambiguous_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer);
    let ext = extensions_with_query(Some("access_token=a&access_token=b".to_owned()));

    let result = invoke_with_payload_and_ext(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
        ext,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.ambiguous_credential");
}

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

#[tokio::test]
async fn query_string_with_control_char_rejects_with_malformed_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer);
    let ext = extensions_with_query(Some("access_token=tok\nen".to_owned()));

    let result = invoke_with_payload_and_ext(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
        ext,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.malformed_credential");
}

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

#[tokio::test]
async fn query_param_name_not_found_rejects_with_missing_credential() {
    let payload = IdentityPayload::new("", TokenSource::Bearer);
    let ext = extensions_with_query(Some("other=value".to_owned()));

    let result = invoke_with_payload_and_ext(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
        ext,
    )
    .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation surfaced");
    assert_eq!(v.code, "auth.missing_credential");
}

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

#[tokio::test]
async fn query_param_selected_from_multi_param_query_string() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    }));

    let payload = IdentityPayload::new("", TokenSource::Bearer);
    let ext = extensions_with_query(Some(format!("page=2&access_token={token}&limit=50")));

    let result = invoke_with_payload_and_ext(
        resolver_plugin_config_for_query_param("access_token"),
        payload,
        ext,
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

#[tokio::test]
async fn client_role_rejects_token_without_client_id() {
    let token = mint_jwt(json!({
        "sub": "alice@corp.com",
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
