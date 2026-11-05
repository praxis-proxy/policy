// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Verification with the FIPS provider as the OpenSSL default.

use std::collections::HashMap;
use std::sync::Arc;

use praxis_policy_builtins::plugins::identity_jwt::dpop::{
    InMemoryReplayGuard, access_token_hash, codes, jwk_thumbprint,
};
use praxis_policy_builtins::plugins::identity_jwt::{DecodingKeySource, JwtIdentityResolver};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::HttpExtension;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::HookHandler as _;
use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::http_testing::{FakeTransport, granting};
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::Plugin as _;
use serde_json::{Value, json};

use crate::oracle::{P256, audience, fixtures, issuer, now, text, token};
use crate::support::{Openssl, build, config, config_error, denial_code, isolated, resolve};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const JWKS_URL: &str = "https://idp.example/certs";
const URL: &str = "https://gateway.test/mcp";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn every_approved_algorithm_verifies_independently_signed_tokens() {
    isolated(
        "verify::every_approved_algorithm_verifies_independently_signed_tokens",
        Openssl::FipsDefault,
        || run(every_approved_algorithm()),
    );
}

#[test]
fn rfc_jws_examples_verify() {
    isolated(
        "verify::rfc_jws_examples_verify",
        Openssl::FipsDefault,
        rfc_examples,
    );
}

#[test]
fn rfc_7638_thumbprint_uses_the_fips_backend() {
    isolated(
        "verify::rfc_7638_thumbprint_uses_the_fips_backend",
        Openssl::FipsDefault,
        || {
            let jwk = json!({
                "kty": "RSA",
                "n": fixtures()["rfc"]["rs256_jwk"]["n"],
                "e": "AQAB",
            });
            assert_eq!(jwk_thumbprint(&jwk).unwrap().len(), 43, "base64url SHA-256");
            assert_eq!(
                access_token_hash("abc").unwrap(),
                "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
                "FIPS 180-2 SHA-256 of abc"
            );
        },
    );
}

#[test]
fn invalid_tokens_and_claims_are_denied() {
    isolated(
        "verify::invalid_tokens_and_claims_are_denied",
        Openssl::FipsDefault,
        || run(invalid_tokens()),
    );
}

#[test]
fn unapproved_keys_are_refused_at_load_and_on_jwks_refresh() {
    isolated(
        "verify::unapproved_keys_are_refused_at_load_and_on_jwks_refresh",
        Openssl::FipsDefault,
        || run(unapproved_keys()),
    );
}

#[test]
fn jwks_rotation_picks_up_a_new_key() {
    isolated(
        "verify::jwks_rotation_picks_up_a_new_key",
        Openssl::FipsDefault,
        || run(jwks_rotation()),
    );
}

#[test]
fn dpop_binding_and_replay_hold_under_fips() {
    isolated(
        "verify::dpop_binding_and_replay_hold_under_fips",
        Openssl::FipsDefault,
        || run(dpop_binding_and_replay()),
    );
}

#[test]
fn shared_secrets_and_hmac_algorithms_are_refused() {
    isolated(
        "verify::shared_secrets_and_hmac_algorithms_are_refused",
        Openssl::FipsDefault,
        hmac_refused,
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn run(future: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future);
}

async fn every_approved_algorithm() {
    for (alg, kid) in [
        ("RS256", "rsa-2048"),
        ("RS384", "rsa-2048"),
        ("RS512", "rsa-2048"),
        ("PS256", "rsa-2048"),
        ("PS384", "rsa-2048"),
        ("PS512", "rsa-2048"),
        ("ES256", "ec-P-256"),
        ("ES384", "ec-P-384"),
    ] {
        let resolver = jwks_resolver(&[alg]).await;
        let result = resolve(&resolver, token(alg)).await;
        assert_eq!(denial_code(&result), None, "{alg} ({kid}) must verify");
    }
}

fn rfc_examples() {
    build(config(
        issuer(),
        audience(),
        &["RS256"],
        json!({ "kind": "pem", "pem": text("rsa_public_pem") }),
    ))
    .expect("building a resolver installs the provider");
    let rfc = &fixtures()["rfc"];
    for (name, alg) in [("rs256", "RS256"), ("es256", "ES256"), ("ps384", "PS384")] {
        let source: DecodingKeySource = serde_json::from_value(json!({
            "kind": "jwk",
            "jwk": rfc[format!("{name}_jwk")],
        }))
        .unwrap();
        let store = source.build().unwrap_or_else(|e| panic!("{name} key: {e}"));
        let key = store.select(None).expect("an inline key is the fallback");
        let jws = rfc[format!("{name}_jws")].as_str().unwrap();
        let (input, signature) = jws.rsplit_once('.').unwrap();
        let algorithm: jsonwebtoken::Algorithm = alg.parse().unwrap();
        assert!(
            jsonwebtoken::crypto::verify(signature, input.as_bytes(), key, algorithm).unwrap(),
            "the published {alg} example must verify"
        );
        let mut tampered = input.to_owned();
        tampered.push('A');
        assert!(
            !jsonwebtoken::crypto::verify(signature, tampered.as_bytes(), key, algorithm).unwrap(),
            "a changed {alg} signing input must not verify"
        );
    }
}

async fn invalid_tokens() {
    let resolver = build(config(
        issuer(),
        audience(),
        &["ES256"],
        json!({ "kind": "pem", "pem": text("ec_p256_public_pem") }),
    ))
    .unwrap();
    assert_eq!(
        denial_code(&resolve(&resolver, token("ES256_no_kid")).await),
        None,
        "the control token verifies against the inline PEM"
    );
    for (name, code) in [
        ("ES256_bad_signature", "auth.signature_invalid"),
        ("ES256_expired", "auth.token_expired"),
        ("ES256_wrong_aud", "auth.audience_mismatch"),
    ] {
        assert_eq!(
            denial_code(&resolve(&resolver, token(name)).await).as_deref(),
            Some(code),
            "{name}"
        );
    }
    let rs_only = jwks_resolver(&["RS256"]).await;
    assert_eq!(
        denial_code(&resolve(&rs_only, token("PS256")).await).as_deref(),
        Some("auth.algorithm_mismatch"),
        "a PS256 token is refused by an RS256-only issuer"
    );
}

async fn unapproved_keys() {
    let n = fixtures()["jwks"]["keys"][0]["n"].clone();
    let rsa_with_e = |e: &str| json!({ "kind": "jwk", "jwk": { "kty": "RSA", "n": n, "e": e } });
    for e in [
        "Aw",
        "AQAC",
        "AQAA",
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    ] {
        let message = config_error(config(issuer(), audience(), &["RS256"], rsa_with_e(e)));
        assert!(
            message.contains("public exponent"),
            "e={e} (3, even, 2^16 or 2^256+1) must be refused: {message}"
        );
    }
    assert!(
        build(config(issuer(), audience(), &["RS256"], rsa_with_e("AQAB"))).is_ok(),
        "e=65537 is accepted"
    );
    for (key, needle) in [
        (
            json!({ "kind": "jwk", "jwk": fixtures()["rsa_1024_jwk"] }),
            "1024-bit",
        ),
        (
            json!({ "kind": "jwk", "jwk": fixtures()["ec_p521_jwk"] }),
            "P-256 or P-384",
        ),
        (
            json!({ "kind": "jwk", "jwk": fixtures()["ed25519_jwk"] }),
            "Ed25519",
        ),
        (
            json!({ "kind": "pem", "pem": text("ed25519_public_pem") }),
            "PEM",
        ),
    ] {
        let message = config_error(config(issuer(), audience(), &["RS256"], key.clone()));
        assert!(message.contains(needle), "{key}: {message}");
    }

    let mut keys = fixtures()["jwks"]["keys"].as_array().unwrap().clone();
    keys.push(fixtures()["rsa_1024_jwk"].clone());
    let resolver = jwks_resolver_with(&["RS256"], json!({ "keys": keys })).await;
    assert_eq!(
        denial_code(&resolve(&resolver, token("RS256")).await),
        None,
        "approved keys in the set still verify"
    );
    assert_eq!(
        denial_code(&resolve(&resolver, text("rsa_1024_token")).await).as_deref(),
        Some("auth.unknown_kid"),
        "a 1024-bit key in a JWKS is skipped, not indexed"
    );
}

async fn jwks_rotation() {
    let keys = fixtures()["jwks"]["keys"].as_array().unwrap();
    let p256 = keys.iter().find(|k| k["kid"] == "ec-P-256").unwrap();
    let p384 = keys.iter().find(|k| k["kid"] == "ec-P-384").unwrap();
    let http = Arc::new(
        FakeTransport::new()
            .json(JWKS_URL, 200, &json!({ "keys": [p256] }).to_string())
            .json(JWKS_URL, 200, &json!({ "keys": [p384] }).to_string()),
    );
    let settings = config(
        issuer(),
        audience(),
        &["ES256", "ES384"],
        json!({ "kind": "jwks_url", "url": JWKS_URL, "min_refresh_interval_secs": 0 }),
    );
    let cfg = crate::support::plugin_config(settings);
    let engine = Arc::new(PolicyEngine::default());
    engine
        .register_handler_for_names::<IdentityHook, _>(
            Arc::new(JwtIdentityResolver::new(cfg.clone()).unwrap()),
            cfg,
            &[HOOK_IDENTITY_RESOLVE],
        )
        .unwrap();
    let transport: Arc<dyn HttpTransport> = http.clone();
    engine.set_http_transport(transport);
    engine.initialize().await.unwrap();

    let send = |name: &'static str| {
        let engine = Arc::clone(&engine);
        async move {
            let payload = IdentityPayload::new(token(name), TokenSource::Bearer);
            let (result, _bg) = engine
                .invoke_named::<IdentityHook>(
                    HOOK_IDENTITY_RESOLVE,
                    payload,
                    Extensions::default(),
                    None,
                )
                .await;
            result.violation.map(|v| v.code)
        }
    };
    assert_eq!(send("ES256").await, None, "the initial key verifies");
    assert_eq!(
        send("ES384").await,
        None,
        "an unknown kid refreshes the JWKS and verifies with the rotated-in key"
    );
    assert_eq!(
        send("ES256").await.as_deref(),
        Some("auth.unknown_kid"),
        "the rotated-out key no longer verifies"
    );
    assert_eq!(
        http.call_count_for(JWKS_URL),
        3,
        "boot, rotation, and the rotated-out retry"
    );
}

async fn dpop_binding_and_replay() {
    let issuer_key = P256::from_scalar(0x31);
    let agent = P256::from_scalar(0x11);
    let other = P256::from_scalar(0x22);
    let mut settings = config(
        "https://idp.dpop",
        "dpop-api",
        &["ES256"],
        json!({ "kind": "jwk", "jwk": issuer_key.jwk }),
    );
    settings["trusted_issuers"][0]["dpop"] = json!({ "mode": "required" });
    let resolver = JwtIdentityResolver::with_replay_guard(
        crate::support::plugin_config(settings),
        Arc::new(InMemoryReplayGuard::default()),
    )
    .unwrap();
    let access = issuer_key.sign(
        &json!({ "alg": "ES256", "typ": "JWT" }),
        &json!({
            "iss": "https://idp.dpop",
            "aud": "dpop-api",
            "sub": "agent-1",
            "exp": now() + 300,
            "cnf": { "jkt": jwk_thumbprint(&agent.jwk).unwrap() },
        }),
    );
    let proof = |signer: &P256, jti: &str| {
        signer.sign(
            &json!({ "alg": "ES256", "typ": "dpop+jwt", "jwk": signer.jwk }),
            &json!({
                "htm": "POST",
                "htu": URL,
                "iat": now(),
                "jti": jti,
                "ath": access_token_hash(&access).unwrap(),
            }),
        )
    };

    let first = proof(&agent, "jti-1");
    assert_eq!(
        dpop(&resolver, &access, &first).await,
        None,
        "a bound proof verifies"
    );
    assert_eq!(
        dpop(&resolver, &access, &first).await.as_deref(),
        Some(codes::DPOP_REPLAY),
        "a replayed proof is refused"
    );
    assert_eq!(
        dpop(&resolver, &access, &proof(&other, "jti-2"))
            .await
            .as_deref(),
        Some(codes::DPOP_KEY_MISMATCH),
        "a proof from another key is refused"
    );
    dpop_with_a_weak_rsa_key(&issuer_key).await;
}

fn hmac_refused() {
    for alg in ["HS256", "HS384", "HS512"] {
        let message = config_error(config(
            issuer(),
            audience(),
            &[alg],
            json!({ "kind": "pem", "pem": text("rsa_public_pem") }),
        ));
        assert!(
            message.contains("jwt-openssl-fips") && message.contains(alg),
            "{alg}: {message}"
        );
    }
    let message = config_error(config(
        issuer(),
        audience(),
        &["RS256"],
        json!({ "kind": "secret", "secret": "shared" }),
    ));
    assert!(
        message.contains("secret") && message.contains("jwt-openssl-fips"),
        "{message}"
    );
    for dpop in [
        json!({ "mode": "optional", "algorithms": ["EdDSA"] }),
        json!({ "mode": "off", "algorithms": ["HS256"] }),
    ] {
        let mut settings = config(
            issuer(),
            audience(),
            &["RS256"],
            json!({ "kind": "pem", "pem": text("rsa_public_pem") }),
        );
        settings["trusted_issuers"][0]["dpop"] = dpop.clone();
        let message = config_error(settings);
        assert!(message.contains("dpop.algorithms"), "{dpop}: {message}");
    }
}

async fn dpop_with_a_weak_rsa_key(issuer_key: &P256) {
    let weak = fixtures()["rsa_e3_jwk"].clone();
    let mut settings = config(
        "https://idp.dpop",
        "dpop-api",
        &["ES256"],
        json!({ "kind": "jwk", "jwk": issuer_key.jwk }),
    );
    settings["trusted_issuers"][0]["dpop"] = json!({ "mode": "required", "algorithms": ["RS256"] });
    let resolver = build(settings).unwrap();
    let public = json!({ "kty": "RSA", "n": weak["n"], "e": weak["e"] });
    let access = issuer_key.sign(
        &json!({ "alg": "ES256", "typ": "JWT" }),
        &json!({
            "iss": "https://idp.dpop",
            "aud": "dpop-api",
            "sub": "agent-1",
            "exp": now() + 300,
            "cnf": { "jkt": jwk_thumbprint(&public).unwrap() },
        }),
    );
    let proof = crate::oracle::rs256(
        text("rsa_e3_private_pem"),
        &json!({ "alg": "RS256", "typ": "dpop+jwt", "jwk": public }),
        &json!({
            "htm": "POST",
            "htu": URL,
            "iat": now(),
            "jti": "weak-1",
            "ath": access_token_hash(&access).unwrap(),
        }),
    );
    assert_eq!(
        dpop(&resolver, &access, &proof).await.as_deref(),
        Some(codes::DPOP_INVALID),
        "a validly signed proof with an e=3 key is refused"
    );
}

async fn dpop(resolver: &JwtIdentityResolver, access: &str, proof: &str) -> Option<String> {
    let headers = HashMap::from([
        ("authorization".to_owned(), format!("DPoP {access}")),
        ("dpop".to_owned(), proof.to_owned()),
    ]);
    let payload = IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers);
    let ext = Extensions {
        http: Some(Arc::new(HttpExtension {
            method: Some("POST".to_owned()),
            scheme: Some("https".to_owned()),
            host: Some("gateway.test".to_owned()),
            path: Some("/mcp".to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let result = resolver
        .handle(&payload, &ext, &mut PluginContext::new())
        .await;
    denial_code(&result)
}

async fn jwks_resolver(algorithms: &[&str]) -> JwtIdentityResolver {
    jwks_resolver_with(algorithms, fixtures()["jwks"].clone()).await
}

async fn jwks_resolver_with(algorithms: &[&str], jwks: Value) -> JwtIdentityResolver {
    let http = Arc::new(FakeTransport::new().json(JWKS_URL, 200, &jwks.to_string()));
    jwks_resolver_on(algorithms, &http, 600).await
}

async fn jwks_resolver_on(
    algorithms: &[&str],
    http: &Arc<FakeTransport>,
    min_refresh_interval_secs: u64,
) -> JwtIdentityResolver {
    let resolver = build(config(
        issuer(),
        audience(),
        algorithms,
        json!({
            "kind": "jwks_url",
            "url": JWKS_URL,
            "min_refresh_interval_secs": min_refresh_interval_secs,
        }),
    ))
    .unwrap();
    resolver
        .initialize_with(&granting(Arc::clone(http)))
        .await
        .unwrap();
    resolver
}
