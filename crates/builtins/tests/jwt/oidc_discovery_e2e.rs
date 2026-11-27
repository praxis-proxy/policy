// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for `decoding_key.kind: oidc_discovery` through the policy
// engine, against a scripted IdP: discovery at boot and on the request path,
// recovery from outages, a moved key set, algorithm narrowing, refresh-storm
// bounds, bounded latency against a stalled IdP, and what a config reload
// leaves behind.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use praxis_policy_builtins::plugins::identity_jwt::{
    JwtIdentityFactory, JwtIdentityResolver, KIND,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::http::{HttpResponse, HttpTransport, HttpTransportError};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use serde_json::{Value, json};

use crate::common::{TEST_AUDIENCE, keypair, now_unix};

const ISSUER: &str = "https://idp.example.test/realms/apps";
const WELL_KNOWN: &str = "/realms/apps/.well-known/openid-configuration";
const CERTS: &str = "/realms/apps/protocol/openid-connect/certs";
const CERTS_V2: &str = "/realms/apps/keys-v2";
const KID: &str = "realm-rs256";

#[tokio::test]
async fn boot_discovers_and_a_valid_token_is_allowed_with_mapped_claims() {
    let http = idp(&doc(CERTS, &["RS256"]), &jwks(&[KID]));
    let engine = engine(discovery_config(false, json!({})), &http, true).await;
    assert_eq!(
        http.call_count(),
        2,
        "boot is one document fetch and one JWKS fetch"
    );
    assert_eq!(http.call_count_for(WELL_KNOWN), 1);
    assert_eq!(http.call_count_for(CERTS), 1);

    let result = call(
        &engine,
        &token(KID, json!({ "realm_access": { "roles": ["hr"] } })),
    )
    .await;

    assert!(result.continue_processing, "{:?}", result.violation);
    let identity = IdentityPayload::from_pipeline_result(&result).expect("identity");
    let subject = identity.subject.expect("subject");
    assert_eq!(subject.id.as_deref(), Some("alice"));
    assert!(
        subject.roles.contains("hr"),
        "the keycloak preset maps realm roles"
    );
    call(&engine, &token(KID, json!({}))).await;
    assert_eq!(http.call_count(), 2, "fresh tokens cost no request");
}

/// Keycloak's default `id_token_signing_alg_values_supported`, verbatim.
const KEYCLOAK_ALGORITHMS: &[&str] = &[
    "PS384", "RS384", "EdDSA", "ES384", "HS256", "HS512", "ES256", "RS256", "HS384", "ES512",
    "PS256", "PS512", "RS512",
];

#[tokio::test]
async fn an_advertised_set_spanning_key_families_allows_each_family() {
    let mut keys: Value = serde_json::from_str(&jwks(&[KID])).unwrap();
    keys["keys"].as_array_mut().unwrap().push(ec_jwk(EC_KID));
    let http = idp(&doc(CERTS, KEYCLOAK_ALGORITHMS), &keys.to_string());
    let engine = engine(discovery_config(false, json!({})), &http, true).await;

    let ps256 = {
        let mut header = Header::new(Algorithm::PS256);
        header.kid = Some(KID.to_owned());
        let key = EncodingKey::from_rsa_pem(keypair().private_pem.as_bytes()).unwrap();
        encode(&header, &claims(json!({})), &key).unwrap()
    };
    for (label, token) in [
        ("RS256", token(KID, json!({}))),
        ("PS256", ps256),
        ("ES256", ec_token(EC_KID)),
    ] {
        let result = call(&engine, &token).await;
        assert!(
            result.continue_processing,
            "{label} is advertised and its key is published: {:?}",
            result.violation
        );
    }
}

#[tokio::test]
async fn a_token_naming_a_key_of_another_family_is_refused() {
    let mut keys: Value = serde_json::from_str(&jwks(&[KID])).unwrap();
    keys["keys"].as_array_mut().unwrap().push(ec_jwk(EC_KID));
    let http = idp(&doc(CERTS, &["RS256", "ES256"]), &keys.to_string());
    let engine = engine(discovery_config(false, json!({})), &http, true).await;

    // ES256-signed, but pointing at the RSA key.
    let result = call(&engine, &ec_token(KID)).await;

    assert_eq!(denial(&result), "auth.algorithm_mismatch");
}

#[tokio::test]
async fn the_first_token_after_a_failed_boot_is_allowed_without_waiting_for_the_floor() {
    let up = Arc::new(AtomicBool::new(false));
    let http = switchable_idp(&up, &doc(CERTS, &["RS256"]));
    // Default 30 s floor.
    let engine = engine(discovery_config(false, json!({})), &http, true).await;
    let boot_calls = http.call_count_for(WELL_KNOWN);

    up.store(true, Ordering::SeqCst);
    let result = call(&engine, &token(KID, json!({}))).await;

    assert!(result.continue_processing, "{:?}", result.violation);
    assert_eq!(
        http.call_count_for(WELL_KNOWN) - boot_calls,
        1,
        "the first token rediscovered at once"
    );
}

#[tokio::test]
async fn engines_built_and_dropped_leave_nothing_behind() {
    let http = idp(&doc(CERTS, &["RS256"]), &jwks(&[KID]));
    let baseline = Arc::strong_count(&http);
    let mut engines = Vec::new();

    for _ in 0..30 {
        let engine = yaml_engine(&http);
        engine
            .load_config_yaml(&yaml_for(ISSUER))
            .expect("the config loads");
        engine.initialize().await.expect("initialize");
        assert!(
            call(&engine, &token(KID, json!({})))
                .await
                .continue_processing
        );
        engine.shutdown().await;
        engines.push(Arc::downgrade(&engine));
    }
    let calls = http.call_count();
    tokio::task::yield_now().await;

    assert!(
        engines.iter().all(|engine| engine.upgrade().is_none()),
        "every dropped engine is freed"
    );
    assert_eq!(
        Arc::strong_count(&http),
        baseline,
        "no plugin instance holds on to the transport"
    );
    assert_eq!(http.call_count(), calls, "nothing fetches after the drop");
    assert_eq!(calls, 60, "one document and one JWKS per engine");
}

#[tokio::test]
async fn a_discovered_and_a_static_issuer_coexist() {
    let http = idp(&doc(CERTS, &["RS256"]), &jwks(&[KID]));
    let mut cfg = discovery_config(false, json!({}));
    cfg.config.as_mut().unwrap()["trusted_issuers"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "issuer": "spiffe://example.org/static",
            "audiences": [TEST_AUDIENCE],
            // Two key families: the token's algorithm is checked against the
            // list, not the whole list against the key.
            "algorithms": ["RS256", "ES256"],
            "decoding_key": { "kind": "pem", "pem": keypair().public_pem },
        }));
    let engine = engine(cfg, &http, true).await;

    let discovered = call(&engine, &token(KID, json!({}))).await;
    let fixed = call(
        &engine,
        &mint(None, json!({ "iss": "spiffe://example.org/static" })),
    )
    .await;

    assert!(discovered.continue_processing, "{:?}", discovered.violation);
    assert!(fixed.continue_processing, "{:?}", fixed.violation);
}

#[tokio::test]
async fn an_issuer_mismatch_boots_denies_and_never_fetches_the_jwks() {
    let wrong =
        json!({ "issuer": "https://keycloak.internal/realms/apps", "jwks_uri": url(CERTS) });
    let http = idp(&wrong.to_string(), &jwks(&[KID]));
    let engine = engine(discovery_config(false, json!({})), &http, true).await;

    let result = call(&engine, &token(KID, json!({}))).await;

    assert_eq!(denial(&result), "auth.jwks_unavailable");
    assert_eq!(
        http.call_count_for(CERTS),
        0,
        "an unverified document names no keys"
    );
}

#[tokio::test]
async fn a_redirect_at_boot_is_not_followed_and_soft_fails() {
    let mut location = praxis_policy_core::http::HeaderMap::new();
    location.insert("location", url(CERTS).parse().unwrap());
    let http = Arc::new(FakeTransport::new().respond(WELL_KNOWN, 302, "", location));
    let engine = engine(discovery_config(false, json!({})), &http, true).await;

    assert_eq!(
        http.call_count(),
        1,
        "one request, no follow-up to the Location"
    );
    assert_eq!(
        denial(&call(&engine, &token(KID, json!({}))).await),
        "auth.jwks_unavailable"
    );
}

#[tokio::test]
async fn symmetric_and_unsigned_tokens_are_never_accepted() {
    let secret = b"a-shared-secret-in-the-jwks";
    let mut keys: Value = serde_json::from_str(&jwks(&[KID])).unwrap();
    keys["keys"].as_array_mut().unwrap().push(json!({
        "kty": "oct", "kid": "shared", "alg": "HS256",
        "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
    }));
    let http = idp(&doc(CERTS, &["HS256", "RS256", "none"]), &keys.to_string());
    let engine = engine(discovery_config(false, json!({})), &http, true).await;

    let hs256 = |kid: &str| {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_owned());
        encode(
            &header,
            &claims(json!({})),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    };
    let unsigned = {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.",
            b64.encode(json!({ "alg": "none", "kid": KID }).to_string()),
            b64.encode(claims(json!({})).to_string())
        )
    };

    for (label, token, expected) in [
        (
            "HS256 under the oct kid",
            hs256("shared"),
            "auth.unknown_kid",
        ),
        (
            "HS256 under the RSA kid",
            hs256(KID),
            "auth.algorithm_mismatch",
        ),
        ("alg none", unsigned, "auth.malformed_credential"),
    ] {
        assert_eq!(denial(&call(&engine, &token).await), expected, "{label}");
    }
    assert!(
        call(&engine, &token(KID, json!({})))
            .await
            .continue_processing,
        "the RS256 control still passes"
    );
}

#[tokio::test]
async fn configured_algorithms_narrow_the_advertised_ones() {
    let http = idp(&doc(CERTS, &["RS256", "ES256"]), &jwks(&[KID]));
    let cfg = discovery_config(false, json!({ "algorithms": ["ES256"] }));
    let engine = engine(cfg, &http, true).await;

    let result = call(&engine, &token(KID, json!({}))).await;

    assert_eq!(
        denial(&result),
        "auth.algorithm_mismatch",
        "RS256 was narrowed away"
    );
}

#[tokio::test]
async fn a_moved_key_set_is_followed_after_the_ttl() {
    let http = Arc::new(
        FakeTransport::new()
            .json(WELL_KNOWN, 200, &doc(CERTS, &["RS256"]))
            .json(WELL_KNOWN, 200, &doc(CERTS_V2, &["RS256"]))
            .json(CERTS, 200, &jwks(&[KID]))
            .json(CERTS_V2, 200, &jwks(&["realm-rs256-v2"])),
    );
    let engine = engine(discovery_config(true, json!({})), &http, true).await;
    assert_eq!(
        denial(&call(&engine, &token("realm-rs256-v2", json!({}))).await),
        "auth.unknown_kid"
    );

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let result = call(&engine, &token("realm-rs256-v2", json!({}))).await;

    assert!(result.continue_processing, "{:?}", result.violation);
    let old_url_calls = http.call_count_for(CERTS);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    call(&engine, &token("realm-rs256-v2", json!({}))).await;
    assert_eq!(
        http.call_count_for(CERTS),
        old_url_calls,
        "the old URL is never contacted again"
    );
}

#[tokio::test]
async fn discovery_down_during_refresh_keeps_verifying_with_the_held_keys() {
    let up = Arc::new(AtomicBool::new(true));
    let http = switchable_idp(&up, &doc(CERTS, &["RS256"]));
    let engine = engine(discovery_config(true, json!({})), &http, true).await;

    up.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let result = call(&engine, &token(KID, json!({}))).await;

    assert!(result.continue_processing, "{:?}", result.violation);
    assert_eq!(
        http.call_count_for(CERTS),
        2,
        "the JWKS hop still ran against the last good URL"
    );
}

#[tokio::test]
async fn discovery_down_at_start_recovers_without_a_restart() {
    let up = Arc::new(AtomicBool::new(false));
    let http = switchable_idp(&up, &doc(CERTS, &["RS256"]));
    let engine = engine(discovery_config(true, json!({})), &http, true).await;
    assert_eq!(
        denial(&call(&engine, &token(KID, json!({}))).await),
        "auth.jwks_unavailable"
    );

    up.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let result = call(&engine, &token(KID, json!({}))).await;

    assert!(result.continue_processing, "{:?}", result.violation);
}

#[tokio::test]
async fn a_rotated_key_is_fetched_on_its_first_token() {
    let http = Arc::new(
        FakeTransport::new()
            .json(WELL_KNOWN, 200, &doc(CERTS, &["RS256"]))
            .json(CERTS, 200, &jwks(&[KID]))
            .json(CERTS, 200, &jwks(&[KID, "rotated"])),
    );
    let engine = engine(discovery_config(true, json!({})), &http, true).await;

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let result = call(&engine, &token("rotated", json!({}))).await;

    assert!(result.continue_processing, "{:?}", result.violation);
}

#[tokio::test]
async fn an_unknown_kid_storm_costs_at_most_one_fetch_of_each() {
    let http = idp(&doc(CERTS, &["RS256"]), &jwks(&[KID]));
    let engine = engine(discovery_config(false, json!({})), &http, false).await;

    for i in 0..100 {
        let result = call(&engine, &token(&format!("invented-{i}"), json!({}))).await;
        assert_eq!(denial(&result), "auth.unknown_kid");
    }

    assert!(
        http.call_count_for(WELL_KNOWN) <= 1,
        "{} discovery GETs",
        http.call_count_for(WELL_KNOWN)
    );
    assert!(
        http.call_count_for(CERTS) <= 1,
        "{} JWKS GETs",
        http.call_count_for(CERTS)
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_idp_on_the_request_path_costs_a_bounded_wait() {
    let http = Arc::new(
        FakeTransport::new()
            .json(WELL_KNOWN, 200, &doc(CERTS, &["RS256"]))
            .json(CERTS, 200, &jwks(&[KID]))
            .with_latency(Duration::from_secs(60)),
    );
    let engine = engine(discovery_config(false, json!({})), &http, false).await;
    let valid = token(KID, json!({}));
    let started = tokio::time::Instant::now();

    let results =
        futures::future::join_all(std::iter::repeat_with(|| call(&engine, &valid)).take(3)).await;

    let elapsed = started.elapsed();
    assert!(elapsed <= Duration::from_millis(4_500), "took {elapsed:?}");
    for result in &results {
        assert_eq!(denial(result), "auth.jwks_unavailable");
    }
}

#[tokio::test(start_paused = true)]
async fn a_stalled_idp_at_boot_soft_fails_within_the_startup_budget() {
    let http = Arc::new(
        FakeTransport::new()
            .json(WELL_KNOWN, 200, &doc(CERTS, &["RS256"]))
            .json(CERTS, 200, &jwks(&[KID]))
            .with_latency(Duration::from_secs(60)),
    );
    let started = tokio::time::Instant::now();

    let engine = engine(discovery_config(false, json!({})), &http, true).await;

    let elapsed = started.elapsed();
    assert!(
        elapsed <= Duration::from_secs(12),
        "boot is two 5 s hops at most, took {elapsed:?}"
    );
    assert_eq!(
        denial(&call(&engine, &token(KID, json!({}))).await),
        "auth.jwks_unavailable"
    );
}

#[tokio::test]
async fn a_config_loaded_after_initialize_discovers_on_the_first_token() {
    let http = idp(&doc(CERTS, &["RS256"]), &jwks(&[KID]));
    let engine = yaml_engine(&http);
    engine
        .initialize()
        .await
        .expect("an empty engine initializes");

    engine
        .load_config_yaml(&yaml_for(ISSUER))
        .expect("a config loads after initialize");
    assert_eq!(http.call_count(), 0, "nothing initializes the new instance");
    let result = call(&engine, &token(KID, json!({}))).await;

    assert!(result.continue_processing, "{:?}", result.violation);
    assert_eq!(
        http.call_count(),
        2,
        "discovered lazily: document, then JWKS"
    );
}

#[tokio::test]
async fn a_reload_serves_the_new_issuer_and_leaves_the_old_idp_alone() {
    let b_issuer = "https://idp-b.example.test/realms/b";
    let b_doc = json!({
        "issuer": b_issuer,
        "jwks_uri": "https://idp-b.example.test/realms/b/certs",
        "id_token_signing_alg_values_supported": ["RS256"],
    });
    let http = Arc::new(
        FakeTransport::new()
            .json(WELL_KNOWN, 200, &doc(CERTS, &["RS256"]))
            .json(CERTS, 200, &jwks(&[KID]))
            .json(
                "idp-b.example.test/realms/b/.well-known",
                200,
                &b_doc.to_string(),
            )
            .json("idp-b.example.test/realms/b/certs", 200, &jwks(&[KID])),
    );
    let old = yaml_engine(&http);
    old.load_config_yaml(&yaml_for(ISSUER))
        .expect("config A loads");
    old.initialize().await.expect("initialize A");
    assert!(call(&old, &token(KID, json!({}))).await.continue_processing);
    let a_calls = http.call_count_for("idp.example.test");

    let new = yaml_engine(&http);
    new.load_config_yaml(&yaml_for(b_issuer))
        .expect("config B loads");
    new.initialize().await.expect("initialize B");
    old.shutdown().await;
    drop(old);
    let b_token = mint(Some(KID), json!({ "iss": b_issuer }));
    let mut outcomes = Vec::new();
    for _ in 0..10 {
        outcomes.push((
            call(&new, &b_token).await,
            call(&new, &token(KID, json!({}))).await,
        ));
    }

    for (b, a) in &outcomes {
        assert!(b.continue_processing, "B is served: {:?}", b.violation);
        assert_eq!(denial(a), "auth.untrusted_issuer", "A is gone");
    }
    assert_eq!(
        http.call_count_for("idp.example.test"),
        a_calls,
        "IdP A gets nothing after the reload"
    );
    assert_eq!(
        http.call_count_for("idp-b.example.test"),
        2,
        "B's discovery and JWKS"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn url(path: &str) -> String {
    format!("https://idp.example.test{path}")
}

fn doc(jwks_path: &str, algorithms: &[&str]) -> String {
    json!({
        "issuer": ISSUER,
        "jwks_uri": url(jwks_path),
        "id_token_signing_alg_values_supported": algorithms,
        "token_endpoint": url("/realms/apps/protocol/openid-connect/token"),
    })
    .to_string()
}

/// The test key published under each of `kids`.
fn jwks(kids: &[&str]) -> String {
    let public = RsaPublicKey::from_public_key_pem(&keypair().public_pem).expect("public key");
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let keys: Vec<Value> = kids
        .iter()
        .map(|kid| {
            json!({
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                "n": b64.encode(public.n().to_bytes_be()),
                "e": b64.encode(public.e().to_bytes_be()),
            })
        })
        .collect();
    json!({ "keys": keys }).to_string()
}

const EC_KID: &str = "realm-es256";

fn ec_signing_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).expect("a valid P-256 scalar")
}

/// The P-256 test key as a JWK published under `kid`.
fn ec_jwk(kid: &str) -> Value {
    let point = ec_signing_key().verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    json!({
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
        "x": b64.encode(&bytes[1..33]),
        "y": b64.encode(&bytes[33..65]),
    })
}

/// An ES256 token signed by the P-256 test key, naming `kid`.
fn ec_token(kid: &str) -> String {
    use p256::pkcs8::EncodePrivateKey as _;
    let pem = ec_signing_key()
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("PEM");
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_owned());
    let key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("EC key");
    encode(&header, &claims(json!({})), &key).expect("sign JWT")
}

fn idp(document: &str, keys: &str) -> Arc<FakeTransport> {
    Arc::new(
        FakeTransport::new()
            .json(WELL_KNOWN, 200, document)
            .json(CERTS, 200, keys),
    )
}

/// An `IdP` whose discovery endpoint answers only while `up` is set. The JWKS
/// always answers, so an outage of the document alone can be staged.
fn switchable_idp(up: &Arc<AtomicBool>, document: &str) -> Arc<FakeTransport> {
    let up = Arc::clone(up);
    let document = document.to_owned();
    Arc::new(
        FakeTransport::new()
            .respond_with(WELL_KNOWN, move |_| {
                if up.load(Ordering::SeqCst) {
                    Ok(HttpResponse::new(200, Bytes::from(document.clone())))
                } else {
                    Err(HttpTransportError::Connect("connection refused".into()))
                }
            })
            .json(CERTS, 200, &jwks(&[KID])),
    )
}

/// A resolver config with one discovered issuer. `fast` sets a one-second
/// TTL and floor, the smallest the config allows, so a test can step past
/// both. `issuer` merges into the issuer entry.
fn discovery_config(fast: bool, issuer: Value) -> PluginConfig {
    let mut decoding_key = json!({ "kind": "oidc_discovery" });
    if fast {
        decoding_key["refresh_secs"] = json!(1);
        decoding_key["min_refresh_interval_secs"] = json!(1);
    }
    let mut entry = json!({
        "issuer": ISSUER,
        "audiences": [TEST_AUDIENCE],
        "decoding_key": decoding_key,
    });
    for (k, v) in issuer.as_object().unwrap() {
        entry[k] = v.clone();
    }
    PluginConfig {
        name: "jwt-discovery".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: ["perform_http".to_owned()].into(),
        config: Some(json!({
            "trusted_issuers": [entry],
            "claim_mapper": "keycloak",
        })),
        ..Default::default()
    }
}

fn yaml_for(issuer: &str) -> String {
    format!(
        r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: jwt-discovery
    kind: {KIND}
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      claim_mapper: keycloak
      trusted_issuers:
        - issuer: "{issuer}"
          audiences: ["{TEST_AUDIENCE}"]
          decoding_key:
            kind: oidc_discovery
"#
    )
}

/// An engine that builds `identity/jwt` plugins from YAML, on `http`.
fn yaml_engine(http: &Arc<FakeTransport>) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(JwtIdentityFactory));
    let transport: Arc<dyn HttpTransport> = http.clone();
    engine.set_http_transport(transport);
    engine
}

async fn engine(
    cfg: PluginConfig,
    http: &Arc<FakeTransport>,
    initialize: bool,
) -> Arc<PolicyEngine> {
    let resolver = JwtIdentityResolver::new(cfg.clone()).expect("the resolver constructs");
    let engine = Arc::new(PolicyEngine::default());
    engine
        .register_handler_for_names::<IdentityHook, _>(
            Arc::new(resolver),
            cfg,
            &[HOOK_IDENTITY_RESOLVE],
        )
        .expect("registration");
    let transport: Arc<dyn HttpTransport> = http.clone();
    engine.set_http_transport(transport);
    if initialize {
        engine
            .initialize()
            .await
            .expect("initialize soft-fails rather than erroring");
    }
    engine
}

fn claims(extra: Value) -> Value {
    let mut claims = json!({
        "iss": ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": "alice",
        "exp": now_unix() + 300,
        "iat": now_unix(),
    });
    for (k, v) in extra.as_object().unwrap() {
        claims[k] = v.clone();
    }
    claims
}

fn mint(kid: Option<&str>, extra: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(ToOwned::to_owned);
    let key = EncodingKey::from_rsa_pem(keypair().private_pem.as_bytes()).expect("encoding key");
    encode(&header, &claims(extra), &key).expect("sign JWT")
}

fn token(kid: &str, extra: Value) -> String {
    mint(Some(kid), extra)
}

async fn call(engine: &Arc<PolicyEngine>, token: &str) -> PipelineResult {
    let payload = IdentityPayload::new(token, TokenSource::Bearer);
    let (result, _bg) = engine
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    result
}

fn denial(result: &PipelineResult) -> String {
    assert!(!result.continue_processing, "expected a denial");
    result.violation.as_ref().expect("a violation").code.clone()
}
