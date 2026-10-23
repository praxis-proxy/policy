// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `DPoP` (RFC 9449) through the real handler pipeline.
//!
//! The access token is signed by the test issuer and bound, through `cnf.jkt`,
//! to a P-256 key the "agent" holds. Each request carries the token with the
//! `DPoP` scheme, a proof signed with that key, and a request line the proof's
//! `htm` and `htu` are checked against. Every case below breaks one thing.
//!
//! The P-256 keys come from fixed scalars at test time, so no private key is
//! checked in.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use praxis_policy_builtins::plugins::identity_jwt::JwtIdentityResolver;
use praxis_policy_builtins::plugins::identity_jwt::dpop::{
    DpopVerifier, InMemoryReplayGuard, PopRequest, ProofOfPossession as _, ReplayGuard,
    ReplayUnavailable, access_token_hash, codes, jwk_thumbprint,
};
#[cfg(feature = "valkey")]
use praxis_policy_builtins::plugins::identity_jwt::dpop_valkey::ValkeyReplayGuard;
use praxis_policy_builtins::plugins::identity_jwt::{DpopConfig, DpopMode};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::extensions::HttpExtension;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::PluginConfig;
use serde_json::{Value, json};
#[cfg(feature = "valkey")]
use testcontainers_modules::testcontainers::ContainerAsync;
#[cfg(feature = "valkey")]
use testcontainers_modules::testcontainers::runners::AsyncRunner as _;
#[cfg(feature = "valkey")]
use testcontainers_modules::valkey::{VALKEY_PORT, Valkey};

use crate::common::{TEST_AUDIENCE, TEST_ISSUER, mint, now_unix, plugin_config};

const URL: &str = "https://gateway.test/mcp";

/// A P-256 key from a fixed scalar, with its public JWK.
struct AgentKey {
    encoding: EncodingKey,
    jwk: Value,
}

impl AgentKey {
    fn from_scalar(byte: u8) -> Self {
        let signing = SigningKey::from_slice(&[byte; 32]).expect("valid P-256 scalar");
        let pem = signing
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private PEM");
        let point = signing.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        Self {
            encoding: EncodingKey::from_ec_pem(pem.as_bytes()).expect("EncodingKey from PEM"),
            jwk: json!({
                "kty": "EC",
                "crv": "P-256",
                "x": b64(&bytes[1..33]),
                "y": b64(&bytes[33..65]),
            }),
        }
    }

    fn thumbprint(&self) -> String {
        jwk_thumbprint(&self.jwk).expect("thumbprint of a P-256 JWK")
    }
}

fn agent() -> AgentKey {
    AgentKey::from_scalar(0x11)
}

fn other() -> AgentKey {
    AgentKey::from_scalar(0x22)
}

/// The proof's claims for a valid request, ready to be broken by a test.
fn claims_for(token: &str) -> Value {
    json!({
        "htm": "POST",
        "htu": URL,
        "iat": now_unix(),
        "jti": format!("jti-{}", now_unix_nanos()),
        "ath": access_token_hash(token),
    })
}

fn now_unix_nanos() -> i128 {
    chrono::Utc::now()
        .timestamp_nanos_opt()
        .map_or(0, i128::from)
}

/// Sign a proof with `signer`, carrying `header_jwk` in its header.
fn proof(signer: &AgentKey, header_jwk: &Value, alg: Algorithm, claims: &Value) -> String {
    let mut header = Header::new(alg);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(serde_json::from_value(header_jwk.clone()).expect("header JWK"));
    encode(&header, claims, &signer.encoding).expect("sign proof")
}

/// Sign a proof whose header is exactly `header`, for a test that needs a header
/// `jsonwebtoken::Header` cannot express, such as a JWK carrying a private member.
fn raw_proof(signer: &AgentKey, header: &Value, claims: &Value) -> String {
    let b64 = |v: &Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(v).expect("serialize"))
    };
    let signing_input = format!("{}.{}", b64(header), b64(claims));
    let signature =
        jsonwebtoken::crypto::sign(signing_input.as_bytes(), &signer.encoding, Algorithm::ES256)
            .expect("sign proof");
    format!("{signing_input}.{signature}")
}

fn valid_proof(token: &str) -> String {
    let key = agent();
    proof(&key, &key.jwk, Algorithm::ES256, &claims_for(token))
}

/// A token from the test issuer bound to `key`.
fn bound_token(key: &AgentKey) -> String {
    mint(json!({ "sub": "agent-1", "cnf": { "jkt": key.thumbprint() } }))
}

fn unbound_token() -> String {
    mint(json!({ "sub": "agent-1" }))
}

/// The test issuer with `dpop` settings, and `read_headers` granted.
fn dpop_config(dpop: Value) -> PluginConfig {
    let mut cfg = plugin_config(json!({}));
    let config = cfg.config.as_mut().expect("config block");
    config["trusted_issuers"][0]["dpop"] = dpop;
    cfg.capabilities = HashSet::from(["read_headers".to_owned()]);
    cfg
}

fn required() -> PluginConfig {
    dpop_config(json!({ "mode": "required" }))
}

/// A request as a host would hand it over: headers plus the request line.
struct Request {
    authorization: String,
    dpop: Option<String>,
    /// The request line. `None` stands for a host that supplies none.
    http: Option<HttpExtension>,
}

impl Request {
    fn new(authorization: String, dpop: Option<String>) -> Self {
        let http = HttpExtension {
            method: Some("POST".to_owned()),
            scheme: Some("https".to_owned()),
            host: Some("gateway.test".to_owned()),
            path: Some("/mcp".to_owned()),
            ..Default::default()
        };
        Self {
            authorization,
            dpop,
            http: Some(http),
        }
    }

    fn dpop(token: &str, proof: String) -> Self {
        Self::new(format!("DPoP {token}"), Some(proof))
    }
}

/// One resolver behind a real engine, so a test can send several requests to
/// the same instance (and its replay store).
struct Gateway {
    engine: Arc<PolicyEngine>,
}

impl Gateway {
    async fn new(cfg: PluginConfig) -> Self {
        let resolver = JwtIdentityResolver::new(cfg.clone()).expect("the resolver must construct");
        Self::from_resolver(cfg, resolver).await
    }

    async fn with_replay_guard(cfg: PluginConfig, replay: Arc<dyn ReplayGuard>) -> Self {
        let resolver = JwtIdentityResolver::with_replay_guard(cfg.clone(), replay)
            .expect("the resolver must construct");
        Self::from_resolver(cfg, resolver).await
    }

    async fn from_resolver(cfg: PluginConfig, resolver: JwtIdentityResolver) -> Self {
        let engine = Arc::new(PolicyEngine::default());
        engine
            .register_handler_for_names::<IdentityHook, _>(
                Arc::new(resolver),
                cfg,
                &[HOOK_IDENTITY_RESOLVE],
            )
            .expect("registration");
        engine.initialize().await.expect("initialize");
        Self { engine }
    }

    async fn send(&self, request: Request) -> PipelineResult {
        let mut headers = HashMap::from([("authorization".to_owned(), request.authorization)]);
        if let Some(proof) = request.dpop {
            headers.insert("dpop".to_owned(), proof);
        }
        let payload =
            IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers);
        let ext = Extensions {
            http: request.http.map(Arc::new),
            ..Default::default()
        };
        let (result, _bg) = self
            .engine
            .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, ext, None)
            .await;
        result
    }
}

async fn send(cfg: PluginConfig, request: Request) -> PipelineResult {
    Gateway::new(cfg).await.send(request).await
}

fn denied_with(result: &PipelineResult) -> &str {
    assert!(!result.continue_processing, "expected a denial");
    &result.violation.as_ref().expect("a violation").code
}

// ---------------------------------------------------------------------
// Accepted
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_bound_token_with_a_valid_proof_is_accepted_and_its_binding_recorded() {
    let token = bound_token(&agent());
    let result = send(required(), Request::dpop(&token, valid_proof(&token))).await;
    assert!(
        result.continue_processing,
        "violation = {:?}",
        result.violation
    );

    let identity = IdentityPayload::from_pipeline_result(&result).expect("payload");
    let binding = identity
        .subject
        .as_ref()
        .and_then(|s| s.key_binding.as_ref())
        .expect("a verified binding on the subject");
    assert_eq!(binding.method, "dpop");
    assert_eq!(binding.thumbprint, agent().thumbprint());
}

#[tokio::test]
async fn optional_mode_accepts_a_bearer_token_without_recording_a_binding() {
    let token = unbound_token();
    let cfg = dpop_config(json!({ "mode": "optional" }));
    let result = send(cfg, Request::new(format!("Bearer {token}"), None)).await;
    assert!(
        result.continue_processing,
        "violation = {:?}",
        result.violation
    );
    let identity = IdentityPayload::from_pipeline_result(&result).expect("payload");
    assert!(identity.subject.expect("subject").key_binding.is_none());
}

#[tokio::test]
async fn an_external_base_url_matches_the_url_the_client_used_behind_a_proxy() {
    // The proxy terminates TLS and forwards to an internal address; the proof
    // names the public URL the client addressed.
    let token = bound_token(&agent());
    let cfg = dpop_config(json!({
        "mode": "required",
        "external_base_url": "https://gateway.test",
    }));
    let mut request = Request::dpop(&token, valid_proof(&token));
    let http = request.http.as_mut().expect("request line");
    http.scheme = Some("http".to_owned());
    http.host = Some("10.0.0.7:8080".to_owned());
    let result = send(cfg, request).await;
    assert!(
        result.continue_processing,
        "violation = {:?}",
        result.violation
    );
}

// ---------------------------------------------------------------------
// Missing proof or binding
// ---------------------------------------------------------------------

#[tokio::test]
async fn required_mode_denies_an_unbound_token() {
    let token = unbound_token();
    let result = send(required(), Request::new(format!("Bearer {token}"), None)).await;
    assert_eq!(denied_with(&result), codes::DPOP_MISSING);
}

#[tokio::test]
async fn a_bound_token_without_a_proof_is_denied_in_either_mode() {
    let token = bound_token(&agent());
    for mode in ["optional", "required"] {
        let cfg = dpop_config(json!({ "mode": mode }));
        let result = send(cfg, Request::new(format!("DPoP {token}"), None)).await;
        assert_eq!(denied_with(&result), codes::DPOP_MISSING, "mode {mode}");
    }
}

/// RFC 9449 Section 7.2: a `DPoP`-bound token sent as a bearer token is rejected.
#[tokio::test]
async fn a_bound_token_presented_as_bearer_is_denied_even_with_a_proof() {
    let token = bound_token(&agent());
    let request = Request::new(format!("Bearer {token}"), Some(valid_proof(&token)));
    let result = send(required(), request).await;
    assert_eq!(denied_with(&result), codes::DPOP_MISSING);
}

#[tokio::test]
async fn the_dpop_scheme_is_refused_by_an_issuer_that_does_not_check_proofs() {
    let token = bound_token(&agent());
    let result = send(
        plugin_config(json!({})),
        Request::dpop(&token, valid_proof(&token)),
    )
    .await;
    assert_eq!(denied_with(&result), codes::DPOP_INVALID);
}

// ---------------------------------------------------------------------
// One check fails
// ---------------------------------------------------------------------

/// RFC 9449 Section 4.3, check 6: the signature verifies with the header `jwk`.
#[tokio::test]
async fn a_proof_whose_signature_does_not_match_its_key_is_denied() {
    // Signed by another key, but carrying the agent's public key.
    let token = bound_token(&agent());
    let forged = proof(
        &other(),
        &agent().jwk,
        Algorithm::ES256,
        &claims_for(&token),
    );
    let result = send(required(), Request::dpop(&token, forged)).await;
    assert_eq!(denied_with(&result), codes::DPOP_INVALID);
}

/// RFC 9449 Section 4.3, check 12: the proof key matches the key the token is bound
/// to (`cnf.jkt`).
#[tokio::test]
async fn a_proof_from_a_different_key_is_a_key_mismatch() {
    let token = bound_token(&agent());
    let key = other();
    let theirs = proof(&key, &key.jwk, Algorithm::ES256, &claims_for(&token));
    let result = send(required(), Request::dpop(&token, theirs)).await;
    assert_eq!(denied_with(&result), codes::DPOP_KEY_MISMATCH);
}

/// RFC 9449 Section 4.3, check 5: an accepted asymmetric algorithm.
#[tokio::test]
async fn a_proof_algorithm_the_issuer_does_not_accept_is_denied() {
    let token = bound_token(&agent());
    let cfg = dpop_config(json!({ "mode": "required", "algorithms": ["ES384"] }));
    let result = send(cfg, Request::dpop(&token, valid_proof(&token))).await;
    assert_eq!(denied_with(&result), codes::DPOP_INVALID);
}

/// RFC 9449 Section 4.3, checks 8, 9, 11 and 12: `htm`, `htu`, `iat` and `ath`.
#[tokio::test]
async fn a_proof_for_another_method_url_time_or_token_is_denied() {
    let token = bound_token(&agent());
    let key = agent();
    let cases: [(&str, Value); 4] = [
        ("method", json!({ "htm": "GET" })),
        ("url", json!({ "htu": "https://gateway.test/other" })),
        ("stale iat", json!({ "iat": now_unix() - 600 })),
        (
            "ath",
            json!({ "ath": access_token_hash("some other token") }),
        ),
    ];
    for (what, change) in cases {
        let mut claims = claims_for(&token);
        for (k, v) in change.as_object().expect("object") {
            claims[k] = v.clone();
        }
        let broken = proof(&key, &key.jwk, Algorithm::ES256, &claims);
        let result = send(required(), Request::dpop(&token, broken)).await;
        assert_eq!(denied_with(&result), codes::DPOP_INVALID, "wrong {what}");
    }
}

/// RFC 9449 Section 4.3, check 7: the `jwk` holds no private key.
#[tokio::test]
async fn a_proof_carrying_a_private_key_member_is_denied() {
    let token = bound_token(&agent());
    let key = agent();
    let mut leaky = key.jwk.clone();
    leaky["d"] = json!("c2VjcmV0");
    let header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": leaky });
    let result = send(
        required(),
        Request::dpop(&token, raw_proof(&key, &header, &claims_for(&token))),
    )
    .await;
    assert_eq!(denied_with(&result), codes::DPOP_INVALID);
    let reason = &result.violation.expect("violation").reason;
    assert!(reason.contains("private member"), "{reason}");
}

/// RFC 9449 Section 11.1: a proof is not accepted twice.
#[tokio::test]
async fn a_replayed_proof_is_denied_the_second_time() {
    let gateway = Gateway::new(required()).await;
    let token = bound_token(&agent());
    let once = valid_proof(&token);
    let first = gateway.send(Request::dpop(&token, once.clone())).await;
    assert!(
        first.continue_processing,
        "violation = {:?}",
        first.violation
    );
    let second = gateway.send(Request::dpop(&token, once)).await;
    assert_eq!(denied_with(&second), codes::DPOP_REPLAY);
}

// ---------------------------------------------------------------------
// Configuration and the replay store
// ---------------------------------------------------------------------

#[test]
fn turning_on_dpop_without_read_headers_fails_at_load() {
    let mut cfg = required();
    cfg.capabilities.clear();
    let Err(e) = JwtIdentityResolver::new(cfg) else {
        panic!("a DPoP issuer without read_headers must not load")
    };
    assert!(e.to_string().contains("read_headers"), "{e}");
}

#[test]
fn a_shared_secret_proof_algorithm_fails_at_load() {
    let cfg = dpop_config(json!({ "mode": "required", "algorithms": ["HS256"] }));
    let Err(e) = JwtIdentityResolver::new(cfg) else {
        panic!("a shared-secret proof algorithm must not load")
    };
    assert!(e.to_string().contains("shared-secret"), "{e}");
}

#[derive(Debug)]
struct UnreachableStore;

#[async_trait]
impl ReplayGuard for UnreachableStore {
    async fn first_use(&self, _: &str, _: &str, _: i64, _: i64) -> Result<bool, ReplayUnavailable> {
        Err(ReplayUnavailable("store unreachable".to_owned()))
    }
}

#[derive(Debug, Default)]
struct RetentionProbe(Mutex<Option<(i64, i64)>>);

#[async_trait]
impl ReplayGuard for RetentionProbe {
    async fn first_use(
        &self,
        _: &str,
        _: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, ReplayUnavailable> {
        *self.0.lock().expect("retention probe lock") = Some((expires_at, now));
        Ok(true)
    }
}

#[tokio::test]
async fn a_late_proof_is_retained_for_the_full_window_across_gateway_clocks() {
    let key = agent();
    let token = bound_token(&key);
    let now = now_unix();
    let mut claims = claims_for(&token);
    claims["iat"] = json!(now - 60);
    let proof = proof(&key, &key.jwk, Algorithm::ES256, &claims);
    let thumbprint = key.thumbprint();
    let probe = RetentionProbe::default();
    let config = DpopConfig {
        mode: DpopMode::Required,
        ..DpopConfig::default()
    };
    let verifier = DpopVerifier::new(&config, &probe);
    verifier
        .verify(&PopRequest {
            issuer: TEST_ISSUER,
            access_token: &token,
            bound_thumbprint: &thumbprint,
            proof: Some(&proof),
            method: "POST",
            url: URL,
            now,
        })
        .await
        .expect("the proof is within the iat window");
    let (expires_at, recorded_at) = probe.0.lock().expect("retention probe lock").expect("call");
    assert_eq!(expires_at - recorded_at, 121);
}

#[tokio::test]
async fn an_unreachable_replay_store_denies_rather_than_accepting_unchecked() {
    let config = DpopConfig {
        mode: DpopMode::Required,
        ..DpopConfig::default()
    };
    let key = agent();
    let token = bound_token(&key);
    let thumbprint = key.thumbprint();
    let proof = valid_proof(&token);
    let verifier = DpopVerifier::new(&config, &UnreachableStore);
    let denial = verifier
        .verify(&PopRequest {
            issuer: TEST_ISSUER,
            access_token: &token,
            bound_thumbprint: &thumbprint,
            proof: Some(&proof),
            method: "POST",
            url: URL,
            now: now_unix(),
        })
        .await
        .expect_err("an unreachable store must deny");
    assert_eq!(denial.code, codes::DPOP_REPLAY_UNAVAILABLE);
    let _ = TEST_AUDIENCE;
}

// ---------------------------------------------------------------------
// What the host supplies
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_bound_token_is_denied_when_the_host_supplies_no_request_line() {
    let token = bound_token(&agent());
    let mut request = Request::dpop(&token, valid_proof(&token));
    request.http = None;
    let result = send(required(), request).await;
    assert_eq!(denied_with(&result), "auth.config_error");
    assert!(
        result
            .violation
            .expect("violation")
            .reason
            .contains("request line")
    );
}

#[tokio::test]
async fn a_bound_token_is_denied_when_the_host_supplies_no_method() {
    let token = bound_token(&agent());
    let mut request = Request::dpop(&token, valid_proof(&token));
    request.http.as_mut().expect("request line").method = None;
    let result = send(required(), request).await;
    assert_eq!(denied_with(&result), "auth.config_error");
    assert!(
        result
            .violation
            .expect("violation")
            .reason
            .contains("method")
    );
}

#[tokio::test]
async fn without_a_scheme_and_host_the_url_needs_an_external_base_url() {
    let token = bound_token(&agent());
    let without_scheme = || {
        let mut request = Request::dpop(&token, valid_proof(&token));
        request.http.as_mut().expect("request line").scheme = None;
        request
    };
    let result = send(required(), without_scheme()).await;
    assert_eq!(denied_with(&result), "auth.config_error");
    assert!(
        result
            .violation
            .expect("violation")
            .reason
            .contains("external_base_url")
    );

    let cfg = dpop_config(json!({
        "mode": "required",
        "external_base_url": "https://gateway.test",
    }));
    let result = send(cfg, without_scheme()).await;
    assert!(
        result.continue_processing,
        "violation = {:?}",
        result.violation
    );
}

// ---------------------------------------------------------------------
// Malformed proofs
// ---------------------------------------------------------------------

/// Send `proof` with a bound token and return the denial reason, asserting the
/// code is `auth.dpop_invalid`.
async fn invalid_reason(proof: String) -> String {
    let token = bound_token(&agent());
    invalid_reason_for_token(&token, proof).await
}

async fn invalid_reason_for_token(token: &str, proof: String) -> String {
    let result = send(required(), Request::dpop(token, proof)).await;
    assert_eq!(
        denied_with(&result),
        codes::DPOP_INVALID,
        "a malformed proof is auth.dpop_invalid"
    );
    result.violation.expect("violation").reason
}

/// RFC 9449 Section 4.3, check 1: exactly one `DPoP` header.
#[tokio::test]
async fn two_dpop_headers_are_denied() {
    let token = bound_token(&agent());
    let one = valid_proof(&token);
    let reason = invalid_reason(format!("{one}, {one}")).await;
    assert!(reason.contains("more than one"), "{reason}");
}

/// RFC 9449 Section 4.3, check 2: a single well-formed JWT.
#[tokio::test]
async fn a_proof_that_is_not_a_jwt_is_denied() {
    let reason = invalid_reason("not-a-jwt".to_owned()).await;
    assert!(reason.contains("well-formed"), "{reason}");
}

/// RFC 9449 Section 4.3, check 4: `typ` is `dpop+jwt`.
#[tokio::test]
async fn a_proof_of_the_wrong_type_is_denied() {
    let token = bound_token(&agent());
    let key = agent();
    let header = json!({ "typ": "JWT", "alg": "ES256", "jwk": key.jwk });
    let reason = invalid_reason(raw_proof(&key, &header, &claims_for(&token))).await;
    assert!(reason.contains("typ"), "{reason}");
}

#[tokio::test]
async fn a_proof_without_a_public_key_is_denied() {
    let token = bound_token(&agent());
    let key = agent();
    let header = json!({ "typ": "dpop+jwt", "alg": "ES256" });
    let reason = invalid_reason(raw_proof(&key, &header, &claims_for(&token))).await;
    assert!(reason.contains("jwk"), "{reason}");
}

/// RFC 9449 Section 4.3, check 3: the required claims are present.
#[tokio::test]
async fn a_proof_with_an_empty_or_oversized_jti_is_denied() {
    let token = bound_token(&agent());
    let key = agent();
    for jti in [String::new(), "x".repeat(257)] {
        let mut claims = claims_for(&token);
        claims["jti"] = json!(jti);
        let reason =
            invalid_reason_for_token(&token, proof(&key, &key.jwk, Algorithm::ES256, &claims))
                .await;
        assert!(reason.contains("jti"), "{reason}");
    }
}

#[tokio::test]
async fn the_dpop_scheme_with_an_unbound_token_is_denied() {
    let token = unbound_token();
    let result = send(required(), Request::dpop(&token, valid_proof(&token))).await;
    assert_eq!(denied_with(&result), codes::DPOP_INVALID);
    assert!(
        result
            .violation
            .expect("violation")
            .reason
            .contains("cnf.jkt")
    );
}

#[tokio::test]
async fn a_cnf_without_a_usable_jkt_is_denied_rather_than_treated_as_unbound() {
    // A certificate-bound token, which this check cannot verify, and a malformed
    // jkt. Treating either as unbound would accept a bound token as bearer.
    let cfg = || dpop_config(json!({ "mode": "optional" }));
    for cnf in [json!({ "x5t#S256": "abc" }), json!({ "jkt": 42 })] {
        let token = mint(json!({ "sub": "agent-1", "cnf": cnf }));
        let result = send(cfg(), Request::new(format!("Bearer {token}"), None)).await;
        assert_eq!(denied_with(&result), codes::DPOP_INVALID, "cnf {cnf}");
    }
}

/// RFC 7515 Section 4.1.11: an unsupported `crit` extension is rejected.
#[tokio::test]
async fn a_proof_naming_critical_extensions_is_denied() {
    let token = bound_token(&agent());
    let key = agent();
    let header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk, "crit": ["exp-ext"] });
    let reason = invalid_reason(raw_proof(&key, &header, &claims_for(&token))).await;
    assert!(reason.contains("crit"), "{reason}");
}

#[tokio::test]
async fn an_iat_far_in_the_past_cannot_wrap_into_the_window() {
    let token = bound_token(&agent());
    let key = agent();
    for iat in [i64::MIN + now_unix(), i64::MIN, 0, -5] {
        let mut claims = claims_for(&token);
        claims["iat"] = json!(iat);
        let reason = invalid_reason(proof(&key, &key.jwk, Algorithm::ES256, &claims)).await;
        assert!(reason.contains("iat"), "iat {iat}: {reason}");
    }
}

#[test]
fn a_trusted_issuer_listed_twice_fails_at_load() {
    let mut cfg = required();
    let config = cfg.config.as_mut().expect("config block");
    let issuers = config["trusted_issuers"].as_array_mut().expect("issuers");
    let duplicate = issuers[0].clone();
    issuers.push(duplicate);
    let Err(e) = JwtIdentityResolver::new(cfg) else {
        panic!("a duplicated issuer must not load")
    };
    assert!(e.to_string().contains("more than once"), "{e}");
}

#[test]
fn an_unusable_external_base_url_fails_at_load() {
    for base in [
        "https://user@gateway.test",
        "ftp://gateway.test",
        "https://gateway.test?x=1",
    ] {
        let cfg = dpop_config(json!({ "mode": "required", "external_base_url": base }));
        assert!(
            JwtIdentityResolver::new(cfg).is_err(),
            "{base} must not load"
        );
    }
}

#[test]
fn a_dpop_issuer_with_no_proof_algorithms_or_an_out_of_range_window_fails_at_load() {
    for dpop in [
        json!({ "mode": "required", "algorithms": [] }),
        json!({ "mode": "required", "iat_window_seconds": 0 }),
        json!({ "mode": "required", "iat_window_seconds": 301 }),
    ] {
        let cfg = dpop_config(dpop.clone());
        assert!(
            JwtIdentityResolver::new(cfg).is_err(),
            "{dpop} weakens or disables the check and must not load"
        );
    }
}

#[tokio::test]
async fn a_long_client_value_is_clipped_in_the_denial_reason() {
    let token = bound_token(&agent());
    let key = agent();
    let mut claims = claims_for(&token);
    claims["htm"] = json!("X".repeat(300));
    let reason = invalid_reason(proof(&key, &key.jwk, Algorithm::ES256, &claims)).await;
    assert!(
        reason.contains('…'),
        "a 300-character htm is clipped: {reason}"
    );
    assert!(
        !reason.contains(&"X".repeat(121)),
        "no more than 120 characters of it are repeated"
    );
}

#[tokio::test]
async fn a_bound_token_is_denied_when_the_host_supplies_no_path() {
    let token = bound_token(&agent());
    let key = agent();
    let mut claims = claims_for(&token);
    claims["htu"] = json!("https://gateway.test/");
    let mut request = Request::dpop(&token, proof(&key, &key.jwk, Algorithm::ES256, &claims));
    request.http.as_mut().expect("request line").path = None;
    let result = send(required(), request).await;
    assert_eq!(denied_with(&result), "auth.config_error");
}

#[tokio::test]
async fn a_bare_authorization_value_cannot_present_a_bound_token() {
    let token = bound_token(&agent());
    let result = send(
        required(),
        Request::new(token.clone(), Some(valid_proof(&token))),
    )
    .await;
    assert_eq!(denied_with(&result), codes::DPOP_MISSING);
}

#[tokio::test]
async fn a_proof_with_an_oth_private_member_is_denied() {
    let token = bound_token(&agent());
    let key = agent();
    let mut jwk = key.jwk.clone();
    jwk["oth"] = json!([{"r":"private-prime", "d":"private-exponent", "t":"private-coefficient"}]);
    let header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
    let result = send(
        required(),
        Request::dpop(&token, raw_proof(&key, &header, &claims_for(&token))),
    )
    .await;
    assert_eq!(denied_with(&result), codes::DPOP_INVALID);
}

#[tokio::test]
async fn a_shared_replay_guard_rejects_a_proof_on_a_second_instance() {
    let replay: Arc<dyn ReplayGuard> = Arc::new(InMemoryReplayGuard::default());
    let first = Gateway::with_replay_guard(required(), Arc::clone(&replay)).await;
    let second = Gateway::with_replay_guard(required(), replay).await;
    let token = bound_token(&agent());
    let once = valid_proof(&token);
    let a = first.send(Request::dpop(&token, once.clone())).await;
    let b = second.send(Request::dpop(&token, once)).await;
    assert!(a.continue_processing, "first violation = {:?}", a.violation);
    assert_eq!(denied_with(&b), codes::DPOP_REPLAY);
}

#[cfg(feature = "valkey")]
#[tokio::test]
#[ignore = "requires VALKEY_TEST_URL"]
async fn valkey_rejects_a_replay_across_independent_gateway_pools() {
    let (url, _container): (String, Option<ContainerAsync<Valkey>>) =
        if let Ok(url) = std::env::var("VALKEY_TEST_URL") {
            (url, None)
        } else {
            match Valkey::default().start().await {
                Ok(container) => {
                    let host = container.get_host().await.expect("container host");
                    let port = container
                        .get_host_port_ipv4(VALKEY_PORT)
                        .await
                        .expect("container port");
                    (format!("redis://{host}:{port}"), Some(container))
                },
                Err(e) if std::env::var("VALKEY_TESTS_OPTIONAL").as_deref() == Ok("1") => {
                    eprintln!("SKIPPED: no Valkey available ({e})");
                    return;
                },
                Err(e) => panic!("no Valkey available: {e}; set VALKEY_TEST_URL or start Docker"),
            }
        };
    let prefix = format!("dpop:replay:test:{}", now_unix_nanos());
    let guard = || {
        let pool = deadpool_redis::Config::from_url(&url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("Valkey pool");
        let replay: Arc<dyn ReplayGuard> = Arc::new(ValkeyReplayGuard::new(pool, prefix.clone()));
        replay
    };
    let first = Gateway::with_replay_guard(required(), guard()).await;
    let second = Gateway::with_replay_guard(required(), guard()).await;
    let token = bound_token(&agent());
    let once = valid_proof(&token);
    let a = first.send(Request::dpop(&token, once.clone())).await;
    assert!(a.continue_processing, "first violation = {:?}", a.violation);
    let b = second.send(Request::dpop(&token, once)).await;
    assert_eq!(denied_with(&b), codes::DPOP_REPLAY);
}
