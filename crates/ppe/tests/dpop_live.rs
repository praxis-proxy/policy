// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Live `DPoP` coverage against a real Keycloak. See `docs/content/testing.md`.
//!
//! The unit and end-to-end `DPoP` tests sign their proofs with the same library
//! the verifier uses, so a mistake shared by both sides would pass. Here the
//! token, and its `cnf.jkt`, come from Keycloak: it checks the proof we send to
//! its token endpoint and binds the token to the key itself. The test then
//! presents that token, with a fresh proof, to the `identity/jwt` resolver.
//!
//! It creates a short-lived confidential client that requires `DPoP`-bound
//! tokens in the given realm, and deletes it afterwards.

#![cfg(all(feature = "jwt", feature = "http-hyper"))]
#![expect(clippy::expect_used, reason = "test code")]
#![allow(
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code reading known JSON shapes and reporting a skip"
)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use praxis_policy::HyperTransport;
use praxis_policy_builtins::plugins::identity_jwt::dpop::{
    access_token_hash, codes, jwk_thumbprint,
};
use praxis_policy_builtins::plugins::identity_jwt::{JwtIdentityResolver, KIND};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::extensions::HttpExtension;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::http::{HttpRequest, HttpTransport as _, Method};
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};
use serde_json::{Value, json};

const CLIENT_ID: &str = "ppe-dpop-live";
const CLIENT_SECRET: &str = "ppe-dpop-live-secret";
const GATEWAY_URL: &str = "https://gateway.test/mcp";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn now() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    i64::try_from(secs).expect("seconds fit in i64")
}

fn unique() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_nanos();
    format!("{nanos:x}")
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A P-256 key from a fixed scalar, with its public JWK.
struct ProofKey {
    encoding: EncodingKey,
    jwk: Value,
}

impl ProofKey {
    fn from_scalar(byte: u8) -> Self {
        let signing = SigningKey::from_slice(&[byte; 32]).expect("valid P-256 scalar");
        let pem = signing
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private PEM");
        let point = signing.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
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

    /// A proof for `method` and `url`, optionally bound to `access_token`.
    fn proof(&self, method: &str, url: &str, access_token: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(serde_json::from_value(self.jwk.clone()).expect("header JWK"));
        let mut claims = json!({ "htm": method, "htu": url, "iat": now(), "jti": unique() });
        if let Some(token) = access_token {
            claims["ath"] = json!(access_token_hash(token));
        }
        encode(&header, &claims, &self.encoding).expect("sign proof")
    }
}

/// Keycloak's admin and token endpoints, over the bundled transport.
struct Keycloak {
    http: HyperTransport,
    base: String,
    realm: String,
}

impl Keycloak {
    async fn send(&self, request: HttpRequest) -> (u16, Value) {
        let response = self
            .http
            .execute(request)
            .await
            .expect("Keycloak reachable");
        let body = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        (response.status, body)
    }

    fn form(pairs: &[(&str, &str)]) -> Bytes {
        let encoded: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{k}={}", v.replace('+', "%2B")))
            .collect();
        Bytes::from(encoded.join("&"))
    }

    async fn admin_token(&self, user: &str, password: &str) -> String {
        let request = HttpRequest::post(
            format!("{}/realms/master/protocol/openid-connect/token", self.base),
            Self::form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", user),
                ("password", password),
            ]),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .expect("header");
        let (status, body) = self.send(request).await;
        assert_eq!(status, 200, "admin login failed: {body}");
        body["access_token"]
            .as_str()
            .expect("admin token")
            .to_owned()
    }

    async fn delete_test_client(&self, admin: &str) {
        let clients = format!("{}/admin/realms/{}/clients", self.base, self.realm);
        let lookup = HttpRequest::get(format!("{clients}?clientId={CLIENT_ID}"))
            .header("authorization", format!("Bearer {admin}"))
            .expect("header");
        let (_, found) = self.send(lookup).await;
        for client in found.as_array().into_iter().flatten() {
            let id = client["id"].as_str().expect("client id");
            let delete = HttpRequest::new(Method::DELETE, format!("{clients}/{id}"))
                .header("authorization", format!("Bearer {admin}"))
                .expect("header");
            self.send(delete).await;
        }
    }

    async fn create_test_client(&self, admin: &str) {
        let client = json!({
            "clientId": CLIENT_ID,
            "enabled": true,
            "publicClient": false,
            "secret": CLIENT_SECRET,
            "serviceAccountsEnabled": true,
            "standardFlowEnabled": false,
            "directAccessGrantsEnabled": false,
            "attributes": { "dpop.bound.access.tokens": "true" },
        });
        let request = HttpRequest::post(
            format!("{}/admin/realms/{}/clients", self.base, self.realm),
            Bytes::from(client.to_string()),
        )
        .header("authorization", format!("Bearer {admin}"))
        .expect("header")
        .header("content-type", "application/json")
        .expect("header");
        let (status, body) = self.send(request).await;
        assert_eq!(status, 201, "creating the test client failed: {body}");
    }

    fn token_endpoint(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.base, self.realm
        )
    }

    /// A client-credentials token, bound to `key` by a proof Keycloak checks.
    async fn dpop_token(&self, key: &ProofKey) -> Value {
        let url = self.token_endpoint();
        let request = HttpRequest::post(
            url.clone(),
            Self::form(&[
                ("grant_type", "client_credentials"),
                ("client_id", CLIENT_ID),
                ("client_secret", CLIENT_SECRET),
            ]),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .expect("header")
        .header("dpop", key.proof("POST", &url, None))
        .expect("header");
        let (status, body) = self.send(request).await;
        assert_eq!(
            status, 200,
            "Keycloak refused the DPoP token request: {body}"
        );
        body
    }

    fn jwks_url(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/certs",
            self.base, self.realm
        )
    }
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

async fn resolver_engine(issuer: &str, jwks_url: &str) -> Arc<PolicyEngine> {
    let cfg = PluginConfig {
        name: "jwt-dpop-live".to_owned(),
        kind: KIND.to_owned(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.to_owned()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: HashSet::from(["read_headers".to_owned(), "perform_http".to_owned()]),
        config: Some(json!({
            "trusted_issuers": [{
                "issuer": issuer,
                "skip_audience_validation": true,
                "algorithms": ["RS256"],
                // Keycloak sets `kid`, which an inline key never matches.
                "decoding_key": { "kind": "jwks_url", "url": jwks_url, "insecure_http": jwks_url.starts_with("http://") },
                "dpop": { "mode": "required" },
            }],
        })),
        ..Default::default()
    };
    let resolver = JwtIdentityResolver::new(cfg.clone()).expect("resolver");
    let engine = Arc::new(PolicyEngine::default());
    engine.set_http_transport(Arc::new(
        HyperTransport::new().with_allow_private_destinations(),
    ));
    engine
        .register_handler_for_names::<IdentityHook, _>(
            Arc::new(resolver),
            cfg,
            &[HOOK_IDENTITY_RESOLVE],
        )
        .expect("registration");
    engine.initialize().await.expect("initialize");
    engine
}

async fn present(engine: &PolicyEngine, authorization: String, proof: String) -> PipelineResult {
    let headers = HashMap::from([
        ("authorization".to_owned(), authorization),
        ("dpop".to_owned(), proof),
    ]);
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
    let payload = IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers);
    let (result, _bg) = engine
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, ext, None)
        .await;
    result
}

fn code(result: &PipelineResult) -> String {
    assert!(!result.continue_processing, "expected a denial");
    result.violation.as_ref().expect("violation").code.clone()
}

#[tokio::test]
#[ignore = "requires a live Keycloak; see docs/content/testing.md"]
async fn a_keycloak_dpop_token_verifies_end_to_end() {
    let (Some(base), Some(realm), Some(user), Some(password)) = (
        env("DPOP_LIVE_KEYCLOAK_URL"),
        env("DPOP_LIVE_REALM"),
        env("DPOP_LIVE_ADMIN_USER"),
        env("DPOP_LIVE_ADMIN_PASSWORD"),
    ) else {
        eprintln!(
            "SKIP: set DPOP_LIVE_KEYCLOAK_URL, DPOP_LIVE_REALM, DPOP_LIVE_ADMIN_USER and \
             DPOP_LIVE_ADMIN_PASSWORD"
        );
        return;
    };
    let kc = Keycloak {
        http: HyperTransport::new().with_allow_private_destinations(),
        base: base.trim_end_matches('/').to_owned(),
        realm,
    };
    let admin = kc.admin_token(&user, &password).await;
    kc.delete_test_client(&admin).await;
    kc.create_test_client(&admin).await;

    let key = ProofKey::from_scalar(0x11);
    let response = kc.dpop_token(&key).await;
    let token = response["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    let claims = claims_of(&token);

    // Keycloak's view of the key matches ours: the thumbprint it bound the
    // token to is the RFC 7638 thumbprint we compute for the same key.
    assert_eq!(response["token_type"], "DPoP", "{response}");
    let expected = jwk_thumbprint(&key.jwk).expect("thumbprint");
    assert_eq!(claims["cnf"]["jkt"], expected.as_str(), "{claims}");

    let issuer = claims["iss"].as_str().expect("iss").to_owned();
    let engine = resolver_engine(&issuer, &kc.jwks_url()).await;

    let proof = key.proof("POST", GATEWAY_URL, Some(&token));
    let accepted = present(&engine, format!("DPoP {token}"), proof.clone()).await;
    assert!(
        accepted.continue_processing,
        "violation = {:?}",
        accepted.violation
    );
    let identity = IdentityPayload::from_pipeline_result(&accepted).expect("payload");
    let binding = identity
        .subject
        .and_then(|s| s.key_binding)
        .expect("a verified binding");
    assert_eq!(binding.method, "dpop");
    assert_eq!(binding.thumbprint, expected);

    // The same real token, refused when the proof does not hold.
    let replayed = present(&engine, format!("DPoP {token}"), proof).await;
    assert_eq!(code(&replayed), codes::DPOP_REPLAY);
    let as_bearer = present(
        &engine,
        format!("Bearer {token}"),
        key.proof("POST", GATEWAY_URL, Some(&token)),
    )
    .await;
    assert_eq!(code(&as_bearer), codes::DPOP_MISSING);
    let other = ProofKey::from_scalar(0x22);
    let wrong_key = present(
        &engine,
        format!("DPoP {token}"),
        other.proof("POST", GATEWAY_URL, Some(&token)),
    )
    .await;
    assert_eq!(code(&wrong_key), codes::DPOP_KEY_MISMATCH);

    kc.delete_test_client(&admin).await;
}
