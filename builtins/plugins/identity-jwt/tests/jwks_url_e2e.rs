// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end test for `DecodingKeySource::JwksUrl` + the async
// resolution path:
//
//   1. Construct a JwtIdentityResolver with `decoding_key.kind:
//      jwks_url` served by a scripted transport. The resolver carries
//      the issuer config in `pending_jwks`; `trusted_issuers` is
//      empty (no inline keys).
//   2. Call `plugin.initialize().await` — this is the async hook the
//      host's `PolicyEngine::initialize()` drives. It triggers the
//      JWKS HTTP fetch.
//   3. Mint a JWT with the corresponding private key, hand it to the
//      resolver, assert the subject is populated. Proves the
//      fetched JWKS key was wired into the trusted-issuer list.
//
// Also covers: missing-initialize sad path (the resolver returns
// `untrusted_issuer` because the JwksUrl-deferred issuer never made
// it into `trusted_issuers`).

#![allow(
    missing_docs,
    clippy::cast_possible_wrap,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::sync::Arc;
use std::time::Duration;

use praxis_policy_core::http::{HeaderMap, HttpTransport, HttpTransportError};
use praxis_policy_core::http_testing::{FakeTransport, granting};

use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_identity_jwt::{DecodingKeySource, JwksFetchBudget, JwtIdentityResolver};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs1::EncodeRsaPublicKey as _;
use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};

const ISS: &str = "https://idp.test.local";
const AUD: &str = "test-api";

/// Build a JWKS JSON document from a single RSA public key. The
/// `kid` is fixed and the key declares `use=sig, alg=RS256` so the
/// resolver picks it via the "first signing-use key" rule.
/// One RSA signature key published under an explicit `kid`.
fn build_jwks_with_kid(public: &RsaPublicKey, kid: &str) -> Value {
    use base64::Engine as _;
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public.n().to_bytes_be()),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public.e().to_bytes_be()),
        }]
    })
}

fn build_jwks(public: &RsaPublicKey) -> Value {
    use base64::Engine as _;
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "test-key-1",
            "n": n_b64,
            "e": e_b64,
        }]
    })
}

fn mint_jwt(private_pem: &str, claims: Value) -> String {
    // Set `kid` so the resolver's KeyStore lookup hits — the JWKS
    // entry exposed by the mock server uses the same kid value
    // ("test-key-1", see `jwks_body`).
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key =
        EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("build EncodingKey from RSA PEM");
    encode(&header, &claims, &key).expect("sign JWT")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn resolver_config(jwks_url: &str) -> PluginConfig {
    PluginConfig {
        name: "jwt-via-jwks".into(),
        kind: "test".into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        // Fetching a JWKS is an outbound call, so the plugin must
        // declare `perform_http`. Withholding it is a real
        // configuration — a deployment using only inline keys needs no
        // egress at all — so the grant is explicit rather than implied
        // by the presence of a `jwks_url`.
        capabilities: ["perform_http".to_owned()].into(),
        config: Some(json!({
            "role": "user",
            "header": "Authorization",
            "trusted_issuers": [{
                "issuer": ISS,
                "audiences": [AUD],
                "algorithms": ["RS256"],
                "decoding_key": { "kind": "jwks_url", "url": jwks_url },
                "leeway_seconds": 60,
            }],
            "claim_mapper": "standard",
        })),
        ..Default::default()
    }
}

/// Verify that a JWT signed by the JWKS-published key validates
/// after `initialize()` resolves the JWKS URL.
/// Path the fake `IdP` serves its JWKS on. The URL host is irrelevant —
/// the transport is scripted, not dialled — but keeping a realistic path
/// means the config under test looks like a real deployment's.
const CERTS_PATH: &str = "/realms/test/protocol/openid-connect/certs";

/// A JWKS URL for the scripted transport.
fn jwks_url() -> String {
    format!("https://idp.example.test{CERTS_PATH}")
}

/// Install `http` as the engine's transport.
///
/// These tests exercise the resolver's behaviour, not the wire. HTTP
/// mechanics — deadlines, body ceilings, TLS — belong to the transport
/// and are covered against real sockets where the transport lives. What
/// a scripted transport buys here is the half a mock server cannot
/// reach: a connect failure or a timeout on demand, deterministically
/// and without sleeping.
fn install(mgr: &Arc<PolicyEngine>, http: &Arc<FakeTransport>) {
    let transport: Arc<dyn HttpTransport> = http.clone();
    mgr.set_http_transport(transport);
}

#[tokio::test(flavor = "multi_thread")]
async fn initialize_fetches_jwks_and_validates_token() {
    // 1. Generate a keypair and serve its public key as a JWKS.
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();
    let jwks_body = build_jwks(&pub_key).to_string();
    // Suppress unused-import warning on EncodeRsaPublicKey — only
    // exists to keep the trait in scope for callers that want
    // alternate PEM exports.
    let _ = pub_key.to_pkcs1_pem(LineEnding::LF);

    let http = Arc::new(FakeTransport::new().json(CERTS_PATH, 200, &jwks_body));
    let jwks_url = jwks_url();

    // 2. Build the resolver. JwksUrl source → trusted_issuers is
    //    empty until initialize() runs.
    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));

    // 3. Wire into a PolicyEngine and call initialize. The
    //    engine's initialize() drives plugin.initialize(), which
    //    triggers the async JWKS fetch.
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    install(&mgr, &http);
    mgr.initialize().await.expect("initialize succeeds");

    // 4. Mint a JWT, dispatch, assert subject populated.
    let token = mint_jwt(
        &priv_pem,
        json!({
            "sub": "alice@corp.com",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
            "roles": ["hr"],
        }),
    );

    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".to_owned(), format!("Bearer {token}"));

    let payload = IdentityPayload::new(token.clone(), TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        result.continue_processing,
        "valid JWT (JWKS-resolved key) should pass: violation = {:?}",
        result.violation
    );
    let identity =
        IdentityPayload::from_pipeline_result(&result).expect("identity payload present");
    let subject = identity.subject.as_ref().expect("subject populated");
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
    assert!(subject.roles.contains("hr"));

    // 5. The mock recorded one (and only one) GET — proves we did
    //    a real network fetch.
    assert_eq!(
        http.call_count_for(CERTS_PATH),
        1,
        "initialize must fetch the JWKS exactly once"
    );
}

/// Without `initialize()`, the issuer config sits in `pending_jwks`
/// and `trusted_issuers` is empty — a token signed by the JWKS key
/// gets `auth.untrusted_issuer` rather than silently passing. This
/// is the deliberate fail-loud mode: hosts must call
/// `PolicyEngine::initialize()`.
#[tokio::test(flavor = "multi_thread")]
async fn skipping_initialize_rejects_with_untrusted_issuer() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();

    // Programmed but never expected to answer: the test skips
    // initialize, so nothing should ever ask for the JWKS.
    let http =
        Arc::new(FakeTransport::new().json(CERTS_PATH, 200, &build_jwks(&pub_key).to_string()));
    let jwks_url = jwks_url();
    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    // Install the transport but deliberately SKIP mgr.initialize() —
    // proving both that the pending JwksUrl issuer never made it into
    // trusted_issuers, and that nothing reached for the JWKS without
    // initialization asking it to.
    install(&mgr, &http);

    let token = mint_jwt(
        &priv_pem,
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".to_owned(), format!("Bearer {token}"));

    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        !result.continue_processing,
        "no initialize() should yield deny (JWKS issuer never wired)",
    );
    let v = result.violation.expect("violation should be reported");
    assert_eq!(v.code, "auth.untrusted_issuer");
    assert_eq!(
        http.call_count(),
        0,
        "nothing may fetch the JWKS unless initialization asks for it"
    );
}

// =====================================================================
// kid-based key selection + JWKS fetch timeout
// =====================================================================

/// Build a JWKS containing two RSA keys with distinct `kid`s. Used by
/// the rotation / kid-selection tests below to prove the resolver
/// picks the key matching the inbound token's header, not the first
/// listed.
fn build_jwks_two_keys(
    pub_a: &RsaPublicKey,
    kid_a: &str,
    pub_b: &RsaPublicKey,
    kid_b: &str,
) -> Value {
    use base64::Engine as _;
    let make_entry = |k: &RsaPublicKey, kid: &str| {
        json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(k.n().to_bytes_be()),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(k.e().to_bytes_be()),
        })
    };
    json!({
        "keys": [
            make_entry(pub_a, kid_a),
            make_entry(pub_b, kid_b),
        ]
    })
}

/// Mint a JWT with a specific `kid` in the header. Distinct from
/// `mint_jwt` (which uses the default test kid) so the kid-selection
/// tests can control which key the resolver should select.
fn mint_jwt_with_kid(private_pem: &str, kid: &str, claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    let key =
        EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("build EncodingKey from RSA PEM");
    encode(&header, &claims, &key).expect("sign JWT")
}

/// JWKS publishes two keys with distinct kids. A token signed by
/// key B with header `kid=key-b` must validate against key B, not
/// against the first-listed key A. Pre-Slice-A code would pick the
/// first key (A) and reject the valid token as `signature_invalid`.
#[tokio::test(flavor = "multi_thread")]
async fn kid_selects_correct_key_when_jwks_has_multiple() {
    let mut rng = rand::thread_rng();
    let priv_a = RsaPrivateKey::new(&mut rng, 2048).expect("rsa a");
    let priv_b = RsaPrivateKey::new(&mut rng, 2048).expect("rsa b");
    let pub_a = RsaPublicKey::from(&priv_a);
    let pub_b = RsaPublicKey::from(&priv_b);
    let priv_pem_b = priv_b
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM b")
        .to_string();

    let jwks_body = build_jwks_two_keys(&pub_a, "key-a", &pub_b, "key-b").to_string();

    let http = Arc::new(FakeTransport::new().json(CERTS_PATH, 200, &jwks_body));
    let jwks_url = jwks_url();

    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    install(&mgr, &http);
    mgr.initialize().await.expect("initialize");

    // Token signed by B, with kid=key-b. The resolver must select
    // key B from the JWKS (not first-listed key A).
    let token = mint_jwt_with_kid(
        &priv_pem_b,
        "key-b",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        result.continue_processing,
        "kid-matched token must verify: violation = {:?}",
        result.violation,
    );
}

/// Token's `kid` header doesn't match any key the JWKS knows about.
/// Must yield `auth.unknown_kid` — distinct from
/// `auth.signature_invalid` so operators can tell rotation lag
/// from forgery at the audit layer.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_kid_yields_unknown_kid_violation() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();

    // JWKS publishes a single key with kid=test-key-1.
    let jwks_body = build_jwks(&pub_key).to_string();
    let http = Arc::new(FakeTransport::new().json(CERTS_PATH, 200, &jwks_body));
    let jwks_url = jwks_url();

    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    install(&mgr, &http);
    mgr.initialize().await.expect("initialize");

    // Token signed by the right private key, but its header
    // declares `kid=stale-key` — which is what the IdP would do
    // post-rotation if we haven't refreshed yet.
    let token = mint_jwt_with_kid(
        &priv_pem,
        "stale-key",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation reported");
    assert_eq!(v.code, "auth.unknown_kid");
    assert!(
        v.reason.contains("stale-key"),
        "reason should name the missing kid: {}",
        v.reason,
    );
}

/// A stalled or unreachable `IdP` must surface as an error rather than
/// hanging `initialize()` forever.
///
/// Enforcing the deadline is the transport's job now, and it is tested
/// against a real stalling socket where the transport lives. What
/// belongs here is the half this plugin owns: that it asks for bounds at
/// all, and that when a bound is hit the failure propagates instead of
/// producing an empty `KeyStore` that would fail verification later with
/// a misleading code.
///
/// Scripting the failure also removes the wall-clock assertion the old
/// version leaned on. Timing out "in under 8 seconds" was really an
/// assertion about reqwest's behaviour, it cost 5 seconds of test time,
/// and it went quiet on any platform where the error arrived by another
/// route.
#[tokio::test]
async fn a_jwks_fetch_that_times_out_is_an_error_not_an_empty_store() {
    let http = Arc::new(FakeTransport::new().fail(CERTS_PATH, HttpTransportError::Timeout));
    let src = DecodingKeySource::JwksUrl {
        url: jwks_url(),
        insecure_http: false,
        refresh_secs: 3600,
        min_refresh_interval_secs: 30,
    };

    match src
        .build_async(&granting(Arc::clone(&http)), JwksFetchBudget::Startup)
        .await
    {
        Ok(_) => panic!("a stalled JWKS must not produce a KeyStore"),
        Err(e) => {
            // A timeout is the `IdP` being slow right now, so the gateway
            // still boots and a later verify tries again. Classifying it
            // fatal would turn a brief outage during a rolling restart
            // into a deployment that refuses to come up.
            assert!(!e.is_fatal(), "a timeout must stay recoverable: {e}");
            assert!(
                e.to_string().contains("JWKS GET"),
                "the message must name the fetch that failed: {e}"
            );
        },
    }

    // The bounds this plugin chose, asserted where a healthy endpoint
    // would never reveal whether they were set.
    let req = http.last_request().expect("a request was attempted");
    assert!(req.timeout > Duration::ZERO);
    assert!(req.connect_timeout.is_some());
    assert!(req.max_response_bytes > 0);
}

/// A `GET` is safe to repeat, so a transient failure should be retried
/// rather than surfacing on the first stumble.
///
/// This is only assertable with a scripted transport: a mock server
/// cannot fail once and then succeed on demand.
#[tokio::test]
async fn a_transient_jwks_failure_is_retried() {
    let http = Arc::new(
        FakeTransport::new()
            .fail(CERTS_PATH, HttpTransportError::Connect("refused".into()))
            .json(CERTS_PATH, 200, r#"{"keys":[]}"#),
    );
    let src = DecodingKeySource::JwksUrl {
        url: jwks_url(),
        insecure_http: false,
        refresh_secs: 3600,
        min_refresh_interval_secs: 30,
    };

    // The second attempt returns an empty key set, which the resolver
    // rejects on its own terms — the point is that it got there at all.
    let err = src
        .build_async(&granting(Arc::clone(&http)), JwksFetchBudget::Startup)
        .await
        .expect_err("an empty JWKS has no usable keys");
    assert!(!err.is_fatal(), "an empty key set stays recoverable: {err}");
    assert!(
        err.to_string().contains("no usable signature keys"),
        "{err}"
    );
    assert_eq!(
        http.call_count_for(CERTS_PATH),
        2,
        "a connect failure on an idempotent GET must be retried"
    );
}

// =====================================================================
// soft-fail at boot + periodic JWKS refresh
// =====================================================================

/// JWKS endpoint is unreachable at gateway boot. The plugin must
/// `initialize()` cleanly (no Err — soft-fail) so the gateway
/// doesn't crash on a transient `IdP` outage. Subsequent verify
/// calls against tokens for that issuer must surface
/// `auth.jwks_unavailable` — a clear, distinct code so operators
/// see "JWKS issue at `IdP` X" rather than the alarming
/// `auth.signature_invalid` they'd see if we silently used an
/// empty key.
#[tokio::test(flavor = "multi_thread")]
async fn jwks_unreachable_at_initialize_soft_fails() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM")
        .to_string();

    // Unreachable, scripted rather than dialled: a refused connection
    // on demand, with no dependence on port 1 being unbound.
    let http = Arc::new(
        FakeTransport::new().fail(CERTS_PATH, HttpTransportError::Connect("refused".into())),
    );
    let jwks_url = jwks_url();
    let cfg = resolver_config(&jwks_url);
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    install(&mgr, &http);

    // The gateway boots — initialize returns Ok even though the
    // JWKS fetch failed. This is the soft-fail invariant.
    mgr.initialize()
        .await
        .expect("initialize must NOT propagate JWKS failure");

    // A token signed by the right key fails verify with
    // `auth.jwks_unavailable` rather than crashing or returning
    // the wrong code. The resolver's KeyStore is empty until
    // refresh succeeds (which it won't, in this test).
    let token = mint_jwt_with_kid(
        &priv_pem,
        "test-key-1",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);
    let (result, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(!result.continue_processing);
    let v = result.violation.expect("violation reported");
    assert_eq!(v.code, "auth.jwks_unavailable");
    assert!(
        v.reason.contains(ISS),
        "reason should name the affected issuer: {}",
        v.reason,
    );
}

// ---- configuration faults are fatal, IdP faults are not ----------------
//
// The counterpart to `jwks_unreachable_at_initialize_soft_fails` above.
// Soft-fail exists so a gateway survives an `IdP` that is down right now.
// It must not extend to faults that no retry clears, because there the
// gateway boots holding an empty key store, denies every token from the
// issuer for the life of the process, and denies it with
// `auth.jwks_unavailable`, which points the operator at an `IdP` that was
// never contacted.

/// Register one resolver and initialize, returning the failure message.
///
/// `http` is `None` for the case where the host wired no transport at all.
async fn init_outcome(cfg: PluginConfig, http: Option<&Arc<FakeTransport>>) -> Result<(), String> {
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    if let Some(h) = http {
        install(&mgr, h);
    }
    mgr.initialize().await.map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_wired_no_transport_fails_initialization() {
    // Nothing in policy YAML fixes this, so the message must not send an
    // operator hunting through their own config.
    let err = init_outcome(resolver_config(&jwks_url()), None)
        .await
        .expect_err("a jwks_url issuer with no transport cannot start");
    assert!(
        err.contains("embedding host"),
        "the message must name the host as the thing to fix: {err}"
    );
    assert!(err.contains(ISS), "and name the issuer affected: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn withholding_perform_http_fails_initialization_and_names_the_capability() {
    // The opposite owner: the host did its part and the fix is one line
    // of the operator's own config. Previously this booted and denied
    // every token, with a warning as the only clue.
    let http = Arc::new(FakeTransport::new());
    let mut cfg = resolver_config(&jwks_url());
    cfg.capabilities.clear();

    let err = init_outcome(cfg, Some(&http))
        .await
        .expect_err("a jwks_url issuer without perform_http cannot start");
    assert!(
        err.contains("perform_http"),
        "the message must name the capability to add: {err}"
    );
    assert_eq!(
        http.call_count(),
        0,
        "the gate is checked before anything is dialled"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_jwks_url_fails_initialization() {
    // Decided from config text alone — the transport is never asked for
    // anything. An `IdP` that genuinely serves plaintext is reached by
    // setting `insecure_http`, so nothing here is unreachable by design.
    let http = Arc::new(FakeTransport::new());
    let cfg = resolver_config(&format!("http://idp.example.test{CERTS_PATH}"));

    let err = init_outcome(cfg, Some(&http))
        .await
        .expect_err("a plaintext jwks_url cannot start");
    assert!(err.contains("insecure_http"), "{err}");
    assert_eq!(
        http.call_count(),
        0,
        "a rejected scheme must not produce a request"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_misconfigured_issuer_is_named_in_one_message() {
    // Reporting the first and stopping would make a deployment with three
    // mistakes take three fix-and-restart cycles to discover them all.
    let http = Arc::new(FakeTransport::new());
    let mut cfg = resolver_config(&jwks_url());
    cfg.config = Some(json!({
        "role": "user",
        "header": "Authorization",
        "trusted_issuers": [
            {
                "issuer": "https://a.example.test",
                "audiences": [AUD],
                "algorithms": ["RS256"],
                "decoding_key": { "kind": "jwks_url", "url": "http://a.example.test/certs" },
                "leeway_seconds": 60,
            },
            {
                "issuer": "https://b.example.test",
                "audiences": [AUD],
                "algorithms": ["RS256"],
                "decoding_key": { "kind": "jwks_url", "url": "http://b.example.test/certs" },
                "leeway_seconds": 60,
            },
        ],
        "claim_mapper": "standard",
    }));

    let err = init_outcome(cfg, Some(&http))
        .await
        .expect_err("two plaintext jwks_urls cannot start");
    assert!(err.contains("a.example.test"), "{err}");
    assert!(err.contains("b.example.test"), "{err}");
    assert!(
        err.contains("2 of 2"),
        "the count tells an operator whether any issuer survived: {err}"
    );
}

/// Initial JWKS publishes key A; the mock then rotates to key B.
/// A token signed by B with `kid=key-b` is initially rejected
/// (`KeyStore` only knows A). After the refresh interval ticks,
/// the resolver's `KeyStore` swaps in B and the same token
/// validates. Pins both:
///   - that refresh runs without restart
///   - that whole-store replacement actually swaps (not merges,
///     not silently drops the update)
#[tokio::test(flavor = "multi_thread")]
async fn jwks_refresh_picks_up_rotated_key() {
    let mut rng = rand::thread_rng();
    let priv_a = RsaPrivateKey::new(&mut rng, 2048).expect("rsa a");
    let priv_b = RsaPrivateKey::new(&mut rng, 2048).expect("rsa b");
    let pub_a = RsaPublicKey::from(&priv_a);
    let pub_b = RsaPublicKey::from(&priv_b);
    let priv_pem_b = priv_b
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private PEM b")
        .to_string();

    let jwks_a = build_jwks(&pub_a).to_string();
    let jwks_b = build_jwks_with_kid(&pub_b, "key-b").to_string();

    // Rotation: the first fetch sees key set A, every fetch after
    // sees B. Queued replies say that directly, where the mock server
    // needed a shared counter to express it.
    let http = Arc::new(
        FakeTransport::new()
            .json(CERTS_PATH, 200, &jwks_a)
            .json(CERTS_PATH, 200, &jwks_b),
    );
    let jwks_url = jwks_url();

    // Resolver config with a short refresh — 1 second keeps the
    // test wall-clock low. The default 600s wouldn't fire inside
    // the test window. Built inline rather than via
    // `resolver_config(...)` because we need the `refresh_secs`
    // field which the shared helper doesn't expose.
    let cfg = PluginConfig {
        name: "jwt-via-jwks".into(),
        kind: "test".into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: ["perform_http".to_owned()].into(),
        config: Some(json!({
            "role": "user",
            "header": "Authorization",
            "trusted_issuers": [{
                "issuer": ISS,
                "audiences": [AUD],
                "algorithms": ["RS256"],
                "decoding_key": {
                    "kind": "jwks_url",
                    "url": jwks_url,
                    "refresh_secs": 1,
                },
                "leeway_seconds": 60,
            }],
            "claim_mapper": "standard",
        })),
        ..Default::default()
    };

    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::clone(&resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .unwrap();
    install(&mgr, &http);
    mgr.initialize().await.expect("initialize");

    // A token signed by key B, which the resolver does not yet know:
    // initialize only fetched key set A.
    let make_payload = || {
        let token = mint_jwt_with_kid(
            &priv_pem_b,
            "key-b",
            json!({
                "sub": "alice",
                "iss": ISS,
                "aud": AUD,
                "exp": now_unix() + 300,
                "iat": now_unix(),
            }),
        );
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".into(), format!("Bearer {token}"));
        IdentityPayload::new(token, TokenSource::Bearer)
            .with_source_header("Authorization")
            .with_headers(headers)
    };

    // The very first token carrying the rotated kid succeeds. No sleep,
    // no polling: the unknown kid *is* the trigger, so recovery happens
    // inside this one request rather than at some later tick.
    let (first, _) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            make_payload(),
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        first.continue_processing,
        "the first token needing the rotated key must trigger a refresh and validate, \
         got violation {:?}",
        first.violation
    );

    assert_eq!(
        http.call_count_for(CERTS_PATH),
        2,
        "one fetch at initialize, one triggered by the unknown kid"
    );

    // A second token needs no further fetch: the refreshed store
    // already holds key B, so nothing re-triggers.
    let (second, _) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            make_payload(),
            Extensions::default(),
            None,
        )
        .await;
    assert!(second.continue_processing);
    assert_eq!(
        http.call_count_for(CERTS_PATH),
        2,
        "a token the current keys can verify must not trigger a fetch"
    );
}

// =====================================================================
// on-demand refresh: the bounds, and the runtime bug it exists to fix
// =====================================================================

/// Build a resolver + engine for `http`, with one JWKS issuer.
async fn engine_for(http: &Arc<FakeTransport>) -> Arc<PolicyEngine> {
    let cfg = resolver_config(&jwks_url());
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(resolver, cfg, &[HOOK_IDENTITY_RESOLVE])
        .unwrap();
    install(&mgr, http);
    mgr
}

/// A token for an issuer whose kid the resolver will not know.
fn unknown_kid_payload(priv_pem: &str) -> IdentityPayload {
    let token = mint_jwt_with_kid(
        priv_pem,
        "never-published",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers)
}

/// An unknown `kid` triggers at most one fetch, however many requests
/// arrive at once.
///
/// A rotation makes every in-flight token fail simultaneously. Without
/// single-flight each would fetch, and the `IdP` would take a stampede
/// at exactly the moment it just rolled its keys — turning a routine
/// operation into an incident.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_unknown_kids_produce_one_fetch() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();

    let http =
        Arc::new(FakeTransport::new().json(CERTS_PATH, 200, &build_jwks(&pub_key).to_string()));
    let mgr = engine_for(&http).await;
    mgr.initialize().await.expect("initialize");
    assert_eq!(http.call_count_for(CERTS_PATH), 1, "the boot fetch");

    let mut handles = Vec::new();
    for _ in 0..8 {
        let mgr = Arc::clone(&mgr);
        let pem = priv_pem.clone();
        handles.push(tokio::spawn(async move {
            mgr.invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                unknown_kid_payload(&pem),
                Extensions::default(),
                None,
            )
            .await
        }));
    }
    for h in handles {
        let (r, _) = h.await.expect("task");
        assert!(!r.continue_processing, "the kid is genuinely unpublished");
    }

    assert_eq!(
        http.call_count_for(CERTS_PATH),
        2,
        "eight concurrent unknown kids must collapse into one refresh"
    );
}

/// A second unknown `kid` inside the floor triggers no fetch at all.
///
/// This is the amplification guard. An unknown `kid` is reachable with
/// an unauthenticated request, so without a floor a stream of invented
/// `kid`s would be a denial-of-service pointed at your own `IdP`.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_unknown_kid_inside_the_floor_does_not_refetch() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();

    let http =
        Arc::new(FakeTransport::new().json(CERTS_PATH, 200, &build_jwks(&pub_key).to_string()));
    let mgr = engine_for(&http).await;
    mgr.initialize().await.expect("initialize");

    for _ in 0..5 {
        let (r, _) = mgr
            .invoke_named::<IdentityHook>(
                HOOK_IDENTITY_RESOLVE,
                unknown_kid_payload(&priv_pem),
                Extensions::default(),
                None,
            )
            .await;
        assert!(!r.continue_processing);
    }

    assert_eq!(
        http.call_count_for(CERTS_PATH),
        2,
        "five invented kids must cost the IdP one fetch, not five"
    );
}

/// A failed boot fetch recovers on a later request rather than denying
/// for the life of the process.
///
/// The design deliberately does not crash when the `IdP` is unreachable
/// at startup. Before on-demand refresh that soft-fail was permanent
/// under any host that dropped the runtime it initialized on: a
/// four-second `IdP` blip during a rolling restart bricked authentication
/// for that issuer until someone restarted the gateway again.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_boot_fetch_recovers_on_a_later_request() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();

    // Unreachable at boot, healthy afterwards.
    let http = Arc::new(
        FakeTransport::new()
            .fail(CERTS_PATH, HttpTransportError::Connect("refused".into()))
            .json(CERTS_PATH, 200, &build_jwks(&pub_key).to_string()),
    );
    let mgr = engine_for(&http).await;
    mgr.initialize()
        .await
        .expect("a failed JWKS fetch must not stop the gateway booting");

    let token = mint_jwt(
        &priv_pem,
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);

    let (r, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        r.continue_processing,
        "an empty key store must refresh on use, got {:?}",
        r.violation
    );
}

/// Refresh survives the runtime that ran `initialize()` being dropped.
///
/// This reproduces the host pattern that made the old background ticker
/// useless: a sync filter factory drives async initialization on a
/// throwaway current-thread runtime, which is dropped as soon as
/// initialization returns. `tokio::spawn` binds a task to whichever
/// runtime is current, and dropping a runtime cancels its tasks — so the
/// ticker was cancelled before it ever fired, and JWKS rotation silently
/// never happened.
///
/// Nothing is spawned any more, so there is nothing to cancel. The shape
/// of this test is the point: the old code could not have passed it, and
/// no test in the previous suite had this shape.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_works_after_the_initialize_runtime_is_dropped() {
    let mut rng = rand::thread_rng();
    let priv_key_a = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_a = RsaPublicKey::from(&priv_key_a);
    let priv_key_b = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_b = RsaPublicKey::from(&priv_key_b);
    let priv_pem_b = priv_key_b
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();

    let jwks_a = build_jwks_with_kid(&pub_a, "key-a").to_string();
    let jwks_b = build_jwks_with_kid(&pub_b, "key-b").to_string();
    let http = Arc::new(
        FakeTransport::new()
            .json(CERTS_PATH, 200, &jwks_a)
            .json(CERTS_PATH, 200, &jwks_b),
    );
    let mgr = engine_for(&http).await;

    // Initialize on a dedicated runtime, then drop it — exactly what a
    // sync filter factory does.
    let mgr_for_init = Arc::clone(&mgr);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("init runtime");
        rt.block_on(async { mgr_for_init.initialize().await.expect("initialize") });
        // `rt` drops here. Anything spawned during initialization dies
        // with it.
    })
    .join()
    .expect("init thread");

    // Now, on the serving runtime, a token needing the rotated key.
    let token = mint_jwt_with_kid(
        &priv_pem_b,
        "key-b",
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    let payload = IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers);

    let (r, _) = mgr
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(
        r.continue_processing,
        "rotation must recover even though the initialize runtime is gone, got {:?}",
        r.violation
    );
}

// =====================================================================
// what a request pays for a refresh
// =====================================================================
//
// Refreshing from the verify path means a request can end up waiting on
// an `IdP`. These pin the three bounds that keep that affordable: one
// attempt rather than a retry loop, no queueing behind a refresh the
// request does not need, and a conditional request so the common case
// costs a round trip instead of a document.

/// A resolver whose staleness and floor are set by the test.
///
/// `refresh_secs: 0` makes the key set stale the moment it is fetched,
/// which is how a test reaches the opportunistic path without waiting
/// out a real interval.
fn tuned_config(refresh_secs: u64, min_refresh_interval_secs: u64) -> PluginConfig {
    let mut cfg = resolver_config(&jwks_url());
    cfg.config = Some(json!({
        "role": "user",
        "header": "Authorization",
        "trusted_issuers": [{
            "issuer": ISS,
            "audiences": [AUD],
            "algorithms": ["RS256"],
            "decoding_key": {
                "kind": "jwks_url",
                "url": jwks_url(),
                "refresh_secs": refresh_secs,
                "min_refresh_interval_secs": min_refresh_interval_secs,
            },
            "leeway_seconds": 60,
        }],
        "claim_mapper": "standard",
    }));
    cfg
}

async fn engine_with(cfg: PluginConfig, http: &Arc<FakeTransport>) -> Arc<PolicyEngine> {
    let resolver = Arc::new(JwtIdentityResolver::new(cfg.clone()).expect("constructs"));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(resolver, cfg, &[HOOK_IDENTITY_RESOLVE])
        .unwrap();
    install(&mgr, http);
    mgr
}

/// A valid token for `priv_pem`, signed under the `kid` the JWKS
/// publishes.
fn valid_payload(priv_pem: &str) -> IdentityPayload {
    let token = mint_jwt(
        priv_pem,
        json!({
            "sub": "alice",
            "iss": ISS,
            "aud": AUD,
            "exp": now_unix() + 300,
            "iat": now_unix(),
        }),
    );
    let mut headers = std::collections::HashMap::new();
    headers.insert("Authorization".into(), format!("Bearer {token}"));
    IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("Authorization")
        .with_headers(headers)
}

/// A refresh a request is waiting on makes exactly one attempt.
///
/// The boot fetch retries three times, which is right when nothing is
/// waiting. On the verify path those same three attempts are the
/// request's latency — against a 5s per-attempt timeout that was roughly
/// fifteen seconds, with every concurrent request for the issuer queued
/// behind it. The retry that matters here is the next request, not a
/// second attempt inside this one.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_a_request_waits_on_makes_one_attempt() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();

    // Healthy at boot, then refuses every subsequent attempt. Three
    // failures are queued so a retry loop would consume them and show up
    // in the count.
    let http = Arc::new(
        FakeTransport::new()
            .json(CERTS_PATH, 200, &build_jwks(&pub_key).to_string())
            .fail(CERTS_PATH, HttpTransportError::Connect("refused".into()))
            .fail(CERTS_PATH, HttpTransportError::Connect("refused".into()))
            .fail(CERTS_PATH, HttpTransportError::Connect("refused".into())),
    );
    let mgr = engine_with(tuned_config(3600, 0), &http).await;
    mgr.initialize().await.expect("boot fetch succeeds");
    assert_eq!(http.call_count_for(CERTS_PATH), 1, "one boot fetch");

    // An unknown `kid` is the Required path: the token cannot validate
    // without keys we do not hold, so this request does wait.
    let (r, _) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            unknown_kid_payload(&priv_pem),
            Extensions::default(),
            None,
        )
        .await;
    assert!(!r.continue_processing, "an unpublished kid still denies");

    assert_eq!(
        http.call_count_for(CERTS_PATH),
        2,
        "the refresh must make one attempt, not a retry loop's worth"
    );
}

/// A token the held keys can verify is never denied because a refresh
/// failed, and never made to wait for one it does not need.
///
/// This is the case that used to add latency for nothing: keys past
/// `refresh_secs`, a token that validates against them perfectly, and a
/// blocking fetch in front of the answer anyway.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_but_valid_token_survives_a_failing_refresh() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();

    let http = Arc::new(
        FakeTransport::new()
            .json(CERTS_PATH, 200, &build_jwks(&pub_key).to_string())
            .fail(CERTS_PATH, HttpTransportError::Connect("refused".into())),
    );
    // Stale immediately, and no floor, so the opportunistic path is
    // reached on the very first request.
    let mgr = engine_with(tuned_config(0, 0), &http).await;
    mgr.initialize().await.expect("boot fetch succeeds");

    let (r, _) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            valid_payload(&priv_pem),
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        r.continue_processing,
        "a failed refresh must not widen into denying a token the held \
         keys verify, got {:?}",
        r.violation
    );
}

/// Concurrent stale-but-valid requests do not queue behind one refresh.
///
/// Single-flight already kept a burst to one *fetch* — the waiters woke,
/// saw a newer generation and skipped fetching. What it did not do was
/// keep them from *waiting*: every concurrent request sat on
/// `lock().await` for however long the leader's fetch took, which with
/// the old three-attempt retry loop was up to about fifteen seconds. And
/// each of those requests already had a correct answer from keys it
/// held.
///
/// So the assertion is about who pays, not how many fetches happen. One
/// request may pay for the refresh. The rest must decline to queue and
/// answer immediately.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_stale_but_valid_requests_do_not_queue_behind_a_refresh() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();
    let jwks = build_jwks(&pub_key).to_string();

    // Latency is what makes the calls actually overlap, and what makes
    // "did this request wait" measurable at all. Against an instant
    // transport every request finishes before the next starts, so
    // waiting and not waiting look identical.
    const FETCH: Duration = Duration::from_millis(300);
    let mut http = FakeTransport::new().with_latency(FETCH);
    for _ in 0..12 {
        http = http.json(CERTS_PATH, 200, &jwks);
    }
    let http = Arc::new(http);
    let mgr = engine_with(tuned_config(0, 0), &http).await;
    mgr.initialize().await.expect("boot fetch succeeds");

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let mgr = Arc::clone(&mgr);
        let payload = valid_payload(&priv_pem);
        tasks.push(tokio::spawn(async move {
            let started = std::time::Instant::now();
            let (r, _) = mgr
                .invoke_named::<IdentityHook>(
                    HOOK_IDENTITY_RESOLVE,
                    payload,
                    Extensions::default(),
                    None,
                )
                .await;
            (r, started.elapsed())
        }));
    }

    let mut waited = 0;
    for t in tasks {
        let (r, elapsed) = t.await.expect("task");
        assert!(
            r.continue_processing,
            "every request validated against keys already held, got {:?}",
            r.violation
        );
        // Half the fetch is comfortably past any scheduling noise and
        // comfortably short of having actually waited one out.
        if elapsed >= FETCH / 2 {
            waited += 1;
        }
    }

    assert!(
        waited <= 1,
        "{waited} of 8 requests waited out a refresh none of them needed; \
         at most the one doing the fetch should have"
    );
}

/// A refresh sends `If-None-Match` when the `IdP` gave us a validator,
/// and a `304` keeps the keys already held.
///
/// This is what makes refreshing on a request path affordable: the
/// common refresh — keys stale, `IdP` has not rotated — costs a round
/// trip rather than a document. It also pins the `304` handling, where
/// the reflexive `!is_success()` would turn a successful revalidation
/// into a fetch failure, and for this plugin that failure is
/// fail-closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_revalidates_conditionally_and_a_304_keeps_the_keys() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .to_string();

    let mut etagged = HeaderMap::new();
    etagged.insert("etag", "\"jwks-v1\"".parse().expect("a legal header value"));

    let http = Arc::new(
        FakeTransport::new()
            .respond(
                CERTS_PATH,
                200,
                &build_jwks(&pub_key).to_string(),
                etagged.clone(),
            )
            // The revalidation: unchanged, no body.
            .respond(CERTS_PATH, 304, "", etagged),
    );
    let mgr = engine_with(tuned_config(0, 0), &http).await;
    mgr.initialize().await.expect("boot fetch succeeds");

    let (r, _) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            valid_payload(&priv_pem),
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        r.continue_processing,
        "a 304 confirms the held keys rather than clearing them, got {:?}",
        r.violation
    );

    let reqs = http.requests();
    assert_eq!(reqs.len(), 2, "boot fetch then one revalidation");
    assert!(
        reqs[0].headers.get("if-none-match").is_none(),
        "the boot fetch holds no document to revalidate against"
    );
    assert_eq!(
        reqs[1]
            .headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok()),
        Some("\"jwks-v1\""),
        "the refresh must send back the validator the IdP gave us, \
         quotes and all"
    );

    // And the keys survived the 304 rather than being replaced by the
    // empty body that came with it.
    let (r2, _) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            valid_payload(&priv_pem),
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        r2.continue_processing,
        "the key set must outlive a revalidation, got {:?}",
        r2.violation
    );
}
