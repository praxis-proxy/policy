// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hostile inbound tokens stop at identity, before any CMF hook, delegation
//! or upstream call.
//!
//! The claim checks themselves are pinned in
//! `crates/builtins/tests/jwt/jwt_e2e.rs`. These cases show the identity
//! deny holds the whole pipeline.

use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{self, Persona, Signer};
use serde_json::{Value, json};

use crate::support::{self, JANE_SSN, assert_identity_deny, planted_for, realm_kid};

/// Hold the realm key id constant while varying hostile JOSE fields.
fn header(extra: Value) -> Value {
    let mut h = json!({ "alg": "RS256", "typ": "JWT", "kid": realm_kid() });
    if let (Some(h), Value::Object(extra)) = (h.as_object_mut(), extra) {
        h.extend(extra);
    }
    h
}

/// Hold the legitimate persona constant while varying one hostile claim.
fn bob_with(extra: Value) -> Value {
    let mut c = Persona::Bob.claims();
    if let (Some(c), Value::Object(extra)) = (c.as_object_mut(), extra) {
        c.extend(extra);
    }
    c
}

/// Keep the route fixed so a denial is attributable to the supplied token.
fn compensation_as(user_token: &str) -> Call {
    Call::new(Persona::Bob, "get_compensation")
        .args(json!({ "employee_id": "EMP-001234", "include_ssn": true }))
        .header("x-user-token", user_token)
}

/// Use the signed token issue time to avoid wall-clock drift in expiry cases.
fn now() -> i64 {
    idp::claims_of(&Persona::Bob.token()).expect("a JWT")["iat"]
        .as_i64()
        .expect("iat")
}

/// Covers AE5.
#[tokio::test]
async fn each_invalid_user_token_stops_at_identity() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let realm = idp::sign(&Persona::Bob.claims());
    let segments: Vec<&str> = realm.split('.').collect();
    let modulus = idp::jwks()["keys"][0]["n"].as_str().expect("n").to_owned();
    let no_kid = json!({ "alg": "RS256", "typ": "JWT" });

    let cases = [
        (
            "alg none",
            idp::forge(
                &json!({ "alg": "none", "typ": "JWT" }),
                &Persona::Bob.claims(),
                Signer::Unsigned,
            ),
            "auth.malformed_header",
        ),
        (
            "HS256 keyed with the published RSA modulus",
            idp::forge(
                &header(json!({ "alg": "HS256" })),
                &Persona::Bob.claims(),
                Signer::Hs256(modulus.as_bytes()),
            ),
            "auth.algorithm_mismatch",
        ),
        (
            "wrong iss",
            idp::sign(&bob_with(
                json!({ "iss": "https://evil.test/realms/policy-demo" }),
            )),
            "auth.untrusted_issuer",
        ),
        (
            "wrong aud",
            idp::sign(&bob_with(json!({ "aud": "some-other-app" }))),
            "auth.audience_mismatch",
        ),
        (
            "expired past the leeway",
            idp::sign(&bob_with(json!({ "exp": now() - 3600 }))),
            "auth.token_expired",
        ),
        (
            "nbf in the future",
            idp::sign(&bob_with(json!({ "nbf": now() + 3600 }))),
            "auth.token_not_yet_valid",
        ),
        (
            "missing kid",
            idp::forge(&no_kid, &Persona::Bob.claims(), Signer::Realm),
            "auth.unknown_kid",
        ),
        (
            "a foreign key under the realm kid",
            idp::forge(&header(json!({})), &Persona::Bob.claims(), Signer::Foreign),
            "auth.signature_invalid",
        ),
        (
            "truncated to two segments",
            format!("{}.{}", segments[0], segments[1]),
            "auth.malformed_header",
        ),
        (
            "non-base64 payload",
            format!("{}.!!not*base64!!.{}", segments[0], segments[2]),
            "auth.malformed_header",
        ),
        (
            "non-base64 signature",
            format!("{}.{}.!!not*base64!!", segments[0], segments[1]),
            "auth.malformed_header",
        ),
    ];
    for (label, token, code) in cases {
        let call = compensation_as(&token);
        let planted = planted_for(&call);
        let out = host.call(call).await;
        assert_eq!(out.violation_code(), Some(code), "{label}");
        assert_identity_deny(&host, &out, code, &planted);
    }
}

/// `jwk`, `jku` and `x5u` name a key the token's own author chose. The
/// resolver selects by `kid` from the issuer's JWKS only, and fetches
/// nothing a token names.
#[tokio::test]
async fn an_embedded_key_or_key_url_is_neither_trusted_nor_fetched() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let attacker = idp::foreign_jwk("attacker-1");
    let jku = "https://attacker.test/.well-known/jwks.json";
    let x5u = "https://attacker.test/cert.pem";
    let cases = [
        (
            "jwk without kid",
            json!({ "alg": "RS256", "typ": "JWT", "jwk": attacker }),
            "auth.unknown_kid",
        ),
        (
            "jwk under the realm kid",
            header(json!({ "jwk": attacker })),
            "auth.signature_invalid",
        ),
        (
            "jku with the attacker kid",
            header(json!({ "jku": jku, "kid": "attacker-1" })),
            "auth.unknown_kid",
        ),
        (
            "x5u under the realm kid",
            header(json!({ "x5u": x5u })),
            "auth.signature_invalid",
        ),
    ];
    for (label, h, code) in cases {
        let call = compensation_as(&idp::forge(&h, &Persona::Bob.claims(), Signer::Foreign));
        let planted = planted_for(&call);
        let out = host.call(call).await;
        assert_eq!(out.violation_code(), Some(code), "{label}");
        assert_identity_deny(&host, &out, code, &planted);
    }
    assert_eq!(host.transport().call_count_for("attacker.test"), 0);
    for request in host.transport().requests() {
        assert_eq!(request.url, idp::JWKS_URL, "only the realm JWKS is fetched");
    }
}

const PARTNER_ISSUER: &str = "https://partner-idp.test/realms/partner";
const PARTNER_JWKS_URL: &str = "https://partner-idp.test/realms/partner/certs";
const PARTNER_KID: &str = "partner-rs256";

/// The cedar fixture with a second trusted issuer on `jwt-user`, whose JWKS
/// publishes the foreign key under [`PARTNER_KID`].
async fn two_issuer_host() -> RefHost {
    let anchor = "      header: X-User-Token\n      trusted_issuers:\n";
    let partner = format!(
        "{anchor}        - issuer: \"{PARTNER_ISSUER}\"\n          \
         audiences: [\"praxis-gateway\"]\n          algorithms: [\"RS256\"]\n          \
         decoding_key:\n            kind: jwks_url\n            url: \"{PARTNER_JWKS_URL}\"\n"
    );
    let yaml = Fixture::Cedar.hermetic().replacen(anchor, &partner, 1);
    assert_ne!(yaml, Fixture::Cedar.hermetic(), "the anchor matched");
    let jwks = json!({ "keys": [idp::foreign_jwk(PARTNER_KID)] });
    RefHost::builder()
        .transport(FakeTransport::new().json(PARTNER_JWKS_URL, 200, &jwks.to_string()))
        .start(&yaml)
        .await
        .expect("the two-issuer fixture starts")
}

/// Issuer A's `iss` with issuer B's `kid`, signed by B's key. Key stores
/// are per issuer, so B's key never verifies a token claiming A.
#[tokio::test]
async fn a_kid_from_another_trusted_issuer_does_not_cross_over() {
    let host = two_issuer_host().await;
    let partner = json!({ "alg": "RS256", "typ": "JWT", "kid": PARTNER_KID });

    // Control: the same key verifies a token that names its own issuer.
    let own = idp::forge(
        &partner,
        &bob_with(json!({ "iss": PARTNER_ISSUER })),
        Signer::Foreign,
    );
    let call = compensation_as(&own);
    let mut planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    planted.plant("minted workday token", support::forwarded_bearer(&out));
    out.assert_no_leaks(&planted);

    let crossed = idp::forge(&partner, &Persona::Bob.claims(), Signer::Foreign);
    let call = compensation_as(&crossed);
    let planted = planted_for(&call);
    let upstream_before = host.upstream().requests().len();
    let exchanges_before = host.transport().call_count_for(idp::TOKEN_EXCHANGE_URL);
    let out = host.call(call).await;
    assert_eq!(out.denied_at, Some(Stage::Identity), "{:?}", out.violation);
    assert_eq!(out.violation_code(), Some("auth.unknown_kid"));
    assert!(out.events.audit_records().is_empty());
    assert_eq!(host.upstream().requests().len(), upstream_before);
    assert_eq!(
        host.transport().call_count_for(idp::TOKEN_EXCHANGE_URL),
        exchanges_before
    );
    out.assert_no_leaks(&planted);
}

/// RFC 7515 section 4.1.11: a recipient that does not understand an
/// extension listed in `crit` must reject the token. jsonwebtoken parses
/// `crit` but does not enforce it, so the resolver must reject it.
#[tokio::test]
async fn an_unknown_crit_header_is_rejected() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let token = idp::forge(
        &header(
            json!({ "crit": ["urn:example:must-understand"], "urn:example:must-understand": true }),
        ),
        &Persona::Bob.claims(),
        Signer::Realm,
    );
    let call = compensation_as(&token);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    out.assert_no_leaks(&planted);
    assert_eq!(out.denied_at, Some(Stage::Identity));
    assert_eq!(
        out.violation_code(),
        Some("auth.unsupported_critical_header")
    );
}

/// Unknown `kid`s are reachable unauthenticated, so the refresh they
/// trigger is floored by `min_refresh_interval_secs` (default 30).
#[tokio::test]
async fn a_burst_of_unknown_kids_refetches_the_jwks_at_most_once() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let before = host.transport().call_count_for(idp::JWKS_URL);
    for i in 0..20 {
        let h = header(json!({ "kid": format!("rotated-{i:02}") }));
        let call = compensation_as(&idp::forge(&h, &Persona::Bob.claims(), Signer::Realm));
        let planted = planted_for(&call);
        let out = host.call(call).await;
        assert_identity_deny(&host, &out, "auth.unknown_kid", &planted);
    }
    let refetches = host.transport().call_count_for(idp::JWKS_URL) - before;
    assert!(
        refetches <= 1,
        "{refetches} JWKS refetches inside the floor"
    );
}

/// Each header is validated for its own role, so a swapped pair grants
/// nothing the user header's subject does not hold.
#[tokio::test]
async fn swapped_user_and_client_tokens_do_not_escalate() {
    let host = RefHost::hermetic(Fixture::Cedar).await;

    // The agent's token as the user, Bob's as the client: the subject is
    // the service account, which holds no `hr` role.
    let call = compensation_as(&Persona::HrCopilot.token())
        .header("authorization", &format!("Bearer {}", Persona::Bob.token()));
    let planted_swap = planted_for(&call);
    let out = host.call(call).await;
    assert_eq!(out.denied_at, Some(Stage::Request), "{:?}", out.violation);
    assert_eq!(
        out.violation_code(),
        Some("routes.tool:get_compensation.pre_invocation[0]")
    );
    assert!(host.upstream().requests().is_empty());
    assert_eq!(host.transport().call_count_for(idp::TOKEN_EXCHANGE_URL), 0);
    out.assert_no_leaks(&planted_swap);

    // Eve as the user with Bob's token as the client: Bob's `view_ssn`
    // does not reach the redaction decision, and the exchange is for Eve.
    let call = Call::new(Persona::Eve, "get_compensation")
        .args(json!({ "employee_id": "EMP-001234", "include_ssn": true }))
        .header("authorization", &format!("Bearer {}", Persona::Bob.token()));
    let mut planted = planted_for(&call);
    planted.plant("ssn", JANE_SSN);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    let minted = support::forwarded_bearer(&out);
    assert_eq!(
        idp::claims_of(&minted).expect("a JWT")["sub"],
        Persona::Eve.sub()
    );
    planted.plant("minted workday token", minted);
    out.assert_no_leaks(&planted);
}
