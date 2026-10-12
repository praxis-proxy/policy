// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Live mode: the scenarios against a real Valkey, Keycloak and Vault.
//!
//! Every test is `#[ignore]` and returns after a skip line when its
//! variables are unset (see `praxis_policy_test_utils::live`). The upstream
//! stays the in-process stand-in. Keycloak 26 ignores `actor_token`, so no
//! test here asserts an `act` claim, and the token endpoint is not counted.

use std::time::{Duration, Instant};

use praxis_policy_test_utils::fixtures::{Fixture, SECRET_HEADER, SECRET_NAME};
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{Persona, claims_of};
use praxis_policy_test_utils::live::{self, Realm, Targets};
use serde_json::{Value, json};

use super::taint::{shared_session_id, tainted_session};
use super::{SSN_PROBE, adjust, each_pdp, jane, plant_minted, planted, upstream_calls};

/// A host running `fixture` with sessions in the Valkey at `url`.
async fn on_valkey(fixture: Fixture, url: &str) -> RefHost {
    let targets = Targets {
        valkey: Some(url),
        ..Targets::default()
    };
    RefHost::live(fixture, targets).await
}

/// A host running `fixture` against the live realm.
async fn on_realm(fixture: Fixture, realm: &Realm) -> RefHost {
    let targets = Targets {
        realm: Some(realm),
        ..Targets::default()
    };
    RefHost::live(fixture, targets).await
}

/// Whether a token's `aud` names `audience`, as a string or in an array.
fn has_audience(claims: &Value, audience: &str) -> bool {
    match &claims["aud"] {
        Value::String(aud) => aud == audience,
        Value::Array(auds) => auds.iter().any(|a| a == audience),
        _ => false,
    }
}

// -----------------------------------------------------------------------------
// Valkey: 08 and 09
// -----------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs VALKEY_TEST_URL"]
async fn live_valkey_an_email_from_a_tainted_session_is_denied() {
    let Some(url) = live::valkey("live_valkey 08") else {
        return;
    };
    each_pdp(move |fixture| {
        let url = url.clone();
        async move { tainted_session(on_valkey(fixture, &url).await).await }
    })
    .await;
}

#[tokio::test]
#[ignore = "needs VALKEY_TEST_URL"]
async fn live_valkey_taint_does_not_cross_principals_sharing_a_session_id() {
    let Some(url) = live::valkey("live_valkey 09") else {
        return;
    };
    each_pdp(move |fixture| {
        let url = url.clone();
        async move { shared_session_id(on_valkey(fixture, &url).await).await }
    })
    .await;
}

// -----------------------------------------------------------------------------
// Keycloak: 01 to 06 and 12
// -----------------------------------------------------------------------------

/// 01.
#[tokio::test]
#[ignore = "needs PPE_KEYCLOAK_URL"]
async fn live_keycloak_bob_reads_compensation_with_a_delegated_token() {
    let Some(realm) = live::keycloak("live_keycloak 01") else {
        return;
    };
    each_pdp(move |fixture| {
        let realm = realm.clone();
        async move {
            let host = on_realm(fixture, &realm).await;
            let call = realm.call(Persona::Bob, "get_compensation").await;
            let call = call.args(jane(true));
            let mut planted = planted(&call);
            let out = host.call(call).await;
            assert!(out.allowed(), "{:?}", out.violation);
            let seen = out.upstream.as_ref().expect("the upstream was called");
            let bearer = seen.jwt_claims("authorization").expect("a bearer");
            assert!(has_audience(&bearer, "workday-api"), "{:?}", bearer["aud"]);
            assert!(!seen.headers.contains_key("x-user-token"));
            assert_eq!(seen.arguments["ssn"], SSN_PROBE);
            assert_eq!(out.record().expect("a record")["ssn"], "123-45-6789");
            plant_minted(&mut planted, &out);
            out.assert_no_leaks(&planted);
        }
    })
    .await;
}

/// 02, 05 and 06: a deny before the upstream, by `code` or by the PDP.
async fn denied(
    realm: &Realm,
    fixture: Fixture,
    user: Persona,
    tool: &str,
    args: Value,
    code: &str,
) {
    let host = on_realm(fixture, realm).await;
    let call = realm.call(user, tool).await.args(args);
    let planted = planted(&call);
    let out = host.call(call).await;
    assert_eq!(out.denied_at, Some(Stage::Request), "{tool}");
    let code = if code.is_empty() {
        fixture.deny_violation()
    } else {
        code
    };
    assert_eq!(out.violation_code(), Some(code), "{tool}");
    assert_eq!(upstream_calls(&host), 0, "{tool}");
    out.assert_no_leaks(&planted);
}

#[tokio::test]
#[ignore = "needs PPE_KEYCLOAK_URL"]
async fn live_keycloak_denies_at_the_gates_and_the_pdp() {
    let Some(realm) = live::keycloak("live_keycloak 02, 05, 06") else {
        return;
    };
    each_pdp(move |fixture| {
        let realm = realm.clone();
        async move {
            // 02: the role gate.
            let gate = "routes.tool:get_compensation.pre_invocation[0]";
            denied(
                &realm,
                fixture,
                Persona::Alice,
                "get_compensation",
                jane(false),
                gate,
            )
            .await;
            // 05: the PDP.
            let external = json!({ "repo_name": "partner-sdk", "visibility": "external" });
            denied(
                &realm,
                fixture,
                Persona::Alice,
                "search_repos",
                external,
                "",
            )
            .await;
            // 06: the team gate.
            let gate = "routes.tool:search_repos.pre_invocation[0]";
            let internal = json!({ "visibility": "internal" });
            denied(
                &realm,
                fixture,
                Persona::Bob,
                "search_repos",
                internal,
                gate,
            )
            .await;
        }
    })
    .await;
}

/// 03.
#[tokio::test]
#[ignore = "needs PPE_KEYCLOAK_URL"]
async fn live_keycloak_eve_gets_compensation_with_the_ssn_redacted_both_ways() {
    let Some(realm) = live::keycloak("live_keycloak 03") else {
        return;
    };
    each_pdp(move |fixture| {
        let realm = realm.clone();
        async move {
            let host = on_realm(fixture, &realm).await;
            let call = realm.call(Persona::Eve, "get_compensation").await;
            let call = call.args(jane(true));
            let mut planted = planted(&call);
            planted.plant("ssn", "123-45-6789");
            let out = host.call(call).await;
            assert!(out.allowed(), "{:?}", out.violation);
            let seen = out.upstream.as_ref().expect("the upstream was called");
            assert_eq!(seen.arguments["ssn"], "[REDACTED]");
            assert_eq!(out.record().expect("a record")["ssn"], "[REDACTED]");
            plant_minted(&mut planted, &out);
            out.assert_no_leaks(&planted);
        }
    })
    .await;
}

/// 04.
#[tokio::test]
#[ignore = "needs PPE_KEYCLOAK_URL"]
async fn live_keycloak_alice_searches_an_internal_repo_with_a_github_token() {
    let Some(realm) = live::keycloak("live_keycloak 04") else {
        return;
    };
    each_pdp(move |fixture| {
        let realm = realm.clone();
        async move {
            let host = on_realm(fixture, &realm).await;
            let call = realm.call(Persona::Alice, "search_repos").await;
            let call = call.args(json!({ "repo_name": "web-app", "visibility": "internal" }));
            let mut planted = planted(&call);
            let out = host.call(call).await;
            assert!(out.allowed(), "{:?}", out.violation);
            let seen = out.upstream.as_ref().expect("the upstream was called");
            let bearer = seen.jwt_claims("authorization").expect("a bearer");
            assert!(has_audience(&bearer, "github-api"), "{:?}", bearer["aud"]);
            let record = out.record().expect("a record");
            assert_eq!(record["matches"][0]["name"], "internal/web-app");
            plant_minted(&mut planted, &out);
            out.assert_no_leaks(&planted);
        }
    })
    .await;
}

/// 12.
#[tokio::test]
#[ignore = "needs PPE_KEYCLOAK_URL"]
async fn live_keycloak_the_upstream_sees_asserted_identity() {
    let Some(realm) = live::keycloak("live_keycloak 12") else {
        return;
    };
    each_pdp(move |fixture| {
        let realm = realm.clone();
        async move {
            let host = on_realm(fixture, &realm).await;
            let user = realm.token(Persona::Bob).await;
            let agent = realm.token(Persona::HrCopilot).await;
            let sub = claims_of(&user).expect("a JWT")["sub"].clone();
            let call = Call::with_tokens("get_compensation", &user, &agent)
                .args(jane(true))
                .header("x-auth-user-id", "root");
            let mut planted = planted(&call);
            let out = host.call(call).await;
            assert!(out.allowed(), "{:?}", out.violation);
            let seen = out.upstream.as_ref().expect("the upstream was called");
            let header = |name: &str| seen.headers.get(name).map(String::as_str);
            assert_eq!(header("x-auth-user-id"), sub.as_str(), "spoof replaced");
            assert_eq!(header("x-auth-username"), Some("bob"));
            let roles = header("x-auth-roles").unwrap_or_default();
            assert!(roles.split(',').any(|r| r == "hr"), "{roles}");
            assert_eq!(header("x-user-token"), None);
            plant_minted(&mut planted, &out);
            out.assert_no_leaks(&planted);
        }
    })
    .await;
}

// -----------------------------------------------------------------------------
// CIBA: 11, when the channel approves on its own
// -----------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs PPE_KEYCLOAK_URL and PPE_CIBA_AUTO_APPROVE"]
async fn live_ciba_a_large_adjustment_applies_after_approval() {
    let Some(realm) = live::ciba("live_ciba 11") else {
        return;
    };
    each_pdp(move |fixture| {
        let realm = realm.clone();
        async move {
            let host = on_realm(fixture, &realm).await;
            let call = realm.call(Persona::Bob, "adjust_compensation").await;
            let call = call.args(adjust(25_000));
            let secrets = planted(&call);
            let out = host.call(call.clone()).await;
            assert_eq!(out.denied_at, Some(Stage::Request));
            assert_eq!(out.violation_code(), Some("elicitation.pending"));
            assert_eq!(upstream_calls(&host), 0);
            out.assert_no_leaks(&secrets);
            let id = out
                .detail("elicitation_id")
                .and_then(Value::as_str)
                .expect("an elicitation id")
                .to_owned();

            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let peek = host.call(call.clone().elicitation_id(&id).peek()).await;
                assert_eq!(peek.denied_at, Some(Stage::Request));
                assert_eq!(upstream_calls(&host), 0, "a peek does not apply");
                peek.assert_no_leaks(&secrets);
                match peek.violation_code() {
                    Some("elicitation.approved") => break,
                    Some("elicitation.pending") if Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    },
                    other => panic!("no approval: {other:?}"),
                }
            }
            let out = host.call(call.elicitation_id(&id)).await;
            assert!(out.allowed(), "{:?}", out.violation);
            assert_eq!(upstream_calls(&host), 1);
            out.assert_no_leaks(&secrets);
            assert_eq!(out.record().expect("a record")["status"], "applied");
        }
    })
    .await;
}

// -----------------------------------------------------------------------------
// Vault
// -----------------------------------------------------------------------------

/// The `x-api-key` assertion sourced from a real Vault. The scripted identity provider
/// still issues the tokens.
#[tokio::test]
#[ignore = "needs VAULT_ADDR, VAULT_ROLE_ID and VAULT_SECRET_ID"]
async fn live_vault_a_secret_assertion_reaches_only_the_upstream() {
    let Some(vault) = live::vault("live_vault") else {
        return;
    };
    let targets = Targets {
        vault: Some(&vault),
        ..Targets::default()
    };
    let host = RefHost::builder()
        .live(targets.bases())
        .start(&targets.rewrite(SECRET_HEADER))
        .await
        .expect("the secret fixture starts");
    let call = Call::new(Persona::Bob, "get_directory").args(json!({ "department": "hr" }));
    let mut planted = call.planted();
    planted.plant("approle secret id", vault.secret_id());
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);

    let seen = out.upstream.as_ref().expect("the upstream was called");
    let key = seen.headers.get("x-api-key").cloned().unwrap_or_default();
    assert!(!key.is_empty(), "{SECRET_NAME} reaches the upstream");
    planted.plant("vault-sourced api key", key);
    out.assert_no_leaks(&planted);
}
