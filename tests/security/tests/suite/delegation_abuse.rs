// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Delegated tokens used where they do not belong.

use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, RefHost};
use praxis_policy_test_utils::idp::{self, Persona, TOKEN_EXCHANGE_URL};
use serde_json::json;

use crate::support::{assert_identity_deny, forwarded_bearer, planted_for};

fn bob_reads_jane() -> Call {
    Call::new(Persona::Bob, "get_compensation").args(json!({ "employee_id": "EMP-001234" }))
}

/// A token minted for `workday-api` carries that audience, so neither
/// inbound header accepts it.
#[tokio::test]
async fn a_minted_downstream_token_replayed_inbound_is_rejected() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let call = bob_reads_jane();
    let mut planted_first = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    let minted = forwarded_bearer(&out);
    planted_first.plant("minted workday token", minted.clone());
    out.assert_no_leaks(&planted_first);

    // A fresh host, so the identity checks see no earlier upstream call.
    let host = RefHost::hermetic(Fixture::Cedar).await;
    for replay in [
        bob_reads_jane().header("x-user-token", &minted),
        bob_reads_jane().header("authorization", &format!("Bearer {minted}")),
    ] {
        let mut planted = planted_for(&replay);
        planted.plant("minted workday token", minted.clone());
        let out = host.call(replay).await;
        assert_identity_deny(&host, &out, "auth.audience_mismatch", &planted);
    }
}

/// One caller entitled to both routes: an exchange for `workday-api` on
/// the first call is never what the `github-api` route attaches.
#[tokio::test]
async fn a_token_minted_for_one_audience_is_not_attached_for_another() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let mut claims = Persona::Bob.claims();
    claims["roles"] = json!(["hr", "engineer"]);
    claims["teams"] = json!(["hr", "engineering"]);
    claims["gh_permissions"] = json!(["repo:read:internal"]);
    let user = idp::sign(&claims);

    let call = bob_reads_jane().header("x-user-token", &user);
    let mut planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    let workday = forwarded_bearer(&out);
    assert_eq!(
        idp::claims_of(&workday).expect("a JWT")["aud"],
        "workday-api"
    );
    planted.plant("minted workday token", workday.clone());
    out.assert_no_leaks(&planted);

    let call = Call::new(Persona::Bob, "search_repos")
        .header("x-user-token", &user)
        .args(json!({ "repo_name": "web-app", "visibility": "internal" }));
    let mut planted = planted_for(&call);
    planted.plant("minted workday token", workday.clone());
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    let seen = out.upstream.as_ref().expect("the upstream was called");
    assert!(
        seen.headers.values().all(|v| !v.contains(&workday)),
        "the workday token reached the github route"
    );
    let github = forwarded_bearer(&out);
    assert_eq!(idp::claims_of(&github).expect("a JWT")["aud"], "github-api");
    let last_form = host
        .transport()
        .requests()
        .into_iter()
        .rfind(|r| r.url == TOKEN_EXCHANGE_URL)
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .expect("an exchange request");
    assert!(last_form.contains("audience=github-api"), "{last_form}");
    assert_eq!(host.transport().call_count_for(TOKEN_EXCHANGE_URL), 2);
    planted.plant("minted github token", github);
    out.assert_no_leaks(&planted);
}
