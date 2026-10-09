// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 04 to 06: `search_repos`, gated by APL, then the PDP, then a delegated
//! `github-api` token.

use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{Persona, TOKEN_EXCHANGE_URL};
use serde_json::json;

use super::{each_pdp, plant_minted, planted, upstream_calls};

/// 04: the PDP permits an engineer on an internal repo.
#[tokio::test]
async fn alice_searches_an_internal_repo_with_a_github_token() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Alice, "search_repos")
            .args(json!({ "repo_name": "web-app", "visibility": "internal" }));
        let mut planted = planted(&call);
        let out = host.call(call).await;
        assert!(out.allowed(), "{:?}", out.violation);
        assert_eq!(upstream_calls(&host), 1);

        let seen = out.upstream.as_ref().expect("the upstream was called");
        let bearer = seen.jwt_claims("authorization").expect("a bearer");
        assert_eq!(bearer["aud"], "github-api", "a per-route audience");
        assert_eq!(bearer["permissions"], json!(["repo:read:internal"]));
        let record = out.record().expect("a record");
        assert_eq!(record["matches"][0]["name"], "internal/web-app");

        plant_minted(&mut planted, &out);
        out.assert_no_leaks(&planted);
    })
    .await;
}

/// 05: the APL gate passes, the PDP denies an engineer on an external repo.
#[tokio::test]
async fn alice_is_denied_an_external_repo_by_the_pdp() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Alice, "search_repos")
            .args(json!({ "repo_name": "partner-sdk", "visibility": "external" }));
        let planted = planted(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request));
        assert_eq!(out.violation_code(), Some(fixture.deny_violation()));
        assert_eq!(out.proto_error_code(), None, "a plain -32001 deny");
        assert_eq!(upstream_calls(&host), 0);
        assert_eq!(host.transport().call_count_for(TOKEN_EXCHANGE_URL), 0);
        out.assert_no_leaks(&planted);
    })
    .await;
}

/// 06: Bob is not in engineering or security, so the gate stops him before
/// the PDP or the identity provider.
#[tokio::test]
async fn bob_is_denied_repo_search_at_the_team_gate() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call =
            Call::new(Persona::Bob, "search_repos").args(json!({ "visibility": "internal" }));
        let planted = planted(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request));
        assert_eq!(
            out.violation_code(),
            Some("routes.tool:search_repos.pre_invocation[0]")
        );
        assert_eq!(out.proto_error_code(), None, "a plain -32001 deny");
        assert_eq!(upstream_calls(&host), 0);
        assert_eq!(host.transport().call_count_for(TOKEN_EXCHANGE_URL), 0);
        out.assert_no_leaks(&planted);
    })
    .await;
}
