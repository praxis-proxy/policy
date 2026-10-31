// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Rate limits at both rate-limit hooks, driven through the reference host:
//! the edge limit runs before identity, the per-user limit after it, and
//! each counts once per call.

use praxis_policy::praxis_policy_apl_cmf::constants::DETAIL_HTTP_STATUS;
use praxis_policy_builtins::plugins::ratelimit::{CODE_EXCEEDED, CODE_MISSING_ATTRIBUTE};
use praxis_policy_test_utils::fixtures::{
    self, DIRECTORY_LIMIT, EDGE_LIMIT, USER_LIMIT, rate_limit_with,
};
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::{self, Persona};
use serde_json::json;

use super::{planted, upstream_calls};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// A tool no route names, so only the global limits apply to it.
const UNROUTED_TOOL: &str = "search_repos";

/// The tool whose route adds its own limiter.
const ROUTED_TOOL: &str = "get_directory";

const ALICE_ADDRESS: &str = "203.0.113.7";

const BOB_ADDRESS: &str = "198.51.100.4";

const OTHER_ADDRESS: &str = "192.0.2.10";

/// The alarm the engine raises when identity runs without the pre-identity
/// stage.
const STAGE_SKIPPED_ALARM: &str = "rate_limit_stage_skipped";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn a_per_user_limit_allows_its_limit_and_then_denies_with_429() {
    let host = start(&fixtures::rate_limit()).await;
    for number in 1..=USER_LIMIT {
        let out = host.call(call(Persona::Alice, ALICE_ADDRESS)).await;
        assert!(
            out.allowed(),
            "Alice's call #{number} is within her limit: {:?}",
            out.violation
        );
    }
    let call = call(Persona::Alice, ALICE_ADDRESS);
    let planted = planted(&call);
    let out = host.call(call).await;
    assert_exceeded(&out, Stage::PostIdentityRateLimit);
    assert_eq!(
        out.detail("limit"),
        Some(&json!(USER_LIMIT)),
        "the 429 reports the per-user limit"
    );
    assert_eq!(
        upstream_calls(&host),
        usize::try_from(USER_LIMIT).expect("fits usize"),
        "the upstream saw exactly the calls within the limit"
    );
    out.assert_no_leaks(&planted);
}

#[tokio::test]
async fn one_subject_exhausting_its_limit_leaves_another_untouched() {
    let host = start(&fixtures::rate_limit()).await;
    for _ in 0..USER_LIMIT {
        host.call(call(Persona::Alice, ALICE_ADDRESS)).await;
    }
    assert_exceeded(
        &host.call(call(Persona::Alice, ALICE_ADDRESS)).await,
        Stage::PostIdentityRateLimit,
    );
    for number in 1..=USER_LIMIT {
        let out = host.call(call(Persona::Bob, BOB_ADDRESS)).await;
        assert!(
            out.allowed(),
            "Bob's call #{number} counts on his own counter: {:?}",
            out.violation
        );
    }
}

#[tokio::test]
async fn the_edge_limit_runs_before_identity() {
    let host = start(&fixtures::rate_limit()).await;
    for number in 1..=EDGE_LIMIT {
        let out = host.call(invalid_token(ALICE_ADDRESS)).await;
        assert_eq!(
            out.denied_at,
            Some(Stage::Identity),
            "invalid call #{number} is within the edge limit, so identity rejects it: {:?}",
            out.violation
        );
        assert!(
            out.violation_code().is_some_and(|c| c.starts_with("auth.")),
            "identity rejects invalid call #{number}: {:?}",
            out.violation
        );
    }
    let call = invalid_token(ALICE_ADDRESS);
    let planted = planted(&call);
    let out = host.call(call).await;
    assert_exceeded(&out, Stage::PreIdentityRateLimit);
    assert_eq!(
        upstream_calls(&host),
        0,
        "no call with an invalid token reached the upstream"
    );
    out.assert_no_leaks(&planted);
}

#[tokio::test]
async fn a_tool_call_resolving_identity_twice_counts_once_per_stage() {
    let host = start(&rate_limit_with(USER_LIMIT, USER_LIMIT)).await;
    for number in 1..=USER_LIMIT {
        let out = host.call(call(Persona::Alice, ALICE_ADDRESS)).await;
        assert!(
            out.allowed(),
            "call #{number} spends one unit of each limit, not one per identity call: {:?}",
            out.violation
        );
    }
    assert_exceeded(
        &host.call(call(Persona::Alice, ALICE_ADDRESS)).await,
        Stage::PreIdentityRateLimit,
    );
    assert_exceeded(
        &host.call(call(Persona::Alice, OTHER_ADDRESS)).await,
        Stage::PostIdentityRateLimit,
    );
}

#[tokio::test]
async fn a_missing_client_address_denies_before_the_upstream() {
    let host = start(&fixtures::rate_limit()).await;
    let call = Call::new(Persona::Alice, UNROUTED_TOOL);
    let planted = planted(&call);
    let out = host.call(call).await;
    assert_eq!(
        out.denied_at,
        Some(Stage::PreIdentityRateLimit),
        "a limiter bound to the client address fails closed without one: {:?}",
        out.violation
    );
    assert_eq!(
        out.violation_code(),
        Some(CODE_MISSING_ATTRIBUTE),
        "the deny names the missing attribute class"
    );
    assert_eq!(
        out.detail(DETAIL_HTTP_STATUS),
        Some(&json!(400)),
        "a request lacking what the limit needs is a bad request"
    );
    assert_eq!(upstream_calls(&host), 0, "the upstream was never reached");
    out.assert_no_leaks(&planted);
}

#[tokio::test]
async fn a_tool_route_stacks_its_limit_on_the_global_list() {
    let host = start(&fixtures::rate_limit()).await;
    for number in 1..=DIRECTORY_LIMIT {
        let out = host
            .call(Call::new(Persona::Alice, ROUTED_TOOL).client_address(ALICE_ADDRESS))
            .await;
        assert!(
            out.allowed(),
            "directory call #{number} is within the route limit: {:?}",
            out.violation
        );
    }
    let out = host
        .call(Call::new(Persona::Alice, ROUTED_TOOL).client_address(ALICE_ADDRESS))
        .await;
    assert_exceeded(&out, Stage::PostIdentityRateLimit);
    assert_eq!(
        out.detail("limit"),
        Some(&json!(DIRECTORY_LIMIT)),
        "the route's own limiter denied"
    );
    let out = host.call(call(Persona::Alice, ALICE_ADDRESS)).await;
    assert!(
        out.allowed(),
        "an unrouted tool runs on the global limits alone: {:?}",
        out.violation
    );
    assert_eq!(
        upstream_calls(&host),
        usize::try_from(DIRECTORY_LIMIT + 1).expect("fits usize"),
        "only the allowed calls reached the upstream"
    );
}

#[tokio::test]
async fn a_conforming_host_raises_no_stage_alarm() {
    let host = start(&fixtures::rate_limit()).await;
    for persona in [Persona::Alice, Persona::Bob] {
        let out = host.call(call(persona, ALICE_ADDRESS)).await;
        assert!(out.allowed(), "{persona:?} is allowed: {:?}", out.violation);
        let alarms: Vec<String> = out
            .events
            .logs()
            .into_iter()
            .filter(|line| line.contains(STAGE_SKIPPED_ALARM))
            .collect();
        assert!(
            alarms.is_empty(),
            "the host ran the pre-identity stage on the table identity saw: {alarms:?}"
        );
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

async fn start(yaml: &str) -> RefHost {
    RefHost::builder()
        .start(yaml)
        .await
        .expect("the rate-limit fixture starts")
}

fn call(persona: Persona, address: &str) -> Call {
    Call::new(persona, UNROUTED_TOOL).client_address(address)
}

/// A call whose user token is signed by a key the realm does not publish.
fn invalid_token(address: &str) -> Call {
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": "not-the-realm-key" });
    let forged = idp::forge(&header, &Persona::Alice.claims(), idp::Signer::Foreign);
    call(Persona::Alice, address).header("x-user-token", &forged)
}

fn assert_exceeded(out: &Outcome, stage: Stage) {
    assert_eq!(
        out.denied_at,
        Some(stage),
        "the call stops at {stage:?}: {:?}",
        out.violation
    );
    assert_eq!(
        out.violation_code(),
        Some(CODE_EXCEEDED),
        "the deny is the rate limit's"
    );
    assert_eq!(
        out.proto_error_code(),
        Some(429),
        "the deny carries 429 for the wire"
    );
    assert_eq!(
        out.detail(DETAIL_HTTP_STATUS),
        Some(&json!(429)),
        "the details carry the HTTP status"
    );
    assert!(
        out.upstream.is_none(),
        "a rate-limited call never reaches the upstream"
    );
}
