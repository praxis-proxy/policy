// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Callers trying to reset, split or borrow a rate-limit counter, and what a
//! rate-limit deny tells them.
//!
//! The counters key on the host-supplied client address and the resolved
//! subject, so nothing the caller sends in a header moves a call to another
//! counter.

use std::collections::BTreeSet;

use praxis_policy::praxis_policy_apl_cmf::constants::DETAIL_HTTP_STATUS;
use praxis_policy_builtins::plugins::ratelimit::{
    CODE_EXCEEDED, DETAIL_LIMIT, DETAIL_REMAINING, DETAIL_RETRY_AFTER_SECONDS,
    DETAIL_WINDOW_SECONDS,
};
use praxis_policy_test_utils::fixtures::{EDGE_LIMIT, USER_LIMIT, rate_limit_with};
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::Persona;

use crate::support::planted_for;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const TOOL: &str = "search_repos";

const CLIENT: &str = "203.0.113.7";

/// A limit no test reaches, for the stage a test does not exercise.
const UNREACHED_LIMIT: u64 = 1_000; // requests per minute

/// The names the policy gives the edge limiter, which a deny must not echo.
const EDGE_INTERNALS: [&str; 5] = [
    "edge-limits",
    "edge-namespace",
    "http.client_address",
    "read_headers",
    "client",
];

/// A secret the caller sends in a header, which a deny must not echo.
const SECRET_HEADER_VALUE: &str = "sk-live-rate-limit-probe";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn caller_headers_do_not_reset_a_client_address_counter() {
    let host = start(&rate_limit_with(EDGE_LIMIT, UNREACHED_LIMIT)).await;
    for number in 1..=EDGE_LIMIT {
        let out = host.call(rotating(Persona::Alice, CLIENT, number)).await;
        assert!(
            out.allowed(),
            "call #{number} is within the edge limit: {:?}",
            out.violation
        );
    }
    let out = host
        .call(rotating(Persona::Alice, CLIENT, EDGE_LIMIT + 1))
        .await;
    assert_exceeded(&out, Stage::PreIdentityRateLimit);
}

#[tokio::test]
async fn caller_headers_do_not_reset_a_subject_counter() {
    let host = start(&rate_limit_with(UNREACHED_LIMIT, USER_LIMIT)).await;
    for number in 1..=USER_LIMIT {
        let address = format!("198.51.100.{number}");
        let out = host.call(rotating(Persona::Alice, &address, number)).await;
        assert!(
            out.allowed(),
            "call #{number} is within the per-user limit: {:?}",
            out.violation
        );
    }
    let out = host
        .call(rotating(Persona::Alice, "198.51.100.200", USER_LIMIT + 1))
        .await;
    assert_exceeded(&out, Stage::PostIdentityRateLimit);
}

#[tokio::test]
async fn a_forged_user_header_cannot_pick_another_subjects_counter() {
    let host = start(&rate_limit_with(UNREACHED_LIMIT, USER_LIMIT)).await;
    for _ in 0..USER_LIMIT {
        host.call(Call::new(Persona::Alice, TOOL).client_address(CLIENT))
            .await;
    }
    let posing_as_bob = Call::new(Persona::Alice, TOOL)
        .client_address(CLIENT)
        .header("x-demo-user", "bob")
        .header("x-auth-user-id", Persona::Bob.sub());
    assert_exceeded(
        &host.call(posing_as_bob).await,
        Stage::PostIdentityRateLimit,
    );

    let bob = host
        .call(
            Call::new(Persona::Bob, TOOL)
                .client_address(CLIENT)
                .header("x-demo-user", "alice")
                .header("x-auth-user-id", Persona::Alice.sub()),
        )
        .await;
    assert!(
        bob.allowed(),
        "Bob posing as Alice still counts on his own, untouched counter: {:?}",
        bob.violation
    );
}

#[tokio::test]
async fn a_pre_identity_deny_reveals_only_the_client_safe_fields() {
    let host = start(&rate_limit_with(1, UNREACHED_LIMIT)).await;
    host.call(Call::new(Persona::Alice, TOOL).client_address(CLIENT))
        .await;
    let call = Call::new(Persona::Alice, TOOL)
        .client_address(CLIENT)
        .header("x-api-key", SECRET_HEADER_VALUE);
    let mut planted = planted_for(&call);
    planted.plant("secret header", SECRET_HEADER_VALUE);
    let out = host.call(call).await;
    assert_exceeded(&out, Stage::PreIdentityRateLimit);

    let violation = out.violation.as_ref().expect("a rate-limit deny");
    let keys: BTreeSet<&str> = violation.details.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            DETAIL_HTTP_STATUS,
            DETAIL_LIMIT,
            DETAIL_REMAINING,
            DETAIL_RETRY_AFTER_SECONDS,
            DETAIL_WINDOW_SECONDS,
        ]),
        "the details carry exactly the client-safe keys"
    );
    let wire = serde_json::json!({
        "code": violation.code,
        "reason": violation.reason,
        "description": violation.description,
        "details": violation.details,
        "proto_error_code": violation.proto_error_code,
    })
    .to_string();
    for internal in EDGE_INTERNALS {
        assert!(
            !wire.contains(internal),
            "the deny must not reveal `{internal}`: {wire}"
        );
    }
    for raw in ["limitador", "Limitador", "storage", "panic"] {
        assert!(
            !wire.contains(raw),
            "the deny must not carry a raw limiter error (`{raw}`): {wire}"
        );
    }
    out.assert_no_leaks(&planted);
}

#[tokio::test]
async fn equivalent_forms_of_one_ipv4_client_share_a_counter() {
    let forms = [
        "203.0.113.7",
        "203.0.113.7:51234",
        "::ffff:203.0.113.7",
        "[::ffff:203.0.113.7]:443",
    ];
    assert_forms_share_a_counter(&forms).await;
}

#[tokio::test]
async fn addresses_in_one_ipv6_slash_64_share_a_counter() {
    let forms = [
        "2001:db8:1:2::5",
        "[2001:db8:1:2::6]:8443",
        "2001:db8:1:2:aaaa:bbbb:cccc:dddd",
        "2001:0db8:0001:0002::7",
    ];
    assert_forms_share_a_counter(&forms).await;
    let host = start(&rate_limit_with(1, UNREACHED_LIMIT)).await;
    for address in ["2001:db8:1:2::1", "2001:db8:1:3::1"] {
        let out = host
            .call(Call::new(Persona::Alice, TOOL).client_address(address))
            .await;
        assert!(
            out.allowed(),
            "{address} is the first call from its own /64: {:?}",
            out.violation
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

/// A call from `address` whose caller-chosen headers differ on every `turn`.
fn rotating(persona: Persona, address: &str, turn: u64) -> Call {
    Call::new(persona, TOOL)
        .client_address(address)
        .header("x-forwarded-for", &format!("10.0.{turn}.1"))
        .header("x-real-ip", &format!("10.1.{turn}.1"))
        .header("forwarded", &format!("for=10.2.{turn}.1"))
        .header("user-agent", &format!("probe/{turn}"))
}

/// Spend the edge limit from the first form, then expect every form to be
/// over it.
async fn assert_forms_share_a_counter(forms: &[&str]) {
    let limit = u64::try_from(forms.len()).expect("fits u64");
    let host = start(&rate_limit_with(limit, UNREACHED_LIMIT)).await;
    for address in forms {
        let out = host
            .call(Call::new(Persona::Alice, TOOL).client_address(address))
            .await;
        assert!(
            out.allowed(),
            "{address} spends one unit of the shared limit: {:?}",
            out.violation
        );
    }
    for address in forms {
        let out = host
            .call(Call::new(Persona::Alice, TOOL).client_address(address))
            .await;
        assert_exceeded(&out, Stage::PreIdentityRateLimit);
    }
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
    assert!(
        out.upstream.is_none(),
        "a rate-limited call never reaches the upstream"
    );
}
