// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The RFC 8693 token endpoint fails or misbehaves on `get_compensation`.
//!
//! Plugin-level mapping: `crates/builtins/tests/oauth/oauth_e2e.rs`.

use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::fixtures::{CLIENT_SECRET, Fixture};
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::{Exchange, Persona, TOKEN_EXCHANGE_URL};
use praxis_policy_test_utils::secrets::Planted;
use serde_json::json;

use super::{Fault, assert_fail_closed};

/// A token a broken endpoint hands back. Never forwarded, never logged.
const STRAY_TOKEN: &str = "stray-minted-token-0c1d";

fn bob_reads_compensation() -> (Call, Planted) {
    let call = Call::new(Persona::Bob, "get_compensation")
        .args(json!({ "employee_id": "EMP-001234" }))
        .session("s-exchange");
    let mut planted = call.planted();
    planted.plant("client secret", CLIENT_SECRET);
    planted.plant("stray minted token", STRAY_TOKEN);
    (call, planted)
}

#[tokio::test]
async fn a_failing_token_endpoint_denies_the_call_before_the_upstream() {
    let rows: [(&str, Fault, &str); 9] = [
        // oauth_e2e.rs: idp_unreachable_surfaces_violation.
        ("connect", Fault::Connect, "delegation.idp_unreachable"),
        // oauth_e2e.rs: a_timed_out_exchange_is_not_retried.
        ("timeout", Fault::Timeout, "delegation.idp_timeout"),
        // No builtin test scripts an oversized answer. The code follows from
        // `HttpTransportError::may_have_reached_peer`: the answer was
        // delivered and not read, so the mint is indeterminate, as on a timeout.
        ("oversized", Fault::TooLarge, "delegation.idp_timeout"),
        // oauth_e2e.rs: a_server_error_is_recorded_unknown_not_rejected.
        (
            "500",
            Fault::Status(500, r#"{"error":"server_error"}"#),
            "delegation.idp_rejected",
        ),
        (
            "503 without a body",
            Fault::Status(503, ""),
            "delegation.idp_rejected",
        ),
        // oauth_e2e.rs: idp_rejection_surfaces_error_code.
        (
            "400 invalid_grant",
            Fault::Status(400, r#"{"error":"invalid_grant"}"#),
            "delegation.idp_rejected",
        ),
        // oauth_e2e.rs: an_unreadable_success_is_recorded_unknown_not_confirmed.
        (
            "malformed JSON",
            Fault::malformed("<html>gateway</html>"),
            "delegation.bad_response",
        ),
        // oauth_e2e.rs: a_leg2_success_with_no_access_token_denies.
        (
            "no access_token",
            Fault::malformed(r#"{"token_type":"Bearer","expires_in":300}"#),
            "delegation.bad_response",
        ),
        // oauth_e2e.rs: idp_narrower_scope_surfaces_scope_too_broad.
        (
            "narrower scope",
            Fault::malformed(
                r#"{"access_token":"stray-minted-token-0c1d","token_type":"Bearer","scope":"read_directory"}"#,
            ),
            "delegation.scope_too_broad",
        ),
    ];
    for (row, fault, code) in rows {
        let host = RefHost::builder()
            .transport(fault.at(TOKEN_EXCHANGE_URL))
            .start(Fixture::Cedar.hermetic())
            .await
            .unwrap_or_else(|e| panic!("{row}: start: {e}"));
        let (call, planted) = bob_reads_compensation();
        let out = host.call(call).await;
        assert_fail_closed(&host, &out, Stage::Request, code, &planted, row);
        assert!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL) >= 1,
            "{row}: the exchange was attempted"
        );
    }
}

/// A call through an endpoint that answers 200 with a token departing from
/// the request as `mode` says.
async fn through(mode: Exchange) -> (RefHost, Outcome, Planted) {
    let host = RefHost::builder()
        .transport(mode.install(FakeTransport::new()))
        .start(Fixture::Cedar.hermetic())
        .await
        .expect("the cedar fixture starts");
    let (call, planted) = bob_reads_compensation();
    let out = host.call(call).await;
    assert_eq!(
        host.transport().call_count_for(TOKEN_EXCHANGE_URL),
        1,
        "the exchange was reached"
    );
    out.assert_no_leaks(&planted);
    (host, out, planted)
}

/// One claim of the bearer the upstream received. A gap test checks it
/// first, so the gap assertion fails only on the engine, not the harness.
fn forwarded_claim(out: &Outcome, claim: &str) -> serde_json::Value {
    out.upstream
        .as_ref()
        .and_then(|u| u.jwt_claims("authorization"))
        .map(|c| c[claim].clone())
        .unwrap_or_default()
}

/// The delegator never inspects the minted token, so an `aud` other than
/// the one requested reaches the upstream.
#[tokio::test]
#[should_panic(expected = "known gap #181 exchange-audience-unchecked")]
async fn known_gap_a_token_for_the_wrong_audience_is_forwarded() {
    let (host, out, planted) = through(Exchange::WrongAudience).await;
    if out.upstream.is_some() {
        assert_eq!(forwarded_claim(&out, "aud"), "not-workday-api");
        panic!(
            "known gap #181 exchange-audience-unchecked: wrong audience token reached the upstream"
        );
    }
    assert!(
        out.violation_code()
            .is_some_and(|c| c.starts_with("delegation.")),
        "the denial must be attributable to delegation: {:?}",
        out.violation
    );
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        out.violation_code().expect("delegation violation"),
        &planted,
        "wrong audience",
    );
}

/// Requested scopes must be a subset of the grant, and nothing bounds the
/// grant from above, so an over-scoped token reaches the upstream.
#[tokio::test]
#[should_panic(expected = "known gap #181 exchange-scope-overgrant")]
async fn known_gap_a_token_broader_than_requested_is_forwarded() {
    let (host, out, planted) = through(Exchange::BroaderScope).await;
    if out.upstream.is_some() {
        assert_eq!(forwarded_claim(&out, "scope"), "read_compensation admin");
        panic!("known gap #181 exchange-scope-overgrant: broader scope token reached the upstream");
    }
    assert!(
        out.violation_code()
            .is_some_and(|c| c.starts_with("delegation.")),
        "the denial must be attributable to delegation: {:?}",
        out.violation
    );
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        out.violation_code().expect("delegation violation"),
        &planted,
        "broader scope",
    );
}

/// The minted token's `sub` is not compared with the caller's.
#[tokio::test]
#[should_panic(expected = "known gap #181 exchange-subject-unchecked")]
async fn known_gap_a_token_for_another_subject_is_forwarded() {
    let (host, out, planted) = through(Exchange::DifferentSubject).await;
    if out.upstream.is_some() {
        assert_eq!(forwarded_claim(&out, "sub"), Persona::Eve.sub());
        panic!(
            "known gap #181 exchange-subject-unchecked: different subject token reached the upstream"
        );
    }
    assert!(
        out.violation_code()
            .is_some_and(|c| c.starts_with("delegation.")),
        "the denial must be attributable to delegation: {:?}",
        out.violation
    );
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        out.violation_code().expect("delegation violation"),
        &planted,
        "different subject",
    );
}

/// `issued_token_type` is recorded, not checked, so an ID token is attached
/// as the outbound bearer.
#[tokio::test]
#[should_panic(expected = "known gap #181 exchange-token-type-unchecked")]
async fn known_gap_an_unexpected_issued_token_type_is_forwarded() {
    let (host, out, planted) = through(Exchange::UnexpectedTokenType).await;
    if out.upstream.is_some() {
        assert_eq!(forwarded_claim(&out, "aud"), "workday-api");
        assert_eq!(forwarded_claim(&out, "typ"), "ID");
        panic!(
            "known gap #181 exchange-token-type-unchecked: unexpected token type token reached the upstream"
        );
    }
    assert!(
        out.violation_code()
            .is_some_and(|c| c.starts_with("delegation.")),
        "the denial must be attributable to delegation: {:?}",
        out.violation
    );
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        out.violation_code().expect("delegation violation"),
        &planted,
        "unexpected token type",
    );
}
