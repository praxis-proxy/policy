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
    let rows: [(&str, Fault, &str); 10] = [
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
        (
            "no issued_token_type",
            Fault::malformed(r#"{"access_token":"stray-minted-token-0c1d","expires_in":300}"#),
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

/// A JWT minted for another audience must stop at delegation.
#[tokio::test]
async fn a_token_for_the_wrong_audience_is_rejected() {
    let (host, out, planted) = through(Exchange::WrongAudience).await;
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        "delegation.audience_mismatch",
        &planted,
        "wrong audience",
    );
}

/// A grant containing an unrequested scope must stop at delegation.
#[tokio::test]
async fn a_token_broader_than_requested_is_rejected() {
    let (host, out, planted) = through(Exchange::BroaderScope).await;
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        "delegation.scope_overgrant",
        &planted,
        "broader scope",
    );
}

/// A JWT minted for another subject must stop at delegation.
#[tokio::test]
async fn a_token_for_another_subject_is_rejected() {
    let (host, out, planted) = through(Exchange::DifferentSubject).await;
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        "delegation.subject_mismatch",
        &planted,
        "different subject",
    );
}

/// An ID token must not be attached as the outbound bearer.
#[tokio::test]
async fn an_unexpected_issued_token_type_is_rejected() {
    let (host, out, planted) = through(Exchange::UnexpectedTokenType).await;
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        "delegation.issued_token_type_mismatch",
        &planted,
        "unexpected token type",
    );
}

#[tokio::test]
async fn an_explicit_opt_out_accepts_an_unchecked_exchange_response() {
    let anchor = "      client_id: \"praxis-gateway\"\n";
    let yaml = Fixture::Cedar.hermetic().replacen(
        anchor,
        &format!("{anchor}      strict_response_validation: false\n"),
        1,
    );
    assert_ne!(
        yaml,
        Fixture::Cedar.hermetic(),
        "the workday delegator matched"
    );
    let host = RefHost::builder()
        .transport(Exchange::WrongAudience.install(FakeTransport::new()))
        .start(&yaml)
        .await
        .expect("opt-out fixture starts");
    let (call, planted) = bob_reads_compensation();
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    let claims = out
        .upstream
        .as_ref()
        .and_then(|upstream| upstream.jwt_claims("authorization"))
        .expect("the unchecked JWT reached the upstream");
    assert_eq!(claims["aud"], "not-workday-api");
    out.assert_no_leaks(&planted);
}
