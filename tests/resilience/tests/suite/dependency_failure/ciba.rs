// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The CIBA OP fails on dispatch or on the token poll for an
//! `adjust_compensation` over the approval threshold.
//!
//! Plugin-level mapping: `crates/builtins/tests/ciba/ciba_e2e.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use bytes::Bytes;
use praxis_policy_core::http::HttpResponse;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::fixtures::{CLIENT_SECRET, Fixture};
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::{CIBA_BACKCHANNEL_URL, CIBA_TOKEN_URL, Persona};
use praxis_policy_test_utils::secrets::Planted;
use serde_json::{Value, json};

use super::{Fault, assert_fail_closed};

/// The protocol code a pending elicitation carries.
const PENDING: i64 = -32_120;

/// The `require_approval` step. A failed elicitation halts as a deny whose
/// code is the step's rule source; the plugin's code is in the reason.
/// `docs/content/apl/elicitation.md` documents channel errors as failing
/// closed and names no code.
const APPROVAL_STEP: &str = "routes.tool:adjust_compensation.pre_invocation[1]";

/// Assert the deny names the plugin's code in its reason.
fn assert_attributed(out: &Outcome, plugin_code: &str, row: &str) {
    let reason = out.violation.as_ref().map_or("", |v| v.reason.as_str());
    assert!(
        reason.contains(plugin_code),
        "{row}: the reason carries {plugin_code}: {reason}"
    );
    assert_ne!(out.proto_error_code(), Some(PENDING), "{row}: not pending");
}

/// Build the above-threshold call used by both OP failure legs.
fn large_adjustment() -> Call {
    Call::new(Persona::Bob, "adjust_compensation")
        .args(json!({ "employee_id": "EMP-001234", "amount": 25_000 }))
}

/// Track the inbound credentials that must stay out of diagnostics.
fn planted(call: &Call) -> Planted {
    let mut planted = call.planted();
    planted.plant("client secret", CLIENT_SECRET);
    planted
}

/// A dispatch the OP never acknowledges denies, never with the pending
/// signal a caller would retry on.
#[tokio::test]
async fn a_failing_backchannel_denies_rather_than_reporting_pending() {
    let rows: [(&str, Fault, &str); 7] = [
        // ciba_e2e.rs: a_dispatch_that_cannot_reach_the_op_denies_rather_than_reporting_pending.
        ("connect", Fault::Connect, "elicitation.op_unreachable"),
        // ciba_e2e.rs: a_timed_out_dispatch_is_not_retried.
        ("timeout", Fault::Timeout, "elicitation.op_timeout"),
        // An answer too large to read was delivered: the same unknown.
        ("oversized", Fault::TooLarge, "elicitation.op_timeout"),
        // ciba_e2e.rs: a_rejected_backchannel_request_denies_with_its_status.
        (
            "503",
            Fault::Status(503, "unavailable"),
            "elicitation.op_rejected",
        ),
        (
            "400 unknown_user_id",
            Fault::Status(400, r#"{"error":"unknown_user_id"}"#),
            "elicitation.op_rejected",
        ),
        (
            "malformed JSON",
            Fault::malformed("not json"),
            "elicitation.bad_response",
        ),
        // ciba_e2e.rs: a_backchannel_success_with_no_auth_req_id_denies.
        (
            "no auth_req_id",
            Fault::malformed(r#"{"expires_in":300}"#),
            "elicitation.bad_response",
        ),
    ];
    for (row, fault, code) in rows {
        let host = RefHost::builder()
            .transport(fault.at(CIBA_BACKCHANNEL_URL))
            .start(Fixture::Cedar.hermetic())
            .await
            .unwrap_or_else(|e| panic!("{row}: start: {e}"));
        let call = large_adjustment();
        let planted = planted(&call);
        let out = host.call(call).await;
        assert_fail_closed(&host, &out, Stage::Request, APPROVAL_STEP, &planted, row);
        assert_attributed(&out, code, row);
        assert!(
            host.transport().call_count_for(CIBA_BACKCHANNEL_URL) >= 1,
            "{row}: the dispatch was attempted"
        );
    }
}

/// The OP acknowledged the dispatch, then a retry's poll fails. The retry
/// denies, and a timed-out poll is attributed to `elicitation.op_timeout`:
/// the approval may exist, so it is not invented either way.
#[tokio::test]
async fn a_failing_token_poll_on_retry_denies_without_inventing_an_outcome() {
    let rows: [(&str, Fault, &str); 5] = [
        // ciba_e2e.rs: a_check_that_cannot_reach_the_op_denies_rather_than_inventing_an_outcome.
        ("connect", Fault::Connect, "elicitation.op_unreachable"),
        // ciba_e2e.rs: a_timed_out_poll_is_not_retried.
        ("timeout", Fault::Timeout, "elicitation.op_timeout"),
        ("500", Fault::Status(500, ""), "elicitation.op_rejected"),
        // ciba_e2e.rs: an_unrecognized_poll_error_denies_instead_of_becoming_a_lifecycle_state.
        (
            "400 invalid_grant",
            Fault::Status(400, r#"{"error":"invalid_grant"}"#),
            "elicitation.op_rejected",
        ),
        // ciba_e2e.rs: a_successful_poll_with_an_unparseable_body_denies.
        (
            "malformed 200",
            Fault::malformed("not json at all"),
            "elicitation.bad_response",
        ),
    ];
    for (row, fault, code) in rows {
        // Pending until armed, so the first call parks on a live id.
        let armed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&armed);
        let transport = FakeTransport::new().respond_with(CIBA_TOKEN_URL, move |_| {
            if flag.load(Ordering::SeqCst) {
                fault.reply()
            } else {
                Ok(HttpResponse::new(
                    400,
                    Bytes::from_static(br#"{"error":"authorization_pending"}"#),
                ))
            }
        });
        let host = RefHost::builder()
            .transport(transport)
            .start(Fixture::Cedar.hermetic())
            .await
            .unwrap_or_else(|e| panic!("{row}: start: {e}"));

        let first = host.call(large_adjustment()).await;
        assert_eq!(
            first.proto_error_code(),
            Some(PENDING),
            "{row}: {:?}",
            first.violation
        );
        let id = first
            .detail("elicitation_id")
            .and_then(Value::as_str)
            .expect("an elicitation id")
            .to_owned();

        armed.store(true, Ordering::SeqCst);
        let polls = host.transport().call_count_for(CIBA_TOKEN_URL);
        let retry = large_adjustment().elicitation_id(&id);
        let planted = planted(&retry);
        let out = host.call(retry).await;
        assert_fail_closed(&host, &out, Stage::Request, APPROVAL_STEP, &planted, row);
        assert_attributed(&out, code, row);
        assert!(
            host.transport().call_count_for(CIBA_TOKEN_URL) > polls,
            "{row}: the retry polled"
        );
    }
}

/// A malicious OP can reflect the client's Basic credential in an error
/// body. Neither the plain secret nor its encoded form may reach the caller.
fn reflected_body() -> (String, String) {
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("praxis-gateway:{CLIENT_SECRET}"));
    (format!("plain={CLIENT_SECRET}; basic={basic}"), basic)
}

/// Require a reflected OP body to stay out of the caller-visible deny.
fn assert_reflected_body_is_private(out: &Outcome, basic: &str, planted: &Planted) {
    assert_eq!(out.denied_at, Some(Stage::Request), "the OP failure denies");
    assert_eq!(
        out.violation_code(),
        Some(APPROVAL_STEP),
        "the approval step denies"
    );
    assert!(out.upstream.is_none(), "the upstream was not called");
    let reason = out.violation.as_ref().map_or("", |v| v.reason.as_str());
    assert!(
        !reason.contains(CLIENT_SECRET) && !reason.contains(basic),
        "known gap #181 ciba-op-body-secret-leak: OP response body reached the deny reason"
    );
    out.assert_no_leaks(planted);
}

/// A rejected backchannel request must not reveal either credential encoding.
#[tokio::test]
#[should_panic(expected = "known gap #181 ciba-op-body-secret-leak")]
async fn known_gap_a_backchannel_error_does_not_reflect_client_credentials() {
    let (body, basic) = reflected_body();
    let transport = FakeTransport::new().respond_with(CIBA_BACKCHANNEL_URL, move |_| {
        Ok(HttpResponse::new(503, Bytes::from(body.clone())))
    });
    let host = RefHost::builder()
        .transport(transport)
        .start(Fixture::Cedar.hermetic())
        .await
        .expect("start the reflected backchannel fixture");
    let call = large_adjustment();
    let mut planted = planted(&call);
    planted.plant("Basic client credential", basic.clone());
    let out = host.call(call).await;
    assert_eq!(host.transport().call_count_for(CIBA_BACKCHANNEL_URL), 1);
    assert_reflected_body_is_private(&out, &basic, &planted);
}

/// A rejected token poll must not reveal either credential encoding.
#[tokio::test]
#[should_panic(expected = "known gap #181 ciba-op-body-secret-leak")]
async fn known_gap_a_poll_error_does_not_reflect_client_credentials() {
    let (body, basic) = reflected_body();
    let armed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&armed);
    let transport = FakeTransport::new().respond_with(CIBA_TOKEN_URL, move |_| {
        if flag.load(Ordering::SeqCst) {
            Ok(HttpResponse::new(503, Bytes::from(body.clone())))
        } else {
            Ok(HttpResponse::new(
                400,
                Bytes::from_static(br#"{"error":"authorization_pending"}"#),
            ))
        }
    });
    let host = RefHost::builder()
        .transport(transport)
        .start(Fixture::Cedar.hermetic())
        .await
        .expect("start the reflected poll fixture");
    let first = host.call(large_adjustment()).await;
    assert_eq!(first.proto_error_code(), Some(PENDING));
    let id = first
        .detail("elicitation_id")
        .and_then(Value::as_str)
        .expect("a pending elicitation id")
        .to_owned();
    armed.store(true, Ordering::SeqCst);
    let call = large_adjustment().elicitation_id(&id);
    let mut planted = planted(&call);
    planted.plant("Basic client credential", basic.clone());
    let out = host.call(call).await;
    assert!(host.transport().call_count_for(CIBA_TOKEN_URL) >= 2);
    assert_reflected_body_is_private(&out, &basic, &planted);
}
