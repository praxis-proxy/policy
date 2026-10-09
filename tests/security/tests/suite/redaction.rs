// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What leaves in a response, and what a session carries to its next call.
//!
//! The demo redacts `result.ssn` unless the caller holds `perm.view_ssn`.
//! Eve does not. Each case reshapes the upstream record so the SSN sits
//! under an explicitly configured field path.

use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::Persona;
use praxis_policy_test_utils::secrets::Planted;
use serde_json::{Value, json};

use crate::support::{JANE_SSN, forwarded_bearer, planted_for};

fn jane() -> Value {
    json!({ "employee_id": "EMP-001234", "name": "Jane Smith", "ssn": JANE_SSN })
}

/// A `result` whose single text part is `record`, as `server.py` answers.
fn as_text(record: &Value) -> Value {
    json!({ "content": [{ "type": "text", "text": record.to_string() }] })
}

/// Eve reads Jane's record with the upstream answering `result`. Returns
/// the outcome after the leak check on everything but the SSN, and the SSN
/// alone for the case to check.
async fn eve_reads(result: Value, path: &str) -> (Outcome, Planted) {
    let yaml = Fixture::Cedar.hermetic().replacen(
        "    result:\n      ssn:",
        &format!("    result:\n      \"{path}\":"),
        1,
    );
    let host = RefHost::builder()
        .start(&yaml)
        .await
        .expect("redaction fixture");
    host.upstream().set_result("get_compensation", result);
    let call = Call::new(Persona::Eve, "get_compensation")
        .args(json!({ "employee_id": "EMP-001234", "include_ssn": true }));
    let mut planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    planted.plant("minted workday token", forwarded_bearer(&out));
    out.assert_no_leaks(&planted);
    let mut ssn = Planted::new();
    ssn.plant("ssn", JANE_SSN);
    (out, ssn)
}

#[tokio::test]
async fn a_top_level_ssn_is_redacted() {
    let (out, ssn) = eve_reads(as_text(&jane()), "ssn").await;
    assert_eq!(out.record().expect("a record")["ssn"], "[REDACTED]");
    out.assert_no_leaks(&ssn);
}

#[tokio::test]
async fn an_ssn_inside_an_array_is_redacted() {
    let (out, ssn) = eve_reads(as_text(&json!([jane(), jane()])), "ssn").await;
    let record = out.record().expect("a record");
    assert_eq!(record[0]["ssn"], "[REDACTED]");
    assert_eq!(record[1]["ssn"], "[REDACTED]");
    out.assert_no_leaks(&ssn);
}

/// Redaction paths match keys without regard to case.
#[tokio::test]
async fn an_uppercase_ssn_matches_a_lowercase_path() {
    let mut record = jane();
    let value = record
        .as_object_mut()
        .and_then(|r| r.remove("ssn"))
        .expect("an ssn");
    record["SSN"] = value;
    let (out, ssn) = eve_reads(as_text(&record), "ssn").await;
    assert_eq!(out.record().expect("a record")["SSN"], "[REDACTED]");
    out.assert_no_leaks(&ssn);
}

#[tokio::test]
async fn a_recursive_path_redacts_nested_ssns_at_any_depth() {
    let result = json!({
        "employee": jane(),
        "teams": [{ "member": { "SSN": JANE_SSN } }],
    });
    let (out, ssn) = eve_reads(as_text(&result), "**.ssn").await;
    let record = out.record().expect("a record");
    assert_eq!(record["employee"]["ssn"], "[REDACTED]");
    assert_eq!(record["teams"][0]["member"]["SSN"], "[REDACTED]");
    out.assert_no_leaks(&ssn);
}

#[tokio::test]
async fn a_recursive_path_redacts_under_a_dotted_object_key() {
    let result = json!({ "employee.v2": { "ssn": JANE_SSN } });
    let (out, ssn) = eve_reads(as_text(&result), "**.ssn").await;
    assert_eq!(
        out.record().expect("a record")["employee.v2"]["ssn"],
        "[REDACTED]"
    );
    out.assert_no_leaks(&ssn);
}

/// `ssn` addresses the top level (and array elements), not a nested record.
#[tokio::test]
async fn an_explicit_nested_ssn_path_is_redacted() {
    let (out, ssn) = eve_reads(as_text(&json!({ "employee": jane() })), "employee.ssn").await;
    assert_eq!(
        out.record().expect("a record")["employee"]["ssn"],
        "[REDACTED]"
    );
    out.assert_no_leaks(&ssn);
}

/// Two text parts are joined into one string, as praxis does
/// (`build_response_content_for_method` in `json_rpc.rs`), so the record
/// is never parsed. Selecting `text` redacts the entire joined value.
#[tokio::test]
async fn an_explicit_text_path_redacts_joined_text_blocks() {
    let result = json!({ "content": [
        { "type": "text", "text": "Record:" },
        { "type": "text", "text": jane().to_string() },
    ] });
    let (out, ssn) = eve_reads(result, "text").await;
    assert_eq!(out.record().expect("a record")["text"], "[REDACTED]");
    out.assert_no_leaks(&ssn);
}

/// Accepted behavior. Taint is keyed by subject and `X-Session-Id`, and
/// `session` scope lasts for that session only
/// (`docs/content/apl/tainting.md`, "Setting Session Taint" and
/// "Persistence and isolation"). The session id is the caller's, so a
/// fresh one starts clean. Same-session write-down still denies.
#[tokio::test]
async fn a_fresh_session_id_starts_without_the_taint() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let read = Call::new(Persona::Bob, "get_compensation")
        .args(json!({ "employee_id": "EMP-001234" }))
        .session("s-read");
    let mut planted = planted_for(&read);
    let out = host.call(read).await;
    assert!(out.allowed(), "{:?}", out.violation);
    planted.plant("minted workday token", forwarded_bearer(&out));
    out.assert_no_leaks(&planted);

    let email = |session: &str| {
        Call::new(Persona::Bob, "send_email")
            .args(json!({ "to": "partner@example.com", "subject": "hi", "body": "clean" }))
            .session(session)
    };
    let call = email("s-read");
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert_eq!(out.denied_at, Some(Stage::Request));
    assert_eq!(out.violation_code(), Some("session_tainted_secret"));
    out.assert_no_leaks(&planted);

    let call = email("s-fresh");
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    out.assert_no_leaks(&planted);
}
