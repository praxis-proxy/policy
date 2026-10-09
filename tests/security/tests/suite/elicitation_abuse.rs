// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Approvals redeemed for something other than what was approved.
//!
//! The CIBA `auth_req_id` is the elicitation id and is returned to the
//! caller by design (`docs/content/apl/elicitation.md`), so it is never
//! planted.

use praxis_policy_core::http::HttpResponse;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::{self, CibaPoll, Persona};
use serde_json::json;

use crate::support::{elicitation_id, planted_for};

/// Where the approval step denies from.
const APPROVAL_STEP: &str = "routes.tool:adjust_compensation.pre_invocation[1]";

/// Build an adjustment call from Bob with the requested amount.
fn adjust(amount: i64) -> Call {
    Call::new(Persona::Bob, "adjust_compensation")
        .args(json!({ "employee_id": "EMP-001234", "amount": amount }))
}

/// Make the scripted OP approve with the supplied manager identity.
fn approve(host: &RefHost, approver: &str) {
    host.ciba().set(CibaPoll::Approved {
        approver: approver.to_owned(),
    });
}

/// How many requests reached the upstream for `tool`.
fn applied(host: &RefHost, tool: &str) -> usize {
    host.upstream()
        .requests()
        .iter()
        .filter(|r| r.tool == tool)
        .count()
}

/// Obtain an approved correlation id without applying it.
async fn approved_unused(host: &RefHost) -> String {
    let call = adjust(25_000);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    out.assert_no_leaks(&planted);
    let id = elicitation_id(&out);
    assert!(host.upstream().requests().is_empty(), "the id is unused");
    approve(host, "alice");
    id
}

/// Bob asks for 25000, alice approves, and the approved retry applies once.
async fn approved_once(host: &RefHost) -> String {
    let id = approved_unused(host).await;
    let call = adjust(25_000).elicitation_id(&id);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    assert_eq!(
        applied(host, "adjust_compensation"),
        1,
        "the approved call applies"
    );
    out.assert_no_leaks(&planted);
    id
}

/// Require a failed approval to stop before the upstream.
fn assert_not_applied(out: &Outcome) {
    assert_eq!(out.denied_at, Some(Stage::Request), "{:?}", out.violation);
    assert!(out.upstream.is_none(), "the upstream was not called");
}

#[tokio::test]
async fn an_unused_approval_applies_for_its_owner_and_tool() {
    approved_once(&RefHost::hermetic(Fixture::Cedar).await).await;
}

#[tokio::test]
async fn an_approval_does_not_cover_a_larger_amount() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let id = approved_unused(&host).await;
    let call = adjust(90_000).elicitation_id(&id);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert_not_applied(&out);
    assert_eq!(out.violation_code(), Some(APPROVAL_STEP));
    let reason = &out.violation.as_ref().expect("a violation").reason;
    assert!(reason.contains("scope not satisfied"), "{reason}");
    assert_eq!(applied(&host, "adjust_compensation"), 0);
    out.assert_no_leaks(&planted);
}

#[tokio::test]
async fn an_approval_from_someone_other_than_the_login_hint_is_denied() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let id = elicitation_id(&host.call(adjust(25_000)).await);
    approve(&host, "mallory");
    let call = adjust(25_000).elicitation_id(&id);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert_not_applied(&out);
    assert_eq!(out.violation_code(), Some(APPROVAL_STEP));
    let reason = &out.violation.as_ref().expect("a violation").reason;
    assert!(reason.contains("approver mismatch"), "{reason}");
    assert!(host.upstream().requests().is_empty());
    out.assert_no_leaks(&planted);
}

#[tokio::test]
async fn an_invented_id_is_denied_even_while_the_op_approves() {
    // This OP approves even an id the engine never dispatched.
    let tokens = json!({"id_token": Persona::Alice.token()}).to_string();
    let transport = FakeTransport::new().respond_with(idp::CIBA_TOKEN_URL, move |_| {
        Ok(HttpResponse::new(200, tokens.clone().into()))
    });
    let host = RefHost::builder()
        .transport(transport)
        .start(Fixture::Cedar.hermetic())
        .await
        .expect("untrusted OP fixture");
    let call = adjust(25_000).elicitation_id("ciba-00000000deadbeef");
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert_not_applied(&out);
    assert_eq!(out.violation_code(), Some(APPROVAL_STEP));
    let reason = &out.violation.as_ref().expect("a violation").reason;
    assert!(reason.contains("unknown elicitation id"), "{reason}");
    out.assert_no_leaks(&planted);
}

/// The CIBA correlation store keeps only the expected and resolved
/// approver (`crates/builtins/src/plugins/elicitation_ciba/store.rs`), and
/// nothing consumes an id once it validates.
#[tokio::test]
#[should_panic(expected = "known gap #181 elicitation-replay")]
async fn known_gap_an_approved_id_applies_once() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let id = approved_once(&host).await;
    let call = adjust(25_000).elicitation_id(&id);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    out.assert_no_leaks(&planted);
    assert_eq!(
        applied(&host, "adjust_compensation"),
        1,
        "known gap #181 elicitation-replay: one approval applied twice"
    );
}

/// The demo policy plus a second tool behind the same approver.
async fn two_approval_routes() -> RefHost {
    let anchor = "  - tool: adjust_compensation\n";
    let bonus = format!(
        "  - tool: approve_bonus\n    authorization:\n      pre_invocation:\n        \
         - \"require(role.hr)\"\n        \
         - \"require_approval(manager-approver, from: claim.manager, channel: \\\"ciba\\\", \
         scope: \\\"args.amount <= 25000\\\", purpose: \\\"Approve a bonus\\\")\"\n{anchor}"
    );
    let yaml = Fixture::Cedar.hermetic().replacen(anchor, &bonus, 1);
    assert_ne!(yaml, Fixture::Cedar.hermetic(), "the anchor matched");
    RefHost::builder()
        .start(&yaml)
        .await
        .expect("the two-route fixture starts")
}

/// Nothing ties an id to the route that dispatched it.
#[tokio::test]
#[should_panic(expected = "known gap #181 elicitation-tool-binding")]
async fn known_gap_an_approved_id_is_bound_to_its_tool() {
    let host = two_approval_routes().await;
    let id = approved_unused(&host).await;
    let call = Call::new(Persona::Bob, "approve_bonus")
        .args(json!({ "employee_id": "EMP-001234", "amount": 25_000 }))
        .elicitation_id(&id);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    out.assert_no_leaks(&planted);
    assert_eq!(
        applied(&host, "approve_bonus"),
        0,
        "known gap #181 elicitation-tool-binding: an adjust_compensation approval \
         applied approve_bonus"
    );
}

/// Nothing ties an id to the subject that asked. Eve, given a manager
/// claim of her own so `from` resolves, redeems the approval alice gave
/// Bob: validate compares the stored approvers only, not the live `from`.
#[tokio::test]
#[should_panic(expected = "known gap #181 elicitation-subject-binding")]
async fn known_gap_an_approved_id_is_bound_to_its_subject() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let id = approved_unused(&host).await;
    let mut eve = Persona::Eve.claims();
    eve["manager"] = json!("carol");
    let call = adjust(25_000)
        .header("x-user-token", &idp::sign(&eve))
        .elicitation_id(&id);
    let planted = planted_for(&call);
    let out = host.call(call).await;
    out.assert_no_leaks(&planted);
    if let Some(seen) = &out.upstream {
        assert_eq!(
            seen.headers.get("x-auth-user-id").map(String::as_str),
            Some(Persona::Eve.sub())
        );
    }
    assert_eq!(
        applied(&host, "adjust_compensation"),
        0,
        "known gap #181 elicitation-subject-binding: Bob's approval applied Eve's call"
    );
}
