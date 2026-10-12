// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tool names and argument types chosen to slip past a route's gates.

use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{self, Persona, TOKEN_EXCHANGE_URL};
use serde_json::{Value, json};

use crate::support::{JANE_SSN, planted_for};

/// Near misses of `get_compensation`: case, trailing whitespace, a
/// zero-width space and a Cyrillic `o`.
const VARIANTS: [&str; 5] = [
    "Get_Compensation",
    "GET_COMPENSATION",
    "get_compensation ",
    "get\u{200b}_compensation",
    "get_c\u{043e}mpensation",
];

fn eve_reads_jane(tool: &str) -> Call {
    Call::new(Persona::Eve, tool).args(json!({ "employee_id": "EMP-001234", "include_ssn": true }))
}

/// Accepted behavior. Route selection is an exact match, so a variant
/// selects no route and passes on global policy alone, as an unknown tool
/// does: no `tool: "*"` catch-all is declared, and a request matching no
/// route falls through to global policy (`docs/content/http-routing.md`,
/// "The catch-all"; `docs/content/identity-delegation.md`, layers table).
/// What the engine owes is that the variant never takes the
/// `get_compensation` path without its gates: nothing delegates, no route
/// step runs, and the name reaches the upstream byte for byte, so an exact
/// upstream answers it as unknown.
#[tokio::test]
async fn tool_name_variants_never_take_the_routed_path() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    for tool in VARIANTS {
        let call = eve_reads_jane(tool);
        let mut planted = planted_for(&call);
        planted.plant("ssn", JANE_SSN);
        let out = host.call(call).await;
        assert!(out.allowed(), "{tool:?}: {:?}", out.violation);
        let seen = out.upstream.as_ref().expect("the upstream was called");
        assert_eq!(seen.tool, tool, "forwarded verbatim, never canonicalized");
        let bearer = seen.jwt_claims("authorization").expect("a bearer");
        assert_eq!(
            (&bearer["azp"], &bearer["aud"]),
            (&json!("hr-copilot"), &json!(idp::GATEWAY_AUDIENCE)),
            "{tool:?}: the agent's own token, not a workday delegation"
        );
        assert!(out.events.audit_records().is_empty(), "{tool:?}");
        assert_eq!(
            out.response.as_ref().map(|r| r["error"]["code"].clone()),
            Some(json!(-32601)),
            "{tool:?}"
        );
        out.assert_no_leaks(&planted);
    }
    assert_eq!(host.transport().call_count_for(TOKEN_EXCHANGE_URL), 0);
}

/// The documented way to close that path: a `tool: "*"` catch-all that
/// denies. The exact route still wins.
#[tokio::test]
async fn a_denying_catch_all_closes_every_variant() {
    let yaml = format!(
        "{}\n  - tool: \"*\"\n    authorization:\n      pre_invocation:\n        \
         - \"deny('no route for this tool', 'tool_not_routed')\"\n",
        Fixture::Cedar.hermetic().trim_end()
    );
    let host = RefHost::builder()
        .start(&yaml)
        .await
        .expect("the catch-all fixture starts");
    for tool in VARIANTS {
        let call = eve_reads_jane(tool);
        let mut planted = planted_for(&call);
        planted.plant("ssn", JANE_SSN);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request), "{tool:?}");
        assert_eq!(out.violation_code(), Some("tool_not_routed"), "{tool:?}");
        out.assert_no_leaks(&planted);
    }
    assert!(host.upstream().requests().is_empty());

    let call = eve_reads_jane("get_compensation");
    let mut planted = planted_for(&call);
    planted.plant("ssn", JANE_SSN);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    let minted = crate::support::forwarded_bearer(&out);
    planted.plant("minted workday token", minted);
    out.assert_no_leaks(&planted);
}

fn adjust(amount: Value) -> Call {
    Call::new(Persona::Bob, "adjust_compensation")
        .args(json!({ "employee_id": "EMP-001234", "amount": amount }))
}

/// `args.amount > 10000` gates the approval. A numeric string is compared
/// as a number, a float and an integer past f64 precision still compare,
/// and arrays, objects, and null fail the comparison closed.
#[tokio::test]
async fn amount_shapes_elicit_or_deny_without_reaching_the_upstream() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let fail_closed = "routes.tool:adjust_compensation.pre_invocation[1]";
    let cases = [
        (json!("25000"), "elicitation.pending"),
        (json!(2.5e4), "elicitation.pending"),
        (json!(9_007_199_254_740_993_u64), "elicitation.pending"),
        (json!([25_000]), fail_closed),
        (json!({"value": 25_000}), fail_closed),
        (Value::Null, fail_closed),
    ];
    for (amount, code) in cases {
        let call = adjust(amount.clone());
        let planted = planted_for(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request), "{amount}");
        assert_eq!(out.violation_code(), Some(code), "{amount}");
        out.assert_no_leaks(&planted);
    }
    assert!(host.upstream().requests().is_empty());
}

/// Accepted behavior. The demo gates on `args.amount > 10000`, so a cut of
/// any size is outside the gate as written. The engine evaluates the
/// predicate faithfully and forwards the value unchanged; gating cuts is a
/// policy change (`args.amount < -10000` beside it), not an engine one.
#[tokio::test]
async fn a_negative_amount_is_outside_the_gate_as_written() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let call = adjust(json!(-50_000));
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    let seen = out.upstream.as_ref().expect("the upstream was called");
    assert_eq!(seen.arguments["amount"], json!(-50_000));
    assert!(host.ciba().auth_req_ids().is_empty(), "nothing elicited");
    out.assert_no_leaks(&planted);
}

// The schema can also reject malformed amounts before the approval gate.
#[tokio::test]
async fn an_amount_schema_rejects_objects_null_and_missing_values() {
    let anchor = "  - tool: adjust_compensation\n    authorization:\n      pre_invocation:\n";
    let yaml = Fixture::Cedar.hermetic().replacen(anchor,
        "  - tool: adjust_compensation\n    args:\n      amount: int\n    authorization:\n      pre_invocation:\n        - \"!exists(args.amount): deny('amount is required', 'amount_missing')\"\n", 1);
    assert_ne!(yaml, Fixture::Cedar.hermetic(), "the route matched");
    let host = RefHost::builder()
        .start(&yaml)
        .await
        .expect("amount schema");
    for args in [
        json!({"employee_id": "EMP-001234", "amount": {"value": 25_000}}),
        json!({"employee_id": "EMP-001234", "amount": null}),
        json!({"employee_id": "EMP-001234"}),
    ] {
        let missing = args.get("amount").is_none();
        let call = Call::new(Persona::Bob, "adjust_compensation").args(args);
        let planted = planted_for(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request));
        assert!(out.upstream.is_none());
        if missing {
            assert_eq!(out.violation_code(), Some("amount_missing"));
        } else {
            assert_ne!(out.violation_code(), Some("elicitation.pending"));
        }
        out.assert_no_leaks(&planted);
    }
    assert!(host.ciba().auth_req_ids().is_empty());
    let call = adjust(json!(25_000));
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert_eq!(out.violation_code(), Some("elicitation.pending"));
    out.assert_no_leaks(&planted);
    assert!(host.upstream().requests().is_empty());
    let call = adjust(json!(5_000));
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    out.assert_no_leaks(&planted);
}
