// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Argument shapes the engine itself bounds. Body parsing and size
//! ceilings are host-owned and tested in praxis.

use praxis_policy::praxis_policy_apl_core::{INPUT_TOO_DEEP_CODE, MAX_STRUCTURED_DEPTH};
use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{Persona, TOKEN_EXCHANGE_URL};
use praxis_policy_test_utils::secrets::Planted;
use serde_json::json;

use crate::support::{JANE_SSN, planted_for};

/// Every fixture's `search_repos` route has a PDP step, which is where the
/// depth limit applies. APL-only steps ignore depth. The step denies with
/// the depth code before its engine runs; the CEL and OPA fixtures declare
/// an `on_deny` reaction, which relabels that deny with the fixture's own
/// code, as an `on_deny` does for any PDP deny.
#[tokio::test]
async fn args_nested_past_the_depth_limit_deny_the_pdp_step_with_the_depth_code() {
    const KEY: &str = "deep-key-marker";
    const LEAF: &str = "deep-leaf-marker";
    // The arguments object adds one level above the chain.
    let deep = (1..MAX_STRUCTURED_DEPTH).fold(json!(LEAF), |inner, _| json!({ KEY: inner }));
    for fixture in Fixture::ALL {
        let pdp = fixture.name();
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Alice, "search_repos").args(json!({
            "repo_name": "web-app",
            "visibility": "internal",
            "deep": deep,
        }));
        let mut planted = planted_for(&call);
        planted.plant("deep key", KEY);
        planted.plant("deep leaf", LEAF);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request), "{pdp}");
        let code = match fixture {
            Fixture::Cedar => INPUT_TOO_DEEP_CODE,
            Fixture::Cel | Fixture::Opa => fixture.deny_violation(),
        };
        assert_eq!(out.violation_code(), Some(code), "{pdp}");
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{pdp}"
        );
        assert!(host.upstream().requests().is_empty(), "{pdp}");
        out.assert_no_leaks(&planted);
    }
}

/// A 1 MiB argument is scanned in full and decided the same way twice: a
/// clean one passes, and an SSN at its tail denies without being echoed.
///
/// The SSN here is the caller's own payload, and the demo runs `audit-log`
/// before `pii-scan`, so the audit record carries the args by design
/// (`reference/plugins/audit-logger/src/logger.rs`). Every other log line,
/// the violation and the errors must not.
#[tokio::test]
async fn an_oversized_args_string_is_decided_deterministically() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let filler = "a".repeat(1 << 20);
    let email = |body: &str| {
        Call::new(Persona::Bob, "send_email")
            .args(json!({ "to": "partner@example.com", "subject": "q3", "body": body }))
    };

    for round in 0..2 {
        let call = email(&filler);
        let planted = planted_for(&call);
        let out = host.call(call).await;
        assert!(out.allowed(), "round {round}: {:?}", out.violation);
        let seen = out.upstream.as_ref().expect("the upstream was called");
        assert_eq!(seen.arguments["body"].as_str().map(str::len), Some(1 << 20));
        out.assert_no_leaks(&planted);
    }
    assert_eq!(host.upstream().requests().len(), 2);

    let tainted = format!("{filler} {JANE_SSN}");
    for round in 0..2 {
        let call = email(&tainted);
        let planted = planted_for(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request), "round {round}");
        assert_eq!(out.violation_code(), Some("pii.detected"), "round {round}");
        assert!(
            out.errors.iter().all(|e| e.plugin_name != "pii-scan"),
            "the scan decided rather than failed: {:?}",
            out.errors
        );
        out.assert_no_leaks(&planted);
        let mut ssn = Planted::new();
        ssn.plant("ssn", JANE_SSN);
        let violation = serde_json::to_value(&out.violation)
            .expect("serialize the violation for leak checking");
        ssn.assert_absent_json("the violation", &violation);
        ssn.assert_absent_json("the errors", &json!(out.errors));
        let diagnostics: Vec<String> = out
            .events
            .logs()
            .into_iter()
            .filter(|line| !line.contains(" apl.audit]"))
            .collect();
        ssn.assert_absent("captured logs", &diagnostics.join("\n"));
    }
    assert_eq!(host.upstream().requests().len(), 2);
}
