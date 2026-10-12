// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A PDP policy that does not compile, or that errors while evaluating, on
//! the `search_repos` route of each demo fixture.
//!
//! OPA runs in-process, so there is no "unavailable" row, and the PDP
//! timeout is pinned by `pdp_fault_catalog_asserts_the_safe_verdict` in
//! `crates/ppe-apl-core/tests/safety_invariants.rs`. Dialect-level
//! behavior: `every_dialect_malformed_policy_is_not_allow` in
//! `crates/ppe-pdp-diff/src/safety.rs`.

use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{Persona, TOKEN_EXCHANGE_URL};
use serde_json::json;

use super::assert_fail_closed;

/// `fixture` with `from` replaced by `to` once, checking it was there.
fn edited(fixture: Fixture, from: &str, to: &str) -> String {
    let yaml = fixture.hermetic();
    assert!(
        yaml.contains(from),
        "{}: {from:?} is in the fixture",
        fixture.name()
    );
    yaml.replacen(from, to, 1)
}

/// Alice reading an internal repo, which every unedited fixture allows.
fn internal_read() -> Call {
    Call::new(Persona::Alice, "search_repos")
        .args(json!({ "repo_name": "platform-sdk", "visibility": "internal" }))
}

#[tokio::test]
async fn the_unedited_fixtures_allow_the_internal_read() {
    for fixture in Fixture::ALL {
        let host = RefHost::hermetic(fixture).await;
        let out = host.call(internal_read()).await;
        assert!(out.allowed(), "{}: {:?}", fixture.name(), out.violation);
    }
}

/// A policy that does not compile stops the load, so no engine runs it.
///
/// Builtin: `crates/builtins/tests/opa/visitor_opa_config.rs` and
/// `crates/builtins/tests/cedar/visitor_pdp_config.rs`.
#[tokio::test]
async fn a_policy_that_does_not_compile_fails_the_start() {
    let rows = [
        (
            "opa rego syntax",
            edited(
                Fixture::Opa,
                "default allow := false",
                "default allow := := false",
            ),
            "failed to load Rego module",
        ),
        (
            "cedar syntax",
            edited(Fixture::Cedar, "permit(", "permit(("),
            "failed to parse Cedar policy set",
        ),
    ];
    for (row, yaml, names) in rows {
        let err = RefHost::builder()
            .start(&yaml)
            .await
            .map(|_| ())
            .expect_err(&format!("{row}: a malformed policy loaded"));
        assert!(
            err.to_string().contains(names),
            "{row}: the error names {names}: {err}"
        );
    }
}

/// The fixtures' PDP `on_error`, spelled out.
const ON_ERROR_DENY: &str = "on_error: deny   # fail-closed; the default, spelled out";

/// Each dialect's policy edited to error on [`internal_read`]: the dialect,
/// the edited document, and the deny code. `cause` is in the reason where
/// the dialect reports it; CEL and OPA deny through the step's `on_deny`,
/// so their reason is the operator's.
fn erroring() -> [(&'static str, String, &'static str, Option<&'static str>); 3] {
    [
        (
            "cel",
            edited(
                Fixture::Cel,
                r#"args.visibility == "internal""#,
                "int(args.visibility) > 0",
            ),
            "cel.policy_denied",
            None,
        ),
        (
            "opa",
            // Two complete rules with different values for one input.
            edited(
                Fixture::Opa,
                "allow if {\n            input.role.security == true\n          }",
                "allow := false if {\n            input.role.engineer == true\n          }",
            ),
            "opa.policy_denied",
            None,
        ),
        (
            "cedar",
            edited(
                Fixture::Cedar,
                r#"resource.visibility == "internal""#,
                r#"resource.classification == "internal""#,
            ),
            "cedar.evaluation_error",
            Some("attribute or tag does not exist"),
        ),
    ]
}

/// A policy that compiles but errors on this input denies under
/// `on_error: deny`, with the dialect's code, before anything delegates.
///
/// Builtin: `membership_on_absent_key_denies_but_empty_set_evaluates` in
/// `crates/builtins/src/pdps/cel/resolver.rs`,
/// `eval_error_reason_omits_payload_values` in
/// `crates/builtins/src/pdps/opa/resolver.rs`, and
/// `crates/builtins/tests/cedar/basic_allow_deny.rs`.
#[tokio::test]
async fn a_policy_that_errors_while_evaluating_denies() {
    for (row, yaml, code, cause) in erroring() {
        let host = RefHost::builder()
            .start(&yaml)
            .await
            .unwrap_or_else(|e| panic!("{row}: start: {e}"));
        let call = internal_read();
        let planted = call.planted();
        let out = host.call(call).await;
        assert_fail_closed(&host, &out, Stage::Request, code, &planted, row);
        if let Some(cause) = cause {
            let reason = out.violation.as_ref().map_or("", |v| v.reason.as_str());
            assert!(reason.contains(cause), "{row}: {reason}");
        }
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{row}"
        );
    }
}

/// The same edits allow under an operator's `on_error: allow`, which shows
/// the denies above came from the evaluation error and not a false.
///
/// Builtin: `on_error_allow_flips_eval_error_to_allow` in
/// `crates/builtins/src/pdps/cel/resolver.rs`.
#[tokio::test]
async fn the_same_errors_allow_under_on_error_allow() {
    let mut ran = 0;
    for (row, yaml, _, _) in erroring() {
        if !yaml.contains(ON_ERROR_DENY) {
            continue;
        }
        ran += 1;
        let yaml = yaml.replace(ON_ERROR_DENY, "on_error: allow");
        let host = RefHost::builder()
            .start(&yaml)
            .await
            .unwrap_or_else(|e| panic!("{row}: start: {e}"));
        let out = host.call(internal_read()).await;
        assert!(out.allowed(), "{row}: {:?}", out.violation);
    }
    assert_eq!(ran, 2, "the CEL and OPA fixtures spell out on_error");
}
