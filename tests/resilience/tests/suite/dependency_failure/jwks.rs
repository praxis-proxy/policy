// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The issuer's JWKS endpoint fails at boot, on a request-time refresh, or
//! stalls past the plugin timeout.
//!
//! Plugin-level mapping: `crates/builtins/tests/jwt/jwks_url_e2e.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use praxis_policy_core::http::HttpResponse;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{self, Persona, TOKEN_EXCHANGE_URL};
use serde_json::json;

use super::{Fault, assert_fail_closed};

/// Two identity plugins, a one-second `plugin_timeout`.
const STALL: &str = include_str!("../../../fixtures/identity-stall.yaml");

fn rotated(persona: Persona) -> String {
    idp::forge(
        &json!({"typ": "JWT", "alg": "RS256", "kid": "rotated-away"}),
        &persona.claims(),
        idp::Signer::Realm,
    )
}

fn the_failures() -> [(&'static str, Fault); 7] {
    [
        ("connect", Fault::Connect),
        ("timeout", Fault::Timeout),
        ("oversized", Fault::TooLarge),
        ("500", Fault::Status(500, "")),
        ("404", Fault::Status(404, r#"{"error":"not_found"}"#)),
        ("malformed JSON", Fault::malformed("{\"keys\": [")),
        ("empty key set", Fault::malformed(r#"{"keys":[]}"#)),
    ]
}

/// Publish the rotated key after boot, or fail the refresh as scripted.
fn refresh_after_boot(fault: Option<Fault>) -> (FakeTransport, Arc<AtomicBool>) {
    let booted = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&booted);
    let original = idp::jwks();
    let mut rotated = original["keys"][0].clone();
    rotated["kid"] = json!("rotated-away");
    let updated = json!({"keys": [original["keys"][0].clone(), rotated]}).to_string();
    let jwks = original.to_string();
    let transport = FakeTransport::new().respond_with(idp::JWKS_URL, move |_| {
        if flag.load(Ordering::SeqCst) {
            match &fault {
                Some(fault) => fault.reply(),
                None => Ok(HttpResponse::new(200, Bytes::from(updated.clone()))),
            }
        } else {
            Ok(HttpResponse::new(200, Bytes::from(jwks.clone())))
        }
    });
    (transport, booted)
}

#[tokio::test]
async fn a_healthy_refresh_accepts_the_rotated_token() {
    let (transport, booted) = refresh_after_boot(None);
    let host = RefHost::builder()
        .transport(transport)
        .start(Fixture::Cedar.hermetic())
        .await
        .expect("start");
    let at_boot = host.transport().call_count_for(idp::JWKS_URL);
    booted.store(true, Ordering::SeqCst);
    let call = Call::new(Persona::Bob, "get_compensation")
        .header("x-user-token", &rotated(Persona::Bob))
        .args(json!({"employee_id": "EMP-001234"}));
    let planted = call.planted();
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    assert!(out.upstream.is_some());
    assert!(host.transport().call_count_for(idp::JWKS_URL) > at_boot);
    assert_eq!(host.transport().call_count_for(TOKEN_EXCHANGE_URL), 1);
    out.assert_no_leaks(&planted);
}

/// A token whose `kid` is unknown forces a refresh, and the refresh fails.
/// The identity gate denies with the rotation-lag code and nothing
/// delegates.
///
/// Builtin: `unknown_kid_yields_unknown_kid_violation` and
/// `a_jwks_fetch_that_times_out_is_an_error_not_an_empty_store`.
#[tokio::test]
async fn a_failing_refresh_denies_an_unknown_kid_at_the_identity_gate() {
    for (row, fault) in the_failures() {
        let (transport, booted) = refresh_after_boot(Some(fault));
        let host = RefHost::builder()
            .transport(transport)
            .start(Fixture::Cedar.hermetic())
            .await
            .unwrap_or_else(|e| panic!("{row}: start: {e}"));
        booted.store(true, Ordering::SeqCst);
        let at_boot = host.transport().call_count_for(idp::JWKS_URL);

        let call = Call::new(Persona::Bob, "get_compensation")
            .header("x-user-token", &rotated(Persona::Bob))
            .args(json!({ "employee_id": "EMP-001234" }));
        let planted = call.planted();
        let out = host.call(call).await;
        assert_fail_closed(
            &host,
            &out,
            Stage::Identity,
            "auth.unknown_kid",
            &planted,
            row,
        );
        assert!(
            host.transport().call_count_for(idp::JWKS_URL) > at_boot,
            "{row}: the unknown kid forced a refresh"
        );
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{row}"
        );
    }
}

/// A JWKS that cannot be read at boot soft-fails: the engine starts, and
/// every token for that issuer denies with `auth.jwks_unavailable` until a
/// refresh succeeds. No request is allowed in between.
///
/// Builtin: `jwks_unreachable_at_initialize_soft_fails` and
/// `a_transient_jwks_failure_is_retried` (an empty key set stays
/// recoverable).
#[tokio::test]
async fn an_unreadable_jwks_at_boot_starts_and_denies_every_token() {
    for (row, fault) in the_failures() {
        let host = RefHost::builder()
            .transport(fault.at(idp::JWKS_URL))
            .start(Fixture::Cedar.hermetic())
            .await
            .unwrap_or_else(|e| panic!("{row}: a JWKS fault at boot soft-fails: {e}"));
        let call =
            Call::new(Persona::Bob, "get_compensation").args(json!({ "employee_id": "EMP-1" }));
        let planted = call.planted();
        let out = host.call(call).await;
        assert_fail_closed(
            &host,
            &out,
            Stage::Identity,
            "auth.jwks_unavailable",
            &planted,
            row,
        );
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{row}"
        );
    }
}

/// How long the scripted JWKS takes to answer. Longer than the fixture's
/// one-second `plugin_timeout`.
const STALL_FOR: Duration = Duration::from_secs(4);

/// Covers AE3. A refresh that stalls past `plugin_timeout` denies with the
/// executor's timeout code, within the timeout plus slack.
///
/// Builtin: the plugin timeout cells of `plugin_fault_catalog_asserts_the_safe_verdict`
/// in `crates/ppe-core/tests/safety_invariants.rs`.
#[tokio::test]
async fn an_identity_plugin_stalled_past_the_plugin_timeout_denies_in_bounded_time() {
    let host = RefHost::builder()
        .transport(FakeTransport::new().with_latency(STALL_FOR))
        .start(STALL)
        .await
        .expect("the stall fixture starts, slowly");
    let call = Call::new(Persona::Bob, "get_directory")
        .header("x-user-token", &rotated(Persona::Bob))
        .args(json!({ "department": "hr" }));
    let planted = call.planted();

    let started = Instant::now();
    let out = host.call(call).await;
    let elapsed = started.elapsed();

    assert_fail_closed(
        &host,
        &out,
        Stage::Identity,
        "plugin_timeout",
        &planted,
        "stall",
    );
    assert!(
        elapsed >= Duration::from_millis(900),
        "denied before the timeout could fire: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1) + Duration::from_secs(2),
        "denied after the stall, not at the timeout: {elapsed:?}"
    );
}

/// `on_error: ignore` is the documented fail-open: a client identity
/// plugin that times out is skipped, the call proceeds on the user's
/// identity, and the timeout is still recorded on the pipeline errors.
///
/// Builtin: `plugin_ignore_and_disable_do_not_halt_serial_transform_or_audit`
/// in `crates/ppe-core/tests/safety_invariants.rs`.
#[tokio::test]
async fn an_ignored_identity_timeout_proceeds_and_records_the_error() {
    let yaml = STALL.replace("on_error: fail # jwt-client", "on_error: ignore");
    assert_ne!(yaml, STALL, "the fixture marks jwt-client's on_error");
    let host = RefHost::builder()
        .transport(FakeTransport::new().with_latency(STALL_FOR))
        .start(&yaml)
        .await
        .expect("the fail-open fixture starts");
    let call = Call::new(Persona::Bob, "get_directory")
        .header(
            "authorization",
            &format!("Bearer {}", rotated(Persona::HrCopilot)),
        )
        .args(json!({ "department": "hr" }));
    let out = host.call(call).await;

    assert!(out.allowed(), "{:?}", out.violation);
    assert!(out.upstream.is_some(), "the call reached the upstream");
    let timeouts: Vec<_> = out
        .errors
        .iter()
        .filter(|e| e.plugin_name == "jwt-client")
        .collect();
    assert!(
        !timeouts.is_empty(),
        "the ignored timeout is recorded: {:?}",
        out.errors
    );
    assert!(
        timeouts
            .iter()
            .all(|e| e.code.as_deref() == Some("timeout")),
        "{timeouts:?}"
    );
}
