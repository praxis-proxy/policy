// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Safety invariant catalog for plugin dispatch.
//!
//! One table: every dispatch phase × {none, error, hang, panic}, with
//! `on_error: fail`. Each cell asserts the decision, not merely that no
//! allow was returned. A new [`PluginMode`] variant fails to compile
//! until [`expected_plugin_verdict`] gains an arm.
//!
//! `docs/safety-invariants.md` is the prose form of this table.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::sync::atomic::Ordering;

use praxis_policy_core::config::parse_config;
use praxis_policy_core::executor::{Executor, ExecutorConfig};
use praxis_policy_core::fault_testing::{
    ExpectedVerdict, InjectedFailure, all_plugin_modes, dispatch_modes, expected_plugin_verdict,
    fault_entry, probe_entry,
};
use praxis_policy_core::hooks::payload::{Extensions, PluginPayload};
use praxis_policy_core::plugin::{OnError, PluginMode};

#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "test fixture — typed shape is the point, not field reads"
)]
struct TestPayload {
    value: String,
}
praxis_policy_core::impl_plugin_payload!(TestPayload);

#[test]
fn plugin_fault_catalog_covers_every_dispatch_mode() {
    let modes = dispatch_modes();
    for mode in all_plugin_modes() {
        assert_eq!(
            modes.contains(&mode),
            mode.is_dispatch_phase(),
            "{mode} must appear in the catalog iff it is a dispatch phase"
        );
    }
    assert!(
        !modes.is_empty(),
        "the executor has at least one dispatch phase"
    );
}

#[tokio::test(start_paused = true)]
async fn plugin_fault_catalog_asserts_the_safe_verdict() {
    let tracker = tokio_util::task::TaskTracker::new();
    for mode in dispatch_modes() {
        for failure in InjectedFailure::all() {
            let expected = expected_plugin_verdict(mode, failure);
            let executor = Executor::new(ExecutorConfig {
                timeout_seconds: 1,
                short_circuit_on_deny: true,
            });
            let entry = fault_entry("fault", mode, OnError::Fail, failure);
            let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
            let (result, bg) = executor
                .execute(
                    std::slice::from_ref(&entry),
                    payload,
                    Extensions::default(),
                    None,
                    &tracker,
                )
                .await;

            match expected {
                ExpectedVerdict::Allow => {
                    assert!(
                        result.continue_processing,
                        "{mode:?} × {failure:?}: expected allow"
                    );
                    assert!(result.violation.is_none(), "{mode:?} × {failure:?}");
                    let bg_errors = bg.wait_for_background_tasks().await;
                    assert!(
                        bg_errors.is_empty(),
                        "{mode:?} × {failure:?}: background errors {bg_errors:?}"
                    );
                },
                ExpectedVerdict::Halt { code } => {
                    assert!(
                        !result.continue_processing,
                        "{mode:?} × {failure:?}: expected deny, got allow"
                    );
                    let v = result
                        .violation
                        .as_ref()
                        .expect("a halt must carry a violation");
                    assert_eq!(v.code, code, "{mode:?} × {failure:?}");
                    assert_eq!(v.plugin_name.as_deref(), Some("fault"));
                    let _ = bg.wait_for_background_tasks().await;
                },
                ExpectedVerdict::Continue { record_code } => {
                    assert!(
                        result.continue_processing,
                        "{mode:?} × {failure:?}: non-blocking phase must not halt"
                    );
                    assert!(
                        result.violation.is_none(),
                        "{mode:?} × {failure:?}: continue is not a deny"
                    );
                    assert_eq!(
                        result.errors.len(),
                        1,
                        "{mode:?} × {failure:?}: the failure must be recorded"
                    );
                    assert_eq!(
                        result.errors[0].code.as_deref(),
                        record_code,
                        "{mode:?} × {failure:?}"
                    );
                    let _ = bg.wait_for_background_tasks().await;
                },
                ExpectedVerdict::AllowThenBackgroundPanic => {
                    assert!(
                        result.continue_processing,
                        "{mode:?} × {failure:?}: fire-and-forget cannot change the verdict"
                    );
                    let bg_errors = bg.wait_for_background_tasks().await;
                    assert_eq!(
                        bg_errors.len(),
                        1,
                        "{mode:?} × {failure:?}: panic must surface on wait, got {bg_errors:?}"
                    );
                },
            }
        }
    }
}

#[tokio::test]
async fn empty_plugin_list_allows() {
    let executor = Executor::default();
    let tracker = tokio_util::task::TaskTracker::new();
    let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "x".into() });
    let (result, bg) = executor
        .execute(&[], payload, Extensions::default(), None, &tracker)
        .await;
    assert!(result.continue_processing);
    assert!(result.violation.is_none());
    assert!(bg.wait_for_background_tasks().await.is_empty());
}

fn catalog_executor() -> Executor {
    Executor::new(ExecutorConfig {
        timeout_seconds: 1,
        short_circuit_on_deny: true,
    })
}

fn test_payload() -> Box<dyn PluginPayload> {
    Box::new(TestPayload { value: "x".into() })
}

/// I4 outside concurrent: ignore and disable must not halt serial, transform,
/// or audit, and disable must trip the circuit breaker. Concurrent already
/// has the nine-cell matrix in `executor.rs`.
#[tokio::test(start_paused = true)]
async fn plugin_ignore_and_disable_do_not_halt_serial_transform_or_audit() {
    let tracker = tokio_util::task::TaskTracker::new();
    let modes = [
        PluginMode::Sequential,
        PluginMode::Transform,
        PluginMode::Audit,
    ];
    for mode in modes {
        for on_error in [OnError::Ignore, OnError::Disable] {
            for failure in [
                InjectedFailure::Error,
                InjectedFailure::Hang,
                InjectedFailure::Panic,
            ] {
                let entry = fault_entry("fault", mode, on_error, failure);
                let (result, bg) = catalog_executor()
                    .execute(
                        std::slice::from_ref(&entry),
                        test_payload(),
                        Extensions::default(),
                        None,
                        &tracker,
                    )
                    .await;
                assert!(
                    result.continue_processing,
                    "{mode:?} × {on_error:?} × {failure:?}: must not halt"
                );
                assert!(
                    result.violation.is_none(),
                    "{mode:?} × {on_error:?} × {failure:?}"
                );
                assert_eq!(
                    result.errors.len(),
                    1,
                    "{mode:?} × {on_error:?} × {failure:?}: failure must be recorded"
                );
                assert_eq!(
                    entry.plugin_ref.is_disabled(),
                    on_error == OnError::Disable,
                    "{mode:?} × {on_error:?} × {failure:?}"
                );
                let _ = bg.wait_for_background_tasks().await;
            }
        }
    }
}

/// A contained serial panic under ignore must not skip later audit. That was
/// the uncontained-unwind failure: audit never ran.
#[tokio::test]
async fn a_contained_serial_panic_under_ignore_still_runs_audit() {
    let tracker = tokio_util::task::TaskTracker::new();
    let audit_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entries = [
        fault_entry(
            "fault",
            PluginMode::Sequential,
            OnError::Ignore,
            InjectedFailure::Panic,
        ),
        probe_entry(
            "audit",
            PluginMode::Audit,
            std::sync::Arc::clone(&audit_calls),
        ),
    ];
    let (result, bg) = catalog_executor()
        .execute(
            &entries,
            test_payload(),
            Extensions::default(),
            None,
            &tracker,
        )
        .await;
    assert!(result.continue_processing);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(
        audit_calls.load(Ordering::SeqCst),
        1,
        "audit must still run after a contained serial panic under ignore"
    );
    let _ = bg.wait_for_background_tasks().await;
}

/// Fail-closed serial panic is a deny. Later audit does not run; the
/// violation is the record.
#[tokio::test]
async fn a_serial_fail_panic_does_not_run_audit() {
    let tracker = tokio_util::task::TaskTracker::new();
    let audit_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entries = [
        fault_entry(
            "fault",
            PluginMode::Sequential,
            OnError::Fail,
            InjectedFailure::Panic,
        ),
        probe_entry(
            "audit",
            PluginMode::Audit,
            std::sync::Arc::clone(&audit_calls),
        ),
    ];
    let (result, bg) = catalog_executor()
        .execute(
            &entries,
            test_payload(),
            Extensions::default(),
            None,
            &tracker,
        )
        .await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.as_ref().map(|v| v.code.as_str()),
        Some("plugin_panic")
    );
    assert_eq!(
        audit_calls.load(Ordering::SeqCst),
        0,
        "a fail-closed serial halt must not dispatch later audit"
    );
    let _ = bg.wait_for_background_tasks().await;
}

#[test]
fn omitted_on_error_in_yaml_is_fail() {
    let yaml = "
plugins:
  - name: rate_limiter
    kind: builtin
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
";
    let config = parse_config(yaml).expect("a plugin with no on_error must still load");
    assert_eq!(config.plugins.len(), 1);
    assert_eq!(
        config.plugins[0].on_error,
        OnError::Fail,
        "omitted on_error is fail-closed"
    );
}

#[test]
fn malformed_config_fails_the_load() {
    let unknown = parse_config("global:\n  not_a_real_key: true\n")
        .expect_err("an unknown key must fail the load");
    let unknown_text = unknown.to_string();
    assert!(
        unknown_text.contains("not_a_real_key"),
        "the load error must name the bad key: {unknown_text}"
    );

    let misspelled = parse_config("pluginss:\n  - name: x\n")
        .expect_err("a misspelled top-level block must fail the load");
    let misspelled_text = misspelled.to_string();
    assert!(
        misspelled_text.contains("pluginss") || misspelled_text.contains("unknown"),
        "the load error must name the misspelled block: {misspelled_text}"
    );

    let unparseable = parse_config(":[ not yaml").expect_err("unparseable YAML must fail the load");
    let unparseable_text = unparseable.to_string();
    assert!(
        !unparseable_text.is_empty(),
        "unparseable YAML must produce a load error"
    );
}
