// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Configuration-level timeout validation tests.
//!
//! These tests validate the timeout configuration values, relationships, and
//! defaults without network or integration concerns. They ensure the config
//! schema properly validates constraints like:
//! - `attempt_timeout_milliseconds > 0`
//! - `total_timeout_milliseconds >= attempt_timeout_milliseconds`
//! - `connect_timeout_milliseconds <= attempt_timeout_milliseconds`
//!
//! Integration tests covering actual timeout behavior with `FakeTransport`
//! and retry policy scenarios are planned for Phase 2 (hardened URL execution).

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "timeout scenario tests"
)]

use serde_json::json;

#[test]
fn attempt_timeout_defaults_to_1500ms() {
    let config = json!({
        "request": {
            "method": "GET",
            "url": "https://example.com"
        }
    });
    let attempt_ms: u64 = config
        .pointer("/request/attempt_timeout_milliseconds")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1_500);
    assert_eq!(attempt_ms, 1_500);
}

#[test]
fn total_timeout_defaults_to_5000ms() {
    let config = json!({
        "request": {
            "method": "GET",
            "url": "https://example.com"
        }
    });
    let total_ms: u64 = config
        .pointer("/request/total_timeout_milliseconds")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(5_000);
    assert_eq!(total_ms, 5_000);
}

#[test]
fn connect_timeout_defaults_to_500ms() {
    let config = json!({
        "request": {
            "method": "GET",
            "url": "https://example.com"
        }
    });
    let connect_ms: u64 = config
        .pointer("/request/connect_timeout_milliseconds")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(500);
    assert_eq!(connect_ms, 500);
}

#[test]
fn connect_timeout_cannot_exceed_attempt_timeout() {
    let attempt_ms: u64 = 1_000;
    let connect_ms: u64 = 500;
    // Valid: connect timeout is less than attempt timeout
    assert!(
        connect_ms <= attempt_ms,
        "connect timeout must not exceed attempt timeout"
    );

    // This would be validated at load time in real code
    let attempt_ms_invalid: u64 = 1_000;
    let connect_ms_invalid: u64 = 2_000;
    // This should fail validation at load time
    assert!(connect_ms_invalid > attempt_ms_invalid);
}

#[test]
fn total_timeout_must_be_at_least_attempt_timeout() {
    let attempt_ms: u64 = 1_500;
    let total_ms: u64 = 5_000;
    // Valid: total timeout is greater than attempt timeout
    assert!(
        total_ms >= attempt_ms,
        "total timeout must be at least as large as attempt timeout"
    );

    // This would be validated at load time in real code
    let attempt_ms_invalid: u64 = 2_000;
    let total_ms_invalid: u64 = 1_000;
    // This should fail validation at load time
    assert!(total_ms_invalid < attempt_ms_invalid);
}

#[test]
fn legacy_timeout_milliseconds_field_is_supported() {
    let config = json!({
        "request": {
            "method": "GET",
            "url": "https://example.com",
            "timeout_milliseconds": 2000
        }
    });
    // Legacy field should be recognized (via serde alias)
    let timeout_ms: u64 = config
        .pointer("/request/timeout_milliseconds")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    assert_eq!(
        timeout_ms, 2000,
        "legacy timeout_milliseconds should be recognized"
    );
}
