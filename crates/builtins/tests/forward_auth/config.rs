// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What the config block rejects at load, so a misconfiguration stops startup
//! rather than denying every request as though the endpoint were down.

use praxis_policy_builtins::plugins::identity_forward_auth::{ForwardAuthResolver, KIND};
use praxis_policy_core::plugin::{OnError, PluginConfig};

use crate::support;

#[test]
fn a_minimal_config_builds() {
    support::resolver(support::config()).expect("the default config builds");
}

#[test]
fn an_unknown_field_is_rejected() {
    let mut block = support::config();
    block["typo"] = serde_json::json!(true);
    let error = support::resolver(block).expect_err("an unknown field must not build");
    assert!(
        error.contains("typo"),
        "the error must name the field: {error}"
    );
}

#[test]
fn a_missing_config_block_is_rejected() {
    let config = PluginConfig {
        name: "dashboard-session".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        config: None,
        ..Default::default()
    };
    let error = ForwardAuthResolver::new(config)
        .expect_err("no config block must not build")
        .to_string();
    assert!(
        error.contains("`config:` block is required"),
        "got: {error}"
    );
}

#[test]
fn an_endpoint_that_is_not_absolute_http_is_rejected() {
    for endpoint in ["127.0.0.1:4180/oauth2/auth", "ftp://host/auth", ""] {
        let mut block = support::config();
        block["endpoint"] = serde_json::json!(endpoint);
        let error = support::resolver(block).expect_err("a bad endpoint must not build");
        assert!(
            error.contains("absolute http"),
            "the error must say what is wrong with '{endpoint}': {error}"
        );
    }
}

#[test]
fn an_invalid_method_is_rejected() {
    let mut block = support::config();
    block["method"] = serde_json::json!("NOT A METHOD");
    let error = support::resolver(block).expect_err("a bad method must not build");
    assert!(error.contains("valid HTTP method"), "got: {error}");
}

#[test]
fn an_empty_forward_headers_list_is_rejected() {
    let mut block = support::config();
    block["forward_headers"] = serde_json::json!([]);
    let error = support::resolver(block).expect_err("an empty list must not build");
    assert!(
        error.contains("no credential would ever be delegated"),
        "got: {error}"
    );
}

#[test]
fn an_empty_forward_header_name_is_rejected() {
    let mut block = support::config();
    block["forward_headers"] = serde_json::json!(["  "]);
    let error = support::resolver(block).expect_err("an empty name must not build");
    assert!(error.contains("empty header name"), "got: {error}");
}

#[test]
fn an_empty_identity_headers_list_is_rejected() {
    let mut block = support::config();
    block["identity_headers"] = serde_json::json!([]);
    let error = support::resolver(block).expect_err("an empty list must not build");
    assert!(
        error.contains("no response header would ever map"),
        "got: {error}"
    );
}

#[test]
fn an_empty_identity_header_name_is_rejected() {
    let mut block = support::config();
    block["identity_headers"] = serde_json::json!([""]);
    let error = support::resolver(block).expect_err("an empty name must not build");
    assert!(error.contains("empty header name"), "got: {error}");
}

#[test]
fn an_empty_success_status_list_is_rejected() {
    let mut block = support::config();
    block["success_status"] = serde_json::json!([]);
    let error = support::resolver(block).expect_err("an empty list must not build");
    assert!(error.contains("resolve unauthenticated"), "got: {error}");
}

#[test]
fn a_zero_timeout_is_rejected() {
    let mut block = support::config();
    block["timeout_secs"] = serde_json::json!(0);
    let error = support::resolver(block).expect_err("a zero timeout must not build");
    assert!(
        error.contains("every sub-request would time out"),
        "got: {error}"
    );
}

#[test]
fn a_zero_response_ceiling_is_rejected() {
    let mut block = support::config();
    block["max_response_bytes"] = serde_json::json!(0);
    let error = support::resolver(block).expect_err("a zero ceiling must not build");
    assert!(error.contains("max_response_bytes"), "got: {error}");
}

#[test]
fn a_map_with_no_subject_section_is_rejected() {
    let block = serde_json::json!({
        "endpoint": support::ENDPOINT,
        "claim_map": { "client": { "client_id": "x-auth-request-user" } },
    });
    let error = support::resolver(block).expect_err("no subject section must not build");
    assert!(error.contains("no `subject` section"), "got: {error}");
}

#[test]
fn an_identity_resolver_needs_fail_closed_on_error() {
    let config = PluginConfig {
        name: "dashboard-session".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        on_error: OnError::Ignore,
        config: Some(support::config()),
        ..Default::default()
    };
    let error = ForwardAuthResolver::new(config)
        .expect_err("a non-fail-closed resolver must not build")
        .to_string();
    assert!(error.contains("on_error: fail"), "got: {error}");
}
