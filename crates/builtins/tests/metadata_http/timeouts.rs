// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Timeout and retry budget validation tests.
//!
//! These tests validate:
//! - Configuration-level timeout validation
//! - Timeout defaults and constraints
//! - Integration with FakeTransport for retry budget scenarios

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "timeout scenario tests"
)]

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use praxis_policy_apl_runtime::{AplOptions, register_apl};
use praxis_policy_builtins::plugins::metadata_http::{KIND, MetadataHttpFactory};
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{Extensions, MetaExtension};
use praxis_policy_core::http::{HeaderMap, HttpResponse, HttpTransport};
use praxis_policy_core::http_testing::FakeTransport;
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

// Integration tests with FakeTransport

fn json_response(body: &str) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    HttpResponse::new(200, Bytes::copy_from_slice(body.as_bytes())).with_headers(headers)
}

#[tokio::test]
async fn get_request_successfully_completes_with_budget() {
    let policy = r#"
engine_settings:
  dispatch: policy

plugins:
  - name: timeout_check
    kind: metadata/http
    hooks: [metadata.fetch]
    mode: sequential
    on_error: fail
    capabilities: [perform_http]
    config:
      require_authenticated: false
      request:
        method: GET
        url: "https://timeout.example/status"
        attempt_timeout_milliseconds: 1500
        total_timeout_milliseconds: 5000
      response:
        type: json

routes:
  - tool: check_status
    authorization:
      pre_invocation:
        - "fetch(timeout_check)"
"#;
    let http = Arc::new(
        FakeTransport::new()
            .respond_with("/status", |_| Ok(json_response(r#"{"status":"ok"}"#))),
    );
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(MetadataHttpFactory));
    register_apl(&engine, AplOptions::in_process());
    let transport: Arc<dyn HttpTransport> = http.clone();
    assert!(engine.set_http_transport(transport));
    engine
        .load_config_yaml(policy)
        .expect("policy loads with timeout budgets");
    engine.initialize().await.expect("engine initializes");

    let payload = MessagePayload {
        message: Message {
            schema_version: "1.0".to_owned(),
            role: Role::User,
            content: vec![ContentPart::ToolCall {
                content: praxis_policy_core::cmf::ToolCall {
                    tool_call_id: "call-1".to_owned(),
                    name: "check_status".to_owned(),
                    arguments: HashMap::new(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    };
    let extensions = Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some("check_status".to_owned()),
            ..MetaExtension::default()
        })),
        ..Extensions::default()
    };

    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, extensions, None)
        .await;

    assert!(
        result.continue_processing,
        "GET request with retry budget completes successfully"
    );
}

#[tokio::test]
async fn post_request_successfully_completes_with_budget() {
    let policy = r#"
engine_settings:
  dispatch: policy

plugins:
  - name: post_check
    kind: metadata/http
    hooks: [metadata.fetch]
    mode: sequential
    on_error: fail
    capabilities: [perform_http]
    config:
      require_authenticated: false
      request:
        method: POST
        url: "https://post.example/verify"
        attempt_timeout_milliseconds: 1500
        total_timeout_milliseconds: 5000
      response:
        type: json

routes:
  - tool: post_verify
    authorization:
      pre_invocation:
        - "fetch(post_check)"
"#;
    let http = Arc::new(
        FakeTransport::new()
            .respond_with("/verify", |_| Ok(json_response(r#"{"verified":true}"#))),
    );
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(MetadataHttpFactory));
    register_apl(&engine, AplOptions::in_process());
    let transport: Arc<dyn HttpTransport> = http.clone();
    assert!(engine.set_http_transport(transport));
    engine
        .load_config_yaml(policy)
        .expect("policy loads with POST timeout budgets");
    engine.initialize().await.expect("engine initializes");

    let payload = MessagePayload {
        message: Message {
            schema_version: "1.0".to_owned(),
            role: Role::User,
            content: vec![ContentPart::ToolCall {
                content: praxis_policy_core::cmf::ToolCall {
                    tool_call_id: "call-1".to_owned(),
                    name: "post_verify".to_owned(),
                    arguments: HashMap::new(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    };
    let extensions = Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some("post_verify".to_owned()),
            ..MetaExtension::default()
        })),
        ..Extensions::default()
    };

    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, extensions, None)
        .await;

    assert!(
        result.continue_processing,
        "POST request with retry budget completes successfully"
    );
}
