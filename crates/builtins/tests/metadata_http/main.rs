// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test fixtures"
)]

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use praxis_policy_apl_runtime::{AplOptions, register_apl};
use praxis_policy_builtins::plugins::metadata_http::{KIND, MetadataHttpFactory};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, ToolCall};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{Extensions, MetaExtension, MetadataOutcome};
use praxis_policy_core::http::{HeaderMap, HttpResponse, HttpTransport};
use praxis_policy_core::http_testing::FakeTransport;

const POLICY: &str = include_str!("../../../../docs/content/apl/metadata-http.example.yaml");

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: "1.0".to_owned(),
            role: Role::User,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "call-1".to_owned(),
                    name: "check_account".to_owned(),
                    arguments: HashMap::new(),
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

fn extensions() -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some("check_account".to_owned()),
            ..MetaExtension::default()
        })),
        ..Extensions::default()
    }
}

fn response() -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    HttpResponse::new(
        200,
        Bytes::from_static(br#"{"active":true,"plan":"enterprise"}"#),
    )
    .with_headers(headers)
}

#[tokio::test]
async fn documented_source_fetches_and_publishes_before_the_next_predicate() {
    let http = Arc::new(
        FakeTransport::new().respond_with("/v1/accounts/check_account", |_| Ok(response())),
    );
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(MetadataHttpFactory));
    register_apl(&engine, AplOptions::in_process());
    let transport: Arc<dyn HttpTransport> = http.clone();
    assert!(engine.set_http_transport(transport));
    engine
        .load_config_yaml(POLICY)
        .expect("documented metadata HTTP policy loads");
    engine.initialize().await.expect("engine initializes");

    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), extensions(), None)
        .await;
    assert!(
        result.continue_processing,
        "the next APL predicate sees the fetched active fact"
    );
    let facts = result
        .modified_extensions
        .as_ref()
        .and_then(|extensions| extensions.metadata.as_deref())
        .and_then(|metadata| metadata.get("account_status"))
        .expect("framework publishes the source record");
    assert_eq!(facts.outcome(), MetadataOutcome::Success);
    assert_eq!(facts.source().expect("framework-stamped source").kind, KIND);
    assert_eq!(http.call_count(), 1);
    let request = http.last_request().expect("one outbound request");
    assert_eq!(
        request.url,
        "https://metadata.example/v1/accounts/check_account?resource=check_account"
    );
}

#[tokio::test]
async fn malformed_content_type_rejects_response() {
    let http = Arc::new(
        FakeTransport::new().respond_with("/v1/accounts/check_account", |_| {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "malformed".parse().unwrap());
            Ok(
                HttpResponse::new(200, Bytes::from_static(br#"{"active":true}"#))
                    .with_headers(headers),
            )
        }),
    );
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(MetadataHttpFactory));
    register_apl(&engine, AplOptions::in_process());
    let transport: Arc<dyn HttpTransport> = http.clone();
    assert!(engine.set_http_transport(transport));
    engine
        .load_config_yaml(POLICY)
        .expect("documented metadata HTTP policy loads");
    engine.initialize().await.expect("engine initializes");

    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), extensions(), None)
        .await;
    assert!(
        !result.continue_processing,
        "malformed content-type stops processing"
    );
}

#[tokio::test]
async fn quoted_charset_parameter_accepted() {
    let http = Arc::new(
        FakeTransport::new().respond_with("/v1/accounts/check_account", |_| {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                "application/json; charset=\"utf-8\"".parse().unwrap(),
            );
            Ok(HttpResponse::new(
                200,
                Bytes::from_static(br#"{"active":true,"plan":"enterprise"}"#),
            )
            .with_headers(headers))
        }),
    );
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(MetadataHttpFactory));
    register_apl(&engine, AplOptions::in_process());
    let transport: Arc<dyn HttpTransport> = http.clone();
    assert!(engine.set_http_transport(transport));
    engine
        .load_config_yaml(POLICY)
        .expect("documented metadata HTTP policy loads");
    engine.initialize().await.expect("engine initializes");

    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), extensions(), None)
        .await;
    assert!(
        result.continue_processing,
        "quoted charset parameter is accepted"
    );
}

#[tokio::test]
async fn trailing_semicolon_in_content_type_accepted() {
    let http = Arc::new(
        FakeTransport::new().respond_with("/v1/accounts/check_account", |_| {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/json;".parse().unwrap());
            Ok(
                HttpResponse::new(200, Bytes::from_static(br#"{"active":true,"plan":"enterprise"}"#))
                    .with_headers(headers),
            )
        }),
    );
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(MetadataHttpFactory));
    register_apl(&engine, AplOptions::in_process());
    let transport: Arc<dyn HttpTransport> = http.clone();
    assert!(engine.set_http_transport(transport));
    engine
        .load_config_yaml(POLICY)
        .expect("documented metadata HTTP policy loads");
    engine.initialize().await.expect("engine initializes");

    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), extensions(), None)
        .await;
    assert!(
        result.continue_processing,
        "trailing semicolon in Content-Type is accepted (RFC 9110)"
    );
}

#[tokio::test]
async fn invalid_media_type_format_rejects_response() {
    let http = Arc::new(
        FakeTransport::new().respond_with("/v1/accounts/check_account", |_| {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "text".parse().unwrap());
            Ok(
                HttpResponse::new(200, Bytes::from_static(br#"{"active":true}"#))
                    .with_headers(headers),
            )
        }),
    );
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(MetadataHttpFactory));
    register_apl(&engine, AplOptions::in_process());
    let transport: Arc<dyn HttpTransport> = http.clone();
    assert!(engine.set_http_transport(transport));
    engine
        .load_config_yaml(POLICY)
        .expect("documented metadata HTTP policy loads");
    engine.initialize().await.expect("engine initializes");

    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), extensions(), None)
        .await;
    assert!(
        !result.continue_processing,
        "invalid media type format stops processing"
    );
}
