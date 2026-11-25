// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::hooks::{HookHandler, PluginResult};
use praxis_policy_core::host::{HostServices as _, HttpRequestError};
use praxis_policy_core::http::HttpTransportError;
use praxis_policy_core::http_retry::RetryPolicy;
use praxis_policy_core::metadata::{MetadataFetchHook, MetadataFetchRequest, MetadataFetchResult};
use praxis_policy_core::metadata_callout::MetadataCalloutErrorCode;
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::plugins::metadata_common::CalloutFailure;

use super::config::CompiledConfig;

pub(super) struct MetadataHttp {
    config: PluginConfig,
    compiled: CompiledConfig,
}

impl MetadataHttp {
    pub(super) const fn new(config: PluginConfig, compiled: CompiledConfig) -> Self {
        Self { config, compiled }
    }

    async fn fetch(
        &self,
        extensions: &Extensions,
    ) -> Result<praxis_policy_core::extensions::AcquiredFacts, CalloutFailure> {
        if self.compiled.require_authenticated
            && extensions
                .security
                .as_ref()
                .and_then(|security| security.subject.as_ref())
                .and_then(|subject| subject.id.as_deref())
                .is_none()
        {
            return Err(CalloutFailure::new(
                MetadataCalloutErrorCode::SubjectRequired,
            ));
        }
        let request = self.compiled.request.build(extensions)?;
        let response = extensions
            .http_request(request, RetryPolicy::none())
            .await
            .map_err(map_transport_error)?;
        if response.body.len() > self.compiled.request.max_response_bytes() {
            return Err(CalloutFailure::new(
                MetadataCalloutErrorCode::ResponseTooLarge,
            ));
        }
        self.compiled.response.parse(&response)
    }
}

impl Plugin for MetadataHttp {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<MetadataFetchHook> for MetadataHttp {
    async fn handle(
        &self,
        payload: &MetadataFetchRequest,
        extensions: &Extensions,
        _context: &mut PluginContext,
    ) -> MetadataFetchResult {
        let facts = self
            .fetch(extensions)
            .await
            .unwrap_or_else(CalloutFailure::facts);
        PluginResult::modify_payload(payload.clone().with_facts(facts))
    }
}

fn map_transport_error(error: HttpRequestError) -> CalloutFailure {
    let code = match error {
        HttpRequestError::Unavailable(_) => MetadataCalloutErrorCode::UpstreamError,
        HttpRequestError::Transport(HttpTransportError::Timeout) => {
            MetadataCalloutErrorCode::Timeout
        },
        HttpRequestError::Transport(HttpTransportError::ResponseTooLarge { .. }) => {
            MetadataCalloutErrorCode::ResponseTooLarge
        },
        HttpRequestError::Transport(HttpTransportError::Rejected(_)) => {
            MetadataCalloutErrorCode::RejectedDestination
        },
        HttpRequestError::Transport(HttpTransportError::InvalidRequest(_)) => {
            MetadataCalloutErrorCode::BadResponse
        },
        HttpRequestError::Transport(HttpTransportError::Connect(_) | HttpTransportError::Io(_)) => {
            MetadataCalloutErrorCode::UpstreamError
        },
        HttpRequestError::Transport(_) => MetadataCalloutErrorCode::UpstreamError,
    };
    CalloutFailure::new(code)
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use praxis_policy_core::engine::PolicyEngine;
    use praxis_policy_core::extensions::MetadataOutcome;
    use praxis_policy_core::http::{HeaderMap, HttpResponse, HttpTransport};
    use praxis_policy_core::http_testing::FakeTransport;
    use praxis_policy_core::metadata::HOOK_METADATA_FETCH;
    use praxis_policy_core::plugin::PluginMode;
    use serde_json::{Value, json};

    use super::*;
    use crate::plugins::metadata_http::factory::KIND;

    fn config() -> PluginConfig {
        PluginConfig {
            name: "account_status".to_owned(),
            kind: KIND.to_owned(),
            hooks: vec![HOOK_METADATA_FETCH.to_owned()],
            mode: PluginMode::Sequential,
            capabilities: ["perform_http".to_owned()].into(),
            config: Some(json!({
                "require_authenticated": false,
                "request": {
                    "method": "GET",
                    "url": "https://metadata.example",
                    "path_segments": ["v1", "account"]
                },
                "response": {"type": "json"}
            })),
            ..PluginConfig::default()
        }
    }

    fn json_response(body: &str) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        HttpResponse::new(200, Bytes::copy_from_slice(body.as_bytes())).with_headers(headers)
    }

    async fn invoke_with_config(
        http: Arc<FakeTransport>,
        config: PluginConfig,
    ) -> (
        praxis_policy_core::executor::PipelineResult,
        Arc<FakeTransport>,
    ) {
        let source = Arc::new(MetadataHttp::new(
            config.clone(),
            CompiledConfig::compile(&config).expect("compiled config"),
        ));
        let engine = PolicyEngine::default();
        engine
            .register_handler_for_names::<MetadataFetchHook, _>(
                source,
                config,
                &[HOOK_METADATA_FETCH],
            )
            .expect("register metadata source");
        let transport: Arc<dyn HttpTransport> = http.clone();
        assert!(engine.set_http_transport(transport));
        engine.initialize().await.expect("initialize engine");
        let (result, _background) = engine
            .invoke_named::<MetadataFetchHook>(
                HOOK_METADATA_FETCH,
                MetadataFetchRequest::new(),
                Extensions::default(),
                None,
            )
            .await;
        (result, http)
    }

    async fn invoke(
        http: Arc<FakeTransport>,
    ) -> (
        praxis_policy_core::executor::PipelineResult,
        Arc<FakeTransport>,
    ) {
        invoke_with_config(http, config()).await
    }

    #[tokio::test]
    async fn dispatches_through_host_transport_and_returns_unstamped_facts() {
        let http = Arc::new(
            FakeTransport::new()
                .respond_with("/v1/account", |_| Ok(json_response(r#"{"active":true}"#))),
        );
        let (result, http) = invoke(http).await;
        assert!(result.continue_processing);
        let facts = MetadataFetchRequest::from_pipeline_result(&result)
            .and_then(MetadataFetchRequest::facts)
            .expect("source facts");
        assert_eq!(facts.outcome(), MetadataOutcome::Success);
        assert_eq!(facts.value(), Some(&json!({"active": true})));
        assert!(
            facts.source().is_none(),
            "framework stamps provenance later"
        );
        assert_eq!(http.call_count(), 1);
        assert_eq!(
            http.last_request().expect("request").url,
            "https://metadata.example/v1/account"
        );
    }

    #[tokio::test]
    async fn transport_failures_are_normalized_and_never_retried() {
        let http =
            Arc::new(FakeTransport::new().fail("metadata.example", HttpTransportError::Timeout));
        let (result, http) = invoke(http).await;
        let facts = MetadataFetchRequest::from_pipeline_result(&result)
            .and_then(MetadataFetchRequest::facts)
            .expect("error facts");
        assert_eq!(facts.outcome(), MetadataOutcome::Error);
        assert_eq!(facts.error_code(), Some("metadata.timeout"));
        assert_eq!(facts.value(), None::<&Value>);
        assert_eq!(http.call_count(), 1, "RetryPolicy::none must stay in force");
    }

    #[tokio::test]
    async fn rejects_a_transport_that_violates_the_response_byte_ceiling() {
        let mut config = config();
        config
            .config
            .as_mut()
            .and_then(|value| value.pointer_mut("/request"))
            .and_then(Value::as_object_mut)
            .expect("request config")
            .insert("max_response_bytes".to_owned(), json!(2));
        let http = Arc::new(
            FakeTransport::new().respond_with("metadata.example", |_| Ok(json_response("null"))),
        );
        let (result, _) = invoke_with_config(http, config).await;
        let facts = MetadataFetchRequest::from_pipeline_result(&result)
            .and_then(MetadataFetchRequest::facts)
            .expect("error facts");
        assert_eq!(facts.error_code(), Some("metadata.response_too_large"));
        assert!(facts.value().is_none());
    }
}
