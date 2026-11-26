// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use http::StatusCode;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::hooks::{HookHandler, PluginResult};
use praxis_policy_core::host::{HostServices as _, HttpRequestError};
use praxis_policy_core::http::HttpTransportError;
use praxis_policy_core::http_retry::RetryPolicy;
use praxis_policy_core::metadata::{MetadataFetchHook, MetadataFetchRequest, MetadataFetchResult};
use praxis_policy_core::metadata_callout::{
    CalloutObserver, MetadataCalloutAuditEvent, MetadataCalloutErrorCode,
};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::plugins::metadata_common::{CalloutFailure, TracingCalloutObserver};

use super::config::CompiledConfig;

pub(super) struct MetadataHttp {
    config: PluginConfig,
    compiled: CompiledConfig,
    observer: Arc<dyn CalloutObserver>,
}

struct FetchSuccess {
    accepted_status: StatusCode,
    facts: praxis_policy_core::extensions::AcquiredFacts,
}

impl MetadataHttp {
    pub(super) fn new(config: PluginConfig, compiled: CompiledConfig) -> Self {
        Self {
            config,
            compiled,
            observer: Arc::new(TracingCalloutObserver),
        }
    }

    #[cfg(test)]
    fn with_observer(
        config: PluginConfig,
        compiled: CompiledConfig,
        observer: Arc<dyn CalloutObserver>,
    ) -> Self {
        Self {
            config,
            compiled,
            observer,
        }
    }

    async fn fetch(&self, extensions: &Extensions) -> Result<FetchSuccess, CalloutFailure> {
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
        let retry_policy = match self.compiled.request.method() {
            crate::plugins::metadata_common::request::RequestMethod::Get => {
                RetryPolicy::idempotent().with_total_budget(self.compiled.request.total_budget())
            },
            crate::plugins::metadata_common::request::RequestMethod::Post => {
                RetryPolicy::undelivered_only()
                    .with_total_budget(self.compiled.request.total_budget())
            },
        };
        let response = extensions
            .http_request(request, retry_policy)
            .await
            .map_err(map_transport_error)?;
        if response.body.len() > self.compiled.request.max_response_bytes() {
            return Err(CalloutFailure::new(
                MetadataCalloutErrorCode::ResponseTooLarge,
            ));
        }
        let facts = self.compiled.response.parse(&response)?;
        let accepted_status = StatusCode::from_u16(response.status)
            .map_err(|_error| CalloutFailure::new(MetadataCalloutErrorCode::BadResponse))?;
        Ok(FetchSuccess {
            accepted_status,
            facts,
        })
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
        let result = self.fetch(extensions).await;
        let mut event = match &result {
            Ok(success) => MetadataCalloutAuditEvent::success_with_accepted_status(
                &self.config.name,
                self.compiled.request.authority(),
                success.facts.cache(),
                success.accepted_status,
            ),
            Err(error) => MetadataCalloutAuditEvent::error(
                &self.config.name,
                self.compiled.request.authority(),
                praxis_policy_core::extensions::MetadataCacheDisposition::Disabled,
                error.code(),
            ),
        };
        if self.compiled.request.uses_credential_interpolation()
            && !matches!(
                &result,
                Err(error) if error.code() == MetadataCalloutErrorCode::SubjectRequired
            )
        {
            event = event.with_credential_interpolation();
        }
        self.observer.observe(&event);
        let facts = result
            .map(|success| success.facts)
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
    use std::sync::Mutex;

    use bytes::Bytes;
    use praxis_policy_core::engine::PolicyEngine;
    use praxis_policy_core::extensions::MetadataOutcome;
    use praxis_policy_core::extensions::raw_credentials::{
        Credential, RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
    };
    use praxis_policy_core::http::{HeaderMap, HttpResponse, HttpTransport};
    use praxis_policy_core::http_testing::FakeTransport;
    use praxis_policy_core::metadata::HOOK_METADATA_FETCH;
    use praxis_policy_core::plugin::PluginMode;
    use serde_json::{Value, json};

    use super::*;
    use crate::plugins::metadata_http::factory::KIND;

    #[derive(Default)]
    struct RecordingObserver {
        events: Mutex<Vec<Value>>,
    }

    impl CalloutObserver for RecordingObserver {
        fn observe(&self, event: &MetadataCalloutAuditEvent) {
            self.events
                .lock()
                .expect("recording observer lock")
                .push(serde_json::to_value(event).expect("audit event serializes"));
        }
    }

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
        invoke_with_context(http, config, Extensions::default(), None).await
    }

    async fn invoke_with_context(
        http: Arc<FakeTransport>,
        config: PluginConfig,
        extensions: Extensions,
        observer: Option<Arc<dyn CalloutObserver>>,
    ) -> (
        praxis_policy_core::executor::PipelineResult,
        Arc<FakeTransport>,
    ) {
        let compiled = CompiledConfig::compile(&config).expect("compiled config");
        let source = Arc::new(match observer {
            Some(observer) => MetadataHttp::with_observer(config.clone(), compiled, observer),
            None => MetadataHttp::new(config.clone(), compiled),
        });
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
                extensions,
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

    #[tokio::test]
    async fn credential_interpolation_is_marked_in_value_free_audit_event() {
        let mut config = config();
        config
            .capabilities
            .insert("read_inbound_credentials".to_owned());
        config.config.as_mut().expect("config")["allow_credential_interpolation"] = json!(true);
        config.config.as_mut().expect("config")["credential_fields"] =
            json!(["request.json.token"]);
        config.config.as_mut().expect("config")["request"] = json!({
            "method": "POST",
            "url": "https://metadata.example",
            "json": {"token": "{raw_credentials.inbound_tokens.user.token}"}
        });
        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new(
                "never-audited-credential",
                Credential::Header {
                    name: "authorization".to_owned(),
                },
                TokenKind::Opaque,
            ),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Extensions::default()
        };
        let observer = Arc::new(RecordingObserver::default());
        let observer_handle: Arc<dyn CalloutObserver> = observer.clone();
        let http = Arc::new(FakeTransport::new().respond_with("metadata.example", |_| {
            Ok(json_response(r#"{"active":true}"#))
        }));

        let (result, _) =
            invoke_with_context(http, config, extensions, Some(observer_handle)).await;
        let facts = MetadataFetchRequest::from_pipeline_result(&result)
            .and_then(MetadataFetchRequest::facts)
            .expect("source facts");
        assert_eq!(facts.outcome(), MetadataOutcome::Success);
        let events = observer.events.lock().expect("recording observer lock");
        assert_eq!(events.len(), 1);
        let event = events.first().expect("one audit event");
        assert_eq!(event.get("credential_interpolation"), Some(&json!(true)));
        assert_eq!(event.get("authority"), Some(&json!("metadata.example")));
        assert_eq!(event.get("accepted_status"), Some(&json!(200)));
        assert!(
            !event.to_string().contains("never-audited-credential"),
            "audit event must remain value-free"
        );
    }
}
