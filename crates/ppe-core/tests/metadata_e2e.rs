// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end coverage for named metadata-source dispatch.

#![expect(clippy::expect_used, reason = "test code")]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{AcquiredFacts, Extensions, MetadataCacheDisposition};
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::metadata::{HOOK_METADATA_FETCH, MetadataFetchHook, MetadataFetchRequest};
use praxis_policy_core::plugin::{Plugin, PluginConfig, PluginMode};

struct Source {
    config: PluginConfig,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Plugin for Source {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<MetadataFetchHook> for Source {
    async fn handle(
        &self,
        request: &MetadataFetchRequest,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MetadataFetchRequest> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        PluginResult::modify_payload(request.clone().with_facts(AcquiredFacts::success(
            json!({"source": self.config.name}),
            Utc::now(),
            MetadataCacheDisposition::Disabled,
        )))
    }
}

fn config(name: &str) -> PluginConfig {
    PluginConfig {
        name: name.to_owned(),
        kind: "metadata/source".to_owned(),
        hooks: vec![HOOK_METADATA_FETCH.to_owned()],
        mode: PluginMode::Sequential,
        ..PluginConfig::default()
    }
}

fn register_source(engine: &PolicyEngine, name: &str, calls: Arc<AtomicUsize>) {
    let config = config(name);
    engine
        .register_handler_for_names::<MetadataFetchHook, _>(
            Arc::new(Source {
                config: config.clone(),
                calls,
            }),
            config,
            &[HOOK_METADATA_FETCH],
        )
        .expect("metadata source should register");
}

#[tokio::test]
async fn named_source_allow_dispatches_only_the_requested_instance() {
    let engine = PolicyEngine::default();
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    register_source(&engine, "first", Arc::clone(&first_calls));
    register_source(&engine, "second", Arc::clone(&second_calls));

    let (result, _) = engine
        .invoke_named::<MetadataFetchHook>(
            HOOK_METADATA_FETCH,
            MetadataFetchRequest::new("second"),
            Extensions::default(),
            None,
        )
        .await;

    assert!(result.continue_processing, "registered source should allow");
    assert_eq!(
        first_calls.load(Ordering::Relaxed),
        0,
        "an unselected source must not be dispatched",
    );
    assert_eq!(
        second_calls.load(Ordering::Relaxed),
        1,
        "the requested source must be dispatched exactly once",
    );
    let response = MetadataFetchRequest::from_pipeline_result(&result)
        .expect("allowed dispatch should return a metadata response");
    assert_eq!(
        response.instance(),
        "second",
        "response should identify the requested source",
    );
    assert_eq!(
        response
            .facts()
            .expect("source should return acquired facts")
            .value(),
        Some(&json!({"source": "second"})),
        "facts should come from the requested source",
    );
}

#[tokio::test]
async fn unknown_named_source_is_denied() {
    let engine = PolicyEngine::default();
    let (result, _) = engine
        .invoke_named::<MetadataFetchHook>(
            HOOK_METADATA_FETCH,
            MetadataFetchRequest::new("missing"),
            Extensions::default(),
            None,
        )
        .await;

    assert!(!result.continue_processing, "unknown source must deny");
    let violation = result.violation.expect("denial should include a violation");
    assert_eq!(
        violation.code, "plugin.not_found",
        "unknown source must use the plugin.not_found code",
    );
    assert!(
        violation.reason.contains("missing"),
        "denial reason should name the requested source",
    );
}

#[tokio::test]
async fn metadata_request_does_not_target_a_different_hook() {
    let engine = PolicyEngine::default();
    register_source(&engine, "account", Arc::new(AtomicUsize::new(0)));

    let (result, _) = engine
        .invoke_by_name(
            "identity.resolve",
            Box::new(MetadataFetchRequest::new("account")),
            Extensions::default(),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "metadata payload on another hook must not trigger metadata targeting",
    );
}

#[test]
fn documented_metadata_fetch_fixture_parses() {
    let policy =
        praxis_policy_core::config::parse_config(include_str!("fixtures/metadata_fetch.yaml"))
            .expect("documented metadata fetch fixture should parse");
    assert_eq!(
        policy.engine_settings.dispatch,
        praxis_policy_core::config::DispatchMode::Hooks,
        "metadata source example must use hook dispatch",
    );
    assert_eq!(
        policy.plugins.len(),
        1,
        "metadata source example should declare one plugin"
    );
    let plugin = policy
        .plugins
        .first()
        .expect("metadata source example should include its plugin");
    assert_eq!(
        plugin.hooks,
        vec![HOOK_METADATA_FETCH.to_owned()],
        "metadata source example should declare metadata.fetch",
    );
    assert!(
        include_str!("../../../docs/content/pipeline.md").contains("kind: metadata/source"),
        "pipeline documentation should retain the metadata source example",
    );
}
