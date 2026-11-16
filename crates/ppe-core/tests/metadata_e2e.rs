// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end coverage for explicitly selected metadata-source dispatch.

#![expect(clippy::expect_used, reason = "test code")]

use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::extensions::{AcquiredFacts, Extensions, MetadataCacheDisposition};
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::metadata::{HOOK_METADATA_FETCH, MetadataFetchHook, MetadataFetchRequest};
use praxis_policy_core::plugin::{Plugin, PluginCondition, PluginConfig, PluginMode};
use praxis_policy_core::registry::HookEntry;

#[tokio::test]
async fn explicit_source_dispatches_only_the_selected_instance() {
    let engine = PolicyEngine::default();
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    register_source(&engine, config("first"), Arc::clone(&first_calls), false);
    register_source(&engine, config("second"), Arc::clone(&second_calls), false);

    let entry = resolve_source(&engine, "second").expect("selected source should resolve");
    let (result, _) = engine
        .invoke_entries::<MetadataFetchHook>(
            std::slice::from_ref(&entry),
            MetadataFetchRequest::new(),
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
        "the selected source must be dispatched exactly once",
    );
    let response = MetadataFetchRequest::from_pipeline_result(&result)
        .expect("allowed dispatch should return a metadata response");
    assert_eq!(
        response
            .facts()
            .expect("source should return acquired facts")
            .value(),
        Some(&json!({"source": "second"})),
        "facts should come from the selected source",
    );
}

#[tokio::test]
async fn explicitly_selected_source_bypasses_hook_conditions() {
    let engine = PolicyEngine::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut source_config = config("account");
    source_config.conditions = vec![PluginCondition {
        tools: Some(HashSet::from(["checkout".to_owned()])),
        ..PluginCondition::default()
    }];
    register_source(&engine, source_config, Arc::clone(&calls), false);
    let entry = resolve_source(&engine, "account").expect("selected source should resolve");
    let (result, _) = engine
        .invoke_entries::<MetadataFetchHook>(
            std::slice::from_ref(&entry),
            MetadataFetchRequest::new(),
            Extensions::default(),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "caller-selected source should allow"
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "explicit dispatch must execute the caller's selection despite hook conditions",
    );
    assert!(
        MetadataFetchRequest::from_pipeline_result(&result)
            .is_some_and(|response| response.facts().is_some()),
        "explicit dispatch must return the selected source's facts",
    );
}

#[tokio::test]
async fn selected_source_denial_returns_no_facts() {
    let engine = PolicyEngine::default();
    let calls = Arc::new(AtomicUsize::new(0));
    register_source(&engine, config("account"), Arc::clone(&calls), true);
    let entry = resolve_source(&engine, "account").expect("selected source should resolve");
    let (result, _) = engine
        .invoke_entries::<MetadataFetchHook>(
            std::slice::from_ref(&entry),
            MetadataFetchRequest::new(),
            Extensions::default(),
            None,
        )
        .await;

    assert!(
        !result.continue_processing,
        "source denial must stop dispatch"
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "denying source should be dispatched once",
    );
    assert!(
        MetadataFetchRequest::from_pipeline_result(&result).is_none(),
        "denied dispatch must not return acquired facts",
    );
    assert_eq!(
        result
            .violation
            .expect("denial must include a violation")
            .code,
        "metadata.unavailable",
        "dispatch must preserve the source's denial code",
    );
}

#[test]
fn caller_rejects_an_unknown_source_before_dispatch() {
    let engine = PolicyEngine::default();
    let error = resolve_source(&engine, "missing")
        .map(|_| ())
        .expect_err("caller must reject an unknown source before dispatch");
    let message = error.to_string();
    assert!(
        message.contains("missing") && message.contains(HOOK_METADATA_FETCH),
        "resolution error must name the missing source and required hook",
    );
}

#[tokio::test]
async fn generic_metadata_dispatch_retains_condition_filtering() {
    for dispatch in ["typed", "named", "dynamic"] {
        let engine = PolicyEngine::default();
        let first_calls = Arc::new(AtomicUsize::new(0));
        let gated_calls = Arc::new(AtomicUsize::new(0));
        register_source(&engine, config("first"), Arc::clone(&first_calls), false);
        let mut gated = config("gated");
        gated.conditions = vec![PluginCondition {
            tools: Some(HashSet::from(["checkout".to_owned()])),
            ..PluginCondition::default()
        }];
        register_source(&engine, gated, Arc::clone(&gated_calls), false);

        let (result, _) = match dispatch {
            "typed" => {
                engine
                    .invoke::<MetadataFetchHook>(
                        MetadataFetchRequest::new(),
                        Extensions::default(),
                        None,
                    )
                    .await
            },
            "named" => {
                engine
                    .invoke_named::<MetadataFetchHook>(
                        HOOK_METADATA_FETCH,
                        MetadataFetchRequest::new(),
                        Extensions::default(),
                        None,
                    )
                    .await
            },
            _ => {
                engine
                    .invoke_by_name(
                        HOOK_METADATA_FETCH,
                        Box::new(MetadataFetchRequest::new()),
                        Extensions::default(),
                        None,
                    )
                    .await
            },
        };

        assert!(
            result.continue_processing,
            "{dispatch} dispatch should allow"
        );
        assert_eq!(
            first_calls.load(Ordering::Relaxed),
            1,
            "{dispatch} dispatch should run an unconditional metadata handler",
        );
        assert_eq!(
            gated_calls.load(Ordering::Relaxed),
            0,
            "{dispatch} dispatch must retain ordinary condition filtering",
        );
    }
}

#[test]
fn documented_metadata_fetch_fixture_parses() {
    let fixture = include_str!("fixtures/metadata_fetch.yaml");
    let policy = praxis_policy_core::config::parse_config(fixture)
        .expect("documented metadata fetch fixture should parse");
    assert_eq!(
        policy.engine_settings.dispatch,
        praxis_policy_core::config::DispatchMode::Hooks,
        "metadata source example must use hook dispatch",
    );
    assert_eq!(
        policy.plugins.len(),
        1,
        "metadata source example should declare one plugin",
    );
    let plugin = policy
        .plugins
        .first()
        .expect("example should include its plugin");
    assert_eq!(
        plugin.hooks,
        vec![HOOK_METADATA_FETCH.to_owned()],
        "metadata source example should declare metadata.fetch",
    );
    assert_eq!(
        plugin.mode,
        PluginMode::Sequential,
        "metadata source must preserve its returned payload",
    );
    assert!(
        include_str!("../../../docs/content/pipeline.md").contains(fixture.trim()),
        "pipeline documentation should retain the exact tested configuration",
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

struct Source {
    config: PluginConfig,
    calls: Arc<AtomicUsize>,
    deny: bool,
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
        if self.deny {
            return PluginResult::deny(PluginViolation::new(
                "metadata.unavailable",
                "metadata source refused acquisition",
            ));
        }
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

fn register_source(
    engine: &PolicyEngine,
    config: PluginConfig,
    calls: Arc<AtomicUsize>,
    deny: bool,
) {
    engine
        .register_handler_for_names::<MetadataFetchHook, _>(
            Arc::new(Source {
                config: config.clone(),
                calls,
                deny,
            }),
            config,
            &[HOOK_METADATA_FETCH],
        )
        .expect("metadata source should register");
}

fn resolve_source(engine: &PolicyEngine, name: &str) -> Result<HookEntry, Box<PluginError>> {
    engine
        .find_plugin_entries(name)
        .into_iter()
        .find(|(hook, _)| hook == HOOK_METADATA_FETCH)
        .map(|(_, entry)| entry)
        .ok_or_else(|| {
            PluginError::Config {
                message: format!("metadata source '{name}' has no '{HOOK_METADATA_FETCH}' handler"),
            }
            .boxed()
        })
}
