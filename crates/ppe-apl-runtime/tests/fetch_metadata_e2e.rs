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

use async_trait::async_trait;
use chrono::Utc;
use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};
use praxis_policy_apl_core::{AttributeBag, Decision};
use praxis_policy_apl_runtime::{AplOptions, register_apl};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, ToolCall};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::extensions::{
    AcquiredFacts, Extensions, MetaExtension, MetadataCacheDisposition,
};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::{HookHandler, PluginResult, TypedHandlerAdapter};
use praxis_policy_core::metadata::{MetadataFetchHook, MetadataFetchRequest};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

#[derive(Clone, Copy)]
enum SourceResult {
    Success,
    Error,
}

struct Source {
    config: PluginConfig,
    result: SourceResult,
}

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
        _context: &mut PluginContext,
    ) -> PluginResult<MetadataFetchRequest> {
        let facts = match self.result {
            SourceResult::Success => AcquiredFacts::success(
                serde_json::json!({"active": true}),
                Utc::now(),
                MetadataCacheDisposition::Disabled,
            ),
            SourceResult::Error => AcquiredFacts::error(
                "metadata.upstream_error",
                MetadataCacheDisposition::Disabled,
            ),
        };
        PluginResult::modify_payload(request.clone().with_facts(facts))
    }
}

struct SourceFactory(SourceResult);

impl PluginFactory for SourceFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let source = Arc::new(Source {
            config: config.clone(),
            result: self.0,
        });
        Ok(PluginInstance {
            plugin: source.clone(),
            handlers: vec![(
                "metadata.fetch",
                Arc::new(TypedHandlerAdapter::<MetadataFetchHook, _>::new(source)),
            )],
        })
    }
}

fn payload(fetch: bool) -> MessagePayload {
    MessagePayload {
        message: Message {
            schema_version: "1.0".to_owned(),
            role: Role::User,
            content: vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "call-1".to_owned(),
                    name: "check_account".to_owned(),
                    arguments: HashMap::from([("fetch".to_owned(), serde_json::json!(fetch))]),
                    namespace: None,
                },
            }],
            channel: None,
        },
    }
}

fn extensions() -> Extensions {
    let meta = MetaExtension {
        entity_type: Some("tool".to_owned()),
        entity_name: Some("check_account".to_owned()),
        ..MetaExtension::default()
    };
    Extensions {
        meta: Some(Arc::new(meta)),
        ..Extensions::default()
    }
}

async fn engine(yaml: &str, result: SourceResult) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory("test-source", Box::new(SourceFactory(result)));
    register_apl(&engine, AplOptions::in_process());
    engine.load_config_yaml(yaml).expect("configuration loads");
    engine.initialize().await.expect("engine initializes");
    engine
}

struct MetadataPdp;

#[async_trait]
impl PdpResolver for MetadataPdp {
    fn dialect(&self) -> PdpDialect {
        PdpDialect::Custom("metadata-check".to_owned())
    }

    async fn evaluate(&self, _call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        let decision = if bag.get_bool("metadata.account.active") == Some(true) {
            Decision::Allow
        } else {
            Decision::Deny {
                reason: Some("fetched metadata missing".to_owned()),
                rule_source: "metadata-check".to_owned(),
            }
        };
        Ok(PdpDecision {
            decision,
            diagnostics: Vec::new(),
        })
    }
}

#[tokio::test]
async fn fetched_facts_are_visible_to_the_next_predicate() {
    let engine = engine(
        r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
routes:
  - tool: check_account
    authorization:
      pre_invocation:
        - "fetch(account)"
        - "require(metadata.account.active)"
"#,
        SourceResult::Success,
    )
    .await;
    let (result, _) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(true), extensions(), None)
        .await;
    assert!(
        result.continue_processing,
        "fetched active fact should allow"
    );
    assert!(
        result
            .modified_extensions
            .as_ref()
            .and_then(|extensions| extensions.metadata.as_deref())
            .and_then(|metadata| metadata.get("account"))
            .is_some(),
        "successful fetch should publish its record"
    );
}

#[tokio::test]
async fn fetched_facts_are_visible_to_the_next_pdp() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
routes:
  - tool: check_account
    authorization:
      pre_invocation:
        - "fetch(account)"
        - pdp(metadata-check): {}
"#;
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(
        "test-source",
        Box::new(SourceFactory(SourceResult::Success)),
    );
    let mut options = AplOptions::in_process();
    options.pdps.push(Arc::new(MetadataPdp));
    register_apl(&engine, options);
    engine.load_config_yaml(yaml).expect("configuration loads");
    engine.initialize().await.expect("engine initializes");

    let (result, _) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(true), extensions(), None)
        .await;
    assert!(
        result.continue_processing,
        "PDP should see the freshly fetched account record"
    );
}

#[tokio::test]
async fn failed_source_publishes_nothing_and_stops() {
    let engine = engine(
        r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
    on_error: fail
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(account)"]
"#,
        SourceResult::Error,
    )
    .await;
    let (result, _) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(true), extensions(), None)
        .await;
    assert!(!result.continue_processing, "on_error fail must stop");
    assert_eq!(
        result
            .violation
            .as_ref()
            .map(|violation| violation.code.as_str()),
        Some("metadata.upstream_error"),
        "the source-owned normalized error must remain the denial code"
    );
    assert!(
        result
            .modified_extensions
            .as_ref()
            .and_then(|extensions| extensions.metadata.as_deref())
            .and_then(|metadata| metadata.get("account"))
            .is_none(),
        "failure must publish no metadata record"
    );
}

#[tokio::test]
async fn ignored_source_error_is_published_for_later_policy() {
    let engine = engine(
        r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
    on_error: ignore
routes:
  - tool: check_account
    authorization:
      pre_invocation:
        - "fetch(account)"
        - "require(metadata.account.$outcome == 'error')"
"#,
        SourceResult::Error,
    )
    .await;
    let (result, _) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(true), extensions(), None)
        .await;
    assert!(result.continue_processing, "ignored error should continue");
    let facts = result
        .modified_extensions
        .as_ref()
        .and_then(|extensions| extensions.metadata.as_deref())
        .and_then(|metadata| metadata.get("account"))
        .expect("ignored error record is published");
    assert_eq!(facts.error_code(), Some("metadata.upstream_error"));
    assert!(
        facts.value().is_none(),
        "error record must not carry a value"
    );
}

#[tokio::test]
async fn skipped_conditional_fetch_publishes_no_instance() {
    let engine = engine(
        r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
routes:
  - tool: check_account
    authorization:
      pre_invocation:
        - when: args.fetch == true
          do: "fetch(account)"
"#,
        SourceResult::Success,
    )
    .await;
    let (result, _) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(false), extensions(), None)
        .await;
    assert!(result.continue_processing);
    assert!(
        result
            .modified_extensions
            .as_ref()
            .and_then(|extensions| extensions.metadata.as_deref())
            .and_then(|metadata| metadata.get("account"))
            .is_none(),
        "skipped fetch publishes no metadata record"
    );
}

#[test]
fn unknown_metadata_source_is_rejected_at_load() {
    let engine = Arc::new(PolicyEngine::default());
    register_apl(&engine, AplOptions::in_process());
    let error = engine
        .load_config_yaml(
            r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(missing)"]
"#,
        )
        .expect_err("an unreachable metadata source must fail the load");
    assert!(error.to_string().contains("missing"), "{error}");
}

#[test]
fn incompatible_metadata_source_hook_is_rejected_at_load() {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(
        "test-source",
        Box::new(SourceFactory(SourceResult::Success)),
    );
    register_apl(&engine, AplOptions::in_process());
    let error = engine
        .load_config_yaml(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(account)"]
"#,
        )
        .expect_err("a source without metadata.fetch must fail the load");
    assert!(error.to_string().contains("metadata.fetch"), "{error}");
}

#[test]
fn duplicate_fetch_introduced_by_route_stacking_is_rejected() {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(
        "test-source",
        Box::new(SourceFactory(SourceResult::Success)),
    );
    register_apl(&engine, AplOptions::in_process());
    let error = engine
        .load_config_yaml(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
global:
  authorization:
    pre_invocation: ["fetch(account)"]
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(account)"]
"#,
        )
        .expect_err("stacked duplicate fetches must fail the load");
    assert!(
        error.to_string().contains("fetched more than once"),
        "{error}"
    );
}

#[test]
fn metadata_source_with_non_sequential_mode_is_rejected_at_load() {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(
        "test-source",
        Box::new(SourceFactory(SourceResult::Success)),
    );
    register_apl(&engine, AplOptions::in_process());
    let error = engine
        .load_config_yaml(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
    mode: audit
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(account)"]
"#,
        )
        .expect_err("a read-only source mode cannot return AcquiredFacts");
    assert!(
        error.to_string().contains("must use `sequential`"),
        "{error}"
    );
}

#[test]
fn metadata_source_with_disable_error_policy_is_rejected_at_load() {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(
        "test-source",
        Box::new(SourceFactory(SourceResult::Success)),
    );
    register_apl(&engine, AplOptions::in_process());
    let error = engine
        .load_config_yaml(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
    on_error: disable
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(account)"]
"#,
        )
        .expect_err("disable has no defined metadata source semantics");
    assert!(
        error
            .to_string()
            .contains("support only `fail` or `ignore`"),
        "{error}"
    );
}
