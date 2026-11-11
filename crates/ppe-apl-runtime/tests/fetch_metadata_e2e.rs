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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
    ReservedError,
    Hang,
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
            SourceResult::ReservedError => AcquiredFacts::error(
                "elicitation.store_unavailable",
                MetadataCacheDisposition::Disabled,
            ),
            SourceResult::Hang => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                AcquiredFacts::success(
                    serde_json::json!({"active": true}),
                    Utc::now(),
                    MetadataCacheDisposition::Disabled,
                )
            },
        };
        PluginResult::modify_payload(request.clone().with_facts(facts))
    }
}

impl HookHandler<CmfHook> for Source {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _context: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
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

struct CountingDualSourceFactory {
    creates: Arc<AtomicUsize>,
}

impl PluginFactory for CountingDualSourceFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        let source = Arc::new(Source {
            config: config.clone(),
            result: SourceResult::Success,
        });
        Ok(PluginInstance {
            plugin: source.clone(),
            handlers: vec![
                (
                    "metadata.fetch",
                    Arc::new(TypedHandlerAdapter::<MetadataFetchHook, _>::new(
                        source.clone(),
                    )),
                ),
                (
                    "cmf.tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(source)),
                ),
            ],
        })
    }
}

struct NoHandlerFactory;

impl PluginFactory for NoHandlerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        Ok(PluginInstance {
            plugin: Arc::new(Source {
                config: config.clone(),
                result: SourceResult::Success,
            }),
            handlers: Vec::new(),
        })
    }
}

/// Build a request whose flag controls the conditional-fetch scenarios.
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

/// Build the request extension view shared by the end-to-end scenarios.
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

/// Load an engine with one controlled metadata source and the supplied policy.
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
/// Fetched facts are available to the immediately following APL predicate.
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
/// Fetched facts are included in the immediately following PDP input.
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
/// A failing source denies without leaving a partial metadata record.
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
/// An ignored source error publishes only its normalized error outcome.
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
/// Executor failures remain fail-closed even when source records are ignored.
async fn ignored_source_timeout_without_a_record_denies() {
    let engine = engine(
        r#"
engine_settings:
  dispatch: policy
  plugin_timeout: 1
plugins:
  - name: account
    kind: test-source
    hooks: [metadata.fetch]
    on_error: ignore
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(account)"]
"#,
        SourceResult::Hang,
    )
    .await;

    let (result, _) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(true), extensions(), None)
        .await;

    assert!(!result.continue_processing, "a missing record must deny");
    assert_eq!(
        result
            .violation
            .as_ref()
            .map(|violation| violation.code.as_str()),
        Some("plugin_timeout"),
        "the executor timeout must remain fail-closed under ignore: {:?}",
        result.violation
    );
}

#[tokio::test]
/// Source codes cannot impersonate framework control signals.
async fn reserved_source_error_code_is_rejected() {
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
        SourceResult::ReservedError,
    )
    .await;

    let (result, _) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(true), extensions(), None)
        .await;

    let violation = result.violation.expect("invalid source code must deny");
    assert_ne!(violation.code, "elicitation.store_unavailable");
    assert!(violation.reason.contains("must start with `metadata.`"));
}

#[tokio::test]
/// One overridden source shared by `run()` and `fetch()` is instantiated once.
async fn run_and_fetch_share_one_overridden_source_instance() {
    let creates = Arc::new(AtomicUsize::new(0));
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(
        "dual-source",
        Box::new(CountingDualSourceFactory {
            creates: Arc::clone(&creates),
        }),
    );
    register_apl(&engine, AplOptions::in_process());
    engine
        .load_config_yaml(
            r#"
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: dual-source
    hooks: [cmf.tool_pre_invoke, metadata.fetch]
routes:
  - tool: check_account
    plugins:
      account:
        config:
          tenant: route
    authorization:
      pre_invocation:
        - "run(account)"
        - "fetch(account)"
"#,
        )
        .expect("configuration loads");
    engine.initialize().await.expect("engine initializes");

    assert_eq!(
        creates.load(Ordering::SeqCst),
        1,
        "run and fetch must share one route-override instance"
    );
}

#[tokio::test]
/// A false conditional does not dispatch or create a metadata instance.
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
    assert!(
        result.continue_processing,
        "conditional fetch should be skipped: {:?}",
        result.violation
    );
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
/// Loading rejects a fetch whose source is absent from the plugin registry.
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
/// Loading rejects a source registered for an incompatible hook family.
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
    assert!(
        error
            .to_string()
            .contains("must declare the `metadata.fetch` hook"),
        "{error}"
    );
}

#[test]
/// Declaring the hook without installing its handler is rejected at load time.
fn metadata_source_without_registered_handler_is_rejected_at_load() {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory("test-source", Box::new(NoHandlerFactory));
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
routes:
  - tool: check_account
    authorization:
      pre_invocation: ["fetch(account)"]
"#,
        )
        .expect_err("a declared metadata.fetch source needs a registered handler");
    assert!(
        error.to_string().contains("no registered handler"),
        "{error}"
    );
}

#[test]
/// Route stacking cannot introduce a second fetch of the same source.
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
/// Fetch sources must use the sequential execution mode.
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
/// Fetch sources reject error policies that cannot preserve fetch semantics.
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
