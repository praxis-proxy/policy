// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Capability-gating end-to-end. praxis-policy-core's executor calls
// `filter_extensions(&ext, &caps)` before every handler invoke — so the
// synthetic `AplRouteHandler` must declare a capability set wide enough
// to cover every downstream plugin it dispatches, otherwise:
//
//   - APL predicates read from a stripped attribute bag (silently wrong
//     policy decisions).
//   - Downstream plugins receive a doubly-filtered view (their own caps
//     applied on top of an already-stripped one).
//   - Write attempts (append_labels, append_delegation, write_headers)
//     fail the monotonicity check on the way back out of the handler.
//
// These tests verify the visitor computes
// `base_capabilities ∪ per-route plugin union` and sets it on the
// synthetic `PluginConfig`.

#![allow(
    missing_docs,
    clippy::field_reassign_with_default,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::sync::Arc;

use async_trait::async_trait;

use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, ToolCall};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError as CoreError;
use praxis_policy_core::extensions::{LlmRequestDocument, MetaExtension, SecurityExtension};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};
use praxis_policy_apl_runtime::{AplOptions, DispatchCache, MemorySessionStore, register_apl};

// =====================================================================
// Fixtures
// =====================================================================

/// Plugin that records whether it saw `security.labels` populated.
/// Used to verify that `read_labels` capability propagates through the
/// synthetic handler so the inner plugin's filtered view actually
/// contains labels.
struct LabelReader {
    cfg: PluginConfig,
    observed_labels: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for LabelReader {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for LabelReader {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let seen: Vec<String> = extensions
            .security
            .as_ref()
            .map(|s| s.labels.iter().cloned().collect())
            .unwrap_or_default();
        *self.observed_labels.lock().unwrap() = seen;
        PluginResult::allow()
    }
}

struct LabelReaderFactory {
    observed_labels: Arc<std::sync::Mutex<Vec<String>>>,
}

impl PluginFactory for LabelReaderFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(LabelReader {
            cfg: config.clone(),
            observed_labels: Arc::clone(&self.observed_labels),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

/// Plugin that appends a label via `modify_extensions`. Used to verify
/// write-cap propagation: requires both an `append_labels` declaration
/// on the plugin AND the synthetic handler to also be granted
/// `append_labels` so the executor accepts the mutation on the way
/// back out.
struct LabelWriter {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for LabelWriter {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for LabelWriter {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let mut owned = extensions.cow_copy();
        let security = owned.security.get_or_insert_with(Default::default);
        security.add_label("APPENDED");
        PluginResult::modify_extensions(owned)
    }
}

struct LabelWriterFactory;
impl PluginFactory for LabelWriterFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(LabelWriter {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

/// Plugin that records the `llm_request` slot it was handed.
struct LlmRequestReader {
    cfg: PluginConfig,
    observed: Arc<std::sync::Mutex<Vec<Option<LlmRequestDocument>>>>,
}

#[async_trait]
impl Plugin for LlmRequestReader {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for LlmRequestReader {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        self.observed
            .lock()
            .unwrap()
            .push(extensions.llm_request.clone());
        PluginResult::allow()
    }
}

struct LlmRequestReaderFactory {
    observed: Arc<std::sync::Mutex<Vec<Option<LlmRequestDocument>>>>,
}

impl PluginFactory for LlmRequestReaderFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(LlmRequestReader {
            cfg: config.clone(),
            observed: Arc::clone(&self.observed),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn cmf_payload(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_owned());
    meta.entity_name = Some(name.to_owned());
    meta
}

fn extensions_with_label(label: &str) -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label(label.to_owned());
    Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        security: Some(Arc::new(security)),
        ..Default::default()
    }
}

// =====================================================================
// Scenarios
// =====================================================================

/// Plugin declares `read_labels`; route references it; pre-existing
/// label `EXISTING` is set on the request extensions. The plugin must
/// observe the label — proving the synthetic `AplRouteHandler` got
/// `read_labels` from the per-route plugin union (praxis-policy-core's filter
/// would otherwise strip security.labels at the handler boundary).
#[tokio::test]
async fn plugin_with_read_labels_sees_labels_through_apl_handler() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: label-reader
    kind: label-reader
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_labels]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(label-reader)"
"#;

    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "label-reader",
        Box::new(LabelReaderFactory {
            observed_labels: Arc::clone(&observed),
        }),
    );
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let ext = extensions_with_label("EXISTING");
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        result.continue_processing,
        "plugin shouldn't deny: {:?}",
        result.violation
    );

    let seen = observed.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["EXISTING".to_owned()],
        "plugin must observe the EXISTING label that the request carried; \
         empty means the synthetic AplRouteHandler stripped security.labels \
         because its cap union didn't include read_labels"
    );
}

/// Same plugin shape, but DON'T declare `read_labels` on the plugin
/// and set an empty `base_capabilities` so neither the per-route
/// union nor the baseline grants the cap. The plugin must NOT see
/// labels — confirms the negative case (capability gating actually
/// hides things when caps are missing).
#[tokio::test]
async fn plugin_without_read_labels_sees_stripped_view() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: label-reader
    kind: label-reader
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(label-reader)"
"#;

    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "label-reader",
        Box::new(LabelReaderFactory {
            observed_labels: Arc::clone(&observed),
        }),
    );
    // Strict mode: empty baseline → only per-plugin caps grant
    // anything, and the plugin declared none.
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: Some(std::collections::HashSet::new()),
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let ext = extensions_with_label("EXISTING");
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(result.continue_processing);

    let seen = observed.lock().unwrap().clone();
    assert!(
        seen.is_empty(),
        "plugin should see no labels when neither it nor the baseline \
         grants read_labels — got: {seen:?}"
    );
}

/// Plugin declares `append_labels` and emits a new label via
/// `modify_extensions`. The synthetic `AplRouteHandler` must also be
/// granted `append_labels` (from the per-route union) so its outer
/// `modify_extensions` write doesn't get rejected on the way back out.
/// After the invoke, the appended label must be visible in the final
/// extensions.
#[tokio::test]
async fn write_capabilities_propagate_through_apl_handler() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: label-writer
    kind: label-writer
    hooks: [cmf.tool_pre_invoke]
    capabilities: [append_labels, read_labels]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(label-writer)"
"#;

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory("label-writer", Box::new(LabelWriterFactory));
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        result.continue_processing,
        "label-writer should allow: {:?}",
        result.violation
    );

    // The appended label should be visible on the way out via
    // `modified_extensions` — None means no plugin wrote anything,
    // which would be a failure here.
    let modified = result
        .modified_extensions
        .expect("label-writer should have modified extensions");
    let labels: Vec<String> = modified
        .security
        .as_ref()
        .map(|s| s.labels.iter().cloned().collect())
        .unwrap_or_default();
    assert!(
        labels.contains(&"APPENDED".to_owned()),
        "expected APPENDED to land in final security.labels — \
         a missing label means the executor rejected the write on the \
         way out of AplRouteHandler (no append_labels cap on the synthetic). \
         Got: {labels:?}"
    );
}

/// Predicate-only route: no plugins, just `require(authenticated)`.
/// APL evaluates this against the attribute bag built from the
/// (capability-filtered) Extensions view the handler sees. Default
/// baseline grants `read_subject`, so `authenticated` evaluates to
/// `true` when subject is present.
#[tokio::test]
async fn predicate_only_route_uses_baseline_capabilities() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#;
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    // Set subject id so `authenticated` derives true via praxis-policy-apl-cmf.
    let mut security = SecurityExtension::default();
    security.subject = Some(praxis_policy_core::extensions::SubjectExtension {
        id: Some("alice".to_owned()),
        ..Default::default()
    });
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        security: Some(Arc::new(security)),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        result.continue_processing,
        "require(authenticated) should pass with subject.id set: violation = {:?}",
        result.violation
    );
}

/// Same predicate-only route but baseline is forcibly empty AND no
/// subject is set. With empty baseline the synthetic handler has no
/// caps, so security.subject is stripped → `authenticated` evaluates
/// false → `require(authenticated)` denies. Confirms the baseline
/// actually controls what predicates can read.
#[tokio::test]
async fn empty_baseline_strips_predicate_view() {
    const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "require(authenticated)"
"#;
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: Some(std::collections::HashSet::new()),
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    // Even though subject.id IS set, the empty baseline means the
    // synthetic handler can't read subject — predicate sees missing →
    // false → require denies.
    let mut security = SecurityExtension::default();
    security.subject = Some(praxis_policy_core::extensions::SubjectExtension {
        id: Some("alice".to_owned()),
        ..Default::default()
    });
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        security: Some(Arc::new(security)),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        !result.continue_processing,
        "empty baseline should cause require(authenticated) to deny \
         even with subject set — capability gating proves it can't see"
    );
}

/// Runs `llm-reader` on a tool route with the host baseline replaced by an
/// empty set, and returns the slot the plugin observed alongside the host's.
async fn observe_llm_request(
    capabilities: &str,
) -> (Option<LlmRequestDocument>, LlmRequestDocument) {
    let yaml = format!(
        r#"
engine_settings:
  dispatch: policy
plugins:
  - name: llm-reader
    kind: llm-reader
    hooks: [cmf.tool_pre_invoke]
    capabilities: {capabilities}
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(llm-reader)"
"#
    );

    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "llm-reader",
        Box::new(LlmRequestReaderFactory {
            observed: Arc::clone(&observed),
        }),
    );
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: Some(std::collections::HashSet::new()),
        },
    );
    mgr.load_config_yaml(&yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let document = LlmRequestDocument::new(serde_json::json!({
        "model": "gpt-4o",
        "tools": [{"type": "function", "name": "search"}],
    }));
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        llm_request: Some(document.clone()),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        result.continue_processing,
        "llm-reader should allow: {:?}",
        result.violation
    );

    let mut seen = std::mem::take(&mut *observed.lock().unwrap());
    assert_eq!(seen.len(), 1, "llm-reader must run exactly once");
    (seen.remove(0), document)
}

/// The synthetic handler keeps the parsed request through the executor filter
/// even with an empty host baseline, and a plugin holding `read_llm_request`
/// sees the host's `Arc` rather than a copy.
#[tokio::test]
async fn llm_request_reaches_plugin_through_apl_handler_with_replaced_baseline() {
    let (seen, document) = observe_llm_request("[read_llm_request]").await;
    let seen = seen.expect("plugin holding read_llm_request must see the slot");
    assert!(Arc::ptr_eq(seen.shared(), document.shared()));
}

/// A plugin without `read_llm_request` sees no document, even though the
/// synthetic handler it runs under holds the capability.
#[tokio::test]
async fn llm_request_hidden_from_plugin_without_capability() {
    let (seen, _document) = observe_llm_request("[]").await;
    assert!(seen.is_none());
}

// =====================================================================
// Structured PDP input
// =====================================================================

/// CEL-dialect PDP that records the structured input it was handed.
#[derive(Default)]
struct StructuredRecorder {
    seen: std::sync::Mutex<Vec<StructuredInput>>,
}

#[async_trait]
impl PdpResolver for StructuredRecorder {
    fn dialect(&self) -> PdpDialect {
        PdpDialect::Cel
    }

    async fn evaluate(
        &self,
        _call: &PdpCall,
        _bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        panic!("the router must forward to evaluate_structured")
    }

    async fn evaluate_structured(
        &self,
        _call: &PdpCall,
        _bag: &AttributeBag,
        structured: &StructuredInput,
    ) -> Result<PdpDecision, PdpError> {
        self.seen.lock().unwrap().push(structured.clone());
        Ok(PdpDecision {
            decision: Decision::Allow,
            diagnostics: Vec::new(),
        })
    }
}

/// Runs one invocation of `hook` against a route whose only step is a PDP
/// call, with no plugins and an empty host baseline, and returns every
/// structured input the PDP received. Any route-level `args:` block goes in
/// `route_extra`.
async fn run_structured(
    selector: &str,
    route_extra: &str,
    hook: &str,
    payload: MessagePayload,
    ext: Extensions,
) -> (
    Vec<StructuredInput>,
    praxis_policy_core::executor::PipelineResult,
) {
    let yaml = format!(
        r#"
engine_settings:
  dispatch: policy
routes:
  - {selector}
{route_extra}    authorization:
      pre_invocation:
        - cel:
            expr: "true"
"#
    );
    let recorder = Arc::new(StructuredRecorder::default());
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: vec![recorder.clone()],
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: Some(std::collections::HashSet::new()),
        },
    );
    mgr.load_config_yaml(&yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let (result, _bg) = mgr.invoke_named::<CmfHook>(hook, payload, ext, None).await;
    let seen = std::mem::take(&mut *recorder.seen.lock().unwrap());
    (seen, result)
}

/// Like [`run_structured`], for a route that must allow after exactly one
/// PDP call. Returns what that call received.
async fn observe_structured(
    selector: &str,
    route_extra: &str,
    hook: &str,
    payload: MessagePayload,
    ext: Extensions,
) -> (
    StructuredInput,
    praxis_policy_core::executor::PipelineResult,
) {
    let (mut seen, result) = run_structured(selector, route_extra, hook, payload, ext).await;
    assert!(
        result.continue_processing,
        "route should allow: {:?}",
        result.violation
    );
    assert_eq!(seen.len(), 1, "the PDP must run exactly once");
    (seen.remove(0), result)
}

fn meta_for(entity_type: &str, name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(entity_type.to_owned());
    meta.entity_name = Some(name.to_owned());
    meta
}

fn tool_call_payload(arguments: serde_json::Value) -> MessagePayload {
    let serde_json::Value::Object(arguments) = arguments else {
        panic!("tool-call arguments must be an object");
    };
    MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".to_owned(),
                    name: "classify".to_owned(),
                    arguments: arguments.into_iter().collect(),
                    namespace: None,
                },
            }],
        ),
    }
}

fn request_document() -> LlmRequestDocument {
    LlmRequestDocument::new(serde_json::json!({
        "model": "gpt-4o",
        "tools": [{"type": "function", "name": "search"}],
    }))
}

/// A tool route hands the PDP the first tool call's arguments as JSON, so an
/// array of objects survives that the flat bag would drop.
#[tokio::test]
async fn tool_route_pdp_receives_structured_args() {
    let ext = Extensions {
        meta: Some(Arc::new(meta_for("tool", "classify"))),
        ..Default::default()
    };
    let payload = tool_call_payload(serde_json::json!({
        "items": [{"classification": "public"}, {"classification": "secret"}],
    }));
    let (seen, _) =
        observe_structured("tool: classify", "", "cmf.tool_pre_invoke", payload, ext).await;
    let args = seen
        .args()
        .cloned()
        .expect("tool route must carry structured args");
    let items = args["items"].as_array().expect("items stays an array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[1]["classification"], "secret");
    assert!(seen.llm_request().is_none());
}

/// A tool invocation whose message has no tool-call part carries no structured
/// args, never an empty object.
#[tokio::test]
async fn tool_route_without_tool_call_part_has_no_args() {
    let ext = Extensions {
        meta: Some(Arc::new(meta_for("tool", "classify"))),
        ..Default::default()
    };
    let (seen, _) = observe_structured(
        "tool: classify",
        "",
        "cmf.tool_pre_invoke",
        cmf_payload("hi"),
        ext,
    )
    .await;
    assert!(seen.args().is_none());
    assert!(seen.llm_request().is_none());
}

/// With no plugin on the route, the PDP still sees the host's document: the
/// synthetic handler's own grant is what lets it through the executor filter.
#[tokio::test]
async fn llm_route_pdp_receives_host_document_without_plugins() {
    let document = request_document();
    let ext = Extensions {
        meta: Some(Arc::new(meta_for("llm", "gpt-4o"))),
        llm_request: Some(document.clone()),
        ..Default::default()
    };
    let (seen, _) =
        observe_structured("llm: gpt-4o", "", "cmf.llm_input", cmf_payload("hi"), ext).await;
    let seen_doc = seen
        .llm_request()
        .cloned()
        .expect("llm route must carry the document");
    assert!(Arc::ptr_eq(&seen_doc, document.shared()));
    assert!(seen.args().is_none(), "llm routes carry no structured args");
}

/// No slot on the request means no document, never an empty object.
#[tokio::test]
async fn llm_route_without_slot_has_no_document() {
    let ext = Extensions {
        meta: Some(Arc::new(meta_for("llm", "gpt-4o"))),
        ..Default::default()
    };
    let (seen, _) =
        observe_structured("llm: gpt-4o", "", "cmf.llm_input", cmf_payload("hi"), ext).await;
    assert!(seen.llm_request().is_none());
    assert!(seen.args().is_none());
}

/// A tool call replayed inside an LLM message does not become structured args.
#[tokio::test]
async fn llm_route_tool_call_part_does_not_fill_args() {
    let ext = Extensions {
        meta: Some(Arc::new(meta_for("llm", "gpt-4o"))),
        ..Default::default()
    };
    let payload = tool_call_payload(serde_json::json!({"items": [{"classification": "secret"}]}));
    let (seen, _) = observe_structured("llm: gpt-4o", "", "cmf.llm_input", payload, ext).await;
    assert!(seen.args().is_none());
}

/// An `args:` pipeline that rewrites a field does not change what the PDP
/// sees: structured args are the pre-pipeline snapshot, as the bag is.
#[tokio::test]
async fn tool_route_pdp_sees_args_before_pipeline_rewrite() {
    let ext = Extensions {
        meta: Some(Arc::new(meta_for("tool", "classify"))),
        ..Default::default()
    };
    let payload = tool_call_payload(serde_json::json!({"city": "Paris"}));
    let (seen, result) = observe_structured(
        "tool: classify",
        "    args:\n      city: \"str | redact\"\n",
        "cmf.tool_pre_invoke",
        payload,
        ext,
    )
    .await;
    assert!(
        result.modified_payload.is_some(),
        "the pipeline must have rewritten the forwarded args"
    );
    let args = seen
        .args()
        .cloned()
        .expect("tool route must carry structured args");
    assert_eq!(args["city"], "Paris");
}

/// Tool arguments nested past the depth limit deny the PDP step before the
/// resolver runs, with a reason that quotes nothing from the arguments.
#[tokio::test]
async fn tool_route_too_deep_args_deny_before_the_pdp() {
    const MARKER: &str = "deep-args-marker";
    let ext = Extensions {
        meta: Some(Arc::new(meta_for("tool", "classify"))),
        ..Default::default()
    };
    // The arguments object adds one level above the nested chain.
    let deep = (1..praxis_policy_apl_core::MAX_STRUCTURED_DEPTH).fold(
        serde_json::json!(MARKER),
        |inner, _| serde_json::json!({MARKER: inner}),
    );
    let payload = tool_call_payload(serde_json::json!({"deep": deep}));
    let (seen, result) =
        run_structured("tool: classify", "", "cmf.tool_pre_invoke", payload, ext).await;
    assert!(seen.is_empty(), "the PDP must not run");
    assert!(!result.continue_processing, "expected deny");
    let violation = result.violation.expect("deny must carry a violation");
    assert_eq!(violation.code, praxis_policy_apl_core::INPUT_TOO_DEEP_CODE);
    let rendered = format!("{violation:?}");
    assert!(!rendered.contains(MARKER), "{rendered}");
}
