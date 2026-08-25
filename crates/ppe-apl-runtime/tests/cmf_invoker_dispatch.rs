// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Integration tests for `CmfPluginInvoker` — exercises the typed
// dispatch path end-to-end against a real `praxis-policy-core::PolicyEngine`
// with hand-rolled test plugins. v0 coverage:
//   - `Step` invocation against an allow-plugin → `Decision::Allow`
//   - `Step` invocation against a deny-plugin → `Decision::Deny` with
//     reason + rule_source pulled from the PPE `PluginViolation`
//   - `Field` invocation against a modify-plugin → `Decision::Allow`
//     with `modified_value` populated from the rewritten text content
//   - Payload mutation persists across invocations (one modifying
//     plugin's output is visible to the next).

#![allow(
    missing_docs,
    trivial_casts,
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
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::{PluginError as CoreError, PluginViolation};
use praxis_policy_core::extensions::{SecurityExtension, SubjectExtension};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::HookPhase;
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::{HookEntry, PluginRef};

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::step::{PluginInvocation, PluginInvoker as _};

use praxis_policy_apl_runtime::{CmfPluginInvoker, MemorySessionStore, RouteDispatchPlan};

/// Build a single-plugin `RouteDispatchPlan` straight off the praxis-policy-core
/// registry — no APL `CompiledRoute` involved. Used by the invoker-primitive
/// tests below to exercise the plan-based dispatch path without standing
/// up a full route.
fn plan_for(
    engine: &praxis_policy_core::engine::PolicyEngine,
    plugin_name: &str,
) -> Arc<RouteDispatchPlan> {
    let entry = RouteDispatchPlan::resolve_plugin(engine, plugin_name)
        .expect("plugin must be registered with the engine");
    let mut plugins = std::collections::HashMap::new();
    plugins.insert(plugin_name.to_owned(), entry);
    Arc::new(RouteDispatchPlan {
        plugins,
        delegation_entries: Default::default(),
        elicitation_entries: Default::default(),
    })
}

// ---------------------------------------------------------------------
// Test plugins — minimal CMF handlers with hard-coded behavior so the
// dispatch path is exercised without external state.
// ---------------------------------------------------------------------

struct AllowPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AllowPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AllowPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

struct AllowPluginFactory;
impl PluginFactory for AllowPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(AllowPlugin {
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

struct DenyPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for DenyPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for DenyPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(PluginViolation::new(
            "policy.forbidden",
            "test-fixture denied this call",
        ))
    }
}

struct DenyPluginFactory;
impl PluginFactory for DenyPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(DenyPlugin {
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

/// Modify plugin — rewrites every Text part by appending `" [MODIFIED]"`
/// so the test can assert mutation propagation deterministically.
struct ModifyPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for ModifyPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for ModifyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let new_content: Vec<ContentPart> = payload
            .message
            .content
            .iter()
            .map(|part| match part {
                ContentPart::Text { text } => ContentPart::Text {
                    text: format!("{text} [MODIFIED]"),
                },
                other => other.clone(),
            })
            .collect();
        PluginResult::modify_payload(MessagePayload {
            message: Message {
                schema_version: payload.message.schema_version.clone(),
                role: payload.message.role,
                content: new_content,
                channel: payload.message.channel,
            },
        })
    }
}

struct ModifyPluginFactory;
impl PluginFactory for ModifyPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(ModifyPlugin {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.field_redact",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

/// Redactor that rewrites **only** `ToolResult.content`, leaving every
/// Text part byte-identical. This is the shape of a real PII/secret
/// redactor, and the shape whose mutation used to vanish: nothing about
/// the message's text changes, so text-based change detection reports
/// "unmodified" and the unredacted result gets forwarded.
struct RedactToolResultPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for RedactToolResultPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for RedactToolResultPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let new_content: Vec<ContentPart> = payload
            .message
            .content
            .iter()
            .map(|part| match part {
                ContentPart::ToolResult { content } => {
                    let mut redacted = content.clone();
                    redacted.content = serde_json::Value::String("[REDACTED]".to_owned());
                    ContentPart::ToolResult { content: redacted }
                },
                other => other.clone(),
            })
            .collect();
        PluginResult::modify_payload(MessagePayload {
            message: Message {
                schema_version: payload.message.schema_version.clone(),
                role: payload.message.role,
                content: new_content,
                channel: payload.message.channel,
            },
        })
    }
}

struct RedactToolResultPluginFactory;
impl PluginFactory for RedactToolResultPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(RedactToolResultPlugin {
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

// ---------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------

fn payload_with_text(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

/// A message carrying a tool result alongside a text part. The text part
/// is what any text-based comparison would see; the secret lives in the
/// tool result, where only a structural reader finds it.
fn payload_with_tool_result(text: &str, result: &str) -> MessagePayload {
    MessagePayload {
        message: Message::with_content(
            Role::Tool,
            vec![
                ContentPart::Text {
                    text: text.to_owned(),
                },
                ContentPart::ToolResult {
                    content: praxis_policy_core::cmf::ToolResult {
                        tool_call_id: "tc_001".to_owned(),
                        tool_name: "get_secret".to_owned(),
                        content: serde_json::Value::String(result.to_owned()),
                        is_error: false,
                    },
                },
            ],
        ),
    }
}

/// Read the first `ToolResult.content` out of a payload.
fn tool_result_content(payload: &MessagePayload) -> Option<&serde_json::Value> {
    payload.message.content.iter().find_map(|part| match part {
        ContentPart::ToolResult { content } => Some(&content.content),
        _ => None,
    })
}

fn empty_bag() -> AttributeBag {
    AttributeBag::new()
}

/// Build a engine, register one factory + one plugin under the given
/// kind, and return the wired engine ready for invocation.
async fn build_manager(factory_kind: &str, factory: Box<dyn PluginFactory>) -> Arc<PolicyEngine> {
    let mgr = PolicyEngine::default();
    mgr.register_factory(factory_kind, factory);

    let yaml = format!("plugins:\n  - name: {factory_kind}\n    kind: {factory_kind}\n");
    let cfg = praxis_policy_core::config::parse_config(&yaml).expect("parse_config");
    mgr.load_config(cfg).expect("load_config");
    mgr.initialize().await.expect("initialize");
    Arc::new(mgr)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[tokio::test]
async fn step_invocation_allow_returns_decision_allow() {
    let mgr = build_manager("allow-plugin", Box::new(AllowPluginFactory)).await;
    let plan = plan_for(&mgr, "allow-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let outcome = invoker
        .invoke(
            "allow-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(outcome.modified_value.is_none());
}

#[tokio::test]
async fn step_invocation_deny_surfaces_violation_reason_and_code() {
    let mgr = build_manager("deny-plugin", Box::new(DenyPluginFactory)).await;
    let plan = plan_for(&mgr, "deny-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let outcome = invoker
        .invoke(
            "deny-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    match outcome.decision {
        Decision::Deny {
            reason,
            rule_source,
        } => {
            assert_eq!(reason.as_deref(), Some("test-fixture denied this call"));
            assert_eq!(rule_source, "policy.forbidden");
        },
        other => panic!("expected Decision::Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn field_invocation_modify_surfaces_modified_value_and_persists_payload() {
    let mgr = build_manager("modify-plugin", Box::new(ModifyPluginFactory)).await;
    let plan = plan_for(&mgr, "modify-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::Value::String("hello".to_owned());
    let outcome = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    assert_eq!(outcome.decision, Decision::Allow);
    assert_eq!(
        outcome.modified_value,
        Some(serde_json::Value::String("hello [MODIFIED]".to_owned()))
    );

    // Payload mutation persisted: a second invocation sees the updated
    // text as input (modifier appends [MODIFIED] each pass).
    let outcome2 = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");
    assert_eq!(
        outcome2.modified_value,
        Some(serde_json::Value::String(
            "hello [MODIFIED] [MODIFIED]".to_owned()
        ))
    );
}

#[tokio::test]
async fn current_payload_reflects_accumulated_mutations() {
    let mgr = build_manager("modify-plugin", Box::new(ModifyPluginFactory)).await;
    let plan = plan_for(&mgr, "modify-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::Value::String("ignored".to_owned());
    let _ = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    let final_payload = invoker.current_payload().await;
    assert_eq!(final_payload.message.get_text_content(), "hello [MODIFIED]");
}

// ---------------------------------------------------------------------
// Mutation signalling — the invoker reports whether a plugin handed back
// a payload, so the host never has to guess from message content. A
// guess based on text can't see a rewritten tool result, tool call,
// thinking block, image, or any other non-text part.
//
// Not covered here: a plugin returning a payload of the wrong concrete
// type (the downcast-failure path that warns and drops). `HookHandler`
// is typed on `PluginResult<MessagePayload>`, so a foreign payload can't
// be constructed through the typed dispatch path these tests use — it
// would take a hand-rolled `AnyHookHandler` bypassing the adapter.
// ---------------------------------------------------------------------

#[tokio::test]
async fn no_mutation_reported_before_any_dispatch() {
    let mgr = build_manager("allow-plugin", Box::new(AllowPluginFactory)).await;
    let plan = plan_for(&mgr, "allow-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    assert!(
        !invoker.payload_was_modified(),
        "a fresh invoker has dispatched nothing, so nothing can have mutated"
    );
}

#[tokio::test]
async fn plugin_that_allows_without_mutating_reports_no_mutation() {
    let mgr = build_manager("allow-plugin", Box::new(AllowPluginFactory)).await;
    let plan = plan_for(&mgr, "allow-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let _ = invoker
        .invoke(
            "allow-plugin",
            &bag,
            PluginInvocation::Step {
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    assert!(
        !invoker.payload_was_modified(),
        "a plain allow carries no payload; reporting a mutation here would \
         make every request look modified"
    );
}

#[tokio::test]
async fn text_mutation_is_reported() {
    let mgr = build_manager("modify-plugin", Box::new(ModifyPluginFactory)).await;
    let plan = plan_for(&mgr, "modify-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::Value::String("hello".to_owned());
    let _ = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    assert!(invoker.payload_was_modified());
}

/// The reported bug, at the invoker layer: a redactor rewrites only
/// `ToolResult.content`, so the message's text is byte-identical before
/// and after. The mutation must still be reported.
#[tokio::test]
async fn tool_result_only_mutation_is_reported() {
    let mgr = build_manager("redact-plugin", Box::new(RedactToolResultPluginFactory)).await;
    let plan = plan_for(&mgr, "redact-plugin");
    let original = payload_with_tool_result("here is the result", "sk-secret-value");
    let text_before = original.message.get_text_content();
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        original,
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let _ = invoker
        .invoke(
            "redact-plugin",
            &bag,
            PluginInvocation::Step {
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    let final_payload = invoker.current_payload().await;
    assert_eq!(
        tool_result_content(&final_payload),
        Some(&serde_json::Value::String("[REDACTED]".to_owned())),
        "the redaction must land in the shared payload"
    );
    assert_eq!(
        final_payload.message.get_text_content(),
        text_before,
        "fixture sanity: the text is untouched, so text comparison sees no change"
    );
    assert!(
        invoker.payload_was_modified(),
        "the mutation is invisible to text comparison but must still be reported"
    );
}

// ---------------------------------------------------------------------
// Field-stage dispatch — a plugin invoked from an `args:` / `result:`
// pipeline is handed the whole message, so its new value for the field
// in focus has to be read back out of the part that field came from.
// Reporting the message's concatenated text instead would overwrite a
// structured argument with unrelated content.
// ---------------------------------------------------------------------

/// Rewrites one named tool-call argument, leaving other arguments and
/// all text parts alone.
struct ArgRewritePlugin {
    cfg: PluginConfig,
    arg: &'static str,
}

#[async_trait]
impl Plugin for ArgRewritePlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for ArgRewritePlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let content: Vec<ContentPart> = payload
            .message
            .content
            .iter()
            .map(|part| match part {
                ContentPart::ToolCall { content } => {
                    let mut next = content.clone();
                    next.arguments.insert(
                        self.arg.to_owned(),
                        serde_json::Value::String("[REDACTED]".to_owned()),
                    );
                    ContentPart::ToolCall { content: next }
                },
                other => other.clone(),
            })
            .collect();
        PluginResult::modify_payload(MessagePayload {
            message: Message {
                schema_version: payload.message.schema_version.clone(),
                role: payload.message.role,
                content,
                channel: payload.message.channel,
            },
        })
    }
}

struct ArgRewriteFactory {
    arg: &'static str,
}

impl PluginFactory for ArgRewriteFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(ArgRewritePlugin {
            cfg: config.clone(),
            arg: self.arg,
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.field_redact",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

/// Rewrites one field inside an object-shaped tool result. The Post-phase
/// counterpart to `ArgRewritePlugin`.
struct ResultFieldRewritePlugin {
    cfg: PluginConfig,
    field: &'static str,
}

#[async_trait]
impl Plugin for ResultFieldRewritePlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for ResultFieldRewritePlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let content: Vec<ContentPart> = payload
            .message
            .content
            .iter()
            .map(|part| match part {
                ContentPart::ToolResult { content } => {
                    let mut next = content.clone();
                    if let Some(obj) = next.content.as_object_mut() {
                        obj.insert(
                            self.field.to_owned(),
                            serde_json::Value::String("[REDACTED]".to_owned()),
                        );
                    }
                    ContentPart::ToolResult { content: next }
                },
                other => other.clone(),
            })
            .collect();
        PluginResult::modify_payload(MessagePayload {
            message: Message {
                schema_version: payload.message.schema_version.clone(),
                role: payload.message.role,
                content,
                channel: payload.message.channel,
            },
        })
    }
}

struct ResultFieldRewriteFactory {
    field: &'static str,
}

impl PluginFactory for ResultFieldRewriteFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(ResultFieldRewritePlugin {
            cfg: config.clone(),
            field: self.field,
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.field_redact",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

fn payload_with_tool_call(city: &str, note: &str) -> MessagePayload {
    MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![
                ContentPart::Text {
                    text: note.to_owned(),
                },
                ContentPart::ToolCall {
                    content: praxis_policy_core::cmf::ToolCall {
                        tool_call_id: "tc_001".to_owned(),
                        name: "get_weather".to_owned(),
                        arguments: [("city".to_owned(), serde_json::json!(city))]
                            .into_iter()
                            .collect(),
                        namespace: None,
                    },
                },
            ],
        ),
    }
}

/// The field in focus is `city`, and the plugin rewrites `city`. The new
/// value must be the redacted city, not the message's text.
#[tokio::test]
async fn field_dispatch_reports_the_field_the_plugin_rewrote() {
    let mgr = build_manager("arg-redactor", Box::new(ArgRewriteFactory { arg: "city" })).await;
    let plan = plan_for(&mgr, "arg-redactor");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_tool_call("London", "unrelated chatter"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::json!("London");
    let outcome = invoker
        .invoke(
            "arg-redactor",
            &bag,
            PluginInvocation::Field {
                name: "city",
                value: &value,
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    assert_eq!(
        outcome.modified_value,
        Some(serde_json::json!("[REDACTED]"))
    );
}

/// The field in focus is `city`, but the plugin rewrote `token`. The
/// pipeline must be told the field is unchanged — and the payload
/// mutation must still be recorded, so the rewrite isn't lost.
#[tokio::test]
async fn field_dispatch_reports_no_change_when_another_field_was_rewritten() {
    let mgr = build_manager("arg-redactor", Box::new(ArgRewriteFactory { arg: "token" })).await;
    let plan = plan_for(&mgr, "arg-redactor");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_tool_call("London", "unrelated chatter"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::json!("London");
    let outcome = invoker
        .invoke(
            "arg-redactor",
            &bag,
            PluginInvocation::Field {
                name: "city",
                value: &value,
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    assert_eq!(
        outcome.modified_value, None,
        "the field in focus is untouched, so the pipeline must leave it alone"
    );
    assert!(
        invoker.payload_was_modified(),
        "the rewrite of another field still has to reach the host"
    );
}

/// Post-phase dispatch reads the field out of the *result* projection,
/// not the args one. A `result:` pipeline stage that rewrites one field
/// of a structured tool result must get that field back.
#[tokio::test]
async fn post_phase_field_dispatch_reads_the_result_projection() {
    let mgr = build_manager(
        "result-redactor",
        Box::new(ResultFieldRewriteFactory { field: "ssn" }),
    )
    .await;
    let plan = plan_for(&mgr, "result-redactor");
    let payload = MessagePayload {
        message: Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolResult {
                content: praxis_policy_core::cmf::ToolResult {
                    tool_call_id: "tc_001".to_owned(),
                    tool_name: "get_employee".to_owned(),
                    content: serde_json::json!({"name": "Ada", "ssn": "123-45-6789"}),
                    is_error: false,
                },
            }],
        ),
    };
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload,
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::json!("123-45-6789");
    let outcome = invoker
        .invoke(
            "result-redactor",
            &bag,
            PluginInvocation::Field {
                name: "ssn",
                value: &value,
                phase: praxis_policy_apl_core::step::DispatchPhase::Post,
            },
        )
        .await
        .expect("invoke");

    assert_eq!(
        outcome.modified_value,
        Some(serde_json::json!("[REDACTED]")),
        "Post phase must read the field back out of the tool result, not the args"
    );
}

// ---------------------------------------------------------------------
// Capability gating — APL route override of `capabilities:` materializes
// a derived PluginRef wrapping the same plugin Arc with a merged
// TrustedConfig. praxis-policy-core's executor then enforces the narrower caps
// in its single per-entry `filter_extensions` pass — no double filter,
// no second clone of security. The base plugin's circuit breaker stays
// isolated.
// ---------------------------------------------------------------------

/// Capture-plugin fixture — records the Extensions it actually receives
/// from the executor so the test can assert what survived filtering.
struct CapturePlugin {
    cfg: PluginConfig,
    captured: Arc<tokio::sync::Mutex<Option<Extensions>>>,
}

#[async_trait]
impl Plugin for CapturePlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for CapturePlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        *self.captured.lock().await = Some(extensions.clone());
        PluginResult::allow()
    }
}

struct CapturePluginFactory {
    slot: Arc<tokio::sync::Mutex<Option<Extensions>>>,
}

impl PluginFactory for CapturePluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(CapturePlugin {
            cfg: config.clone(),
            captured: self.slot.clone(),
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

/// Build a engine whose registered plugin holds the given capability
/// set (wide caps in this test — the override is supposed to narrow
/// what these caps would have allowed).
async fn build_manager_with_caps(
    factory_kind: &str,
    factory: Box<dyn PluginFactory>,
    policy_caps: &[&str],
) -> Arc<PolicyEngine> {
    let mgr = PolicyEngine::default();
    mgr.register_factory(factory_kind, factory);
    let caps_yaml = if policy_caps.is_empty() {
        String::new()
    } else {
        format!("    capabilities: [{}]\n", policy_caps.join(", "))
    };
    let yaml =
        format!("plugins:\n  - name: {factory_kind}\n    kind: {factory_kind}\n{caps_yaml}",);
    let cfg = praxis_policy_core::config::parse_config(&yaml).expect("parse_config");
    mgr.load_config(cfg).expect("load_config");
    mgr.initialize().await.expect("initialize");
    Arc::new(mgr)
}

fn extensions_with_subject_and_labels() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label("PII");
    security.subject = Some(SubjectExtension {
        id: Some("alice".into()),
        ..Default::default()
    });
    Extensions {
        security: Some(Arc::new(security)),
        ..Default::default()
    }
}

/// Build a `RoutePluginEntry` that wraps the base plugin's handler with a
/// derived `PluginRef` carrying narrower caps — same plugin Arc, fresh
/// circuit breaker, smaller cap set. Mirrors what
/// `RouteDispatchPlan::build` does when APL declares a route-level
/// `plugins.<name>.capabilities:` override.
fn plan_with_narrowed_caps(
    engine: &PolicyEngine,
    plugin_name: &str,
    narrowed_caps: &[&str],
) -> Arc<praxis_policy_apl_runtime::RouteDispatchPlan> {
    let base = engine
        .find_plugin_entries(plugin_name)
        .into_iter()
        .next()
        .expect("plugin registered");
    let (_hook_name, base_entry) = base;
    let mut merged = base_entry.plugin_ref.trusted_config().clone();
    merged.capabilities = narrowed_caps
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let override_ref = Arc::new(PluginRef::new(
        Arc::clone(base_entry.plugin_ref.plugin()),
        merged,
    ));
    let entry = HookEntry {
        plugin_ref: override_ref,
        handler: Arc::clone(&base_entry.handler),
    };
    let mut plugins = std::collections::HashMap::new();
    let mut entries_by_hook = std::collections::HashMap::new();
    entries_by_hook.insert("cmf.tool_pre_invoke".to_owned(), entry);
    plugins.insert(
        plugin_name.to_owned(),
        praxis_policy_apl_runtime::RoutePluginEntry {
            plugin_name: plugin_name.to_owned(),
            entries_by_hook,
        },
    );
    Arc::new(praxis_policy_apl_runtime::RouteDispatchPlan {
        plugins,
        delegation_entries: Default::default(),
        elicitation_entries: Default::default(),
    })
}

#[tokio::test]
async fn route_override_caps_narrow_what_plugin_sees() {
    // praxis-policy-core registers the plugin with WIDE caps: read_subject AND
    // read_labels. Without an override, the plugin would see both.
    let captured = Arc::new(tokio::sync::Mutex::new(None));
    let factory = CapturePluginFactory {
        slot: captured.clone(),
    };
    let mgr = build_manager_with_caps(
        "capture-plugin",
        Box::new(factory),
        &["read_subject", "read_labels"],
    )
    .await;

    // APL route override narrows to ONLY read_subject — labels should
    // be stripped despite praxis-policy-core having registered them.
    let plan = plan_with_narrowed_caps(&mgr, "capture-plugin", &["read_subject"]);

    let invoker = CmfPluginInvoker::for_request(
        mgr,
        extensions_with_subject_and_labels(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let outcome = invoker
        .invoke(
            "capture-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");
    assert_eq!(outcome.decision, Decision::Allow);

    let captured = captured.lock().await.clone().expect("handler ran");
    let security = captured.security.expect("security extension present");

    // read_subject is in the narrowed set → subject still visible.
    assert!(
        security.subject.is_some(),
        "route override declared read_subject; plugin should see subject"
    );
    assert_eq!(
        security.subject.as_ref().unwrap().id.as_deref(),
        Some("alice")
    );

    // read_labels is NOT in the narrowed set → labels stripped, even
    // though praxis-policy-core's registration would have allowed them through.
    assert!(
        security.labels.is_empty(),
        "route override dropped read_labels; labels should be empty (got {:?})",
        security.labels,
    );
}

// ---------------------------------------------------------------------
// Hook routing table regression
// ---------------------------------------------------------------------
//
// Multi-hook plugin selection bug regression: a plugin registered
// under BOTH `cmf.tool_pre_invoke` and `cmf.tool_post_invoke` must
// dispatch to the right entry per phase. Previously the
// dispatch plan classified both as "step" and arbitrary "first
// non-field wins" picked one for every dispatch — silent wrong
// routing when policy and post_policy needed different handlers.

/// Pre-side handler — returns Allow with no modification.
struct PreSideHandler {
    cfg: PluginConfig,
}
#[async_trait]
impl Plugin for PreSideHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}
impl HookHandler<CmfHook> for PreSideHandler {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

/// Post-side handler — returns Deny with a distinctive violation
/// code so the test can assert "which handler fired" from the
/// outcome alone.
struct PostSideHandler {
    cfg: PluginConfig,
}
#[async_trait]
impl Plugin for PostSideHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}
impl HookHandler<CmfHook> for PostSideHandler {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(praxis_policy_core::error::PluginViolation::new(
            "test.multi_hook.post_fired",
            "post handler fired",
        ))
    }
}

/// Marker plugin held by the `PluginInstance` (handlers are
/// independent structs — the marker satisfies the
/// `PluginInstance.plugin` field).
struct MultiHookMarker {
    cfg: PluginConfig,
}
#[async_trait]
impl Plugin for MultiHookMarker {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

struct MultiHookPluginFactory;
impl PluginFactory for MultiHookPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let marker = Arc::new(MultiHookMarker {
            cfg: config.clone(),
        });
        let pre = Arc::new(PreSideHandler {
            cfg: config.clone(),
        });
        let post = Arc::new(PostSideHandler {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: marker as Arc<dyn Plugin>,
            handlers: vec![
                (
                    "cmf.tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(pre)),
                ),
                (
                    "cmf.tool_post_invoke",
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(post)),
                ),
            ],
        })
    }
}

/// Plugin registered under both `cmf.tool_pre_invoke` and
/// `cmf.tool_post_invoke`. `PluginInvocation::Step { phase: Pre }`
/// must pick the pre-side handler; `Step { phase: Post }` must pick
/// the post-side handler. The post handler emits a distinctive
/// violation code so we can prove WHICH handler fired from the
/// outcome alone — not just that "a handler" fired.
#[tokio::test]
async fn multi_hook_plugin_dispatches_per_phase_via_routing_table() {
    let mgr = build_manager("multi-hook-plugin", Box::new(MultiHookPluginFactory)).await;
    let plan = plan_for(&mgr, "multi-hook-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    // Pre phase — should hit pre handler → Allow.
    let pre_outcome = invoker
        .invoke(
            "multi-hook-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: praxis_policy_apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("pre invoke");
    assert_eq!(pre_outcome.decision, Decision::Allow);

    // Post phase — should hit post handler → Deny with the
    // distinctive code. Proves the post handler ran, not the pre
    // handler (which would have returned Allow).
    let post_outcome = invoker
        .invoke(
            "multi-hook-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: praxis_policy_apl_core::step::DispatchPhase::Post,
            },
        )
        .await
        .expect("post invoke");
    match post_outcome.decision {
        Decision::Deny { rule_source, .. } => {
            assert_eq!(
                rule_source, "test.multi_hook.post_fired",
                "Post phase should dispatch to the post-side handler",
            );
        },
        d => panic!("expected Deny from post handler, got {d:?}"),
    }
}

// ---------------------------------------------------------------------
// The permissive fallback: a handler registered under a hook name the
// metadata table does not hold still dispatches. `lookup` returns None for
// it and `pick_entry` substitutes `HookMetadata::permissive()`, a wildcard
// matching any entity type and phase. Nothing covered this branch, so a
// change that dropped the fallback would have looked green.
// ---------------------------------------------------------------------

/// The hook name under test. Deliberately absent from `BUILTIN_HOOK_METADATA`,
/// and never named in `hooks:`, so only the Rust registration knows it.
const UNREGISTERED_HOOK: &str = "host.hook_with_no_metadata_row";

struct UnlistedHookFactory;
impl PluginFactory for UnlistedHookFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                UNREGISTERED_HOOK,
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

#[tokio::test]
async fn an_unregistered_hook_dispatches_through_the_permissive_fallback() {
    // Precondition: the table really does not describe this name, so the
    // test exercises the fallback rather than a registered row.
    assert!(
        praxis_policy_core::hooks::lookup_hook_metadata(UNREGISTERED_HOOK).is_none(),
        "the test hook must have no metadata row for the fallback to be under test",
    );

    let mgr = build_manager("unlisted", Box::new(UnlistedHookFactory)).await;
    let plan = plan_for(&mgr, "unlisted");
    let entry = plan.plugins.get("unlisted").expect("plugin in plan");

    // The wildcard matches every context, so each of these resolves.
    for (entity, phase) in [
        (Some("tool"), HookPhase::Pre),
        (Some("llm"), HookPhase::Post),
        (None, HookPhase::Unphased),
    ] {
        assert!(
            entry.pick_entry(entity, phase).is_some(),
            "an unregistered hook must still dispatch for {entity:?}/{phase:?}",
        );
    }
}

#[tokio::test]
async fn a_registered_hook_is_filtered_by_its_row() {
    // The contrast case: a hook the table describes is filtered, which is
    // what makes the fallback above a fallback rather than the rule.
    let mgr = build_manager("allow-plugin", Box::new(AllowPluginFactory)).await;
    let plan = plan_for(&mgr, "allow-plugin");
    let entry = plan.plugins.get("allow-plugin").expect("plugin in plan");

    assert!(
        entry.pick_entry(Some("tool"), HookPhase::Pre).is_some(),
        "cmf.tool_pre_invoke matches its own entity and phase",
    );
    assert!(
        entry.pick_entry(Some("llm"), HookPhase::Pre).is_none(),
        "cmf.tool_pre_invoke must not match the llm entity",
    );
    assert!(
        entry.pick_entry(Some("tool"), HookPhase::Post).is_none(),
        "cmf.tool_pre_invoke must not match the post phase",
    );
}
