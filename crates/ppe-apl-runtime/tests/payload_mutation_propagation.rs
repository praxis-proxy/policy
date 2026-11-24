// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Text-only comparisons cannot detect edits to structured content parts.
// These regressions require every accepted edit to reach the forwarded payload.

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

use praxis_policy_core::cmf::enums::{ResourceType, Role};

use praxis_policy_core::cmf::{
    CmfHook, ContentPart, Message, MessagePayload, PromptRequest, PromptResult, Resource,
    ResourceReference, ToolCall, ToolResult,
};

use praxis_policy_core::context::PluginContext;

use praxis_policy_core::engine::PolicyEngine;

use praxis_policy_core::error::PluginError as CoreError;

use praxis_policy_core::factory::{PluginFactory, PluginInstance};

use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;

use praxis_policy_core::hooks::payload::Extensions;

use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};

use praxis_policy_core::plugin::{Plugin, PluginConfig};

use praxis_policy_apl_runtime::{AplOptions, DispatchCache, MemorySessionStore, register_apl};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn tool_result_redaction_reaches_the_host() {
    let mgr = manager_with(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(
        Role::Tool,
        vec![
            ContentPart::Text {
                text: "here is the result".to_owned(),
            },
            tool_result_part("sk-secret-value"),
        ],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    assert!(
        result.payload_modified,
        "the plugin returned a mutation, so the pipeline must report one"
    );
    let out = forwarded(&result);
    assert_eq!(
        tool_result_of(out),
        Some(&serde_json::Value::String("[REDACTED]".to_owned())),
        "the host must receive the redacted tool result, not the original secret"
    );
    assert_eq!(
        out.message.get_text_content(),
        "here is the result",
        "fixture sanity: text is untouched, so text comparison sees no change"
    );
}

#[tokio::test]
async fn tool_call_argument_rewrite_reaches_the_host() {
    let mgr = manager_with(
        "arg-redactor",
        Box::new(RewriteFactory {
            target: Target::ToolCallArguments,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(Role::User, vec![tool_call_part("London")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(
        tool_arg_of(forwarded(&result), "city"),
        Some(&serde_json::json!("[REDACTED]"))
    );
}

#[tokio::test]
async fn thinking_rewrite_reaches_the_host() {
    let mgr = manager_with(
        "thought-redactor",
        Box::new(RewriteFactory {
            target: Target::Thinking,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(
        Role::Assistant,
        vec![ContentPart::Thinking {
            text: "the user's SSN is 123-45-6789".to_owned(),
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(
        forwarded(&result).message.get_thinking_content().as_deref(),
        Some("[REDACTED]")
    );
}

#[tokio::test]
async fn text_rewrite_still_reaches_the_host() {
    let mgr = manager_with(
        "text-redactor",
        Box::new(RewriteFactory {
            target: Target::Text,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::Text {
            text: "my card is 4111 1111 1111 1111".to_owned(),
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(forwarded(&result).message.get_text_content(), "[REDACTED]");
}

#[tokio::test]
async fn tool_result_redaction_reaches_the_host_in_post_phase() {
    let mgr = manager_with(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_post_invoke",
        }),
        "cmf.tool_post_invoke",
        "post_invocation",
    )
    .await;

    let payload = payload_of(Role::Tool, vec![tool_result_part("sk-secret-value")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(
        tool_result_of(forwarded(&result)),
        Some(&serde_json::Value::String("[REDACTED]".to_owned()))
    );
}

#[tokio::test]
async fn args_pipeline_and_plugin_edits_both_survive() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: token-scrubber
    kind: token-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    args:
      city: "str | redact"
    authorization:
      pre_invocation:
        - "run(token-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "token-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("token"),
            hook: "cmf.tool_pre_invoke",
        }),
        yaml,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_owned(),
                name: "get_weather".to_owned(),
                arguments: [
                    ("city".to_owned(), serde_json::json!("London")),
                    ("token".to_owned(), serde_json::json!("sk-secret")),
                ]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    let out = forwarded(&result);
    assert_eq!(
        tool_arg_of(out, "city"),
        Some(&serde_json::json!("[REDACTED]")),
        "the pipeline's redaction must reach the host"
    );
    assert_eq!(
        tool_arg_of(out, "token"),
        Some(&serde_json::json!("[REDACTED]")),
        "the plugin's edit must not be clobbered by folding the pipeline's \
         args back in"
    );
}

#[tokio::test]
async fn result_pipeline_and_plugin_edits_both_survive() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: ssn-redactor
    kind: ssn-redactor
    hooks: [cmf.tool_post_invoke]
routes:
  - tool: get_weather
    result:
      employee_id: "str | mask(2)"
    authorization:
      post_invocation:
        - "run(ssn-redactor)"
"#;

    let mgr = manager_with_yaml(
        "ssn-redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultField("ssn"),
            hook: "cmf.tool_post_invoke",
        }),
        yaml,
    )
    .await;

    let payload = payload_of(
        Role::Tool,
        vec![ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: "tc_001".to_owned(),
                tool_name: "get_weather".to_owned(),
                content: serde_json::json!({
                    "employee_id": "E12345",
                    "ssn": "123-45-6789",
                }),
                is_error: false,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    let out = forwarded(&result);
    let content = tool_result_of(out).expect("tool result present");
    assert_eq!(
        content.get("employee_id"),
        Some(&serde_json::json!("****45")),
        "the pipeline's mask must reach the host"
    );
    assert_eq!(
        content.get("ssn"),
        Some(&serde_json::json!("[REDACTED]")),
        "the plugin's redaction must not be clobbered by folding the \
         pipeline's result back in"
    );
}

#[tokio::test]
async fn a_plugin_removing_the_checked_resource_is_denied_as_removed() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: resource-dropper
    kind: resource-dropper
    hooks: [cmf.resource_post_fetch]
routes:
  - resource: hr://employees/*
    result:
      content: redact
    authorization:
      post_invocation:
        - "run(resource-dropper)"
"#;

    let mgr = manager_with_yaml(
        "resource-dropper",
        Box::new(RewriteFactory {
            target: Target::RemoveResources,
            hook: "cmf.resource_post_fetch",
        }),
        yaml,
    )
    .await;

    let mut meta = praxis_policy_core::extensions::MetaExtension::default();
    meta.entity_type = Some("resource".to_owned());
    meta.entity_name = Some("hr://employees/42".to_owned());
    let ext = Extensions {
        meta: Some(Arc::new(meta)),
        ..Default::default()
    };
    let payload = payload_of(
        Role::Tool,
        vec![ContentPart::Resource {
            content: Resource {
                resource_request_id: "rr_001".to_owned(),
                uri: "hr://employees/42".to_owned(),
                content: Some("SSN 123-45-6789".to_owned()),
                resource_type: ResourceType::Uri,
                ..Resource::default()
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.resource_post_fetch", payload, ext, None)
        .await;

    assert!(
        !result.continue_processing,
        "with the checked resource gone, the request must be denied"
    );
    let violation = result.violation.expect("deny must carry a violation");
    assert_eq!(violation.code, "policy.envelope_replaced");
    assert!(
        violation.reason.contains("no longer in the message")
            && !violation.reason.contains("replaced the whole"),
        "the reason must say the part is gone, not that it was replaced: {}",
        violation.reason
    );
}

#[tokio::test]
async fn plugin_stage_rewrites_only_the_field_it_was_pointed_at() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: city-scrubber
    kind: city-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    args:
      city: "str | run(city-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "city-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("city"),
            hook: "cmf.tool_pre_invoke",
        }),
        yaml,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![
            ContentPart::Text {
                text: "chatter that must not become an argument".to_owned(),
            },
            tool_call_part("London"),
        ],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    assert_eq!(
        tool_arg_of(forwarded(&result), "city"),
        Some(&serde_json::json!("[REDACTED]"))
    );
}

#[tokio::test]
async fn mutations_from_several_plugins_accumulate() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: result-redactor
    kind: result-redactor
    hooks: [cmf.tool_pre_invoke]
  - name: thought-redactor
    kind: thought-redactor
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(result-redactor)"
        - "run(thought-redactor)"
"#;

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "result-redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
    );
    mgr.register_factory(
        "thought-redactor",
        Box::new(RewriteFactory {
            target: Target::Thinking,
            hook: "cmf.tool_pre_invoke",
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
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let payload = payload_of(
        Role::Assistant,
        vec![
            ContentPart::Thinking {
                text: "ssn is 123-45-6789".to_owned(),
            },
            tool_result_part("sk-secret-value"),
        ],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    let out = forwarded(&result);
    assert_eq!(
        tool_result_of(out),
        Some(&serde_json::Value::String("[REDACTED]".to_owned())),
        "the first plugin's redaction must survive the second plugin's dispatch"
    );
    assert_eq!(
        out.message.get_thinking_content().as_deref(),
        Some("[REDACTED]"),
        "the second plugin's redaction must land too"
    );
}

#[tokio::test]
async fn a_denied_route_forwards_no_payload() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: redactor
    kind: redactor
    hooks: [cmf.tool_pre_invoke]
  - name: denier
    kind: denier
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(redactor)"
        - "run(denier)"
"#;

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
    );
    mgr.register_factory("denier", Box::new(DenyFactory));
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
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let payload = payload_of(Role::Tool, vec![tool_result_part("sk-secret-value")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(!result.continue_processing, "the route must deny");
    assert!(
        result.modified_payload.is_none(),
        "a denied pipeline carries no payload forward"
    );
    assert!(!result.payload_modified);
}

#[tokio::test]
async fn a_mutation_the_executor_rejects_is_not_reported() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: redactor
    kind: redactor
    hooks: [cmf.tool_pre_invoke]
    mode: audit
routes:
  - tool: get_weather
    authorization:
      pre_invocation:
        - "run(redactor)"
"#;

    let mgr = manager_with_yaml(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
        yaml,
    )
    .await;

    let payload = payload_of(Role::Tool, vec![tool_result_part("sk-secret-value")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert!(
        !result.payload_modified,
        "an audit-mode plugin's payload is discarded, so no mutation was applied"
    );
    assert_eq!(
        tool_result_of(forwarded(&result)),
        Some(&serde_json::Value::String("sk-secret-value".to_owned())),
        "and the original must be what's forwarded"
    );
}

#[tokio::test]
async fn omit_stage_and_plugin_edit_both_survive() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: token-scrubber
    kind: token-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    args:
      debug: "str | omit"
    authorization:
      pre_invocation:
        - "run(token-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "token-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("token"),
            hook: "cmf.tool_pre_invoke",
        }),
        yaml,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_owned(),
                name: "get_weather".to_owned(),
                arguments: [
                    ("city".to_owned(), serde_json::json!("London")),
                    ("debug".to_owned(), serde_json::json!("verbose")),
                    ("token".to_owned(), serde_json::json!("sk-secret")),
                ]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    let out = forwarded(&result);
    assert_eq!(tool_arg_of(out, "debug"), None, "the omit must apply");
    assert_eq!(
        tool_arg_of(out, "token"),
        Some(&serde_json::json!("[REDACTED]")),
        "the plugin's edit must not be undone by applying the omit"
    );
    assert_eq!(
        tool_arg_of(out, "city"),
        Some(&serde_json::json!("London")),
        "an argument nobody touched must be left alone"
    );
}

#[tokio::test]
async fn nested_pipeline_and_plugin_edits_both_survive() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: name-scrubber
    kind: name-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    args:
      user.ssn: "str | redact"
    authorization:
      pre_invocation:
        - "run(name-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "name-scrubber",
        Box::new(RewriteFactory {
            target: Target::NestedToolCallArgument("user", "name"),
            hook: "cmf.tool_pre_invoke",
        }),
        yaml,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_owned(),
                name: "get_weather".to_owned(),
                arguments: [(
                    "user".to_owned(),
                    serde_json::json!({"name": "Ada Lovelace", "ssn": "123-45-6789"}),
                )]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    let user = tool_arg_of(forwarded(&result), "user").expect("user argument present");
    assert_eq!(
        user.get("ssn"),
        Some(&serde_json::json!("[REDACTED]")),
        "the pipeline's nested redaction must reach the host"
    );
    assert_eq!(
        user.get("name"),
        Some(&serde_json::json!("[REDACTED]")),
        "the plugin's edit to a sibling key must survive the merge"
    );
}

#[tokio::test]
async fn a_plugin_stage_does_not_undo_an_earlier_mask_in_the_same_chain() {
    let yaml = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: token-scrubber
    kind: token-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    args:
      city: "str | mask(2) | run(token-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "token-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("token"),
            hook: "cmf.tool_pre_invoke",
        }),
        yaml,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_owned(),
                name: "get_weather".to_owned(),
                arguments: [
                    ("city".to_owned(), serde_json::json!("London")),
                    ("token".to_owned(), serde_json::json!("sk-secret")),
                ]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    let out = forwarded(&result);
    assert_eq!(
        tool_arg_of(out, "city"),
        Some(&serde_json::json!("****on")),
        "the mask stage's output must survive the plugin stage that followed it"
    );
    assert_eq!(
        tool_arg_of(out, "token"),
        Some(&serde_json::json!("[REDACTED]")),
        "and the plugin's own edit must still reach the host"
    );
}

#[tokio::test]
async fn allow_without_mutation_reports_no_modification() {
    let mgr = manager_with(
        "noop",
        Box::new(NoopFactory {
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(Role::User, vec![tool_call_part("London")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert!(!result.payload_modified);
    assert_eq!(
        tool_arg_of(forwarded(&result), "city"),
        Some(&serde_json::json!("London")),
        "an untouched request must arrive untouched"
    );
}

#[tokio::test]
async fn resource_field_readback_survives_reordering() {
    let result = resource_plugin_result(
        "str | run(resource-editor)",
        "",
        false,
        Target::ReorderResources,
    )
    .await;
    assert!(
        result.continue_processing,
        "reordering unique resources must allow"
    );
    let names: Vec<_> = forwarded(&result)
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Resource { content } => content.name.as_deref(),
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        ["other", "original"],
        "the reordered parts must reach the host"
    );
    assert_eq!(
        resource_content(&result, "original"),
        Some("SSN 123-45-6789"),
        "reordering alone must not transfer another resource's content"
    );
    assert_eq!(
        resource_content(&result, "other"),
        Some("public"),
        "the other resource must keep its own content"
    );
}

#[tokio::test]
async fn same_uri_resource_edits_are_denied_as_ambiguous() {
    let result = resource_plugin_result(
        "redact",
        "    authorization:\n      post_invocation:\n        - \"run(resource-editor)\"",
        true,
        Target::ReorderResources,
    )
    .await;
    assert!(
        !result.continue_processing,
        "same-URI edits must fail closed"
    );
    let violation = result.violation.expect("ambiguity carries a violation");
    assert_eq!(
        violation.code, "policy.envelope_replaced",
        "the write must be refused"
    );
    assert!(
        violation.reason.contains("unique"),
        "the denial must describe the ambiguous target: {}",
        violation.reason
    );
}

#[tokio::test]
async fn ambiguous_resource_field_plugins_are_denied_before_dispatch() {
    let result = resource_plugin_result(
        "str | run(resource-editor)",
        "",
        true,
        Target::DenyIfDispatched,
    )
    .await;
    assert!(
        !result.continue_processing,
        "an ambiguous baseline must fail closed"
    );
    let violation = result.violation.expect("ambiguity carries a violation");
    assert!(
        violation.reason.contains("unique"),
        "the denial must explain the ambiguous baseline: {}",
        violation.reason
    );
}

#[tokio::test]
async fn a_plugin_introducing_a_duplicate_resource_uri_is_denied_on_readback() {
    let result = resource_plugin_result(
        "str | run(resource-editor)",
        "",
        false,
        Target::DuplicateResource,
    )
    .await;
    assert!(
        !result.continue_processing,
        "readback must refuse a newly ambiguous target"
    );
    let violation = result.violation.expect("ambiguity carries a violation");
    assert!(
        violation.reason.contains("unique"),
        "the denial must explain the duplicate introduced by the plugin: {}",
        violation.reason
    );
}

#[tokio::test]
async fn resource_readback_preserves_redaction_across_multiple_plugins() {
    let result = resource_plugin_result(
        "str | redact | run(resource-editor) | run(resource-editor)",
        "",
        false,
        Target::ReorderResources,
    )
    .await;
    assert!(
        result.continue_processing,
        "unique resources can be reordered twice"
    );
    assert_eq!(
        resource_content(&result, "original"),
        Some("[REDACTED]"),
        "later plugin baselines must keep the original target and preserve redaction"
    );
    assert_eq!(
        resource_content(&result, "other"),
        Some("public"),
        "the unrelated resource must remain unchanged"
    );
}

#[tokio::test]
async fn a_resource_removed_during_field_readback_is_denied() {
    let result = resource_plugin_result(
        "str | run(resource-editor)",
        "",
        false,
        Target::RemoveResources,
    )
    .await;
    assert!(
        !result.continue_processing,
        "removing the selected readback target must fail closed"
    );
    let violation = result
        .violation
        .expect("missing target carries a violation");
    assert!(
        violation.code.ends_with(".result.content"),
        "readback denial must be attributed to the focused field: {}",
        violation.code
    );
    assert!(
        violation.reason.contains("no longer in the message"),
        "the denial must distinguish removal: {}",
        violation.reason
    );
}

#[tokio::test]
async fn resource_reference_edits_follow_the_original_after_reordering() {
    let result = projection_edit_result(
        ("resource", "cmf.resource_pre_fetch", "args"),
        "selector",
        "redact",
        "    authorization:\n      pre_invocation:\n        - \"run(projection-editor)\"",
        vec![reference_part("original"), reference_part("other")],
        Target::ReorderResources,
    )
    .await;
    assert!(
        result.continue_processing,
        "unique references can be reordered"
    );
    let references: Vec<_> = forwarded(&result)
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::ResourceRef { content } => {
                Some((content.uri.as_str(), content.selector.as_deref()))
            },
            _ => None,
        })
        .collect();
    assert_eq!(
        references,
        [("other", Some("other")), ("original", Some("[REDACTED]"))]
    );
}

#[tokio::test]
async fn missing_or_duplicate_references_deny_edits_and_field_readback() {
    for pipeline in ["redact", "run(projection-editor)"] {
        for target in [Target::RemoveReferences, Target::DuplicateReference] {
            let result = projection_edit_result(
                ("resource", "cmf.resource_pre_fetch", "args"),
                "selector",
                pipeline,
                "    authorization:\n      pre_invocation:\n        - \"run(projection-editor)\"",
                vec![reference_part("original")],
                target,
            )
            .await;
            assert!(
                !result.continue_processing,
                "a reference edit requires a unique surviving target"
            );
            let violation = result.violation.expect("target denial");
            assert!(
                violation.reason.contains("unique") || violation.reason.contains("no longer"),
                "{}",
                violation.reason
            );
        }
    }
}

#[tokio::test]
async fn prompt_edits_and_field_readback_follow_the_original_after_reordering() {
    for pipeline in ["redact", "run(projection-editor) | mask(1)"] {
        let result = projection_edit_result(
            ("prompt", "cmf.prompt_post_invoke", "result"),
            "content",
            pipeline,
            "    authorization:\n      post_invocation:\n        - \"run(projection-editor)\"",
            vec![prompt_part("original"), prompt_part("other")],
            Target::ReorderResources,
        )
        .await;
        assert!(
            result.continue_processing,
            "unique prompts can be reordered"
        );
        let prompts: Vec<_> = forwarded(&result)
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::PromptResult { content } => {
                    Some((content.prompt_name.as_str(), content.content.as_deref()))
                },
                _ => None,
            })
            .collect();
        let original = if pipeline == "redact" {
            "[REDACTED]"
        } else {
            "*******l"
        };
        let order = if pipeline == "redact" {
            vec![("other", Some("other")), ("original", Some(original))]
        } else {
            vec![("original", Some(original)), ("other", Some("other"))]
        };
        assert_eq!(
            prompts, order,
            "only the inspected prompt can receive a policy edit"
        );
    }
}

#[tokio::test]
async fn missing_or_duplicate_prompts_deny_edits_and_field_readback() {
    for pipeline in ["redact", "run(projection-editor) | str"] {
        for target in [Target::RemovePrompts, Target::DuplicatePrompt] {
            let result = projection_edit_result(
                ("prompt", "cmf.prompt_post_invoke", "result"),
                "content",
                pipeline,
                "    authorization:\n      post_invocation:\n        - \"run(projection-editor)\"",
                vec![prompt_part("original")],
                target,
            )
            .await;
            assert!(
                !result.continue_processing,
                "a prompt edit requires a unique surviving target"
            );
        }
    }
}

#[tokio::test]
async fn an_idempotent_policy_redaction_overrides_a_later_plugin_edit() {
    for (pipeline, authorization) in [
        (
            "redact",
            "    authorization:\n      post_invocation:\n        - \"run(projection-editor)\"",
        ),
        (
            "str",
            "    authorization:\n      post_invocation:\n        - when: \"result.content == '[REDACTED]'\"\n          do: \"result.content | redact\"\n        - \"run(projection-editor)\"",
        ),
    ] {
        let part = ContentPart::Resource {
            content: Resource {
                uri: "original".to_owned(),
                content: Some("[REDACTED]".to_owned()),
                ..Resource::default()
            },
        };
        let result = projection_edit_result(
            ("resource", "cmf.resource_post_fetch", "result"),
            "content",
            pipeline,
            authorization,
            vec![part],
            Target::RewriteResourceContent,
        )
        .await;
        assert!(result.continue_processing, "redaction should allow");
        let ContentPart::Resource { content } = &forwarded(&result).message.content[0] else {
            panic!("resource result")
        };
        assert_eq!(
            content.version.as_deref(),
            Some("plugin-edited"),
            "the authorization plugin must have run"
        );
        assert_eq!(
            content.content.as_deref(),
            Some("[REDACTED]"),
            "a policy write wins even when its input was already redacted"
        );
    }
}

#[tokio::test]
async fn annotation_plugin_readback_uses_expanded_array_and_dotted_key_paths() {
    for (field, pipeline, annotations) in [
        (
            "annotations.rows.ssn",
            "run(projection-editor) | str",
            serde_json::json!({"rows": [{"ssn": 123}, {"ssn": 456}]}),
        ),
        (
            "**.ssn",
            "run(projection-editor) | str | redact",
            serde_json::json!({"case.file": {"ssn": 123}}),
        ),
    ] {
        let part = ContentPart::Resource {
            content: Resource {
                uri: "original".to_owned(),
                annotations: serde_json::from_value(annotations).expect("annotation map"),
                ..Resource::default()
            },
        };
        let result = projection_edit_result(
            ("resource", "cmf.resource_post_fetch", "result"),
            field,
            pipeline,
            "",
            vec![part],
            Target::RewriteResourceAnnotations,
        )
        .await;
        assert!(
            result.continue_processing,
            "plugin readback must return the concrete string for {field}"
        );
        let ContentPart::Resource { content } = &forwarded(&result).message.content[0] else {
            panic!("resource result")
        };
        if field == "**.ssn" {
            assert_eq!(
                content.annotations["case.file"]["ssn"],
                serde_json::json!("[REDACTED]")
            );
        } else {
            assert_eq!(
                content.annotations["rows"],
                serde_json::json!([{"ssn": "[REDACTED]"}, {"ssn": "[REDACTED]"}])
            );
        }
    }
}

#[tokio::test]
async fn array_leaf_replay_preserves_sibling_redaction_and_denies_removal() {
    for target in [Target::EditSiblingArrayNote, Target::RemoveFirstResourceRow] {
        let part = ContentPart::Resource {
            content: Resource {
                uri: "original".to_owned(),
                annotations: serde_json::from_value(
                    serde_json::json!({"rows": [{"ssn": "[REDACTED]"}, {"note": "secret"}]}),
                )
                .expect("annotation map"),
                ..Resource::default()
            },
        };
        let result = projection_edit_result(
            ("resource", "cmf.resource_post_fetch", "result"),
            "annotations.rows.0.ssn",
            "redact",
            "    authorization:\n      post_invocation:\n        - \"run(projection-editor)\"",
            vec![part],
            target,
        )
        .await;
        if matches!(target, Target::RemoveFirstResourceRow) {
            assert!(
                !result.continue_processing,
                "array removal must refuse an unmappable policy write"
            );
            assert!(
                result.modified_payload.is_none(),
                "denial must forward no resurrected elements"
            );
        } else {
            assert!(
                result.continue_processing,
                "an independent sibling edit must survive"
            );
            let ContentPart::Resource { content } = &forwarded(&result).message.content[0] else {
                panic!("resource")
            };
            assert_eq!(content.version.as_deref(), Some("plugin-row-edit"));
            assert_eq!(
                content.annotations["rows"][0]["ssn"],
                serde_json::json!("[REDACTED]")
            );
            assert_eq!(
                content.annotations["rows"][1]["note"],
                serde_json::json!("[REDACTED]")
            );
        }
    }
}

#[tokio::test]
async fn tool_readback_preserves_literal_dotted_keys() {
    let mut part = tool_result_part("unused");
    let ContentPart::ToolResult { content } = &mut part else {
        panic!("tool result")
    };
    content.content = serde_json::json!({"a.b": {"secret": "original"}});
    let result = projection_edit_result(
        ("tool", "cmf.tool_post_invoke", "result"),
        "**.secret",
        "redact | run(projection-editor)",
        "",
        vec![part],
        Target::InsertNestedToolResultBranch,
    )
    .await;
    assert!(
        result.continue_processing,
        "an unrelated branch can be added"
    );
    let content = tool_result_of(forwarded(&result)).expect("tool result");
    assert_eq!(content["a.b"]["secret"], serde_json::json!("[REDACTED]"));
    assert_eq!(content["a"]["b"]["secret"], serde_json::json!("public"));
}

#[tokio::test]
async fn resource_readback_refuses_a_replacement_request_at_the_same_uri() {
    for (hook, block, field, part) in [
        (
            "cmf.resource_pre_fetch",
            "args",
            "selector",
            reference_part("original"),
        ),
        (
            "cmf.resource_post_fetch",
            "result",
            "content",
            ContentPart::Resource {
                content: Resource {
                    uri: "original".to_owned(),
                    content: Some("original".to_owned()),
                    ..Resource::default()
                },
            },
        ),
    ] {
        let result = projection_edit_result(
            ("resource", hook, block),
            field,
            "str | run(projection-editor)",
            "",
            vec![part],
            Target::ReplaceResourceRequest,
        )
        .await;
        assert!(
            !result.continue_processing,
            "a different request must not receive this request's field write"
        );
        let reason = result.violation.expect("target denial").reason;
        assert!(
            reason.contains(&format!("`{block}:`")),
            "phase must be correct: {reason}"
        );
    }
}

#[tokio::test]
async fn a_field_plugin_after_array_omission_is_denied_before_dispatch() {
    let yaml = r#"engine_settings:
  dispatch: policy
plugins:
  - name: editor
    kind: editor
    hooks: [cmf.resource_post_fetch]
routes:
  - resource: '*'
    authorization:
      post_invocation:
        - when: "result.uri == 'original'"
          do:
            - "result.annotations.rows.0 | omit"
            - "result.annotations.rows.0.ssn | run(editor)"
"#;
    let mgr = manager_with_yaml(
        "editor",
        Box::new(RewriteFactory {
            target: Target::DenyIfDispatched,
            hook: "cmf.resource_post_fetch",
        }),
        yaml,
    )
    .await;
    let part = ContentPart::Resource {
        content: Resource {
            uri: "original".to_owned(),
            annotations: serde_json::from_value(
                serde_json::json!({"rows": [{"ssn": "first"}, {"ssn": "second"}]}),
            )
            .expect("annotations"),
            ..Resource::default()
        },
    };
    let extensions = Extensions {
        meta: Some(Arc::new(praxis_policy_core::extensions::MetaExtension {
            entity_type: Some("resource".to_owned()),
            entity_name: Some("original".to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let (result, _background) = mgr
        .invoke_named::<CmfHook>(
            "cmf.resource_post_fetch",
            payload_of(Role::Tool, vec![part]),
            extensions,
            None,
        )
        .await;
    assert!(
        !result.continue_processing,
        "readback after an omission must not select the old index"
    );
    let violation = result.violation.expect("array index denial");
    assert!(
        violation.reason.contains("indexes"),
        "the plugin must not dispatch: {}",
        violation.reason
    );
}

#[tokio::test]
async fn ordered_field_ops_after_an_array_omission_use_the_remaining_element() {
    let yaml = r#"engine_settings:
  dispatch: policy
routes:
  - resource: '*'
    authorization:
      post_invocation:
        - when: "result.uri == 'original'"
          do:
            - "result.annotations.rows.0 | omit"
            - "result.annotations.rows.0.profile.ssn | redact"
"#;
    let mgr = manager_with_yaml(
        "unused",
        Box::new(RewriteFactory {
            target: Target::DenyIfDispatched,
            hook: "cmf.resource_post_fetch",
        }),
        yaml,
    )
    .await;
    let part = ContentPart::Resource {
        content: Resource {
            uri: "original".to_owned(),
            annotations: serde_json::from_value(serde_json::json!({
                "rows": [
                    {"removed": true},
                    {"profile": {"ssn": "secret"}, "note": "keep"},
                ],
            }))
            .expect("annotations"),
            ..Resource::default()
        },
    };
    let extensions = Extensions {
        meta: Some(Arc::new(praxis_policy_core::extensions::MetaExtension {
            entity_type: Some("resource".to_owned()),
            entity_name: Some("original".to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let (result, _background) = mgr
        .invoke_named::<CmfHook>(
            "cmf.resource_post_fetch",
            payload_of(Role::Tool, vec![part]),
            extensions,
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "pure rules must retain sequential array indexing"
    );
    let ContentPart::Resource { content } = &forwarded(&result).message.content[0] else {
        panic!("resource")
    };
    assert_eq!(
        content.annotations["rows"],
        serde_json::json!([{"profile": {"ssn": "[REDACTED]"}, "note": "keep"}])
    );
}

#[tokio::test]
async fn prompt_argument_readback_and_writes_follow_the_original_request() {
    for fallback in [false, true] {
        let original = if fallback {
            ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "original".to_owned(),
                    name: "original".to_owned(),
                    arguments: serde_json::from_value(serde_json::json!({"tone": "original"}))
                        .expect("arguments"),
                    namespace: None,
                },
            }
        } else {
            ContentPart::PromptRequest {
                content: PromptRequest {
                    prompt_request_id: "original".to_owned(),
                    name: "original".to_owned(),
                    arguments: serde_json::from_value(serde_json::json!({"tone": "original"}))
                        .expect("arguments"),
                    server_id: None,
                },
            }
        };
        let mut other = original.clone();
        match &mut other {
            ContentPart::PromptRequest { content } => {
                content.prompt_request_id = "other".to_owned();
                content
                    .arguments
                    .insert("tone".to_owned(), serde_json::json!(123));
            },
            ContentPart::ToolCall { content } => {
                content.tool_call_id = "other".to_owned();
                content
                    .arguments
                    .insert("tone".to_owned(), serde_json::json!(123));
            },
            _ => panic!("request"),
        }
        let result = projection_edit_result(
            ("prompt", "cmf.prompt_pre_invoke", "args"),
            "tone",
            "run(projection-editor) | str | mask(1)",
            "",
            vec![original, other],
            Target::ReorderResources,
        )
        .await;
        assert!(
            result.continue_processing,
            "readback must use the original string argument"
        );
        let values: Vec<_> = forwarded(&result)
            .message
            .content
            .iter()
            .map(|part| match part {
                ContentPart::PromptRequest { content } => &content.arguments["tone"],
                ContentPart::ToolCall { content } => &content.arguments["tone"],
                _ => panic!("request"),
            })
            .collect();
        assert_eq!(
            values,
            vec![&serde_json::json!(123), &serde_json::json!("*******l")]
        );
    }
}

#[tokio::test]
async fn missing_or_duplicate_prompt_requests_deny_field_readback() {
    for target in [Target::RemoveRequests, Target::DuplicateRequest] {
        let part = ContentPart::PromptRequest {
            content: PromptRequest {
                prompt_request_id: "original".to_owned(),
                name: "original".to_owned(),
                arguments: serde_json::from_value(serde_json::json!({"tone": "original"}))
                    .expect("arguments"),
                server_id: None,
            },
        };
        let result = projection_edit_result(
            ("prompt", "cmf.prompt_pre_invoke", "args"),
            "tone",
            "run(projection-editor) | str",
            "",
            vec![part],
            target,
        )
        .await;
        assert!(
            !result.continue_processing,
            "request identity must remain unique"
        );
        assert!(
            result.modified_payload.is_none(),
            "a denied edit must not reach the host"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Target {
    ToolResultContent,
    ToolResultField(&'static str),
    ToolCallArguments,
    ToolCallArgument(&'static str),
    NestedToolCallArgument(&'static str, &'static str),
    Thinking,
    Text,
    RemoveResources,
    ReorderResources,
    DuplicateResource,
    DuplicatePrompt,
    DuplicateReference,
    RemovePrompts,
    RemoveReferences,
    RewriteResourceContent,
    RewriteResourceAnnotations,
    DenyIfDispatched,
    ReplaceResourceRequest,
    InsertNestedToolResultBranch,
    EditSiblingArrayNote,
    RemoveFirstResourceRow,
    RemoveRequests,
    DuplicateRequest,
}

struct RewritePlugin {
    cfg: PluginConfig,
    target: Target,
}

#[async_trait]
impl Plugin for RewritePlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for RewritePlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        if matches!(self.target, Target::DenyIfDispatched) {
            return PluginResult::deny(praxis_policy_core::error::PluginViolation::new(
                "fixture.dispatched",
                "the plugin was dispatched",
            ));
        }
        let mut content: Vec<ContentPart> = payload
            .message
            .content
            .iter()
            .filter(|part| {
                !matches!(
                    (self.target, part),
                    (Target::RemoveResources, ContentPart::Resource { .. })
                        | (Target::RemoveReferences, ContentPart::ResourceRef { .. })
                        | (Target::RemovePrompts, ContentPart::PromptResult { .. })
                        | (
                            Target::RemoveRequests,
                            ContentPart::PromptRequest { .. } | ContentPart::ToolCall { .. }
                        )
                )
            })
            .map(|part| match (self.target, part) {
                (Target::ToolResultContent, ContentPart::ToolResult { content }) => {
                    let mut next = content.clone();
                    next.content = serde_json::Value::String("[REDACTED]".to_owned());
                    ContentPart::ToolResult { content: next }
                },
                (Target::ToolResultField(field), ContentPart::ToolResult { content }) => {
                    let mut next = content.clone();
                    if let Some(obj) = next.content.as_object_mut() {
                        obj.insert(
                            field.to_owned(),
                            serde_json::Value::String("[REDACTED]".to_owned()),
                        );
                    }
                    ContentPart::ToolResult { content: next }
                },
                (Target::ToolCallArguments, ContentPart::ToolCall { content }) => {
                    let mut next = content.clone();
                    next.arguments.insert(
                        "city".to_owned(),
                        serde_json::Value::String("[REDACTED]".to_owned()),
                    );
                    ContentPart::ToolCall { content: next }
                },
                (Target::ToolCallArgument(arg), ContentPart::ToolCall { content }) => {
                    let mut next = content.clone();
                    next.arguments.insert(
                        arg.to_owned(),
                        serde_json::Value::String("[REDACTED]".to_owned()),
                    );
                    ContentPart::ToolCall { content: next }
                },
                (Target::NestedToolCallArgument(arg, key), ContentPart::ToolCall { content }) => {
                    let mut next = content.clone();
                    if let Some(obj) = next.arguments.get_mut(arg).and_then(|v| v.as_object_mut()) {
                        obj.insert(
                            key.to_owned(),
                            serde_json::Value::String("[REDACTED]".to_owned()),
                        );
                    }
                    ContentPart::ToolCall { content: next }
                },
                (Target::Thinking, ContentPart::Thinking { .. }) => ContentPart::Thinking {
                    text: "[REDACTED]".to_owned(),
                },
                (Target::Text, ContentPart::Text { .. }) => ContentPart::Text {
                    text: "[REDACTED]".to_owned(),
                },
                (Target::ReplaceResourceRequest, ContentPart::Resource { content }) => {
                    let mut next = content.clone();
                    next.resource_request_id = "replacement".to_owned();
                    ContentPart::Resource { content: next }
                },
                (Target::ReplaceResourceRequest, ContentPart::ResourceRef { content }) => {
                    let mut next = content.clone();
                    next.resource_request_id = "replacement".to_owned();
                    ContentPart::ResourceRef { content: next }
                },
                (Target::InsertNestedToolResultBranch, ContentPart::ToolResult { content }) => {
                    let mut next = content.clone();
                    next.content.as_object_mut().expect("object result").insert(
                        "a".to_owned(),
                        serde_json::json!({"b": {"secret": "public"}}),
                    );
                    ContentPart::ToolResult { content: next }
                },
                (
                    Target::EditSiblingArrayNote | Target::RemoveFirstResourceRow,
                    ContentPart::Resource { content },
                ) => {
                    let mut next = content.clone();
                    let rows = next
                        .annotations
                        .get_mut("rows")
                        .and_then(serde_json::Value::as_array_mut)
                        .expect("resource rows");
                    if matches!(self.target, Target::RemoveFirstResourceRow) {
                        rows.remove(0);
                    } else {
                        rows[1]["note"] = serde_json::json!("[REDACTED]");
                    }
                    next.version = Some("plugin-row-edit".to_owned());
                    ContentPart::Resource { content: next }
                },
                (Target::RewriteResourceContent, ContentPart::Resource { content }) => {
                    let mut next = content.clone();
                    next.content = Some("plugin-secret".to_owned());
                    next.version = Some("plugin-edited".to_owned());
                    ContentPart::Resource { content: next }
                },
                (Target::RewriteResourceAnnotations, ContentPart::Resource { content }) => {
                    let mut next = content.clone();
                    next.annotations.values_mut().any(rewrite_ssn);
                    ContentPart::Resource { content: next }
                },
                (_, other) => other.clone(),
            })
            .collect();

        if matches!(self.target, Target::ReorderResources) {
            content.reverse();
        }
        if matches!(self.target, Target::DuplicateResource)
            && let Some(resource) = content
                .iter()
                .find(|part| matches!(part, ContentPart::Resource { .. }))
                .cloned()
        {
            content.push(resource);
        }
        if let Some(part) = content
            .iter()
            .find(|part| {
                matches!(
                    (self.target, part),
                    (Target::DuplicatePrompt, ContentPart::PromptResult { .. })
                        | (Target::DuplicateReference, ContentPart::ResourceRef { .. })
                        | (
                            Target::DuplicateRequest,
                            ContentPart::PromptRequest { .. } | ContentPart::ToolCall { .. }
                        )
                )
            })
            .cloned()
        {
            content.push(part);
        }

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

struct RewriteFactory {
    target: Target,
    hook: &'static str,
}

impl PluginFactory for RewriteFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(RewritePlugin {
            cfg: config.clone(),
            target: self.target,
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                self.hook,
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

struct NoopPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for NoopPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for NoopPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
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
        PluginResult::deny(praxis_policy_core::error::PluginViolation::new(
            "policy.forbidden",
            "test fixture denied this call",
        ))
    }
}

struct DenyFactory;

impl PluginFactory for DenyFactory {
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

struct NoopFactory {
    hook: &'static str,
}

impl PluginFactory for NoopFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(NoopPlugin {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                self.hook,
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

async fn manager_with(
    kind: &'static str,
    factory: Box<dyn PluginFactory>,
    hook: &str,
    phase: &str,
) -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(kind, factory);
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
    let yaml = format!(
        r#"
engine_settings:
  dispatch: policy
plugins:
  - name: {kind}
    kind: {kind}
    hooks: [{hook}]
routes:
  - tool: get_weather
    authorization:
      {phase}:
        - "run({kind})"
"#
    );
    mgr.load_config_yaml(&yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

async fn manager_with_yaml(
    kind: &'static str,
    factory: Box<dyn PluginFactory>,
    yaml: &str,
) -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(kind, factory);
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
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

fn tool_meta() -> Extensions {
    let mut meta = praxis_policy_core::extensions::MetaExtension::default();
    meta.entity_type = Some("tool".to_owned());
    meta.entity_name = Some("get_weather".to_owned());
    Extensions {
        meta: Some(Arc::new(meta)),
        ..Default::default()
    }
}

fn tool_call_part(city: &str) -> ContentPart {
    ContentPart::ToolCall {
        content: ToolCall {
            tool_call_id: "tc_001".to_owned(),
            name: "get_weather".to_owned(),
            arguments: [("city".to_owned(), serde_json::json!(city))]
                .into_iter()
                .collect(),
            namespace: None,
        },
    }
}

fn tool_result_part(content: &str) -> ContentPart {
    ContentPart::ToolResult {
        content: ToolResult {
            tool_call_id: "tc_001".to_owned(),
            tool_name: "get_weather".to_owned(),
            content: serde_json::Value::String(content.to_owned()),
            is_error: false,
        },
    }
}

fn payload_of(role: Role, parts: Vec<ContentPart>) -> MessagePayload {
    MessagePayload {
        message: Message::with_content(role, parts),
    }
}

fn forwarded(result: &praxis_policy_core::executor::PipelineResult) -> &MessagePayload {
    result
        .modified_payload
        .as_ref()
        .expect("an allowed pipeline always carries the final payload")
        .as_any()
        .downcast_ref::<MessagePayload>()
        .expect("cmf hooks carry MessagePayload")
}

fn tool_result_of(payload: &MessagePayload) -> Option<&serde_json::Value> {
    payload.message.content.iter().find_map(|part| match part {
        ContentPart::ToolResult { content } => Some(&content.content),
        _ => None,
    })
}

fn tool_arg_of<'a>(payload: &'a MessagePayload, key: &str) -> Option<&'a serde_json::Value> {
    payload.message.content.iter().find_map(|part| match part {
        ContentPart::ToolCall { content } => content.arguments.get(key),
        _ => None,
    })
}

async fn resource_plugin_result(
    pipeline: &str,
    authorization: &str,
    duplicate_uri: bool,
    target: Target,
) -> praxis_policy_core::executor::PipelineResult {
    let yaml = format!(
        r#"engine_settings:
  dispatch: policy
plugins:
  - name: resource-editor
    kind: resource-editor
    hooks: [cmf.resource_post_fetch]
routes:
  - resource: hr://employees/*
    result:
      content: "{pipeline}"
{authorization}
"#
    );
    let mgr = manager_with_yaml(
        "resource-editor",
        Box::new(RewriteFactory {
            target,
            hook: "cmf.resource_post_fetch",
        }),
        &yaml,
    )
    .await;
    let ext = Extensions {
        meta: Some(Arc::new(praxis_policy_core::extensions::MetaExtension {
            entity_type: Some("resource".to_owned()),
            entity_name: Some("hr://employees/42".to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let parts = [
        ("original", "hr://employees/42", "SSN 123-45-6789"),
        (
            "other",
            if duplicate_uri {
                "hr://employees/42"
            } else {
                "hr://employees/99"
            },
            "public",
        ),
    ]
    .into_iter()
    .map(|(name, uri, text)| ContentPart::Resource {
        content: Resource {
            resource_request_id: "shared-request-id".to_owned(),
            name: Some(name.to_owned()),
            uri: uri.to_owned(),
            content: Some(text.to_owned()),
            resource_type: ResourceType::Uri,
            ..Resource::default()
        },
    })
    .collect();
    let (result, _background) = mgr
        .invoke_named::<CmfHook>(
            "cmf.resource_post_fetch",
            payload_of(Role::Tool, parts),
            ext,
            None,
        )
        .await;
    result
}

fn resource_content<'a>(
    result: &'a praxis_policy_core::executor::PipelineResult,
    name: &str,
) -> Option<&'a str> {
    forwarded(result)
        .message
        .content
        .iter()
        .find_map(|part| match part {
            ContentPart::Resource { content } if content.name.as_deref() == Some(name) => {
                content.content.as_deref()
            },
            _ => None,
        })
}

fn rewrite_ssn(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "ssn" && !value.is_string() {
                    *value = serde_json::json!("[REDACTED]");
                    return true;
                } else if rewrite_ssn(value) {
                    return true;
                }
            }
        },
        serde_json::Value::Array(items) => return items.iter_mut().any(rewrite_ssn),
        _ => {},
    }
    false
}

fn reference_part(uri: &str) -> ContentPart {
    ContentPart::ResourceRef {
        content: ResourceReference {
            resource_request_id: "shared-request".to_owned(),
            uri: uri.to_owned(),
            selector: Some(uri.to_owned()),
            name: None,
            resource_type: ResourceType::Uri,
            range_start: None,
            range_end: None,
        },
    }
}

fn prompt_part(name: &str) -> ContentPart {
    ContentPart::PromptResult {
        content: PromptResult {
            prompt_request_id: "shared-request".to_owned(),
            prompt_name: name.to_owned(),
            content: Some(name.to_owned()),
            description: None,
            messages: vec![],
            is_error: false,
            error_message: None,
        },
    }
}

async fn projection_edit_result(
    context: (&str, &str, &str),
    field: &str,
    pipeline: &str,
    authorization: &str,
    parts: Vec<ContentPart>,
    target: Target,
) -> praxis_policy_core::executor::PipelineResult {
    let (entity, hook, block) = context;
    let yaml = format!(
        "engine_settings:\n  dispatch: policy\nplugins:\n  - name: projection-editor\n    kind: projection-editor\n    hooks: [{hook}]\nroutes:\n  - {entity}: '*'\n    {block}:\n      '{field}': '{pipeline}'\n{authorization}\n"
    );
    let mgr = manager_with_yaml(
        "projection-editor",
        Box::new(RewriteFactory {
            target,
            hook: match hook {
                "cmf.resource_pre_fetch" => "cmf.resource_pre_fetch",
                "cmf.resource_post_fetch" => "cmf.resource_post_fetch",
                "cmf.tool_post_invoke" => "cmf.tool_post_invoke",
                "cmf.prompt_pre_invoke" => "cmf.prompt_pre_invoke",
                _ => "cmf.prompt_post_invoke",
            },
        }),
        &yaml,
    )
    .await;
    let extensions = Extensions {
        meta: Some(Arc::new(praxis_policy_core::extensions::MetaExtension {
            entity_type: Some(entity.to_owned()),
            entity_name: Some("original".to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let (result, _background) = mgr
        .invoke_named::<CmfHook>(hook, payload_of(Role::Tool, parts), extensions, None)
        .await;
    result
}
