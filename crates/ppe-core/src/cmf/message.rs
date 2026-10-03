// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// CMF Message — canonical message representation.
//
// A Message is the storage and wire format for a single turn in a
// conversation. It preserves structure exactly as the LLM or
// framework sent it.
//
// Extensions are NOT part of the Message. They are passed separately
// to handlers via the framework's Extensions type. This allows
// extensions to be shared across payload types and avoids copying
// the message when extensions change.

use serde::{Deserialize, Serialize};

#[allow(
    clippy::wildcard_imports,
    reason = "sibling module in one logical unit split across files; naming each \
              item would be a hand-maintained list with no reader benefit"
)]
use super::content::*;
use super::enums::{Channel, Role};
use crate::hooks::trait_def::PluginResult;

/// Canonical CMF message representing a single turn in a conversation.
///
/// All content is carried as typed `ContentPart` variants. Extensions
/// (identity, security, HTTP, agent context) are passed separately
/// to handlers — not inside the message.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Who is speaking.
    pub role: Role,

    /// List of typed content parts (multimodal).
    #[serde(default)]
    pub content: Vec<ContentPart>,

    /// Optional output classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Channel>,
}

fn default_schema_version() -> String {
    super::constants::SCHEMA_VERSION.to_owned()
}

impl Message {
    /// Create a simple text message.
    pub fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            schema_version: super::constants::SCHEMA_VERSION.to_owned(),
            role,
            content: vec![ContentPart::Text { text: text.into() }],
            channel: None,
        }
    }

    /// Create a message from an arbitrary list of typed content
    /// parts. The schema version is set from `SCHEMA_VERSION` —
    /// callers never hardcode it. Use this when the content isn't a
    /// single text blob (tool calls, prompt requests, resource refs,
    /// multimodal mixes).
    pub fn with_content(role: Role, content: Vec<ContentPart>) -> Self {
        Self {
            schema_version: super::constants::SCHEMA_VERSION.to_owned(),
            role,
            content,
            channel: None,
        }
    }

    /// Extract all text content from the message.
    ///
    /// Concatenates text from all `Text` content parts.
    ///
    /// Reads `Text` parts and nothing else, so it is not a stand-in for
    /// message equality or change detection: two messages differing only
    /// in a tool call, tool result, thinking block, or attachment return
    /// the same string. Callers asking "did this change?" need a signal
    /// from whatever performed the change.
    pub fn get_text_content(&self) -> String {
        let mut texts = Vec::new();
        for part in &self.content {
            if let ContentPart::Text { text } = part {
                texts.push(text.as_str());
            }
        }
        texts.join("")
    }

    /// Extract thinking/reasoning content if present.
    pub fn get_thinking_content(&self) -> Option<String> {
        let mut texts = Vec::new();
        for part in &self.content {
            if let ContentPart::Thinking { text } = part {
                texts.push(text.as_str());
            }
        }
        if texts.is_empty() {
            None
        } else {
            Some(texts.join(""))
        }
    }

    /// Get all tool calls in this message.
    pub fn get_tool_calls(&self) -> Vec<&ToolCall> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::ToolCall { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all tool results in this message.
    pub fn get_tool_results(&self) -> Vec<&ToolResult> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::ToolResult { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Whether this message contains any tool calls.
    pub fn is_tool_call(&self) -> bool {
        self.content
            .iter()
            .any(|p| matches!(p, ContentPart::ToolCall { .. }))
    }

    /// Whether this message contains any tool results.
    pub fn is_tool_result(&self) -> bool {
        self.content
            .iter()
            .any(|p| matches!(p, ContentPart::ToolResult { .. }))
    }

    /// Get all embedded resources in this message.
    pub fn get_resources(&self) -> Vec<&Resource> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Resource { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all resource references in this message.
    pub fn get_resource_refs(&self) -> Vec<&ResourceReference> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::ResourceRef { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all resource URIs (both embedded and references).
    pub fn get_all_resource_uris(&self) -> Vec<&str> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Resource { content } => Some(content.uri.as_str()),
                ContentPart::ResourceRef { content } => Some(content.uri.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Whether this message contains any resources or resource references.
    pub fn has_resources(&self) -> bool {
        self.content.iter().any(|p| {
            matches!(
                p,
                ContentPart::Resource { .. } | ContentPart::ResourceRef { .. }
            )
        })
    }

    /// Get all prompt requests in this message.
    pub fn get_prompt_requests(&self) -> Vec<&PromptRequest> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::PromptRequest { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all prompt results in this message.
    pub fn get_prompt_results(&self) -> Vec<&PromptResult> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::PromptResult { content } => Some(content),
                _ => None,
            })
            .collect()
    }
}

/// CMF Message wrapped as a `PluginPayload` for hook dispatch.
///
/// This is the payload type for all `cmf.*` hooks. Plugins that
/// handle CMF hooks implement `HookHandler<CmfHook>` and receive
/// `&MessagePayload` in their handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    /// The CMF message.
    pub message: Message,
}

// `audit_serialize` opts this payload into content-provenance hashing. It is
// the payload that carries tool arguments and model output, so it is the one a
// reader most wants to know went in and came out unchanged. Only the digest is
// recorded, and only when an operator enables provenance.
crate::impl_plugin_payload!(MessagePayload, audit_serialize);

crate::define_hook! {
    /// CMF message evaluation hook.
    ///
    /// Plugins implement `HookHandler<CmfHook>` and register under
    /// one or more `cmf.*` hook names (e.g., `cmf.tool_pre_invoke`,
    /// `cmf.llm_input`). The same handler covers all CMF hook points.
    CmfHook, "cmf" => {
        payload: MessagePayload,
        result: PluginResult<MessagePayload>,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::hooks::payload::PluginPayload;
    use crate::hooks::trait_def::HookTypeDef as _;

    #[test]
    fn test_message_text_helper() {
        let msg = Message::text(Role::User, "What is the weather?");
        assert_eq!(msg.get_text_content(), "What is the weather?");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.schema_version, "2.0");
    }

    #[test]
    fn test_message_multi_part_text() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text {
                    text: "Hello ".into(),
                },
                ContentPart::Text {
                    text: "world!".into(),
                },
            ],
            channel: None,
        };
        assert_eq!(msg.get_text_content(), "Hello world!");
    }

    #[test]
    fn test_message_thinking_content() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Thinking {
                    text: "Let me think...".into(),
                },
                ContentPart::Text {
                    text: "Here's my answer.".into(),
                },
            ],
            channel: Some(Channel::Final),
        };
        assert_eq!(
            msg.get_thinking_content(),
            Some("Let me think...".to_owned())
        );
        assert_eq!(msg.get_text_content(), "Here's my answer.");
    }

    #[test]
    fn test_message_tool_calls() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text {
                    text: "Let me check.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_weather".into(),
                        arguments: [("city".to_owned(), serde_json::json!("London"))].into(),
                        namespace: None,
                    },
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_002".into(),
                        name: "get_time".into(),
                        arguments: [("timezone".to_owned(), serde_json::json!("UTC"))].into(),
                        namespace: None,
                    },
                },
            ],
            channel: None,
        };
        assert!(msg.is_tool_call());
        assert!(!msg.is_tool_result());
        let calls = msg.get_tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[1].name, "get_time");
    }

    #[test]
    fn test_message_tool_results() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "tc_001".into(),
                    tool_name: "get_weather".into(),
                    content: serde_json::json!({"temp": 20}),
                    is_error: false,
                },
            }],
            channel: None,
        };
        assert!(msg.is_tool_result());
        assert!(!msg.is_tool_call());
        let results = msg.get_tool_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tool_name, "get_weather");
    }

    #[test]
    fn test_message_resources() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "rr_001".into(),
                        uri: "file:///data.txt".into(),
                        name: Some("Data File".into()),
                        description: None,
                        resource_type: super::super::enums::ResourceType::File,
                        content: Some("file contents".into()),
                        blob: None,
                        mime_type: None,
                        size_bytes: None,
                        annotations: std::collections::HashMap::new(),
                        version: None,
                    },
                },
                ContentPart::ResourceRef {
                    content: ResourceReference {
                        resource_request_id: "rr_002".into(),
                        uri: "db://users/42".into(),
                        name: None,
                        resource_type: super::super::enums::ResourceType::Database,
                        range_start: None,
                        range_end: None,
                        selector: None,
                    },
                },
            ],
            channel: None,
        };
        assert!(msg.has_resources());
        assert_eq!(msg.get_resources().len(), 1);
        assert_eq!(msg.get_resource_refs().len(), 1);
        let uris = msg.get_all_resource_uris();
        assert_eq!(uris.len(), 2);
        assert!(uris.contains(&"file:///data.txt"));
        assert!(uris.contains(&"db://users/42"));
    }

    #[test]
    fn test_message_no_resources() {
        let msg = Message::text(Role::User, "Hello");
        assert!(!msg.has_resources());
        assert!(msg.get_resources().is_empty());
    }

    #[test]
    fn test_message_serde_roundtrip() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Thinking {
                    text: "Analyzing...".into(),
                },
                ContentPart::Text {
                    text: "Here's the answer.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "search".into(),
                        arguments: [("q".to_owned(), serde_json::json!("rust"))].into(),
                        namespace: None,
                    },
                },
            ],
            channel: Some(Channel::Final),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.role, Role::Assistant);
        assert_eq!(deserialized.schema_version, "2.0");
        assert_eq!(deserialized.channel, Some(Channel::Final));
        assert_eq!(deserialized.content.len(), 3);
        assert_eq!(deserialized.get_text_content(), "Here's the answer.");
        assert_eq!(deserialized.get_tool_calls().len(), 1);
    }

    #[test]
    fn test_message_payload_as_plugin_payload() {
        let payload = MessagePayload {
            message: Message::text(Role::User, "Hello"),
        };

        // Test clone_boxed
        let boxed: Box<dyn PluginPayload> = Box::new(payload.clone());
        let cloned = boxed.clone_boxed();

        // Test as_any downcast
        let downcasted = cloned
            .as_any()
            .downcast_ref::<MessagePayload>()
            .expect("should downcast to MessagePayload");
        assert_eq!(downcasted.message.get_text_content(), "Hello");
    }

    #[test]
    fn test_cmf_hook_type_def() {
        assert_eq!(CmfHook::NAME, "cmf");
    }

    #[test]
    fn test_message_default_schema_version() {
        let json = r#"{"role":"user","content":[]}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.schema_version, "2.0");
    }

    // ---- the content selectors --------------------------------------------

    /// A message holding one of every part these selectors care about, so each
    /// one has both something to find and something it must not return.
    fn mixed_message() -> Message {
        Message::with_content(
            Role::Assistant,
            vec![
                ContentPart::Text {
                    text: "visible".into(),
                },
                ContentPart::Thinking {
                    text: "hidden".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_1".into(),
                        name: "transfer".into(),
                        arguments: std::collections::HashMap::new(),
                        namespace: None,
                    },
                },
                ContentPart::ToolResult {
                    content: ToolResult {
                        tool_call_id: "tc_1".into(),
                        tool_name: "transfer".into(),
                        content: serde_json::json!("done"),
                        is_error: false,
                    },
                },
                ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "rr_1".into(),
                        uri: "file:///inline.csv".into(),
                        ..Default::default()
                    },
                },
                ContentPart::ResourceRef {
                    content: ResourceReference {
                        resource_request_id: "rr_2".into(),
                        uri: "file:///pointer.csv".into(),
                        name: None,
                        resource_type: crate::cmf::enums::ResourceType::File,
                        range_start: None,
                        range_end: None,
                        selector: None,
                    },
                },
                ContentPart::PromptRequest {
                    content: PromptRequest {
                        prompt_request_id: "pr_1".into(),
                        name: "summarize".into(),
                        arguments: std::collections::HashMap::new(),
                        server_id: None,
                    },
                },
                ContentPart::PromptResult {
                    content: PromptResult {
                        prompt_request_id: "pr_1".into(),
                        prompt_name: "summarize".into(),
                        messages: vec![],
                        content: None,
                        is_error: false,
                        error_message: None,
                    },
                },
            ],
        )
    }

    /// Each selector returns exactly its own parts from a message holding all of
    /// them. They are separate filters over the same list, so one matching the
    /// wrong variant would hand a caller a part it cannot use, and the mistake
    /// is invisible in a message that carries only one kind of content.
    #[test]
    fn each_selector_returns_only_the_parts_it_names() {
        let msg = mixed_message();

        assert_eq!(msg.get_text_content(), "visible");
        assert_eq!(
            msg.get_thinking_content().as_deref(),
            Some("hidden"),
            "reasoning is separate from visible text"
        );

        assert_eq!(msg.get_tool_calls().len(), 1);
        assert_eq!(msg.get_tool_calls()[0].name, "transfer");
        assert_eq!(msg.get_tool_results().len(), 1);
        assert_eq!(msg.get_tool_results()[0].tool_name, "transfer");

        assert_eq!(msg.get_resources().len(), 1, "inline resources only");
        assert_eq!(msg.get_resource_refs().len(), 1, "references only");
        assert_eq!(
            msg.get_all_resource_uris(),
            vec!["file:///inline.csv", "file:///pointer.csv"],
            "the combined view spans both resource kinds, in content order"
        );
        assert!(msg.has_resources());

        assert_eq!(msg.get_prompt_requests().len(), 1);
        assert_eq!(msg.get_prompt_requests()[0].name, "summarize");
        assert_eq!(msg.get_prompt_results().len(), 1);
        assert_eq!(msg.get_prompt_results()[0].prompt_name, "summarize");
    }

    /// A message whose only resource is a reference still reports having
    /// resources.
    ///
    /// `has_resources` matches two variants, and the mixed message above holds
    /// an inline resource as well, so that assertion passes even if the
    /// reference arm is dropped. A reference-only message is what makes the arm
    /// load-bearing: it is also the common shape, since a large resource is
    /// usually passed by uri rather than inline, and a rule scoped to resource
    /// access would skip exactly those.
    #[test]
    fn a_message_whose_only_resource_is_a_reference_still_has_resources() {
        let msg = Message::with_content(
            Role::User,
            vec![ContentPart::ResourceRef {
                content: ResourceReference {
                    resource_request_id: "rr".into(),
                    uri: "file:///pointer.csv".into(),
                    name: None,
                    resource_type: crate::cmf::enums::ResourceType::File,
                    range_start: None,
                    range_end: None,
                    selector: None,
                },
            }],
        );
        assert!(
            msg.has_resources(),
            "a reference is a resource for the purposes of a resource rule"
        );
        assert!(
            msg.get_resources().is_empty(),
            "and it is not an inline resource"
        );
        assert_eq!(msg.get_all_resource_uris(), vec!["file:///pointer.csv"]);
    }

    /// The mirror: an inline-only message, so neither arm can be dropped without
    /// a failure.
    #[test]
    fn a_message_whose_only_resource_is_inline_still_has_resources() {
        let msg = Message::with_content(
            Role::User,
            vec![ContentPart::Resource {
                content: Resource {
                    resource_request_id: "rr".into(),
                    uri: "file:///inline.csv".into(),
                    ..Default::default()
                },
            }],
        );
        assert!(msg.has_resources());
        assert!(msg.get_resource_refs().is_empty());
        assert_eq!(msg.get_all_resource_uris(), vec!["file:///inline.csv"]);
    }

    #[test]
    fn the_mixed_message_reports_both_prompt_kinds() {
        let msg = mixed_message();
        assert_eq!(msg.get_prompt_requests().len(), 1);
        assert_eq!(msg.get_prompt_requests()[0].name, "summarize");
        assert_eq!(msg.get_prompt_results().len(), 1);
        assert_eq!(msg.get_prompt_results()[0].prompt_name, "summarize");
    }

    /// The empty answers. A message with no reasoning reports none rather than
    /// an empty string, since `get_thinking_content` is an `Option` precisely so
    /// a caller can tell "no reasoning" from "reasoning that was blank".
    #[test]
    fn a_message_with_none_of_a_kind_reports_empty_rather_than_guessing() {
        let msg = Message::text(Role::User, "just text");
        assert_eq!(msg.get_thinking_content(), None);
        assert!(msg.get_tool_calls().is_empty());
        assert!(msg.get_tool_results().is_empty());
        assert!(msg.get_resources().is_empty());
        assert!(msg.get_resource_refs().is_empty());
        assert!(msg.get_all_resource_uris().is_empty());
        assert!(
            !msg.has_resources(),
            "a text-only message carries no resources"
        );
        assert!(msg.get_prompt_requests().is_empty());
        assert!(msg.get_prompt_results().is_empty());
    }
}
