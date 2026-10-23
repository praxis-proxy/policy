// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Model identity and the gated inference request.

use std::{fmt, sync::Arc};

use serde::{Deserialize, Serialize};

use super::mcp::ToolMetadata;

/// Model identity and capabilities.
///
/// Immutable — set by the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LLMExtension {
    /// Model identifier (e.g., "gpt-4o", "claude-sonnet-4-20250514").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,

    /// Provider name (e.g., "openai", "anthropic").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Model capabilities (e.g., "`tool_use`", "vision", "streaming").
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// A system or developer instruction sent to the model.
#[derive(Clone, Serialize, Deserialize)]
pub struct LlmInstruction {
    /// The instruction's authority level.
    pub role: LlmInstructionRole,
    /// Exact UTF-8 text.
    pub text: String,
}

impl fmt::Debug for LlmInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmInstruction")
            .field("role", &self.role)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}

/// Authority level of an inference instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmInstructionRole {
    /// Provider system instruction.
    System,
    /// Application developer instruction.
    Developer,
}

/// Normalized parts of an LLM request other than the conversation itself.
///
/// Carried inside [`LlmRequest`], not on [`LLMExtension`], so a plugin sees it
/// only with `read_llm_request`, and it is never serialized as an extension.
///
/// A present request claims the host saw all of it: `offered_tools` lists
/// every tool the provider will expose, and `instructions` holds every system
/// and developer instruction in order. A host that cannot list everything
/// leaves the normalized parts absent.
///
/// Every field is optional because providers name and default them
/// differently: an absent field means the request did not set it, and the
/// provider's default applies.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LlmRequestParts {
    /// Ordered system and developer instructions, with their roles preserved.
    #[serde(default)]
    pub instructions: Vec<LlmInstruction>,

    /// The tool definitions offered to the model on this request.
    ///
    /// The same type MCP tool metadata uses: a tool offered to a model is
    /// often an MCP tool, and `server_id` / `namespace` say which.
    #[serde(default)]
    pub offered_tools: Vec<ToolMetadata>,

    /// How the model may use the offered tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,

    /// Upper bound on output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,

    /// Number of candidate completions requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_count: Option<u32>,

    /// Sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,

    /// Nucleus sampling cutoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,

    /// Sequences that end generation.
    #[serde(default)]
    pub stop_sequences: Vec<String>,

    /// Whether the response is streamed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

impl fmt::Debug for LlmRequestParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmRequestParts")
            .field("instructions", &self.instructions.len())
            .field("offered_tools", &self.offered_tools.len())
            .field("tool_choice_present", &self.tool_choice.is_some())
            .field("max_tokens", &self.max_tokens)
            .field("candidate_count", &self.candidate_count)
            .field("temperature", &self.temperature)
            .field("top_p", &self.top_p)
            .field("stop_sequences", &self.stop_sequences.len())
            .field("stream", &self.stream)
            .finish()
    }
}

/// Compatibility name for the normalized request parts.
pub type LLMRequest = LlmRequestParts;

/// How the model may use the tools it is offered.
///
/// Serialized with a `type` tag: `{"type": "auto"}`,
/// `{"type": "tool", "name": "search"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolChoice {
    /// The model decides whether to call a tool.
    Auto,
    /// The model must not call a tool.
    None,
    /// The model must call some tool.
    Required,
    /// The model must call this tool.
    Tool {
        /// Name of the tool the model is forced to call.
        name: String,
    },
}

/// The inference request, carrying an optional parsed body and normalized parts.
///
/// The whole carrier is immutable and gated by `read_llm_request`. `Debug`
/// prints only shape, so logging extensions never dumps prompt text or tools.
#[derive(Clone)]
pub struct LlmRequest(Arc<LlmRequestData>);

struct LlmRequestData {
    body: Option<Arc<serde_json::Value>>,
    parts: Option<LlmRequestParts>,
}

impl LlmRequest {
    /// Wraps a parsed request body without normalized parts.
    #[must_use]
    pub fn new(value: serde_json::Value) -> Self {
        Self(Arc::new(LlmRequestData {
            body: Some(Arc::new(value)),
            parts: None,
        }))
    }

    /// Wraps normalized parts when the host has no JSON body.
    #[must_use]
    pub fn from_parts(parts: LlmRequestParts) -> Self {
        Self(Arc::new(LlmRequestData {
            body: None,
            parts: Some(parts),
        }))
    }

    /// Attaches normalized parts to a body-only request.
    #[must_use]
    pub fn with_parts(self, parts: LlmRequestParts) -> Self {
        Self(Arc::new(LlmRequestData {
            body: self.0.body.clone(),
            parts: Some(parts),
        }))
    }

    /// The parsed request body, if supplied by the host.
    #[must_use]
    pub fn body(&self) -> Option<&serde_json::Value> {
        self.0.body.as_deref()
    }

    /// The shared parsed body, for passing it to a PDP without a copy.
    #[must_use]
    pub fn body_shared(&self) -> Option<&Arc<serde_json::Value>> {
        self.0.body.as_ref()
    }

    /// The normalized request parts, if supplied by the host.
    #[must_use]
    pub fn parts(&self) -> Option<&LlmRequestParts> {
        self.0.parts.as_ref()
    }

    /// Whether two carriers share exactly the same immutable request data.
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for LlmRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmRequest")
            .field("body_present", &self.0.body.is_some())
            .field("parts_present", &self.0.parts.is_some())
            .finish()
    }
}

/// Compatibility name for a body-only inference request.
pub type LlmRequestDocument = LlmRequest;

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
    use serde_json::json;

    #[test]
    fn a_full_request_round_trips() {
        let wire = json!({
            "instructions": [{
                "role": "system", "text": "You are a helpful assistant."
            }],
            "offered_tools": [
                { "name": "send_email", "description": "Send an email" },
                { "name": "search", "server_id": "web" }
            ],
            "tool_choice": { "type": "tool", "name": "search" },
            "max_tokens": 1024,
            "candidate_count": 2,
            "temperature": 0.2,
            "top_p": 0.9,
            "stop_sequences": ["\n\nHuman:"],
            "stream": true
        });
        let req: LlmRequestParts = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(req.instructions[0].role, LlmInstructionRole::System);
        assert_eq!(req.instructions[0].text, "You are a helpful assistant.");
        assert_eq!(req.offered_tools.len(), 2);
        assert_eq!(req.offered_tools[1].server_id.as_deref(), Some("web"));
        assert_eq!(
            req.tool_choice,
            Some(ToolChoice::Tool {
                name: "search".into()
            })
        );
        assert_eq!(req.max_tokens, Some(1024));
        assert_eq!(req.candidate_count, Some(2));
        assert_eq!(req.temperature, Some(0.2));
        assert_eq!(req.stream, Some(true));

        // Serialization adds defaulted fields (a tool's `annotations`), so
        // compare a second trip against the first rather than against the
        // input.
        let once = serde_json::to_value(&req).unwrap();
        let again: LlmRequestParts = serde_json::from_value(once.clone()).unwrap();
        assert_eq!(serde_json::to_value(&again).unwrap(), once);
        assert_eq!(once["tool_choice"], wire["tool_choice"]);
    }

    /// The tag values are what a host writes, so they are pinned.
    #[test]
    fn tool_choice_wire_form() {
        for (choice, wire) in [
            (ToolChoice::Auto, json!({ "type": "auto" })),
            (ToolChoice::None, json!({ "type": "none" })),
            (ToolChoice::Required, json!({ "type": "required" })),
            (
                ToolChoice::Tool { name: "x".into() },
                json!({ "type": "tool", "name": "x" }),
            ),
        ] {
            assert_eq!(serde_json::to_value(&choice).unwrap(), wire);
            assert_eq!(serde_json::from_value::<ToolChoice>(wire).unwrap(), choice);
        }
    }

    #[test]
    fn an_offered_tool_without_a_name_is_refused() {
        let err = serde_json::from_value::<LlmRequestParts>(json!({
            "offered_tools": [{ "description": "nameless" }]
        }));
        assert!(err.is_err(), "a tool a policy cannot name must not load");
    }

    #[test]
    fn test_debug_hides_request_body() {
        let doc = LlmRequest::new(serde_json::json!({"messages": ["secret-marker"]}));
        let rendered = format!("{doc:?}");
        assert_eq!(
            rendered,
            "LlmRequest { body_present: true, parts_present: false }"
        );
        assert!(!rendered.contains("secret-marker"));
    }

    #[test]
    fn normalized_parts_and_instructions_hide_content_in_debug() {
        let parts = LlmRequestParts {
            instructions: vec![LlmInstruction {
                role: LlmInstructionRole::Developer,
                text: "secret-prompt-marker".into(),
            }],
            offered_tools: vec![ToolMetadata {
                name: "search".into(),
                description: Some("secret-schema-marker".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        for rendered in [
            format!("{parts:?}"),
            format!("{:?}", parts.instructions[0]),
            format!("{:?}", LlmRequest::from_parts(parts.clone())),
        ] {
            assert!(!rendered.contains("secret-prompt-marker"));
            assert!(!rendered.contains("secret-schema-marker"));
        }
    }

    #[test]
    fn carrier_supports_body_only_parts_only_and_both() {
        let body = json!({"model": "gpt-4o"});
        let parts = LlmRequestParts::default();
        let raw = LlmRequest::new(body.clone());
        assert_eq!(raw.body(), Some(&body));
        assert!(raw.parts().is_none());
        let typed = LlmRequest::from_parts(parts.clone());
        assert!(typed.body().is_none());
        assert!(typed.parts().is_some());
        let both = raw.with_parts(parts);
        assert_eq!(both.body(), Some(&body));
        assert!(both.parts().is_some());
    }
}
