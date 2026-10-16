// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// LLMExtension — model identity and capabilities, plus what the request asks
// of the model.

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

/// The parts of an LLM request that are not the conversation itself.
///
/// Carried on `Extensions.llm_request_parts`, not on [`LLMExtension`], so a
/// plugin sees it only with `read_llm_request`, and it is never serialized.
/// `None` there means the host did not report the request, which is not the
/// same as a request that offers no tools and sets no parameters.
///
/// A present request claims the host saw all of it: `offered_tools` lists
/// every tool the provider will expose, and `system_prompt` holds every
/// system and developer instruction. A host that cannot list everything
/// leaves the slot `None`.
///
/// Every field is optional because providers name and default them
/// differently: an absent field means the request did not set it, and the
/// provider's default applies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LLMRequest {
    /// The system prompt, verbatim.
    ///
    /// Carried in full for plugins. The attribute bag gets only its digest,
    /// `llm.system_prompt_digest`, which is enough to pin a known prompt
    /// without copying a possibly large string onto every request's bag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,

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

/// Host-parsed LLM request body, shared without copying.
///
/// `Debug` prints only the JSON kind, so logging extensions never dumps the payload.
#[derive(Clone)]
pub struct LlmRequestDocument(Arc<serde_json::Value>);

impl LlmRequestDocument {
    /// Wraps a parsed request body.
    #[must_use]
    pub fn new(value: serde_json::Value) -> Self {
        Self(Arc::new(value))
    }

    /// The parsed request body.
    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.0
    }

    /// The shared handle, for passing the body on without a copy.
    #[must_use]
    pub fn shared(&self) -> &Arc<serde_json::Value> {
        &self.0
    }
}

impl fmt::Debug for LlmRequestDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.value() {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        };
        write!(f, "LlmRequestDocument(<{kind}>)")
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
    use serde_json::json;

    #[test]
    fn a_full_request_round_trips() {
        let wire = json!({
            "system_prompt": "You are a helpful assistant.",
            "offered_tools": [
                { "name": "send_email", "description": "Send an email" },
                { "name": "search", "server_id": "web" }
            ],
            "tool_choice": { "type": "tool", "name": "search" },
            "max_tokens": 1024,
            "temperature": 0.2,
            "top_p": 0.9,
            "stop_sequences": ["\n\nHuman:"],
            "stream": true
        });
        let req: LLMRequest = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(
            req.system_prompt.as_deref(),
            Some("You are a helpful assistant.")
        );
        assert_eq!(req.offered_tools.len(), 2);
        assert_eq!(req.offered_tools[1].server_id.as_deref(), Some("web"));
        assert_eq!(
            req.tool_choice,
            Some(ToolChoice::Tool {
                name: "search".into()
            })
        );
        assert_eq!(req.max_tokens, Some(1024));
        assert_eq!(req.temperature, Some(0.2));
        assert_eq!(req.stream, Some(true));

        // Serialization adds defaulted fields (a tool's `annotations`), so
        // compare a second trip against the first rather than against the
        // input.
        let once = serde_json::to_value(&req).unwrap();
        let again: LLMRequest = serde_json::from_value(once.clone()).unwrap();
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
        let err = serde_json::from_value::<LLMRequest>(json!({
            "offered_tools": [{ "description": "nameless" }]
        }));
        assert!(err.is_err(), "a tool a policy cannot name must not load");
    }

    #[test]
    fn test_debug_hides_request_body() {
        let doc = LlmRequestDocument::new(serde_json::json!({"messages": ["secret-marker"]}));
        let rendered = format!("{doc:?}");
        assert_eq!(rendered, "LlmRequestDocument(<object>)");
        assert!(!rendered.contains("secret-marker"));
    }
}
