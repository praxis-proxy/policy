// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// LLMExtension — model identity and capabilities, plus what the request asks
// of the model.

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

    /// What this request asks of the model, when the host can see it.
    ///
    /// `None` means the host did not report the request, which is not the
    /// same as a request that offers no tools and sets no parameters. A
    /// gateway on a provider HTTP API reads all of this from the request
    /// body; an in-process hook may see only part of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<LLMRequest>,
}

/// The parts of an LLM request that are not the conversation itself.
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

    /// A host that does not report the request still produces a valid
    /// extension, and the request stays `None` rather than defaulting to an
    /// empty one: the two mean different things to a policy.
    #[test]
    fn absent_request_stays_none() {
        let llm: LLMExtension = serde_json::from_value(json!({ "model_id": "gpt-4" })).unwrap();
        assert!(llm.request.is_none());
        let back = serde_json::to_value(&llm).unwrap();
        assert!(back.get("request").is_none(), "None is not serialized");
    }

    #[test]
    fn a_full_request_round_trips() {
        let wire = json!({
            "model_id": "gpt-4",
            "request": {
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
            }
        });
        let llm: LLMExtension = serde_json::from_value(wire.clone()).unwrap();
        let req = llm.request.as_ref().expect("request present");
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

        // Serialization adds defaulted fields (`capabilities`, a tool's
        // `annotations`), so compare a second trip against the first rather
        // than against the input.
        let once = serde_json::to_value(&llm).unwrap();
        let again: LLMExtension = serde_json::from_value(once.clone()).unwrap();
        assert_eq!(serde_json::to_value(&again).unwrap(), once);
        assert_eq!(
            once["request"]["tool_choice"],
            wire["request"]["tool_choice"]
        );
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
}
