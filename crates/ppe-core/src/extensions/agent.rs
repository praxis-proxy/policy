// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// AgentExtension — session, conversation, agent lineage.

use serde::{Deserialize, Serialize};

use crate::cmf::Message;

/// Conversation history context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversationContext {
    /// Prior turns of the conversation, oldest first, as CMF messages.
    ///
    /// The same type as the current turn's payload, so a plugin walks a
    /// historical turn's `ContentPart`s with the code it uses on the live one.
    /// The host decides how far back this reaches; an empty list means the
    /// host carried no history, not that the conversation has none.
    ///
    /// Not flattened into the APL attribute bag. A policy that needs to reason
    /// over history does it through a plugin holding `read_agent`.
    #[serde(default)]
    pub history: Vec<Message>,

    /// LLM-generated summary of the conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Detected topics in the conversation.
    #[serde(default)]
    pub topics: Vec<String>,
}

/// Agent execution context extension.
///
/// Carries session tracking, conversation context, multi-agent
/// lineage, and the original user/agent input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentExtension {
    /// Original user/agent input that triggered this action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,

    /// Broad user/agent session identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Specific dialogue/task identifier within a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,

    /// Position within the conversation (0-indexed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<u32>,

    /// Identifier of the agent that produced this message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// If spawned by another agent, the parent's ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent_id: Option<String>,

    /// Optional conversation context with history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<ConversationContext>,
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
    use crate::cmf::{ContentPart, Role, ToolCall};
    use serde_json::json;

    /// A history turn keeps every part it was built with, not only its text,
    /// so a plugin reading history sees tool calls the same way it would on
    /// the live turn.
    #[test]
    fn typed_history_round_trips_with_its_parts() {
        let conv = ConversationContext {
            history: vec![
                Message::text(Role::User, "look up alice"),
                Message::with_content(
                    Role::Assistant,
                    vec![ContentPart::ToolCall {
                        content: ToolCall {
                            tool_call_id: "tc_1".into(),
                            name: "lookup".into(),
                            arguments: [("who".to_owned(), json!("alice"))].into(),
                            namespace: None,
                        },
                    }],
                ),
            ],
            ..Default::default()
        };

        let wire = serde_json::to_value(&conv).unwrap();
        let back: ConversationContext = serde_json::from_value(wire).unwrap();

        assert_eq!(back.history.len(), 2, "turns are preserved in order");
        assert_eq!(back.history[0].role, Role::User);
        assert_eq!(back.history[0].get_text_content(), "look up alice");
        assert_eq!(back.history[1].role, Role::Assistant);
        let calls = back.history[1].get_tool_calls();
        assert_eq!(calls.len(), 1, "the tool call survives the round trip");
        assert_eq!(calls[0].name, "lookup");
    }

    /// A host that sends no history at all still yields a valid context.
    #[test]
    fn absent_history_is_empty() {
        let conv: ConversationContext =
            serde_json::from_value(json!({ "summary": "hr inquiry" })).unwrap();
        assert!(conv.history.is_empty());
        assert_eq!(conv.summary.as_deref(), Some("hr inquiry"));
    }

    /// A history turn written as the JSON form of a Common Message Format
    /// (CMF) `Message`, the type every hook payload uses, deserializes:
    /// `{"role": "user", "content": [...]}`. `schema_version` may be omitted
    /// and is defaulted exactly as it is on the current turn's message.
    #[test]
    fn a_cmf_shaped_turn_deserializes() {
        let conv: ConversationContext = serde_json::from_value(json!({
            "history": [{ "role": "user", "content": [] }]
        }))
        .unwrap();
        assert_eq!(conv.history.len(), 1);
        assert_eq!(conv.history[0].role, Role::User);
        assert_eq!(
            conv.history[0].schema_version,
            crate::cmf::constants::SCHEMA_VERSION
        );
    }

    /// Entries that are not messages are refused rather than dropped. Before
    /// the field was typed a host could put anything here, so a host still
    /// sending free-form summaries has to find out at the boundary, not when a
    /// scanner quietly reads an empty transcript.
    #[test]
    fn a_turn_that_is_not_a_message_is_refused() {
        for entry in [
            json!({ "summary": "user asked about payroll" }),
            json!("hi"),
        ] {
            let err = serde_json::from_value::<ConversationContext>(json!({
                "history": [entry]
            }));
            assert!(err.is_err(), "{entry} must not deserialize as a turn");
        }
    }
}
