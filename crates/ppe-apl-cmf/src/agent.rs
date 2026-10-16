// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// AgentExtension → AttributeBag.
//
// Namespace:
//   agent.input                  : String
//   agent.session_id             : String
//   agent.conversation_id        : String
//   agent.turn                   : Int
//   agent.agent_id               : String
//   agent.parent_agent_id        : String
//   agent.conversation.summary   : String
//   agent.conversation.topics    : StringSet (always, when `conversation` is present)

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::AgentExtension;
use std::collections::HashSet;

/// Write agent session and lineage into the bag.
pub fn extract_agent(agent: &AgentExtension, bag: &mut AttributeBag) {
    if let Some(v) = &agent.input {
        bag.set("agent.input", v.clone());
    }
    if let Some(v) = &agent.session_id {
        bag.set("agent.session_id", v.clone());
    }
    if let Some(v) = &agent.conversation_id {
        bag.set("agent.conversation_id", v.clone());
    }
    if let Some(v) = agent.turn {
        bag.set("agent.turn", i64::from(v));
    }
    if let Some(v) = &agent.agent_id {
        bag.set("agent.agent_id", v.clone());
    }
    if let Some(v) = &agent.parent_agent_id {
        bag.set("agent.parent_agent_id", v.clone());
    }
    if let Some(conv) = &agent.conversation {
        if let Some(s) = &conv.summary {
            bag.set("agent.conversation.summary", s.clone());
        }
        // Always emitted, empty rather than absent — see the empty-set note in
        // `security.rs`, which documents the rule for the whole bridge.
        let topics: HashSet<String> = conv.topics.iter().cloned().collect();
        bag.set("agent.conversation.topics", topics);
        // `history` is `Vec<Message>`, the CMF type the host already builds for
        // the current turn, so a plugin reads a past turn with the same
        // `ContentPart` code it uses on the payload, and a malformed turn fails
        // at deserialization rather than reaching a plugin as opaque JSON.
        // It is not written into the bag: bag values are scalars and string
        // sets, and a turn's nested content parts have no flat key to live
        // under. A policy that needs history calls a plugin holding
        // `read_agent`; see `reference/plugins/transcript-scanner`.
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
    use praxis_policy_core::extensions::agent::ConversationContext;

    #[test]
    fn populates_present_fields_only() {
        let agent = AgentExtension {
            session_id: Some("sess-1".into()),
            conversation_id: Some("conv-9".into()),
            turn: Some(3),
            agent_id: Some("hr-agent".into()),
            parent_agent_id: None,
            conversation: Some(ConversationContext {
                summary: Some("hr inquiry".into()),
                topics: vec!["payroll".into(), "ssn".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_agent(&agent, &mut bag);
        assert_eq!(bag.get_string("agent.session_id"), Some("sess-1"));
        assert_eq!(bag.get_int("agent.turn"), Some(3));
        assert_eq!(
            bag.get_string("agent.conversation.summary"),
            Some("hr inquiry")
        );
        assert!(bag.set_contains("agent.conversation.topics", "payroll"));
        assert!(!bag.contains("agent.parent_agent_id"));
    }

    /// History reaches plugins, not the bag. Nothing a turn holds may surface
    /// under any key, so a policy cannot come to depend on a flattening this
    /// bridge does not promise.
    #[test]
    fn history_is_not_flattened_into_the_bag() {
        use praxis_policy_apl_core::AttributeValue;
        use praxis_policy_core::cmf::{Message, Role};

        let agent = AgentExtension {
            conversation: Some(ConversationContext {
                history: vec![
                    Message::text(Role::User, "turn-zero-text"),
                    Message::text(Role::Assistant, "turn-one-text"),
                ],
                summary: None,
                topics: vec![],
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_agent(&agent, &mut bag);

        // The topics key is still written, as an empty set: the bridge emits
        // it whenever a conversation is present (see the empty-set note in
        // `security.rs`). It is the only key history-only input may produce.
        let keys: Vec<&str> = bag.iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec!["agent.conversation.topics"],
            "a conversation with only history contributes only the topics set"
        );
        assert!(
            bag.get_string_set("agent.conversation.topics")
                .expect("topics is a string set")
                .is_empty(),
            "no topics were given, so the set is empty"
        );
        for (_, v) in bag.iter() {
            if let AttributeValue::String(s) = v {
                assert!(
                    !s.contains("turn-"),
                    "history text leaked into the bag: {s}"
                );
            }
        }
    }
}
