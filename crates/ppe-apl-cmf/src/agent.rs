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
        // `history: Vec<Value>` is deliberately not flattened — too unstructured.
        // Policies wanting conversation history should call a plugin.
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
}
