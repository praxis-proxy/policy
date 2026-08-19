// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// LLMExtension → AttributeBag.
//
// Namespace:
//   llm.model_id        : String
//   llm.provider        : String
//   llm.capabilities    : StringSet (always present, empty rather than absent)

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::LLMExtension;
use std::collections::HashSet;

/// Write model identity into the bag.
pub fn extract_llm(llm: &LLMExtension, bag: &mut AttributeBag) {
    if let Some(v) = &llm.model_id {
        bag.set("llm.model_id", v.clone());
    }
    if let Some(v) = &llm.provider {
        bag.set("llm.provider", v.clone());
    }
    // Always emitted, empty rather than absent — see the empty-set note in
    // `security.rs`, which documents the rule for the whole bridge.
    let caps: HashSet<String> = llm.capabilities.iter().cloned().collect();
    bag.set("llm.capabilities", caps);
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

    #[test]
    fn extracts_model_and_capabilities() {
        let llm = LLMExtension {
            model_id: Some("gpt-4".into()),
            provider: Some("openai".into()),
            capabilities: vec!["tool_use".into(), "vision".into()],
        };
        let mut bag = AttributeBag::new();
        extract_llm(&llm, &mut bag);
        assert_eq!(bag.get_string("llm.model_id"), Some("gpt-4"));
        assert_eq!(bag.get_string("llm.provider"), Some("openai"));
        assert!(bag.set_contains("llm.capabilities", "tool_use"));
        assert!(bag.set_contains("llm.capabilities", "vision"));
    }
}
