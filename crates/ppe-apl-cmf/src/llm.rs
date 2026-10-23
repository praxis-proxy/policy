// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Model identity and normalized inference input → AttributeBag.
//
// Namespace:
//   llm.model.id              : String
//   llm.model.provider        : String
//   llm.model.capabilities    : StringSet (always present, empty rather than absent)
//
// From normalized `Extensions.llm_request.parts()`, when reported:
//   llm.input.offered_tools        : StringSet of tool names
//   llm.input.stop_sequences       : StringSet
//   llm.input.tool_choice          : String — `auto`, `none`, `required`, `tool`
//   llm.input.forced_tool          : String (when choice is `tool`)
//   llm.input.max_tokens           : Int
//   llm.input.candidate_count      : Int
//   llm.input.temperature          : Float
//   llm.input.top_p                : Float
//   llm.input.stream               : Bool
//   llm.input.instructions_digest  : String, `sha256-v1:<hex>`
//
// An absent request writes none of these, so a predicate on one of them
// reads a missing key. That is deliberate: "the host could not see the
// request" must not look like "the request offered no tools".
//
// Instruction text is not bridged. Its role-aware digest supports a policy
// pin, and a plugin with `read_llm_request` reads the original parts.
//
// The forced tool name is its own key rather than `llm.tool_choice.name`:
// a key that is both a leaf and a namespace prefix collides in the CEL and
// OPA inputs, where dotted keys become nested maps.

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::{
    LLMExtension, LlmInstruction, LlmInstructionRole, LlmRequestParts, ToolChoice,
};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

use crate::constants::{
    BAG_LLM_CANDIDATE_COUNT, BAG_LLM_FORCED_TOOL, BAG_LLM_INSTRUCTIONS_DIGEST, BAG_LLM_MAX_TOKENS,
    BAG_LLM_OFFERED_TOOLS, BAG_LLM_STOP_SEQUENCES, BAG_LLM_STREAM, BAG_LLM_TEMPERATURE,
    BAG_LLM_TOOL_CHOICE, BAG_LLM_TOP_P,
};

/// Write model identity into the bag.
pub fn extract_llm(llm: &LLMExtension, bag: &mut AttributeBag) {
    if let Some(v) = &llm.model_id {
        bag.set("llm.model.id", v.clone());
        bag.set("llm.model_id", v.clone());
    }
    if let Some(v) = &llm.provider {
        bag.set("llm.model.provider", v.clone());
        bag.set("llm.provider", v.clone());
    }
    // Always emitted, empty rather than absent — see the empty-set note in
    // `security.rs`, which documents the rule for the whole bridge.
    let caps: HashSet<String> = llm.capabilities.iter().cloned().collect();
    bag.set("llm.model.capabilities", caps.clone());
    bag.set("llm.capabilities", caps);
}

/// Write what the request asks of the model into the bag.
pub fn extract_llm_request(req: &LlmRequestParts, bag: &mut AttributeBag) {
    // Sets follow the empty-set rule within a present request.
    let offered: HashSet<String> = req.offered_tools.iter().map(|t| t.name.clone()).collect();
    bag.set(BAG_LLM_OFFERED_TOOLS, offered);
    let stops: HashSet<String> = req.stop_sequences.iter().cloned().collect();
    bag.set(BAG_LLM_STOP_SEQUENCES, stops);

    if let Some(choice) = &req.tool_choice {
        let mode = match choice {
            ToolChoice::Auto => "auto",
            ToolChoice::None => "none",
            ToolChoice::Required => "required",
            ToolChoice::Tool { name } => {
                bag.set(BAG_LLM_FORCED_TOOL, name.clone());
                "tool"
            },
        };
        bag.set(BAG_LLM_TOOL_CHOICE, mode);
    }
    if let Some(v) = req.max_tokens {
        bag.set(BAG_LLM_MAX_TOKENS, i64::from(v));
    }
    if let Some(v) = req.candidate_count {
        bag.set(BAG_LLM_CANDIDATE_COUNT, i64::from(v));
    }
    if let Some(v) = req.temperature {
        bag.set(BAG_LLM_TEMPERATURE, v);
    }
    if let Some(v) = req.top_p {
        bag.set(BAG_LLM_TOP_P, v);
    }
    if let Some(v) = req.stream {
        bag.set(BAG_LLM_STREAM, v);
    }
    bag.set(
        BAG_LLM_INSTRUCTIONS_DIGEST,
        instruction_digest(&req.instructions),
    );
}

/// Digest of ordered instructions, including their roles and boundaries.
///
/// The preimage is `ppe.llm.instructions.v1\0`, a big-endian `u32` count,
/// then for each instruction a one-byte role (`0` system, `1` developer),
/// a big-endian `u64` byte length, and the exact UTF-8 text bytes.
#[must_use]
pub fn instruction_digest(instructions: &[LlmInstruction]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ppe.llm.instructions.v1\0");
    digest.update(
        u32::try_from(instructions.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for instruction in instructions {
        let role = match instruction.role {
            LlmInstructionRole::System => 0_u8,
            LlmInstructionRole::Developer => 1_u8,
        };
        digest.update([role]);
        digest.update(
            u64::try_from(instruction.text.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        digest.update(instruction.text.as_bytes());
    }
    let hex: String = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256-v1:{hex}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use praxis_policy_core::extensions::{Extensions, LlmRequest, ToolMetadata};
    use std::sync::Arc;

    fn bag_for(parts: Option<LlmRequestParts>) -> AttributeBag {
        let ext = Extensions {
            llm: Some(Arc::new(LLMExtension {
                model_id: Some("gpt-4".into()),
                provider: Some("openai".into()),
                capabilities: vec!["tools".into()],
            })),
            llm_request: parts.map(LlmRequest::from_parts),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        crate::extract_extensions(&ext, &mut bag);
        bag
    }

    #[test]
    fn model_aliases_have_identical_values() {
        let bag = bag_for(None);
        for (canonical, legacy) in [
            ("llm.model.id", "llm.model_id"),
            ("llm.model.provider", "llm.provider"),
            ("llm.model.capabilities", "llm.capabilities"),
        ] {
            assert_eq!(bag.get(canonical), bag.get(legacy));
        }
    }

    #[test]
    fn normalized_request_keys_and_digest() {
        let parts = LlmRequestParts {
            instructions: vec![LlmInstruction {
                role: LlmInstructionRole::System,
                text: "abc".into(),
            }],
            offered_tools: vec![ToolMetadata {
                name: "search".into(),
                ..Default::default()
            }],
            tool_choice: Some(ToolChoice::Tool {
                name: "search".into(),
            }),
            max_tokens: Some(1024),
            candidate_count: Some(2),
            temperature: Some(0.5),
            top_p: Some(0.9),
            stop_sequences: vec!["END".into()],
            stream: Some(true),
        };
        let bag = bag_for(Some(parts.clone()));
        assert!(bag.set_contains("llm.input.offered_tools", "search"));
        assert!(bag.set_contains("llm.input.stop_sequences", "END"));
        assert_eq!(bag.get_string("llm.input.tool_choice"), Some("tool"));
        assert_eq!(bag.get_string("llm.input.forced_tool"), Some("search"));
        assert_eq!(bag.get_int("llm.input.max_tokens"), Some(1024));
        assert_eq!(bag.get_int("llm.input.candidate_count"), Some(2));
        assert_eq!(bag.get_float("llm.input.temperature"), Some(0.5));
        assert_eq!(bag.get_float("llm.input.top_p"), Some(0.9));
        assert_eq!(bag.get_bool("llm.input.stream"), Some(true));
        assert_eq!(
            bag.get_string("llm.input.instructions_digest"),
            Some(instruction_digest(&parts.instructions).as_str())
        );
        assert!(!bag.contains("llm.offered_tools"));
    }

    #[test]
    fn digest_distinguishes_roles_boundaries_order_and_bytes() {
        let system = |text: &str| LlmInstruction {
            role: LlmInstructionRole::System,
            text: text.into(),
        };
        let developer = |text: &str| LlmInstruction {
            role: LlmInstructionRole::Developer,
            text: text.into(),
        };
        let base = vec![system("ab"), developer("c")];
        let digest = instruction_digest(&base);
        assert!(digest.starts_with("sha256-v1:"));
        for changed in [
            vec![developer("ab"), developer("c")],
            vec![system("a"), developer("bc")],
            vec![developer("c"), system("ab")],
            vec![system("aB"), developer("c")],
        ] {
            assert_ne!(digest, instruction_digest(&changed));
        }
        assert_ne!(digest, instruction_digest(&[]));
    }

    #[test]
    fn absence_and_empty_parts_differ() {
        let absent = bag_for(None);
        assert!(!absent.contains("llm.input.offered_tools"));
        let empty = bag_for(Some(LlmRequestParts::default()));
        assert!(
            empty
                .get_string_set("llm.input.offered_tools")
                .unwrap()
                .is_empty()
        );
        assert!(
            empty
                .get_string_set("llm.input.stop_sequences")
                .unwrap()
                .is_empty()
        );
        assert!(empty.contains("llm.input.instructions_digest"));
        assert!(!empty.contains("llm.input.max_tokens"));
    }
}
