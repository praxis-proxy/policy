// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// LLMExtension → AttributeBag.
//
// Namespace:
//   llm.model_id              : String
//   llm.provider              : String
//   llm.capabilities          : StringSet (always present, empty rather than absent)
//
// From `LLMExtension.request`, only when the host reported one:
//   llm.offered_tools         : StringSet of tool names (always, when `request` is present)
//   llm.stop_sequences        : StringSet (always, when `request` is present)
//   llm.tool_choice           : String — `auto`, `none`, `required`, or `tool`
//   llm.forced_tool           : String (when `tool_choice` is `tool`)
//   llm.max_tokens            : Int
//   llm.temperature           : Float
//   llm.top_p                 : Float
//   llm.stream                : Bool
//   llm.system_prompt_digest  : String, `sha256:<hex>` of the prompt's UTF-8 bytes
//
// An absent `request` writes none of these, so a predicate on one of them
// reads a missing key. That is deliberate: "the host could not see the
// request" must not look like "the request offered no tools".
//
// The system prompt itself is not bridged. The digest is enough to pin a
// known prompt (`llm.system_prompt_digest != 'sha256:…': deny`), and a plugin
// that needs the text reads it from the extension.
//
// The forced tool name is its own key rather than `llm.tool_choice.name`:
// a key that is both a leaf and a namespace prefix collides in the CEL and
// OPA inputs, where dotted keys become nested maps.

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::{LLMExtension, LLMRequest, ToolChoice};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

/// Write model identity, and the request when present, into the bag.
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

    if let Some(req) = &llm.request {
        extract_request(req, bag);
    }
}

fn extract_request(req: &LLMRequest, bag: &mut AttributeBag) {
    // Sets follow the empty-set rule within a present request.
    let offered: HashSet<String> = req.offered_tools.iter().map(|t| t.name.clone()).collect();
    bag.set("llm.offered_tools", offered);
    let stops: HashSet<String> = req.stop_sequences.iter().cloned().collect();
    bag.set("llm.stop_sequences", stops);

    if let Some(choice) = &req.tool_choice {
        let mode = match choice {
            ToolChoice::Auto => "auto",
            ToolChoice::None => "none",
            ToolChoice::Required => "required",
            ToolChoice::Tool { name } => {
                bag.set("llm.forced_tool", name.clone());
                "tool"
            },
        };
        bag.set("llm.tool_choice", mode);
    }
    if let Some(v) = req.max_tokens {
        bag.set("llm.max_tokens", i64::from(v));
    }
    if let Some(v) = req.temperature {
        bag.set("llm.temperature", v);
    }
    if let Some(v) = req.top_p {
        bag.set("llm.top_p", v);
    }
    if let Some(v) = req.stream {
        bag.set("llm.stream", v);
    }
    if let Some(prompt) = &req.system_prompt {
        bag.set("llm.system_prompt_digest", sha256_ref(prompt));
    }
}

/// `sha256:` followed by the lowercase hex digest of `text`'s UTF-8 bytes.
fn sha256_ref(text: &str) -> String {
    let hex: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
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
    use praxis_policy_core::extensions::ToolMetadata;

    fn tool(name: &str) -> ToolMetadata {
        ToolMetadata {
            name: name.into(),
            ..Default::default()
        }
    }

    fn bag_for(request: Option<LLMRequest>) -> AttributeBag {
        let llm = LLMExtension {
            model_id: Some("gpt-4".into()),
            request,
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_llm(&llm, &mut bag);
        bag
    }

    #[test]
    fn extracts_model_and_capabilities() {
        let llm = LLMExtension {
            model_id: Some("gpt-4".into()),
            provider: Some("openai".into()),
            capabilities: vec!["tool_use".into(), "vision".into()],
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_llm(&llm, &mut bag);
        assert_eq!(bag.get_string("llm.model_id"), Some("gpt-4"));
        assert_eq!(bag.get_string("llm.provider"), Some("openai"));
        assert!(bag.set_contains("llm.capabilities", "tool_use"));
        assert!(bag.set_contains("llm.capabilities", "vision"));
    }

    #[test]
    fn extracts_every_request_field() {
        let bag = bag_for(Some(LLMRequest {
            system_prompt: Some("abc".into()),
            offered_tools: vec![tool("send_email"), tool("search")],
            tool_choice: Some(ToolChoice::Tool {
                name: "search".into(),
            }),
            max_tokens: Some(1024),
            temperature: Some(0.5),
            top_p: Some(0.9),
            stop_sequences: vec!["END".into()],
            stream: Some(true),
        }));

        assert!(bag.set_contains("llm.offered_tools", "send_email"));
        assert!(bag.set_contains("llm.offered_tools", "search"));
        assert!(bag.set_contains("llm.stop_sequences", "END"));
        assert_eq!(bag.get_string("llm.tool_choice"), Some("tool"));
        assert_eq!(bag.get_string("llm.forced_tool"), Some("search"));
        assert_eq!(bag.get_int("llm.max_tokens"), Some(1024));
        assert_eq!(bag.get_float("llm.temperature"), Some(0.5));
        assert_eq!(bag.get_float("llm.top_p"), Some(0.9));
        assert_eq!(bag.get_bool("llm.stream"), Some(true));
        // The well-known SHA-256 of "abc".
        assert_eq!(
            bag.get_string("llm.system_prompt_digest"),
            Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    /// The prompt text itself never reaches the bag, under any key.
    #[test]
    fn the_system_prompt_text_is_not_bridged() {
        let bag = bag_for(Some(LLMRequest {
            system_prompt: Some("prompt-text-marker".into()),
            ..Default::default()
        }));
        for (k, v) in bag.iter() {
            if let praxis_policy_apl_core::AttributeValue::String(s) = v {
                assert!(!s.contains("prompt-text-marker"), "{k} carries the prompt");
            }
        }
    }

    /// Only a forced tool writes `llm.forced_tool`; the other modes do not
    /// leave a stale name behind.
    #[test]
    fn tool_choice_modes() {
        for (choice, mode) in [
            (ToolChoice::Auto, "auto"),
            (ToolChoice::None, "none"),
            (ToolChoice::Required, "required"),
        ] {
            let bag = bag_for(Some(LLMRequest {
                tool_choice: Some(choice),
                ..Default::default()
            }));
            assert_eq!(bag.get_string("llm.tool_choice"), Some(mode));
            assert!(!bag.contains("llm.forced_tool"), "{mode} forces no tool");
        }
    }

    /// A present request with nothing set still yields the two sets, empty,
    /// so `llm.offered_tools contains 'x'` evaluates false rather than
    /// reading a missing key. The optional scalars stay absent.
    #[test]
    fn an_empty_request_emits_empty_sets_and_no_scalars() {
        let bag = bag_for(Some(LLMRequest::default()));
        assert!(bag.get_string_set("llm.offered_tools").unwrap().is_empty());
        assert!(bag.get_string_set("llm.stop_sequences").unwrap().is_empty());
        for key in [
            "llm.tool_choice",
            "llm.forced_tool",
            "llm.max_tokens",
            "llm.temperature",
            "llm.top_p",
            "llm.stream",
            "llm.system_prompt_digest",
        ] {
            assert!(!bag.contains(key), "{key} was not set on the request");
        }
    }

    /// No request, no request keys, not even the sets: the host could not see
    /// the request, and an empty set would claim it offered no tools.
    #[test]
    fn an_absent_request_emits_no_request_keys() {
        let bag = bag_for(None);
        let keys: HashSet<&str> = bag.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, HashSet::from(["llm.model_id", "llm.capabilities"]));
    }
}
