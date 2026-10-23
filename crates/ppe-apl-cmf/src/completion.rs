// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// CompletionExtension → canonical `llm.output.*` and legacy `completion.*`.
//
// Canonical namespace: llm.output.*. Published completion.* keys remain
// value-identical aliases during policy migration.

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::{CompletionExtension, StopReason};

/// Write completion metadata into the bag.
pub fn extract_completion(c: &CompletionExtension, bag: &mut AttributeBag) {
    if let Some(sr) = c.stop_reason {
        set_alias(
            bag,
            "llm.output.stop_reason",
            "completion.stop_reason",
            stop_reason_str(sr),
        );
    }
    if let Some(tu) = &c.tokens {
        set_alias(
            bag,
            "llm.output.tokens.input",
            "completion.tokens.input",
            i64::from(tu.input_tokens),
        );
        set_alias(
            bag,
            "llm.output.tokens.output",
            "completion.tokens.output",
            i64::from(tu.output_tokens),
        );
        set_alias(
            bag,
            "llm.output.tokens.total",
            "completion.tokens.total",
            i64::from(tu.total_tokens),
        );
    }
    if let Some(v) = &c.model {
        set_alias(bag, "llm.output.model", "completion.model", v.clone());
    }
    if let Some(v) = &c.raw_format {
        set_alias(
            bag,
            "llm.output.raw_format",
            "completion.raw_format",
            v.clone(),
        );
    }
    if let Some(v) = &c.created_at {
        set_alias(
            bag,
            "llm.output.created_at",
            "completion.created_at",
            v.clone(),
        );
    }
    if let Some(ms) = c.latency_ms {
        // Saturating. This is a telemetry attribute a policy can read, so a
        // wrapped negative latency would be both wrong and confusing in a rule.
        set_alias(
            bag,
            "llm.output.latency_ms",
            "completion.latency_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        );
    }
}

fn set_alias<T: Into<praxis_policy_apl_core::AttributeValue> + Clone>(
    bag: &mut AttributeBag,
    canonical: &str,
    legacy: &str,
    value: T,
) {
    bag.set(canonical, value.clone());
    bag.set(legacy, value);
}

fn stop_reason_str(sr: StopReason) -> &'static str {
    match sr {
        StopReason::End => "end",
        StopReason::Return => "return",
        StopReason::Call => "call",
        StopReason::MaxTokens => "max_tokens",
        StopReason::StopSequence => "stop_sequence",
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
    use praxis_policy_core::extensions::completion::TokenUsage;

    #[test]
    fn stop_reason_serializes_as_snake_case_string() {
        let c = CompletionExtension {
            stop_reason: Some(StopReason::MaxTokens),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_completion(&c, &mut bag);
        assert_eq!(bag.get_string("completion.stop_reason"), Some("max_tokens"));
    }

    #[test]
    fn tokens_flatten_to_nested_ints() {
        let c = CompletionExtension {
            tokens: Some(TokenUsage {
                input_tokens: 100,
                output_tokens: 50,
                total_tokens: 150,
            }),
            latency_ms: Some(420),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_completion(&c, &mut bag);
        assert_eq!(bag.get_int("completion.tokens.input"), Some(100));
        assert_eq!(bag.get_int("completion.tokens.output"), Some(50));
        assert_eq!(bag.get_int("completion.tokens.total"), Some(150));
        assert_eq!(bag.get_int("completion.latency_ms"), Some(420));
    }

    #[test]
    fn all_output_aliases_equal_canonical_keys() {
        let c = CompletionExtension {
            stop_reason: Some(StopReason::End),
            tokens: Some(TokenUsage {
                input_tokens: 1,
                output_tokens: 2,
                total_tokens: 3,
            }),
            model: Some("gpt-4".into()),
            raw_format: Some("json".into()),
            created_at: Some("2026-01-01".into()),
            latency_ms: Some(42),
        };
        let mut bag = AttributeBag::new();
        extract_completion(&c, &mut bag);
        for suffix in [
            "stop_reason",
            "tokens.input",
            "tokens.output",
            "tokens.total",
            "model",
            "raw_format",
            "created_at",
            "latency_ms",
        ] {
            assert_eq!(
                bag.get(&format!("llm.output.{suffix}")),
                bag.get(&format!("completion.{suffix}"))
            );
        }
    }
}
