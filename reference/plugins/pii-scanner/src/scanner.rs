// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;

use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::config::{PiiPattern, PiiScanMode, PiiScannerConfig};

/// CMF plugin that walks the message's `ToolCall` / `PromptRequest` /
/// `ResourceRef` arguments and tests each string value against the
/// configured PII patterns.
#[derive(Debug)]
pub struct PiiScanner {
    cfg: PluginConfig,
    typed: PiiScannerConfig,
    /// Compiled regexes paired with the pattern name (for violation
    /// attribution). Compiled once at construction; matched per call.
    patterns: Vec<(String, Regex)>,
}

impl PiiScanner {
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the `config:` block is absent or does
    /// not deserialize into this plugin's settings, and when a validated field
    /// is out of range.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-pii-scanner) requires a `config:` block",
                    cfg.name
                ),
            })
        })?;
        let typed: PiiScannerConfig = serde_json::from_value(raw.clone()).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-pii-scanner) config parse failed: {e}",
                    cfg.name
                ),
            })
        })?;

        let patterns = compile_patterns(&typed.detect, &cfg.name)?;
        Ok(Self {
            cfg,
            typed,
            patterns,
        })
    }

    /// Scan every string value in the message's structured content
    /// (ToolCall.arguments, PromptRequest.arguments) plus any text
    /// parts. Returns the name of the first matching pattern, or
    /// `None` if no match. The pattern name flows into the violation
    /// code so audit logs say `pii.detected: ssn` rather than
    /// generic `pii.detected`.
    fn first_match(&self, message: &Message) -> Option<&str> {
        for part in &message.content {
            match part {
                ContentPart::ToolCall { content } => {
                    for v in content.arguments.values() {
                        if let Some(name) = self.match_value(v) {
                            return Some(name);
                        }
                    }
                },
                ContentPart::PromptRequest { content } => {
                    for v in content.arguments.values() {
                        if let Some(name) = self.match_value(v) {
                            return Some(name);
                        }
                    }
                },
                ContentPart::Text { text } => {
                    if let Some(name) = self.match_str(text) {
                        return Some(name);
                    }
                },
                _ => {}, // images / video / audio / etc. — out of scope for v0
            }
        }
        None
    }

    fn match_value(&self, v: &Value) -> Option<&str> {
        match v {
            Value::String(s) => self.match_str(s),
            // Numbers / bools can't carry PII patterns. Arrays /
            // objects could be walked recursively in a future
            // version; for now we only flag flat string fields,
            // which covers the common LLM tool-call shape.
            _ => None,
        }
    }

    fn match_str(&self, s: &str) -> Option<&str> {
        for (name, re) in &self.patterns {
            if re.is_match(s) {
                return Some(name);
            }
        }
        None
    }

    /// Rewrite the message's content: replace any string value that
    /// matches a pattern with `[PII]`. Used in `redact` mode.
    fn redact_message(&self, message: &mut Message) {
        for part in &mut message.content {
            match part {
                ContentPart::ToolCall { content } => {
                    for v in content.arguments.values_mut() {
                        self.redact_value(v);
                    }
                },
                ContentPart::PromptRequest { content } => {
                    for v in content.arguments.values_mut() {
                        self.redact_value(v);
                    }
                },
                ContentPart::Text { text } if self.match_str(text).is_some() => {
                    *text = "[PII]".to_owned();
                },
                _ => {},
            }
        }
    }

    fn redact_value(&self, v: &mut Value) {
        if let Value::String(s) = v
            && self.match_str(s).is_some()
        {
            *v = Value::String("[PII]".to_owned());
        }
    }
}

fn compile_patterns(
    patterns: &[PiiPattern],
    plugin_name: &str,
) -> Result<Vec<(String, Regex)>, Box<PluginError>> {
    let mut out = Vec::with_capacity(patterns.len());
    for p in patterns {
        let (name, re_str) = match p {
            PiiPattern::Ssn => ("ssn", r"\b\d{3}-\d{2}-\d{4}\b".to_owned()),
            PiiPattern::CreditCard => (
                "credit_card",
                // 13-19 digit sequences with optional spaces / hyphens
                // every 4 digits. Liberal — Luhn validation would
                // tighten this but isn't needed for the demo signal.
                r"\b(?:\d[ -]?){13,19}\b".to_owned(),
            ),
            PiiPattern::Email => (
                "email",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_owned(),
            ),
            PiiPattern::Custom { name, regex } => (name.as_str(), regex.clone()),
        };
        let re = Regex::new(&re_str).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{plugin_name}' (praxis-policy-plugin-pii-scanner): pattern '{name}' \
                     failed to compile: {e}"
                ),
            })
        })?;
        out.push((name.to_owned(), re));
    }
    Ok(out)
}

#[async_trait]
impl Plugin for PiiScanner {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for PiiScanner {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let hit = self.first_match(&payload.message);
        match (hit, self.typed.mode) {
            (None, _) => PluginResult::allow(),
            (Some(pattern_name), PiiScanMode::Deny) => PluginResult::deny(PluginViolation::new(
                "pii.detected",
                format!(
                    "PII pattern '{pattern_name}' detected in request \
                         args — refusing to forward to downstream"
                ),
            )),
            (Some(_), PiiScanMode::Redact) => {
                let mut updated = payload.clone();
                self.redact_message(&mut updated.message);
                PluginResult::modify_payload(updated)
            },
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_strings,
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
    use praxis_policy_core::cmf::{Role, ToolCall};
    use praxis_policy_core::plugin::{OnError, PluginMode};
    use serde_json::json;
    use std::collections::HashMap;

    fn cfg(detect: Vec<PiiPattern>, mode: PiiScanMode) -> PluginConfig {
        let cfg_json = serde_json::to_value(PiiScannerConfig { detect, mode }).unwrap();
        PluginConfig {
            name: "pii-scan".into(),
            kind: "test".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            mode: PluginMode::Sequential,
            priority: 10,
            on_error: OnError::Fail,
            config: Some(cfg_json),
            ..Default::default()
        }
    }

    fn message_with_args(args: HashMap<String, serde_json::Value>) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "1".into(),
                        name: "send_email".into(),
                        arguments: args,
                        namespace: None,
                    },
                }],
            ),
        }
    }

    /// The scanner walks prompt arguments on the same footing as tool-call
    /// arguments, so it needs its own fixture: operators wire this plugin on
    /// `cmf.prompt_pre_fetch` as well as `cmf.tool_pre_invoke`.
    fn message_with_prompt_args(args: HashMap<String, serde_json::Value>) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::PromptRequest {
                    content: praxis_policy_core::cmf::PromptRequest {
                        prompt_request_id: "1".into(),
                        name: "summarize".into(),
                        arguments: args,
                        server_id: None,
                    },
                }],
            ),
        }
    }

    fn message_with_text(text: &str) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::Text {
                    text: text.to_owned(),
                }],
            ),
        }
    }

    #[tokio::test]
    async fn ssn_in_args_denied() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny)).unwrap();
        let payload = message_with_args(HashMap::from([(
            "body".to_owned(),
            json!("Her SSN is 555-12-3456"),
        )]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing, "should deny");
        let v = r.violation.expect("violation present");
        assert_eq!(v.code, "pii.detected");
        assert!(v.reason.contains("ssn"));
    }

    #[tokio::test]
    async fn clean_args_allowed() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny)).unwrap();
        let payload = message_with_args(HashMap::from([(
            "body".to_owned(),
            json!("Quarterly compensation review summary."),
        )]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(r.continue_processing);
        assert!(r.modified_payload.is_none());
    }

    #[tokio::test]
    async fn redact_mode_rewrites_value() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Redact)).unwrap();
        let payload = message_with_args(HashMap::from([
            ("body".to_owned(), json!("555-12-3456")),
            ("subject".to_owned(), json!("payroll question")),
        ]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(r.continue_processing, "redact allows; doesn't deny");
        let modified = r.modified_payload.expect("payload was modified");
        let args = match &modified.message.content[0] {
            ContentPart::ToolCall { content } => &content.arguments,
            _ => panic!("expected ToolCall"),
        };
        assert_eq!(args["body"], json!("[PII]"));
        // Untouched fields preserved.
        assert_eq!(args["subject"], json!("payroll question"));
    }

    #[tokio::test]
    async fn custom_pattern() {
        let p = PiiScanner::new(cfg(
            vec![PiiPattern::Custom {
                name: "internal_id".into(),
                regex: r"^INT-[A-Z0-9]{6}$".into(),
            }],
            PiiScanMode::Deny,
        ))
        .unwrap();
        let payload = message_with_args(HashMap::from([("ref".to_owned(), json!("INT-ABC123"))]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing);
        let v = r.violation.expect("violation present");
        assert!(v.reason.contains("internal_id"));
    }

    /// `default_detect()` ships `[Ssn, CreditCard]`, but every test above passes
    /// an explicit list, so the credit-card branch of `compile_patterns` had
    /// never been compiled, let alone matched.
    #[tokio::test]
    async fn credit_card_is_detected() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::CreditCard], PiiScanMode::Deny)).unwrap();
        let payload = message_with_args(HashMap::from([(
            "card".to_owned(),
            json!("4111 1111 1111 1111"),
        )]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing, "a card number should deny");
        let v = r.violation.expect("violation present");
        assert!(
            v.reason.contains("credit_card"),
            "the pattern name flows into the reason: {}",
            v.reason
        );
    }

    #[tokio::test]
    async fn email_is_detected() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Email], PiiScanMode::Deny)).unwrap();
        let payload = message_with_args(HashMap::from([(
            "to".to_owned(),
            json!("alice@example.com"),
        )]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing, "an address should deny");
        let v = r.violation.expect("violation present");
        assert!(v.reason.contains("email"), "reason: {}", v.reason);
    }

    /// A custom pattern that does not compile has to be refused at load time.
    /// Accepting it would leave the scanner running with one fewer pattern than
    /// the operator configured, and nothing would say so.
    #[test]
    fn an_uncompilable_custom_pattern_is_rejected() {
        let bad = cfg(
            vec![PiiPattern::Custom {
                name: "broken".into(),
                regex: "([unclosed".into(),
            }],
            PiiScanMode::Deny,
        );
        let err = PiiScanner::new(bad).expect_err("a malformed regex must not build");
        let msg = err.to_string();
        assert!(
            msg.contains("broken") && msg.contains("failed to compile"),
            "the message must name the offending pattern: {msg}"
        );
    }

    #[test]
    fn a_missing_config_block_is_rejected() {
        let mut c = cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny);
        c.config = None;
        let err = PiiScanner::new(c).expect_err("no config block must not build");
        assert!(
            err.to_string().contains("`config:`"),
            "the message must name the missing block: {err}"
        );
    }

    #[test]
    fn a_config_block_of_the_wrong_shape_is_rejected() {
        let mut c = cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny);
        c.config = Some(json!({ "detect": "not-a-list" }));
        let err = PiiScanner::new(c).expect_err("a malformed config must not build");
        assert!(
            err.to_string().contains("parse failed"),
            "the message must say the config did not parse: {err}"
        );
    }

    /// Prompt arguments are scanned on the same footing as tool-call arguments.
    #[tokio::test]
    async fn ssn_in_prompt_args_denied() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny)).unwrap();
        let payload = message_with_prompt_args(HashMap::from([(
            "subject".to_owned(),
            json!("SSN 555-12-3456"),
        )]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing, "prompt args must be scanned too");
    }

    #[tokio::test]
    async fn ssn_in_a_text_part_denied() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny)).unwrap();
        let payload = message_with_text("my ssn is 555-12-3456");
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing, "text parts must be scanned too");
    }

    /// Redaction has to reach prompt arguments and text parts, not only tool
    /// calls, or a redact-mode deployment would forward PII from those shapes.
    #[tokio::test]
    async fn redact_mode_rewrites_prompt_args_and_text() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Redact)).unwrap();

        let payload = message_with_prompt_args(HashMap::from([
            ("subject".to_owned(), json!("SSN 555-12-3456")),
            ("keep".to_owned(), json!("nothing sensitive")),
        ]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        let updated = r
            .modified_payload
            .expect("redact mode returns a modified payload");
        let ContentPart::PromptRequest { content } = &updated.message.content[0] else {
            panic!("expected the prompt part back");
        };
        assert_eq!(
            content.arguments["subject"],
            json!("[PII]"),
            "match redacted"
        );
        assert_eq!(
            content.arguments["keep"],
            json!("nothing sensitive"),
            "a non-matching value must be left alone"
        );

        let payload = message_with_text("my ssn is 555-12-3456");
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        let updated = r
            .modified_payload
            .expect("redact mode returns a modified payload");
        let ContentPart::Text { text } = &updated.message.content[0] else {
            panic!("expected the text part back");
        };
        assert_eq!(text, "[PII]", "a matching text part is replaced wholesale");
    }

    /// Non-string argument values cannot carry a pattern and must not be
    /// mistaken for a match or rewritten.
    #[tokio::test]
    async fn non_string_argument_values_are_ignored() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Redact)).unwrap();
        let payload = message_with_args(HashMap::from([
            ("count".to_owned(), json!(42)),
            ("flag".to_owned(), json!(true)),
            ("list".to_owned(), json!(["555-12-3456"])),
            ("nested".to_owned(), json!({ "ssn": "555-12-3456" })),
        ]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(
            r.continue_processing,
            "flat-string scanning only, so nothing here matches"
        );
        assert!(
            r.modified_payload.is_none(),
            "no match means no rewrite, not an unchanged copy"
        );
    }

    /// Content kinds the scanner does not inspect must pass through rather than
    /// error or match.
    #[tokio::test]
    async fn unscanned_content_kinds_pass_through() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny)).unwrap();
        let payload = MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::Image {
                    content: praxis_policy_core::cmf::ImageSource {
                        source_type: "base64".into(),
                        data: "AAAA".into(),
                        media_type: Some("image/png".into()),
                    },
                }],
            ),
        };
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(
            r.continue_processing,
            "an image is out of scope, not a deny"
        );
    }
}
