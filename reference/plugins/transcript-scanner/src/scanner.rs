// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;

use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::config::{TranscriptPattern, TranscriptScannerConfig};

/// Capability the scanner cannot work without: the agent extension, and the
/// history on it, is filtered out of a plugin's view unless it is declared.
const READ_AGENT: &str = "read_agent";

/// The first pattern found in history, and where.
#[derive(Debug, PartialEq, Eq)]
struct Hit<'a> {
    pattern: &'a str,
    turn: usize,
    role: Role,
}

/// CMF plugin that walks `AgentExtension.conversation.history` and tests each
/// string a turn holds against the configured patterns.
///
/// Per turn it reads text and reasoning parts, tool-call and prompt arguments,
/// and tool-result content. Argument and result values are walked through
/// nested arrays and objects, so a secret one level down in a tool result is
/// still found.
#[derive(Debug)]
pub struct TranscriptScanner {
    cfg: PluginConfig,
    roles: Vec<Role>,
    /// Compiled regexes paired with the pattern name for the violation.
    patterns: Vec<(String, Regex)>,
}

impl TranscriptScanner {
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the `config:` block is absent or does
    /// not deserialize, when it lists no patterns, when a pattern does not
    /// compile, and when the plugin does not declare `read_agent`.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let config_err = |detail: String| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-transcript-scanner) {detail}",
                    cfg.name
                ),
            })
        };

        let raw = cfg
            .config
            .as_ref()
            .ok_or_else(|| config_err("requires a `config:` block".to_owned()))?;
        let typed: TranscriptScannerConfig = serde_json::from_value(raw.clone())
            .map_err(|e| config_err(format!("config parse failed: {e}")))?;
        if typed.patterns.is_empty() {
            return Err(config_err(
                "`patterns:` must list at least one pattern".to_owned(),
            ));
        }
        // Without the capability the history is always empty in this plugin's
        // view, so every request would pass as scanned and clean.
        if !cfg.capabilities.contains(READ_AGENT) {
            return Err(config_err(format!(
                "must declare `capabilities: [{READ_AGENT}]`; without it the \
                 conversation history is filtered out and nothing is scanned"
            )));
        }
        let patterns = compile_patterns(&typed.patterns).map_err(config_err)?;

        Ok(Self {
            cfg,
            roles: typed.roles,
            patterns,
        })
    }

    /// The first match in history, oldest turn first.
    fn first_match<'a>(&'a self, history: &[Message]) -> Option<Hit<'a>> {
        history
            .iter()
            .enumerate()
            .filter(|(_, turn)| self.roles.is_empty() || self.roles.contains(&turn.role))
            .find_map(|(i, turn)| {
                self.match_turn(turn).map(|pattern| Hit {
                    pattern,
                    turn: i,
                    role: turn.role,
                })
            })
    }

    fn match_turn(&self, turn: &Message) -> Option<&str> {
        turn.content.iter().find_map(|part| match part {
            ContentPart::Text { text } | ContentPart::Thinking { text } => self.match_str(text),
            ContentPart::ToolCall { content } => {
                content.arguments.values().find_map(|v| self.match_value(v))
            },
            ContentPart::PromptRequest { content } => {
                content.arguments.values().find_map(|v| self.match_value(v))
            },
            ContentPart::ToolResult { content } => self.match_value(&content.content),
            // Media and resource parts carry no scannable text of their own.
            _ => None,
        })
    }

    /// Walks nested arrays and objects. Depth is bounded by `serde_json`'s
    /// own recursion limit on whatever produced the value.
    fn match_value(&self, v: &Value) -> Option<&str> {
        match v {
            Value::String(s) => self.match_str(s),
            Value::Array(items) => items.iter().find_map(|i| self.match_value(i)),
            Value::Object(map) => map.values().find_map(|i| self.match_value(i)),
            Value::Null | Value::Bool(_) | Value::Number(_) => None,
        }
    }

    fn match_str(&self, s: &str) -> Option<&str> {
        self.patterns
            .iter()
            .find(|(_, re)| re.is_match(s))
            .map(|(name, _)| name.as_str())
    }
}

fn compile_patterns(patterns: &[TranscriptPattern]) -> Result<Vec<(String, Regex)>, String> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(&p.regex)
                .map(|re| (p.name.clone(), re))
                .map_err(|e| format!("pattern '{}' failed to compile: {e}", p.name))
        })
        .collect()
}

#[async_trait]
impl Plugin for TranscriptScanner {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for TranscriptScanner {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let history = ext
            .agent
            .as_deref()
            .and_then(|a| a.conversation.as_ref())
            .map_or(&[][..], |c| c.history.as_slice());

        match self.first_match(history) {
            None => PluginResult::allow(),
            // The reason names the pattern and the turn, never the matched
            // text: the violation is logged and may be returned to the caller.
            Some(hit) => PluginResult::deny(PluginViolation::new(
                "transcript.detected",
                format!(
                    "pattern '{}' matched in conversation history turn {} ({:?})",
                    hit.pattern, hit.turn, hit.role
                ),
            )),
        }
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
    use praxis_policy_core::cmf::{ToolCall, ToolResult};
    use praxis_policy_core::extensions::{AgentExtension, ConversationContext};
    use praxis_policy_core::plugin::{OnError, PluginMode};
    use serde_json::json;
    use std::sync::Arc;

    const SECRET: &str = "sk-live0123456789";

    fn cfg_with(config: Value, capabilities: &[&str]) -> PluginConfig {
        PluginConfig {
            name: "transcript-scan".into(),
            kind: "test".into(),
            hooks: vec!["cmf.llm_input".into()],
            mode: PluginMode::Sequential,
            priority: 10,
            on_error: OnError::Fail,
            capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
            config: Some(config),
            ..Default::default()
        }
    }

    fn scanner(roles: &[&str]) -> TranscriptScanner {
        TranscriptScanner::new(cfg_with(
            json!({
                "patterns": [{ "name": "api_key", "regex": "sk-[A-Za-z0-9]{8,}" }],
                "roles": roles,
            }),
            &[READ_AGENT],
        ))
        .unwrap()
    }

    fn ext_with_history(history: Vec<Message>) -> Extensions {
        Extensions {
            agent: Some(Arc::new(AgentExtension {
                conversation: Some(ConversationContext {
                    history,
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn payload(text: &str) -> MessagePayload {
        MessagePayload {
            message: Message::text(Role::User, text),
        }
    }

    async fn run(
        s: &TranscriptScanner,
        p: &MessagePayload,
        ext: &Extensions,
    ) -> PluginResult<MessagePayload> {
        s.handle(p, ext, &mut PluginContext::default()).await
    }

    #[tokio::test]
    async fn a_match_in_a_prior_turn_denies_and_names_the_turn() {
        let ext = ext_with_history(vec![
            Message::text(Role::User, "hello"),
            Message::text(Role::User, format!("my key is {SECRET}")),
        ]);
        let r = run(&scanner(&[]), &payload("what next?"), &ext).await;

        assert!(!r.continue_processing, "should deny");
        let v = r.violation.expect("violation present");
        assert_eq!(v.code, "transcript.detected");
        assert!(
            v.reason.contains("api_key"),
            "names the pattern: {}",
            v.reason
        );
        assert!(v.reason.contains("turn 1"), "names the turn: {}", v.reason);
        assert!(
            !v.reason.contains(SECRET),
            "the matched text must not be echoed into the violation"
        );
    }

    #[tokio::test]
    async fn clean_history_is_allowed() {
        let ext = ext_with_history(vec![Message::text(Role::User, "hello")]);
        let r = run(&scanner(&[]), &payload("hi"), &ext).await;
        assert!(r.continue_processing);
        assert!(r.violation.is_none());
    }

    /// The current turn is the payload, which is `pii-scanner`'s job. Scanning
    /// it here too would make this plugin's contract depend on where it is
    /// wired, since the payload of a post hook is the response.
    #[tokio::test]
    async fn the_current_turn_is_not_scanned() {
        let ext = ext_with_history(vec![Message::text(Role::User, "hello")]);
        let r = run(&scanner(&[]), &payload(SECRET), &ext).await;
        assert!(r.continue_processing, "history only");
    }

    #[tokio::test]
    async fn nested_tool_arguments_and_results_are_scanned() {
        let call = Message::with_content(
            Role::Assistant,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc".into(),
                    name: "configure".into(),
                    arguments: [("auth".to_owned(), json!({ "headers": [SECRET] }))].into(),
                    namespace: None,
                },
            }],
        );
        let r = run(&scanner(&[]), &payload("hi"), &ext_with_history(vec![call])).await;
        assert!(!r.continue_processing, "a nested tool argument is scanned");

        let result = Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "tc".into(),
                    tool_name: "read_env".into(),
                    content: json!({ "env": { "KEY": SECRET } }),
                    is_error: false,
                },
            }],
        );
        let r = run(
            &scanner(&[]),
            &payload("hi"),
            &ext_with_history(vec![result]),
        )
        .await;
        assert!(!r.continue_processing, "a nested tool result is scanned");
    }

    #[tokio::test]
    async fn reasoning_parts_are_scanned() {
        let turn = Message::with_content(
            Role::Assistant,
            vec![ContentPart::Thinking {
                text: format!("the user pasted {SECRET}"),
            }],
        );
        let r = run(&scanner(&[]), &payload("hi"), &ext_with_history(vec![turn])).await;
        assert!(!r.continue_processing);
    }

    #[tokio::test]
    async fn only_the_configured_roles_are_scanned() {
        let history = vec![
            Message::text(Role::Assistant, SECRET),
            Message::text(Role::User, "hello"),
        ];
        let r = run(
            &scanner(&["user"]),
            &payload("hi"),
            &ext_with_history(history.clone()),
        )
        .await;
        assert!(r.continue_processing, "the assistant turn is out of scope");

        let r = run(
            &scanner(&["assistant"]),
            &payload("hi"),
            &ext_with_history(history),
        )
        .await;
        assert!(!r.continue_processing, "and in scope when listed");
    }

    /// A request that carries no agent extension, or one with no
    /// conversation, has no history to scan. That is an allow: the scanner
    /// cannot tell a host that sends no history from a fresh conversation.
    #[tokio::test]
    async fn no_history_is_allowed() {
        let s = scanner(&[]);
        let r = run(&s, &payload("hi"), &Extensions::default()).await;
        assert!(r.continue_processing, "no agent extension");

        let ext = Extensions {
            agent: Some(Arc::new(AgentExtension::default())),
            ..Default::default()
        };
        let r = run(&s, &payload("hi"), &ext).await;
        assert!(r.continue_processing, "no conversation");
    }

    #[test]
    fn first_match_reports_the_earliest_turn() {
        let s = scanner(&[]);
        let history = vec![
            Message::text(Role::User, "hello"),
            Message::text(Role::Tool, SECRET),
            Message::text(Role::User, SECRET),
        ];
        assert_eq!(
            s.first_match(&history),
            Some(Hit {
                pattern: "api_key",
                turn: 1,
                role: Role::Tool,
            })
        );
    }

    #[test]
    fn a_missing_read_agent_capability_is_rejected() {
        let err = TranscriptScanner::new(cfg_with(
            json!({ "patterns": [{ "name": "x", "regex": "x" }] }),
            &[],
        ))
        .expect_err("a scanner that cannot see history must not build");
        assert!(err.to_string().contains(READ_AGENT), "{err}");
    }

    #[test]
    fn an_empty_pattern_list_is_rejected() {
        let err = TranscriptScanner::new(cfg_with(json!({ "patterns": [] }), &[READ_AGENT]))
            .expect_err("no patterns must not build");
        assert!(err.to_string().contains("patterns:"), "{err}");
    }

    #[test]
    fn an_uncompilable_pattern_is_rejected() {
        let err = TranscriptScanner::new(cfg_with(
            json!({ "patterns": [{ "name": "broken", "regex": "([unclosed" }] }),
            &[READ_AGENT],
        ))
        .expect_err("a malformed regex must not build");
        let msg = err.to_string();
        assert!(
            msg.contains("broken") && msg.contains("failed to compile"),
            "{msg}"
        );
    }

    #[test]
    fn a_missing_or_malformed_config_block_is_rejected() {
        let mut c = cfg_with(json!({}), &[READ_AGENT]);
        c.config = None;
        let err = TranscriptScanner::new(c).expect_err("no config block must not build");
        assert!(err.to_string().contains("`config:`"), "{err}");

        let err = TranscriptScanner::new(cfg_with(json!({ "patterns": "x" }), &[READ_AGENT]))
            .expect_err("a malformed config must not build");
        assert!(err.to_string().contains("parse failed"), "{err}");
    }
}
