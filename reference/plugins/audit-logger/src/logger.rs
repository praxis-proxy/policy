// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use praxis_policy_core::cmf::{CmfHook, ContentPart, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::config::{AuditDestination, AuditLoggerConfig};

/// Observation-only CMF plugin. Builds a structured audit record
/// from the request's `MessagePayload` + Extensions, emits to the
/// configured destination, returns `Allow`. Never blocks.
#[derive(Debug)]
pub struct AuditLogger {
    cfg: PluginConfig,
    typed: AuditLoggerConfig,
}

impl AuditLogger {
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the `config:` block is absent or does
    /// not deserialize into this plugin's settings, and when a validated field
    /// is out of range.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let typed: AuditLoggerConfig = match cfg.config.as_ref() {
            Some(raw) => serde_json::from_value(raw.clone()).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (praxis-policy-plugin-audit-logger) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?,
            None => AuditLoggerConfig::default(),
        };
        Ok(Self { cfg, typed })
    }

    fn build_record(&self, payload: &MessagePayload, ext: &Extensions) -> Value {
        let mut record = Map::new();
        record.insert(
            "ts".into(),
            json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        );
        record.insert("plugin".into(), json!(self.cfg.name));
        if let Some(src) = &self.typed.source {
            record.insert("source".into(), json!(src));
        }

        // Subject — capability-filtered. Empty Subject means the
        // plugin lacks `read_subject` cap (won't happen if the
        // operator configured it correctly).
        if let Some(sec) = ext.security.as_ref() {
            if let Some(s) = &sec.subject {
                record.insert(
                    "subject".into(),
                    json!({
                        "id": s.id,
                        "roles": s.roles.iter().collect::<Vec<_>>(),
                        "teams": s.teams.iter().collect::<Vec<_>>(),
                    }),
                );
            }
            if let Some(c) = &sec.client {
                record.insert(
                    "client".into(),
                    json!({
                        "client_id": c.client_id,
                        "client_name": c.client_name,
                    }),
                );
            }
        }

        // Entity — the route's tool/prompt/resource coords.
        if let Some(meta) = ext.meta.as_ref() {
            record.insert(
                "entity".into(),
                json!({
                    "type": meta.entity_type,
                    "name": meta.entity_name,
                }),
            );
        }

        // Tool / prompt args summary — the first structured
        // content part's args, if any. Mirrors what the gateway
        // would actually forward (so audit reflects post-redact
        // state if a PII scanner ran ahead of us).
        for part in &payload.message.content {
            match part {
                ContentPart::ToolCall { content } => {
                    record.insert(
                        "tool_call".into(),
                        json!({
                            "name": content.name,
                            "tool_call_id": content.tool_call_id,
                            "args": content.arguments,
                        }),
                    );
                    break;
                },
                ContentPart::PromptRequest { content } => {
                    record.insert(
                        "prompt_request".into(),
                        json!({
                            "name": content.name,
                            "args": content.arguments,
                        }),
                    );
                    break;
                },
                _ => {},
            }
        }

        // Delegation outcomes — which audiences got tokens, with
        // what (effective, possibly narrowed) scopes. The whole
        // point of including this: it makes the audit trail show
        // "we exchanged for workday-api with scope=read_compensation",
        // which is the proof that delegation enforcement happened.
        if let Some(raw) = ext.raw_credentials.as_ref()
            && !raw.delegated_tokens.is_empty()
        {
            let tokens: Vec<Value> = raw
                .delegated_tokens
                .values()
                .map(|tok| {
                    json!({
                        "audience": tok.audience,
                        "scopes": tok.scopes,
                        "outbound_header": tok.outbound_header,
                        "expires_at": tok.expires_at.to_rfc3339_opts(
                            chrono::SecondsFormat::Secs, true,
                        ),
                    })
                })
                .collect();
            record.insert("delegated_tokens".into(), json!(tokens));
        }

        Value::Object(record)
    }

    #[allow(
        clippy::field_reassign_with_default,
        clippy::print_stderr,
        reason = "writing the audit record to stderr is what AuditDestination::Stderr \
                  selects; the operator asked for this stream by name"
    )]
    fn emit(&self, record: &Value) {
        match self.typed.destination {
            AuditDestination::Stderr => {
                // One JSON line — easy to grep / forward / jq through.
                eprintln!("{record}");
            },
            AuditDestination::Tracing => {
                tracing::info!(target: "apl.audit", record = %record, "audit");
            },
        }
    }
}

#[async_trait]
impl Plugin for AuditLogger {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AuditLogger {
    async fn handle(
        &self,
        payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let record = self.build_record(payload, ext);
        self.emit(&record);
        PluginResult::allow()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::cmf::{Message, Role, ToolCall};
    use praxis_policy_core::extensions::{MetaExtension, SecurityExtension, SubjectExtension};
    use praxis_policy_core::plugin::{OnError, PluginMode};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn cfg() -> PluginConfig {
        PluginConfig {
            name: "audit".into(),
            kind: "test".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            mode: PluginMode::Sequential,
            priority: 50,
            on_error: OnError::Fail,
            config: Some(serde_json::json!({ "destination": "stderr" })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn build_record_includes_subject_entity_toolcall() {
        let plugin = AuditLogger::new(cfg()).unwrap();
        let payload = MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "1".into(),
                        name: "get_compensation".into(),
                        arguments: HashMap::from([(
                            "employee_id".to_owned(),
                            serde_json::json!("EMP-001234"),
                        )]),
                        namespace: None,
                    },
                }],
            ),
        };
        let mut sec = SecurityExtension::default();
        sec.subject = Some(SubjectExtension {
            id: Some("alice@corp.com".into()),
            ..Default::default()
        });
        let mut meta = MetaExtension::default();
        meta.entity_type = Some("tool".into());
        meta.entity_name = Some("get_compensation".into());
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            meta: Some(Arc::new(meta)),
            ..Default::default()
        };

        let record = plugin.build_record(&payload, &ext);
        assert_eq!(record["subject"]["id"], "alice@corp.com");
        assert_eq!(record["entity"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["args"]["employee_id"], "EMP-001234");
        // Always-allow contract: handler returns continue_processing.
        let mut ctx = PluginContext::default();
        let r = plugin.handle(&payload, &ext, &mut ctx).await;
        assert!(r.continue_processing);
        assert!(r.violation.is_none());
    }

    /// The delegation block is the reason this plugin exists in a delegating
    /// deployment: it is the evidence that an exchange happened and with what
    /// narrowed scopes. It had no test.
    #[test]
    fn delegated_tokens_are_recorded_with_audience_scopes_header_and_expiry() {
        use praxis_policy_core::extensions::raw_credentials::{
            DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken,
        };

        let plugin = AuditLogger::new(cfg()).unwrap();
        let expires_at = chrono::DateTime::parse_from_rfc3339("2026-08-11T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let token = RawDelegatedToken::new(
            "minted-jwt",
            "Authorization",
            "workday-api",
            vec!["read_compensation".to_owned()],
            expires_at,
        );
        let key = DelegationKey::new(
            DelegationMode::OnBehalfOfUser,
            "workday-api",
            vec!["read_compensation".to_owned()],
        );
        let mut raw = RawCredentialsExtension::default();
        raw.delegated_tokens.insert(key, token);
        let ext = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let record = plugin.build_record(&empty_payload(), &ext);
        let tokens = record["delegated_tokens"]
            .as_array()
            .expect("delegated_tokens must be an array");
        assert_eq!(tokens.len(), 1, "one exchange, one entry");
        assert_eq!(tokens[0]["audience"], "workday-api");
        assert_eq!(tokens[0]["scopes"][0], "read_compensation");
        assert_eq!(tokens[0]["outbound_header"], "Authorization");
        assert_eq!(
            tokens[0]["expires_at"], "2026-08-11T12:00:00Z",
            "the expiry is recorded to second precision"
        );
        assert!(
            !record.to_string().contains("minted-jwt"),
            "the audit record must describe the token, never carry it"
        );
    }

    /// An empty delegation map must not emit an empty array: a reader would not
    /// be able to tell "no exchange happened" from "the field is always there".
    #[test]
    fn no_delegation_means_no_delegated_tokens_key() {
        use praxis_policy_core::extensions::raw_credentials::RawCredentialsExtension;

        let plugin = AuditLogger::new(cfg()).unwrap();
        let ext = Extensions {
            raw_credentials: Some(Arc::new(RawCredentialsExtension::default())),
            ..Default::default()
        };
        let record = plugin.build_record(&empty_payload(), &ext);
        assert!(
            record.get("delegated_tokens").is_none(),
            "absence, not an empty array"
        );
    }

    #[test]
    fn client_identity_is_recorded_when_the_caller_is_a_client() {
        use praxis_policy_core::extensions::ClientExtension;

        let plugin = AuditLogger::new(cfg()).unwrap();
        let mut sec = SecurityExtension::default();
        sec.client = Some(ClientExtension {
            client_id: "svc-billing".into(),
            client_name: Some("Billing Service".into()),
            ..Default::default()
        });
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        };
        let record = plugin.build_record(&empty_payload(), &ext);
        assert_eq!(record["client"]["client_id"], "svc-billing");
        assert_eq!(record["client"]["client_name"], "Billing Service");
    }

    /// Prompt traffic has to be audited too, and it lands in its own key rather
    /// than being flattened into `tool_call`.
    #[test]
    fn a_prompt_request_is_recorded_under_its_own_key() {
        let plugin = AuditLogger::new(cfg()).unwrap();
        let payload = MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::PromptRequest {
                    content: praxis_policy_core::cmf::PromptRequest {
                        prompt_request_id: "1".into(),
                        name: "summarize".into(),
                        arguments: HashMap::from([(
                            "doc".to_owned(),
                            serde_json::json!("q3-report"),
                        )]),
                        server_id: None,
                    },
                }],
            ),
        };
        let record = plugin.build_record(&payload, &Extensions::default());
        assert_eq!(record["prompt_request"]["name"], "summarize");
        assert_eq!(record["prompt_request"]["args"]["doc"], "q3-report");
        assert!(
            record.get("tool_call").is_none(),
            "a prompt must not be recorded as a tool call"
        );
    }

    /// `source` is how an operator tags which gateway produced a record when
    /// several forward to one log sink. The existing config never set it.
    #[test]
    fn a_configured_source_is_stamped_on_every_record() {
        let mut c = cfg();
        c.config = Some(serde_json::json!({
            "destination": "stderr",
            "source": "edge-gateway-1",
        }));
        let plugin = AuditLogger::new(c).unwrap();
        let record = plugin.build_record(&empty_payload(), &Extensions::default());
        assert_eq!(record["source"], "edge-gateway-1");
    }

    /// With no `config:` block at all the plugin takes its defaults rather than
    /// failing, so an operator can wire it with just `kind:` and `hooks:`.
    #[test]
    fn an_absent_config_block_falls_back_to_defaults() {
        let mut c = cfg();
        c.config = None;
        let plugin = AuditLogger::new(c).expect("no config block must still build");
        let record = plugin.build_record(&empty_payload(), &Extensions::default());
        assert!(
            record.get("source").is_none(),
            "the default carries no source tag"
        );
    }

    #[test]
    fn a_config_block_of_the_wrong_shape_is_rejected() {
        let mut c = cfg();
        c.config = Some(serde_json::json!({ "destination": "carrier-pigeon" }));
        let err = AuditLogger::new(c).expect_err("an unknown destination must not build");
        assert!(
            err.to_string().contains("parse failed"),
            "the message must say the config did not parse: {err}"
        );
    }

    /// The tracing destination had never been selected by a test, so the arm
    /// that routes a record to the subscriber instead of stderr never ran.
    #[tokio::test]
    async fn the_tracing_destination_emits_without_a_subscriber() {
        let mut c = cfg();
        c.config = Some(serde_json::json!({ "destination": "tracing" }));
        let plugin = AuditLogger::new(c).unwrap();
        let mut ctx = PluginContext::default();
        let r = plugin
            .handle(&empty_payload(), &Extensions::default(), &mut ctx)
            .await;
        assert!(
            r.continue_processing,
            "auditing never blocks, whatever the destination"
        );
    }

    /// A record is built even with nothing to describe, so the timestamp and
    /// plugin name are always present for correlation.
    #[test]
    fn a_bare_record_still_carries_a_timestamp_and_the_plugin_name() {
        let plugin = AuditLogger::new(cfg()).unwrap();
        let record = plugin.build_record(&empty_payload(), &Extensions::default());
        assert_eq!(record["plugin"], "audit");
        assert!(
            record["ts"].as_str().is_some_and(|s| s.ends_with('Z')),
            "an RFC 3339 UTC timestamp: {}",
            record["ts"]
        );
    }

    fn empty_payload() -> MessagePayload {
        MessagePayload {
            message: Message::with_content(Role::User, vec![]),
        }
    }
}
