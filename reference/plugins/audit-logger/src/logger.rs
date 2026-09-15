// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use praxis_policy_core::audit::AuditHandler;
use praxis_policy_core::cmf::{CmfHook, ContentPart, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::decision::{DecisionLog, PluginAction, Verdict};
use praxis_policy_core::effect::EffectRecord;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::payload::{Extensions, PluginPayload};
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

    fn build_record(&self, payload: Option<&MessagePayload>, ext: &Extensions) -> Value {
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
        for part in payload.iter().flat_map(|p| p.message.content.iter()) {
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

    /// Attach as a decision sink when no `hooks:` are listed. With hooks
    /// listed the logger runs as a CMF post-hook observer instead, so a
    /// request does not produce two records from the same instance.
    fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
        if !self.cfg.hooks.is_empty() {
            return None;
        }
        Some(self)
    }
}

impl AuditLogger {
    /// The effect record: the request's ambient context plus the act itself.
    ///
    /// Emitted as its own event rather than folded into the decision, because
    /// an effect happened to the outside world and outlives the request that
    /// caused it. The ambient fields are what let a reader tie the two back
    /// together.
    fn build_effect_record(&self, effect: &EffectRecord, ext: &Extensions) -> Value {
        let mut record = match self.build_record(None, ext) {
            Value::Object(map) => map,
            // `build_record` always returns an object. Anything else means no
            // ambient context, which is not a reason to drop the effect.
            _ => Map::new(),
        };
        record.insert("event".into(), json!("effect"));
        record.insert("effect_kind".into(), json!(effect.kind));
        record.insert("effect_state".into(), json!(effect.state));
        record.insert("effect_key".into(), json!(effect.key));
        record.insert("effect_description".into(), json!(effect.description));
        if let Some(plugin) = &effect.plugin_name {
            record.insert("effect_plugin".into(), json!(plugin));
        }
        if !effect.details.is_empty() {
            record.insert("effect_details".into(), json!(effect.details));
        }
        if let Some(stream_seq) = effect.stream_seq {
            record.insert("epoch".into(), json!(effect.epoch));
            record.insert("stream_id".into(), json!(effect.stream_id));
            record.insert("stream_seq".into(), json!(stream_seq));
            record.insert("emission_seq".into(), json!(effect.emission_seq));
        }
        Value::Object(record)
    }

    /// The decision record: the observation record's fields plus the
    /// pipeline's verdict and the ordered plugin actions.
    ///
    /// `payload` is present only when the dispatch carried a CMF
    /// `MessagePayload`; sinks fire for every hook family.
    fn build_decision_record(
        &self,
        payload: Option<&MessagePayload>,
        ext: &Extensions,
        decisions: &DecisionLog,
    ) -> Value {
        let mut record = self.build_record(payload, ext);
        if let Value::Object(map) = &mut record {
            let verdict = match decisions.verdict() {
                Some(Verdict::Allow) => json!("allow"),
                Some(Verdict::Deny(v)) => json!({ "deny": violation_json(v) }),
                None => json!("pending"),
            };
            map.insert("verdict".into(), verdict);

            let steps: Vec<Value> = decisions
                .steps()
                .iter()
                .map(|s| {
                    let mut step = Map::new();
                    step.insert("plugin".into(), json!(s.plugin_name));
                    step.insert("phase".into(), json!(format!("{:?}", s.phase)));
                    let (action, detail) = match &s.action {
                        PluginAction::Allowed => ("allowed", None),
                        PluginAction::Denied(v) => ("denied", Some(violation_json(v))),
                        // Suppressed, so no verdict names it. Without the
                        // violation here the objection leaves no trace at all.
                        PluginAction::DenyIgnored(v) => ("deny_ignored", Some(violation_json(v))),
                        PluginAction::ModifiedPayload => ("modified_payload", None),
                        PluginAction::ModifiedExtensions => ("modified_extensions", None),
                        PluginAction::Aborted => ("aborted", None),
                        PluginAction::Error(e) => ("error", Some(json!({ "message": e }))),
                    };
                    step.insert("action".into(), json!(action));
                    if let Some(detail) = detail {
                        step.insert("detail".into(), detail);
                    }
                    Value::Object(step)
                })
                .collect();
            map.insert("decision_steps".into(), json!(steps));

            // This invocation's place in the decision graph: its own span, the
            // upstream call that triggered it, and the trace they share.
            if let Some(span) = decisions.span() {
                map.insert(
                    "span".into(),
                    json!({
                        "trace_id": span.trace_id,
                        "span_id": span.span_id,
                        "parent_span_id": span.parent_span_id,
                    }),
                );
            }

            // Taint: the labels the request arrived with against the labels it
            // leaves with. The difference is what this node added.
            let input_labels: Vec<&String> = decisions.input_labels().iter().collect();
            let final_labels: Vec<String> = ext
                .security
                .as_ref()
                .map(|s| {
                    let mut l: Vec<String> = s.labels.iter().cloned().collect();
                    l.sort_unstable();
                    l
                })
                .unwrap_or_default();
            if !input_labels.is_empty() || !final_labels.is_empty() {
                map.insert(
                    "taint".into(),
                    json!({ "input": input_labels, "final": final_labels }),
                );
            }

            // Content: the hash at entry and this node's output hash, so a
            // reader can tell whether a stage changed the payload. Gated on
            // the input hash, which is absent unless an operator enabled
            // provenance. Digests only, never content.
            // Stream identity and the two counters. `stream_seq` is gap-free
            // within its stream, so a consumer can prove nothing was dropped;
            // `emission_seq` is shared with the effect stream, so the two can
            // be merged back into the order they happened.
            if let Some(stream_seq) = decisions.stream_seq() {
                map.insert("epoch".into(), json!(decisions.epoch()));
                map.insert("stream_id".into(), json!(decisions.stream_id()));
                map.insert("stream_seq".into(), json!(stream_seq));
                map.insert("emission_seq".into(), json!(decisions.emission_seq()));
            }

            if let Some(input_hash) = decisions.input_hash() {
                let output_hash = payload
                    .and_then(PluginPayload::audit_bytes)
                    .map(|b| praxis_policy_core::hooks::payload::content_hash(&b));
                map.insert(
                    "content".into(),
                    json!({ "input_hash": input_hash, "output_hash": output_hash }),
                );
            }
        }
        record
    }
}

/// Render a violation for the audit record.
///
/// `description` and `details` are carried by every `PluginViolation` and are
/// where a policy engine puts the specifics of a refusal, so a record that
/// stops at `code` and `reason` loses the part an operator needs.
fn violation_json(v: &PluginViolation) -> Value {
    let mut out = Map::new();
    out.insert("code".into(), json!(v.code));
    out.insert("reason".into(), json!(v.reason));
    if let Some(description) = &v.description {
        out.insert("description".into(), json!(description));
    }
    if !v.details.is_empty() {
        out.insert("details".into(), json!(v.details));
    }
    if let Some(plugin) = &v.plugin_name {
        out.insert("plugin".into(), json!(plugin));
    }
    Value::Object(out)
}

#[async_trait]
impl AuditHandler for AuditLogger {
    async fn handle(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    ) {
        let cmf = payload.as_any().downcast_ref::<MessagePayload>();
        let record = self.build_decision_record(cmf, extensions, decisions);
        self.emit(&record);
    }

    async fn on_effect(&self, effect: &EffectRecord, ext: &Extensions) {
        let record = self.build_effect_record(effect, ext);
        self.emit(&record);
    }

    fn name(&self) -> &str {
        &self.cfg.name
    }
}

impl HookHandler<CmfHook> for AuditLogger {
    async fn handle(
        &self,
        payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let record = self.build_record(Some(payload), ext);
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

        let record = plugin.build_record(Some(&payload), &ext);
        assert_eq!(record["subject"]["id"], "alice@corp.com");
        assert_eq!(record["entity"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["args"]["employee_id"], "EMP-001234");
        // Always-allow contract: handler returns continue_processing.
        let mut ctx = PluginContext::default();
        let r = HookHandler::<CmfHook>::handle(&plugin, &payload, &ext, &mut ctx).await;
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

        let record = plugin.build_record(Some(&empty_payload()), &ext);
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
        let record = plugin.build_record(Some(&empty_payload()), &ext);
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
        let record = plugin.build_record(Some(&empty_payload()), &ext);
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
        let record = plugin.build_record(Some(&payload), &Extensions::default());
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
        let record = plugin.build_record(Some(&empty_payload()), &Extensions::default());
        assert_eq!(record["source"], "edge-gateway-1");
    }

    /// With no `config:` block at all the plugin takes its defaults rather than
    /// failing, so an operator can wire it with just `kind:` and `hooks:`.
    #[test]
    fn an_absent_config_block_falls_back_to_defaults() {
        let mut c = cfg();
        c.config = None;
        let plugin = AuditLogger::new(c).expect("no config block must still build");
        let record = plugin.build_record(Some(&empty_payload()), &Extensions::default());
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
        let r = HookHandler::<CmfHook>::handle(
            &plugin,
            &empty_payload(),
            &Extensions::default(),
            &mut ctx,
        )
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
        let record = plugin.build_record(Some(&empty_payload()), &Extensions::default());
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

    // =====================================================================
    // Decision sink
    // =====================================================================
    //
    // In sink mode the logger runs off the executor's verdict rather than a
    // post-hook, which is the only way it sees a request that was blocked.

    fn sink_cfg() -> PluginConfig {
        PluginConfig {
            hooks: Vec::new(),
            ..cfg()
        }
    }

    #[test]
    fn sink_mode_is_inferred_from_an_empty_hooks_list() {
        let sink = Arc::new(AuditLogger::new(sink_cfg()).unwrap());
        assert!(sink.as_audit_handler().is_some());
    }

    /// With hooks listed the logger is already observing as a post-hook.
    /// Attaching as a sink too would emit two records for one request.
    #[test]
    fn listing_hooks_keeps_it_a_post_hook_observer_and_not_a_sink() {
        let observer = Arc::new(AuditLogger::new(cfg()).unwrap());
        assert!(observer.as_audit_handler().is_none());
    }

    #[test]
    fn a_decision_record_carries_the_verdict_and_the_ordered_steps() {
        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        let mut violation = PluginViolation::new("not_permitted", "no grant for this tool");
        violation.description = Some("the subject holds no grant covering it".into());
        violation
            .details
            .insert("tool".into(), serde_json::json!("get_compensation"));
        violation.plugin_name = Some("pdp".into());

        log.record("identity", PluginMode::Sequential, PluginAction::Allowed);
        log.record(
            "pdp",
            PluginMode::Sequential,
            PluginAction::Denied(Box::new(violation.clone())),
        );
        log.finalize(Verdict::Deny(violation));

        let record =
            plugin.build_decision_record(Some(&empty_payload()), &Extensions::default(), &log);

        assert_eq!(record["verdict"]["deny"]["code"], "not_permitted");
        assert_eq!(
            record["verdict"]["deny"]["reason"],
            "no grant for this tool"
        );
        // `description` and `details` are where a policy engine puts the
        // specifics of a refusal, so a record that stops at code and reason is
        // not usable evidence of why the call was blocked.
        assert_eq!(
            record["verdict"]["deny"]["description"],
            "the subject holds no grant covering it"
        );
        assert_eq!(
            record["verdict"]["deny"]["details"]["tool"],
            "get_compensation"
        );
        assert_eq!(record["decision_steps"][0]["plugin"], "identity");
        assert_eq!(record["decision_steps"][0]["action"], "allowed");
        assert_eq!(record["decision_steps"][1]["plugin"], "pdp");
        assert_eq!(record["decision_steps"][1]["action"], "denied");
        assert_eq!(
            record["decision_steps"][1]["detail"]["code"],
            "not_permitted"
        );
    }

    /// A suppressed block is the case with no verdict to fall back on: the
    /// pipeline allowed the request, so the step is the only record that the
    /// plugin objected at all.
    #[test]
    fn a_suppressed_block_still_records_why_the_plugin_objected() {
        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.record(
            "scanner",
            PluginMode::Transform,
            PluginAction::DenyIgnored(Box::new(PluginViolation::new(
                "pii_present",
                "unredactable field",
            ))),
        );
        log.finalize(Verdict::Allow);

        let record =
            plugin.build_decision_record(Some(&empty_payload()), &Extensions::default(), &log);

        assert_eq!(record["verdict"], "allow");
        assert_eq!(record["decision_steps"][0]["action"], "deny_ignored");
        assert_eq!(record["decision_steps"][0]["detail"]["code"], "pii_present");
        assert_eq!(
            record["decision_steps"][0]["detail"]["reason"],
            "unredactable field"
        );
    }

    #[test]
    fn an_allow_verdict_renders_as_a_plain_allow() {
        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Allow);

        let record =
            plugin.build_decision_record(Some(&empty_payload()), &Extensions::default(), &log);

        assert_eq!(record["verdict"], "allow");
        assert_eq!(record["decision_steps"].as_array().unwrap().len(), 0);
    }

    /// Sinks fire for every hook family, not only the CMF ones, so a payload
    /// the logger cannot downcast must still produce a record rather than
    /// panicking or being dropped.
    #[tokio::test]
    async fn a_non_cmf_payload_still_produces_a_record() {
        #[derive(Debug, Clone)]
        struct Other;
        praxis_policy_core::impl_plugin_payload!(Other);

        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Allow);

        // The record is built from a payload that is not a MessagePayload.
        let record = plugin.build_decision_record(None, &Extensions::default(), &log);
        assert_eq!(record["verdict"], "allow");

        // And the sink path itself tolerates it.
        AuditHandler::handle(&plugin, &Other, &Extensions::default(), &log).await;
    }

    /// An effect is its own event, not part of a decision record: it happened
    /// to the outside world and outlives the request that caused it.
    #[test]
    fn an_effect_is_recorded_as_its_own_event() {
        use praxis_policy_core::effect::{EffectRecord, EffectState};

        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut effect = EffectRecord::prepared("token_mint", "exchange for workday", "k-1")
            .with_detail("audience", "workday-api")
            .into_state(EffectState::Confirmed);
        effect.plugin_name = Some("delegator".into());

        let record = plugin.build_effect_record(&effect, &Extensions::default());

        assert_eq!(record["event"], "effect");
        assert_eq!(record["effect_kind"], "token_mint");
        assert_eq!(record["effect_state"], "confirmed");
        assert_eq!(record["effect_key"], "k-1");
        // Attribution is the framework's, so a reader can trust which plugin
        // caused the act.
        assert_eq!(record["effect_plugin"], "delegator");
        assert_eq!(record["effect_details"]["audience"], "workday-api");
    }

    /// The intent is recorded before the act, so a reader sees a prepared
    /// record with no outcome when a process died mid-mint.
    #[test]
    fn an_unfinished_effect_renders_as_prepared() {
        use praxis_policy_core::effect::EffectRecord;

        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let effect = EffectRecord::prepared("token_mint", "d", "k-2");

        let record = plugin.build_effect_record(&effect, &Extensions::default());

        assert_eq!(record["effect_state"], "prepared");
    }

    /// Provenance is what turns a pile of records into a graph: the span says
    /// where this node sits, the taint says what it added, the hashes say
    /// whether the content changed.
    #[test]
    fn a_decision_record_carries_span_and_taint() {
        use praxis_policy_core::decision::Span;

        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.set_span(Span::for_request(Some("trace-abc"), Some("upstream")));
        log.set_input_labels(vec!["PII".to_owned()]);
        log.finalize(Verdict::Allow);

        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.add_label("CONFIDENTIAL");
        let ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };

        let record = plugin.build_decision_record(Some(&empty_payload()), &ext, &log);

        assert_eq!(record["span"]["trace_id"], "trace-abc");
        assert_eq!(record["span"]["parent_span_id"], "upstream");
        assert_ne!(
            record["span"]["span_id"], "upstream",
            "this node has its own span"
        );
        // The difference between the two is the taint this node added.
        assert_eq!(record["taint"]["input"][0], "PII");
        assert_eq!(record["taint"]["final"][0], "CONFIDENTIAL");
        assert_eq!(record["taint"]["final"][1], "PII");
    }

    /// With provenance off there is no input hash, so the record carries no
    /// content block at all rather than a half-populated one.
    #[test]
    fn no_input_hash_means_no_content_block() {
        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Allow);

        let record =
            plugin.build_decision_record(Some(&empty_payload()), &Extensions::default(), &log);

        assert!(record.get("content").is_none());
        assert!(record.get("taint").is_none(), "no labels either side");
    }

    /// Both hashes, so a reader can tell whether a stage changed the payload.
    /// Only digests are recorded; the content itself never reaches the trail.
    #[test]
    fn an_input_hash_brings_the_output_hash_with_it() {
        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.set_input_hash(Some("sha256:aaa".to_owned()));
        log.finalize(Verdict::Allow);

        let record =
            plugin.build_decision_record(Some(&empty_payload()), &Extensions::default(), &log);

        assert_eq!(record["content"]["input_hash"], "sha256:aaa");
        let output = record["content"]["output_hash"]
            .as_str()
            .expect("a CMF payload opts into hashing");
        assert!(output.starts_with("sha256:"));
    }

    /// A sink fires for every hook family, so it can be handed a payload it
    /// cannot hash. The record still says what it knows.
    #[test]
    fn a_payload_that_cannot_be_hashed_leaves_the_output_hash_null() {
        let plugin = AuditLogger::new(sink_cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.set_input_hash(Some("sha256:aaa".to_owned()));
        log.finalize(Verdict::Allow);

        let record = plugin.build_decision_record(None, &Extensions::default(), &log);

        assert_eq!(record["content"]["input_hash"], "sha256:aaa");
        assert!(record["content"]["output_hash"].is_null());
    }
}
