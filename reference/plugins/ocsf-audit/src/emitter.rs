// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The plugin proper. Mirrors audit-logger::AuditLogger: holds config,
// implements Plugin + AuditHandler + HookHandler<CmfHook>, builds a
// record, emits, and returns allow() (observation-only, never blocks).
//
// Added over audit-logger:
//   * OCSF mapping (ocsf::build_event, ocsf::apply_decision)
//   * optional attestation with a tamper-evident hash chain
//     (fingerprint -> prev_event.fingerprint) threaded across calls
//   * a pluggable signer (sign::OcsfSigner)

//! The emitter: builds, chains, signs and writes each record.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize as _;

use praxis_policy_core::audit::export::{AuditExporter, AuditStamp, ExportError, SerializedRecord};
use praxis_policy_core::cmf::{CmfHook, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::config::{OcsfAuditConfig, SigningMode};
use crate::ocsf;
use crate::sign::{DsseSigner, NoopSigner, OcsfSigner, canonical_bytes, fingerprint_value};

/// Back-reference to the preceding record in the chain, i.e. everything
/// the `prev_event` object needs: the predecessor's
/// `metadata.uid` (schema-required), its `type_uid` (which tells a
/// consumer the class, and therefore the store, to retrieve it from),
/// and its fingerprint value (what actually binds the link to content).
#[derive(Clone)]
struct PrevRef {
    uid: String,
    type_uid: i64,
    fingerprint: String,
}

/// The chain's position, held for the life of the emitter and nowhere
/// else. It starts at sequence zero with no predecessor on every process
/// start, so a chain spans one process and the uids it mints are unique
/// only within that process. The default `chain_uid` carries a random
/// per-process component so two processes never mint the same uid; a
/// configured one is the operator's to keep per process (see
/// `OcsfAuditConfig::chain_uid`).
#[derive(Default)]
struct ChainState {
    /// Monotonic per-emitter counter. Drives deterministic record and
    /// attestation uids so example/demo output stays reproducible.
    seq: u64,
    prev: Option<PrevRef>,
}

/// Scrub the inline signing key from both config copies: the typed field
/// and the raw `config:` entry. `Zeroize` on a `String` overwrites the
/// bytes before the allocation is freed, and the raw entry is cleared the
/// same way so the JSON `Value` does not keep a second copy.
///
/// Runs whatever the signing mode is. A key configured alongside
/// `signing: none`, which is what an operator leaves behind when signing
/// is turned off for a rotation or an incident, is never consumed by a
/// signer and would otherwise stay printable for the life of the plugin.
fn redact_inline_key(typed: &mut OcsfAuditConfig, cfg: &mut PluginConfig) {
    if let Some(mut inline) = typed.signing_key_pem.take() {
        inline.zeroize();
    }
    if let Some(raw) = cfg.config.as_mut().and_then(Value::as_object_mut)
        && let Some(Value::String(mut s)) = raw.remove("signing_key_pem")
    {
        s.zeroize();
    }
}

/// The plugin: one instance per `audit/ocsf` entry, holding the parsed
/// config, the signer and the chain state.
pub struct OcsfAuditEmitter {
    cfg: PluginConfig,
    typed: OcsfAuditConfig,
    chain_uid: String,
    signer: Box<dyn OcsfSigner>,
    chain: Mutex<ChainState>,
    /// Every record goes to each of these, byte for byte.
    exporters: Vec<Arc<dyn AuditExporter>>,
    /// Bounds detached writes if an audit callback times out while its
    /// blocking destination is still stalled.
    output_slots: Arc<Semaphore>,
}

const MAX_PENDING_WRITES: usize = 4;
#[expect(
    clippy::cast_possible_truncation,
    reason = "MAX_PENDING_WRITES is a small compile-time constant"
)]
const MAX_PENDING_WRITES_U32: u32 = MAX_PENDING_WRITES as u32;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Build a `fingerprint` object around a hex digest.
///
/// `algorithm_id` 3 = SHA-256, `encoding_id` 1 = Hex, `serialization_id`
/// 2 = JCS, the last being how a verifier knows which bytes were hashed
/// (the JCS-style canonicalizer in `sign.rs`).
fn fingerprint_obj(value: &str) -> Value {
    json!({
        "algorithm_id": 3,
        "algorithm": "SHA-256",
        "encoding_id": 1,
        "encoding": "Hex",
        "serialization_id": 2,
        "serialization": "JCS",
        "value": value,
    })
}

impl std::fmt::Debug for OcsfAuditEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcsfAuditEmitter")
            .field("name", &self.cfg.name)
            .field("chain_uid", &self.chain_uid)
            .finish()
    }
}

impl OcsfAuditEmitter {
    /// Build an audit sink from a plugin entry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, a missing output, an
    /// unavailable exporter, or invalid signing keys.
    pub fn new(mut cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg.config.clone().unwrap_or_else(|| json!({}));
        let mut typed: OcsfAuditConfig = serde_json::from_value(raw).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-ocsf-audit) config parse failed: {e}",
                    cfg.name
                ),
            })
        })?;

        // Opened here so an unwritable file fails the load, not the first
        // verdict.
        let exporters = typed.output.build_exporters().map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-ocsf-audit): {e}",
                    cfg.name
                ),
            })
        })?;

        let chain_uid = typed.chain_uid.clone().unwrap_or_else(|| {
            // A chain spans one process (see `ChainState`), so the default
            // names the process: plugin name plus a random component. Two
            // processes, a restart or a replica, then never mint the same
            // `<chain_uid>-<seq>` uid from the default. A configured value
            // is the operator's to keep per process.
            format!("ocsf-chain-{}-{}", cfg.name, uuid::Uuid::new_v4().simple())
        });

        // The signature covers the chained record (`attestation_list`,
        // AID-EMIT-1 section 4), so `chain: false` has nothing to sign and
        // the signer would never run. Refuse the pair rather than emit
        // unsigned records under a config that promises signatures.
        if typed.signing == SigningMode::Dsse && !typed.chain {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-ocsf-audit): signing=dsse requires \
                     chain: true; the signature is computed over the chained record",
                    cfg.name
                ),
            }));
        }

        let signer: Box<dyn OcsfSigner> = match typed.signing {
            SigningMode::None => Box::new(NoopSigner),
            SigningMode::Dsse => {
                // A missing/unreadable/invalid key fails construction
                // loudly. The alternative, falling back to unsigned,
                // would emit records that look like the operator's
                // signing policy while silently lacking the signatures
                // it promised.
                let config_err = |message: String| Box::new(PluginError::Config { message });
                let mut pem = match (&typed.signing_key_pem, &typed.signing_key_pem_path) {
                    (Some(inline), None) => inline.clone(),
                    (None, Some(path)) => std::fs::read_to_string(path).map_err(|e| {
                        config_err(format!(
                            "plugin '{}' (praxis-policy-plugin-ocsf-audit): signing=dsse could not \
                             read signing_key_pem_path '{path}': {e}",
                            cfg.name
                        ))
                    })?,
                    (Some(_), Some(_)) => {
                        return Err(config_err(format!(
                            "plugin '{}' (praxis-policy-plugin-ocsf-audit): set exactly one of \
                             signing_key_pem / signing_key_pem_path, not both",
                            cfg.name
                        )));
                    },
                    (None, None) => {
                        return Err(config_err(format!(
                            "plugin '{}' (praxis-policy-plugin-ocsf-audit): signing=dsse requires a \
                             key: set signing_key_pem (inline PKCS#8 PEM) or \
                             signing_key_pem_path",
                            cfg.name
                        )));
                    },
                };
                let signer =
                    DsseSigner::from_pem(&pem, typed.signing_key_id.clone()).map_err(|e| {
                        config_err(format!(
                            "plugin '{}' (praxis-policy-plugin-ocsf-audit): {e}",
                            cfg.name
                        ))
                    })?;
                // The signer now holds the key, so the construction-time
                // copy goes before anything else can read it.
                pem.zeroize();
                Box::new(signer)
            },
        };

        // Everything that still carries the PEM is config, and config gets
        // printed: `OcsfAuditConfig` derives `Debug` and `Serialize`, and
        // `PluginConfig::config` is a `Debug` `Value`. Zeroize the copies
        // and clear both slots rather than redacting at each print site.
        // The path form carries no key material.
        redact_inline_key(&mut typed, &mut cfg);

        Ok(Self {
            cfg,
            typed,
            chain_uid,
            signer,
            chain: Mutex::new(ChainState::default()),
            exporters,
            output_slots: Arc::new(Semaphore::new(MAX_PENDING_WRITES)),
        })
    }

    /// Build the OCSF event and, if chaining is on, wrap it in an
    /// attestation. `now_rfc3339` injected for testability and for
    /// deterministic example/demo output. Public so `examples/` and
    /// downstream tooling can obtain the event without going through
    /// the stderr/tracing emit path.
    pub fn build(&self, payload: &MessagePayload, ext: &Extensions, now_rfc3339: &str) -> Value {
        let event = ocsf::build_ai_operation(payload, ext, &self.typed, now_rfc3339);
        self.wrap_in_chain(event)
    }

    /// Build a decision-audit event: the same OCSF shape as `build`, with
    /// the pipeline's ruling overlaid (verdict to action/disposition/status,
    /// per-plugin steps, span, taint, content digests and stream stamps
    /// under `unmapped.aid.*`), then chained like any other record.
    /// `payload` is `None` for a non-CMF dispatch (delegation, identity):
    /// the record still emits, from the extensions alone.
    pub fn build_decision(
        &self,
        payload: Option<&MessagePayload>,
        ext: &Extensions,
        decisions: &praxis_policy_core::decision::DecisionLog,
        now_rfc3339: &str,
    ) -> Value {
        let mut event = ocsf::build_event(payload, ext, &self.typed, now_rfc3339);
        ocsf::apply_decision(&mut event, decisions);
        self.wrap_in_chain(event)
    }

    /// Wrap `event` in the attestation chain (no-op when `chain: false`).
    /// Decision records and post-hook observations share one chain: the
    /// chain orders *emissions of this emitter*, whichever path built them.
    fn wrap_in_chain(&self, event: Value) -> Value {
        if !self.typed.chain {
            return event;
        }

        // Predecessor binding: the fingerprint is computed over the
        // canonical serialization of the whole event, including this
        // attestation's own `uid`, `chain_uid`, `authority_uid` and
        // `prev_event`, and excluding only `fingerprint` and `signatures`.
        // So the record's chain position is inside the hashed input:
        // deleting, reordering or splicing a record changes its own
        // fingerprint, and every later link with it. A verifier following
        // the schema reproduces the bytes without knowing this crate.
        //
        // Canonical bytes are JCS-style: key-sorted, compact, with the
        // set-derived arrays already sorted at build time (ocsf.rs).
        let mut out = event;

        // Held from seq allocation through the chain advance: those must
        // be one atomic step, or two concurrent invocations can mint the
        // same uid and fork the chain off the same predecessor. Signing
        // and the write happen after release. `build` is sync, so there
        // is no await under the guard. A poisoned lock is recovered
        // rather than propagated:
        // the state is two plain values and a panic between reading and
        // advancing them cannot leave either half-written.
        let mut guard = self
            .chain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record_uid = format!("{}-{:06}", self.chain_uid, guard.seq);
        let att_uid = format!("{}-att-{:06}", self.chain_uid, guard.seq);
        let prev = guard.prev.clone();

        // `metadata.uid` identifies this record; the next record's
        // `prev_event.uid` points at it, so it must exist before hashing.
        let type_uid = out.get("type_uid").and_then(Value::as_i64).unwrap_or(0);
        if let Some(m) = out.get_mut("metadata").and_then(Value::as_object_mut) {
            m.insert("uid".into(), json!(record_uid));
        }

        // Attestation minus fingerprint/signatures: the hashed form.
        let mut attestation = serde_json::Map::new();
        attestation.insert("uid".into(), json!(att_uid));
        attestation.insert("chain_uid".into(), json!(self.chain_uid));
        // authority_uid is part of the hashed serialization, alongside
        // chain_uid and prev_event, so the claimed authority cannot be
        // swapped post-hoc without breaking the fingerprint, and every
        // signature over it.
        if let Some(authority) = &self.typed.authority_uid {
            attestation.insert("authority_uid".into(), json!(authority));
        }
        if let Some(p) = &prev {
            attestation.insert(
                "prev_event".into(),
                json!({
                    "uid": p.uid,
                    "type_uid": p.type_uid,
                    "fingerprint": fingerprint_obj(&p.fingerprint),
                }),
            );
        }
        if let Value::Object(m) = &mut out {
            m.insert("attestation_list".into(), json!([attestation]));
        }

        let bytes = canonical_bytes(&out);
        let this_fp = fingerprint_value(&bytes);

        // The chain state needs only this record's uid, type and
        // fingerprint, all known now. Advance it and release the lock
        // before signing, so one ECDSA operation per record does not
        // serialize every concurrent request behind the mutex.
        guard.prev = Some(PrevRef {
            uid: record_uid,
            type_uid,
            fingerprint: this_fp.clone(),
        });
        guard.seq += 1;
        drop(guard);

        let signed = self.signer.sign(&bytes);

        // Now fill in the two excluded members.
        if let Some(att) = out
            .get_mut("attestation_list")
            .and_then(|l| l.get_mut(0))
            .and_then(Value::as_object_mut)
        {
            att.insert("fingerprint".into(), fingerprint_obj(&this_fp));
            if let Some(signed) = &signed {
                att.insert("signatures".into(), json!([signed.digital_signature]));
            }
        }
        if let Some(signed) = signed {
            // The signature bytes (and the JWKS kid that resolves the
            // public key) have no home on `digital_signature`; that gap
            // is filed as ocsf-schema#1709. Until it lands they ride in
            // `unmapped`, merged into any existing `unmapped`: the gap
            // fields from ocsf.rs already live there, and those are
            // inside the hashed bytes; only these two post-hash keys are
            // excluded by a verifier (see sign::signing_input).
            if let Value::Object(m) = &mut out {
                let un = m
                    .entry("unmapped")
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Some(un) = un.as_object_mut() {
                    un.insert("signature_b64".into(), json!(signed.signature));
                    if let Some(kid) = &signed.key_id {
                        un.insert("signature_key_id".into(), json!(kid));
                    }
                }
            }
        }

        out
    }

    /// Reserve a write slot before advancing the chain. Waiting for a slot
    /// yields to the executor's audit timeout, and a cancelled waiter has
    /// not minted a chain position for a record it cannot write.
    async fn output_slot(&self) -> Option<OwnedSemaphorePermit> {
        match Arc::clone(&self.output_slots).acquire_owned().await {
            Ok(permit) => Some(permit),
            Err(err) => {
                tracing::error!(plugin = %self.cfg.name, error = %err, "audit output closed");
                None
            },
        }
    }

    /// Run a synchronous destination on a blocking thread, holding the
    /// slot until that write actually finishes. A timed-out callback drops
    /// its join handle, but the still-running write keeps its slot, so a
    /// stalled destination cannot spawn an unbounded number of threads.
    async fn write_off_thread(permit: OwnedSemaphorePermit, write: impl FnOnce() + Send + 'static) {
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            write();
        })
        .await;
        if let Err(err) = result {
            if err.is_panic() {
                std::panic::resume_unwind(err.into_panic());
            }
            tracing::error!(error = %err, "audit output task was cancelled");
        }
    }

    /// Serialize `event` once and hand the same bytes to every exporter, on
    /// a blocking thread. An exporter that fails is logged and the others
    /// still run: losing one destination must not silence the rest.
    async fn emit(&self, event: Value, stamp: Option<AuditStamp>, permit: OwnedSemaphorePermit) {
        let uid = event
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let bytes = match serde_json::to_vec(&event) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::error!(plugin = %self.cfg.name, error = %err, "ocsf record did not serialize");
                return;
            },
        };
        let record = SerializedRecord::json(bytes)
            .with_stamp(stamp)
            .with_uid(uid);
        let exporters = self.exporters.clone();
        let plugin = self.cfg.name.clone();
        Self::write_off_thread(permit, move || {
            for exporter in &exporters {
                if let Err(err) = exporter.export(std::slice::from_ref(&record)) {
                    tracing::error!(
                        plugin = %plugin,
                        exporter = exporter.name(),
                        error = %err,
                        "ocsf record export failed"
                    );
                }
            }
        })
        .await;
    }

    /// Wait for blocking writes whose audit callbacks may already have timed
    /// out, then prevent new writes and flush. A stalled destination makes
    /// shutdown fail after the grace period instead of claiming durability.
    async fn drain_and_flush(&self, grace: Duration) -> Result<(), Box<PluginError>> {
        // The semaphore has four permits. Taking all four waits for every
        // blocking worker, including those detached by an audit timeout.
        let drained = tokio::time::timeout(
            grace,
            Arc::clone(&self.output_slots).acquire_many_owned(MAX_PENDING_WRITES_U32),
        )
        .await;
        let drain_guard = match drained {
            Ok(Ok(permit)) => Some(permit),
            Ok(Err(err)) => {
                tracing::error!(plugin = %self.cfg.name, error = %err, "audit output closed before shutdown drain");
                None
            },
            Err(_) => {
                tracing::error!(plugin = %self.cfg.name, "audit output did not drain before shutdown timeout");
                None
            },
        };
        self.output_slots.close();

        let exporters = self.exporters.clone();
        let plugin = self.cfg.name.clone();
        let flushed = tokio::time::timeout(
            grace,
            tokio::task::spawn_blocking(move || {
                for exporter in &exporters {
                    if let Err(err) = exporter.flush() {
                        tracing::error!(
                            plugin = %plugin,
                            exporter = exporter.name(),
                            error = %err,
                            "ocsf exporter flush failed at shutdown"
                        );
                    }
                }
            }),
        )
        .await;
        match flushed {
            Ok(Ok(())) => {},
            Ok(Err(err)) => {
                return Err(PluginError::Execution {
                    plugin_name: self.cfg.name.clone(),
                    message: "ocsf exporter flush task failed".to_owned(),
                    source: Some(Box::new(err)),
                    code: None,
                    details: Default::default(),
                    proto_error_code: None,
                }
                .boxed());
            },
            Err(_) => {
                tracing::error!(plugin = %self.cfg.name, "ocsf exporter flush exceeded shutdown timeout");
                return Err(PluginError::Timeout {
                    plugin_name: self.cfg.name.clone(),
                    timeout_ms: u64::try_from(grace.as_millis()).unwrap_or(u64::MAX),
                    proto_error_code: None,
                }
                .boxed());
            },
        }
        if drain_guard.is_none() {
            return Err(PluginError::Timeout {
                plugin_name: self.cfg.name.clone(),
                timeout_ms: u64::try_from(grace.as_millis()).unwrap_or(u64::MAX),
                proto_error_code: None,
            }
            .boxed());
        }
        Ok(())
    }
}

/// The `tracing` destination: one event per record at target `ocsf.audit`,
/// the record as the `event` field. A `tracing` target is fixed at compile
/// time, so this lives with the sink rather than among the engine's
/// exporters.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingExporter;

impl AuditExporter for TracingExporter {
    fn name(&self) -> &str {
        "tracing"
    }

    fn export(&self, batch: &[SerializedRecord]) -> Result<(), ExportError> {
        for record in batch {
            let event = String::from_utf8_lossy(&record.bytes);
            tracing::info!(target: "ocsf.audit", event = %event, "ocsf");
        }
        Ok(())
    }
}

#[async_trait]
impl Plugin for OcsfAuditEmitter {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }

    /// Drain detached writes before flushing every exporter. A failing
    /// exporter is logged and the rest are still flushed; a stalled worker
    /// or flush makes shutdown return an error after the grace period.
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        self.drain_and_flush(SHUTDOWN_TIMEOUT).await
    }

    /// Attach as a decision-audit sink when run in audit-only mode (no
    /// `hooks:` listed): the engine then invokes the `AuditHandler` impl
    /// below at every pipeline verdict, denials included. If the operator
    /// listed hooks, this runs as a CMF post-hook observer instead and
    /// does not also attach, so records are not emitted twice for one
    /// invocation. (Same contract as the `audit-logger` reference sink.)
    fn as_audit_handler(
        self: std::sync::Arc<Self>,
    ) -> Option<std::sync::Arc<dyn praxis_policy_core::audit::AuditHandler>> {
        let attach = self.cfg.hooks.is_empty();
        let sink: std::sync::Arc<dyn praxis_policy_core::audit::AuditHandler> = self;
        attach.then_some(sink)
    }
}

/// Decision-audit consumer, the sink path. Fires at the verdict of every
/// pipeline run with the finalized
/// [`DecisionLog`](praxis_policy_core::decision::DecisionLog); this is
/// what makes denials, suppressed transform-denies, panics and
/// modifications visible to the OCSF stream (a post-hook observer only
/// ever sees allowed traffic). Awaited on the request path by contract,
/// so `handle` stays serialize-and-emit cheap.
///
/// Only the decision stream is rendered. `on_effect` keeps the trait's
/// ignoring default: an `EffectRecord` (intent or outcome, token mints
/// included) has no OCSF rendering here yet, so the `effect` stream never
/// reaches this sink's output. The README states the limit.
#[async_trait]
impl praxis_policy_core::audit::AuditHandler for OcsfAuditEmitter {
    async fn handle(
        &self,
        payload: &dyn praxis_policy_core::hooks::payload::PluginPayload,
        ext: &Extensions,
        decisions: &praxis_policy_core::decision::DecisionLog,
    ) {
        let Some(permit) = self.output_slot().await else {
            return;
        };
        // Downcast to the CMF payload when this dispatch carried one; a
        // non-CMF dispatch (delegation, identity) records without the
        // message-derived fields.
        let msg = payload.as_any().downcast_ref::<MessagePayload>();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let event = self.build_decision(msg, ext, decisions, &now);
        self.emit(event, AuditStamp::from_decisions(decisions), permit)
            .await;
    }

    fn name(&self) -> &str {
        &self.cfg.name
    }
}

impl HookHandler<CmfHook> for OcsfAuditEmitter {
    async fn handle(
        &self,
        payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let Some(permit) = self.output_slot().await else {
            return PluginResult::allow();
        };
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let event = self.build(payload, ext, &now);
        self.emit(event, None, permit).await;
        // Observation-only: never block the request.
        PluginResult::allow()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::cmf::{ContentPart, Message, Role, ToolCall};
    use praxis_policy_core::extensions::{SecurityExtension, SubjectExtension};
    use praxis_policy_core::plugin::{OnError, PluginMode};
    use std::collections::HashMap;

    fn cfg(mut extra: serde_json::Value) -> PluginConfig {
        if let Some(block) = extra.as_object_mut()
            && !block.contains_key("destination")
            && !block.contains_key("exporters")
        {
            block.insert("destination".into(), json!("stderr"));
        }
        PluginConfig {
            name: "ocsf-audit".into(),
            kind: super::super::factory::KIND.into(),
            hooks: vec!["cmf.tool_post_invoke".into()],
            mode: PluginMode::Sequential,
            priority: 50,
            on_error: OnError::Fail,
            config: Some(extra),
            ..Default::default()
        }
    }

    fn tool_payload() -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::Tool,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "call-1".into(),
                        name: "get_compensation".into(),
                        arguments: HashMap::new(),
                        namespace: Some("hr".into()),
                    },
                }],
            ),
        }
    }

    fn subject_ext() -> Extensions {
        let mut sec = SecurityExtension::default();
        sec.subject = Some(SubjectExtension {
            id: Some("alice@corp.com".into()),
            ..Default::default()
        });
        Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        }
    }

    /// Gap 6: `RequestExtension.request_id`, the mandate draw-receipt
    /// join key, rides `unmapped."cmf.request.request_id"` on every
    /// event (dispatch and decision alike), and stays absent when the
    /// request extension is missing. Deliberately not
    /// `metadata.correlation_uid`, which is the conversation-stable key.
    #[test]
    fn request_id_rides_unmapped_as_receipt_join_key() {
        use praxis_policy_core::extensions::RequestExtension;
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();

        let mut ext = subject_ext();
        ext.request = Some(Arc::new(RequestExtension {
            request_id: Some("corr-7f3e2a91".into()),
            ..Default::default()
        }));

        // Dispatch event carries the join key…
        let ev = e.build(&tool_payload(), &ext, "2026-08-21T05:00:00.000Z");
        assert_eq!(ev["unmapped"]["cmf.request.request_id"], "corr-7f3e2a91");
        // …and never in the conversation-correlation slot.
        assert_ne!(ev["metadata"]["correlation_uid"], "corr-7f3e2a91");

        // Decision events built from the same extensions carry it too.
        use praxis_policy_core::decision::{PluginAction, Verdict};
        let mut log = praxis_policy_core::decision::DecisionLog::new();
        log.record("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed);
        log.finalize(Verdict::Allow);
        let dev = e.build_decision(
            Some(&tool_payload()),
            &ext,
            &log,
            "2026-08-21T05:00:01.000Z",
        );
        assert_eq!(dev["unmapped"]["cmf.request.request_id"], "corr-7f3e2a91");

        // Absent request extension -> absent key (no empty scaffolding).
        let bare = e.build(&tool_payload(), &subject_ext(), "2026-08-21T05:00:02.000Z");
        assert!(bare["unmapped"].get("cmf.request.request_id").is_none());
    }

    #[test]
    fn maps_tool_call_to_ocsf_ai_operation() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:00.000Z");

        // Host class: API Activity.
        assert_eq!(ev["class_uid"], 6003);
        // No readOnlyHint on this tool -> honest 99 (Other) with a
        // source-defined name, per the OCSF enum contract.
        assert_eq!(ev["activity_id"], 99);
        assert_eq!(ev["activity_name"], "Invoke Tool");
        assert_eq!(ev["type_uid"], 600_399);
        // Passive post-hook stream = security_control Observed/Logged.
        assert_eq!(ev["action_id"], 3);
        assert_eq!(ev["disposition_id"], 17);
        // The per-call id lands at api.request.uid, not correlation_uid
        // (which mirrors the run id and is absent here because this
        // payload carries no AgentExtension).
        assert_eq!(ev["api"]["request"]["uid"], "call-1");
        assert!(ev["metadata"]["correlation_uid"].is_null());
        assert_eq!(ev["tool"]["name"], "get_compensation");
        assert_eq!(ev["tool"]["namespace"], "hr");
        assert_eq!(ev["actor"]["user"]["uid"], "alice@corp.com");
        assert_eq!(ev["metadata"]["product"]["vendor_name"], "Praxis");
    }

    #[test]
    fn chains_fingerprints_across_calls() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();

        let ev1 = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:00.000Z");
        let ev2 = e.build(&tool_payload(), &subject_ext(), "2026-06-30T12:00:01.000Z");

        let (a1, a2) = (&ev1["attestation_list"][0], &ev2["attestation_list"][0]);

        // Genesis record carries no prev_event at all (the shape omits it
        // rather than emitting an explicit null).
        assert!(a1.get("prev_event").is_none());

        // Second record's prev_event binds the first: fingerprint by
        // content, uid + type_uid for retrieval.
        assert_eq!(a2["prev_event"]["fingerprint"], a1["fingerprint"]);
        assert_eq!(a2["prev_event"]["uid"], ev1["metadata"]["uid"]);
        assert_eq!(a2["prev_event"]["type_uid"], ev1["type_uid"]);

        // Fingerprint is an object, bare-hex valued.
        assert_eq!(a1["fingerprint"]["algorithm_id"], 3);
        assert_eq!(a1["fingerprint"]["encoding_id"], 1);
        assert_eq!(a1["fingerprint"]["serialization_id"], 2);
        assert_eq!(a1["fingerprint"]["value"].as_str().unwrap().len(), 64);

        // Unsigned-but-chained in the default (None) signing mode: the
        // at_least_one(fingerprint, signatures) constraint is satisfied
        // by the fingerprint, and no empty signatures array is emitted.
        assert!(a1.get("signatures").is_none());
        assert!(ev1.get("unmapped").is_none());
    }

    #[test]
    fn read_only_hint_maps_tool_call_to_read() {
        use praxis_policy_core::extensions::{MCPExtension, ToolMetadata};

        let mut ext = subject_ext();
        ext.mcp = Some(Arc::new(MCPExtension {
            tool: Some(ToolMetadata {
                name: "get_compensation".into(),
                annotations: HashMap::from([("readOnlyHint".to_owned(), json!(true))]),
                ..Default::default()
            }),
            ..Default::default()
        }));

        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &ext, "2026-07-20T12:00:00.000Z");

        // readOnlyHint: true -> known id 2 with the normalized caption.
        assert_eq!(ev["activity_id"], 2);
        assert_eq!(ev["activity_name"], "Read");
        assert_eq!(ev["type_uid"], 600_302);
    }

    #[test]
    fn read_only_hint_for_different_tool_is_ignored() {
        use praxis_policy_core::extensions::{MCPExtension, ToolMetadata};

        let mut ext = subject_ext();
        ext.mcp = Some(Arc::new(MCPExtension {
            tool: Some(ToolMetadata {
                name: "some_other_tool".into(),
                annotations: HashMap::from([("readOnlyHint".to_owned(), json!(true))]),
                ..Default::default()
            }),
            ..Default::default()
        }));

        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &ext, "2026-07-20T12:00:00.000Z");

        // The hint describes a different tool than the one invoked.
        assert_eq!(ev["activity_id"], 99);
        assert_eq!(ev["activity_name"], "Invoke Tool");
    }

    #[test]
    fn profiles_reflect_chain_config() {
        let chained = OcsfAuditEmitter::new(cfg(json!({ "chain": true })))
            .unwrap()
            .build(&tool_payload(), &subject_ext(), "2026-07-20T12:00:00.000Z");
        assert_eq!(
            chained["metadata"]["profiles"],
            json!(["ai_operation", "security_control", "record_integrity"])
        );

        let unchained = OcsfAuditEmitter::new(cfg(json!({ "chain": false })))
            .unwrap()
            .build(&tool_payload(), &subject_ext(), "2026-07-20T12:00:00.000Z");
        assert_eq!(
            unchained["metadata"]["profiles"],
            json!(["ai_operation", "security_control"])
        );
    }

    /// The predecessor is folded into the hashed input, by `prev_event`
    /// living inside the serialized event. Two byte-identical events at
    /// different chain positions must produce different fingerprints;
    /// under a plain back-pointer design they collide, so reordering or
    /// splicing records between positions (or chains) is undetectable
    /// from the hashes alone.
    #[test]
    fn fingerprint_binds_predecessor_into_hashed_input() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();
        let t = "2026-07-20T12:00:00.000Z";
        let ev1 = e.build(&tool_payload(), &subject_ext(), t);
        let ev2 = e.build(&tool_payload(), &subject_ext(), t);

        // Identical event content (attestation and record uid aside)...
        let strip = |v: &Value| {
            let mut v = v.clone();
            let m = v.as_object_mut().unwrap();
            m.remove("attestation_list");
            m.get_mut("metadata")
                .and_then(Value::as_object_mut)
                .map(|md| md.remove("uid"));
            v
        };
        assert_eq!(strip(&ev1), strip(&ev2));

        // ...but a different chain position -> a different fingerprint,
        // while linkage still holds.
        let (a1, a2) = (&ev1["attestation_list"][0], &ev2["attestation_list"][0]);
        assert_ne!(a1["fingerprint"]["value"], a2["fingerprint"]["value"]);
        assert_eq!(a2["prev_event"]["fingerprint"], a1["fingerprint"]);
    }

    // --- signing (DSSE) --------------------------------------------------

    /// Deterministic test key (RFC 6979 makes ECDSA deterministic per
    /// key+message, so signed sample output stays reproducible). PEM is
    /// generated at runtime; no key material lives in the repo.
    fn test_key_pem() -> String {
        use p256::pkcs8::EncodePrivateKey as _;
        p256::ecdsa::SigningKey::from_slice(&[0x11_u8; 32])
            .unwrap()
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn signed_cfg() -> PluginConfig {
        cfg(json!({
            "chain": true,
            "signing": "dsse",
            "signing_key_pem": test_key_pem(),
            "signing_key_id": "test-key-1",
            "authority_uid": "org-test-authority",
        }))
    }

    /// The full independent-verifier loop, from nothing but the emitted
    /// JSON and the public key: reconstruct the signed bytes
    /// (`sign::signing_input`), recompute the fingerprint, verify the
    /// DSSE signature over the PAE.
    #[test]
    fn signed_event_verifies_offline() {
        use crate::sign::{dsse_pae, signing_input};
        use base64::Engine as _;
        use p256::ecdsa::signature::Verifier as _;

        let e = OcsfAuditEmitter::new(signed_cfg()).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-07-31T12:00:00.000Z");

        let att = &ev["attestation_list"][0];
        // authority_uid emitted, and it names the configured party.
        assert_eq!(att["authority_uid"], "org-test-authority");
        // Descriptor carries the verified enum ids: ECDSA (3) / DSSE (5),
        // with normalized captions.
        assert_eq!(att["signatures"][0]["algorithm_id"], 3);
        assert_eq!(att["signatures"][0]["algorithm"], "ECDSA");
        assert_eq!(att["signatures"][0]["serialization_id"], 5);
        assert_eq!(att["signatures"][0]["serialization"], "DSSE");
        // kid rides beside the bytes so a verifier can resolve the key.
        assert_eq!(ev["unmapped"]["signature_key_id"], "test-key-1");

        // Independent reconstruction: fingerprint matches...
        let bytes = signing_input(&ev);
        assert_eq!(
            crate::sign::fingerprint_value(&bytes),
            att["fingerprint"]["value"].as_str().unwrap()
        );
        // ...and the signature verifies over the PAE of the same bytes.
        let der = base64::engine::general_purpose::STANDARD
            .decode(ev["unmapped"]["signature_b64"].as_str().unwrap())
            .unwrap();
        let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
        let vk = *p256::ecdsa::SigningKey::from_slice(&[0x11_u8; 32])
            .unwrap()
            .verifying_key();
        vk.verify(&dsse_pae(&bytes), &sig)
            .expect("emitted signature must verify offline");
    }

    /// Without a configured `chain_uid`, two emitters (two processes, in
    /// effect) must not mint the same record uid: the default carries a
    /// per-process component, so a restart or a replica on the default
    /// config never collides with its predecessor's `<chain_uid>-000000`.
    #[test]
    fn default_chain_uid_is_unique_per_emitter() {
        let a = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();
        let b = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();
        let t = "2026-07-20T12:00:00.000Z";
        let ev_a = a.build(&tool_payload(), &subject_ext(), t);
        let ev_b = b.build(&tool_payload(), &subject_ext(), t);
        assert_ne!(
            a.chain_uid, b.chain_uid,
            "default chain_uid must differ per process"
        );
        assert!(
            a.chain_uid.starts_with("ocsf-chain-ocsf-audit-"),
            "{}",
            a.chain_uid
        );
        assert_ne!(ev_a["metadata"]["uid"], ev_b["metadata"]["uid"]);

        // A configured value is taken verbatim.
        let c =
            OcsfAuditEmitter::new(cfg(json!({ "chain": true, "chain_uid": "gw-1-x" }))).unwrap();
        assert_eq!(c.chain_uid, "gw-1-x");
    }

    /// An inline key is consumed by the signer and must not stay printable:
    /// neither the typed config nor the raw `config:` entry, both of which
    /// implement `Debug`, may still carry the PEM, and signing must still
    /// work from the signer's own copy.
    #[test]
    fn inline_signing_key_is_cleared_after_construction() {
        let e = OcsfAuditEmitter::new(signed_cfg()).unwrap();
        assert!(
            e.typed.signing_key_pem.is_none(),
            "typed field must be cleared"
        );
        let typed_debug = format!("{:?}", e.typed);
        let raw_debug = format!("{:?}", e.cfg.config);
        for (what, s) in [("typed", &typed_debug), ("raw", &raw_debug)] {
            assert!(
                !s.contains("PRIVATE KEY"),
                "{what} config still prints the PEM: {s}"
            );
        }
        assert!(
            e.cfg
                .config
                .as_ref()
                .unwrap()
                .get("signing_key_pem")
                .is_none(),
            "raw config entry must be removed"
        );
        // The signer still signs after the inline key is cleared.
        let ev = e.build(&tool_payload(), &subject_ext(), "2026-07-31T12:00:00.000Z");
        assert!(ev["unmapped"]["signature_b64"].is_string());
    }

    #[test]
    fn a_destination_only_config_block_takes_the_documented_defaults() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "destination": "stderr" }))).unwrap();
        assert!(e.typed.chain, "chain defaults on");
        assert!(e.typed.include_gap_fields, "gap fields default on");
        assert_eq!(e.typed.product_name, "Praxis Policy Engine OCSF Audit");
        let ev = e.build(&tool_payload(), &subject_ext(), "2026-10-12T12:00:00.000Z");
        assert!(
            ev["attestation_list"][0]["fingerprint"]["value"].is_string(),
            "a sink on its defaults must emit a chained, fingerprinted record: {ev}"
        );
    }

    /// A key configured with `signing: none` is never consumed by a signer,
    /// which is what an operator leaves behind when signing is turned off
    /// for a rotation. It must be cleared all the same: both config copies
    /// implement `Debug`, and a key nothing reads is still a key in the
    /// process image.
    #[test]
    fn inline_signing_key_is_cleared_when_signing_is_off() {
        let e = OcsfAuditEmitter::new(cfg(json!({
            "chain": true,
            "signing": "none",
            "signing_key_pem": test_key_pem(),
        })))
        .unwrap();
        assert!(
            e.typed.signing_key_pem.is_none(),
            "typed field must be cleared with signing off too"
        );
        assert!(
            e.cfg
                .config
                .as_ref()
                .unwrap()
                .get("signing_key_pem")
                .is_none(),
            "raw config entry must be removed with signing off too"
        );
        for (what, s) in [
            ("typed", format!("{:?}", e.typed)),
            ("raw", format!("{:?}", e.cfg.config)),
        ] {
            assert!(
                !s.contains("PRIVATE KEY"),
                "{what} config still prints the PEM: {s}"
            );
        }
        // Signing is off, so the record chains unsigned.
        let ev = e.build(&tool_payload(), &subject_ext(), "2026-07-31T12:00:00.000Z");
        assert!(ev["unmapped"]["signature_b64"].is_null());
        assert!(ev["attestation_list"][0]["fingerprint"]["value"].is_string());
    }

    /// The executor wraps this future in `tokio::time::timeout`. A blocked
    /// destination must yield the runtime thread so that timer can fire;
    /// otherwise the request waits for the blocking write indefinitely.
    #[tokio::test(flavor = "current_thread")]
    async fn blocked_output_yields_to_the_audit_timeout() {
        let emitter = OcsfAuditEmitter::new(cfg(json!({}))).unwrap();
        let permit = emitter.output_slot().await.unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

        // The watchdog makes a synchronous-write regression fail rather
        // than hang the test indefinitely.
        let watchdog = std::thread::spawn(move || {
            let _ = stop_rx.recv_timeout(std::time::Duration::from_secs(1));
            let _ = release_tx.send(());
        });
        let started = std::time::Instant::now();
        let mut task = tokio::spawn(OcsfAuditEmitter::write_off_thread(permit, move || {
            let _ = entered_tx.send(());
            let _ = release_rx.recv();
        }));
        entered_rx.await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), &mut task).await;
        let elapsed = started.elapsed();
        let _ = stop_tx.send(());
        task.await.unwrap();
        watchdog.join().unwrap();
        assert!(result.is_err(), "a blocked write must yield to the timer");
        assert!(
            elapsed < std::time::Duration::from_millis(750),
            "the timer did not fire until the blocking write finished"
        );
    }

    /// Float bounds in a tool's `inputSchema` and a non-ASCII annotation
    /// key are routine MCP metadata, serialized whole under `cmf.mcp`.
    /// They must neither panic the canonicalizer nor produce bytes an RFC
    /// 8785 verifier cannot reproduce: the hashed form carries the ES6
    /// number form and the signature verifies over it.
    #[test]
    fn float_schema_and_non_ascii_annotation_key_verify_offline() {
        use crate::sign::{dsse_pae, signing_input};
        use base64::Engine as _;
        use p256::ecdsa::signature::Verifier as _;
        use praxis_policy_core::extensions::{MCPExtension, ToolMetadata};

        let mut ext = subject_ext();
        ext.mcp = Some(Arc::new(MCPExtension {
            tool: Some(ToolMetadata {
                name: "get_compensation".into(),
                input_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "ratio": { "type": "number", "minimum": 0.0, "maximum": 2.0, "default": 1.0 },
                        "big": { "type": "number", "maximum": 1e21 },
                        // The shape a bound computed by whoever published
                        // the schema takes: `0.21000000000000002`,
                        // seventeen significant digits and one ULP from
                        // `0.21`. Written as the product so the digits are
                        // not a magic literal.
                        "step": { "type": "number", "default": 0.07 * 3.0 }
                    }
                })),
                annotations: HashMap::from([
                    ("readOnlyHint".to_owned(), json!(false)),
                    ("résumé".to_owned(), json!("non-ASCII key")),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        }));

        let e = OcsfAuditEmitter::new(signed_cfg()).unwrap();
        let ev = e.build(&tool_payload(), &ext, "2026-07-31T12:00:00.000Z");

        let bytes = signing_input(&ev);
        let canonical = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            canonical.contains(r#""default":1,"maximum":2,"minimum":0"#),
            "floats must take the ES6 form in the hashed bytes: {canonical}"
        );
        assert!(canonical.contains(r#""maximum":1e+21"#), "{canonical}");
        assert!(
            canonical.contains(r#""résumé":"non-ASCII key""#),
            "{canonical}"
        );

        assert_eq!(
            crate::sign::fingerprint_value(&bytes),
            ev["attestation_list"][0]["fingerprint"]["value"]
                .as_str()
                .unwrap()
        );
        let der = base64::engine::general_purpose::STANDARD
            .decode(ev["unmapped"]["signature_b64"].as_str().unwrap())
            .unwrap();
        let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
        let vk = *p256::ecdsa::SigningKey::from_slice(&[0x11_u8; 32])
            .unwrap()
            .verifying_key();
        vk.verify(&dsse_pae(&bytes), &sig)
            .expect("signature over the ES6-form bytes must verify");

        // The whole point of a canonical form is that a verifier reaches it
        // from the emitted text, so walk the README's four steps from the
        // serialized record rather than from the `Value` in hand. This is
        // the step that holds the float parser to its side of the contract:
        // `serde_json` without `float_roundtrip` re-parses a value such as
        // `0.21000000000000002` one ULP off, recanonicalizes different bytes
        // and reports an untouched record as tampered.
        let emitted = serde_json::to_string(&ev).unwrap();
        let reparsed: Value = serde_json::from_str(&emitted).unwrap();
        let reparsed_bytes = signing_input(&reparsed);
        assert_eq!(
            reparsed_bytes, bytes,
            "a verifier must reach the same canonical bytes from the emitted text"
        );
        assert_eq!(
            crate::sign::fingerprint_value(&reparsed_bytes),
            ev["attestation_list"][0]["fingerprint"]["value"]
                .as_str()
                .unwrap()
        );
        vk.verify(&dsse_pae(&reparsed_bytes), &sig)
            .expect("the signature must verify from the reparsed record");
    }

    /// Signing must merge into `unmapped`, not replace it: the gap fields
    /// (`stop_reason`, mcp, framework, labels, workload) live there and
    /// are part of the hashed evidence.
    #[test]
    fn signing_preserves_gap_fields_in_unmapped() {
        let e = OcsfAuditEmitter::new(signed_cfg()).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-07-31T12:00:00.000Z");

        let un = ev["unmapped"].as_object().unwrap();
        assert!(un.contains_key("signature_b64"));
        assert!(un.contains_key("cmf.completion.stop_reason"));
        assert!(un.contains_key("cmf.mcp"));
        assert!(un.contains_key("cmf.security.labels"));
    }

    /// `authority_uid` sits inside the hashed serialization: two otherwise
    /// identical records claiming different authorities must fingerprint
    /// differently, so the claimed authority cannot be swapped post-hoc.
    #[test]
    fn authority_uid_is_bound_into_the_fingerprint() {
        let build = |authority: &str| {
            OcsfAuditEmitter::new(cfg(json!({
                "chain": true,
                "authority_uid": authority,
            })))
            .unwrap()
            .build(&tool_payload(), &subject_ext(), "2026-07-31T12:00:00.000Z")
        };
        let a = build("org-alpha");
        let b = build("org-beta");
        assert_ne!(
            a["attestation_list"][0]["fingerprint"]["value"],
            b["attestation_list"][0]["fingerprint"]["value"]
        );
    }

    /// `signing: dsse` with no key must fail construction loudly, never
    /// fall back to silently-unsigned records.
    /// `signing: dsse` with `chain: false` has nothing to sign: the
    /// signature covers the chained record, so the pair must fail
    /// construction rather than emit unsigned records under a signing
    /// policy.
    #[test]
    fn dsse_with_chain_off_fails_construction() {
        let err =
            OcsfAuditEmitter::new(cfg(json!({ "signing": "dsse", "chain": false }))).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("chain: true"), "unexpected error: {msg}");
    }

    /// A misspelled key must fail construction, not silently fall back:
    /// `authorty_uid` would otherwise emit signed records with no
    /// `authority_uid` binding and no warning.
    #[test]
    fn unknown_config_key_fails_construction() {
        let err = OcsfAuditEmitter::new(cfg(json!({ "authorty_uid": "org-1" }))).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field"), "unexpected error: {msg}");
    }

    #[test]
    fn dsse_without_key_fails_construction() {
        let err = OcsfAuditEmitter::new(cfg(json!({ "signing": "dsse" }))).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("requires a key"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn handler_is_observation_only() {
        let e = OcsfAuditEmitter::new(cfg(json!({}))).unwrap();
        let mut ctx = PluginContext::default();
        let r = HookHandler::<CmfHook>::handle(&e, &tool_payload(), &subject_ext(), &mut ctx).await;
        assert!(r.continue_processing);
        assert!(r.violation.is_none());
    }

    // --- decision-audit sink ----------------------------------------------

    use praxis_policy_core::decision::{DecisionLog, PluginAction, Span, Verdict};
    use praxis_policy_core::error::PluginViolation;

    /// Sink-mode config: no `hooks:`, so the factory registers no post-hook
    /// handlers and the plugin attaches as a decision-audit sink.
    fn sink_cfg(extra: serde_json::Value) -> PluginConfig {
        PluginConfig {
            hooks: vec![],
            ..cfg(extra)
        }
    }

    fn finalized(steps: Vec<(&str, PluginMode, PluginAction)>, verdict: Verdict) -> DecisionLog {
        let mut log = DecisionLog::new();
        for (name, mode, action) in steps {
            log.record(name, mode, action);
        }
        log.finalize(verdict);
        log
    }

    /// Registration contract: audit-only mode (no hooks) attaches as a
    /// sink; a hook-listed observer does not also attach, so one
    /// invocation never emits twice.
    #[test]
    fn audit_handler_attaches_only_in_sink_mode() {
        use praxis_policy_core::plugin::Plugin as _;
        let sink = Arc::new(OcsfAuditEmitter::new(sink_cfg(json!({}))).unwrap());
        assert!(sink.as_audit_handler().is_some(), "no hooks -> sink");

        let observer = Arc::new(OcsfAuditEmitter::new(cfg(json!({}))).unwrap());
        assert!(
            observer.as_audit_handler().is_none(),
            "hooks listed -> post-hook observer only, no double emission"
        );
    }

    #[test]
    fn allow_verdict_maps_to_allowed() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let log = finalized(
            vec![("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed)],
            Verdict::Allow,
        );
        let ev = e.build_decision(
            Some(&tool_payload()),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );

        assert_eq!(ev["action_id"], 1);
        assert_eq!(ev["action"], "Allowed");
        assert_eq!(ev["disposition_id"], 1);
        assert_eq!(ev["disposition"], "Allowed");
        // The operation classification is untouched by the ruling.
        assert_eq!(ev["class_uid"], 6003);
        assert_eq!(ev["activity_name"], "Invoke Tool");
        let steps = ev["unmapped"]["aid.decision"]["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0]["plugin"], "cedar-pdp");
        assert_eq!(steps[0]["phase"], "sequential");
        assert_eq!(steps[0]["action"], "allowed");
        assert_eq!(ev["unmapped"]["aid.decision"]["verdict"], "allow");
    }

    /// The record a post-hook observer could never produce: a denial,
    /// including the fail-closed panic contract: the violation code
    /// (`plugin_panic`) must survive to `status_code`, distinguishable
    /// from an ordinary `plugin_error`.
    #[test]
    fn deny_verdict_maps_to_denied_with_violation_status() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let mut violation = PluginViolation::new(
            "plugin_panic",
            "Plugin 'minter' failed: task panicked: simulated",
        );
        violation.plugin_name = Some("minter".into());
        let log = finalized(
            vec![(
                "minter",
                PluginMode::Sequential,
                PluginAction::Error("task panicked: simulated".into()),
            )],
            Verdict::Deny(violation),
        );
        let ev = e.build_decision(
            Some(&tool_payload()),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );

        assert_eq!(ev["action_id"], 2);
        assert_eq!(ev["action"], "Denied");
        assert_eq!(ev["disposition_id"], 2);
        assert_eq!(ev["disposition"], "Blocked");
        assert_eq!(ev["status_id"], 2);
        assert_eq!(ev["status_code"], "plugin_panic");
        assert!(
            ev["status_detail"]
                .as_str()
                .unwrap()
                .contains("task panicked")
        );
        let d = &ev["unmapped"]["aid.decision"];
        assert_eq!(d["verdict"]["deny"]["code"], "plugin_panic");
        assert_eq!(d["steps"][0]["action"], "error");
        assert!(
            d["steps"][0]["error"]
                .as_str()
                .unwrap()
                .contains("panicked")
        );
    }

    #[test]
    fn modified_allow_maps_to_modified() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let log = finalized(
            vec![
                (
                    "pii-scrubber",
                    PluginMode::Transform,
                    PluginAction::ModifiedPayload,
                ),
                ("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed),
            ],
            Verdict::Allow,
        );
        let ev = e.build_decision(
            Some(&tool_payload()),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );

        assert_eq!(ev["action_id"], 4);
        assert_eq!(ev["action"], "Modified");
        // The request still proceeded.
        assert_eq!(ev["disposition_id"], 1);
        assert_eq!(
            ev["unmapped"]["aid.decision"]["steps"][0]["action"],
            "modified_payload"
        );
    }

    /// Seam contract on `PluginAction::DenyIgnored`: a suppressed
    /// Transform-phase block must never read as a plain allow. The event
    /// stays Allowed (enforcement DID allow it) but the step carries the
    /// plugin's actual decision and the block is flagged flat for SIEM
    /// queries.
    #[test]
    fn deny_ignored_never_reads_as_plain_allow() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let log = finalized(
            vec![(
                "strict-transform",
                PluginMode::Transform,
                PluginAction::DenyIgnored(Box::new(PluginViolation::new("policy_deny", "blocked"))),
            )],
            Verdict::Allow,
        );
        let ev = e.build_decision(
            Some(&tool_payload()),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );

        assert_eq!(ev["action_id"], 1, "enforcement outcome was allow");
        let d = &ev["unmapped"]["aid.decision"];
        assert_eq!(d["steps"][0]["action"], "deny_ignored");
        assert_eq!(d["deny_ignored"], true, "flat flag for SIEM queries");
    }

    /// A denying step names what objected: `denied` / `deny_ignored`
    /// steps carry `detail` (code + reason; description / details only
    /// when set). For a suppressed deny that is the only place the
    /// objection survives, since no verdict names it.
    #[test]
    fn denying_steps_carry_their_violation_as_detail() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let mut described = PluginViolation::new("pii_present", "unredactable field");
        described.description = Some("ssn in free text".into());
        let log = finalized(
            vec![
                (
                    "strict-transform",
                    PluginMode::Transform,
                    PluginAction::DenyIgnored(Box::new(described)),
                ),
                (
                    "cedar-pdp",
                    PluginMode::Sequential,
                    PluginAction::Denied(Box::new(PluginViolation::new(
                        "missing_permission",
                        "no",
                    ))),
                ),
            ],
            Verdict::Deny(PluginViolation::new("missing_permission", "no")),
        );
        let ev = e.build_decision(
            Some(&tool_payload()),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );
        let steps = &ev["unmapped"]["aid.decision"]["steps"];
        assert_eq!(steps[0]["action"], "deny_ignored");
        assert_eq!(steps[1]["action"], "denied");
        assert_eq!(ev["unmapped"]["aid.decision"]["deny_ignored"], true);
        assert_eq!(ev["status_code"], "missing_permission");

        assert_eq!(steps[0]["detail"]["code"], "pii_present");
        assert_eq!(steps[0]["detail"]["reason"], "unredactable field");
        assert_eq!(steps[0]["detail"]["description"], "ssn in free text");
        assert!(
            steps[0]["detail"].get("details").is_none(),
            "empty details map is omitted, not emitted as {{}}"
        );
        assert_eq!(steps[1]["detail"]["code"], "missing_permission");
        assert!(
            steps[1]["detail"].get("description").is_none(),
            "no description set, none rendered"
        );
    }

    /// `Aborted` (a concurrent sibling short-circuited the phase) is an
    /// intentional cancellation; it must not render as an error.
    #[test]
    fn aborted_step_is_not_an_error() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let log = finalized(
            vec![
                ("scanner-b", PluginMode::Concurrent, PluginAction::Aborted),
                (
                    "scanner-a",
                    PluginMode::Concurrent,
                    PluginAction::Denied(Box::new(PluginViolation::new("policy_deny", "blocked"))),
                ),
            ],
            Verdict::Deny(PluginViolation::new("policy_deny", "blocked")),
        );
        let ev = e.build_decision(
            Some(&tool_payload()),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );

        let steps = ev["unmapped"]["aid.decision"]["steps"].as_array().unwrap();
        assert_eq!(steps[0]["action"], "aborted");
        assert!(steps[0].get("error").is_none());
        assert_eq!(steps[1]["action"], "denied");
    }

    /// Zero-plugin invocations emit one allow record on the seam (dense
    /// stream); the sink renders it with an empty steps array, not a gap.
    #[test]
    fn zero_step_invocation_emits_allow_record() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let log = finalized(vec![], Verdict::Allow);
        let ev = e.build_decision(
            Some(&tool_payload()),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );

        assert_eq!(ev["action_id"], 1);
        assert_eq!(
            ev["unmapped"]["aid.decision"]["steps"],
            json!([]),
            "explicit empty steps, not absence"
        );
    }

    /// Audit sinks fire for every hook family; a non-CMF dispatch carries
    /// no `MessagePayload` and must still produce a record.
    #[test]
    fn non_cmf_dispatch_still_emits() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let log = finalized(
            vec![(
                "cedar-pdp",
                PluginMode::Sequential,
                PluginAction::Denied(Box::new(PluginViolation::new("missing_permission", "no"))),
            )],
            Verdict::Deny(PluginViolation::new("missing_permission", "no")),
        );
        let ev = e.build_decision(None, &subject_ext(), &log, "2026-08-18T12:00:00.000Z");

        assert_eq!(ev["class_uid"], 6003);
        assert_eq!(ev["activity_id"], 0, "no payload -> honest Unknown");
        assert_eq!(ev["action_id"], 2);
        assert_eq!(ev["status_code"], "missing_permission");
        assert!(ev.get("tool").is_none(), "no payload -> no tool coords");
        // Extension-derived context still populates.
        assert_eq!(ev["actor"]["user"]["uid"], "alice@corp.com");
    }

    /// Span, entry taint, content provenance and the stream stamps land
    /// under `unmapped.aid.*`, the seam's counters verbatim.
    #[test]
    fn provenance_and_stream_stamps_land_in_unmapped() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let mut log = finalized(
            vec![("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed)],
            Verdict::Allow,
        );
        log.set_span(Span::for_request(Some("trace-1"), Some("parent-1")));
        log.set_input_labels(vec!["PII".into()]);
        log.set_input_hash(Some("in-hash".into()));
        log.set_stream(1_755_000_000_000_000_000, "decision".into(), 7, 42);

        let payload = tool_payload();
        let ev = e.build_decision(
            Some(&payload),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );

        let un = &ev["unmapped"];
        assert_eq!(un["aid.span"]["trace_id"], "trace-1");
        assert_eq!(un["aid.span"]["parent_span_id"], "parent-1");
        assert_eq!(un["aid.taint.input_labels"], json!(["PII"]));
        assert_eq!(un["aid.content"]["input_hash"], "in-hash");
        // The output digest key exists whether or not the engine recorded
        // one, so the claim is explicit.
        assert!(
            un["aid.content"]
                .as_object()
                .unwrap()
                .contains_key("output_hash")
        );
        assert_eq!(un["aid.stream"]["epoch"], 1_755_000_000_000_000_000_u64);
        assert_eq!(un["aid.stream"]["stream_id"], "decision");
        assert_eq!(un["aid.stream"]["stream_seq"], 7);
        assert_eq!(un["aid.stream"]["emission_seq"], 42);
    }

    /// The output digest is the engine's value: recorded on the log and
    /// copied verbatim by the emitter, key id and all, and an explicit
    /// null, not an absent key, when nothing was digested.
    #[test]
    fn output_hash_is_copied_from_the_log() {
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let mut log = finalized(
            vec![("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed)],
            Verdict::Allow,
        );
        log.set_input_hash(Some("in-hash".into()));
        let payload = tool_payload();

        log.set_output_hash(Some("hmac-sha256:k1:bbb".into()));
        let ev = e.build_decision(
            Some(&payload),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );
        assert_eq!(
            ev["unmapped"]["aid.content"]["output_hash"], "hmac-sha256:k1:bbb",
            "copied from the log, never recomputed"
        );

        // The engine recorded nothing: null even though a payload is
        // present, because this sink does not hash.
        log.set_output_hash(None);
        let ev = e.build_decision(
            Some(&payload),
            &subject_ext(),
            &log,
            "2026-08-18T12:00:00.000Z",
        );
        assert_eq!(
            ev["unmapped"]["aid.content"]["output_hash"],
            serde_json::Value::Null
        );
    }

    /// The decision facts sit inside the hashed bytes: two otherwise
    /// identical genesis records with different stream stamps must
    /// fingerprint differently, so renumbering the stream post-hoc breaks
    /// the chain.
    #[test]
    fn decision_facts_are_bound_into_the_fingerprint() {
        let build = |stream_seq: u64| {
            let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": true }))).unwrap();
            let mut log = finalized(
                vec![("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed)],
                Verdict::Allow,
            );
            log.set_stream(1, "decision".into(), stream_seq, stream_seq);
            e.build_decision(
                Some(&tool_payload()),
                &subject_ext(),
                &log,
                "2026-08-18T12:00:00.000Z",
            )
        };
        let a = build(7);
        let b = build(8);
        assert_ne!(
            a["attestation_list"][0]["fingerprint"]["value"],
            b["attestation_list"][0]["fingerprint"]["value"]
        );
    }

    /// End-to-end through the trait object, as the executor calls it: the
    /// dyn payload downcasts to CMF and the handler completes.
    #[tokio::test]
    async fn audit_handler_handles_dyn_payload() {
        use praxis_policy_core::audit::AuditHandler;
        let e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": false }))).unwrap();
        let payload = tool_payload();
        let log = finalized(
            vec![("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed)],
            Verdict::Allow,
        );
        AuditHandler::handle(&e, &payload, &subject_ext(), &log).await;
        assert_eq!(AuditHandler::name(&e), "ocsf-audit");
    }

    // --- gap-branch coverage --------------------------------------------
    // The happy-path test above only exercises a tool call + subject. These
    // build a fully-populated Extensions set and assert every gap field
    // lands where the mapping puts it.

    use praxis_policy_core::extensions::{
        AgentExtension, CompletionExtension, DelegationExtension, DelegationHop,
        FrameworkExtension, MCPExtension, StopReason, TokenUsage, ToolMetadata, WorkloadIdentity,
    };

    /// Extensions with every audit-relevant branch populated.
    fn full_ext() -> Extensions {
        let mut sec = SecurityExtension::default();
        let mut subj = SubjectExtension::default();
        subj.id = Some("alice@corp.com".into());
        subj.roles.insert("hr".into());
        subj.teams.insert("people-ops".into());
        sec.subject = Some(subj);
        // monotonic taint labels (gap 4)
        sec.labels.insert("PII".into());
        sec.labels.insert("secret".into());
        // workload attestation (gap 5)
        sec.caller_workload = Some(WorkloadIdentity {
            spiffe_id: Some("spiffe://corp/agent/hr-bot".into()),
            trust_domain: Some("corp".into()),
            attestor: Some("gke-workload-identity".into()),
            ..Default::default()
        });

        let agent = AgentExtension {
            agent_id: Some("agent-7".into()),
            parent_agent_id: Some("orchestrator-1".into()),
            session_id: Some("sess-42".into()),
            conversation_id: Some("conv-9".into()),
            turn: Some(3),
            ..Default::default()
        };

        let completion = CompletionExtension {
            stop_reason: Some(StopReason::MaxTokens), // gap 3
            tokens: Some(TokenUsage {
                input_tokens: 120,
                output_tokens: 30,
                total_tokens: 150,
            }),
            model: Some("claude-opus-4-8".into()),
            latency_ms: Some(842),
            ..Default::default()
        };

        let delegation = DelegationExtension {
            delegated: true,
            depth: 1,
            origin_subject_id: Some("alice@corp.com".into()),
            actor_subject_id: Some("agent-7".into()),
            chain: vec![DelegationHop {
                subject_id: "agent-7".into(),
                audience: Some("workday-api".into()),
                scopes_granted: vec!["read_compensation".into()],
                ttl_seconds: Some(300),
                ..Default::default()
            }],
            ..Default::default()
        };

        let mcp = MCPExtension {
            tool: Some(ToolMetadata {
                name: "get_compensation".into(),
                server_id: Some("hr-mcp".into()),
                namespace: Some("hr".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let framework = FrameworkExtension {
            framework: Some("langgraph".into()),
            node_id: Some("node-compensation".into()),
            graph_id: Some("graph-hr".into()),
            ..Default::default()
        };

        Extensions {
            security: Some(Arc::new(sec)),
            agent: Some(Arc::new(agent)),
            completion: Some(Arc::new(completion)),
            delegation: Some(Arc::new(delegation)),
            mcp: Some(Arc::new(mcp)),
            framework: Some(Arc::new(framework)),
            ..Default::default()
        }
    }

    #[test]
    fn gap_fields_land_in_unmapped() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-06-30T12:00:00.000Z");

        let un = &ev["unmapped"];
        assert_eq!(un["cmf.completion.stop_reason"], "MaxTokens");
        assert_eq!(un["cmf.framework"]["framework"], "langgraph");
        assert_eq!(un["cmf.framework"]["graph_id"], "graph-hr");
        assert_eq!(un["cmf.mcp"]["tool"]["server_id"], "hr-mcp");
        assert_eq!(
            un["cmf.workload_identity"]["spiffe_id"],
            "spiffe://corp/agent/hr-bot"
        );
        assert_eq!(
            un["cmf.workload_identity"]["attestor"],
            "gke-workload-identity"
        );
        // monotonic labels: order-independent membership check
        let labels = un["cmf.security.labels"].as_array().expect("labels array");
        assert!(labels.iter().any(|v| v == "PII"));
        assert!(labels.iter().any(|v| v == "secret"));
    }

    #[test]
    fn mapped_objects_populate_from_extensions() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-06-30T12:00:00.000Z");

        // ai_agent + lineage
        assert_eq!(ev["ai_agent"]["uid"], "agent-7");
        assert_eq!(ev["ai_agent"]["parent_uid"], "orchestrator-1");
        // correlation_uid mirrors the run id (AgentExtension.conversation_id)
        // so every event of one run carries the same value; a per-event id
        // correlates nothing. It lives on `metadata`, which is where OCSF
        // defines it.
        assert_eq!(ev["metadata"]["correlation_uid"], "conv-9");
        assert!(ev.get("correlation_uid").is_none());
        assert_eq!(ev["api"]["request"]["uid"], "call-1");
        // message_context tokens
        assert_eq!(ev["message_context"]["total_tokens"], 150);
        assert_eq!(ev["ai_model"]["name"], "claude-opus-4-8");
        assert_eq!(ev["duration"], 842);
        // delegation object
        assert_eq!(ev["delegation"]["depth"], 1);
        assert_eq!(ev["delegation"]["chain"][0]["audience"], "workday-api");
        assert_eq!(
            ev["delegation"]["chain"][0]["scopes_granted"][0],
            "read_compensation"
        );
    }

    /// `HashSet` / `MonotonicSet` iteration order is randomized per
    /// instance, so the builder must sort set-derived arrays; otherwise
    /// the same logical event canonicalizes to different bytes across
    /// process runs and an independent verifier cannot recompute the
    /// fingerprint.
    #[test]
    fn set_derived_arrays_are_sorted_for_canonical_hashing() {
        let mut sec = SecurityExtension::default();
        let mut subj = SubjectExtension::default();
        subj.id = Some("alice@corp.com".into());
        for r in ["zeta", "alpha", "mid"] {
            subj.roles.insert(r.into());
        }
        for t in ["t2", "t1", "t3"] {
            subj.teams.insert(t.into());
        }
        sec.subject = Some(subj);
        for l in ["secret", "PII", "internal", "export-controlled"] {
            sec.labels.insert(l.into());
        }
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        };

        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": true }))).unwrap();
        let ev = e.build(&tool_payload(), &ext, "2026-07-06T12:00:00.000Z");

        assert_eq!(
            ev["unmapped"]["cmf.security.labels"],
            json!(["PII", "export-controlled", "internal", "secret"])
        );
        assert_eq!(ev["actor"]["roles"], json!(["alpha", "mid", "zeta"]));
        assert_eq!(ev["actor"]["user"]["groups"], json!(["t1", "t2", "t3"]));
    }

    /// Structural OCSF conformance, not full schema validation (that needs
    /// the published schema and a validator; see the README). Asserts the
    /// base event has the required, correctly-typed fields every OCSF
    /// consumer relies on to route a record.
    #[test]
    fn emits_required_ocsf_base_fields() {
        let e = OcsfAuditEmitter::new(cfg(json!({ "chain": false }))).unwrap();
        let ev = e.build(&tool_payload(), &full_ext(), "2026-06-30T12:00:00.000Z");

        for key in [
            "activity_id",
            "category_uid",
            "class_uid",
            "type_uid",
            "severity_id",
        ] {
            assert!(ev[key].is_u64(), "{key} must be an integer");
        }
        assert!(ev["time"].is_string(), "time must be present");
        assert!(ev["metadata"]["version"].is_string());
        assert!(ev["metadata"]["product"]["name"].is_string());
        // type_uid convention: class_uid * 100 + activity_id
        assert_eq!(
            ev["type_uid"].as_u64().unwrap(),
            ev["class_uid"].as_u64().unwrap() * 100 + ev["activity_id"].as_u64().unwrap()
        );
    }

    // --- exporters ----------------------------------------------------------

    /// A directory nothing else is using, removed when the guard drops.
    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir() -> TempDir {
        let dir = std::env::temp_dir().join(format!("ocsf-audit-export-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn exporter_names(typed: &OcsfAuditConfig) -> Vec<String> {
        typed
            .output
            .build_exporters()
            .unwrap()
            .iter()
            .map(|e| e.name().to_owned())
            .collect()
    }

    fn exporter_err(extra: serde_json::Value) -> String {
        OcsfAuditEmitter::new(sink_cfg(extra))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn an_unwritable_file_fails_construction() {
        let err = exporter_err(json!({
            "exporters": [{ "kind": "file", "path": "relative.ndjson" }],
        }));
        assert!(err.contains("must be absolute"), "{err}");
    }

    #[test]
    fn exporter_kinds_parse_and_unknown_settings_are_rejected() {
        let dir = temp_dir();
        let typed: OcsfAuditConfig = serde_json::from_value(json!({
            "exporters": [
                { "kind": "stderr" },
                { "kind": "tracing" },
                { "kind": "file", "path": dir.0.join("a.ndjson"), "fsync": "batch" },
            ],
        }))
        .unwrap();
        assert_eq!(exporter_names(&typed), ["stderr", "tracing", "file"]);

        for bad in [
            json!({ "kind": "tracing", "target": "x" }),
            json!({ "kind": "file", "path": "/a", "mode": 1 }),
            json!({ "kind": "kafka" }),
        ] {
            assert!(
                serde_json::from_value::<OcsfAuditConfig>(json!({ "exporters": [bad.clone()] }))
                    .is_err(),
                "{bad} must not parse"
            );
        }
    }

    #[test]
    fn with_no_destination_or_exporters_the_sink_refuses_to_load() {
        let mut absent = cfg(json!({}));
        absent.config = None;
        let mut silent = cfg(json!({}));
        silent.config = Some(json!({ "chain": true }));
        let mut blank = cfg(json!({}));
        blank.config = Some(json!({ "destination": null, "exporters": null }));
        for c in [absent, silent, blank] {
            let err = OcsfAuditEmitter::new(c).unwrap_err().to_string();
            assert!(
                err.contains("no audit destination configured"),
                "an entry without an output must not build: {err}"
            );
        }
    }

    #[test]
    fn an_unknown_destination_is_rejected() {
        let err = exporter_err(json!({ "destination": "carrier-pigeon" }));
        assert!(err.contains("parse failed"), "{err}");
        assert!(err.contains("carrier-pigeon"), "{err}");
    }

    /// Signed, chained records from the decision sink, fanned out to two
    /// files: both files hold the same bytes, one record per line, and every
    /// record verifies offline from those bytes and the public key, with its
    /// predecessor link intact.
    #[tokio::test]
    async fn file_exporters_receive_identical_verifiable_records() {
        use crate::sign::{dsse_pae, signing_input};
        use base64::Engine as _;
        use p256::ecdsa::signature::Verifier as _;
        use praxis_policy_core::audit::AuditHandler;

        let dir = temp_dir();
        let a = dir.0.join("a.ndjson");
        let b = dir.0.join("b.ndjson");
        let mut extra = signed_cfg().config.unwrap();
        extra.as_object_mut().unwrap().remove("destination");
        extra["exporters"] = json!([
            { "kind": "file", "path": a, "fsync": "batch" },
            { "kind": "file", "path": b },
        ]);
        let e = OcsfAuditEmitter::new(sink_cfg(extra)).unwrap();

        for stream_seq in 0..3 {
            let mut log = finalized(
                vec![("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed)],
                Verdict::Allow,
            );
            log.set_stream(1, "gw-1:decision".into(), stream_seq, stream_seq);
            AuditHandler::handle(&e, &tool_payload(), &subject_ext(), &log).await;
        }

        let from_a = std::fs::read(&a).unwrap();
        assert_eq!(
            from_a,
            std::fs::read(&b).unwrap(),
            "fan-out must be byte-identical"
        );

        let vk = *p256::ecdsa::SigningKey::from_slice(&[0x11_u8; 32])
            .unwrap()
            .verifying_key();
        let mut prev_fp: Option<String> = None;
        let lines: Vec<&[u8]> = from_a
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            let ev: Value = serde_json::from_slice(line).unwrap();
            assert_eq!(ev["unmapped"]["aid.stream"]["stream_seq"], i);
            let bytes = signing_input(&ev);
            let fp = crate::sign::fingerprint_value(&bytes);
            let att = &ev["attestation_list"][0];
            assert_eq!(att["fingerprint"]["value"].as_str().unwrap(), fp);
            assert_eq!(
                att["prev_event"]["fingerprint"]["value"]
                    .as_str()
                    .map(str::to_owned),
                prev_fp,
            );
            let der = base64::engine::general_purpose::STANDARD
                .decode(ev["unmapped"]["signature_b64"].as_str().unwrap())
                .unwrap();
            let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
            vk.verify(&dsse_pae(&bytes), &sig)
                .expect("a record read back from the file must verify");
            prev_fp = Some(fp);
        }
    }

    /// The record an exporter receives carries the executor's stamp and the
    /// record's own uid, so a consumer or a metric can use them without
    /// parsing the body.
    /// Records what it was given and how often it was flushed.
    #[derive(Debug, Default)]
    struct Capture {
        records: std::sync::Mutex<Vec<SerializedRecord>>,
        flushes: std::sync::atomic::AtomicUsize,
    }

    impl AuditExporter for Capture {
        fn name(&self) -> &str {
            "capture"
        }
        fn export(&self, batch: &[SerializedRecord]) -> Result<(), ExportError> {
            self.records.lock().unwrap().extend_from_slice(batch);
            Ok(())
        }
        fn flush(&self) -> Result<(), ExportError> {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// A failing flush is logged and does not stop the others.
    #[derive(Debug)]
    struct FailingFlush;

    impl AuditExporter for FailingFlush {
        fn name(&self) -> &str {
            "failing"
        }
        fn export(&self, _batch: &[SerializedRecord]) -> Result<(), ExportError> {
            Ok(())
        }
        fn flush(&self) -> Result<(), ExportError> {
            Err(ExportError::Config("flush failed".to_owned()))
        }
    }

    struct BlockingExporter {
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl std::fmt::Debug for BlockingExporter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("BlockingExporter")
        }
    }

    impl AuditExporter for BlockingExporter {
        fn name(&self) -> &str {
            "blocking"
        }

        fn export(&self, _batch: &[SerializedRecord]) -> Result<(), ExportError> {
            let entered = self.entered.lock().unwrap().take();
            if let Some(entered) = entered {
                let _ = entered.send(());
            }
            let _ = self.release.lock().unwrap().recv();
            Ok(())
        }
    }

    fn blocking_exporter() -> (
        Arc<dyn AuditExporter>,
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        (
            Arc::new(BlockingExporter {
                entered: std::sync::Mutex::new(Some(entered_tx)),
                release: std::sync::Mutex::new(release_rx),
            }),
            entered_rx,
            release_tx,
        )
    }

    #[tokio::test]
    async fn shutdown_drains_a_timed_out_write_before_flushing() {
        let (blocking, entered, release) = blocking_exporter();
        let capture = Arc::new(Capture::default());
        let mut emitter = OcsfAuditEmitter::new(sink_cfg(json!({}))).unwrap();
        emitter.exporters = vec![blocking, capture.clone()];
        let emitter = Arc::new(emitter);
        let permit = emitter.output_slot().await.unwrap();
        let writing = {
            let emitter = Arc::clone(&emitter);
            tokio::spawn(async move {
                emitter
                    .emit(json!({ "metadata": { "uid": "record-1" } }), None, permit)
                    .await;
            })
        };
        entered.await.unwrap();

        let mut shutdown = {
            let emitter = Arc::clone(&emitter);
            tokio::spawn(async move { Plugin::shutdown(&*emitter).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
                .await
                .is_err(),
            "shutdown must wait for the detached write"
        );
        assert_eq!(capture.flushes.load(std::sync::atomic::Ordering::SeqCst), 0);

        release.send(()).unwrap();
        writing.await.unwrap();
        shutdown.await.unwrap().unwrap();
        assert_eq!(capture.records.lock().unwrap().len(), 1);
        assert_eq!(capture.flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn drain_waits_for_all_in_flight_writes_before_flushing() {
        let (blocking, entered, release) = blocking_exporter();
        let capture = Arc::new(Capture::default());
        let mut emitter = OcsfAuditEmitter::new(sink_cfg(json!({}))).unwrap();
        emitter.exporters = vec![blocking, capture.clone()];
        let emitter = Arc::new(emitter);

        let mut handles = Vec::new();
        for i in 0..MAX_PENDING_WRITES {
            let permit = emitter.output_slot().await.unwrap();
            let emitter = Arc::clone(&emitter);
            handles.push(tokio::spawn(async move {
                emitter
                    .emit(
                        json!({ "metadata": { "uid": format!("record-{i}") } }),
                        None,
                        permit,
                    )
                    .await;
            }));
        }

        entered.await.unwrap();
        let mut drain = {
            let emitter = Arc::clone(&emitter);
            tokio::spawn(async move { emitter.drain_and_flush(Duration::from_secs(5)).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut drain)
                .await
                .is_err(),
            "drain must wait while a write is in flight"
        );
        assert_eq!(capture.flushes.load(std::sync::atomic::Ordering::SeqCst), 0);

        for _ in 0..MAX_PENDING_WRITES {
            release.send(()).unwrap();
        }
        for handle in handles {
            handle.await.unwrap();
        }
        drain.await.unwrap().unwrap();

        let records = capture.records.lock().unwrap();
        assert_eq!(
            records.len(),
            MAX_PENDING_WRITES,
            "all in-flight writes must complete before drain returns"
        );
        assert_eq!(
            capture.flushes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "flush must run exactly once after drain"
        );
    }

    #[tokio::test]
    async fn stalled_write_makes_shutdown_report_a_timeout() {
        let (blocking, entered, release) = blocking_exporter();
        let capture = Arc::new(Capture::default());
        let mut emitter = OcsfAuditEmitter::new(sink_cfg(json!({}))).unwrap();
        emitter.exporters = vec![blocking, capture.clone()];
        let emitter = Arc::new(emitter);
        let permit = emitter.output_slot().await.unwrap();
        let writing = {
            let emitter = Arc::clone(&emitter);
            tokio::spawn(async move {
                emitter
                    .emit(json!({ "metadata": { "uid": "record-1" } }), None, permit)
                    .await;
            })
        };
        entered.await.unwrap();

        let err = emitter
            .drain_and_flush(Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(*err, PluginError::Timeout { .. }), "{err}");
        assert!(emitter.output_slots.is_closed());
        assert_eq!(capture.flushes.load(std::sync::atomic::Ordering::SeqCst), 1);

        release.send(()).unwrap();
        writing.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_flushes_every_exporter_even_after_one_fails() {
        let first = Arc::new(Capture::default());
        let last = Arc::new(Capture::default());
        let mut e = OcsfAuditEmitter::new(sink_cfg(json!({}))).unwrap();
        let (a, b): (Arc<dyn AuditExporter>, Arc<dyn AuditExporter>) =
            (first.clone(), last.clone());
        e.exporters = vec![a, Arc::new(FailingFlush), b];

        Plugin::shutdown(&e).await.unwrap();

        for capture in [&first, &last] {
            assert_eq!(capture.flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn exported_records_carry_the_stamp_and_uid() {
        use praxis_policy_core::audit::AuditHandler;
        let capture = Arc::new(Capture::default());
        let mut e = OcsfAuditEmitter::new(sink_cfg(json!({ "chain": true }))).unwrap();
        let exporter: Arc<dyn AuditExporter> = capture.clone();
        e.exporters = vec![exporter];

        let mut log = finalized(
            vec![("cedar-pdp", PluginMode::Sequential, PluginAction::Allowed)],
            Verdict::Allow,
        );
        log.set_stream(5, "gw-1:decision".into(), 4, 11);
        AuditHandler::handle(&e, &tool_payload(), &subject_ext(), &log).await;

        let got = capture.records.lock().unwrap();
        assert_eq!(got.len(), 1);
        let stamp = got[0].stamp.as_ref().unwrap();
        assert_eq!(
            (
                stamp.epoch,
                stamp.stream_id.as_str(),
                stamp.stream_seq,
                stamp.emission_seq
            ),
            (5, "gw-1:decision", 4, 11)
        );
        let ev: Value = serde_json::from_slice(&got[0].bytes).unwrap();
        assert_eq!(got[0].uid.as_deref(), ev["metadata"]["uid"].as_str());
        assert!(got[0].uid.is_some());
    }
}
