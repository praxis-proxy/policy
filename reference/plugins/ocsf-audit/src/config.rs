// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Operator-facing config for the OCSF audit sink. Follows the audit-logger
// config style (serde, snake_case enums, stderr default) and adds the OCSF
// and attestation settings.

//! Operator configuration: exporters, product identity, chaining and
//! signing.

use std::sync::Arc;

use praxis_policy_core::audit::export::{AuditExporter, ExportError, ExporterConfig};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::emitter::TracingExporter;

/// The `config:` block of an `audit/ocsf` plugin entry.
///
/// `Default` is written out below rather than derived, so that the defaults
/// an entry gets by omitting the whole `config:` block are the ones
/// documented on the fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcsfAuditConfig {
    /// Where OCSF events go, as a single destination: `stderr` or
    /// `tracing`. Mutually exclusive with `exporters`, which can name
    /// several. With neither set, records go to stderr, which keeps the
    /// demo flow (`docker compose logs -f | jq`) identical to audit-logger.
    #[serde(default)]
    pub destination: Option<OcsfDestination>,

    /// Where OCSF events go, as a list of exporters. Every record is
    /// written, byte for byte, to each one. Mutually exclusive with
    /// `destination`; an empty list is rejected.
    ///
    /// ```yaml
    /// exporters:
    ///   - { kind: file, path: /var/log/ppe/ocsf.ndjson, fsync: batch }
    ///   - { kind: stderr }
    /// ```
    #[serde(default)]
    pub exporters: Option<Vec<OcsfExporterConfig>>,

    /// Populates OCSF `metadata.product` so a single collector can
    /// attribute events to a deployment.
    #[serde(default = "default_product_name")]
    pub product_name: String,

    /// Populates OCSF `metadata.product.vendor_name`.
    #[serde(default = "default_vendor_name")]
    pub vendor_name: String,

    /// When true, attach an attestation to every event: compute a
    /// `fingerprint` over the canonical event and reference the previous
    /// event through `prev_event` (its uid, `type_uid` and fingerprint),
    /// forming a tamper-evident chain. This declares the
    /// `record_integrity` profile.
    #[serde(default = "default_true")]
    pub chain: bool,

    /// Identifier for this attestation chain (OCSF
    /// `attestation.chain_uid`). If absent, one is minted at startup from
    /// the plugin name and a random per-process component.
    ///
    /// A chain lives for one process: the sequence restarts at zero with
    /// no predecessor on every start, and `metadata.uid` is
    /// `<chain_uid>-<seq>`, so the uids are unique only within that
    /// process. Two processes sharing a configured `chain_uid`, a restart
    /// or a replica, mint colliding uids, and a consumer deduplicating by
    /// `metadata.uid` (AID-EMIT-1 section 6) discards the later records as
    /// replays. Give every process its own value, or leave it unset and
    /// take the per-process default.
    #[serde(default)]
    pub chain_uid: Option<String>,

    /// Signing mode for the attestation. `none` produces an unsigned
    /// (but still hash-chained) record, which the schema accepts: its
    /// `at_least_one(fingerprint, signatures)` constraint is satisfied by
    /// the fingerprint alone. `dsse` is the production mode and declares
    /// `signatures[0].serialization_id = DSSE`; it requires a key via
    /// exactly one of `signing_key_pem` / `signing_key_pem_path`, and a
    /// missing key fails construction loudly rather than silently
    /// emitting unsigned records. Through the factory, use the path form:
    /// the engine retains its plugin config.
    #[serde(default)]
    pub signing: SigningMode,

    /// Inline PKCS#8 P-256 private key PEM for `signing: dsse`.
    /// Mutually exclusive with `signing_key_pem_path`. Only direct
    /// `OcsfAuditEmitter::new` callers (tests and demos) may use this:
    /// `OcsfAuditFactory` rejects it because the engine retains an
    /// independent, unsanitized copy of its plugin config. Operators must
    /// use the path form.
    ///
    /// Consumed at direct construction: the emitter zeroizes and clears
    /// this field and its own raw plugin config, whatever `signing` is set
    /// to. A caller that kept another config copy must clear that copy.
    #[serde(default)]
    pub signing_key_pem: Option<String>,

    /// Path to a PKCS#8 P-256 private key PEM for `signing: dsse`.
    /// Mutually exclusive with `signing_key_pem`.
    #[serde(default)]
    pub signing_key_pem_path: Option<String>,

    /// Key identifier (JWKS `kid`) stamped at `unmapped.signature_key_id`,
    /// so a verifier can resolve the public key from the authority's
    /// published key set. Rides in `unmapped`, outside the hashed bytes
    /// like the signature itself, because `digital_signature` has no
    /// member for signature material; that gap is filed as
    /// ocsf-schema#1709.
    #[serde(default)]
    pub signing_key_id: Option<String>,

    /// OCSF `attestation.authority_uid`: the authority the signing
    /// credential belongs to. Signing keys rotate and expire; this is the
    /// stable party identifier a verifier checks the resolved key
    /// against, which is what defeats a substitution with an
    /// otherwise-valid credential. Part of the hashed canonical
    /// serialization, so it cannot be swapped after the fact without
    /// breaking the fingerprint. Recommended in the schema; set it
    /// whenever signing is on.
    #[serde(default)]
    pub authority_uid: Option<String>,

    /// When true (default), fields that have no native OCSF home
    /// (`completion.stop_reason`, `mcp.*`, `framework.*`, the monotonic
    /// security labels) are emitted under OCSF `unmapped` rather than
    /// dropped. That preserves the evidence and keeps the schema gaps
    /// visible in the records themselves.
    #[serde(default = "default_true")]
    pub include_gap_fields: bool,
}

impl Default for OcsfAuditConfig {
    /// The same values the `#[serde(default ...)]` attributes above supply,
    /// through the same functions. A derived `Default` would give `chain`
    /// and `include_gap_fields` as `false`, which is not what the fields
    /// say and not what an entry with a `config: {}` block gets: a sink
    /// running on its defaults would emit records with no attestation, no
    /// fingerprint and no signature, and nothing would say so.
    fn default() -> Self {
        Self {
            destination: None,
            exporters: None,
            product_name: default_product_name(),
            vendor_name: default_vendor_name(),
            chain: default_true(),
            chain_uid: None,
            signing: SigningMode::default(),
            signing_key_pem: None,
            signing_key_pem_path: None,
            signing_key_id: None,
            authority_uid: None,
            include_gap_fields: default_true(),
        }
    }
}

fn default_product_name() -> String {
    "Praxis Policy Engine OCSF Audit".to_owned()
}
fn default_vendor_name() -> String {
    "Praxis".to_owned()
}
fn default_true() -> bool {
    true
}

/// Where a record is written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcsfDestination {
    /// One OCSF JSON object per line to stderr.
    #[default]
    Stderr,
    /// Emit via `tracing::info!` at target `ocsf.audit`.
    Tracing,
}

/// One entry of `exporters`: a built-in exporter from the engine, or
/// `{ kind: tracing }`, which emits at target `ocsf.audit` as
/// `destination: tracing` does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum OcsfExporterConfig {
    /// `stderr`, `stdout` or `file`.
    Builtin(ExporterConfig),
    /// `tracing` at target `ocsf.audit`.
    Tracing(TracingTag),
}

/// The `{ kind: tracing }` exporter entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TracingTag {
    /// The only value.
    Tracing,
}

impl<'de> Deserialize<'de> for OcsfExporterConfig {
    /// `tracing` is checked by hand so every other kind is parsed by
    /// `ExporterConfig` itself and keeps its own error messages.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Value::deserialize(deserializer)?;
        if raw.get("kind").and_then(Value::as_str) == Some("tracing") {
            if raw.as_object().is_some_and(|m| m.len() > 1) {
                return Err(serde::de::Error::custom(
                    "the tracing exporter takes no settings besides `kind`",
                ));
            }
            return Ok(Self::Tracing(TracingTag::Tracing));
        }
        ExporterConfig::deserialize(raw)
            .map(Self::Builtin)
            .map_err(serde::de::Error::custom)
    }
}

impl OcsfExporterConfig {
    /// Build the exporter this entry names.
    ///
    /// # Errors
    ///
    /// A built-in exporter that cannot be opened, such as a `file` path that
    /// is not absolute or not writable.
    pub fn build(&self) -> Result<Arc<dyn AuditExporter>, ExportError> {
        match self {
            Self::Builtin(cfg) => cfg.build(),
            Self::Tracing(TracingTag::Tracing) => Ok(Arc::new(TracingExporter)),
        }
    }
}

impl OcsfAuditConfig {
    /// The exporters records go to: `exporters` when set, otherwise the one
    /// `destination` names, otherwise stderr.
    ///
    /// # Errors
    ///
    /// `destination` and `exporters` both set, an empty `exporters` list, or
    /// an exporter that cannot be opened.
    pub fn build_exporters(&self) -> Result<Vec<Arc<dyn AuditExporter>>, ExportError> {
        match (&self.destination, &self.exporters) {
            (Some(_), Some(_)) => Err(ExportError::Config(
                "set either `destination` or `exporters`, not both".to_owned(),
            )),
            (_, Some(list)) if list.is_empty() => Err(ExportError::Config(
                "`exporters` is empty; name at least one, or omit it for stderr".to_owned(),
            )),
            (_, Some(list)) => list.iter().map(OcsfExporterConfig::build).collect(),
            (Some(OcsfDestination::Tracing), None) => Ok(vec![Arc::new(TracingExporter)]),
            (Some(OcsfDestination::Stderr) | None, None) => {
                Ok(vec![ExporterConfig::Stderr.build()?])
            },
        }
    }
}

/// How the attestation is signed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningMode {
    /// Hash-chained but unsigned. For the demo and for environments where
    /// the signing key is not provisioned yet.
    #[default]
    None,
    /// DSSE-signed (`digital_signature.serialization_id` 5):
    /// ECDSA-P256-SHA256 over the PAE of the event's canonical bytes; see
    /// `sign.rs`. Requires a key.
    Dsse,
}
