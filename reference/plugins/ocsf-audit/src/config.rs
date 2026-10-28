// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Operator configuration: exporters, product identity, chaining and
//! signing.

use std::sync::Arc;

use praxis_policy_core::audit::export::{AuditExporter, ExportError, ExporterConfig};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::emitter::TracingExporter;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const MISSING_OUTPUT: &str = "no audit destination configured; set `destination: stderr` or \
                              `destination: tracing`, or list `exporters` (kinds: stderr, \
                              stdout, file, tracing)";

/// The `config:` block of an `audit/ocsf` plugin entry.
///
/// Holds exactly one output. In YAML the entry sets exactly one of
/// `destination` and `exporters`, and an `exporters` list is never empty.
/// Build one in code with [`OcsfAuditConfig::new`].
///
/// ```
/// use praxis_policy_plugin_ocsf_audit::{OcsfAuditConfig, OcsfDestination, OutputSelection};
///
/// let mut config = OcsfAuditConfig::new(OutputSelection::Destination(OcsfDestination::Stderr));
/// config.chain_uid = Some("gateway-eu-1".to_owned());
/// assert!(config.chain, "chaining is on unless the entry turns it off");
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(into = "WireConfig", try_from = "WireConfig")]
pub struct OcsfAuditConfig {
    /// Where OCSF events go: a single `destination`, `stderr` or `tracing`,
    /// or an `exporters` list that can name several. The entry sets one of
    /// the two keys.
    ///
    /// ```yaml
    /// exporters:
    ///   - { kind: file, path: /var/log/ppe/ocsf.ndjson, fsync: batch }
    ///   - { kind: stderr }
    /// ```
    pub output: OutputSelection,

    /// Populates OCSF `metadata.product` so a single collector can
    /// attribute events to a deployment.
    pub product_name: String,

    /// Populates OCSF `metadata.product.vendor_name`.
    pub vendor_name: String,

    /// When true, attach an attestation to every event: compute a
    /// `fingerprint` over the canonical event and reference the previous
    /// event through `prev_event` (its uid, `type_uid` and fingerprint),
    /// forming a tamper-evident chain. This declares the
    /// `record_integrity` profile.
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
    /// `metadata.uid` discards the later records as
    /// replays. Give every process its own value, or leave it unset and
    /// take the per-process default.
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
    pub signing_key_pem: Option<String>,

    /// Path to a PKCS#8 P-256 private key PEM for `signing: dsse`.
    /// Mutually exclusive with `signing_key_pem`.
    pub signing_key_pem_path: Option<String>,

    /// Key identifier (JWKS `kid`) stamped at `unmapped.signature_key_id`,
    /// so a verifier can resolve the public key from the authority's
    /// published key set. Rides in `unmapped`, outside the hashed bytes
    /// like the signature itself, because `digital_signature` has no
    /// member for signature material.
    pub signing_key_id: Option<String>,

    /// OCSF `attestation.authority_uid`: the authority the signing
    /// credential belongs to. Signing keys rotate and expire; this is the
    /// stable party identifier a verifier checks the resolved key
    /// against, which is what defeats a substitution with an
    /// otherwise-valid credential. Part of the hashed canonical
    /// serialization, so it cannot be swapped after the fact without
    /// breaking the fingerprint. Recommended in the schema; set it
    /// whenever signing is on.
    pub authority_uid: Option<String>,

    /// When true (default), fields that have no native OCSF home
    /// (`completion.stop_reason`, `mcp.*`, `framework.*`, the monotonic
    /// security labels) are emitted under OCSF `unmapped` rather than
    /// dropped. That preserves the evidence and keeps the schema gaps
    /// visible in the records themselves.
    pub include_gap_fields: bool,
}

impl OcsfAuditConfig {
    /// A config that writes to `output`, with every other field at its
    /// default.
    #[must_use]
    pub fn new(output: OutputSelection) -> Self {
        Self {
            output,
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

/// Where the sink writes: one destination, or a list of exporters that each
/// receive every record byte for byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutputSelection {
    /// The `destination` key: `stderr` or `tracing`.
    Destination(OcsfDestination),
    /// The `exporters` key: one or more exporters.
    Exporters(ExporterList),
}

impl OutputSelection {
    /// The exporters this selection names, opened and ready to write.
    ///
    /// # Errors
    ///
    /// Returns an error if an exporter cannot be opened, such as a `file`
    /// path that is not absolute or not writable.
    pub fn build_exporters(&self) -> Result<Vec<Arc<dyn AuditExporter>>, ExportError> {
        match self {
            Self::Destination(OcsfDestination::Tracing) => Ok(vec![Arc::new(TracingExporter)]),
            Self::Destination(OcsfDestination::Stderr) => Ok(vec![ExporterConfig::Stderr.build()?]),
            Self::Exporters(list) => list
                .as_slice()
                .iter()
                .map(OcsfExporterConfig::build)
                .collect(),
        }
    }
}

/// A nonempty `exporters` list.
///
/// ```
/// use praxis_policy_plugin_ocsf_audit::{
///     ExporterList, OcsfExporterConfig, OutputSelectionError, TracingTag,
/// };
///
/// let list = ExporterList::try_from(vec![OcsfExporterConfig::Tracing(TracingTag::Tracing)])?;
/// assert_eq!(list.as_slice().len(), 1);
/// assert!(
///     matches!(ExporterList::try_from(vec![]), Err(OutputSelectionError::Empty)),
///     "an empty list is refused"
/// );
/// # Ok::<(), OutputSelectionError>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExporterList(Vec<OcsfExporterConfig>);

impl ExporterList {
    /// The entries, in the order records are written to them.
    #[must_use]
    pub fn as_slice(&self) -> &[OcsfExporterConfig] {
        &self.0
    }
}

impl TryFrom<Vec<OcsfExporterConfig>> for ExporterList {
    type Error = OutputSelectionError;

    fn try_from(entries: Vec<OcsfExporterConfig>) -> Result<Self, Self::Error> {
        if entries.is_empty() {
            return Err(OutputSelectionError::Empty);
        }
        Ok(Self(entries))
    }
}

/// Why a `config:` block does not select an output.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OutputSelectionError {
    /// Both `destination` and `exporters` are set.
    #[error("set either `destination` or `exporters`, not both")]
    Conflicting,
    /// `exporters` is set but names nothing.
    #[error("`exporters` is empty; name at least one of stderr, stdout, file or tracing")]
    Empty,
    /// Neither key is set; null counts as unset.
    #[error("{MISSING_OUTPUT}")]
    Missing,
}

/// Where a record is written when `destination` is set.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

/// The `config:` block as the entry writes it, with `destination` and
/// `exporters` as two keys. The checked conversion into [`OcsfAuditConfig`]
/// is where an entry that selects no single output is refused.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireConfig {
    #[serde(default)]
    authority_uid: Option<String>,
    #[serde(default = "default_true")]
    chain: bool,
    #[serde(default)]
    chain_uid: Option<String>,
    #[serde(default)]
    destination: Option<OcsfDestination>,
    #[serde(default)]
    exporters: Option<Vec<OcsfExporterConfig>>,
    #[serde(default = "default_true")]
    include_gap_fields: bool,
    #[serde(default = "default_product_name")]
    product_name: String,
    #[serde(default)]
    signing: SigningMode,
    #[serde(default)]
    signing_key_id: Option<String>,
    #[serde(default)]
    signing_key_pem: Option<String>,
    #[serde(default)]
    signing_key_pem_path: Option<String>,
    #[serde(default = "default_vendor_name")]
    vendor_name: String,
}

impl TryFrom<WireConfig> for OcsfAuditConfig {
    type Error = OutputSelectionError;

    fn try_from(wire: WireConfig) -> Result<Self, Self::Error> {
        let output = match (wire.destination, wire.exporters) {
            (None, None) => return Err(OutputSelectionError::Missing),
            (Some(_), Some(_)) => return Err(OutputSelectionError::Conflicting),
            (Some(destination), None) => OutputSelection::Destination(destination),
            (None, Some(entries)) => OutputSelection::Exporters(ExporterList::try_from(entries)?),
        };
        Ok(Self {
            output,
            product_name: wire.product_name,
            vendor_name: wire.vendor_name,
            chain: wire.chain,
            chain_uid: wire.chain_uid,
            signing: wire.signing,
            signing_key_pem: wire.signing_key_pem,
            signing_key_pem_path: wire.signing_key_pem_path,
            signing_key_id: wire.signing_key_id,
            authority_uid: wire.authority_uid,
            include_gap_fields: wire.include_gap_fields,
        })
    }
}

impl From<OcsfAuditConfig> for WireConfig {
    fn from(config: OcsfAuditConfig) -> Self {
        let (destination, exporters) = match config.output {
            OutputSelection::Destination(destination) => (Some(destination), None),
            OutputSelection::Exporters(list) => (None, Some(list.0)),
        };
        Self {
            authority_uid: config.authority_uid,
            chain: config.chain,
            chain_uid: config.chain_uid,
            destination,
            exporters,
            include_gap_fields: config.include_gap_fields,
            product_name: config.product_name,
            signing: config.signing,
            signing_key_id: config.signing_key_id,
            signing_key_pem: config.signing_key_pem,
            signing_key_pem_path: config.signing_key_pem_path,
            vendor_name: config.vendor_name,
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn default_product_name() -> String {
    "Praxis Policy Engine OCSF Audit".to_owned()
}

fn default_vendor_name() -> String {
    "Praxis".to_owned()
}

fn default_true() -> bool {
    true
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_config_built_in_code_matches_a_destination_only_block() -> TestResult {
        let built = OcsfAuditConfig::new(OutputSelection::Destination(OcsfDestination::Stderr));
        let parsed: OcsfAuditConfig = serde_json::from_value(json!({ "destination": "stderr" }))?;

        assert_eq!(
            serde_json::to_value(built)?,
            serde_json::to_value(parsed)?,
            "code and YAML must agree on every default"
        );
        Ok(())
    }

    #[test]
    fn each_destination_builds_its_one_exporter() -> TestResult {
        let stderr = OutputSelection::Destination(OcsfDestination::Stderr).build_exporters()?;
        let tracing = OutputSelection::Destination(OcsfDestination::Tracing).build_exporters()?;

        assert_eq!(
            exporter_names(&stderr),
            ["stderr"],
            "destination stderr must build one stderr exporter"
        );
        assert_eq!(
            exporter_names(&tracing),
            ["tracing"],
            "destination tracing must build one tracing exporter"
        );
        Ok(())
    }

    #[test]
    fn an_exporter_list_builds_every_entry_in_order() -> TestResult {
        let list = ExporterList::try_from(vec![
            OcsfExporterConfig::Tracing(TracingTag::Tracing),
            OcsfExporterConfig::Builtin(ExporterConfig::Stdout),
        ])?;
        let exporters = OutputSelection::Exporters(list).build_exporters()?;

        assert_eq!(
            exporter_names(&exporters),
            ["tracing", "stdout"],
            "exporters must build in list order"
        );
        Ok(())
    }

    #[test]
    fn an_empty_exporter_list_cannot_be_constructed() {
        assert!(
            matches!(
                ExporterList::try_from(vec![]),
                Err(OutputSelectionError::Empty)
            ),
            "an empty list must be refused at construction"
        );
    }

    #[test]
    fn missing_conflicting_null_and_empty_selections_fail_to_parse() {
        for (block, expected) in [
            (json!({}), OutputSelectionError::Missing),
            (json!({ "chain": true }), OutputSelectionError::Missing),
            (
                json!({ "destination": null }),
                OutputSelectionError::Missing,
            ),
            (json!({ "exporters": null }), OutputSelectionError::Missing),
            (
                json!({ "destination": null, "exporters": null }),
                OutputSelectionError::Missing,
            ),
            (
                json!({ "destination": "stderr", "exporters": [{ "kind": "stderr" }] }),
                OutputSelectionError::Conflicting,
            ),
            (json!({ "exporters": [] }), OutputSelectionError::Empty),
        ] {
            let message = serde_json::from_value::<OcsfAuditConfig>(block.clone())
                .err()
                .map(|err| err.to_string());

            assert_eq!(
                message,
                Some(expected.to_string()),
                "{block} must fail with the {expected:?} message"
            );
        }
    }

    #[test]
    fn the_missing_output_error_lists_every_option() {
        let message = OutputSelectionError::Missing.to_string();

        for needle in [
            "destination",
            "exporters",
            "stderr",
            "tracing",
            "stdout",
            "file",
        ] {
            assert!(
                message.contains(needle),
                "the error must name {needle}: {message}"
            );
        }
    }

    #[test]
    fn unknown_keys_are_still_rejected() {
        let message = serde_json::from_value::<OcsfAuditConfig>(json!({
            "destination": "stderr",
            "destinations": "stdout",
        }))
        .err()
        .map(|err| err.to_string());

        assert!(
            message
                .as_deref()
                .is_some_and(|text| text.contains("destinations")),
            "an unknown key must fail the parse and be named: {message:?}"
        );
    }

    #[test]
    fn a_null_beside_a_set_key_is_ignored() -> TestResult {
        let parsed: OcsfAuditConfig = serde_json::from_value(json!({
            "destination": null,
            "exporters": [{ "kind": "stdout" }],
        }))?;

        assert_eq!(
            parsed.output,
            OutputSelection::Exporters(ExporterList::try_from(vec![OcsfExporterConfig::Builtin(
                ExporterConfig::Stdout
            )])?),
            "an explicit null must read as absent"
        );
        Ok(())
    }

    #[test]
    fn both_shapes_round_trip_on_the_wire() -> TestResult {
        let destination = json!({ "destination": "tracing", "chain": false });
        let exporters = json!({
            "exporters": [{ "kind": "tracing" }, { "kind": "stdout" }],
            "vendor_name": "Acme",
        });

        for block in [destination, exporters] {
            let parsed: OcsfAuditConfig = serde_json::from_value(block.clone())?;
            let wire = serde_json::to_value(&parsed)?;
            let reparsed: OcsfAuditConfig = serde_json::from_value(wire.clone())?;

            for (key, value) in block.as_object().into_iter().flatten() {
                assert_eq!(
                    wire.get(key),
                    Some(value),
                    "{key} must serialize as it was written"
                );
            }
            assert_eq!(
                wire.as_object().map(serde_json::Map::len),
                Some(12),
                "the wire shape keeps both output keys: {wire}"
            );
            assert_eq!(
                serde_json::to_value(reparsed)?,
                wire,
                "a serialized config must parse back to the same wire form"
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn exporter_names(exporters: &[Arc<dyn AuditExporter>]) -> Vec<String> {
        exporters
            .iter()
            .map(|exporter| exporter.name().to_owned())
            .collect()
    }
}
