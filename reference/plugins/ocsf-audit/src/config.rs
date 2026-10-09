// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Operator-facing config for the OCSF audit sink. Follows the audit-logger
// config style (serde, snake_case enums, stderr default) and adds the OCSF
// and attestation settings.

//! Operator configuration: destination, product identity, chaining and
//! signing.

use serde::{Deserialize, Serialize};

/// The `config:` block of an `audit/ocsf` plugin entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcsfAuditConfig {
    /// Where OCSF events go. The stderr default keeps the demo flow
    /// (`docker compose logs -f | jq`) identical to audit-logger.
    #[serde(default)]
    pub destination: OcsfDestination,

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

    /// Stable identifier for this attestation chain (OCSF
    /// `attestation.chain_uid`). If absent, a process-lifetime uid is
    /// derived from the plugin name at startup.
    #[serde(default)]
    pub chain_uid: Option<String>,

    /// Signing mode for the attestation. `none` produces an unsigned
    /// (but still hash-chained) record, which the schema accepts: its
    /// `at_least_one(fingerprint, signatures)` constraint is satisfied by
    /// the fingerprint alone. `dsse` is the production mode and declares
    /// `signatures[0].serialization_id = DSSE`; it requires a key via
    /// exactly one of `signing_key_pem` / `signing_key_pem_path`, and a
    /// missing key fails construction loudly rather than silently
    /// emitting unsigned records.
    #[serde(default)]
    pub signing: SigningMode,

    /// Inline PKCS#8 P-256 private key PEM for `signing: dsse`.
    /// Mutually exclusive with `signing_key_pem_path`. Inline is for
    /// tests, demos and secret-manager injection; operators with a key
    /// file should prefer the path form.
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
