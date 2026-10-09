// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-plugin-ocsf-audit — audit sink that serializes each decision
// the engine finalizes into an OCSF API Activity event, with the ruling
// overlaid as security_control and the per-plugin steps, span, taint,
// content digests and stream stamps under `unmapped`. With chaining on,
// every record carries an attestation whose fingerprint binds it to its
// predecessor, and with a key, a DSSE signature over the same bytes.
//
// It shares the `audit-logger` contract: observation only, always allow,
// factory plus hook wiring. The record shape is the difference: OCSF so a
// SIEM ingests it without a bespoke parser, and a hash chain so a verifier
// with the public key can check the stream offline, without this crate.
//
// Two ways to run it, decided by the `hooks:` list in the plugin config:
//
//   * no `hooks:` (recommended): the plugin attaches as an `AuditHandler`
//     and fires at every pipeline verdict, denials included;
//   * `hooks:` listed: it runs as a CMF post-hook observer on those hooks
//     only, which sees allowed traffic alone, and does not also attach as
//     a sink, so one invocation never emits twice.
//
// The record format is specified host-independently as AID-EMIT-1
// (https://github.com/Levaj2000/AI-Identity/blob/main/docs/specs/aid-emit-1.md);
// the `cpex.*` / `cmf.*` key prefixes under `unmapped` are pinned by that
// specification and do not follow the engine's name. SAMPLE-OUTPUT.md,
// SAMPLE-OUTPUT-DECISIONS.md and SAMPLE-OUTPUT-PROVENANCE.md next to this
// crate are its conformance vectors, produced by the three examples of the
// same name.

//! Audit sink that emits one OCSF API Activity event per decision, with an
//! optional hash-chained, DSSE-signed attestation.
//!
//! Register [`OcsfAuditFactory`] under [`KIND`] and declare the plugin with
//! no `hooks:` to attach it as an audit sink. The event mapping lives in
//! [`ocsf`], the chain and signature in [`emitter`] and [`sign`].

pub mod config;
pub mod emitter;
pub mod factory;
pub mod ocsf;
pub mod sign;

pub use config::{OcsfAuditConfig, OcsfDestination, SigningMode};
pub use emitter::OcsfAuditEmitter;
pub use factory::{KIND, OcsfAuditFactory};
