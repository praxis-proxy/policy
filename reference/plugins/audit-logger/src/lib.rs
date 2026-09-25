// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-plugin-audit-logger — CMF plugin that emits one structured JSON
// audit record per dispatched request. The record captures:
//
//   * timestamp + correlation id
//   * subject (id, roles, teams) and client (client_id, name)
//   * entity (type + name) and tool args summary
//   * delegation outcomes (which audiences got tokens, which
//     scopes were granted)
//
// Mode: always allow — the plugin is observation-only. Operators
// who want to halt on audit failure would compose this with a
// downstream policy step.
//
// Output:
//
//   * `destination: stderr` (default) — one JSON line per call,
//     handy for the demo's `docker compose logs -f` flow.
//   * `destination: tracing` — emit as a structured `tracing::info!`
//     so it lands in whatever the host's subscriber routes to.
//
// Capabilities the operator wires in YAML under `capabilities:`. The
// extensions a sink is handed are filtered against them exactly as a
// hook plugin's are, so a grant left out is a field this logger
// silently omits rather than an error it reports:
//
//   * `read_subject`           — for sub / roles / teams / claims
//   * `read_client`            — for client_id / client_name
//   * `read_labels`            — for the taint diff
//   * `read_delegated_tokens`  — to surface what got minted

//! Emits one structured JSON audit record per dispatched request.
//!
//! Records the subject and client, the entity being called, an argument
//! summary, and the delegation outcomes. Observation only: it never denies. The
//! delegation detail is the part that makes the trail evidence, since it shows
//! which audience received which scopes.

/// Plugin configuration, including the output destination.
pub mod config;
/// Constructs the logger from configuration.
pub mod factory;
/// Builds and emits the audit record.
pub mod logger;

pub use config::{AuditDestination, AuditLoggerConfig};
pub use factory::{AuditLoggerFactory, KIND};
pub use logger::AuditLogger;
