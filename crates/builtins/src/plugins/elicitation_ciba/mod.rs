// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Out-of-band human approval over OIDC CIBA.
//!
//! Handles the elicitation hook, which a policy selects by name. Each dispatch,
//! check, and validate maps onto the backchannel authentication flow, so a
//! request can wait on a person without holding the connection open.
//!
//! The host registers this handler against the `elicit` hook; APL
//! policies select it by name (`require_approval(manager-approver, ...)`).
//! The praxis-policy-apl-runtime bridge invokes it once per dispatch / check / validate
//! across the elicitation's lifetime; this module turns each into the
//! corresponding CIBA round-trip against the configured OP (Keycloak by
//! default).
//!
//! See the module docs for the per-operation flow:
//!   * [`config`] — typed `config:` block.
//!   * [`store`]  — in-flight correlation store (in-memory v1).
//!   * [`approver`] — the handler + CIBA HTTP.
//!   * [`factory`]  — `kind: elicitation/ciba` registration.

/// The elicitation hook handler.
pub mod approver;
/// Plugin configuration and its validation.
pub mod config;
/// Constructs the approver from configuration.
pub mod factory;
/// Tracks pending approvals across the requests that poll them.
pub mod store;

pub use approver::CibaApprover;
pub use config::{CibaConfig, ClientSecretSource};
pub use factory::{CibaApproverFactory, KIND};
pub use store::{Correlation, CorrelationStore, InMemoryCorrelationStore};
