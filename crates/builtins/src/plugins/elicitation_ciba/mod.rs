// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Out-of-band human approval over OIDC CIBA.
//!
//! Register the handler on the `elicit` hook and select it in APL with
//! `require_approval`. The [`store`] module holds approvals between dispatch,
//! check, and validate. By default, approvals stay in process memory.
//!
//! [`store`]: crate::plugins::elicitation_ciba::store

/// The elicitation hook handler.
pub mod approver;
/// Plugin configuration and its validation.
pub mod config;
/// Constructs the approver from configuration.
pub mod factory;
/// Tracks pending approvals across the requests that poll them.
pub mod store;
/// Valkey-backed correlations shared across replicas.
#[cfg(feature = "valkey")]
pub mod valkey_store;

pub use approver::CibaApprover;
pub use config::{CibaConfig, ClientSecretSource, MemoryStoreConfig, StoreConfig};
pub use factory::{CibaApproverFactory, KIND};
pub use store::{Correlation, CorrelationStore, InMemoryCorrelationStore, StoreError, TakeResult};
#[cfg(feature = "valkey")]
pub use valkey_store::{SettingsError, ValkeyCorrelationStore};
