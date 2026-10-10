// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! PPE delegation handler — `HashiCorp` Vault KV v2 secret retrieval.
//!
//! Resolves downstream credentials from Vault at delegation time, scoped to
//! the caller's identity. For subjects `user`, `client`, and
//! `caller_workload`, PPE logs in to Vault with the caller's own JWT so
//! Vault's own policies enforce per-user isolation. Only `this_workload`
//! authenticates as PPE itself via `AppRole`.

/// Credential cache keyed by resolved principal identity.
pub(crate) mod cache;
/// Plugin configuration and its validation.
pub mod config;
/// The delegation hook handler.
pub mod delegator;
/// Constructs the delegator from configuration.
pub mod factory;
/// Claim resolution per delegation subject, path templating.
pub(crate) mod identity;
/// Vault HTTP API helpers (login, KV read).
pub(crate) mod vault;

pub use config::VaultDelegatorConfig;
pub use delegator::VaultDelegator;
pub use factory::{KIND, VaultDelegatorFactory};
