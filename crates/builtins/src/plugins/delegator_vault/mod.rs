// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! PPE delegation handler — `HashiCorp` Vault KV v2 secret retrieval.
//!
//! Resolves downstream credentials from Vault at delegation time. For subjects
//! `user`, `client`, and `caller_workload`, PPE logs in with the caller's JWT;
//! per-caller isolation additionally requires an identity-templated Vault
//! policy bound to that JWT auth mount. `this_workload` authenticates as PPE
//! itself via `AppRole` and normally reads a workload-owned fixed path.

/// Credential cache keyed by subject, resolved path, audience, and credential.
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
