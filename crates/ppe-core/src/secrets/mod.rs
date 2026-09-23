// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Secret material the engine resolves ahead of serving and re-reads on demand.
//
// A provider addresses one backend: an environment variable, a file, later a
// vault. A declared value binds a name to one provider and one reference.
// Everything downstream names the value and never the provider or a raw
// reference, which is what keeps the set of reachable secrets finite and
// enumerable at config load: an operator can read the `values:` block and know
// exactly what the process can reach.
//
// Resolution is fail-fast and completes before the engine serves. A value that
// cannot be resolved stops startup rather than leaving a consumer to find the
// gap on a request, because there is no degraded-but-serving state for a
// credential that was never read once.
//
// After startup, `refresh` replaces values in place and a failed refresh keeps
// the last-good value: a stale credential still serves traffic and a missing
// one does not. Refresh is driven by the host rather than by a task this module
// spawns. A spawned ticker binds to whichever runtime started it, and a host
// that initializes on a short-lived runtime loses it before it ticks once,
// which is silent and indistinguishable from a secret that never rotates.

/// The `secrets:` block: declared providers and the values bound to them.
pub mod config;
/// Why a secret did not resolve.
pub mod error;
/// The provider trait, its factory, and the registry of factories by kind.
pub mod provider;
/// Resolved values, the handles consumers hold, and refresh.
pub mod store;

/// Providers with no dependencies beyond the standard library.
pub mod backends;

pub use config::{SecretProviderConfig, SecretValueConfig, SecretsConfig};
pub use error::SecretError;
pub use provider::{SecretProvider, SecretProviderFactory, SecretProviderRegistry};
pub use store::{RefreshReport, SecretRef, SecretStore};
