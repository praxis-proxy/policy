// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Valkey session store: a Valkey-backed `praxis_policy_apl_runtime::SessionStore` for
// distributed, cross-restart persistence of session security labels.
//
// # Where this sits
//
//   praxis-policy-apl-runtime (SessionStore trait, SessionStoreFactory)
//        ▲
//        │ implements
//   praxis-policy-builtins  ──uses──▶  redis-rs + deadpool-redis (rustls)
//
// The host registers `ValkeySessionStoreFactory` via
// `AplOptions.session_store_factories`; a `global.session_store:
// { kind: valkey, ... }` block then selects it during config load. When
// no such block is present, praxis-policy-apl-runtime keeps its default in-process
// `MemorySessionStore`, so this store is entirely opt-in.
//
// # Design invariants (carried from the requirements/plan)
//
//   - Fail-closed: any backend error (unreachable, timeout, undecodable)
//     becomes `SessionStoreError`; only a confirmed key-miss is empty.
//   - Atomic union: `append_labels` is a single server-side `SADD`.
//   - Primary-only: a single endpoint, no replica read-splitting.
//   - TLS required off-localhost; `noeviction` is an operator runbook
//     concern the client can only warn about.
//
// The connection layer is kept internal (no public reusable API): the
// planned OAuth token cache is the trigger to extract a shared layer
// later, shaped by two real consumers.

//! Valkey-backed session store for security labels.
//!
//! Keeps accumulated session taint outside the process so it survives a restart
//! and is shared across gateway instances. Label sets merge server-side, so
//! concurrent appends from different nodes cannot lose a label.

/// Store configuration and its validation.
mod config;
/// Connection setup, including TLS and authentication.
mod connection;
/// Errors raised while building or reaching the store.
mod error;
/// Constructs the store from configuration.
mod factory;
/// The `SessionStore` implementation.
mod store;

pub use config::ValkeyConfig;
pub use error::BuildError;
pub use factory::{KIND, ValkeySessionStoreFactory};
pub use store::ValkeySessionStore;
