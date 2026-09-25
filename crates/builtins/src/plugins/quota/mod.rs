// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Durable per-consumer token quota, enforced as a policy against a standalone
//! Limitador. A pre-invoke check on `cmf.llm_input` and a post-invoke debit on
//! `cmf.llm_output`, keyed on the resolved identity. The counter lives in
//! Limitador, so the budget survives restarts and stays correct across replicas.
//!
//! Config must declare `capabilities: [read_subject]`, plus `read_claims` for a
//! claim key. An undeclared identity filters to `None` and nothing meters.
//!
//! Trust boundary: the debited amount is the upstream's self-reported usage, so a
//! usage-omitting provider is not metered. Assumes a first-party, honest upstream.
//! `identity_claim` must name a verified subject id, never a self-asserted claim.
//!
//! Consistency: the check precedes the request and the debit follows the response,
//! so concurrent requests can briefly burst past the budget before the counter
//! catches up. The overrun is bounded and self-correcting. Strict pre-charge
//! admission needs Limitador's gRPC Reserve and Commit, absent from released
//! Limitador. Deployment requires an authenticated, network-restricted Limitador.

/// The backend contract: the trait, its verdict, and its error.
pub mod backend;
/// Plugin configuration and its validation.
pub mod config;
/// Constructs the plugin from configuration.
pub mod factory;
/// The pre-invoke check and post-invoke debit hook handlers.
pub mod handlers;

// Private so no Limitador type reaches the public surface.
mod client;

pub use backend::{BackendError, CheckOutcome, QuotaBackend};
pub use config::{OnErrorMode, QuotaConfig};
pub use factory::{KIND, QuotaFactory};
pub use handlers::{
    CODE_QUOTA_BACKEND_UNAVAILABLE, CODE_QUOTA_EXHAUSTED, Quota, QuotaCheck, QuotaReport,
};
