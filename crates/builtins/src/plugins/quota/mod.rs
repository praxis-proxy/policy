// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Experimental per-consumer token quota, enforced as a policy against a
//! standalone Limitador. A pre-invoke check on `cmf.llm_input` and a post-invoke
//! debit on `cmf.llm_output`, keyed on the resolved identity. The counter lives
//! in Limitador, so the budget survives restarts and stays correct across replicas.
//!
//! Stability: experimental (`experimental-quota` feature). Not covered by semver;
//! not for production.
//!
//! Config must declare `capabilities: [read_subject, perform_http]`, plus
//! `read_claims` for a non-`sub` claim. Without a resolved identity the check
//! denies with `quota.no_identity` unless `allow_unauthenticated` is enabled.
//!
//! Trust boundary: the debited amount is the upstream's self-reported usage.
//! When usage cannot be determined (streaming, or an absent field) the plugin
//! debits a conservative `missing_usage_charge`, not nothing, so the balance
//! always moves. A streamed response typically has no typed usage, so it debits
//! that fallback; it never rides free, but it under-meters if the fallback is
//! below the stream's real usage. The check cannot fail a stream closed (the CMF
//! payload carries no request `stream` flag), so accurate stream metering needs
//! the gateway to aggregate streamed usage into the typed completion usage.
//! `identity_claim` must name a verified subject id.
//!
//! Fail-closed reconciliation: the post-invoke `/report` finishes before the
//! handler returns, using only its invocation-scoped host transport. A slow
//! Limitador can extend the response tail up to the configured timeout. A failed
//! `/report` is recorded per principal and re-reported on the next admission,
//! which is denied until it lands. Limitador
//! `/report` is not idempotent, so a retry after an ambiguous loss may over-charge
//! (the safe direction). The guard state is in-process: lost on restart and not
//! shared across replicas, so the residual leak is bounded per replica, not the
//! unbounded free-request stream a dropped debit caused before. The Limitador
//! counter stays the source of truth.
//!
//! Transport: the plugin performs no HTTP itself; it uses the host transport from
//! `Extensions`. An in-cluster Limitador needs a transport that allows private
//! destinations (`HyperTransport::with_allow_private_destinations`); the default
//! helper refuses RFC 1918 addresses.
//!
//! Consistency: the check precedes the request and the debit follows the response,
//! so concurrent requests can briefly burst past the budget before the counter
//! catches up. Strict pre-charge admission needs Limitador's gRPC Reserve and
//! Commit, absent from released Limitador. Deployment requires an authenticated,
//! network-restricted Limitador.

// The backend contract (trait, verdict, error) is crate-internal: there is no
// public constructor that accepts a custom backend yet, so keeping the types
// unexported avoids committing to that surface prematurely.
mod backend;
/// Plugin configuration and its validation.
pub mod config;
/// Constructs the plugin from configuration.
pub mod factory;
/// The pre-invoke check and post-invoke debit hook handlers.
pub mod handlers;

// Private so no Limitador type reaches the public surface.
mod client;

pub use config::{OnErrorMode, QuotaConfig};
pub use factory::{KIND, QuotaFactory};
pub use handlers::{
    CODE_QUOTA_BACKEND_UNAVAILABLE, CODE_QUOTA_EGRESS_DENIED, CODE_QUOTA_EXHAUSTED,
    CODE_QUOTA_NO_IDENTITY, CODE_QUOTA_UNSETTLED_DEBIT, Quota, QuotaCheck, QuotaReport,
};
