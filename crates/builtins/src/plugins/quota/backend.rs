// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The backend contract the quota plugin meters through: a check and a debit.
// The core holds a `dyn QuotaBackend`, so a second backend needs no handler
// change. LimitadorClient (client.rs) is the one implementor.

use async_trait::async_trait;
use praxis_policy_core::hooks::Extensions;

/// Verdict of a backend `check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Within budget: the request may proceed.
    WithinLimit,
    /// Over budget: the request must be refused.
    OverLimit,
}

/// Whether a [`BackendError`] is a transient failure or a permanent fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorKind {
    /// A transient failure reaching the backend: a timeout, a refused
    /// connection, a dropped socket, or an unrecognized status. The peer may
    /// recover, so the caller's `on_error` posture governs it.
    Transport,
    /// A permanent fault that no retry or backend recovery fixes: no host
    /// transport is installed, the plugin lacks the `perform_http` capability,
    /// or the request could not be constructed. `on_error` does not apply,
    /// because it governs an unreachable Limitador, not a misconfigured plugin;
    /// the caller must never serve unmetered on it.
    Unavailable,
    /// The host refused to send the request at all: an egress policy, an SSRF
    /// guard, or an open circuit. Never reached the peer, and no retry helps,
    /// so like [`Self::Unavailable`] it fails closed regardless of `on_error`;
    /// kept distinct so the denial points an operator at egress config rather
    /// than at a Limitador that is actually healthy.
    EgressDenied,
}

/// A backend call that failed or answered unrecognizably. Distinct from an
/// over-limit verdict, which is a successful [`CheckOutcome`].
#[derive(Debug)]
pub struct BackendError {
    /// Human-readable cause, for logs and fail-closed denials.
    pub message: String,
    /// Whether the failure is transient (`on_error` applies) or a permanent
    /// wiring/capability fault (always deny).
    pub kind: BackendErrorKind,
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Where a per-principal budget is checked and debited, keyed on a descriptor
/// (`descriptor_key: descriptor_value`) resolved from identity.
///
/// The outbound call runs through the host's HTTP transport, reached via
/// `ext`, so the process keeps one connection pool and TLS stack. A backend
/// holds no HTTP client of its own.
#[async_trait]
pub trait QuotaBackend: std::fmt::Debug + Send + Sync {
    /// Whether the descriptor is within budget, charging nothing.
    ///
    /// # Errors
    ///
    /// [`BackendError`] when the call cannot complete or is unrecognizable.
    /// Its [`BackendError::kind`] tells the caller whether the failure is a
    /// transient backend problem (`on_error` applies) or a permanent wiring
    /// fault such as a withheld `perform_http` (always deny).
    async fn check(
        &self,
        ext: &Extensions,
        descriptor_key: &str,
        descriptor_value: &str,
    ) -> Result<CheckOutcome, BackendError>;

    /// Debit `delta` against the descriptor, recording the spend.
    ///
    /// # Errors
    ///
    /// [`BackendError`] when the call cannot complete. The caller logs it and
    /// never denies.
    async fn report(
        &self,
        ext: &Extensions,
        descriptor_key: &str,
        descriptor_value: &str,
        delta: u64,
    ) -> Result<(), BackendError>;
}
