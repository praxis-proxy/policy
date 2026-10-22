// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `ValkeySessionStore` — the Valkey-backed `SessionStore`. Labels live in
// a Redis SET per session so `append_labels` is a single atomic
// server-side union (`SADD`), never a client-side read-modify-write that
// would lose labels under concurrent cross-node appends.
//
// # Fail-closed mapping
//
//   - `SMEMBERS` on a missing key returns an empty set → `Ok(empty)`
//     (unknown session). It is NOT an error.
//   - connection/timeout/protocol/decode failures → `Err(Backend)` so the
//     caller fails the request closed.
//
// # Sliding TTL
//
// `append_labels` issues `SADD` + `EXPIRE` in one atomic pipeline.
// `load_labels` refreshes the TTL fail-open: the read already succeeded,
// so a refresh failure is alarmed but the labels are still returned.

use async_trait::async_trait;
use praxis_policy_apl_runtime::{SessionStore, SessionStoreError};
use redis::AsyncCommands as _;

use crate::session::valkey::config::ValkeyConfig;
use crate::session::valkey::connection::Valkey;
use crate::session::valkey::error::BuildError;

/// Valkey-backed session label store.
/// The configured TTL as the `i64` valkey expects.
///
/// Saturating rather than wrapping. `EXPIRE` treats a non-positive TTL as
/// "delete now", so a wrapped negative value would drop the session key and with
/// it any accumulated taint. `ValkeyConfig::validate` already rejects a TTL this
/// large, so this is the second of two guards; it exists because the consequence
/// of getting it wrong is a silent downgrade rather than a visible failure.
fn ttl_for_expire(ttl: u64) -> i64 {
    i64::try_from(ttl).unwrap_or(i64::MAX)
}

/// A Valkey-backed store for session security labels.
pub struct ValkeySessionStore {
    ttl_seconds: Option<u64>,
    valkey: Valkey,
}

impl ValkeySessionStore {
    /// Build from validated config. The pool is created lazily, so this
    /// does not dial Valkey — connection failures surface on first use
    /// and correctly fail the request closed.
    /// # Errors
    ///
    /// Returns `BuildError` when the connection URL cannot be built or the client
    /// cannot be constructed from it.
    pub fn from_config(cfg: &ValkeyConfig) -> Result<Self, BuildError> {
        Ok(Self {
            ttl_seconds: cfg.ttl_seconds,
            valkey: Valkey::new(cfg, format!("{}:", cfg.key_prefix))?,
        })
    }
}

/// Map any backend failure to the fail-closed `SessionStoreError`.
fn backend(e: impl std::fmt::Display) -> SessionStoreError {
    SessionStoreError::Backend(e.to_string())
}

#[async_trait]
impl SessionStore for ValkeySessionStore {
    async fn load_labels(&self, session_id: &str) -> Result<Vec<String>, SessionStoreError> {
        let key = self.valkey.key(session_id);
        let mut conn = self.valkey.conn().await.map_err(backend)?;

        // SMEMBERS on a missing key returns an empty set (Ok), so an
        // unknown session naturally maps to Ok(empty). Only a real
        // backend failure becomes Err.
        let labels: Vec<String> = self
            .valkey
            .timed("SMEMBERS", conn.smembers(&key))
            .await
            .map_err(backend)?;

        // Sliding-TTL refresh is fail-open for the read: the labels were
        // read successfully, so a refresh failure is alarmed, not failed
        // closed. A persistently-failing refresh risks silent key
        // expiry across requests — see the operator runbook.
        if let Some(ttl) = self.ttl_seconds {
            // Timeouts raise the same refresh-failure alarm as backend errors.
            let refresh: Result<bool, String> = self
                .valkey
                .timed("EXPIRE", conn.expire(&key, ttl_for_expire(ttl)))
                .await;
            if let Err(e) = refresh {
                tracing::warn!(
                    alarm = "session_store_ttl_refresh_failed",
                    error = %e,
                    "valkey TTL refresh on load failed; returning read labels (fail-open)"
                );
            }
        }

        Ok(labels)
    }

    async fn append_labels(
        &self,
        session_id: &str,
        labels: &[String],
    ) -> Result<(), SessionStoreError> {
        if labels.is_empty() {
            return Ok(());
        }
        let key = self.valkey.key(session_id);
        let mut conn = self.valkey.conn().await.map_err(backend)?;

        // Atomic server-side union + optional TTL refresh in one round
        // trip (MULTI/EXEC). SADD is a commutative merge, so concurrent
        // cross-node appends never lose labels.
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.sadd(&key, labels).ignore();
        if let Some(ttl) = self.ttl_seconds {
            pipe.expire(&key, ttl_for_expire(ttl)).ignore();
        }

        self.valkey
            .timed("append (SADD+EXPIRE)", pipe.query_async::<()>(&mut conn))
            .await
            .map_err(backend)?;
        Ok(())
    }
}
