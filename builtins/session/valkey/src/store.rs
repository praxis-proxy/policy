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

use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use deadpool_redis::{Connection, Pool};
use praxis_policy_apl_runtime::{SessionStore, SessionStoreError};
use redis::AsyncCommands as _;
use sha2::{Digest as _, Sha256};

use crate::config::ValkeyConfig;
use crate::connection::build_pool;
use crate::error::BuildError;

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
    pool: Pool,
    key_prefix: String,
    ttl_seconds: Option<u64>,
    connect_timeout: Duration,
    command_timeout: Duration,
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
            pool: build_pool(cfg)?,
            key_prefix: cfg.key_prefix.clone(),
            ttl_seconds: cfg.ttl_seconds,
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms),
            command_timeout: Duration::from_millis(cfg.command_timeout_ms),
        })
    }

    /// Key schema: `<prefix>:<hex(sha256(session_id))>`. The full-width
    /// digest keeps the Valkey keyspace collision-free and removes raw
    /// session ids from it.
    fn key(&self, session_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        format!("{}:{}", self.key_prefix, hex)
    }

    /// Acquire a pooled connection, bounded by the connect timeout (the
    /// fail-fast knob for a dead/slow endpoint, distinct from the
    /// per-command timeout applied to SMEMBERS/SADD below).
    async fn conn(&self) -> Result<Connection, SessionStoreError> {
        match tokio::time::timeout(self.connect_timeout, self.pool.get()).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(backend(e)),
            Err(_) => Err(SessionStoreError::Backend(
                "valkey connection acquire timed out".to_owned(),
            )),
        }
    }
}

/// Map any backend failure to the fail-closed `SessionStoreError`.
fn backend(e: impl std::fmt::Display) -> SessionStoreError {
    SessionStoreError::Backend(e.to_string())
}

#[async_trait]
impl SessionStore for ValkeySessionStore {
    async fn load_labels(&self, session_id: &str) -> Result<Vec<String>, SessionStoreError> {
        let key = self.key(session_id);
        let mut conn = self.conn().await?;

        // SMEMBERS on a missing key returns an empty set (Ok), so an
        // unknown session naturally maps to Ok(empty). Only a real
        // backend failure becomes Err.
        let labels: Vec<String> =
            match tokio::time::timeout(self.command_timeout, conn.smembers(&key)).await {
                Ok(res) => res.map_err(backend)?,
                Err(_) => {
                    return Err(SessionStoreError::Backend(
                        "valkey SMEMBERS timed out".to_owned(),
                    ));
                },
            };

        // Sliding-TTL refresh is fail-open for the read: the labels were
        // read successfully, so a refresh failure is alarmed, not failed
        // closed. A persistently-failing refresh risks silent key
        // expiry across requests — see the operator runbook.
        if let Some(ttl) = self.ttl_seconds {
            // Timeouts raise the same refresh-failure alarm as backend errors.
            let refresh: Result<Result<bool, _>, _> =
                tokio::time::timeout(self.command_timeout, conn.expire(&key, ttl_for_expire(ttl)))
                    .await;
            let refresh_error: Option<String> = match refresh {
                Ok(Ok(_)) => None,
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => Some("EXPIRE timed out".to_owned()),
            };
            if let Some(e) = refresh_error {
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
        let key = self.key(session_id);
        let mut conn = self.conn().await?;

        // Atomic server-side union + optional TTL refresh in one round
        // trip (MULTI/EXEC). SADD is a commutative merge, so concurrent
        // cross-node appends never lose labels.
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.sadd(&key, labels).ignore();
        if let Some(ttl) = self.ttl_seconds {
            pipe.expire(&key, ttl_for_expire(ttl)).ignore();
        }

        match tokio::time::timeout(self.command_timeout, pipe.query_async::<()>(&mut conn)).await {
            Ok(res) => res.map_err(backend)?,
            Err(_) => {
                return Err(SessionStoreError::Backend(
                    "valkey append (SADD+EXPIRE) timed out".to_owned(),
                ));
            },
        }
        Ok(())
    }
}
