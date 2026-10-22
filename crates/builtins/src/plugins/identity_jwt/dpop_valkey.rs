// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared `DPoP` replay detection using a host-owned Valkey connection pool.
//!
//! All gateway instances must use the same Valkey database and key prefix.
//! A single atomic `SET NX EX` accepts each `(issuer, key, jti)` once for the
//! supplied retention period. Backend errors deny the proof.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use deadpool_redis::Pool;
use sha2::{Digest as _, Sha256};

use super::dpop::{ReplayGuard, ReplayUnavailable};

/// Default time allowed to acquire a pooled connection.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
/// Default time allowed for the atomic replay command.
const COMMAND_TIMEOUT: Duration = Duration::from_millis(500);

/// A [`ReplayGuard`] backed by a host-owned Valkey pool.
///
/// The host owns pool construction and lifecycle. Give every gateway instance
/// a pool for the same Valkey database and the same prefix, then pass the guard
/// to [`JwtIdentityFactory::with_replay_guard`](super::JwtIdentityFactory::with_replay_guard).
pub struct ValkeyReplayGuard {
    pool: Pool,
    key_prefix: String,
    connect_timeout: Duration,
    command_timeout: Duration,
}

impl std::fmt::Debug for ValkeyReplayGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyReplayGuard")
            .field("key_prefix", &self.key_prefix)
            .field("connect_timeout", &self.connect_timeout)
            .field("command_timeout", &self.command_timeout)
            .finish_non_exhaustive()
    }
}

impl ValkeyReplayGuard {
    /// Use a host-owned pool and a prefix shared by every gateway instance.
    /// A dedicated prefix, such as `dpop:replay:v1`, isolates replay keys from
    /// other uses of the database.
    pub fn new(pool: Pool, key_prefix: impl Into<String>) -> Self {
        Self {
            pool,
            key_prefix: key_prefix.into(),
            connect_timeout: CONNECT_TIMEOUT,
            command_timeout: COMMAND_TIMEOUT,
        }
    }

    /// Set connection and command deadlines for a host's latency budget.
    pub fn with_timeouts(mut self, connect: Duration, command: Duration) -> Self {
        self.connect_timeout = connect;
        self.command_timeout = command;
        self
    }

    fn key(&self, scope: &str, id: &str) -> String {
        // Length framing keeps arbitrary issuer and jti strings unambiguous.
        // The digest also keeps those values out of Valkey's keyspace.
        let mut digest = Sha256::new();
        digest.update(u64::try_from(scope.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(scope.as_bytes());
        digest.update(id.as_bytes());
        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize());
        format!("{}:{hash}", self.key_prefix)
    }
}

#[async_trait]
impl ReplayGuard for ValkeyReplayGuard {
    async fn first_use(
        &self,
        scope: &str,
        id: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, ReplayUnavailable> {
        let ttl = expires_at.saturating_sub(now);
        if ttl <= 0 {
            return Err(ReplayUnavailable(
                "the proof replay expiry is not in the future".to_owned(),
            ));
        }
        let mut conn = tokio::time::timeout(self.connect_timeout, self.pool.get())
            .await
            .map_err(|_elapsed| {
                ReplayUnavailable("valkey connection acquire timed out".to_owned())
            })?
            .map_err(|e| ReplayUnavailable(format!("valkey connection unavailable: {e}")))?;
        let key = self.key(scope, id);
        let response: Option<String> = tokio::time::timeout(
            self.command_timeout,
            redis::cmd("SET")
                .arg(key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(ttl)
                .query_async(&mut conn),
        )
        .await
        .map_err(|_elapsed| ReplayUnavailable("valkey replay check timed out".to_owned()))?
        .map_err(|e| ReplayUnavailable(format!("valkey replay check failed: {e}")))?;
        Ok(response.is_some())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test pool construction")]
mod tests {
    use super::*;

    #[test]
    fn key_frames_scope_and_id_and_does_not_expose_them() {
        let pool = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("test pool");
        let guard = ValkeyReplayGuard::new(pool, "dpop:v1");
        assert_ne!(guard.key("a", "bc"), guard.key("ab", "c"));
        assert!(!guard.key("secret-issuer", "private-jti").contains("secret"));
        assert_eq!(guard.key("same", "proof"), guard.key("same", "proof"));
    }
}
