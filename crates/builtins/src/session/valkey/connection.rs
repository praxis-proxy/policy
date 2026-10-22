// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Internal connection layer shared by the Valkey backends: the lazy pool,
// the connect and command timeouts, and the hashed key schema. Crate-visible
// so the session and CIBA stores share one implementation; not a public API.
// Errors are plain strings that each store maps to its own error type.

use std::fmt::Write as _;
use std::time::Duration;

use deadpool_redis::{Config as PoolConfig, Connection, Pool, Runtime};
use sha2::{Digest as _, Sha256};

use crate::session::valkey::config::ValkeyConfig;
use crate::session::valkey::error::BuildError;

/// A pool with the timeouts and key prefix every request uses.
pub(crate) struct Valkey {
    command_timeout: Duration,
    connect_timeout: Duration,
    key_prefix: String,
    pool: Pool,
}

impl Valkey {
    /// Build from validated config, keying under `key_prefix`. Does not dial.
    pub(crate) fn new(cfg: &ValkeyConfig, key_prefix: String) -> Result<Self, BuildError> {
        Ok(Self {
            command_timeout: Duration::from_millis(cfg.command_timeout_ms),
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms),
            key_prefix,
            pool: build_pool(cfg)?,
        })
    }

    /// `<key_prefix><hex(sha256(id))>`. The digest keeps raw ids out of the
    /// keyspace and the keyspace collision-free.
    pub(crate) fn key(&self, id: &str) -> String {
        let mut key = self.key_prefix.clone();
        for byte in Sha256::digest(id.as_bytes()) {
            let _ = write!(key, "{byte:02x}");
        }
        key
    }

    /// A pooled connection, bounded by the connect timeout.
    pub(crate) async fn conn(&self) -> Result<Connection, String> {
        match tokio::time::timeout(self.connect_timeout, self.pool.get()).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("valkey connection acquire timed out".to_owned()),
        }
    }

    /// One command under the command timeout. `what` names it in the error.
    pub(crate) async fn timed<T>(
        &self,
        what: &str,
        fut: impl Future<Output = redis::RedisResult<T>>,
    ) -> Result<T, String> {
        match tokio::time::timeout(self.command_timeout, fut).await {
            Ok(res) => res.map_err(|e| e.to_string()),
            Err(_) => Err(format!("valkey {what} timed out")),
        }
    }
}

/// Build the connection pool from validated config. The pool is created
/// lazily — `create_pool` does not dial Valkey, so a bad endpoint surfaces
/// on first use (where it correctly fails the request closed) rather than
/// blocking `load_config_yaml`.
pub(crate) fn build_pool(cfg: &ValkeyConfig) -> Result<Pool, BuildError> {
    let url = cfg.connection_url()?;
    let pool_cfg = PoolConfig::from_url(url);
    // Note: the pool-create error is intentionally not interpolated with
    // the URL — that string carries credentials. `connection_url()` has
    // already validated the URL parses, so failures here are rare.
    pool_cfg
        .create_pool(Some(Runtime::Tokio1))
        .map_err(|e| BuildError::Pool(e.to_string()))
}
