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

pub(crate) struct Valkey {
    command_timeout: Duration,
    connect_timeout: Duration,
    key_prefix: String,
    pool: Pool,
}

impl Valkey {
    // Pool creation is lazy; an unavailable server fails the first request.
    pub(crate) fn new(cfg: &ValkeyConfig, key_prefix: String) -> Result<Self, BuildError> {
        Ok(Self {
            command_timeout: Duration::from_millis(cfg.command_timeout_ms),
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms),
            key_prefix,
            pool: build_pool(cfg)?,
        })
    }

    // Hash ids so raw elicitation and session ids do not appear in Valkey keys.
    pub(crate) fn key(&self, id: &str) -> String {
        let mut key = self.key_prefix.clone();
        for byte in Sha256::digest(id.as_bytes()) {
            let _ = write!(key, "{byte:02x}");
        }
        key
    }

    pub(crate) async fn conn(&self) -> Result<Connection, String> {
        match tokio::time::timeout(self.connect_timeout, self.pool.get()).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("valkey connection acquire timed out".to_owned()),
        }
    }

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
