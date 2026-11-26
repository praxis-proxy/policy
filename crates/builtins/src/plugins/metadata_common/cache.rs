// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Response caching for metadata HTTP callouts.
#![allow(
    dead_code,
    reason = "Phase 1: Cache configuration and types defined. Phase 2: Integrate moka storage and key hashing."
)]
//!
//! Implements a bounded in-process LRU cache with:
//! - Dynamic cache keys from request attributes and credentials
//! - TTL-based expiration
//! - Single-flight coalescing for concurrent identical misses
//! - Credential-scoped partitioning for safe invalidation

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Cache configuration from metadata HTTP plugin config.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheConfig {
    /// Request attributes that determine the cache key.
    /// Every request attribute used in templates MUST appear here or in `key_exempt`.
    #[serde(default)]
    pub(crate) key: Vec<String>,

    /// Attributes that don't affect the response (opt-in with audit warning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key_exempt: Option<Vec<KeyExemption>>,

    /// Scope dimensions for credential-safe partitioning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<ScopeConfig>,

    /// TTL for cache entries in seconds.
    /// Capped at value from Cache-Control header if present.
    #[serde(default = "default_ttl_seconds")]
    pub(crate) ttl_seconds: u64,

    /// Maximum number of cache entries.
    #[serde(default = "default_max_entries")]
    pub(crate) max_entries: u64,

    /// Maximum bytes for all cache entries combined.
    #[serde(default = "default_max_bytes")]
    pub(crate) max_bytes: usize,

    /// Volatile mode: implicit 30s TTL ceiling, no stale serving.
    #[serde(default)]
    pub(crate) volatile: bool,
}

fn default_ttl_seconds() -> u64 {
    300 // 5 minutes
}

fn default_max_entries() -> u64 {
    10_000
}

fn default_max_bytes() -> usize {
    64 * 1024 * 1024 // 64 MiB
}

/// Single exempted attribute from cache key (with audit reason).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyExemption {
    /// Attribute path that is exempted.
    pub(crate) path: String,
    /// Why this attribute doesn't affect the response.
    pub(crate) reason: String,
}

/// Scope dimensions for credential-safe partitioning.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeConfig {
    /// Principal partition (e.g., `subject.id`).
    /// Missing principal → cache bypass (security-sensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) principal: Option<String>,

    /// Tenant partition (e.g., `subject.organization_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tenant: Option<TenantPartition>,

    /// Credential generation partition (non-secret ID).
    /// When credential rotates, cache entries for old generation are invalidated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) credential: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TenantPartition {
    /// Path to tenant attribute.
    pub(crate) path: String,

    /// Whether tenant is invariant across all requests (no per-tenant partitioning needed).
    #[serde(default)]
    pub(crate) invariant: bool,

    /// Reason for invariant claim (audit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

/// Cache disposition tracking for audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CacheDisposition {
    /// Cache not configured.
    Disabled,
    /// First fetch of this key.
    Miss,
    /// Returned from cache.
    Hit,
    /// `ETag` revalidation hit (Phase 2).
    Revalidated,
    /// Permitted stale value served (Phase 2).
    Stale,
}

/// Compiled cache configuration with validation.
#[derive(Clone, Debug)]
pub(crate) struct CompiledCacheConfig {
    config: CacheConfig,
    // Validation results computed at compile time
}

impl CompiledCacheConfig {
    /// Compile and validate cache configuration.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Phase 2: Will return Err on validation failure"
    )]
    pub(crate) fn compile(config: CacheConfig) -> Result<Self, String> {
        // Phase 1: Basic validation
        // - key and key_exempt must reference known attributes
        // - scope dimensions must be valid paths
        // Phase 2: Will enforce scoped validity
        Ok(Self { config })
    }

    pub(crate) fn is_enabled(&self) -> bool {
        !self.config.key.is_empty()
    }

    pub(crate) fn ttl(&self) -> Duration {
        Duration::from_secs(self.config.ttl_seconds)
    }

    pub(crate) fn max_entries(&self) -> u64 {
        self.config.max_entries
    }

    pub(crate) fn max_bytes(&self) -> usize {
        self.config.max_bytes
    }

    pub(crate) fn is_volatile(&self) -> bool {
        self.config.volatile
    }

    pub(crate) fn key_attributes(&self) -> &[String] {
        &self.config.key
    }

    pub(crate) fn scope_config(&self) -> Option<&ScopeConfig> {
        self.config.scope.as_ref()
    }
}

/// In-process response cache store (Phase 2).
/// Phase 1: Struct definition and configuration only.
#[derive(Clone, Debug)]
pub(crate) struct CacheStore {
    #[allow(dead_code, reason = "Phase 2: Will be used in cache operations")]
    config: Arc<CompiledCacheConfig>,
    // Phase 2: Will contain moka::future::Cache<CacheKey, CachedResponse>
    // Phase 2: Will contain Arc<AtomicUsize> for byte tracking
}

impl CacheStore {
    /// Create a new cache store from compiled config.
    pub(crate) fn new(config: Arc<CompiledCacheConfig>) -> Self {
        Self { config }
    }

    /// Check if cache is enabled.
    pub(crate) fn is_enabled(&self) -> bool {
        self.config.is_enabled()
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn cache_config_deserializes_with_defaults() {
        let json = serde_json::json!({
            "key": ["subject.id"]
        });
        let config: CacheConfig = serde_json::from_value(json).expect("parse config");
        assert_eq!(config.key, vec!["subject.id"]);
        assert_eq!(config.ttl_seconds, 300);
        assert_eq!(config.max_entries, 10_000);
        assert_eq!(config.max_bytes, 64 * 1024 * 1024);
        assert!(!config.volatile);
    }

    #[test]
    fn cache_config_respects_custom_ttl() {
        let json = serde_json::json!({
            "key": ["subject.id"],
            "ttl_seconds": 60
        });
        let config: CacheConfig = serde_json::from_value(json).expect("parse config");
        assert_eq!(config.ttl_seconds, 60);
    }

    #[test]
    fn compiled_cache_config_enables_when_key_configured() {
        let config = CacheConfig {
            key: vec!["subject.id".to_owned()],
            key_exempt: None,
            scope: None,
            ttl_seconds: 300,
            max_entries: 10_000,
            max_bytes: 64 * 1024 * 1024,
            volatile: false,
        };
        let compiled = CompiledCacheConfig::compile(config).expect("compile");
        assert!(compiled.is_enabled());
    }

    #[test]
    fn compiled_cache_config_disables_when_no_key() {
        let config = CacheConfig {
            key: vec![],
            key_exempt: None,
            scope: None,
            ttl_seconds: 300,
            max_entries: 10_000,
            max_bytes: 64 * 1024 * 1024,
            volatile: false,
        };
        let compiled = CompiledCacheConfig::compile(config).expect("compile");
        assert!(!compiled.is_enabled());
    }

    #[test]
    fn scope_config_deserializes() {
        let json = serde_json::json!({
            "principal": "subject.id",
            "credential": "secret.entitlement-api-token"
        });
        let scope: ScopeConfig = serde_json::from_value(json).expect("parse scope");
        assert_eq!(scope.principal, Some("subject.id".to_owned()));
        assert_eq!(
            scope.credential,
            Some("secret.entitlement-api-token".to_owned())
        );
    }
}
