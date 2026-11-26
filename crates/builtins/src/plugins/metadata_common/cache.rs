// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Response caching for metadata HTTP callouts.
//!
//! Implements a bounded in-process LRU cache with:
//! - Dynamic cache keys from request attributes and credentials
//! - TTL-based expiration
//! - Single-flight coalescing for concurrent identical misses
//! - Credential-scoped partitioning for safe invalidation

use std::collections::HashSet;
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
#[allow(dead_code, reason = "Phase 2: Cache store integration")]
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
#[allow(dead_code, reason = "Phase 2: Cache store integration")]
#[derive(Clone, Debug)]
pub(crate) struct CompiledCacheConfig {
    config: CacheConfig,
    // Validation results computed at compile time
}

impl CompiledCacheConfig {
    /// Compile and validate cache configuration.
    pub(crate) fn compile(config: CacheConfig) -> Result<Self, String> {
        // If cache is enabled, validate key and scope configuration
        if !config.key.is_empty() {
            // Validate that at least one key remains after exemptions
            let exempted: HashSet<&str> = config
                .key_exempt
                .as_ref()
                .map(|ex| ex.iter().map(|e| e.path.as_str()).collect())
                .unwrap_or_default();
            let remaining_keys: Vec<_> = config
                .key
                .iter()
                .filter(|k| !exempted.contains(k.as_str()))
                .collect();
            if remaining_keys.is_empty() {
                return Err(
                    "cache.key: all attributes are exempted; at least one key must remain"
                        .to_owned(),
                );
            }

            // Validate scope fields if present
            if let Some(scope) = &config.scope {
                if let Some(principal) = &scope.principal {
                    if principal.trim().is_empty() {
                        return Err("cache.scope.principal: must not be empty".to_owned());
                    }
                }
                if let Some(tenant) = &scope.tenant {
                    if tenant.path.trim().is_empty() {
                        return Err("cache.scope.tenant.path: must not be empty".to_owned());
                    }
                }
                if let Some(credential) = &scope.credential {
                    if credential.trim().is_empty() {
                        return Err(
                            "cache.scope.credential: must not be empty".to_owned(),
                        );
                    }
                }
            }
        }

        Ok(Self { config })
    }

    #[allow(dead_code, reason = "Phase 2: Cache store integration")]
    pub(crate) fn is_enabled(&self) -> bool {
        !self.config.key.is_empty()
    }

    #[allow(dead_code, reason = "Phase 2: Cache store integration")]
    pub(crate) fn ttl(&self) -> Duration {
        Duration::from_secs(self.config.ttl_seconds)
    }

    #[allow(dead_code, reason = "Phase 2: Cache store integration")]
    pub(crate) fn max_entries(&self) -> u64 {
        self.config.max_entries
    }

    #[allow(dead_code, reason = "Phase 2: Cache store integration")]
    pub(crate) fn max_bytes(&self) -> usize {
        self.config.max_bytes
    }

    #[allow(dead_code, reason = "Phase 2: Cache store integration")]
    pub(crate) fn is_volatile(&self) -> bool {
        self.config.volatile
    }

    #[allow(dead_code, reason = "Phase 2: Cache store integration")]
    pub(crate) fn key_attributes(&self) -> &[String] {
        &self.config.key
    }

    #[allow(dead_code, reason = "Phase 2: Cache store integration")]
    pub(crate) fn scope_config(&self) -> Option<&ScopeConfig> {
        self.config.scope.as_ref()
    }
}

/// In-process response cache store (Phase 2).
/// Phase 1: Struct definition and configuration only.
#[allow(dead_code, reason = "Phase 2: Cache store implementation")]
#[derive(Clone, Debug)]
pub(crate) struct CacheStore {
    #[allow(dead_code, reason = "Phase 2: Will be used in cache operations")]
    config: Arc<CompiledCacheConfig>,
    // Phase 2: Will contain moka::future::Cache<CacheKey, CachedResponse>
    // Phase 2: Will contain Arc<AtomicUsize> for byte tracking
}

impl CacheStore {
    /// Create a new cache store from compiled config.
    #[allow(dead_code, reason = "Phase 2: Cache store implementation")]
    pub(crate) fn new(config: Arc<CompiledCacheConfig>) -> Self {
        Self { config }
    }

    /// Check if cache is enabled.
    #[allow(dead_code, reason = "Phase 2: Cache store implementation")]
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

    #[test]
    fn compiled_cache_config_accessors() {
        let config = CacheConfig {
            key: vec!["subject.id".to_owned()],
            key_exempt: None,
            scope: Some(ScopeConfig {
                principal: Some("subject.id".to_owned()),
                tenant: None,
                credential: None,
            }),
            ttl_seconds: 600,
            max_entries: 5_000,
            max_bytes: 32 * 1024 * 1024,
            volatile: true,
        };
        let compiled = CompiledCacheConfig::compile(config).expect("compile");
        assert_eq!(compiled.ttl().as_secs(), 600);
        assert_eq!(compiled.max_entries(), 5_000);
        assert_eq!(compiled.max_bytes(), 32 * 1024 * 1024);
        assert!(compiled.is_volatile());
        assert_eq!(compiled.key_attributes(), &["subject.id".to_owned()]);
        assert!(compiled.scope_config().is_some());
    }

    #[test]
    fn cache_store_new() {
        let config = CacheConfig::default();
        let compiled = CompiledCacheConfig::compile(config).expect("compile");
        let store = CacheStore::new(Arc::new(compiled));
        assert!(!store.is_enabled()); // empty key means disabled
    }

    #[test]
    fn cache_store_enabled() {
        let config = CacheConfig {
            key: vec!["subject.id".to_owned()],
            ..CacheConfig::default()
        };
        let compiled = CompiledCacheConfig::compile(config).expect("compile");
        let store = CacheStore::new(Arc::new(compiled));
        assert!(store.is_enabled());
    }
}
