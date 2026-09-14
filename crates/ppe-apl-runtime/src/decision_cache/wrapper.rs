// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `CachedPdpResolver` — wrap any `PdpResolver` with an opt-in decision cache.
//
// Caches Allow and Deny. Dispatch errors are not stored. The map key is a
// digest, so request attributes never sit in the cache. A PPE config
// generation bump drops every entry so a reload cannot reuse a previous
// policy's answers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use async_trait::async_trait;

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};
use praxis_policy_core::engine::PolicyEngine;

use super::config::DecisionCacheConfig;
use super::key::CacheKey;
use super::store::{Insert, Lookup, Store};

/// Hit / miss / expiry / eviction counters. Values only; no keys, no bag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionCacheStats {
    /// Backend was skipped because a live entry matched.
    pub hits: u64,
    /// No live entry; the backend ran (or a dispatch error returned).
    pub misses: u64,
    /// An entry existed but its TTL had elapsed, so it was dropped.
    pub expiries: u64,
    /// An insert dropped the oldest live entry to stay inside the bound.
    pub evictions: u64,
}

/// PDP resolver that reuses Allow/Deny for identical digest keys.
pub struct CachedPdpResolver {
    inner: Arc<dyn PdpResolver>,
    config: DecisionCacheConfig,
    store: Mutex<Store>,
    engine: Weak<PolicyEngine>,
    generation: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    expiries: AtomicU64,
    evictions: AtomicU64,
}

impl CachedPdpResolver {
    /// Wrap `inner`. `engine` is used only to read [`PolicyEngine::config_generation`].
    #[must_use]
    pub fn wrap(
        inner: Arc<dyn PdpResolver>,
        config: DecisionCacheConfig,
        engine: Weak<PolicyEngine>,
    ) -> Arc<Self> {
        let generation = engine.upgrade().map_or(0, |mgr| mgr.config_generation());
        Arc::new(Self {
            inner,
            config,
            store: Mutex::new(Store::new(config.max_entries)),
            engine,
            generation: AtomicU64::new(generation),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            expiries: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        })
    }

    /// Snapshot of counters. Safe to log: no digest, no attributes.
    #[must_use]
    pub fn stats(&self) -> DecisionCacheStats {
        DecisionCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            expiries: self.expiries.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    fn lock_store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drop cached answers when PPE configuration generation moved.
    /// Must run while `store` is held so a miss cannot insert a
    /// previous-generation decision after another thread already cleared.
    fn sync_generation(&self, store: &mut Store) {
        let Some(mgr) = self.engine.upgrade() else {
            return;
        };
        let current = mgr.config_generation();
        let previous = self.generation.load(Ordering::Acquire);
        if current == previous {
            return;
        }
        store.clear();
        self.generation.store(current, Ordering::Release);
        tracing::debug!(
            alarm = "pdp_decision_cache",
            event = "generation_invalidated",
            previous,
            current,
            "PDP decision cache dropped because PPE configuration generation changed"
        );
    }

    fn lookup(&self, key: &CacheKey) -> Lookup {
        let mut store = self.lock_store();
        self.sync_generation(&mut store);
        store.lookup(key, Instant::now())
    }

    fn insert_if_generation(&self, key: CacheKey, decision: PdpDecision, expected_gen: u64) {
        let now = Instant::now();
        let Some(expires_at) = now.checked_add(self.config.ttl) else {
            return;
        };
        let mut store = self.lock_store();
        self.sync_generation(&mut store);
        if self.generation.load(Ordering::Acquire) != expected_gen {
            return;
        }
        let outcome = store.insert(key, decision, expires_at, now);
        drop(store);
        if matches!(outcome, Insert::Evicted) {
            self.evictions.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                alarm = "pdp_decision_cache",
                event = "eviction",
                "PDP decision cache evicted the oldest entry to stay inside max_entries"
            );
        }
    }
}

#[async_trait]
impl PdpResolver for CachedPdpResolver {
    fn dialect(&self) -> PdpDialect {
        self.inner.dialect()
    }

    async fn evaluate(&self, call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        let key = CacheKey::for_call(call, bag);
        match self.lookup(&key) {
            Lookup::Hit(decision) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    alarm = "pdp_decision_cache",
                    event = "hit",
                    "PDP decision cache hit"
                );
                return Ok(decision);
            },
            Lookup::Expired => {
                self.expiries.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    alarm = "pdp_decision_cache",
                    event = "expiry",
                    "PDP decision cache dropped an expired entry"
                );
            },
            Lookup::Miss => {},
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            alarm = "pdp_decision_cache",
            event = "miss",
            "PDP decision cache miss"
        );

        let generation = self.generation.load(Ordering::Acquire);
        let result = self.inner.evaluate(call, bag).await;
        if let Ok(decision) = &result {
            self.insert_if_generation(key, decision.clone(), generation);
        }
        result
    }
}
