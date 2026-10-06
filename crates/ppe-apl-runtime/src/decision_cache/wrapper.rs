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
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{
    PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver, StructuredInputAvailability,
};
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
            store: Mutex::new(Store::new(config.entry_bound())),
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
    ///
    /// Callers upgrade the `Weak` before taking `store`, then pass the
    /// generation they read *after* the lock is held. A generation sampled
    /// before the lock can be older than one another thread already stored;
    /// applying it would clear the newer entries and write that older
    /// generation back.
    fn maybe_clear_for_generation(&self, store: &mut Store, current: u64) {
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

    fn lookup(&self, key: &CacheKey) -> (Lookup, u64) {
        // `engine` is declared first so the mutex drops before the `Arc`
        // refcount: upgrade stays outside the lock, the generation read stays inside.
        let engine = self.engine.upgrade();
        let mut store = self.lock_store();
        if let Some(engine) = engine.as_ref() {
            self.maybe_clear_for_generation(&mut store, engine.config_generation());
        }
        let generation = self.generation.load(Ordering::Acquire);
        (store.lookup(key, Instant::now()), generation)
    }

    fn insert_if_generation(&self, key: CacheKey, decision: PdpDecision, expected_gen: u64) {
        let now = Instant::now();
        let Some(expires_at) = now.checked_add(self.config.ttl()) else {
            return;
        };
        let outcome = {
            let engine = self.engine.upgrade();
            let mut store = self.lock_store();
            if let Some(engine) = engine.as_ref() {
                self.maybe_clear_for_generation(&mut store, engine.config_generation());
            }
            if self.generation.load(Ordering::Acquire) != expected_gen {
                return;
            }
            store.insert(key, decision, expires_at, now)
        };
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

    fn validate_call(&self, call: &PdpCall) -> Result<(), String> {
        self.inner.validate_call(call)
    }

    fn validate_call_with_input(
        &self,
        call: &PdpCall,
        input: StructuredInputAvailability,
    ) -> Result<(), String> {
        self.inner.validate_call_with_input(call, input)
    }

    async fn evaluate(&self, call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        self.evaluate_structured(call, bag, &StructuredInput::default())
            .await
    }

    async fn evaluate_structured(
        &self,
        call: &PdpCall,
        bag: &AttributeBag,
        structured: &StructuredInput,
    ) -> Result<PdpDecision, PdpError> {
        let key = CacheKey::for_evaluation(call, bag, structured);
        let (lookup, generation) = self.lookup(&key);
        match lookup {
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

        // Use the generation observed with the miss under the cache lock.
        // `insert_if_generation` drops the decision if a reload landed since.
        let result = self.inner.evaluate_structured(call, bag, structured).await;
        if let Ok(decision) = &result {
            self.insert_if_generation(key, decision.clone(), generation);
        }
        result
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use praxis_policy_apl_core::attributes::AttributeBag;
    use praxis_policy_apl_core::evaluator::Decision;
    use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};
    use praxis_policy_core::engine::PolicyEngine;

    use super::super::config::DecisionCacheConfig;
    use super::super::key::CacheKey;
    use super::{CachedPdpResolver, Lookup};

    fn config() -> DecisionCacheConfig {
        DecisionCacheConfig::new(Duration::from_secs(60), NonZeroUsize::MIN).expect("positive ttl")
    }

    fn call() -> PdpCall {
        PdpCall {
            dialect: PdpDialect::Cel,
            args: serde_yaml::Value::Null,
        }
    }

    struct CountingResolver {
        calls: Arc<AtomicU64>,
    }

    #[async_trait]
    impl PdpResolver for CountingResolver {
        fn dialect(&self) -> PdpDialect {
            PdpDialect::Cel
        }

        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: Vec::new(),
            })
        }
    }

    struct GatedResolver {
        calls: Arc<AtomicU64>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl PdpResolver for GatedResolver {
        fn dialect(&self) -> PdpDialect {
            PdpDialect::Cel
        }

        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: Vec::new(),
            })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_miss_keeps_its_generation_when_another_lookup_observes_a_reload() {
        let mgr = Arc::new(PolicyEngine::default());
        let cache = CachedPdpResolver::wrap(
            Arc::new(CountingResolver {
                calls: Arc::new(AtomicU64::new(0)),
            }),
            config(),
            Arc::downgrade(&mgr),
        );
        let key = CacheKey::for_call(&call(), &AttributeBag::default());
        let (lookup, old_generation) = cache.lookup(&key);
        assert!(matches!(lookup, Lookup::Miss));

        mgr.load_config_yaml("engine_settings:\n  dispatch: hooks\n")
            .expect("reload bumps generation");
        let (lookup, new_generation) = cache.lookup(&key);
        assert!(matches!(lookup, Lookup::Miss));
        assert_ne!(old_generation, new_generation);

        let decision = PdpDecision {
            decision: Decision::Allow,
            diagnostics: Vec::new(),
        };
        cache.insert_if_generation(key, decision.clone(), old_generation);
        assert!(
            matches!(cache.lookup(&key).0, Lookup::Miss),
            "the old evaluation must not be cached under the new generation"
        );
        cache.insert_if_generation(key, decision, new_generation);
        assert!(matches!(cache.lookup(&key).0, Lookup::Hit(_)));
    }

    #[tokio::test]
    async fn a_decision_in_flight_across_a_reload_is_not_cached() {
        let mgr = Arc::new(PolicyEngine::default());
        let calls = Arc::new(AtomicU64::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let cache = CachedPdpResolver::wrap(
            Arc::new(GatedResolver {
                calls: Arc::clone(&calls),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
            config(),
            Arc::downgrade(&mgr),
        );
        let inflight = tokio::spawn({
            let cache = Arc::clone(&cache);
            async move { cache.evaluate(&call(), &AttributeBag::default()).await }
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("the backend was entered");
        mgr.load_config_yaml("engine_settings:\n  dispatch: hooks\n")
            .expect("reload bumps generation");
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), inflight)
            .await
            .expect("in-flight evaluate finished")
            .expect("join")
            .expect("allow");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        cache
            .evaluate(&call(), &AttributeBag::default())
            .await
            .expect("post-reload evaluate");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a decision computed before the bump must not be stored"
        );
        cache
            .evaluate(&call(), &AttributeBag::default())
            .await
            .expect("cached at the new generation");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the re-evaluated decision is reused"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reloads_do_not_serve_a_pre_bump_decision_as_current() {
        let mgr = Arc::new(PolicyEngine::default());
        let calls = Arc::new(AtomicU64::new(0));
        let cache = CachedPdpResolver::wrap(
            Arc::new(CountingResolver {
                calls: Arc::clone(&calls),
            }),
            config(),
            Arc::downgrade(&mgr),
        );
        cache
            .evaluate(&call(), &AttributeBag::default())
            .await
            .expect("seed");

        let mut joins = Vec::new();
        for _ in 0..4 {
            let cache = Arc::clone(&cache);
            joins.push(tokio::spawn(async move {
                for _ in 0..20 {
                    cache
                        .evaluate(&call(), &AttributeBag::default())
                        .await
                        .expect("evaluate");
                    tokio::task::yield_now().await;
                }
            }));
        }
        let reloader = {
            let mgr = Arc::clone(&mgr);
            tokio::spawn(async move {
                for _ in 0..10 {
                    mgr.load_config_yaml("engine_settings:\n  dispatch: hooks\n")
                        .expect("reload");
                    tokio::task::yield_now().await;
                }
            })
        };
        for join in joins {
            join.await.expect("worker");
        }
        reloader.await.expect("reloader");

        let before = calls.load(Ordering::SeqCst);
        mgr.load_config_yaml("engine_settings:\n  dispatch: hooks\n")
            .expect("final reload");
        cache
            .evaluate(&call(), &AttributeBag::default())
            .await
            .expect("after final reload");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "a generation bump drops cached decisions"
        );
        cache
            .evaluate(&call(), &AttributeBag::default())
            .await
            .expect("hit at the new generation");
        assert_eq!(calls.load(Ordering::SeqCst), before + 1);
    }
}
