// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Shared cache-contract runner used by this crate's tests and by each
// builtin PDP crate, so Cedar, CEL, and OPA cannot drift off the issue's
// acceptance list.
//
// Behind `test-util` (and `cfg(test)`): it panics on unexpected input
// and must not compile into a production library build.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test contract runner called from builtin PDP crates"
)]

use std::sync::Arc;
use std::time::Duration;

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::step::{PdpCall, PdpResolver};
use praxis_policy_core::engine::PolicyEngine;

use super::config::DecisionCacheConfig;
use super::wrapper::CachedPdpResolver;

/// One Allow, one Deny, one dispatch error, and two extra bags for capacity.
#[doc(hidden)]
pub struct CacheContractSamples {
    /// Inputs that must yield [`Decision::Allow`].
    pub allow: (PdpCall, AttributeBag),
    /// Inputs that must yield [`Decision::Deny`].
    pub deny: (PdpCall, AttributeBag),
    /// Inputs that must yield [`praxis_policy_apl_core::step::PdpError`].
    pub error: (PdpCall, AttributeBag),
    /// Distinct bags used with `allow.0` to fill the cap without colliding.
    pub extra_bags: [AttributeBag; 2],
}

/// TTL, cap, reload, Allow, Deny, errors, and concurrent access.
///
/// # Panics
///
/// Panics when a sample does not match the expected decision, when an
/// error is cached, or when counters do not move as the contract requires.
#[doc(hidden)]
pub async fn run_cache_contract(inner: Arc<dyn PdpResolver>, samples: CacheContractSamples) {
    let mgr = Arc::new(PolicyEngine::default());
    let config = DecisionCacheConfig {
        ttl: Duration::from_secs(60),
        max_entries: 32,
    };
    let cache = CachedPdpResolver::wrap(Arc::clone(&inner), config, Arc::downgrade(&mgr));

    let (ref allow_call, ref allow_bag) = samples.allow;
    let first = cache
        .evaluate(allow_call, allow_bag)
        .await
        .expect("allow sample must succeed");
    assert!(
        matches!(first.decision, Decision::Allow),
        "allow sample must Allow, got {:?}",
        first.decision
    );
    let second = cache
        .evaluate(allow_call, allow_bag)
        .await
        .expect("cached allow must succeed");
    assert_eq!(first, second, "cached Allow must equal the uncached one");
    assert_eq!(cache.stats().misses, 1, "first allow is a miss");
    assert_eq!(cache.stats().hits, 1, "second allow is a hit");

    let (ref deny_call, ref deny_bag) = samples.deny;
    let denied = cache
        .evaluate(deny_call, deny_bag)
        .await
        .expect("deny sample must succeed");
    assert!(
        matches!(denied.decision, Decision::Deny { .. }),
        "deny sample must Deny, got {:?}",
        denied.decision
    );
    let denied_again = cache
        .evaluate(deny_call, deny_bag)
        .await
        .expect("cached deny must succeed");
    assert_eq!(
        denied, denied_again,
        "cached Deny must equal the uncached one"
    );
    assert_eq!(cache.stats().misses, 2, "deny first evaluation is a miss");
    assert_eq!(cache.stats().hits, 2, "deny second evaluation is a hit");

    let (ref error_call, ref error_bag) = samples.error;
    cache
        .evaluate(error_call, error_bag)
        .await
        .expect_err("error sample must be a dispatch error");
    cache
        .evaluate(error_call, error_bag)
        .await
        .expect_err("errors must not be cached into a success");
    assert_eq!(cache.stats().misses, 4, "errors are misses every time");
    assert_eq!(cache.stats().hits, 2, "errors must not increment hits");

    let tasks: Vec<_> = std::iter::repeat_with(|| {
        let cache = Arc::clone(&cache);
        let call = allow_call.clone();
        let bag = allow_bag.clone();
        tokio::spawn(async move { cache.evaluate(&call, &bag).await })
    })
    .take(16)
    .collect();
    for task in tasks {
        let decision = task.await.expect("join").expect("concurrent evaluate");
        assert_eq!(
            decision, first,
            "concurrent evaluation must match the uncached Allow"
        );
    }
    assert!(
        cache.stats().hits >= 18,
        "concurrent Allow reuse must register as hits, stats={:?}",
        cache.stats()
    );

    let hits_before = cache.stats().hits;
    let misses_before = cache.stats().misses;
    mgr.load_config_yaml("engine_settings:\n  dispatch: hooks\n")
        .expect("a hooks-only document must bump generation");
    let after_reload = cache
        .evaluate(allow_call, allow_bag)
        .await
        .expect("post-reload allow");
    assert_eq!(
        after_reload, first,
        "re-evaluation after a generation bump must match the original Allow"
    );
    assert_eq!(
        cache.stats().hits,
        hits_before,
        "a generation bump must not count as a hit"
    );
    assert_eq!(
        cache.stats().misses,
        misses_before + 1,
        "a generation bump must miss and re-evaluate"
    );

    let cap = CachedPdpResolver::wrap(
        Arc::clone(&inner),
        DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries: 2,
        },
        Arc::downgrade(&mgr),
    );
    let [extra0, extra1] = samples.extra_bags;
    cap.evaluate(allow_call, allow_bag)
        .await
        .expect("cap allow");
    cap.evaluate(allow_call, &extra0)
        .await
        .expect("cap extra 0");
    cap.evaluate(allow_call, &extra1)
        .await
        .expect("cap extra 1");
    assert!(
        cap.stats().evictions >= 1,
        "inserting past max_entries must evict, stats={:?}",
        cap.stats()
    );

    let ttl = CachedPdpResolver::wrap(
        inner,
        DecisionCacheConfig {
            ttl: Duration::from_millis(40),
            max_entries: 8,
        },
        Arc::downgrade(&mgr),
    );
    ttl.evaluate(deny_call, deny_bag).await.expect("ttl seed");
    ttl.evaluate(deny_call, deny_bag).await.expect("ttl hit");
    assert_eq!(
        ttl.stats().hits,
        1,
        "the second evaluate before sleep is a hit"
    );
    tokio::time::sleep(Duration::from_millis(80)).await;
    ttl.evaluate(deny_call, deny_bag)
        .await
        .expect("ttl after expiry");
    assert!(
        ttl.stats().expiries >= 1,
        "expired entries must not be returned, stats={:?}",
        ttl.stats()
    );
    assert_eq!(
        ttl.stats().hits,
        1,
        "a post-TTL evaluate is a miss, not a hit"
    );
}
