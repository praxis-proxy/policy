// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Hit vs miss cost for the PDP decision cache, harness-aligned with
// PR 35's `ppe-benches` `pdp_cost` bench (issue #19): same CEL fixture
// (`has(role.reader) && role.reader` plus `reader_bag`), `to_async`,
// `SamplingMode::Flat`, setup (including CEL compile) outside the timed
// loop. When that crate is on main, copy these two functions next to
// `cel_evaluate` as `pdp_cost/cache_hit` and `pdp_cost/cache_miss`.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "benchmark harness — Criterion macros + fixture expects"
)]

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpResolver};
use praxis_policy_apl_runtime::{CachedPdpResolver, DecisionCacheConfig};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_pdp_cel::CelResolver;
use tokio::runtime::Runtime;

/// Fail loud in setup if a fixture times a deny path (same idea as PR 35).
fn assert_allow(label: &str, d: &PdpDecision) {
    assert!(
        matches!(d.decision, Decision::Allow),
        "{label} fixture must allow; got {:?}",
        d.decision
    );
}

fn cel_call(expr: &str) -> PdpCall {
    let mut m = serde_yaml::Mapping::new();
    m.insert(
        serde_yaml::Value::String("expr".into()),
        serde_yaml::Value::String(expr.into()),
    );
    PdpCall {
        dialect: PdpDialect::Cel,
        args: serde_yaml::Value::Mapping(m),
    }
}

/// Same bag as `ppe-benches` `pdp_cost::reader_bag`.
fn reader_bag() -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    bag.set("role.reader", true);
    bag
}

fn bench_cache(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("pdp_cost");
    group
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4))
        .sample_size(100);

    let mgr = Arc::new(PolicyEngine::default());
    let inner: Arc<dyn PdpResolver> = Arc::new(CelResolver::new());
    let call = cel_call("has(role.reader) && role.reader");
    let bag = reader_bag();
    {
        let d = rt.block_on(inner.evaluate(&call, &bag)).expect("cel setup");
        assert_allow("cel_evaluate", &d);
    }

    // Cap is well above Criterion's iteration count so a miss is hash +
    // CEL evaluate + insert, not FIFO eviction (see review of #101).
    let miss_cache = CachedPdpResolver::wrap(
        Arc::clone(&inner),
        DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries: 1_000_000,
        },
        Arc::downgrade(&mgr),
    );
    let nonce = AtomicU64::new(0);
    group.bench_function("cache_miss", |b| {
        b.to_async(&rt).iter(|| async {
            let mut unique = bag.clone();
            unique.set("nonce", nonce.fetch_add(1, Ordering::Relaxed).to_string());
            let d = miss_cache
                .evaluate(black_box(&call), black_box(&unique))
                .await
                .expect("cache miss");
            black_box(d);
        });
    });

    let hit_cache = CachedPdpResolver::wrap(
        inner,
        DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries: 1024,
        },
        Arc::downgrade(&mgr),
    );
    {
        let d = rt
            .block_on(hit_cache.evaluate(&call, &bag))
            .expect("cache_hit seed");
        assert_allow("cache_hit seed", &d);
    }
    group.bench_function("cache_hit", |b| {
        b.to_async(&rt).iter(|| async {
            let d = hit_cache
                .evaluate(black_box(&call), black_box(&bag))
                .await
                .expect("cache hit");
            black_box(d);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
