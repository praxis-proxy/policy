// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Memory / session-taint growth (issue #19 — Memory).
//!
//! 1. **`SessionStore` curve** — `append_labels` / `load_labels` as label
//!    set and session count grow (session taint sticks across requests).
//! 2. **Policy-size sweep** — full decision latency as Cedar policy count grows.
//! 3. **Optional dhat** — `cargo bench -p ppe-benches --features dhat-heap
//!    --bench memory` writes `dhat-heap.json`. See `docs/benchmarks.md`.
//!    For isolated per-decision / policy-size heap numbers use
//!    `--bench heap_profile` (requires `dhat-heap`).

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "benchmark harness — Criterion macros + fixture expects"
)]
#![cfg_attr(feature = "dhat-heap", allow(dead_code))]

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ppe_benches::{
    YAML_PLUGIN_THEN_CEDAR, engine_from_yaml, extensions_reader, extensions_with_session,
    invoke_once, yaml_cedar_policy_count,
};
use praxis_policy_apl_runtime::{MemorySessionStore, SessionStore as _};
use tokio::runtime::Runtime;

fn seed_store(rt: &Runtime, n_labels: usize) -> Arc<MemorySessionStore> {
    let store = Arc::new(MemorySessionStore::new());
    let seed: Vec<String> = (0..n_labels).map(|i| format!("L{i}")).collect();
    rt.block_on(async {
        store
            .append_labels("sess-taint", &seed)
            .await
            .expect("seed");
    });
    store
}

fn memory(c: &mut Criterion) {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("memory");
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4))
        .sample_size(60);

    for &n_labels in &[8_usize, 64, 512] {
        let store = seed_store(&rt, n_labels);
        group.throughput(Throughput::Elements(n_labels as u64));
        group.bench_with_input(
            BenchmarkId::new("session_load_labels", n_labels),
            &n_labels,
            |b, _| {
                let store = Arc::clone(&store);
                b.to_async(&rt).iter(|| async {
                    let labels = store.load_labels("sess-taint").await.expect("load");
                    black_box(labels.len());
                });
            },
        );

        // Reseed to exactly `n_labels` every iteration so the starting size is
        // stable (unique-append on a shared store would swamp 8/64/512).
        // Use sync `iter_batched` (not `to_async`) so setup can `block_on`
        // without nesting inside Criterion's async runtime.
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("session_append_one", n_labels),
            &n_labels,
            |b, &n| {
                b.iter_batched(
                    || seed_store(&rt, n),
                    |store| {
                        rt.block_on(async {
                            store
                                .append_labels("sess-taint", &["EXTRA".to_owned()])
                                .await
                                .expect("append");
                            black_box(store);
                        });
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    for &n_sessions in &[10_usize, 100, 1000] {
        let store = Arc::new(MemorySessionStore::new());
        rt.block_on(async {
            for i in 0..n_sessions {
                let sid = format!("s{i}");
                store
                    .append_labels(&sid, &["PII".to_owned(), "INTERNAL".to_owned()])
                    .await
                    .expect("seed session");
            }
        });
        group.throughput(Throughput::Elements(n_sessions as u64));
        group.bench_with_input(
            BenchmarkId::new("session_snapshot", n_sessions),
            &n_sessions,
            |b, _| {
                let store = Arc::clone(&store);
                b.iter(|| {
                    let snap = store.snapshot();
                    black_box(snap.len());
                });
            },
        );
    }

    // Reset so this single-decision bench is not reported as Elements(1000).
    group.throughput(Throughput::Elements(1));
    let (mgr, _store) = rt.block_on(engine_from_yaml(YAML_PLUGIN_THEN_CEDAR, None));
    group.bench_function("full_decision_with_session_id", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(invoke_once(&mgr, extensions_with_session("bench-sess")).await);
        });
    });

    // Policy-size sweep: decision latency as Cedar rule count grows (ticket:
    // footprint / cost vs policy size). Heap bytes for the same sweep live in
    // `--bench heap_profile`.
    for &n_policies in &[1_usize, 10, 50] {
        let yaml = yaml_cedar_policy_count(n_policies);
        let (mgr, _) = rt.block_on(engine_from_yaml(&yaml, None));
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("policy_size_decision", n_policies),
            &n_policies,
            |b, _| {
                let mgr = Arc::clone(&mgr);
                b.to_async(&rt).iter(|| async {
                    black_box(invoke_once(&mgr, extensions_reader()).await);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, memory);
criterion_main!(benches);
