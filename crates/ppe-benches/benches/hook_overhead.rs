// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hook / plugin-dispatch overhead (issue #19 — Time: plugin dispatch).
//!
//! Isolates the executor path with **no APL visitor and no PDP**:
//! `register_handler_for_names` → `invoke_named` → N no-op `HookHandler`s.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "benchmark harness — Criterion macros + fixture expects"
)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ppe_benches::{
    HOOK_TOOL_PRE, cmf_payload, engine_plugins_only, extensions_reader, invoke_once,
};
use praxis_policy_core::cmf::CmfHook;
use praxis_policy_core::plugin::PluginMode;
use tokio::runtime::Runtime;

fn hook_overhead(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("hook_overhead");
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(100);

    for &n in &[1_usize, 4, 16] {
        let mgr = rt.block_on(engine_plugins_only(n, PluginMode::Sequential));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("sequential", n), &n, |b, _| {
            b.to_async(&rt).iter(|| async {
                black_box(invoke_once(&mgr, extensions_reader()).await);
            });
        });

        let mgr_c = rt.block_on(engine_plugins_only(n, PluginMode::Concurrent));
        group.bench_with_input(BenchmarkId::new("concurrent", n), &n, |b, _| {
            b.to_async(&rt).iter(|| async {
                black_box(invoke_once(&mgr_c, extensions_reader()).await);
            });
        });
    }

    // Reset throughput so empty_registry is not reported as Elements(16).
    group.throughput(Throughput::Elements(1));
    let empty = rt.block_on(engine_plugins_only(0, PluginMode::Sequential));
    group.bench_function("empty_registry", |b| {
        b.to_async(&rt).iter(|| async {
            let (result, _bg) = empty
                .invoke_named::<CmfHook>(
                    HOOK_TOOL_PRE,
                    cmf_payload("bench"),
                    extensions_reader(),
                    None,
                )
                .await;
            black_box(result.continue_processing);
        });
    });

    group.finish();
}

criterion_group!(benches, hook_overhead);
criterion_main!(benches);
