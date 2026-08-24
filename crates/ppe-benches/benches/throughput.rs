// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Throughput under concurrency (issue #19 — Throughput).
//!
//! Decisions/sec with many Tokio tasks calling `invoke_named`, including
//! YAML `mode: concurrent`.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "benchmark harness — Criterion macros + fixture expects"
)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ppe_benches::{
    YAML_CONCURRENT_PLUGINS, YAML_PLUGIN_THEN_CEDAR, engine_from_yaml, engine_plugins_only,
    extensions_reader, invoke_once,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::plugin::PluginMode;
use tokio::runtime::Runtime;

async fn burst(mgr: Arc<PolicyEngine>, tasks: usize) {
    let mut joins = Vec::with_capacity(tasks);
    for _ in 0..tasks {
        let m = Arc::clone(&mgr);
        joins.push(tokio::spawn(async move {
            black_box(invoke_once(&m, extensions_reader()).await);
        }));
    }
    for j in joins {
        j.await.expect("task join");
    }
}

fn throughput(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("throughput");
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(40);

    for &tasks in &[8_usize, 32, 128] {
        group.throughput(Throughput::Elements(tasks as u64));

        let seq = rt.block_on(engine_plugins_only(4, PluginMode::Sequential));
        group.bench_with_input(
            BenchmarkId::new("plugins_sequential", tasks),
            &tasks,
            |b, &t| {
                b.to_async(&rt).iter(|| async {
                    burst(Arc::clone(&seq), t).await;
                });
            },
        );

        let conc = rt.block_on(engine_plugins_only(4, PluginMode::Concurrent));
        group.bench_with_input(
            BenchmarkId::new("plugins_concurrent_mode", tasks),
            &tasks,
            |b, &t| {
                b.to_async(&rt).iter(|| async {
                    burst(Arc::clone(&conc), t).await;
                });
            },
        );

        let (full, _) = rt.block_on(engine_from_yaml(YAML_PLUGIN_THEN_CEDAR, None));
        group.bench_with_input(
            BenchmarkId::new("apl_plugin_then_cedar", tasks),
            &tasks,
            |b, &t| {
                b.to_async(&rt).iter(|| async {
                    burst(Arc::clone(&full), t).await;
                });
            },
        );

        let (yaml_conc, _) = rt.block_on(engine_from_yaml(YAML_CONCURRENT_PLUGINS, None));
        group.bench_with_input(
            BenchmarkId::new("apl_yaml_mode_concurrent", tasks),
            &tasks,
            |b, &t| {
                b.to_async(&rt).iter(|| async {
                    burst(Arc::clone(&yaml_conc), t).await;
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, throughput);
criterion_main!(benches);
