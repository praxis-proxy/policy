// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Full-decision latency (issue #19 — Time: full decision + eval vs dispatch).
//!
//! | Fixture              | Path                                      |
//! |----------------------|-------------------------------------------|
//! | `plugin_only`        | APL route → `run(noop)`                   |
//! | `cedar_only`         | APL route → `cedar:` PDP step             |
//! | `plugin_then_cedar`  | APL → plugin then Cedar (operator shape) |
//!
//! Flamegraph: `cargo flamegraph -p ppe-benches --bench full_decision`

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "benchmark harness — Criterion macros + fixture expects"
)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use ppe_benches::{
    YAML_CEDAR_ONLY, YAML_PLUGIN_ONLY, YAML_PLUGIN_THEN_CEDAR, engine_from_yaml, extensions_reader,
    invoke_once,
};
use tokio::runtime::Runtime;

fn full_decision(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("full_decision");
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(80);

    let (plugin_only, _) = rt.block_on(engine_from_yaml(YAML_PLUGIN_ONLY, None));
    group.bench_function("plugin_only", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(invoke_once(&plugin_only, extensions_reader()).await);
        });
    });

    let (cedar_only, _) = rt.block_on(engine_from_yaml(YAML_CEDAR_ONLY, None));
    group.bench_function("cedar_only", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(invoke_once(&cedar_only, extensions_reader()).await);
        });
    });

    let (full, _) = rt.block_on(engine_from_yaml(YAML_PLUGIN_THEN_CEDAR, None));
    group.bench_function("plugin_then_cedar", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(invoke_once(&full, extensions_reader()).await);
        });
    });

    group.finish();
}

criterion_group!(benches, full_decision);
criterion_main!(benches);
