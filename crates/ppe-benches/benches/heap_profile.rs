// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Isolated heap measurements (issue #19 — Memory).
//!
//! Unlike the Criterion `memory` target, this binary runs a **fixed** number of
//! decisions under `dhat` so totals are attributable:
//!
//! - **per-decision** — `total_bytes / N` after N hot-path invokes (setup outside)
//! - **policy-size footprint** — `max_bytes` after load + one decide for 1/10/50
//!   Cedar policies
//!
//! Each profiler scope writes its own JSON file (`dhat-heap-*.json`).
//!
//! ```bash
//! cargo bench -p ppe-benches --features dhat-heap --bench heap_profile
//! ```

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "heap profile harness — prints findings for docs/dev/benchmarks.md"
)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use ppe_benches::{
    YAML_PLUGIN_THEN_CEDAR, engine_from_yaml, extensions_reader, extensions_with_session,
    invoke_once, yaml_cedar_policy_count,
};
use tokio::runtime::Runtime;

const PER_DECISION_ITERS: usize = 500;

fn profile_per_decision(rt: &Runtime) {
    // Engine setup is outside the profiler so bytes are hot-path only.
    let (mgr, _) = rt.block_on(engine_from_yaml(YAML_PLUGIN_THEN_CEDAR, None));
    let _profiler = dhat::Profiler::builder()
        .file_name("dhat-heap-per-decision.json")
        .build();
    let before = dhat::HeapStats::get();
    for _ in 0..PER_DECISION_ITERS {
        rt.block_on(invoke_once(&mgr, extensions_with_session("bench-sess")));
    }
    let after = dhat::HeapStats::get();
    let delta = after.total_bytes.saturating_sub(before.total_bytes);
    let per = delta / PER_DECISION_ITERS as u64;
    println!(
        "iters={PER_DECISION_ITERS} delta_total_bytes={delta} per_decision_bytes≈{per} peak_max_bytes={}",
        after.max_bytes
    );
    println!("wrote dhat-heap-per-decision.json");
}

fn profile_policy_size(rt: &Runtime, n_policies: usize) {
    let yaml = yaml_cedar_policy_count(n_policies);
    let file_name = format!("dhat-heap-policy-{n_policies}.json");
    // Profiler starts before the load: Cedar compile is the footprint this
    // measures, so it has to be inside the profiled window.
    let _profiler = dhat::Profiler::builder().file_name(&file_name).build();
    let (mgr, _) = rt.block_on(engine_from_yaml(&yaml, None));
    rt.block_on(invoke_once(&mgr, extensions_reader()));
    let stats = dhat::HeapStats::get();
    println!(
        "policies={n_policies} total_bytes={} max_bytes={} curr_bytes={}",
        stats.total_bytes, stats.max_bytes, stats.curr_bytes
    );
    println!("wrote {file_name}");
}

fn main() {
    let rt = Runtime::new().expect("tokio runtime");

    println!("ppe-benches heap_profile (dhat-heap)");
    println!("--- per-decision allocation ---");
    profile_per_decision(&rt);

    println!("--- policy-size footprint (load + 1 decide) ---");
    for &n_policies in &[1_usize, 10, 50] {
        profile_policy_size(&rt, n_policies);
    }
}
