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
//! ```bash
//! cargo bench -p ppe-benches --features dhat-heap --bench heap_profile
//! ```

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "heap profile harness — prints findings for docs/benchmarks.md"
)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::sync::Arc;

use ppe_benches::{
    YAML_PLUGIN_THEN_CEDAR, engine_from_yaml, extensions_reader, extensions_with_session,
    invoke_once, yaml_cedar_policy_count,
};
use tokio::runtime::Runtime;

const PER_DECISION_ITERS: usize = 500;

fn main() {
    let rt = Runtime::new().expect("tokio runtime");

    println!("ppe-benches heap_profile (dhat-heap)");
    println!("--- per-decision allocation ---");
    {
        let _profiler = dhat::Profiler::new_heap();
        let (mgr, _) = rt.block_on(engine_from_yaml(YAML_PLUGIN_THEN_CEDAR, None));
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
    }

    println!("--- policy-size footprint (load + 1 decide) ---");
    for &n_policies in &[1_usize, 10, 50] {
        let _profiler = dhat::Profiler::new_heap();
        let yaml = yaml_cedar_policy_count(n_policies);
        let (mgr, _) = rt.block_on(engine_from_yaml(&yaml, None));
        rt.block_on(invoke_once(&mgr, extensions_reader()));
        let stats = dhat::HeapStats::get();
        println!(
            "policies={n_policies} total_bytes={} max_bytes={} curr_bytes={}",
            stats.total_bytes, stats.max_bytes, stats.curr_bytes
        );
        // Keep engine alive until after stats read.
        let _keep = Arc::clone(&mgr);
    }

    println!("dhat-heap.json written on profiler drop (see docs/benchmarks.md)");
}
