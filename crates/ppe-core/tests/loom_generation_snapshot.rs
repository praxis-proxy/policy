// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Extracted model of the `generation` / snapshot pairing in `PolicyEngine`.
//!
//! Production code publishes a snapshot and then bumps `generation` with
//! `Release`. Orchestrators load `generation` with `Acquire` and then load
//! the snapshot. The comment on `mutate_runtime` claims that a reader who
//! observes a higher generation is guaranteed to see the snapshot stored
//! before that bump.
//!
//! Loom explores every allowed interleaving of those atomics. The model is
//! this pairing only: two threads, two atomics. A third writer thread is
//! not included — exhaustive search does not scale past this size, and
//! writers are already serialised by `runtime_write` in the engine.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

/// One writer: `store` the snapshot, then `fetch_add(Release)` on
/// generation. A reader that `Acquire`-loads a non-zero generation must
/// see the stored snapshot.
#[test]
fn acquire_on_generation_sees_snapshot_stored_before_release_bump() {
    loom::model(|| {
        let snapshot = Arc::new(AtomicU64::new(0));
        let generation = Arc::new(AtomicU64::new(0));

        let writer_snapshot = Arc::clone(&snapshot);
        let writer_generation = Arc::clone(&generation);
        let writer = thread::spawn(move || {
            writer_snapshot.store(1, Ordering::Relaxed);
            writer_generation.fetch_add(1, Ordering::Release);
        });

        let reader_snapshot = Arc::clone(&snapshot);
        let reader_generation = Arc::clone(&generation);
        let reader = thread::spawn(move || {
            let observed = reader_generation.load(Ordering::Acquire);
            let snap = reader_snapshot.load(Ordering::Relaxed);
            if observed >= 1 {
                assert_eq!(
                    snap, 1,
                    "Acquire on generation must observe the snapshot \
                     stored before the Release bump; generation={observed} \
                     snap={snap}"
                );
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
    });
}
