// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Stack headroom for PDP work that recurses over nested input.

/// Grow the stack when the current thread has less than this much headroom.
/// cedar-policy-core's own guard is 100 `KiB` (`REQUIRED_STACK_SPACE`); we grow
/// at 10x that so the guard never fires mid-descent. On glibc (8 MiB thread
/// stacks) there is usually more than this available, so `maybe_grow` is a
/// cheap no-op; on musl (128 `KiB` default) we fall below it and grow.
const RED_ZONE: usize = 1024 * 1024;

/// Size of the fresh stack segment to run on when we grow. Matches glibc's
/// default 8 MiB thread stack. Allocated only on small-stack hosts, freed when
/// the work returns.
const GROW_SIZE: usize = 8 * 1024 * 1024;

/// Run `work` with at least [`RED_ZONE`] of stack, growing onto a
/// [`GROW_SIZE`] segment when the current thread has less. `work` must be
/// synchronous. Convert, evaluate and drop nested input inside it, since each
/// of those recurses.
pub(crate) fn guarded<R>(work: impl FnOnce() -> R) -> R {
    stacker::maybe_grow(RED_ZONE, GROW_SIZE, work)
}
