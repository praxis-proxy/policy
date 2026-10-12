// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Resilience suite: how the full engine behaves when a dependency fails or
//! calls run concurrently.
//!
//! Known gaps follow the convention in the integration suite.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code"
)]

mod concurrency;
mod dependency_failure;
mod smoke;
