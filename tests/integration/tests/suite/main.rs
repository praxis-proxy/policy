// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Integration suite: the full engine, builtins and reference plugins driven
//! the way a host drives them.
//!
//! # Known gaps
//!
//! A test that exposes an open defect is named `known_gap_*`. It asserts the
//! desired behavior with a message containing `known gap #<issue>` and is
//! marked `#[should_panic(expected = "known gap #<issue>")]`, so it passes
//! while the defect stands and fails once the fix lands. Remove the marker and
//! the prefix in the fixing change.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code"
)]

mod host_contract;
mod scenarios;
mod smoke;
