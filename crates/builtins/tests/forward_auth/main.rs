// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End to end behaviour of the `ForwardAuth` resolver, from a config block and a
//! scripted endpoint through to a populated identity slot — or an unauthenticated
//! pass-through, or a fail-closed deny.
//!
//! One harness rather than a binary per concern: cargo links one executable per
//! `tests/*.rs`, and these cases share their fixtures.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "test and example code"
)]

mod config;
mod resolve;

pub mod support;
