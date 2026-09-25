// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End to end behaviour of the API key resolver, from a config block and a
//! record file through to a populated identity slot.
//!
//! One harness rather than a binary per concern: cargo links one executable
//! per `tests/*.rs`, and these cases share their fixtures.

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

mod caching;
mod expiry;
mod extraction;
mod file_backend;
mod http_backend;
mod populations;
mod projection;
mod wiring;

pub mod support;
