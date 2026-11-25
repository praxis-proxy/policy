// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Basic credential decoding, hash verification, and directory regression tests.

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

mod challenge;
mod decoding;
mod engine_e2e;
mod htpasswd_backend;
mod projection;
mod user_file_backend;
mod verifying;
mod wiring;

/// Shared test utilities for Basic authentication cases.
pub mod support;
