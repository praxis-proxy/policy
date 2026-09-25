// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

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

//! Integration harness for the `cedar` extension. One linked binary per
//! extension: cargo links one executable per test target, and these cases share
//! their fixtures.

mod basic_allow_deny;
mod entities_unit;
mod request_context;
mod resolver_config;
mod small_stack_eval;
mod visitor_pdp_config;
