// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End to end behaviour of the Kubernetes `TokenReview` resolver, from a config
//! block and a scripted API server through to a populated identity slot.
//!
//! Response bodies in `fixtures/` were captured from a real API server,
//! including the part that is easy to get wrong: `authenticated` is omitted,
//! not `false`, when the API server refuses the token.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "test and example code"
)]

mod backend;
mod resolver;

pub mod support;
