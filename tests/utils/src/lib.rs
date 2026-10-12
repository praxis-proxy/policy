// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared harness for the integration, resilience and security suites.
//!
//! Every item is gated on the `suite` feature, so the default workspace pass
//! builds an empty crate and unifies no builtin features. A crate-level
//! `#![cfg]` would strip these docs too and trip `missing_docs`.

#![cfg_attr(
    feature = "suite",
    expect(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::panic,
        reason = "test harness; a broken fixture should fail the test loudly"
    )
)]

#[cfg(feature = "suite")]
pub mod capture;
#[cfg(feature = "suite")]
pub mod fixtures;
#[cfg(feature = "suite")]
pub mod host;
#[cfg(feature = "suite")]
pub mod idp;
#[cfg(feature = "suite")]
pub mod live;
#[cfg(feature = "suite")]
pub mod mcp;
#[cfg(feature = "suite")]
pub mod secrets;
#[cfg(feature = "suite")]
pub mod upstream;
