// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code"
)]

//! JWT and `DPoP` verification under `jwt-openssl-fips`.
//!
//! The `jsonwebtoken` provider and OpenSSL's provider state are process-wide,
//! so each case that depends on them runs in a child process with its own
//! `OPENSSL_CONF`. The parent is what `make` selects; it asserts the child ran
//! exactly one test. Tokens come from published RFC examples or are signed
//! with `RustCrypto`, never by OpenSSL.

mod oracle;
mod refusals;
mod support;
mod verify;
