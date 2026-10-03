// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Distributed session stores for session-scoped labels.
//!
//! Module paths are fixed here rather than per extension as it lands: these are
//! public API from first publish, so a later rename is a breaking change.
//!
//! - `valkey` (`valkey`) — kind `valkey`
//!
//! The only group needing `praxis-policy-apl-runtime`, and the only one that
//! pulls a Redis client and a TLS stack.

#[cfg(feature = "valkey")]
pub mod valkey;
