// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Secret providers a host wires in to resolve `secret:` references.
//!
//! Module paths are fixed here rather than per extension as it lands: these are
//! public API from first publish, so a later rename is a breaking change.
//!
//! - `vault` (`secrets-vault`) — kind `vault`
//!
//! Unlike the other groups this one is not auto-registered: a provider needs an
//! `HttpTransport` the host supplies, so the facade exposes a registration
//! helper rather than wiring it into `install_builtins`.
