// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! By-kind plugins the engine instantiates from a config `kind:` string.
//!
//! Module paths are fixed here rather than per extension as it lands: these are
//! public API from first publish, so a later rename is a breaking change.
//!
//! - `identity_jwt` (`jwt`) — kind `identity/jwt`
//! - `identity_api_key` (`api-key`) — kind `identity/api-key`
//! - `delegator_oauth` (`oauth`) — kind `delegator/oauth`
//! - `elicitation_ciba` (`elicitation-ciba`) — kind `elicitation/ciba`

#[cfg(feature = "jwt")]
pub mod identity_jwt;

#[cfg(feature = "api-key")]
pub mod identity_api_key;

#[cfg(feature = "oauth")]
pub mod delegator_oauth;

#[cfg(feature = "elicitation-ciba")]
pub mod elicitation_ciba;
