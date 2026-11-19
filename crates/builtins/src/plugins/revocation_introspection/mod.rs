// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Checks revocation by asking the issuer, through RFC 7662 token
//! introspection.
//!
//! Handles `revocation.check`. For each identity slot the engine asks about,
//! the checker takes the slot's raw inbound token and, when the token names
//! the configured issuer, posts it to the issuer's introspection endpoint.
//! `active: true` vouches for the slot, `active: false` denies
//! `auth.revoked`, and a failed lookup denies `auth.revocation_unavailable`.
//! A slot with no raw token, or a token from another issuer, is left
//! unvouched for another checker to cover.
//!
//! Needs `perform_http` for the call and `read_inbound_credentials` for the
//! tokens.

/// The answer cache in front of the introspection endpoint.
mod cache;
/// The revocation hook handler.
pub mod checker;
/// Plugin configuration and its validation.
pub mod config;
/// Constructs the checker from configuration.
pub mod factory;

pub use checker::IntrospectionChecker;
pub use config::{ClientSecretSource, IntrospectionConfig};
pub use factory::{IntrospectionFactory, KIND};
