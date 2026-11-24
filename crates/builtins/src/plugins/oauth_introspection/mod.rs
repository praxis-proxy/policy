// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Asks an issuer about a token through RFC 7662 token introspection.
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
mod checker;
/// The introspection call both hooks share.
mod client;
/// Plugin configuration and its validation.
pub mod config;
/// Constructs the plugin from configuration.
pub mod factory;
/// The plugin and its construction.
mod plugin;
/// Fixtures the test modules share.
#[cfg(test)]
mod test_support;

pub use config::{ClientSecretSource, IntrospectionConfig};
pub use factory::{IntrospectionFactory, KIND};
pub use plugin::IntrospectionPlugin;
