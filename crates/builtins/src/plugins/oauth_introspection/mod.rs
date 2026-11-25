// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Asks an issuer about a token through RFC 7662 token introspection. One
//! plugin serves either hook it declares, or both, sharing one client and one
//! answer cache.
//!
//! `identity.resolve` authenticates a bearer token, typically an opaque one
//! no offline resolver can verify. An active response is checked (`exp`,
//! `nbf`, `iss`, and `aud` when audiences are configured) and mapped onto the
//! slot the `identity:` block names. The token is stored with this issuer
//! recorded on it. A JWT another issuer minted, or a value without the
//! configured prefix, is declined for another resolver and never sent.
//!
//! `revocation.check`: for each identity slot the engine asks about, the
//! checker takes the slot's raw inbound token and, when the token belongs to
//! the configured issuer, posts it to the issuer's introspection endpoint.
//! `active: true` vouches for the slot, `active: false` denies
//! `auth.revoked`, and a failed lookup denies `auth.revocation_unavailable`.
//! A slot with no raw token, or a token from another issuer, is left
//! unvouched for another checker to cover.
//!
//! Needs `perform_http` for the call, and `read_inbound_credentials` to read
//! the tokens at `revocation.check`.

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
/// The identity hook handler.
mod resolver;
/// Fixtures the test modules share.
#[cfg(test)]
mod test_support;

pub use config::{ClientSecretSource, IntrospectionConfig};
pub use factory::{IntrospectionFactory, KIND};
pub use plugin::IntrospectionPlugin;
