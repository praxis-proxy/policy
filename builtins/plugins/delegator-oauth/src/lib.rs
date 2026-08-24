// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-plugin-delegator-oauth — `TokenDelegateHandler` backed by RFC 8693
// OAuth 2.0 Token Exchange.
//
// The host registers this handler against `token.delegate`; outbound
// forwarding plugins invoke `mgr.invoke_named::<TokenDelegateHook>(...)`
// with a `DelegationPayload` (caller's bearer token + target
// audience + required scopes); this handler POSTs to the configured
// OAuth server's token endpoint with `grant_type=urn:ietf:params:
// oauth:grant-type:token-exchange` and the appropriate
// `subject_token` / `audience` / `scope` parameters; the response's
// `access_token` becomes the `RawDelegatedToken` the framework
// stashes under `Extensions.raw_credentials.delegated_tokens`.
//
// Scope: data shapes + module structure only. Actual HTTP exchange
// logic and mock-IdP integration tests land later.

//! Mints downstream credentials by RFC 8693 token exchange.
//!
//! Handles the delegation hook: given the caller's token, a target audience,
//! and the scopes a route requires, it exchanges at the configured endpoint and
//! returns a token scoped to that audience alone.

/// Reuse of live delegated tokens: key derivation and cache settings.
pub mod cache;
/// Plugin configuration and its validation.
pub mod config;
/// The delegation hook handler.
pub mod delegator;
/// Constructs the delegator from configuration.
pub mod factory;

pub use cache::{CacheConfig, StalenessConfig};
pub use config::{ClientSecretSource, OAuthDelegatorConfig};
pub use delegator::OAuthDelegator;
pub use factory::{KIND, OAuthDelegatorFactory};
