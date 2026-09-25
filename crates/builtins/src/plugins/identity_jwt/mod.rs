// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Validates inbound JWTs and fills the request's identity slots.
//!
//! Checks a token against the configured trusted issuers, then maps its claims
//! into the subject, client, or workload slot. This is the lightweight identity
//! path: it establishes who is calling, independent of any decision point that
//! runs later in the route.
//!
//! Which claims fill which field is configuration. Name a shipped preset with
//! `claim_mapper` (`standard`, `keycloak`, `auth0`, `cognito`, `ibmverify`) or write a
//! [`ClaimMapConfig`] under `claim_map` for a shape no preset covers, including
//! the nested and URL-namespaced claims that otherwise need Rust. Naming no
//! mapper resolves to `standard`, which maps what this plugin has always mapped.
//!
//! # Error handling
//!
//! No bespoke error type. Two surfaces:
//!
//! - **Build and config errors** — constructors return
//!   `Result<Self, Box<PluginError>>`. Bad PEM, a missing issuer URL and the
//!   like surface as `PluginError::Config { message }`.
//! - **Runtime token rejection** — the handler returns
//!   `PluginResult::deny(PluginViolation::new(code, reason))`. `code` is a
//!   stable identifier a host can map to an HTTP status
//!   (`auth.token_expired`, `auth.signature_invalid`,
//!   `auth.untrusted_issuer`, …); `reason` is the operator-readable message.
//!
//! # When to use this
//!
//! This is the JWT-only flow, and the default choice for "validate a Bearer
//! token, extract identity". Bespoke identity flows — mTLS-only, opaque tokens
//! with introspection, capability tokens — implement
//! `HookHandler<IdentityHook>` instead. This module's API surface is the
//! reference shape, and nothing prevents other resolvers coexisting with it.

/// The OIDC-standard claim map.
pub mod claim_map;
/// Plugin configuration and its validation.
pub mod config;
/// Constructs the resolver from configuration.
pub mod factory;
/// The shipped claim maps, by name.
pub mod presets;
/// The identity hook handler.
pub mod resolver;
/// A trusted issuer, its key store, and its accepted algorithms.
pub mod trusted_issuer;

pub use claim_map::StandardClaimMap;
// The map compiler and the mapper it drives live in core, since an API key
// directory record maps the same way a claim set does. Re-exported here so a
// host naming them through this crate keeps working.
pub use config::{
    DecodingKeySource, JwksFetch, JwksFetchBudget, JwtIdentityResolverConfig, KeySourceError,
    TrustedIssuerConfig,
};
pub use factory::{JwtIdentityFactory, KIND};
pub use praxis_policy_core::identity::mapping::{
    ClaimMap, ClaimMapConfig, ClaimMapper, ClaimPath, ClaimsOverrides, CompiledClaimMap,
    CompiledClaimsOverrides, CompiledRoleMap, ConfiguredClaimMap, MergeMode, OnMissing, SplitMode,
};
pub use presets::{DEFAULT_PRESET, Preset};
pub use resolver::JwtIdentityResolver;
pub use trusted_issuer::TrustedIssuer;
