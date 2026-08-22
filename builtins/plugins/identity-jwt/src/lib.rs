// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-plugin-identity-jwt — JWT-based `IdentityResolveHandler` for APL.
//
// Validates inbound JWTs against configured trusted issuers and
// maps validated claims into the request's `IdentityPayload`
// (subject / client / raw_credentials slots). The lightweight
// identity path: validate a Bearer token and extract identity,
// independent of any PDP step that runs later in the route.
//
// Scope: data shapes + module structure only. Actual validation
// logic, multi-issuer + key rotation, and integration tests land later.
//
// # Error handling
//
// No bespoke error type. Two surfaces:
//
//   * **Build / config errors** — constructors return
//     `Result<Self, Box<PluginError>>`. Bad PEM, missing issuer
//     URL, etc. surface as `PluginError::Config { message }`.
//   * **Runtime token-rejection errors** — handler returns
//     `PluginResult::deny(PluginViolation::new(code, reason))`.
//     `code` is a stable identifier the host can map to HTTP
//     status (`auth.token_expired`, `auth.signature_invalid`,
//     `auth.untrusted_issuer`, …); `reason` is the operator-
//     readable message.
//
// # When to use this vs alternatives
//
// - **`praxis-policy-plugin-identity-jwt`** (this crate) — JWT-only flow.
//   Lightweight, ~5-15 transitive deps. The default choice for
//   "validate a Bearer token, extract identity."
// - **Custom resolver** — anyone with bespoke identity flows
//   (mTLS-only, opaque tokens with introspection, capability
//   tokens) writes their own `HookHandler<IdentityHook>`. This
//   crate's API surface is the reference shape but nothing
//   prevents other resolvers from coexisting.

//! Validates inbound JWTs and fills the request's identity slots.
//!
//! Checks a token against the configured trusted issuers, then maps its claims
//! into the subject, client, or workload slot. This is the lightweight identity
//! path: it establishes who is calling, independent of any decision point that
//! runs later in the route.
//!
//! Which claims fill which field is configuration. Name a shipped preset with
//! `claim_mapper` (`standard`, `keycloak`, `auth0`, `cognito`) or write a
//! [`ClaimMapConfig`] under `claim_map` for a shape no preset covers, including
//! the nested and URL-namespaced claims that otherwise need Rust. Naming no
//! mapper resolves to `standard`, which maps what this plugin has always mapped.

/// Maps validated claims onto the identity slots.
pub mod claim_map;
/// The claim map an operator authors, and its compiled form.
pub mod claim_map_config;
/// Addresses a claim value by a dot-separated path.
pub mod claim_path;
/// Plugin configuration and its validation.
pub mod config;
/// The mapper a compiled claim map drives.
pub mod configured_mapper;
/// Constructs the resolver from configuration.
pub mod factory;
/// The shipped claim maps, by name.
pub mod presets;
/// The identity hook handler.
pub mod resolver;
/// A trusted issuer, its key store, and its accepted algorithms.
pub mod trusted_issuer;

pub use claim_map::{ClaimMap, ClaimMapper, StandardClaimMap};
pub use claim_map_config::{
    ClaimMapConfig, ClaimsOverrides, CompiledClaimMap, CompiledClaimsOverrides, CompiledRoleMap,
    MergeMode, OnMissing, SplitMode,
};
pub use claim_path::ClaimPath;
pub use config::{DecodingKeySource, JwtIdentityResolverConfig, TrustedIssuerConfig};
pub use configured_mapper::ConfiguredClaimMap;
pub use factory::{JwtIdentityFactory, KIND};
pub use presets::{DEFAULT_PRESET, Preset};
pub use resolver::JwtIdentityResolver;
pub use trusted_issuer::TrustedIssuer;
