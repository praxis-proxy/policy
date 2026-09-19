// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Identity hook family — IdentityResolve.
//
// Mirrors the cmf/ module layout: the hook marker + handler trait
// machinery (provided by praxis-policy-core's generic hooks layer) plus the
// hook-specific payload + result types. Token-delegation lives in
// its own sibling module; the two hook families share
// nothing in terms of payloads so they get separate `HookTypeDef`
// markers.
//
// Scope: data shapes only — no executor wiring, no
// framework merge-into-Extensions logic, no APL integration. Those
// land later.

/// The identity resolution hook.
pub mod hook;
/// Maps a JSON record onto the typed identity slots.
pub mod mapping;
/// The payload carrying resolved subject, client, and workload.
pub mod payload;
/// Per-route identity configuration.
pub mod route_config;

pub use hook::{HOOK_IDENTITY_RESOLVE, IdentityHook};
pub use mapping::{ClaimMap, ClaimMapConfig, ClaimMapper, ClaimPath, ConfiguredClaimMap};
pub use payload::{IdentityPayload, TokenSource};
pub use route_config::{RouteIdentityConfig, RouteIdentityStep};
