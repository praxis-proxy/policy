// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A record's fields onto the identity slots.
//
// The compiler is `praxis_policy_core::identity::mapping`, the same one the JWT
// plugin runs, so `subject.roles` means the same thing whichever credential
// produced it and a policy cannot tell them apart. This module is only the two
// places a record differs from a claim set.

use praxis_policy_core::identity::mapping::{
    ClaimMapConfig, ClaimsOverrides, ConfiguredClaimMap, MappingProfile,
};

/// What a mapped workload identity records as its attestor.
///
/// A policy gating on how an identity was established has to be told the truth
/// about it: this resolver verified an API key.
pub const ATTESTOR: &str = "api_key";

/// The field names the claims bag drops before projecting.
///
/// Empty, and that is the point. JWT mapping drops registered claims, which a
/// directory record does not carry: a record naming a field
/// `exp` or `iss` means its own thing by it, and dropping that loses an
/// attribute a policy may be written against, silently. A backend's own storage
/// fields are stripped by the backend instead, since only it knows which are
/// its own.
pub const RESERVED_FIELDS: &[&str] = &[];

/// Compile an operator's `record_map` block into the mapper that runs it.
///
/// # Errors
///
/// Whatever the shared compiler rejects: an unparseable path, a field that
/// cannot hold the shape asked of it, overrides that contradict each other.
pub fn compile(
    config: &ClaimMapConfig,
    claims: &ClaimsOverrides,
) -> Result<ConfiguredClaimMap, String> {
    let compiled = config.compile()?.with_claims(claims.compile()?);
    Ok(ConfiguredClaimMap::new(
        compiled,
        MappingProfile {
            reserved_names: RESERVED_FIELDS,
            attestor: ATTESTOR,
        },
    ))
}
