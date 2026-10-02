// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The identity headers an auth endpoint returns, onto the subject slots.
//
// The compiler is `praxis_policy_core::identity::mapping`, the same one the JWT
// and API-key resolvers run, so `subject.teams` means the same thing whichever
// credential produced it and a policy cannot tell them apart. This module is
// only the two places a ForwardAuth record differs from a claim set.

use praxis_policy_core::identity::mapping::{
    ClaimMapConfig, ClaimsOverrides, ConfiguredClaimMap, MappingProfile,
};

/// What a mapped workload identity records as its attestor.
///
/// A policy gating on how an identity was established has to be told the truth
/// about it: this resolver validated an opaque session by delegating to an
/// external authentication endpoint.
pub const ATTESTOR: &str = "forward_auth";

/// The field names the claims bag drops before projecting.
///
/// Empty, and that is the point. JWT mapping drops registered claims, which the
/// identity headers an auth endpoint returns do not carry: a header named
/// `x-auth-request-email` means its own thing, and dropping it would lose an
/// attribute a policy may be written against, silently. The endpoint's own
/// bookkeeping headers never reach this map — only the configured
/// `identity_headers` do — so there is nothing to strip here.
pub const RESERVED_FIELDS: &[&str] = &[];

/// Compile an operator's `claim_map` block into the mapper that runs it.
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
