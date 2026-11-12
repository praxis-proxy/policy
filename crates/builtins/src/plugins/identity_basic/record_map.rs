// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A record's fields onto the identity slots.
//
// The compiler is `praxis_policy_core::identity::mapping`, the same one the JWT
// and API-key plugins run, so `subject.roles` means the same thing whichever
// credential produced it and a policy cannot tell them apart. This module is
// only the three places a Basic record differs from a claim set.

use praxis_policy_core::extensions::raw_credentials::TokenRole;
use praxis_policy_core::identity::mapping::claim_map_config::RoleMapConfig;
use praxis_policy_core::identity::mapping::{
    ClaimMapConfig, ClaimsOverrides, ConfiguredClaimMap, MappingProfile,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// What a mapped workload identity records as its attestor.
///
/// A policy gating on how an identity was established has to be told the truth
/// about it: this resolver verified a password against a stored hash.
pub const ATTESTOR: &str = "basic";

/// The field name the resolver injects the verified user-id under.
///
/// Every backend here is indexed by user-id and `.htpasswd` carries nothing
/// else, so without this a record would project no anchor and the default
/// configuration would deny every authenticated caller. Injected by the
/// resolver rather than by each backend, so one name serves all three.
pub const USER_ID_FIELD: &str = "user_id";

/// The field names the claims bag drops before projecting.
///
/// Empty, matching the API-key plugin, and for its reason: a directory record
/// carries operator-chosen names, so a static drop list would silently remove
/// an attribute a policy is written against. The injected user-id needs no
/// entry either, because the default anchor consumes it and an operator who
/// re-anchors `subject.id` elsewhere has said they want it in the bag.
/// A backend's own storage fields are stripped by the backend, since only it
/// knows which are its own.
pub const RESERVED_FIELDS: &[&str] = &[];

// -----------------------------------------------------------------------------
// Compilation
// -----------------------------------------------------------------------------

/// Compile an operator's `record_map` block into the mapper that runs it.
///
/// A block with no section for `role` is given one anchoring that role's
/// identifier on the verified user-id, so the minimal `.htpasswd` deployment
/// needs no `record_map` at all.
///
/// # Errors
///
/// Whatever the shared compiler rejects: an unparseable path, a field that
/// cannot hold the shape asked of it, overrides that contradict each other.
pub fn compile(
    config: &ClaimMapConfig,
    claims: &ClaimsOverrides,
    role: &TokenRole,
) -> Result<ConfiguredClaimMap, String> {
    let compiled = with_default_anchor(config, role)
        .compile()?
        .with_claims(claims.compile()?);
    Ok(ConfiguredClaimMap::new(
        compiled,
        MappingProfile {
            reserved_names: RESERVED_FIELDS,
            attestor: ATTESTOR,
        },
    ))
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// The operator's block, with the role's section defaulted when absent.
///
/// Only the whole section is defaulted, and only for the two roles whose
/// anchor a user-id can actually satisfy. A section an operator wrote is left
/// exactly as written, including one that omits the anchor: silently adding a
/// `user_id` fallback under a map that names another field would authenticate
/// a caller under an identifier the operator did not choose.
///
/// `caller_workload` is deliberately not defaulted. Its anchor is `spiffe_id`
/// and the mapper requires a SPIFFE-shaped value with an authority, which a
/// user-id is not, so a defaulted section would compile and then decline every
/// request. An operator wanting that role writes the section themselves and
/// gets the compiler's own error when the value cannot serve it.
fn with_default_anchor(config: &ClaimMapConfig, role: &TokenRole) -> ClaimMapConfig {
    let mut defaulted = config.clone();
    let (anchor, section) = match role {
        TokenRole::User => ("id", &mut defaulted.subject),
        TokenRole::Client => ("client_id", &mut defaulted.client),
        // `validate` refuses a role with no section, which is where a role
        // this module cannot default is reported. Returning the block
        // unchanged leaves that error to say so, rather than inventing a
        // section the mapper would decline on every request.
        _ => return defaulted,
    };
    if section.is_none() {
        *section = Some(RoleMapConfig(
            [(anchor.to_owned(), serde_json::json!(USER_ID_FIELD))]
                .into_iter()
                .collect(),
        ));
    }
    defaulted
}
