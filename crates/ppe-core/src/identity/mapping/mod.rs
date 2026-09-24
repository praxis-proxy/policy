// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Maps a JSON record onto the typed identity slots.
//
// One compiler and one resolution routine, shared by every resolver whose
// credential resolves to a JSON object: a JWT's validated claims, an API key
// directory's record. The shape is the same problem in both cases, and a policy
// written against `subject.roles` cannot tell which produced it.
//
// The provider-specific parts stay with the resolver that knows them. The JWT
// plugin keeps its OIDC claim names and its Keycloak / Auth0 / Cognito presets;
// this module holds only what is true of any record.

/// The claim map an operator authors, and its compiled form.
pub mod claim_map_config;
/// Addresses a value by a dot-separated path.
pub mod claim_path;
/// The mapper a compiled map drives.
pub mod configured_mapper;

use std::collections::HashMap;

use serde_json::Value;

use crate::extensions::{ClientExtension, SubjectExtension, WorkloadIdentity};

pub use claim_map_config::{
    ClaimMapConfig, ClaimsOverrides, CompiledClaimMap, CompiledClaimsOverrides, CompiledRoleMap,
    MergeMode, OnMissing, SplitMode,
};
pub use claim_path::ClaimPath;
pub use configured_mapper::{ConfiguredClaimMap, MappingProfile};

/// Convert a record's fields into the typed identity slot for the resolver's
/// configured role.
///
/// Implementations supply one method per role they understand:
///
///   * [`map_subject`] — the subject anchor plus subject-shaped fields, for
///     `TokenRole::User`.
///   * [`map_client`]  — `client_id` plus client-shaped fields, for
///     `TokenRole::Client`.
///   * [`map_workload`] — SPIFFE-style identity, for `TokenRole::CallerWorkload`.
///
/// Each defaults to `None` so a mapper stays valid when a role is added —
/// it gets implicit "this mapper doesn't know how to do that role,"
/// which a resolver surfaces as `auth.mapping_failed` when an
/// operator wires a role the mapper can't fill.
///
/// `Debug` is a supertrait so structs holding `Arc<dyn ClaimMapper>`
/// can themselves derive `Debug`.
///
/// [`map_subject`]: ClaimMapper::map_subject
/// [`map_client`]: ClaimMapper::map_client
/// [`map_workload`]: ClaimMapper::map_workload
pub trait ClaimMapper: std::fmt::Debug + Send + Sync {
    /// Map a record into a `SubjectExtension` (for `role: user`).
    fn map_subject(&self, claims: &HashMap<String, Value>) -> Option<SubjectExtension> {
        let _ = claims;
        None
    }

    /// Map a record into a `ClientExtension` (for `role: client`).
    /// Default returns `None` — implementations that handle client
    /// credentials override this.
    fn map_client(&self, claims: &HashMap<String, Value>) -> Option<ClientExtension> {
        let _ = claims;
        None
    }

    /// Map a record into a `WorkloadIdentity` (for `role: workload`).
    /// Default returns `None` — implementations that handle SPIFFE /
    /// SPIFFE-JWT-SVID credentials override this.
    fn map_workload(&self, claims: &HashMap<String, Value>) -> Option<WorkloadIdentity> {
        let _ = claims;
        None
    }
}

/// A record's fields — a JSON object's key/value pairs.
pub type ClaimMap = HashMap<String, Value>;

/// Every SPIFFE ID starts here, and no configuration can turn the check off.
const SPIFFE_SCHEME: &str = "spiffe://";

/// Whether a string is usable as a SPIFFE ID.
///
/// The scheme alone is not enough: the authority carries the trust domain, and
/// the SPIFFE standard makes it mandatory. `spiffe:///ns/default/sa/agent` names
/// no trust boundary, so it is not an identity that can be filed.
pub fn is_spiffe_id(text: &str) -> bool {
    trust_domain_of(text).is_some()
}

/// The trust domain is the SPIFFE URI's authority, which the standard makes the
/// trust boundary. Deriving it from `iss` instead is explicitly discouraged.
///
/// `None` when the authority is absent, which is what makes the string unusable
/// as an identity rather than an identity with no trust domain.
pub fn trust_domain_of(spiffe_id: &str) -> Option<String> {
    spiffe_id
        .strip_prefix(SPIFFE_SCHEME)
        .and_then(|rest| rest.split('/').next())
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned)
}
