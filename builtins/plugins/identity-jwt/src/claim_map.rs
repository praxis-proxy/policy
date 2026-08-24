// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `ClaimMapper` — converts validated JWT claims into a populated
// `SubjectExtension`.
//
// Different IdPs use different claim shapes:
//
//   * Keycloak — `realm_access.roles` (nested array), `email`,
//                 `preferred_username`, custom `groups` array
//   * Auth0    — flat `permissions` array, `https://my-app/roles`
//                 (namespaced custom claims), `email`
//   * Cognito  — `cognito:groups`, `cognito:username`,
//                 `cognito:roles`
//   * Standard OIDC — `sub`, `email`, `name`, `groups`, …
//
// `StandardClaimMap` covers the OIDC-standard shape; deployments
// with bespoke IdPs implement `ClaimMapper` themselves and inject
// at resolver construction.

use std::collections::HashMap;

use serde_json::Value;

use praxis_policy_core::extensions::{ClientExtension, SubjectExtension, WorkloadIdentity};

/// Convert a validated JWT's claim map into the typed identity slot
/// for the resolver's configured role.
///
/// Implementations supply one method per role they understand:
///
///   * [`map_subject`] — `sub` plus subject-shaped fields, for
///     `TokenRole::User`.
///   * [`map_client`]  — `client_id` plus client-shaped fields, for
///     `TokenRole::Client`.
///   * [`map_workload`] — SPIFFE-style identity, for `TokenRole::CallerWorkload`.
///
/// Each defaults to `None` so existing custom mappers stay valid —
/// they get implicit "this mapper doesn't know how to do that role,"
/// which the resolver surfaces as `auth.mapping_failed` when an
/// operator wires a role the mapper can't fill.
///
/// `Debug` is a supertrait so structs holding `Arc<dyn ClaimMapper>`
/// (notably `JwtIdentityResolver`) can themselves derive `Debug`.
///
/// [`map_subject`]: ClaimMapper::map_subject
/// [`map_client`]: ClaimMapper::map_client
/// [`map_workload`]: ClaimMapper::map_workload
pub trait ClaimMapper: std::fmt::Debug + Send + Sync {
    /// Map JWT claims into a `SubjectExtension` (for `role: user`).
    fn map_subject(&self, claims: &HashMap<String, Value>) -> Option<SubjectExtension> {
        let _ = claims;
        None
    }

    /// Map JWT claims into a `ClientExtension` (for `role: client`).
    /// Default returns `None` — implementations that handle client
    /// tokens override this.
    fn map_client(&self, claims: &HashMap<String, Value>) -> Option<ClientExtension> {
        let _ = claims;
        None
    }

    /// Map JWT claims into a `WorkloadIdentity` (for `role: workload`).
    /// Default returns `None` — implementations that handle SPIFFE /
    /// SPIFFE-JWT-SVID tokens override this.
    fn map_workload(&self, claims: &HashMap<String, Value>) -> Option<WorkloadIdentity> {
        let _ = claims;
        None
    }
}

/// Type alias matching what `jsonwebtoken::decode::<ClaimMap>(...)`
/// produces — a JSON object's key/value pairs.
pub type ClaimMap = HashMap<String, Value>;

/// Default `ClaimMapper` covering the OIDC-standard claim shape:
///
///   * `sub`                    → `subject.id` (required)
///   * `roles`                  → `subject.roles`     (string array)
///   * `permissions` / `scope`  → `subject.permissions` (array, or a
///     space-separated string)
///   * `groups` / `teams`       → `subject.teams`     (string array)
///   * Every other claim        → `subject.claims.<name>` (full `Value`)
///
/// Implementations with non-standard `IdPs` (Keycloak's nested
/// `realm_access.roles`, AWS Cognito's `cognito:*` prefixed claims)
/// write their own `ClaimMapper`; this struct is for the common
/// vanilla-OIDC case.
#[derive(Debug, Clone, Default)]
pub struct StandardClaimMap;

impl ClaimMapper for StandardClaimMap {
    fn map_client(&self, claims: &ClaimMap) -> Option<ClientExtension> {
        // `client_id` is required for ClientExtension — it's the anchor
        // identifier policy authors gate on. Falls back to `azp`
        // (authorized party, OIDC §2 for the "client_id of the party
        // to which the token was issued") which Keycloak and several
        // OPs send in place of `client_id`.
        let client_id = claims
            .get("client_id")
            .or_else(|| claims.get("azp"))
            .and_then(Value::as_str)?
            .to_owned();

        let mut client = ClientExtension {
            client_id,
            ..Default::default()
        };

        if let Some(name) = claims.get("client_name").and_then(Value::as_str) {
            client.client_name = Some(name.to_owned());
        }

        // Scopes — array OR space-separated string.
        if let Some(arr) = claims.get("authorized_scopes").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    client.authorized_scopes.push(s.to_owned());
                }
            }
        } else if let Some(s) = claims.get("scope").and_then(Value::as_str) {
            for scope in s.split_whitespace() {
                if !scope.is_empty() {
                    client.authorized_scopes.push(scope.to_owned());
                }
            }
        }

        // Audiences — single string or array (RFC 7519 §4.1.3).
        match claims.get("aud") {
            Some(Value::String(s)) => client.authorized_audiences.push(s.clone()),
            Some(Value::Array(arr)) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        client.authorized_audiences.push(s.to_owned());
                    }
                }
            },
            _ => {},
        }

        // Platform-native roles.
        if let Some(arr) = claims.get("roles").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    client.roles.push(s.to_owned());
                }
            }
        }

        // Remaining claims — keyed by name with full Value preserved,
        // same as `SubjectExtension.claims`.
        const RESERVED: &[&str] = &[
            "client_id",
            "azp",
            "client_name",
            "authorized_scopes",
            "scope",
            "aud",
            "roles",
            "iss",
            "exp",
            "nbf",
            "iat",
            "jti",
            "sub",
        ];
        for (k, v) in claims {
            if RESERVED.contains(&k.as_str()) {
                continue;
            }
            client.claims.insert(k.clone(), v.clone());
        }

        Some(client)
    }

    fn map_workload(&self, claims: &ClaimMap) -> Option<WorkloadIdentity> {
        // SPIFFE JWT-SVID convention: the SPIFFE ID lives in `sub`
        // (per the SPIFFE JWT-SVID spec). We look there first, then
        // fall back to an explicit `spiffe_id` claim for IdPs that
        // surface it separately.
        let spiffe_id = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| is_spiffe_id(s))
            .or_else(|| claims.get("spiffe_id").and_then(Value::as_str))
            // Guard the `spiffe_id` fallback with the SAME check as `sub`: a
            // non-SPIFFE `sub` must not smuggle in an arbitrary `spiffe_id`
            // claim and be accepted as a workload identity.
            .filter(|s| is_spiffe_id(s))
            .map(str::to_owned)?;

        // The URI authority, which `is_spiffe_id` already required, so this
        // cannot be `None`.
        let trust_domain = trust_domain_of(&spiffe_id);

        Some(WorkloadIdentity {
            spiffe_id: Some(spiffe_id),
            trust_domain,
            attested_at: None,
            attestor: Some("jwt".to_owned()),
            ..Default::default()
        })
    }

    fn map_subject(&self, claims: &ClaimMap) -> Option<SubjectExtension> {
        // `sub` is required — RFC 7519 §4.1.2 makes it optional in
        // the spec but it's effectively mandatory for identity flows.
        let sub = claims.get("sub").and_then(Value::as_str)?.to_owned();

        let mut subject = SubjectExtension {
            id: Some(sub),
            ..Default::default()
        };

        // `roles` — array of strings.
        if let Some(arr) = claims.get("roles").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.roles.insert(s.to_owned());
                }
            }
        }

        // `permissions` (array) OR `scope` (space-separated string,
        // OAuth-style). Either populates `subject.permissions`.
        if let Some(arr) = claims.get("permissions").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.permissions.insert(s.to_owned());
                }
            }
        } else if let Some(s) = claims.get("scope").and_then(Value::as_str) {
            for scope in s.split_whitespace() {
                if !scope.is_empty() {
                    subject.permissions.insert(scope.to_owned());
                }
            }
        }

        // `teams` (explicit) preferred; fall back to `groups` (OIDC
        // conventional name for the same concept).
        if let Some(arr) = claims.get("teams").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.teams.insert(s.to_owned());
                }
            }
        } else if let Some(arr) = claims.get("groups").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.teams.insert(s.to_owned());
                }
            }
        }

        // Every other claim → `subject.claims.<name>`, with the full
        // `Value` preserved so a nested claim survives to the policy
        // bag (`payload::walk` flattens it there). The reserved-claim
        // set is the ones we already mapped to structured fields, plus
        // the JWT standard registered claims (iss/aud/exp/nbf/iat/jti)
        // which aren't useful as policy-visible claims.
        const RESERVED: &[&str] = &[
            "sub",
            "roles",
            "permissions",
            "scope",
            "teams",
            "groups",
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
        ];
        for (k, v) in claims {
            if RESERVED.contains(&k.as_str()) {
                continue;
            }
            subject.claims.insert(k.clone(), v.clone());
        }

        Some(subject)
    }
}

/// Every SPIFFE ID starts here, and no configuration can turn the check off.
const SPIFFE_SCHEME: &str = "spiffe://";

/// Whether a string is usable as a SPIFFE ID.
///
/// The scheme alone is not enough: the authority carries the trust domain, and
/// the SPIFFE standard makes it mandatory. `spiffe:///ns/default/sa/agent` names
/// no trust boundary, so it is not an identity this plugin can file.
pub(crate) fn is_spiffe_id(text: &str) -> bool {
    trust_domain_of(text).is_some()
}

/// The trust domain is the SPIFFE URI's authority, which the standard makes the
/// trust boundary. Deriving it from `iss` instead is explicitly discouraged.
///
/// `None` when the authority is absent, which is what makes the string unusable
/// as an identity rather than an identity with no trust domain.
pub(crate) fn trust_domain_of(spiffe_id: &str) -> Option<String> {
    spiffe_id
        .strip_prefix(SPIFFE_SCHEME)
        .and_then(|rest| rest.split('/').next())
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unreadable_literal, reason = "tests")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_claims(json: Value) -> ClaimMap {
        json.as_object().unwrap().clone().into_iter().collect()
    }

    #[test]
    fn sub_becomes_subject_id() {
        let claims = make_claims(json!({"sub": "alice@corp.com"}));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
    }

    #[test]
    fn missing_sub_returns_none() {
        // No `sub` claim → mapper rejects. Caller will surface
        // this as `auth.mapping_failed`.
        let claims = make_claims(json!({"email": "alice@corp.com"}));
        assert!(StandardClaimMap.map_subject(&claims).is_none());
    }

    #[test]
    fn roles_array_becomes_subject_roles() {
        let claims = make_claims(json!({
            "sub": "alice",
            "roles": ["hr", "admin"],
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.roles.contains("hr"));
        assert!(subject.roles.contains("admin"));
    }

    #[test]
    fn scope_string_splits_into_permissions() {
        // OAuth-style space-separated scope claim — `scope: "read write"`.
        let claims = make_claims(json!({
            "sub": "alice",
            "scope": "read write delete",
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.permissions.contains("read"));
        assert!(subject.permissions.contains("write"));
        assert!(subject.permissions.contains("delete"));
    }

    #[test]
    fn permissions_array_preferred_over_scope() {
        // If both are present, `permissions` (array) wins. Most
        // modern IdPs send arrays; OAuth-1-era `scope` is a fallback.
        let claims = make_claims(json!({
            "sub": "alice",
            "permissions": ["call_tool", "list_tools"],
            "scope": "read write",
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.permissions.contains("call_tool"));
        // `scope` ignored when `permissions` is present.
        assert!(!subject.permissions.contains("read"));
    }

    #[test]
    fn groups_fallback_when_teams_absent() {
        let claims = make_claims(json!({
            "sub": "alice",
            "groups": ["engineering", "platform"],
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.teams.contains("engineering"));
        assert!(subject.teams.contains("platform"));
    }

    #[test]
    fn teams_preferred_over_groups() {
        let claims = make_claims(json!({
            "sub": "alice",
            "teams": ["explicit-team"],
            "groups": ["fallback-group"],
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.teams.contains("explicit-team"));
        assert!(!subject.teams.contains("fallback-group"));
    }

    #[test]
    fn unmapped_claims_land_in_subject_claims_map() {
        let claims = make_claims(json!({
            "sub": "alice",
            "email": "alice@corp.com",
            "preferred_username": "alice",
            "iat": 1700000000,  // reserved, should be skipped
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert_eq!(subject.claims.get("email"), Some(&json!("alice@corp.com")));
        assert_eq!(
            subject.claims.get("preferred_username"),
            Some(&json!("alice")),
        );
        // Reserved JWT claims aren't propagated as policy-visible
        // subject claims.
        assert!(!subject.claims.contains_key("iat"));
        assert!(!subject.claims.contains_key("sub"));
    }

    #[test]
    fn structured_subject_claims_keep_their_shape() {
        // A nested or list claim must reach `subject.claims` as the JSON it
        // was, not as a string of that JSON. `praxis-policy-apl-cmf` flattens
        // it into the policy bag from there, which is what makes
        // `claim.realm_access.roles contains 'admin'` resolve for a Keycloak
        // token.
        let claims = make_claims(json!({
            "sub": "alice",
            "realm_access": { "roles": ["admin"] },
            "projects": ["rhoai-prod", "rhoai-stage"],
            "quota": 42,
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert_eq!(
            subject.claims.get("realm_access"),
            Some(&json!({ "roles": ["admin"] })),
            "a nested object must not be flattened to a string here"
        );
        assert_eq!(
            subject.claims.get("projects"),
            Some(&json!(["rhoai-prod", "rhoai-stage"])),
        );
        assert_eq!(subject.claims.get("quota"), Some(&json!(42)));
    }

    #[test]
    fn a_string_claim_is_not_confused_with_a_one_element_array() {
        // The ambiguity stringification used to create: a claim whose value
        // is literally the text `["a"]` and a claim whose value is the array
        // `["a"]` both serialized to the same five characters, so nothing
        // downstream could tell them apart. Preserving `Value` keeps them
        // distinct.
        let as_string = StandardClaimMap
            .map_subject(&make_claims(json!({ "sub": "alice", "x": "[\"a\"]" })))
            .unwrap();
        let as_array = StandardClaimMap
            .map_subject(&make_claims(json!({ "sub": "alice", "x": ["a"] })))
            .unwrap();
        assert_eq!(as_string.claims.get("x"), Some(&json!("[\"a\"]")));
        assert_eq!(as_array.claims.get("x"), Some(&json!(["a"])));
        assert_ne!(as_string.claims.get("x"), as_array.claims.get("x"));
    }

    // ---- map_client -------------------------------------------------------
    //
    // `map_client` fills the identity slot for a resolver configured
    // `role: client`, which is machine-to-machine traffic rather than a user.
    // Every test above covers `map_subject`, so none of this had been
    // exercised.

    #[test]
    fn client_id_becomes_the_client_anchor() {
        let claims = make_claims(json!({"client_id": "svc-billing"}));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.client_id, "svc-billing");
    }

    /// Keycloak and several other providers send `azp` (authorized party)
    /// rather than `client_id`, so the fallback is what makes those tokens
    /// usable at all.
    #[test]
    fn azp_is_accepted_when_client_id_is_absent() {
        let claims = make_claims(json!({"azp": "svc-billing"}));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.client_id, "svc-billing");
    }

    #[test]
    fn client_id_wins_over_azp_when_both_are_present() {
        let claims = make_claims(json!({"client_id": "explicit", "azp": "fallback"}));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.client_id, "explicit");
    }

    /// With neither claim there is no anchor to gate on, so the mapper must
    /// decline rather than invent one. The resolver turns this into
    /// `auth.mapping_failed`.
    #[test]
    fn no_client_id_and_no_azp_yields_none() {
        let claims = make_claims(json!({"client_name": "Billing"}));
        assert!(StandardClaimMap.map_client(&claims).is_none());
    }

    #[test]
    fn client_name_is_carried_when_present() {
        let claims = make_claims(json!({"client_id": "svc", "client_name": "Billing Service"}));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.client_name.as_deref(), Some("Billing Service"));
    }

    #[test]
    fn authorized_scopes_array_becomes_client_scopes() {
        let claims = make_claims(json!({
            "client_id": "svc",
            "authorized_scopes": ["read", "write"],
        }));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.authorized_scopes, vec!["read", "write"]);
    }

    /// The OAuth `scope` claim is a single space-separated string, so it has to
    /// be split rather than taken whole.
    #[test]
    fn scope_string_splits_into_client_scopes() {
        let claims = make_claims(json!({"client_id": "svc", "scope": "read write admin"}));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.authorized_scopes, vec!["read", "write", "admin"]);
    }

    /// `authorized_scopes` is checked first, so a token carrying both must not
    /// end up with the union.
    #[test]
    fn authorized_scopes_preferred_over_scope() {
        let claims = make_claims(json!({
            "client_id": "svc",
            "authorized_scopes": ["read"],
            "scope": "write admin",
        }));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.authorized_scopes, vec!["read"]);
    }

    /// RFC 7519 allows `aud` as either a single string or an array, and a
    /// mapper that handled only one shape would silently drop the audience.
    #[test]
    fn aud_is_accepted_as_a_string_or_an_array() {
        let one = make_claims(json!({"client_id": "svc", "aud": "gateway"}));
        assert_eq!(
            StandardClaimMap
                .map_client(&one)
                .unwrap()
                .authorized_audiences,
            vec!["gateway"]
        );

        let many = make_claims(json!({"client_id": "svc", "aud": ["gateway", "api"]}));
        assert_eq!(
            StandardClaimMap
                .map_client(&many)
                .unwrap()
                .authorized_audiences,
            vec!["gateway", "api"]
        );
    }

    #[test]
    fn a_non_string_non_array_aud_is_ignored_rather_than_rejected() {
        let claims = make_claims(json!({"client_id": "svc", "aud": 42}));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert!(
            client.authorized_audiences.is_empty(),
            "an unusable aud shape must not produce a bogus audience"
        );
    }

    #[test]
    fn roles_array_becomes_client_roles() {
        let claims = make_claims(json!({"client_id": "svc", "roles": ["service", "admin"]}));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.roles, vec!["service", "admin"]);
    }

    /// Unlike the subject mapper, the client mapper preserves the full JSON
    /// value rather than stringifying, and it must not leak the claims it has
    /// already consumed or the standard JWT registered claims.
    #[test]
    fn unconsumed_claims_land_in_client_claims_with_values_intact() {
        let claims = make_claims(json!({
            "client_id": "svc",
            "azp": "svc",
            "client_name": "Billing",
            "scope": "read",
            "aud": "gateway",
            "roles": ["service"],
            "iss": "https://issuer.example",
            "exp": 9_999_999_999_i64,
            "nbf": 0,
            "iat": 0,
            "jti": "abc",
            "sub": "svc",
            "tenant": "acme",
            "tier": 3,
            "beta": true,
        }));
        let client = StandardClaimMap.map_client(&claims).unwrap();
        assert_eq!(client.claims.get("tenant"), Some(&json!("acme")));
        assert_eq!(
            client.claims.get("tier"),
            Some(&json!(3)),
            "the value keeps its JSON type rather than being stringified"
        );
        assert_eq!(client.claims.get("beta"), Some(&json!(true)));
        for reserved in [
            "client_id",
            "azp",
            "client_name",
            "authorized_scopes",
            "scope",
            "aud",
            "roles",
            "iss",
            "exp",
            "nbf",
            "iat",
            "jti",
            "sub",
        ] {
            assert!(
                !client.claims.contains_key(reserved),
                "{reserved} was consumed and must not reappear as a policy claim"
            );
        }
    }

    // ---- workload identity ------------------------------------------------

    /// The scheme alone is not a SPIFFE ID. The authority carries the trust
    /// domain, which the standard makes mandatory, so an authority-less string
    /// declines rather than filing an identity whose trust boundary is `""`.
    #[test]
    fn a_spiffe_id_with_no_authority_declines() {
        for id in ["spiffe:///ns/default/sa/agent", "spiffe://", "spiffe:///"] {
            let claims = make_claims(json!({"sub": id}));
            assert!(
                StandardClaimMap.map_workload(&claims).is_none(),
                "`{id}` names no trust domain, so it is not an identity"
            );
        }
    }

    /// Checked per candidate, like the prefix itself: an authority-less `sub`
    /// does not poison the `spiffe_id` fallback behind it.
    #[test]
    fn an_authority_less_sub_still_falls_back_to_the_spiffe_id_claim() {
        let claims = make_claims(json!({
            "sub": "spiffe:///ns/default/sa/agent",
            "spiffe_id": "spiffe://corp.example/ns/default/sa/agent",
        }));
        let workload = StandardClaimMap.map_workload(&claims).unwrap();
        assert_eq!(workload.trust_domain.as_deref(), Some("corp.example"));
    }

    /// The authority is the whole identifier when there is no path, and every
    /// accepted identity has one.
    #[test]
    fn the_trust_domain_is_the_uri_authority() {
        for (id, domain) in [
            ("spiffe://example.org", Some("example.org")),
            ("spiffe://example.org/ns/a/sa/b", Some("example.org")),
            ("spiffe://", None),
            ("https://example.org/ns/a", None),
        ] {
            assert_eq!(trust_domain_of(id).as_deref(), domain, "{id}");
            assert_eq!(is_spiffe_id(id), domain.is_some(), "{id}");
        }
    }

    // ---- trait defaults ---------------------------------------------------

    /// A custom mapper that implements none of the three methods is valid: the
    /// defaults exist so an operator wiring a role the mapper cannot fill gets
    /// `auth.mapping_failed` rather than a compile error. Nothing in the
    /// workspace exercises them, because the resolver only ever builds
    /// `StandardClaimMap`.
    #[test]
    fn a_mapper_that_overrides_nothing_declines_every_role() {
        #[derive(Debug)]
        struct Nothing;
        impl ClaimMapper for Nothing {}

        let claims = make_claims(json!({"sub": "alice", "client_id": "svc"}));
        assert!(Nothing.map_subject(&claims).is_none());
        assert!(Nothing.map_client(&claims).is_none());
        assert!(Nothing.map_workload(&claims).is_none());
    }
}
