// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// SecurityExtension → AttributeBag.
//
// # Empty sets are emitted, not omitted
//
// Every StringSet key below is present whenever its extension slot is
// present — empty rather than absent. Strict-evaluation decision points
// treat a *missing* key as an error, not as an empty collection: the CEL
// PDP raises "no such key" and its default `OnError::Deny` turns that
// into a denial, so a policy like `!("banned" in subject.roles)` would
// deny every subject that happens to have no roles. Emitting the empty
// set makes the membership test simply evaluate false. `cedar-direct`
// reaches the same conclusion independently — see the empty-defaults
// note in `builtins/pdps/cedar-direct/src/entities.rs`.
//
// This matters most for the capability-gated sub-fields. When a plugin
// lacks `read_roles`, core's `build_filtered_subject` hands us an empty
// role set rather than the real one, so "no roles" is a routine state,
// not an edge case.
//
// Bound: this covers an empty set inside a *present* slot. When the slot
// itself is None (a plugin without `read_client` never sees a
// ClientExtension at all), the whole `client.*` namespace is absent and
// CEL reports an undeclared reference instead. Fixing that means
// synthesizing namespaces for absent extensions, which this bridge does
// not do.
//
// Namespace map (canonical — extend this comment when adding a new key):
//
// ----- Subject (user identity) ------------------------------------------
//   sec.subject.id                   → subject.id           : String
//   sec.subject.subject_type         → subject.type         : String
//   sec.subject.roles                → subject.roles        : StringSet (always)
//                                    → role.<r>             : Bool(true)
//   sec.subject.permissions          → subject.permissions  : StringSet (always)
//                                    → perm.<p>             : Bool(true)
//   sec.subject.teams                → subject.teams        : StringSet (always)
//                                    → team.<t>             : Bool(true)
//   sec.subject.claims               → claim.<k>            : flattened JSON
//        Scalars keep their type; scalar arrays (empty included) become a
//        StringSet, numbers and bools as strings. `{}`, `null` and an array
//        holding a nested container set no key, and a structured claim sets
//        only the children beneath it.
//   <derived>                        → authenticated        : Bool (iff subject.id is Some)
//
// ----- Client (OAuth application identity) ------------------------------
//   sec.client.client_id             → client.client_id     : String
//   sec.client.client_name           → client.client_name   : String
//   sec.client.trust_level           → client.trust_level   : String
//   sec.client.authorized_scopes     → client.authorized_scopes : StringSet (always)
//   sec.client.authorized_audiences  → client.authorized_audiences : StringSet (always)
//   sec.client.roles                 → client.roles         : StringSet (always)
//                                    → client.role.<r>      : Bool(true)
//   sec.client.permissions           → client.permissions   : StringSet (always)
//                                    → client.perm.<p>      : Bool(true)
//   sec.client.teams                 → client.teams         : StringSet (always)
//   sec.client.claims                → client.claim.<k>     : flattened JSON
//        Same shape as `claim.<k>` above.
//
// ----- Workload identity (SPIFFE / mTLS attestation) --------------------
//   sec.caller_workload.spiffe_id    → caller_workload.spiffe_id    : String
//   sec.caller_workload.trust_domain → caller_workload.trust_domain : String
//   sec.caller_workload.attestor     → caller_workload.attestor     : String
//   sec.caller_workload.selectors    → caller_workload.selectors    : StringSet (always)
//   sec.caller_workload.client_id    → caller_workload.client_id    : String
//   sec.this_workload.*              → this_workload.*  (same shape, our identity)
//
// Note: `caller_workload.*` / `this_workload.*` are separate from
// `agent.*` (the `AgentExtension` slot — session / conversation context,
// NOT a credential). Reusing `agent.*` would collide.
//
// ----- Other -----------------------------------------------------------
//   sec.auth_method                  → auth_method          : String
//   sec.labels                       → security.labels      : StringSet (always)
//   sec.classification               → security.classification : String

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::{
    ClientExtension, ClientTrustLevel, SecurityExtension, SubjectType, WorkloadIdentity,
};
use std::collections::HashSet;

use crate::constants::{
    BAG_AUTHENTICATED, BAG_CLAIM_PREFIX, BAG_CLIENT_PERMISSIONS, BAG_CLIENT_ROLES, BAG_PERM_PREFIX,
    BAG_ROLE_PREFIX, BAG_SUBJECT_ID, BAG_SUBJECT_PERMISSIONS, BAG_SUBJECT_ROLES, BAG_SUBJECT_TEAMS,
    BAG_SUBJECT_TYPE, BAG_TEAM_PREFIX,
};

/// Flatten a `SecurityExtension` into the bag.
pub fn extract_security(sec: &SecurityExtension, bag: &mut AttributeBag) {
    if let Some(subject) = &sec.subject {
        let mut authenticated = false;
        if let Some(id) = &subject.id {
            bag.set(BAG_SUBJECT_ID, id.clone());
            authenticated = true;
        }
        if let Some(st) = subject.subject_type {
            bag.set(BAG_SUBJECT_TYPE, subject_type_str(st));
        }
        // Full role set as one StringSet, so policies can do membership
        // tests (`"hr" in subject.roles`) without enumerating names. Set
        // unconditionally — see the empty-set note in the module header.
        bag.set(BAG_SUBJECT_ROLES, subject.roles.clone());
        // Plus the flattened role.<name> = true keys. DSL: `require(role.hr)`.
        // No guard needed: iterating an empty set writes nothing.
        for role in &subject.roles {
            bag.set(format!("{BAG_ROLE_PREFIX}{role}"), true);
        }
        bag.set(BAG_SUBJECT_PERMISSIONS, subject.permissions.clone());
        for perm in &subject.permissions {
            bag.set(format!("{BAG_PERM_PREFIX}{perm}"), true);
        }
        bag.set(BAG_SUBJECT_TEAMS, subject.teams.clone());
        // Mirror the role.X / perm.X namespace so policies can
        // gate on team membership with the same DSL shape, e.g.
        // `require(team.engineering | team.security)`.
        for team in &subject.teams {
            bag.set(format!("{BAG_TEAM_PREFIX}{team}"), true);
        }
        for (k, v) in &subject.claims {
            // Nested JSON claims flatten through the same walker
            // `client.claim.*` and `custom.*` use — keeps semantics
            // consistent across bridges, so `claim.realm_access.roles`
            // is a StringSet a policy can test with `contains`.
            crate::payload::walk(v, &format!("{BAG_CLAIM_PREFIX}{k}"), bag);
        }
        // Single top-level authenticated marker — DSL idiom is `require(authenticated)`,
        // unprefixed. Only set when truly authenticated (subject + id present).
        if authenticated {
            bag.set(BAG_AUTHENTICATED, true);
        }
    }

    if let Some(client) = &sec.client {
        extract_client(client, bag);
    }

    if let Some(caller) = &sec.caller_workload {
        extract_workload("caller_workload", caller, bag);
    }

    if let Some(this_w) = &sec.this_workload {
        extract_workload("this_workload", this_w, bag);
    }

    if let Some(m) = &sec.auth_method {
        bag.set("auth_method", m.clone());
    }
    let labels: HashSet<String> = sec.labels.iter().cloned().collect();
    bag.set("security.labels", labels);
    if let Some(c) = &sec.classification {
        bag.set("security.classification", c.clone());
    }
}

/// Flatten a `ClientExtension` into the bag under the `client.*`
/// namespace. Shape is deliberately symmetric with subject — roles and
/// permissions land twice, as the whole set under `client.roles` /
/// `client.permissions` for membership tests
/// (`"partner" in client.roles`), and as presence-only
/// `client.role.<r> = true` / `client.perm.<p> = true` keys so policies
/// can write `require(client.role.partner)` the same way as `role.hr`.
/// Claims are flattened through the same JSON walker as `custom.*`, so
/// nested objects produce dotted-path keys.
pub fn extract_client(client: &ClientExtension, bag: &mut AttributeBag) {
    bag.set("client.client_id", client.client_id.clone());
    if let Some(n) = &client.client_name {
        bag.set("client.client_name", n.clone());
    }
    bag.set("client.trust_level", trust_level_str(&client.trust_level));
    let roles: HashSet<String> = client.roles.iter().cloned().collect();
    bag.set(BAG_CLIENT_ROLES, roles);
    for role in &client.roles {
        bag.set(format!("client.role.{role}"), true);
    }
    let perms: HashSet<String> = client.permissions.iter().cloned().collect();
    bag.set(BAG_CLIENT_PERMISSIONS, perms);
    for perm in &client.permissions {
        bag.set(format!("client.perm.{perm}"), true);
    }
    let scopes: HashSet<String> = client.authorized_scopes.iter().cloned().collect();
    bag.set("client.authorized_scopes", scopes);
    let auds: HashSet<String> = client.authorized_audiences.iter().cloned().collect();
    bag.set("client.authorized_audiences", auds);
    let teams: HashSet<String> = client.teams.iter().cloned().collect();
    bag.set("client.teams", teams);
    for (k, v) in &client.claims {
        crate::payload::walk(v, &format!("client.claim.{k}"), bag);
    }
}

/// Flatten a `WorkloadIdentity` into the bag under the given namespace
/// prefix — typically `"caller_workload"` or `"this_workload"`. Two
/// instances of this struct can coexist in `SecurityExtension`
/// (one inbound, one outbound) and they share the bag shape; the only
/// thing that varies is the namespace.
pub fn extract_workload(prefix: &str, w: &WorkloadIdentity, bag: &mut AttributeBag) {
    if let Some(s) = &w.spiffe_id {
        bag.set(format!("{prefix}.spiffe_id"), s.clone());
    }
    if let Some(t) = &w.trust_domain {
        bag.set(format!("{prefix}.trust_domain"), t.clone());
    }
    if let Some(a) = &w.attestor {
        bag.set(format!("{prefix}.attestor"), a.clone());
    }
    let selectors: HashSet<String> = w.selectors.iter().cloned().collect();
    bag.set(format!("{prefix}.selectors"), selectors);
    if let Some(id) = &w.client_id {
        bag.set(format!("{prefix}.client_id"), id.clone());
    }
    // `attested_at` intentionally omitted from the bag at v0 — APL
    // doesn't carry DateTime as a bag value type, and policies that
    // need it can opt into reading the typed extension directly.
    let _ = &w.attested_at;
}

/// Render the `ClientTrustLevel` enum as the bag string. Matches
/// `serde(rename_all = "snake_case")` on the type, with `Custom(s)`
/// rendering as `s` verbatim so policies can write
/// `client.trust_level == "partner-tier-A"`. The `_` arm exists
/// because `ClientTrustLevel` is `#[non_exhaustive]`; if a new
/// well-known variant lands upstream, this falls through to
/// "unknown" until we explicitly add a case — fail-loud rather than
/// silently picking one of the existing strings.
fn trust_level_str(level: &ClientTrustLevel) -> String {
    match level {
        ClientTrustLevel::FirstParty => "first_party".to_owned(),
        ClientTrustLevel::ThirdParty => "third_party".to_owned(),
        ClientTrustLevel::Internal => "internal".to_owned(),
        ClientTrustLevel::Custom(s) => s.clone(),
        _ => "unknown".to_owned(),
    }
}

fn subject_type_str(t: SubjectType) -> &'static str {
    match t {
        SubjectType::User => "user",
        SubjectType::Agent => "agent",
        SubjectType::Service => "service",
        SubjectType::System => "system",
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::extensions::{SubjectExtension, WorkloadIdentity};
    use std::collections::HashMap;

    fn alice() -> SecurityExtension {
        SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice@corp.com".into()),
                subject_type: Some(SubjectType::User),
                roles: HashSet::from(["hr".to_owned(), "manager".to_owned()]),
                permissions: HashSet::from(["view_ssn".to_owned()]),
                teams: HashSet::from(["compliance".to_owned()]),
                claims: HashMap::from([("iss".to_owned(), serde_json::json!("auth.corp"))]),
            }),
            this_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/hr-tool".into()),
                trust_domain: Some("corp.com".into()),
                attestor: Some("spire-agent".into()),
                selectors: vec!["k8s:ns:hr".into()],
                client_id: Some("hr-tool".into()),
                ..Default::default()
            }),
            auth_method: Some("jwt".into()),
            ..Default::default()
        }
    }

    #[test]
    fn subject_id_and_authenticated_marker() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("subject.id"), Some("alice@corp.com"));
        assert_eq!(bag.get_bool("authenticated"), Some(true));
        assert_eq!(bag.get_string("subject.type"), Some("user"));
    }

    #[test]
    fn roles_become_individual_true_keys() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        // Each role → role.<name> = true. DSL: `require(role.hr)`.
        assert_eq!(bag.get_bool("role.hr"), Some(true));
        assert_eq!(bag.get_bool("role.manager"), Some(true));
        // A role Alice doesn't have is absent (not false — missing).
        assert_eq!(bag.get_bool("role.finance"), None);
        // Roles are ALSO mirrored as one set under subject.roles, so
        // membership tests work without enumerating names.
        assert!(bag.set_contains("subject.roles", "hr"));
        assert!(bag.set_contains("subject.roles", "manager"));
        assert!(!bag.set_contains("subject.roles", "finance"));
    }

    #[test]
    fn permissions_become_individual_true_keys() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_bool("perm.view_ssn"), Some(true));
        assert_eq!(bag.get_bool("perm.delete_user"), None);
        // Mirrored as a set under subject.permissions too.
        assert!(bag.set_contains("subject.permissions", "view_ssn"));
        assert!(!bag.set_contains("subject.permissions", "delete_user"));
    }

    #[test]
    fn teams_become_string_set() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert!(bag.set_contains("subject.teams", "compliance"));
        assert!(!bag.set_contains("subject.teams", "engineering"));
    }

    #[test]
    fn claims_become_dotted_strings() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("claim.iss"), Some("auth.corp"));
    }

    #[test]
    fn this_workload_identity_keys() {
        // `this_workload.*` namespace — our own attested identity.
        // Distinct from the `agent.*` namespace of `AgentExtension`
        // (session context) and the future `caller_workload.*`
        // namespace for the inbound caller's SPIFFE identity.
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("this_workload.client_id"), Some("hr-tool"));
        assert_eq!(
            bag.get_string("this_workload.spiffe_id"),
            Some("spiffe://corp.com/hr-tool")
        );
        assert_eq!(
            bag.get_string("this_workload.trust_domain"),
            Some("corp.com")
        );
        assert_eq!(
            bag.get_string("this_workload.attestor"),
            Some("spire-agent")
        );
        assert!(bag.set_contains("this_workload.selectors", "k8s:ns:hr"));
    }

    #[test]
    fn auth_method_is_top_level() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("auth_method"), Some("jwt"));
    }

    #[test]
    fn labels_and_classification() {
        let mut sec = SecurityExtension::default();
        sec.add_label("PII");
        sec.add_label("financial");
        sec.classification = Some("confidential".into());

        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert!(bag.set_contains("security.labels", "PII"));
        assert!(bag.set_contains("security.labels", "financial"));
        assert_eq!(
            bag.get_string("security.classification"),
            Some("confidential")
        );
    }

    #[test]
    fn no_subject_means_no_authenticated_marker() {
        let sec = SecurityExtension::default(); // subject: None
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert!(!bag.contains("authenticated"));
        assert!(!bag.contains("subject.id"));
    }

    #[test]
    fn subject_without_id_is_not_authenticated() {
        // A subject record exists but has no id — represents a recognized
        // but unauthenticated principal (e.g. anonymous). The marker must
        // not be set.
        let sec = SecurityExtension {
            subject: Some(SubjectExtension {
                id: None,
                roles: HashSet::from(["guest".to_owned()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert!(!bag.contains("authenticated"));
        // But role keys still land — role.guest is true.
        assert_eq!(bag.get_bool("role.guest"), Some(true));
    }

    #[test]
    fn empty_subject_sets_are_present_not_absent() {
        // The regression this guards: a subject with no roles used to leave
        // `subject.roles` out of the bag entirely, and a strict-evaluation
        // PDP (CEL) turns a missing key into an eval error that its
        // fail-closed default converts to Deny — so `"x" in subject.roles`
        // denied every unroled subject instead of evaluating false.
        //
        // Assert presence-with-emptiness, not just `!set_contains(...)`:
        // that weaker check passes under the buggy behavior too.
        let sec = SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("nobody@corp.com".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);

        let empty = HashSet::new();
        assert_eq!(bag.get_string_set("subject.roles"), Some(&empty));
        assert_eq!(bag.get_string_set("subject.permissions"), Some(&empty));
        assert_eq!(bag.get_string_set("subject.teams"), Some(&empty));
        // No flattened keys, though — those stay presence-only.
        assert_eq!(bag.get_bool("role.hr"), None);
    }

    #[test]
    fn empty_labels_and_selectors_are_present_not_absent() {
        let sec = SecurityExtension {
            this_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/svc".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);

        let empty = HashSet::new();
        assert_eq!(bag.get_string_set("security.labels"), Some(&empty));
        assert_eq!(bag.get_string_set("this_workload.selectors"), Some(&empty));
    }

    #[test]
    fn empty_client_sets_are_present_not_absent() {
        let client = ClientExtension {
            client_id: "bare-app".into(),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_client(&client, &mut bag);

        let empty = HashSet::new();
        assert_eq!(bag.get_string_set("client.authorized_scopes"), Some(&empty));
        assert_eq!(
            bag.get_string_set("client.authorized_audiences"),
            Some(&empty)
        );
        assert_eq!(bag.get_string_set("client.teams"), Some(&empty));
    }

    fn agent_client() -> ClientExtension {
        ClientExtension {
            client_id: "agent-app".into(),
            client_name: Some("Agent App".into()),
            trust_level: ClientTrustLevel::FirstParty,
            authorized_scopes: vec!["read".into(), "write".into()],
            authorized_audiences: vec!["https://api.example.com".into()],
            roles: vec!["partner".into()],
            permissions: vec!["call_tool".into()],
            teams: vec!["acme".into()],
            claims: HashMap::from([
                ("iss".to_owned(), serde_json::json!("auth.example.com")),
                (
                    "scope_meta".to_owned(),
                    serde_json::json!({ "max_calls_per_min": 60 }),
                ),
            ]),
        }
    }

    #[test]
    fn client_required_id_and_trust_level() {
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert_eq!(bag.get_string("client.client_id"), Some("agent-app"));
        assert_eq!(bag.get_string("client.client_name"), Some("Agent App"));
        assert_eq!(bag.get_string("client.trust_level"), Some("first_party"));
    }

    #[test]
    fn client_roles_and_perms_become_individual_true_keys() {
        // Symmetric with the subject pattern: `client.role.partner = true`.
        // Lets policies write `require(client.role.partner)`.
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert_eq!(bag.get_bool("client.role.partner"), Some(true));
        assert_eq!(bag.get_bool("client.perm.call_tool"), Some(true));
        assert_eq!(bag.get_bool("client.role.nonexistent"), None);
    }

    #[test]
    fn client_roles_and_perms_also_land_as_sets() {
        // The membership idiom generalizes across principals: an author who
        // learns `"hr" in subject.roles` can write `"partner" in
        // client.roles` and have it resolve rather than error.
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert!(bag.set_contains("client.roles", "partner"));
        assert!(!bag.set_contains("client.roles", "nonexistent"));
        assert!(bag.set_contains("client.permissions", "call_tool"));
    }

    #[test]
    fn empty_client_roles_and_perms_are_present_not_absent() {
        let client = ClientExtension {
            client_id: "bare-app".into(),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_client(&client, &mut bag);

        let empty = HashSet::new();
        assert_eq!(bag.get_string_set("client.roles"), Some(&empty));
        assert_eq!(bag.get_string_set("client.permissions"), Some(&empty));
    }

    #[test]
    fn client_scopes_audiences_teams_are_string_sets() {
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert!(bag.set_contains("client.authorized_scopes", "read"));
        assert!(bag.set_contains("client.authorized_scopes", "write"));
        assert!(bag.set_contains("client.authorized_audiences", "https://api.example.com",));
        assert!(bag.set_contains("client.teams", "acme"));
    }

    #[test]
    fn client_claims_flatten_nested_paths() {
        // Claims are `HashMap<String, Value>` — nested objects must
        // flatten through the same walker `custom.*` uses. Asserts the
        // JSON-walker integration works for client just like custom.
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert_eq!(bag.get_string("client.claim.iss"), Some("auth.example.com"));
        assert_eq!(
            bag.get_int("client.claim.scope_meta.max_calls_per_min"),
            Some(60),
        );
    }

    #[test]
    fn subject_claims_flatten_nested_paths() {
        // The reason this bridge exists: an IdP that nests roles under
        // `realm_access.roles` (Keycloak) must reach policy with the
        // structure intact, so `claim.realm_access.roles contains 'admin'`
        // resolves. Before subject claims carried `Value`, this arrived as
        // one opaque JSON string and no predicate could see inside it.
        let subject = SubjectExtension {
            id: Some("alice".to_owned()),
            claims: HashMap::from([(
                "realm_access".to_owned(),
                serde_json::json!({ "roles": ["admin", "auditor"] }),
            )]),
            ..Default::default()
        };
        let sec = SecurityExtension {
            subject: Some(subject),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert!(
            bag.set_contains("claim.realm_access.roles", "admin"),
            "a nested string array must arrive as a StringSet, not a JSON string"
        );
        assert!(bag.set_contains("claim.realm_access.roles", "auditor"));
        assert!(
            bag.get("claim.realm_access").is_none(),
            "the parent key holds no scalar of its own — only the flattened children"
        );
    }

    #[test]
    fn subject_claims_keep_scalars_as_scalars() {
        // The compatibility half of the same change: a plain string claim
        // still lands as a String at the same key, so an existing policy
        // written as `claim.tenant == 'acme'` is unaffected.
        let subject = SubjectExtension {
            id: Some("alice".to_owned()),
            claims: HashMap::from([
                ("tenant".to_owned(), serde_json::json!("acme")),
                ("level".to_owned(), serde_json::json!(3)),
            ]),
            ..Default::default()
        };
        let sec = SecurityExtension {
            subject: Some(subject),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert_eq!(bag.get_string("claim.tenant"), Some("acme"));
        assert_eq!(
            bag.get_int("claim.level"),
            Some(3),
            "a numeric claim keeps its type"
        );
    }

    #[test]
    fn trust_level_custom_renders_verbatim() {
        let mut client = agent_client();
        client.trust_level = ClientTrustLevel::Custom("partner-tier-A".into());
        let mut bag = AttributeBag::new();
        extract_client(&client, &mut bag);
        assert_eq!(bag.get_string("client.trust_level"), Some("partner-tier-A"));
    }

    fn workload_fixture() -> WorkloadIdentity {
        WorkloadIdentity {
            spiffe_id: Some("spiffe://corp.com/svc/foo".into()),
            trust_domain: Some("corp.com".into()),
            attestor: Some("spire-agent".into()),
            selectors: vec!["k8s:ns:foo".into(), "k8s:sa:foo-sa".into()],
            client_id: Some("foo-svc".into()),
            ..Default::default()
        }
    }

    #[test]
    fn extract_workload_populates_under_caller_prefix() {
        // The same WorkloadIdentity feeds two distinct bag namespaces
        // depending on which slot it lives in. This test pins
        // `caller_workload.*`; the next pins `this_workload.*`.
        let mut bag = AttributeBag::new();
        extract_workload("caller_workload", &workload_fixture(), &mut bag);
        assert_eq!(
            bag.get_string("caller_workload.spiffe_id"),
            Some("spiffe://corp.com/svc/foo"),
        );
        assert_eq!(
            bag.get_string("caller_workload.trust_domain"),
            Some("corp.com"),
        );
        assert!(bag.set_contains("caller_workload.selectors", "k8s:ns:foo"));
        // And the `this_workload.*` namespace must stay empty in this
        // case — caller-prefix call must not leak into the other slot.
        assert_eq!(bag.get_string("this_workload.spiffe_id"), None);
    }

    #[test]
    fn extract_workload_populates_under_this_prefix() {
        let mut bag = AttributeBag::new();
        extract_workload("this_workload", &workload_fixture(), &mut bag);
        assert_eq!(
            bag.get_string("this_workload.spiffe_id"),
            Some("spiffe://corp.com/svc/foo"),
        );
        assert_eq!(
            bag.get_string("this_workload.attestor"),
            Some("spire-agent")
        );
        assert_eq!(bag.get_string("caller_workload.spiffe_id"), None);
    }

    #[test]
    fn extract_security_populates_all_four_identity_namespaces() {
        // Single fixture exercising subject + client + caller_workload +
        // this_workload. Documents that one SecurityExtension can carry
        // all four principals on a single request and the bridge fans
        // them out into disjoint namespaces.
        let sec = SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice".into()),
                ..Default::default()
            }),
            client: Some(agent_client()),
            caller_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/inbound".into()),
                ..Default::default()
            }),
            this_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/gateway".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert_eq!(bag.get_string("subject.id"), Some("alice"));
        assert_eq!(bag.get_string("client.client_id"), Some("agent-app"));
        assert_eq!(
            bag.get_string("caller_workload.spiffe_id"),
            Some("spiffe://corp.com/inbound"),
        );
        assert_eq!(
            bag.get_string("this_workload.spiffe_id"),
            Some("spiffe://corp.com/gateway"),
        );
    }
}
