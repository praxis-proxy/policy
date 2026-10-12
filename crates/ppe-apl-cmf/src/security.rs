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
// note in `crates/builtins/src/pdps/cedar_direct/entities.rs`.
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
//                                    → role.<r>             : Bool(true) for atomic names
//   sec.subject.permissions          → subject.permissions  : StringSet (always)
//                                    → perm.<p>             : Bool(true) for atomic names
//   sec.subject.teams                → subject.teams        : StringSet (always)
//                                    → team.<t>             : Bool(true) for atomic names
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
//                                    → client.role.<r>      : Bool(true) for atomic names
//   sec.client.permissions           → client.permissions   : StringSet (always)
//                                    → client.perm.<p>      : Bool(true) for atomic names
//   sec.client.teams                 → client.teams         : StringSet (always)
//   sec.client.claims                → client.claim.<k>     : flattened JSON
//        Same shape as `claim.<k>` above.
//
// ----- Workload identity (SPIFFE / mTLS attestation) --------------------
//   sec.caller_workload.spiffe_id    → caller_workload.spiffe_id    : String
//   sec.caller_workload.trust_domain → caller_workload.trust_domain : String
//   sec.caller_workload.attestor     → caller_workload.attestor     : String
//   sec.caller_workload.attested_at  → caller_workload.attested_at  : String (RFC3339, seconds, Z)
//                                    → caller_workload.attested_at_epoch : Int (Unix seconds)
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
//   sec.objects, sec.data            → not in the bag. Both stay on the
//                                      typed slot (`filter_extensions`
//                                      copies them unrestricted). Plugins
//                                      read ObjectSecurityProfile /
//                                      DataPolicy directly. Distinct from
//                                      the static `data:` payload tree.

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
        // Plus the flattened role.<name> = true keys for atomic membership
        // names. Dotted names stay in the exact set so CEL cannot reinterpret
        // an alias such as `role.admin.readonly` as a nested `role.admin` map.
        for role in &subject.roles {
            if is_atomic_membership_name(role) {
                bag.set(format!("{BAG_ROLE_PREFIX}{role}"), true);
            }
        }
        bag.set(BAG_SUBJECT_PERMISSIONS, subject.permissions.clone());
        for perm in &subject.permissions {
            if is_atomic_membership_name(perm) {
                bag.set(format!("{BAG_PERM_PREFIX}{perm}"), true);
            }
        }
        bag.set(BAG_SUBJECT_TEAMS, subject.teams.clone());
        // Mirror the role.X / perm.X namespace so policies can
        // gate on team membership with the same DSL shape, e.g.
        // `require(team.engineering | team.security)`.
        for team in &subject.teams {
            if is_atomic_membership_name(team) {
                bag.set(format!("{BAG_TEAM_PREFIX}{team}"), true);
            }
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
/// Only atomic membership names receive presence-only aliases; dotted names
/// remain addressable through the exact sets without becoming CEL namespaces.
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
        if is_atomic_membership_name(role) {
            bag.set(format!("client.role.{role}"), true);
        }
    }
    let perms: HashSet<String> = client.permissions.iter().cloned().collect();
    bag.set(BAG_CLIENT_PERMISSIONS, perms);
    for perm in &client.permissions {
        if is_atomic_membership_name(perm) {
            bag.set(format!("client.perm.{perm}"), true);
        }
    }
    let scopes: HashSet<String> = client.authorized_scopes.iter().cloned().collect();
    bag.set("client.authorized_scopes", scopes);
    let auds: HashSet<String> = client.authorized_audiences.iter().cloned().collect();
    bag.set("client.authorized_audiences", auds);
    // Set only, unlike the two loops above and unlike `subject.teams`. The
    // flattened form cannot hold a dotted name, so it is lossy wherever one
    // occurs; the five that have it predate the sets and the list is closed.
    // Adding a sixth would spread an incomplete projection, not complete the
    // vocabulary. `client.teams contains "platform"` is the form that always
    // works.
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
    if let Some(at) = &w.attested_at {
        // Fixed second precision and a literal `Z`, so the string sorts the
        // way the instant does. `SecondsFormat::AutoSi` would emit `00.5Z`
        // beside `00Z`, and `.` sorts before `Z`, so a sub-second reading
        // would compare as earlier than a whole-second one in the same second.
        //
        // That buys lexicographic ordering in CEL and Rego only. APL's order
        // comparison is numeric and fails closed on an operand that will not
        // coerce to a finite f64, so `attested_at < "..."` denies every
        // request there rather than testing freshness, so `attested_at_epoch`
        // carries the same instant in a form APL can order.
        bag.set(
            format!("{prefix}.attested_at"),
            at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        // Unix seconds as `i64`, which `numeric_compare` orders on its exact
        // integer path without going through `f64`. Seconds rather than
        // nanoseconds: nanoseconds exhaust `i64` in 2262 and exceed 2^53, so a
        // comparison against a float literal would be refused as unorderable.
        //
        // Both keys truncate the same value, so they describe one instant
        // rather than two. Truncation loses up to a second and always toward
        // the past, which reads an attestation as very slightly older than it
        // is: a freshness rule errs toward stale and never toward fresh.
        bag.set(format!("{prefix}.attested_at_epoch"), at.timestamp());
    }
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

/// Membership names are atomic in the exact-set representation. A dotted
/// name must not also become a flattened alias because CEL interprets dotted
/// bag keys as nested maps (`role.admin.readonly` would make `role.admin`
/// appear present).
fn is_atomic_membership_name(name: &str) -> bool {
    !name.contains('.')
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
    use praxis_policy_core::extensions::SubjectExtension;
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
    fn dotted_subject_memberships_stay_exact_without_aliases() {
        let sec = SecurityExtension {
            subject: Some(SubjectExtension {
                roles: HashSet::from(["admin.readonly".to_owned(), "reader".to_owned()]),
                permissions: HashSet::from(["data.read".to_owned(), "view".to_owned()]),
                teams: HashSet::from(["engineering.platform".to_owned(), "security".to_owned()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);

        assert!(bag.set_contains("subject.roles", "admin.readonly"));
        assert!(bag.set_contains("subject.permissions", "data.read"));
        assert!(bag.set_contains("subject.teams", "engineering.platform"));
        assert_eq!(bag.get_bool("role.admin.readonly"), None);
        assert_eq!(bag.get_bool("perm.data.read"), None);
        assert_eq!(bag.get_bool("team.engineering.platform"), None);
        assert_eq!(bag.get_bool("role.reader"), Some(true));
        assert_eq!(bag.get_bool("perm.view"), Some(true));
        assert_eq!(bag.get_bool("team.security"), Some(true));
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
    fn dotted_client_memberships_stay_exact_without_aliases() {
        let client = ClientExtension {
            client_id: "dotted-app".into(),
            roles: vec!["admin.readonly".into(), "partner".into()],
            permissions: vec!["data.read".into(), "call_tool".into()],
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_client(&client, &mut bag);

        assert!(bag.set_contains("client.roles", "admin.readonly"));
        assert!(bag.set_contains("client.permissions", "data.read"));
        assert_eq!(bag.get_bool("client.role.admin.readonly"), None);
        assert_eq!(bag.get_bool("client.perm.data.read"), None);
        assert_eq!(bag.get_bool("client.role.partner"), Some(true));
        assert_eq!(bag.get_bool("client.perm.call_tool"), Some(true));
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

    /// The rendering is pinned rather than left to the formatter's defaults,
    /// because the fixed width is what makes the string sort the way the
    /// instant does: at variable precision `.` sorts before `Z` and a
    /// sub-second reading would compare as earlier than a whole-second one in
    /// the same second.
    ///
    /// This asserts the rendering and Rust's ordering of it, which is what CEL
    /// and Rego see. It says nothing about APL, whose order comparison is
    /// numeric and refuses this value; `apl_cannot_order_a_rendered_instant`
    /// covers that.
    #[test]
    fn attested_at_renders_orderable_rfc3339() {
        use praxis_policy_core::extensions::WorkloadIdentity;
        let at = |s: &str| WorkloadIdentity {
            attested_at: Some(s.parse().expect("a literal RFC3339 instant")),
            ..Default::default()
        };

        let mut bag = AttributeBag::new();
        extract_workload("caller_workload", &at("2026-10-01T12:00:00Z"), &mut bag);
        assert_eq!(
            bag.get_string("caller_workload.attested_at"),
            Some("2026-10-01T12:00:00Z")
        );
        // The same instant, and the same truncation, so the two keys cannot
        // describe different moments.
        assert_eq!(
            bag.get_int("caller_workload.attested_at_epoch"),
            Some(1_790_856_000)
        );

        // A sub-second input truncates rather than widening the format, which
        // is what keeps every value the same width.
        let mut sub = AttributeBag::new();
        extract_workload("caller_workload", &at("2026-10-01T12:00:00.5Z"), &mut sub);
        assert_eq!(
            sub.get_string("caller_workload.attested_at"),
            Some("2026-10-01T12:00:00Z")
        );
        assert_eq!(
            sub.get_int("caller_workload.attested_at_epoch"),
            Some(1_790_856_000),
            "truncation has to lose the same half-second in both forms"
        );

        // A non-UTC input renders as the same instant in UTC, so two hosts in
        // different zones produce comparable strings.
        let mut offset = AttributeBag::new();
        extract_workload(
            "caller_workload",
            &at("2026-10-01T13:00:00+01:00"),
            &mut offset,
        );
        assert_eq!(
            offset.get_string("caller_workload.attested_at"),
            Some("2026-10-01T12:00:00Z")
        );

        // An offset that moves the instant across midnight, so the date and
        // not only the clock has to be converted.
        let mut crossing = AttributeBag::new();
        extract_workload(
            "caller_workload",
            &at("2026-10-01T00:30:00+05:30"),
            &mut crossing,
        );
        assert_eq!(
            crossing.get_string("caller_workload.attested_at"),
            Some("2026-09-30T19:00:00Z")
        );

        // The property a staleness check depends on. Both sides are taken out
        // of the bag before comparing: comparing the `Option`s would let a
        // missing key pass, because `None` orders below `Some`.
        let mut later_bag = AttributeBag::new();
        extract_workload(
            "caller_workload",
            &at("2026-10-02T00:00:00Z"),
            &mut later_bag,
        );
        let earlier = bag
            .get_string("caller_workload.attested_at")
            .expect("the earlier instant rendered");
        let later = later_bag
            .get_string("caller_workload.attested_at")
            .expect("the later instant rendered");
        assert!(
            earlier < later,
            "the string must order the way the instant does: {earlier} then {later}"
        );
    }

    /// What the rendered instant is worth to an APL author, which is not what
    /// the format suggests. Order comparison in APL is numeric and fails
    /// closed on an operand that will not coerce to a finite `f64`, so a rule
    /// written as a staleness check denies every request instead, including
    /// one whose attestation is recent. Pinned through the evaluator, because
    /// asserting Rust's `str` ordering says nothing about the language a
    /// policy is written in.
    #[test]
    fn apl_cannot_order_a_rendered_instant() {
        use praxis_policy_apl_core::{evaluate_rules, parse_rule};

        let mut bag = AttributeBag::new();
        extract_workload(
            "caller_workload",
            &WorkloadIdentity {
                attested_at: Some(
                    "2026-10-01T12:00:00Z"
                        .parse()
                        .expect("a literal RFC3339 instant"),
                ),
                ..Default::default()
            },
            &mut bag,
        );

        // Noon on the 1st is after the floor, so a working order comparison
        // would not deny. This one denies, and says why.
        let stale = parse_rule(
            r#"caller_workload.attested_at < "2026-10-01T00:00:00Z": deny"#,
            "test",
        )
        .expect("the rule parses");
        let decision = evaluate_rules(std::slice::from_ref(&stale), &bag);
        match decision {
            praxis_policy_apl_core::Decision::Deny { reason, .. } => {
                let reason = reason.unwrap_or_default();
                assert!(
                    reason.contains("not a finite number"),
                    "the denial should be the unorderable-operand one: {reason}"
                );
            },
            other => panic!("APL ordered a string instant: {other:?}"),
        }

        // Equality is what an APL rule can do with it today.
        let exact = parse_rule(
            r#"caller_workload.attested_at == "2026-10-01T12:00:00Z": deny"#,
            "test",
        )
        .expect("the rule parses");
        assert!(matches!(
            evaluate_rules(std::slice::from_ref(&exact), &bag),
            praxis_policy_apl_core::Decision::Deny { reason: None, .. }
        ));
    }

    /// What `attested_at_epoch` is for. An event-pinned floor is the rule the
    /// string form cannot express in APL: "reject anything attested before the
    /// CA rotation" is a lasting control rather than a window that goes stale,
    /// and it needs an operand APL can order.
    #[test]
    fn apl_orders_the_epoch_form() {
        use praxis_policy_apl_core::{Decision, evaluate_rules, parse_rule};

        let bag_at = |rfc: &str| {
            let mut bag = AttributeBag::new();
            extract_workload(
                "caller_workload",
                &WorkloadIdentity {
                    attested_at: Some(rfc.parse().expect("a literal RFC3339 instant")),
                    ..Default::default()
                },
                &mut bag,
            );
            bag
        };
        // 1790812800 is 2026-10-01T00:00:00Z, standing in for the rotation.
        let floor = "caller_workload.attested_at_epoch < 1790812800: deny";
        let rule = parse_rule(floor, "test").expect("the rule parses");

        // Attested after the floor: allowed, and no fail-closed denial.
        assert_eq!(
            evaluate_rules(std::slice::from_ref(&rule), &bag_at("2026-10-01T12:00:00Z")),
            Decision::Allow
        );

        // Attested before it: denied on the rule, not on unorderability.
        match evaluate_rules(std::slice::from_ref(&rule), &bag_at("2026-09-30T12:00:00Z")) {
            Decision::Deny { reason, .. } => assert!(
                reason.is_none(),
                "a rule denial carries no reason; a fail-closed one does: {reason:?}"
            ),
            other => panic!("the floor should have denied: {other:?}"),
        }
    }

    /// `client.teams` is set-only on purpose, where `subject.teams` carries the
    /// flattened boolean too. Guarding it because the asymmetry reads as an
    /// oversight: the two loops immediately above this one in `extract_client`
    /// do flatten, so completing the pattern is the obvious wrong edit.
    #[test]
    fn client_teams_stays_set_only() {
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert!(bag.set_contains("client.teams", "acme"));
        assert_eq!(bag.get_bool("client.team.acme"), None);
        // The pair it is asymmetric with, so a reader sees both halves.
        let mut subject_bag = AttributeBag::new();
        extract_security(
            &SecurityExtension {
                subject: Some(SubjectExtension {
                    teams: HashSet::from(["acme".to_owned()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &mut subject_bag,
        );
        assert_eq!(subject_bag.get_bool("team.acme"), Some(true));
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
