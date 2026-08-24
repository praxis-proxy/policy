// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The shipped claim maps, embedded as JSON. Embedding rather than reading from
// disk means a preset cannot go missing at deploy, and the registry is one table
// so a single test covers every entry: adding a preset without covering it is not
// possible.
//
// A preset ships a candidate only where the provider actually mints the claim.
// Each `description` names what it omits and why, because a preset that quietly
// fills a field with the wrong concept is worse than one that leaves it empty:
// the operator has no reason to look.

use serde::Deserialize;

use crate::claim_map_config::{ClaimMapConfig, CompiledClaimMap};

/// Every shipped preset, by the name an operator writes in `claim_mapper`.
///
/// Sorted by name so the unknown-name error lists them in a stable order. Not
/// public: the embedded JSON is an implementation detail, and [`names`] plus
/// [`lookup`] are what a caller needs.
const PRESETS: &[(&str, &str)] = &[
    ("auth0", include_str!("presets/auth0.json")),
    ("cognito", include_str!("presets/cognito.json")),
    ("keycloak", include_str!("presets/keycloak.json")),
    ("standard", include_str!("presets/standard.json")),
];

/// The preset an absent `claim_mapper` resolves to.
pub const DEFAULT_PRESET: &str = "standard";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PresetFile {
    description: String,
    claim_map: ClaimMapConfig,
}

/// A shipped preset: what it covers, and the map it compiles to.
#[derive(Debug, Clone)]
pub struct Preset {
    name: &'static str,
    description: String,
    claim_map: CompiledClaimMap,
}

impl Preset {
    /// The name an operator writes.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// What the preset covers, what it deliberately omits, and which of its
    /// claims are opt-in at the provider.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The compiled map.
    pub fn claim_map(&self) -> &CompiledClaimMap {
        &self.claim_map
    }

    /// Take the compiled map, dropping the metadata.
    pub fn into_claim_map(self) -> CompiledClaimMap {
        self.claim_map
    }
}

/// Every preset name, in the order the error text lists them.
pub fn names() -> impl Iterator<Item = &'static str> {
    PRESETS.iter().map(|(name, _)| *name)
}

/// The valid names, formatted for an error message.
pub fn valid_names() -> String {
    names().collect::<Vec<_>>().join(", ")
}

/// Parse and compile a preset by name.
///
/// # Errors
///
/// Returns a message listing every valid name when `name` is not one of them,
/// and the parse or compile failure when a shipped preset is itself malformed,
/// which a table-driven test rules out before release.
pub fn lookup(name: &str) -> Result<Preset, String> {
    let (interned, source) = PRESETS
        .iter()
        .find(|(preset, _)| *preset == name)
        .ok_or_else(|| format!("unknown claim_mapper '{name}'; valid: [{}]", valid_names()))?;

    let file: PresetFile = serde_json::from_str(source)
        .map_err(|e| format!("the '{interned}' preset does not parse: {e}"))?;
    let claim_map = file
        .claim_map
        .compile()
        .map_err(|e| format!("the '{interned}' preset does not compile: {e}"))?;

    Ok(Preset {
        name: interned,
        description: file.description,
        claim_map,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::collections::HashSet;

    use praxis_policy_core::extensions::raw_credentials::TokenRole;
    use serde_json::{Value, json};

    use super::*;
    use crate::claim_map::{ClaimMap, ClaimMapper as _};
    use crate::configured_mapper::ConfiguredClaimMap;

    fn claims(value: Value) -> ClaimMap {
        value.as_object().unwrap().clone().into_iter().collect()
    }

    fn mapper(preset: &str) -> ConfiguredClaimMap {
        ConfiguredClaimMap::new(
            lookup(preset)
                .unwrap_or_else(|e| panic!("the '{preset}' preset must load: {e}"))
                .into_claim_map(),
        )
    }

    fn sorted(values: &HashSet<String>) -> Vec<&str> {
        let mut items: Vec<&str> = values.iter().map(String::as_str).collect();
        items.sort_unstable();
        items
    }

    fn authored_paths(map: &CompiledClaimMap, role: &TokenRole, field: &str) -> Vec<String> {
        map.role(role)
            .unwrap_or_else(|e| panic!("the section must exist: {e}"))
            .field(field)
            .unwrap_or_else(|| panic!("`{field}` must be declared"))
            .candidates()
            .iter()
            .map(|candidate| candidate.path().to_string())
            .collect()
    }

    // ---- the table --------------------------------------------------------

    /// Table-driven, so a preset added without a test is not possible: this
    /// parses, compiles, and sanity-checks every entry in the registry.
    #[test]
    fn every_shipped_preset_parses_compiles_and_declares_a_role() {
        for name in names() {
            let preset = lookup(name).unwrap_or_else(|e| panic!("'{name}': {e}"));
            assert_eq!(preset.name(), name);
            assert!(
                preset.description().len() > 40,
                "'{name}': the description must say what the preset covers and omits"
            );
            let declares_a_role = [
                TokenRole::User,
                TokenRole::Client,
                TokenRole::CallerWorkload,
            ]
            .iter()
            .any(|role| preset.claim_map().role(role).is_ok());
            assert!(declares_a_role, "'{name}' declares no role section");
        }
    }

    /// Compilation already parses every path; asserting it per preset is what
    /// makes a failure name the preset rather than a line in a table.
    #[test]
    fn every_shipped_presets_paths_parse() {
        for name in names() {
            for role in [
                TokenRole::User,
                TokenRole::Client,
                TokenRole::CallerWorkload,
            ] {
                let preset = lookup(name).unwrap_or_else(|e| panic!("'{name}': {e}"));
                if let Ok(section) = preset.claim_map().role(&role) {
                    for (field, compiled) in section.fields() {
                        assert!(
                            !compiled.candidates().is_empty(),
                            "'{name}' {role:?} {field}: no candidates"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn preset_names_are_unique_and_sorted() {
        let names: Vec<&str> = names().collect();
        let mut expected = names.clone();
        expected.sort_unstable();
        assert_eq!(names, expected, "the error text's order must be stable");
        assert_eq!(
            names.iter().collect::<HashSet<_>>().len(),
            names.len(),
            "duplicate preset name"
        );
    }

    #[test]
    fn an_unknown_name_lists_every_valid_name() {
        let err = lookup("made-up").expect_err("an unknown preset must not resolve");
        assert!(err.contains("made-up"), "{err}");
        for name in names() {
            assert!(err.contains(name), "'{name}' missing from: {err}");
        }
    }

    /// An absent `claim_mapper` resolves here, so changing this name would
    /// change what every deployment that names no mapper gets.
    #[test]
    fn the_default_preset_is_standard_and_is_in_the_table() {
        assert_eq!(DEFAULT_PRESET, "standard");
        lookup(DEFAULT_PRESET).expect("the default preset must load");
    }

    // ---- the standard preset ----------------------------------------------

    /// The standard preset must check in the order the Rust mapper checks, since
    /// the order is what decides which claim wins.
    #[test]
    fn the_standard_preset_declares_the_rust_mappers_candidate_order() {
        let map = lookup("standard").expect("standard loads").into_claim_map();

        for (field, expected) in [
            ("id", vec!["sub"]),
            ("roles", vec!["roles"]),
            ("permissions", vec!["permissions", "scope"]),
            ("teams", vec!["teams", "groups"]),
        ] {
            assert_eq!(
                authored_paths(&map, &TokenRole::User, field),
                expected,
                "subject.{field}"
            );
        }

        for (field, expected) in [
            ("client_id", vec!["client_id", "azp"]),
            ("client_name", vec!["client_name"]),
            ("authorized_scopes", vec!["authorized_scopes", "scope"]),
            ("authorized_audiences", vec!["aud"]),
            ("roles", vec!["roles"]),
        ] {
            assert_eq!(
                authored_paths(&map, &TokenRole::Client, field),
                expected,
                "client.{field}"
            );
        }

        assert_eq!(
            authored_paths(&map, &TokenRole::CallerWorkload, "spiffe_id"),
            vec!["sub", "spiffe_id"],
        );
        assert!(
            map.role(&TokenRole::CallerWorkload)
                .expect("standard declares a workload section")
                .field("trust_domain")
                .is_none(),
            "the trust domain is derived from the SPIFFE URI, not mapped"
        );
    }

    /// Each provider preset's candidates, pinned in order. The standard preset has
    /// a parity gate; these have only their own tests, so without this a candidate
    /// could be added, reordered or dropped silently.
    #[test]
    fn every_provider_preset_declares_the_candidates_it_is_documented_to() {
        for (name, role, field, expected) in [
            ("keycloak", TokenRole::User, "id", vec!["sub"]),
            (
                "keycloak",
                TokenRole::User,
                "roles",
                vec!["realm_access.roles"],
            ),
            ("keycloak", TokenRole::User, "permissions", vec!["scope"]),
            (
                "keycloak",
                TokenRole::Client,
                "client_id",
                vec!["client_id", "azp", "clientId"],
            ),
            ("auth0", TokenRole::User, "id", vec!["sub"]),
            (
                "auth0",
                TokenRole::User,
                "permissions",
                vec!["permissions", "scope"],
            ),
            (
                "auth0",
                TokenRole::Client,
                "client_id",
                vec!["client_id", "azp"],
            ),
            ("cognito", TokenRole::User, "id", vec!["sub"]),
            ("cognito", TokenRole::User, "teams", vec!["cognito:groups"]),
            ("cognito", TokenRole::Client, "client_id", vec!["client_id"]),
        ] {
            let map = lookup(name)
                .unwrap_or_else(|e| panic!("'{name}': {e}"))
                .into_claim_map();
            assert_eq!(
                authored_paths(&map, &role, field),
                expected,
                "'{name}' {role:?}.{field}"
            );
        }
    }

    /// Pre-2023 Keycloak spells the claim `clientId`. It is the tail candidate, so
    /// nothing else in the suite reaches it.
    #[test]
    fn the_keycloak_preset_accepts_the_camel_case_client_id() {
        let client = mapper("keycloak")
            .map_client(&claims(
                json!({"clientId": "legacy-service", "scope": "openid"}),
            ))
            .expect("a pre-2023 Keycloak token resolves");
        assert_eq!(client.client_id, "legacy-service");

        let precedence = mapper("keycloak")
            .map_client(&claims(json!({
                "client_id": "modern", "azp": "middle", "clientId": "legacy",
            })))
            .expect("resolves");
        assert_eq!(
            precedence.client_id, "modern",
            "the candidates are tried in the order the preset declares"
        );
    }

    /// Only `standard` has a workload shape to offer. A provider preset that
    /// declared one would be guessing.
    #[test]
    fn standard_is_the_only_preset_with_a_workload_section() {
        for name in names() {
            let declares = lookup(name)
                .unwrap_or_else(|e| panic!("'{name}': {e}"))
                .claim_map()
                .role(&TokenRole::CallerWorkload)
                .is_ok();
            assert_eq!(
                declares,
                name == "standard",
                "'{name}': only standard should declare a workload section"
            );
        }
    }

    /// `role: workload` against a provider preset fails at construction naming
    /// the role, which is the right outcome: better than a section of guesses.
    #[test]
    fn a_provider_preset_refuses_the_workload_role_and_names_it() {
        for name in ["auth0", "cognito", "keycloak"] {
            let err = lookup(name)
                .unwrap_or_else(|e| panic!("'{name}': {e}"))
                .claim_map()
                .role(&TokenRole::CallerWorkload)
                .expect_err("a provider preset has no workload shape");
            assert!(err.contains("workload"), "'{name}': {err}");
        }
    }

    // ---- provider presets resolve real tokens -----------------------------

    #[test]
    fn the_keycloak_preset_reads_realm_roles_and_an_azp_anchor() {
        let subject = mapper("keycloak")
            .map_subject(&claims(json!({
                "sub": "f:2c1b:alice",
                "realm_access": {"roles": ["viewer", "editor"]},
                "scope": "openid profile",
            })))
            .expect("a Keycloak access token resolves");
        assert_eq!(sorted(&subject.roles), vec!["editor", "viewer"]);
        assert_eq!(sorted(&subject.permissions), vec!["openid", "profile"]);

        let client = mapper("keycloak")
            .map_client(&claims(json!({"azp": "my-api", "scope": "openid"})))
            .expect("azp anchors a Keycloak client");
        assert_eq!(client.client_id, "my-api");
    }

    #[test]
    fn the_auth0_preset_reads_permissions_and_an_azp_anchor() {
        let subject = mapper("auth0")
            .map_subject(&claims(json!({
                "sub": "auth0|507f",
                "permissions": ["read:reports"],
                "scope": "openid profile",
            })))
            .expect("an Auth0 token resolves");
        assert_eq!(
            sorted(&subject.permissions),
            vec!["read:reports"],
            "the permissions array wins over scope"
        );

        let client = mapper("auth0")
            .map_client(&claims(json!({
                "azp": "6MZ2Wt3rBGxOA1example", "scope": "read:reports",
            })))
            .expect("azp anchors an Auth0 client");
        assert_eq!(client.client_id, "6MZ2Wt3rBGxOA1example");
    }

    #[test]
    fn the_cognito_preset_reads_groups_into_teams_and_a_client_id_anchor() {
        let subject = mapper("cognito")
            .map_subject(&claims(json!({
                "sub": "a1b2", "cognito:groups": ["admins", "engineering"],
            })))
            .expect("a Cognito token resolves");
        assert_eq!(sorted(&subject.teams), vec!["admins", "engineering"]);

        let client = mapper("cognito")
            .map_client(&claims(json!({
                "client_id": "1example23456789", "scope": "resourceserver.1/appclient2",
            })))
            .expect("client_id anchors a Cognito client");
        assert_eq!(client.client_id, "1example23456789");
        assert_eq!(
            client.authorized_scopes,
            vec!["resourceserver.1/appclient2"]
        );
    }

    // ---- the deliberate omissions -----------------------------------------

    /// Each omission is asserted rather than left to review, because a candidate
    /// added later out of helpfulness would otherwise pass silently, and each of
    /// these would fill a field with the wrong concept.
    #[test]
    fn each_preset_leaves_the_fields_it_omits_empty() {
        // Keycloak's `groups` claim holds realm roles, not groups.
        let keycloak = mapper("keycloak")
            .map_subject(&claims(json!({
                "sub": "alice", "groups": ["offline_access", "uma_authorization"],
            })))
            .expect("resolves");
        assert!(
            keycloak.teams.is_empty(),
            "mapping Keycloak's groups to teams would fill teams with realm roles"
        );

        // Auth0 forbids a bare `roles` claim, so roles are per-deployment
        // namespaced and no preset can name the path.
        let auth0 = mapper("auth0")
            .map_subject(&claims(json!({
                "sub": "auth0|507f",
                "https://my-app.example.com/roles": ["editor"],
                "roles": ["editor"],
            })))
            .expect("resolves");
        assert!(
            auth0.roles.is_empty(),
            "the Auth0 preset cannot know a deployment's namespace"
        );
        assert!(auth0.teams.is_empty());

        // Cognito's `cognito:roles` holds IAM role ARNs.
        let cognito = mapper("cognito")
            .map_subject(&claims(json!({
                "sub": "a1b2",
                "cognito:roles": ["arn:aws:iam::123456789012:role/AppRole"],
            })))
            .expect("resolves");
        assert!(
            cognito.roles.is_empty(),
            "cognito:roles holds IAM ARNs, which are not application roles"
        );

        // Cognito access tokens carry no aud, so the preset does not read one.
        let cognito_client = mapper("cognito")
            .map_client(&claims(
                json!({"client_id": "svc", "aud": "would-be-wrong"}),
            ))
            .expect("resolves");
        assert!(cognito_client.authorized_audiences.is_empty());
    }

    /// Every preset reads `scope` as a delimited string, so an array-valued
    /// `scope` must contribute nothing rather than contributing each element as a
    /// permission. Without this, dropping `string_only` from a provider preset
    /// would fail no test, and only the standard preset's parity gate would
    /// notice.
    #[test]
    fn no_preset_grants_permissions_from_an_array_valued_scope() {
        let array_scope = json!({
            "sub": "alice",
            "client_id": "svc",
            "azp": "svc",
            "scope": ["admin", "root"],
        });
        for name in names() {
            let map = mapper(name);

            let subject = map
                .map_subject(&claims(array_scope.clone()))
                .unwrap_or_else(|| panic!("'{name}': the subject resolves"));
            assert!(
                subject.permissions.is_empty(),
                "'{name}': an array-valued scope granted {:?} as permissions",
                sorted(&subject.permissions)
            );

            let client = map
                .map_client(&claims(array_scope.clone()))
                .unwrap_or_else(|| panic!("'{name}': the client resolves"));
            assert!(
                client.authorized_scopes.is_empty(),
                "'{name}': an array-valued scope granted {:?} as authorized scopes",
                client.authorized_scopes
            );
        }
    }

    /// The four presets have to agree on the same token. A present but unusable
    /// anchor declines everywhere rather than falling through to the next
    /// candidate in some presets and not others.
    #[test]
    fn every_preset_declines_a_present_but_unusable_client_anchor() {
        for name in names() {
            let declined =
                mapper(name).map_client(&claims(json!({"client_id": null, "azp": "svc-billing"})));
            assert!(
                declined.is_none(),
                "'{name}': a null client_id must not fall through to azp"
            );
        }
    }

    /// A field no preset declares is still reachable, which is the point of the
    /// map: no provider mints `client_name`, so only a hand-written map fills it.
    #[test]
    fn no_preset_declares_a_client_name_candidate_except_standard() {
        for name in ["auth0", "cognito", "keycloak"] {
            let preset = lookup(name).unwrap_or_else(|e| panic!("'{name}': {e}"));
            let section = preset
                .claim_map()
                .role(&TokenRole::Client)
                .unwrap_or_else(|e| panic!("'{name}': {e}"));
            assert!(
                section.field("client_name").is_none(),
                "'{name}': no researched provider mints client_name"
            );
            for field in ["permissions", "teams"] {
                assert!(
                    section.field(field).is_none(),
                    "'{name}': no researched provider mints a client {field} source"
                );
            }
        }
    }
}
