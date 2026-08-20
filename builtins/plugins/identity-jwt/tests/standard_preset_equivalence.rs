// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A deployment that upgrades without touching its config must see the identity
//! it saw before.
//!
//! `fixtures/claim-corpus.json` pairs a claim set with the typed identity it
//! produces, one entry per token shape, each recording where its shape came
//! from. The corpus is the contract: it is asserted against `StandardClaimMap`,
//! so it describes the mapper rather than any later reimplementation of it.
//!
//! The gate then holds the shipped `standard` preset to that same corpus. Where
//! the two disagree the preset is what changes, never the Rust mapper and never
//! the corpus, unless the corpus entry is itself wrong about what an `IdP` mints.
//!
//! The corpus is embedded rather than read at run time, so a missing or
//! unparseable file is a compile or test failure and never a silently skipped
//! entry.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::collections::{HashMap, HashSet};

use praxis_policy_core::extensions::{ClientExtension, SubjectExtension, WorkloadIdentity};
use praxis_policy_plugin_identity_jwt::{
    ClaimMapper as _, ConfiguredClaimMap, StandardClaimMap, presets,
};
use serde::Deserialize;
use serde_json::Value;

const CORPUS_JSON: &str = include_str!("fixtures/claim-corpus.json");

// =====================================================================
// Corpus shape
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CorpusRole {
    User,
    Client,
    Workload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusEntry {
    name: String,
    role: CorpusRole,
    /// Where the shape came from: a provider document, or what it was
    /// constructed to exercise. A data field because JSON has no comments.
    provenance: String,
    claims: HashMap<String, Value>,
    /// The typed identity for this entry's role, or `null` when the mapper
    /// declines the token.
    expected: Option<Value>,
}

fn corpus() -> Vec<CorpusEntry> {
    serde_json::from_str(CORPUS_JSON).expect(
        "the corpus must parse; a malformed entry fails the suite rather than being skipped",
    )
}

/// Field names each role's `expected` block may use.
///
/// The extension types do not deny unknown fields, so a typo in the corpus
/// would otherwise deserialize to a default and pass.
const SUBJECT_FIELDS: &[&str] = &[
    "id",
    "subject_type",
    "roles",
    "permissions",
    "teams",
    "claims",
];
const CLIENT_FIELDS: &[&str] = &[
    "client_id",
    "client_name",
    "trust_level",
    "authorized_scopes",
    "authorized_audiences",
    "roles",
    "permissions",
    "teams",
    "claims",
];
const WORKLOAD_FIELDS: &[&str] = &[
    "spiffe_id",
    "trust_domain",
    "attested_at",
    "attestor",
    "selectors",
    "client_id",
];

fn allowed_fields(role: CorpusRole) -> &'static [&'static str] {
    match role {
        CorpusRole::User => SUBJECT_FIELDS,
        CorpusRole::Client => CLIENT_FIELDS,
        CorpusRole::Workload => WORKLOAD_FIELDS,
    }
}

fn expected_subject(entry: &CorpusEntry) -> Option<SubjectExtension> {
    let value = entry.expected.as_ref()?;
    Some(
        serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("{}: `expected` is not a subject: {e}", entry.name)),
    )
}

fn expected_client(entry: &CorpusEntry) -> Option<ClientExtension> {
    let value = entry.expected.as_ref()?;
    Some(
        serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("{}: `expected` is not a client: {e}", entry.name)),
    )
}

fn expected_workload(entry: &CorpusEntry) -> Option<WorkloadIdentity> {
    let value = entry.expected.as_ref()?;
    Some(
        serde_json::from_value(value.clone()).unwrap_or_else(|e| {
            panic!("{}: `expected` is not a workload identity: {e}", entry.name)
        }),
    )
}

// =====================================================================
// Comparison
// =====================================================================

/// Serialize a subject with its set-typed fields sorted.
///
/// `roles`, `permissions` and `teams` are `HashSet`s, so their serialized order
/// is not stable. Everything else compares as serialized, which is what makes
/// this a catch-all for fields the per-field assertions do not name.
fn subject_shape(subject: &SubjectExtension) -> Value {
    let mut value = serde_json::to_value(subject).expect("a subject serializes");
    for field in ["roles", "permissions", "teams"] {
        if let Some(Value::Array(elements)) = value.get_mut(field) {
            elements.sort_by_key(ToString::to_string);
        }
    }
    value
}

fn sorted(set: &HashSet<String>) -> Vec<&str> {
    let mut items: Vec<&str> = set.iter().map(String::as_str).collect();
    items.sort_unstable();
    items
}

/// Assert two subjects agree, naming the field that diverged.
fn assert_subjects_agree(context: &str, actual: &SubjectExtension, expected: &SubjectExtension) {
    assert_eq!(actual.id, expected.id, "{context}: subject id");
    assert_eq!(
        sorted(&actual.roles),
        sorted(&expected.roles),
        "{context}: subject roles"
    );
    assert_eq!(
        sorted(&actual.permissions),
        sorted(&expected.permissions),
        "{context}: subject permissions"
    );
    assert_eq!(
        sorted(&actual.teams),
        sorted(&expected.teams),
        "{context}: subject teams"
    );
    assert_eq!(
        actual.claims, expected.claims,
        "{context}: subject claims bag"
    );
    assert_eq!(
        subject_shape(actual),
        subject_shape(expected),
        "{context}: subject, whole"
    );
}

/// Assert two clients agree. The collection fields are `Vec`s, so order is part
/// of the comparison: candidate-declaration order and no deduplication are only
/// observable here.
fn assert_clients_agree(context: &str, actual: &ClientExtension, expected: &ClientExtension) {
    assert_eq!(actual.client_id, expected.client_id, "{context}: client id");
    assert_eq!(
        actual.client_name, expected.client_name,
        "{context}: client name"
    );
    assert_eq!(
        actual.authorized_scopes, expected.authorized_scopes,
        "{context}: client authorized scopes, in order"
    );
    assert_eq!(
        actual.authorized_audiences, expected.authorized_audiences,
        "{context}: client authorized audiences, in order"
    );
    assert_eq!(
        actual.roles, expected.roles,
        "{context}: client roles, in order"
    );
    assert_eq!(
        actual.permissions, expected.permissions,
        "{context}: client permissions, in order"
    );
    assert_eq!(
        actual.teams, expected.teams,
        "{context}: client teams, in order"
    );
    assert_eq!(
        actual.claims, expected.claims,
        "{context}: client claims bag"
    );
    assert_eq!(
        serde_json::to_value(actual).expect("a client serializes"),
        serde_json::to_value(expected).expect("a client serializes"),
        "{context}: client, whole"
    );
}

/// Assert two workload identities agree.
fn assert_workloads_agree(context: &str, actual: &WorkloadIdentity, expected: &WorkloadIdentity) {
    assert_eq!(actual.spiffe_id, expected.spiffe_id, "{context}: spiffe id");
    assert_eq!(
        actual.trust_domain, expected.trust_domain,
        "{context}: trust domain"
    );
    assert_eq!(actual.attestor, expected.attestor, "{context}: attestor");
    assert_eq!(actual.selectors, expected.selectors, "{context}: selectors");
    assert_eq!(actual.client_id, expected.client_id, "{context}: client id");
    assert_eq!(
        serde_json::to_value(actual).expect("a workload identity serializes"),
        serde_json::to_value(expected).expect("a workload identity serializes"),
        "{context}: workload identity, whole"
    );
}

// =====================================================================
// The baseline: the corpus describes today's Rust mapper
// =====================================================================

#[test]
fn every_corpus_entry_matches_the_rust_standard_mapper() {
    for entry in corpus() {
        let context = format!("{} (rust mapper)", entry.name);
        match entry.role {
            CorpusRole::User => match (
                StandardClaimMap.map_subject(&entry.claims),
                expected_subject(&entry),
            ) {
                (Some(actual), Some(expected)) => {
                    assert_subjects_agree(&context, &actual, &expected);
                },
                (None, None) => {},
                (actual, expected) => panic!(
                    "{context}: mapper produced {:?} but the corpus expects {:?}",
                    actual.is_some(),
                    expected.is_some()
                ),
            },
            CorpusRole::Client => match (
                StandardClaimMap.map_client(&entry.claims),
                expected_client(&entry),
            ) {
                (Some(actual), Some(expected)) => {
                    assert_clients_agree(&context, &actual, &expected);
                },
                (None, None) => {},
                (actual, expected) => panic!(
                    "{context}: mapper produced {:?} but the corpus expects {:?}",
                    actual.is_some(),
                    expected.is_some()
                ),
            },
            CorpusRole::Workload => match (
                StandardClaimMap.map_workload(&entry.claims),
                expected_workload(&entry),
            ) {
                (Some(actual), Some(expected)) => {
                    assert_workloads_agree(&context, &actual, &expected);
                },
                (None, None) => {},
                (actual, expected) => panic!(
                    "{context}: mapper produced {:?} but the corpus expects {:?}",
                    actual.is_some(),
                    expected.is_some()
                ),
            },
        }
    }
}

// =====================================================================
// The corpus covers what it claims to cover
// =====================================================================

#[test]
fn the_corpus_parses_and_every_entry_is_usable() {
    let entries = corpus();
    assert!(!entries.is_empty(), "the corpus must not be empty");
    for entry in &entries {
        assert!(!entry.name.trim().is_empty(), "every entry needs a name");
        assert!(
            !entry.provenance.trim().is_empty(),
            "{}: every entry records where its shape came from",
            entry.name
        );
        assert!(
            !entry.claims.is_empty(),
            "{}: an entry with no claims tests nothing",
            entry.name
        );
        if let Some(Value::Object(fields)) = entry.expected.as_ref() {
            for field in fields.keys() {
                assert!(
                    allowed_fields(entry.role).contains(&field.as_str()),
                    "{}: `{field}` is not a field of the {:?} identity; a typo here would \
                     deserialize to a default and pass",
                    entry.name,
                    entry.role
                );
            }
        }
    }
}

#[test]
fn entry_names_are_unique() {
    let mut seen: HashSet<String> = HashSet::new();
    for entry in corpus() {
        assert!(
            seen.insert(entry.name.clone()),
            "duplicate corpus entry name '{}'; the coverage checks address entries by name",
            entry.name
        );
    }
}

/// A later edit must not quietly drop a role from the corpus, which would leave
/// that role's mapping unmeasured while the suite still passed.
#[test]
fn all_three_roles_have_entries() {
    let roles: HashSet<CorpusRole> = corpus().into_iter().map(|entry| entry.role).collect();
    for role in [CorpusRole::User, CorpusRole::Client, CorpusRole::Workload] {
        assert!(roles.contains(&role), "the corpus has no {role:?} entry");
    }
}

/// Every fallback the Rust mapper implements, and the entry covering each
/// branch of it. Asserted structurally rather than trusted to review: a
/// fallback covered on one branch only can pass on the strength of the other.
const FALLBACK_BRANCHES: &[(&str, &str, &str)] = &[
    (
        "client anchor: client_id then azp",
        "client-anchor-from-client-id",
        "client-anchor-from-azp",
    ),
    (
        "client scopes: authorized_scopes then scope",
        "client-scopes-from-authorized-scopes",
        "client-scopes-from-scope-fallback",
    ),
    (
        "subject permissions: permissions then scope",
        "subject-permissions-from-permissions-array",
        "subject-permissions-from-scope-fallback",
    ),
    (
        "subject teams: teams then groups",
        "subject-teams-from-teams-array",
        "subject-teams-from-groups-fallback",
    ),
    (
        "workload identity: sub then spiffe_id",
        "workload-spiffe-id-from-sub",
        "workload-spiffe-id-from-the-spiffe-id-claim-fallback",
    ),
];

/// The `aud` shapes, which are not a fallback but a polymorphic single claim.
/// One provider flips between all three.
const AUD_SHAPES: &[&str] = &[
    "client-aud-as-a-string",
    "client-aud-as-an-array",
    "client-aud-absent",
];

#[test]
fn every_fallback_has_an_entry_on_both_branches() {
    let names: HashSet<String> = corpus().into_iter().map(|entry| entry.name).collect();
    for (fallback, first, second) in FALLBACK_BRANCHES {
        for branch in [first, second] {
            assert!(
                names.contains(*branch),
                "{fallback}: no entry named '{branch}' covers this branch"
            );
        }
    }
}

#[test]
fn every_aud_shape_has_an_entry() {
    let names: HashSet<String> = corpus().into_iter().map(|entry| entry.name).collect();
    for shape in AUD_SHAPES {
        assert!(
            names.contains(*shape),
            "no entry named '{shape}' covers this aud shape"
        );
    }
}

/// A token the mapper declines is as much a contract as one it accepts, and
/// each role declines for its own reason.
#[test]
fn every_role_has_a_declining_entry() {
    let declining: HashSet<CorpusRole> = corpus()
        .into_iter()
        .filter(|entry| entry.expected.is_none())
        .map(|entry| entry.role)
        .collect();
    for role in [CorpusRole::User, CorpusRole::Client, CorpusRole::Workload] {
        assert!(
            declining.contains(&role),
            "no {role:?} entry expects the mapper to decline"
        );
    }
}

// =====================================================================
// The gate: the standard preset agrees with the Rust mapper
// =====================================================================

fn standard_preset() -> ConfiguredClaimMap {
    ConfiguredClaimMap::new(
        presets::lookup("standard")
            .expect("the shipped standard preset must load")
            .into_claim_map(),
    )
}

/// Map one entry through both paths and assert they agree.
///
/// The preset is the `actual` side so a failure reads as the preset diverging,
/// which is the side that changes when it does.
fn assert_entry_agrees(entry: &CorpusEntry, preset: &ConfiguredClaimMap) {
    let context = format!("{} (standard preset vs rust mapper)", entry.name);
    match entry.role {
        CorpusRole::User => {
            match (
                preset.map_subject(&entry.claims),
                StandardClaimMap.map_subject(&entry.claims),
            ) {
                (Some(from_preset), Some(from_rust)) => {
                    assert_subjects_agree(&context, &from_preset, &from_rust);
                },
                (None, None) => {},
                (from_preset, from_rust) => panic!(
                    "{context}: the preset {} but the mapper {}",
                    described(from_preset.is_some()),
                    described(from_rust.is_some())
                ),
            }
        },
        CorpusRole::Client => {
            match (
                preset.map_client(&entry.claims),
                StandardClaimMap.map_client(&entry.claims),
            ) {
                (Some(from_preset), Some(from_rust)) => {
                    assert_clients_agree(&context, &from_preset, &from_rust);
                },
                (None, None) => {},
                (from_preset, from_rust) => panic!(
                    "{context}: the preset {} but the mapper {}",
                    described(from_preset.is_some()),
                    described(from_rust.is_some())
                ),
            }
        },
        CorpusRole::Workload => {
            match (
                preset.map_workload(&entry.claims),
                StandardClaimMap.map_workload(&entry.claims),
            ) {
                (Some(from_preset), Some(from_rust)) => {
                    assert_workloads_agree(&context, &from_preset, &from_rust);
                },
                (None, None) => {},
                (from_preset, from_rust) => panic!(
                    "{context}: the preset {} but the mapper {}",
                    described(from_preset.is_some()),
                    described(from_rust.is_some())
                ),
            }
        },
    }
}

fn described(produced: bool) -> &'static str {
    if produced {
        "produced an identity"
    } else {
        "declined"
    }
}

/// The compatibility promise, in one test: an upgrading deployment that names no
/// mapper sees the identity it saw before, for every shape in the corpus.
#[test]
fn the_standard_preset_agrees_with_the_rust_mapper_across_the_corpus() {
    let preset = standard_preset();
    for entry in corpus() {
        assert_entry_agrees(&entry, &preset);
    }
}

/// Both branches of every fallback, asserted through both paths and named by
/// their fallback. Without this a preset expressing a fallback differently could
/// pass on the strength of the branch that happens to agree.
#[test]
fn both_branches_of_every_fallback_agree_through_both_paths() {
    let preset = standard_preset();
    let entries = corpus();
    let find = |name: &str| {
        entries
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("the corpus must carry an entry named '{name}'"))
    };

    for (fallback, first, second) in FALLBACK_BRANCHES {
        for branch in [first, second] {
            let entry = find(branch);
            assert_entry_agrees(entry, &preset);
            println!("{fallback}: '{branch}' agrees");
        }
    }
    for shape in AUD_SHAPES {
        assert_entry_agrees(find(shape), &preset);
    }
}

/// A token the Rust mapper declines must be declined by the preset too. An
/// anchor the preset accepts where the mapper does not is a widened surface, not
/// a compatible one.
#[test]
fn a_token_the_rust_mapper_declines_is_declined_by_the_preset() {
    let preset = standard_preset();
    let declining: Vec<CorpusEntry> = corpus()
        .into_iter()
        .filter(|entry| entry.expected.is_none())
        .collect();
    assert!(
        !declining.is_empty(),
        "the corpus must carry entries the mapper declines"
    );
    for entry in declining {
        let produced = match entry.role {
            CorpusRole::User => preset.map_subject(&entry.claims).is_some(),
            CorpusRole::Client => preset.map_client(&entry.claims).is_some(),
            CorpusRole::Workload => preset.map_workload(&entry.claims).is_some(),
        };
        assert!(
            !produced,
            "{}: the Rust mapper declines this token and the preset must too",
            entry.name
        );
    }
}

/// The claims bag is compared key for key and value for value inside
/// `assert_*_agree`. This spells out why: the bag is the only route from a claim
/// to a policy, so a claim the preset fails to exclude is a visible change even
/// when every typed field matches.
#[test]
fn the_claims_bag_comparison_is_exhaustive() {
    let preset = standard_preset();
    let entry = corpus()
        .into_iter()
        .find(|entry| entry.name == "subject-keycloak-access-token")
        .expect("the Keycloak entry carries the widest claims bag in the corpus");

    let from_preset = preset
        .map_subject(&entry.claims)
        .expect("the Keycloak token resolves");
    let from_rust = StandardClaimMap
        .map_subject(&entry.claims)
        .expect("the Keycloak token resolves");

    assert_eq!(
        from_preset.claims.keys().collect::<HashSet<_>>(),
        from_rust.claims.keys().collect::<HashSet<_>>(),
        "same key set"
    );
    for (name, value) in &from_rust.claims {
        assert_eq!(from_preset.claims.get(name), Some(value), "claim `{name}`");
    }
    assert!(
        from_preset.claims.contains_key("realm_access"),
        "a nested claim no single-segment path consumed stays visible"
    );
}
