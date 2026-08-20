// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The claim map an operator authors, and its compilation into the form the
// mapper runs. Every path is parsed here, once, so nothing parses a path on the
// request path and a malformed map fails at plugin construction.
//
// Field shapes are read out of `serde_json::Value` rather than through derived
// deserializers. An untagged enum over the three authored forms collapses every
// mistake into "data did not match any variant", and the whole point of failing
// at construction is telling the operator which field and which path.

use std::collections::BTreeMap;

use praxis_policy_core::extensions::raw_credentials::TokenRole;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claim_path::ClaimPath;

/// Fields a `subject` section may map.
pub const SUBJECT_FIELDS: &[&str] = &["id", "permissions", "roles", "teams"];

/// Fields a `client` section may map.
///
/// `permissions` and `teams` are mappable although no researched provider mints
/// a source for either. They exist on the client identity and no path reaches
/// them otherwise.
pub const CLIENT_FIELDS: &[&str] = &[
    "authorized_audiences",
    "authorized_scopes",
    "client_id",
    "client_name",
    "permissions",
    "roles",
    "teams",
];

/// Fields a `workload` section may map.
pub const WORKLOAD_FIELDS: &[&str] = &["client_id", "selectors", "spiffe_id", "trust_domain"];

/// Fields whose destination holds one string, so the first candidate resolving
/// to a string wins and `merge: union` is meaningless.
const SCALAR_FIELDS: &[&str] = &[
    "client_id",
    "client_name",
    "id",
    "spiffe_id",
    "trust_domain",
];

/// How a field combines its resolving candidates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeMode {
    /// Stop at the first candidate that resolves.
    #[default]
    FirstMatch,
    /// Every candidate that resolves contributes.
    Union,
}

/// How a resolved string is broken into elements.
///
/// An enum rather than a bare bool so a delimiter form can be added later
/// without invalidating a config anyone has already written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitMode {
    /// Split on runs of whitespace, which is how all three researched providers
    /// delimit `scope`.
    Whitespace,
}

/// What happens when no candidate resolves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMissing {
    /// Leave the field empty and emit a diagnostic.
    #[default]
    Ignore,
    /// Decline the mapping, which the resolver turns into a denial.
    Deny,
}

/// One authored candidate: a path, plus whether only an array satisfies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The path as authored.
    pub path: String,
    /// Require an array. A string is then unusable and the chain continues.
    pub array_only: bool,
}

/// One authored field: its ordered candidates and its options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMap {
    /// Candidates in the order the author wrote them.
    pub paths: Vec<Candidate>,
    /// How resolving candidates combine.
    pub merge: MergeMode,
    /// How a resolved string is broken into elements.
    pub split: Option<SplitMode>,
    /// What happens when no candidate resolves.
    pub on_missing: OnMissing,
}

const FIELD_OPTIONS: &[&str] = &["merge", "on_missing", "paths", "split"];
const CANDIDATE_KEYS: &[&str] = &["array_only", "path"];

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

fn option_from_value<T: for<'de> Deserialize<'de>>(
    field: &str,
    option: &str,
    value: &Value,
) -> Result<T, String> {
    serde_json::from_value(value.clone())
        .map_err(|e| format!("{field}: `{option}` is not valid: {e}"))
}

impl Candidate {
    fn from_value(field: &str, value: &Value) -> Result<Self, String> {
        match value {
            Value::String(path) => Ok(Self {
                path: path.clone(),
                array_only: false,
            }),
            Value::Object(entries) => {
                for key in entries.keys() {
                    if !CANDIDATE_KEYS.contains(&key.as_str()) {
                        return Err(format!(
                            "{field}: unknown candidate key `{key}`; a candidate takes {}",
                            CANDIDATE_KEYS.join(", ")
                        ));
                    }
                }
                let path = match entries.get("path") {
                    Some(Value::String(path)) => path.clone(),
                    Some(other) => {
                        return Err(format!(
                            "{field}: a candidate's `path` must be a string, got {}",
                            kind_of(other)
                        ));
                    },
                    None => return Err(format!("{field}: a candidate object needs a `path`")),
                };
                let array_only = match entries.get("array_only") {
                    Some(value) => option_from_value(field, "array_only", value)?,
                    None => false,
                };
                Ok(Self { path, array_only })
            },
            other => Err(format!(
                "{field}: a candidate is a path or an object with `path`, got {}",
                kind_of(other)
            )),
        }
    }
}

impl FieldMap {
    /// Read a field's authored form: a single path, an ordered list of
    /// candidates, or an object carrying `paths` plus options.
    ///
    /// `field` is the qualified name (`subject.roles`) and appears in every
    /// error, since the value alone does not say which field it was written for.
    ///
    /// # Errors
    ///
    /// Returns a message naming the field when the value is not one of the three
    /// forms, when an option or candidate key is unrecognized, or when `paths`
    /// is missing.
    pub fn from_value(field: &str, value: &Value) -> Result<Self, String> {
        match value {
            Value::String(path) => Ok(Self {
                paths: vec![Candidate {
                    path: path.clone(),
                    array_only: false,
                }],
                merge: MergeMode::default(),
                split: None,
                on_missing: OnMissing::default(),
            }),
            Value::Array(items) => Ok(Self {
                paths: candidates_from_list(field, items)?,
                merge: MergeMode::default(),
                split: None,
                on_missing: OnMissing::default(),
            }),
            Value::Object(entries) => {
                for key in entries.keys() {
                    if !FIELD_OPTIONS.contains(&key.as_str()) {
                        return Err(format!(
                            "{field}: unknown option `{key}`; a field takes {}",
                            FIELD_OPTIONS.join(", ")
                        ));
                    }
                }
                let paths = match entries.get("paths") {
                    Some(Value::Array(items)) => candidates_from_list(field, items)?,
                    Some(Value::String(path)) => vec![Candidate {
                        path: path.clone(),
                        array_only: false,
                    }],
                    Some(other) => {
                        return Err(format!(
                            "{field}: `paths` is a path or a list of candidates, got {}",
                            kind_of(other)
                        ));
                    },
                    None => {
                        return Err(format!(
                            "{field}: the expanded form needs `paths`; write the field as a path \
                             or a list of paths if it has no options"
                        ));
                    },
                };
                Ok(Self {
                    paths,
                    merge: match entries.get("merge") {
                        Some(value) => option_from_value(field, "merge", value)?,
                        None => MergeMode::default(),
                    },
                    split: match entries.get("split") {
                        Some(value) => Some(option_from_value(field, "split", value)?),
                        None => None,
                    },
                    on_missing: match entries.get("on_missing") {
                        Some(value) => option_from_value(field, "on_missing", value)?,
                        None => OnMissing::default(),
                    },
                })
            },
            other => Err(format!(
                "{field}: a field maps to a path, a list of paths, or an object with `paths`, got \
                 {}",
                kind_of(other)
            )),
        }
    }
}

fn candidates_from_list(field: &str, items: &[Value]) -> Result<Vec<Candidate>, String> {
    items
        .iter()
        .map(|item| Candidate::from_value(field, item))
        .collect()
}

/// Claim names to drop from, or restore to, the policy-visible claims bag.
///
/// Plain names rather than paths: the bag is keyed by top-level claim name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsOverrides {
    /// Claims to drop even though nothing consumed them.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Claims to keep even though a path consumed them, or because they are
    /// registered JWT claims the inference always drops. `iss` is the reason
    /// this exists: it is otherwise unreachable from a policy.
    #[serde(default)]
    pub include: Vec<String>,
}

/// One role's authored section: field name to field map.
///
/// Field names are checked against the role's own set during compilation, which
/// is where the role is known and can be named in the error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleMapConfig(pub BTreeMap<String, Value>);

/// The claim map an operator writes under `claim_map:`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimMapConfig {
    /// The section a `role: user` resolver uses.
    #[serde(default)]
    pub subject: Option<RoleMapConfig>,
    /// The section a `role: client` resolver uses.
    #[serde(default)]
    pub client: Option<RoleMapConfig>,
    /// The section a `role: caller_workload` resolver uses.
    #[serde(default)]
    pub workload: Option<RoleMapConfig>,
    /// Overrides for the inferred claims-bag exclusions.
    #[serde(default)]
    pub claims: Option<ClaimsOverrides>,
}

// =====================================================================
// Compiled form
// =====================================================================

/// A candidate with its path parsed.
#[derive(Debug, Clone)]
pub struct CompiledCandidate {
    path: ClaimPath,
    array_only: bool,
}

impl CompiledCandidate {
    /// The parsed path.
    pub fn path(&self) -> &ClaimPath {
        &self.path
    }

    /// Whether only an array satisfies this candidate.
    pub fn array_only(&self) -> bool {
        self.array_only
    }
}

/// A field with every candidate path parsed.
#[derive(Debug, Clone)]
pub struct CompiledField {
    candidates: Vec<CompiledCandidate>,
    merge: MergeMode,
    split: Option<SplitMode>,
    on_missing: OnMissing,
}

impl CompiledField {
    /// The candidates, in the order the author wrote them.
    pub fn candidates(&self) -> &[CompiledCandidate] {
        &self.candidates
    }

    /// How resolving candidates combine.
    pub fn merge(&self) -> MergeMode {
        self.merge
    }

    /// How a resolved string is broken into elements.
    pub fn split(&self) -> Option<SplitMode> {
        self.split
    }

    /// What happens when no candidate resolves.
    pub fn on_missing(&self) -> OnMissing {
        self.on_missing
    }
}

/// One role's compiled section.
#[derive(Debug, Clone, Default)]
pub struct CompiledRoleMap {
    fields: BTreeMap<&'static str, CompiledField>,
}

impl CompiledRoleMap {
    /// The field's compiled form, or `None` when the section declares no path
    /// for it.
    pub fn field(&self, name: &str) -> Option<&CompiledField> {
        self.fields.get(name)
    }

    /// Every declared field, by name.
    pub fn fields(&self) -> impl Iterator<Item = (&'static str, &CompiledField)> {
        self.fields.iter().map(|(name, field)| (*name, field))
    }
}

/// A claim map with every path parsed and every field name checked.
#[derive(Debug, Clone, Default)]
pub struct CompiledClaimMap {
    subject: Option<CompiledRoleMap>,
    client: Option<CompiledRoleMap>,
    workload: Option<CompiledRoleMap>,
    claims: ClaimsOverrides,
}

impl CompiledClaimMap {
    /// The section matching a resolver's configured role.
    ///
    /// # Errors
    ///
    /// Returns a message naming the role when the map declares no section for
    /// it, so a misconfigured pairing fails at load rather than denying every
    /// request.
    pub fn role(&self, role: &TokenRole) -> Result<&CompiledRoleMap, String> {
        let (name, section) = match role {
            TokenRole::User => ("subject", self.subject.as_ref()),
            TokenRole::Client => ("client", self.client.as_ref()),
            TokenRole::CallerWorkload => ("workload", self.workload.as_ref()),
            other => {
                return Err(format!(
                    "no claim-map section can serve role {other:?}; use `user`, `client` or \
                     `caller_workload`"
                ));
            },
        };
        section
            .ok_or_else(|| format!("the claim map declares no `{name}` section for `role: {name}`"))
    }

    /// The claims-bag overrides.
    pub fn claims(&self) -> &ClaimsOverrides {
        &self.claims
    }
}

impl ClaimMapConfig {
    /// Parse every path, check every field name, and reject the combinations
    /// that cannot mean anything.
    ///
    /// # Errors
    ///
    /// Returns a message naming the field and, where relevant, the path, for a
    /// malformed path, an unknown field name in a role section, an empty
    /// candidate list, `merge: union` on a field holding one string, and a claim
    /// named in both `exclude` and `include`.
    pub fn compile(&self) -> Result<CompiledClaimMap, String> {
        let claims = self.claims.clone().unwrap_or_default();
        for claim in &claims.include {
            if claims.exclude.iter().any(|excluded| excluded == claim) {
                return Err(format!(
                    "claims: `{claim}` is in both `exclude` and `include`; pick one"
                ));
            }
        }

        Ok(CompiledClaimMap {
            subject: compile_role("subject", SUBJECT_FIELDS, self.subject.as_ref())?,
            client: compile_role("client", CLIENT_FIELDS, self.client.as_ref())?,
            workload: compile_role("workload", WORKLOAD_FIELDS, self.workload.as_ref())?,
            claims,
        })
    }
}

fn compile_role(
    role: &str,
    allowed: &[&'static str],
    section: Option<&RoleMapConfig>,
) -> Result<Option<CompiledRoleMap>, String> {
    let Some(RoleMapConfig(authored)) = section else {
        return Ok(None);
    };

    let mut fields: BTreeMap<&'static str, CompiledField> = BTreeMap::new();
    for (name, value) in authored {
        let interned = allowed
            .iter()
            .find(|candidate| **candidate == name.as_str())
            .ok_or_else(|| {
                format!(
                    "{role}: unknown field `{name}`; a {role} section maps {}",
                    allowed.join(", ")
                )
            })?;
        let qualified = format!("{role}.{name}");
        let authored_field = FieldMap::from_value(&qualified, value)?;

        if authored_field.paths.is_empty() {
            return Err(format!(
                "{qualified}: `paths` is empty, so nothing can resolve"
            ));
        }
        if authored_field.merge == MergeMode::Union && SCALAR_FIELDS.contains(interned) {
            return Err(format!(
                "{qualified}: `merge: union` needs a field that holds a collection, and \
                 {qualified} holds one value"
            ));
        }

        let mut candidates = Vec::with_capacity(authored_field.paths.len());
        for candidate in &authored_field.paths {
            let path = ClaimPath::parse(&candidate.path)
                .map_err(|reason| format!("{qualified}: {reason}"))?;
            candidates.push(CompiledCandidate {
                path,
                array_only: candidate.array_only,
            });
        }

        fields.insert(
            interned,
            CompiledField {
                candidates,
                merge: authored_field.merge,
                split: authored_field.split,
                on_missing: authored_field.on_missing,
            },
        );
    }

    Ok(Some(CompiledRoleMap { fields }))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(value: Value) -> ClaimMapConfig {
        serde_json::from_value(value).expect("the map should deserialize")
    }

    fn compiled(value: Value) -> CompiledClaimMap {
        config(value).compile().expect("the map should compile")
    }

    fn compile_err(value: Value) -> String {
        config(value)
            .compile()
            .expect_err("the map should be rejected")
    }

    fn authored_paths(field: &CompiledField) -> Vec<String> {
        field
            .candidates()
            .iter()
            .map(|candidate| candidate.path().to_string())
            .collect()
    }

    // ---- the three field forms -------------------------------------------

    /// A shorthand path, an ordered list, and the expanded object form all reach
    /// the same compiled shape, and each keeps the order the author wrote.
    #[test]
    fn all_three_field_forms_compile_to_the_authored_candidate_order() {
        let map = compiled(json!({
            "subject": {
                "id": "sub",
                "teams": ["teams", "groups"],
                "roles": {
                    "paths": ["realm_access.roles", "resource_access.my-api.roles"],
                    "merge": "union",
                },
            }
        }));
        let subject = map.role(&TokenRole::User).unwrap();

        assert_eq!(authored_paths(subject.field("id").unwrap()), vec!["sub"]);
        assert_eq!(
            authored_paths(subject.field("teams").unwrap()),
            vec!["teams", "groups"],
        );
        let roles = subject.field("roles").unwrap();
        assert_eq!(
            authored_paths(roles),
            vec!["realm_access.roles", "resource_access.my-api.roles"],
        );
        assert_eq!(roles.merge(), MergeMode::Union);
    }

    #[test]
    fn a_candidate_object_carries_the_array_only_flag() {
        let map = compiled(json!({
            "subject": {
                "permissions": {
                    "paths": [{"path": "permissions", "array_only": true}, "scope"],
                    "split": "whitespace",
                }
            }
        }));
        let permissions = map
            .role(&TokenRole::User)
            .unwrap()
            .field("permissions")
            .unwrap();
        let flags: Vec<bool> = permissions
            .candidates()
            .iter()
            .map(CompiledCandidate::array_only)
            .collect();
        assert_eq!(
            flags,
            vec![true, false],
            "the declared flag survives compilation and a bare path leaves it unset"
        );
        assert_eq!(permissions.split(), Some(SplitMode::Whitespace));
    }

    #[test]
    fn every_option_round_trips_and_omitted_options_take_their_defaults() {
        let declared = compiled(json!({
            "client": {
                "roles": {
                    "paths": ["roles"],
                    "merge": "union",
                    "split": "whitespace",
                    "on_missing": "deny",
                }
            }
        }));
        let field = declared
            .role(&TokenRole::Client)
            .unwrap()
            .field("roles")
            .unwrap();
        assert_eq!(field.merge(), MergeMode::Union);
        assert_eq!(field.split(), Some(SplitMode::Whitespace));
        assert_eq!(field.on_missing(), OnMissing::Deny);

        let bare = compiled(json!({"client": {"roles": "roles"}}));
        let field = bare
            .role(&TokenRole::Client)
            .unwrap()
            .field("roles")
            .unwrap();
        assert_eq!(field.merge(), MergeMode::FirstMatch);
        assert_eq!(field.split(), None);
        assert_eq!(field.on_missing(), OnMissing::Ignore);
    }

    /// The expanded form accepts a bare path for `paths` too, which is the
    /// natural thing to write when a field needs an option but only one source.
    #[test]
    fn the_expanded_form_accepts_a_single_path_for_paths() {
        let map = compiled(json!({
            "subject": {"permissions": {"paths": "scope", "split": "whitespace"}}
        }));
        let field = map
            .role(&TokenRole::User)
            .unwrap()
            .field("permissions")
            .unwrap();
        assert_eq!(authored_paths(field), vec!["scope"]);
        assert_eq!(field.split(), Some(SplitMode::Whitespace));
    }

    // ---- claims overrides -------------------------------------------------

    #[test]
    fn claims_overrides_compile_and_default_to_empty() {
        let with = compiled(json!({
            "subject": {"id": "sub"},
            "claims": {"exclude": ["internal_debug"], "include": ["iss"]},
        }));
        assert_eq!(with.claims().exclude, vec!["internal_debug"]);
        assert_eq!(with.claims().include, vec!["iss"]);

        let without = compiled(json!({"subject": {"id": "sub"}}));
        assert!(without.claims().exclude.is_empty());
        assert!(without.claims().include.is_empty());
    }

    #[test]
    fn a_claim_in_both_exclude_and_include_is_rejected_and_named() {
        let err = compile_err(json!({
            "subject": {"id": "sub"},
            "claims": {"exclude": ["tenant"], "include": ["tenant"]},
        }));
        assert!(err.contains("tenant"), "{err}");
        assert!(err.contains("exclude") && err.contains("include"), "{err}");
    }

    // ---- role sections ----------------------------------------------------

    /// An empty section still declares the role, which is what the role check
    /// asks. The anchor then denies at runtime rather than at load.
    #[test]
    fn a_declared_but_empty_role_section_compiles() {
        let map = compiled(json!({"client": {}}));
        let client = map
            .role(&TokenRole::Client)
            .expect("an empty section still declares the role");
        assert_eq!(client.fields().count(), 0);
    }

    #[test]
    fn asking_for_an_undeclared_role_names_it() {
        let map = compiled(json!({"subject": {"id": "sub"}}));
        let err = map
            .role(&TokenRole::Client)
            .expect_err("a subject-only map cannot serve a client resolver");
        assert!(err.contains("client"), "{err}");
    }

    #[test]
    fn a_custom_role_cannot_be_served() {
        let map = compiled(json!({"subject": {"id": "sub"}}));
        assert!(
            map.role(&TokenRole::Custom("bespoke".to_owned())).is_err(),
            "there is no section for a host-defined role"
        );
    }

    // ---- rejection --------------------------------------------------------

    #[test]
    fn a_malformed_path_names_both_the_field_and_the_path() {
        let err = compile_err(json!({"subject": {"roles": "realm_access..roles"}}));
        assert!(err.contains("subject.roles"), "{err}");
        assert!(err.contains("realm_access..roles"), "{err}");
    }

    #[test]
    fn a_malformed_path_inside_a_candidate_list_is_rejected() {
        let err = compile_err(json!({"subject": {"roles": ["roles", "teams\\"]}}));
        assert!(err.contains("subject.roles"), "{err}");
        assert!(err.contains("teams\\"), "{err}");
    }

    #[test]
    fn an_unknown_field_name_names_the_field_and_the_role() {
        let err = compile_err(json!({"subject": {"rolez": "roles"}}));
        assert!(err.contains("rolez"), "{err}");
        assert!(err.contains("subject"), "{err}");
        assert!(
            err.contains("roles"),
            "the message should list the valid fields: {err}"
        );
    }

    /// A field valid for one role is not valid for another, so the check is per
    /// role rather than a single union.
    #[test]
    fn a_field_belonging_to_another_role_is_rejected() {
        let err = compile_err(json!({"subject": {"spiffe_id": "sub"}}));
        assert!(
            err.contains("spiffe_id") && err.contains("subject"),
            "{err}"
        );
    }

    #[test]
    fn union_on_a_field_holding_one_value_is_rejected() {
        for (role, field) in [
            ("subject", "id"),
            ("client", "client_id"),
            ("workload", "spiffe_id"),
        ] {
            let err = compile_err(json!({
                role: {field: {"paths": ["a", "b"], "merge": "union"}}
            }));
            assert!(
                err.contains(&format!("{role}.{field}")),
                "{role}.{field}: {err}"
            );
        }
    }

    #[test]
    fn an_empty_candidate_list_is_rejected() {
        let err = compile_err(json!({"subject": {"roles": []}}));
        assert!(err.contains("subject.roles"), "{err}");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn the_expanded_form_without_paths_names_paths() {
        let err = compile_err(json!({"subject": {"roles": {}}}));
        assert!(err.contains("subject.roles"), "{err}");
        assert!(err.contains("paths"), "{err}");
    }

    /// The three authored forms are dispatched on the JSON kind, so anything
    /// else is rejected by naming the field and the forms, not by dumping a
    /// serde variant list.
    #[test]
    fn a_field_given_a_number_or_boolean_names_the_field() {
        for value in [json!(42), json!(true), json!(null)] {
            let err = compile_err(json!({"subject": {"roles": value}}));
            assert!(err.contains("subject.roles"), "{err}");
            assert!(
                !err.contains("did not match any variant"),
                "the message must not be a serde variant dump: {err}"
            );
        }
    }

    #[test]
    fn an_unknown_field_option_is_rejected_and_listed() {
        let err = compile_err(json!({
            "subject": {"roles": {"paths": ["roles"], "mergemode": "union"}}
        }));
        assert!(err.contains("mergemode"), "{err}");
        assert!(err.contains("merge"), "{err}");
    }

    #[test]
    fn an_unknown_candidate_key_is_rejected() {
        let err = compile_err(json!({
            "subject": {"roles": [{"path": "roles", "arrayonly": true}]}
        }));
        assert!(err.contains("arrayonly"), "{err}");
    }

    #[test]
    fn a_candidate_object_without_a_path_is_rejected() {
        let err = compile_err(json!({"subject": {"roles": [{"array_only": true}]}}));
        assert!(err.contains("path"), "{err}");
    }

    #[test]
    fn an_unrecognized_option_value_is_rejected() {
        for (option, value) in [
            ("merge", json!("intersection")),
            ("split", json!("comma")),
            ("on_missing", json!("warn")),
        ] {
            let err = compile_err(json!({
                "subject": {"roles": {"paths": ["roles"], option: value}}
            }));
            assert!(err.contains("subject.roles"), "{option}: {err}");
            assert!(err.contains(option), "{option}: {err}");
        }
    }

    /// A misspelled section name is caught by the top level, which lists the
    /// sections a map may declare.
    #[test]
    fn an_unknown_top_level_section_is_rejected() {
        let err = serde_json::from_value::<ClaimMapConfig>(json!({"subjekt": {"id": "sub"}}))
            .expect_err("a misspelled section must not be ignored");
        assert!(err.to_string().contains("subjekt"), "{err}");
    }
}
