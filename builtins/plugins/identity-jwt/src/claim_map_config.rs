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

use std::collections::{BTreeMap, BTreeSet, HashSet};

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
///
/// `trust_domain` is deliberately absent. It is the SPIFFE URI's authority, so it
/// is derived from the identity rather than read from a claim: a mapped value
/// that disagreed would let a policy read one workload's trust boundary off
/// another's identity, and one that agreed would be decoration.
pub const WORKLOAD_FIELDS: &[&str] = &["client_id", "selectors", "spiffe_id"];

/// Fields whose destination holds one string, so the first candidate resolving
/// to a string wins and `merge: union` is meaningless.
const SCALAR_FIELDS: &[&str] = &["client_id", "client_name", "id", "spiffe_id"];

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
#[non_exhaustive]
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

/// One authored candidate: a path, plus the rules for what satisfies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    /// The path as authored.
    pub(crate) path: String,
    /// Require an array. A string is then unusable and the chain continues.
    pub(crate) array_only: bool,
    /// Require a string. An array is then unusable and the chain continues.
    ///
    /// The mirror of `array_only`, and what a claim read as a delimited string
    /// needs: an array-valued `scope` must contribute nothing rather than
    /// contributing each element.
    pub(crate) string_only: bool,
    /// End the chain as soon as this path resolves to anything, usable or not.
    ///
    /// The default is to keep looking when a value is present but the wrong
    /// shape. A chain that picks the first claim that *exists* and then requires
    /// a shape of it needs this instead, so a present-but-unusable value denies
    /// rather than falling through to a later candidate.
    pub(crate) stop_if_present: bool,
}

/// One authored field: its ordered candidates and its options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldMap {
    /// Candidates in the order the author wrote them.
    pub(crate) paths: Vec<Candidate>,
    /// How resolving candidates combine.
    pub(crate) merge: MergeMode,
    /// How a resolved string is broken into elements.
    pub(crate) split: Option<SplitMode>,
    /// What happens when no candidate resolves.
    pub(crate) on_missing: OnMissing,
}

const FIELD_OPTIONS: &[&str] = &["merge", "on_missing", "paths", "split"];
const CANDIDATE_KEYS: &[&str] = &["array_only", "path", "stop_if_present", "string_only"];

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
                string_only: false,
                stop_if_present: false,
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
                let flag = |name: &str| -> Result<bool, String> {
                    match entries.get(name) {
                        Some(value) => option_from_value(field, name, value),
                        None => Ok(false),
                    }
                };
                let array_only = flag("array_only")?;
                let string_only = flag("string_only")?;
                if array_only && string_only {
                    return Err(format!(
                        "{field}: '{path}' declares both `array_only` and `string_only`, so \
                         nothing can satisfy it"
                    ));
                }
                Ok(Self {
                    path,
                    array_only,
                    string_only,
                    stop_if_present: flag("stop_if_present")?,
                })
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
    pub(crate) fn from_value(field: &str, value: &Value) -> Result<Self, String> {
        match value {
            Value::String(path) => Ok(Self {
                paths: vec![Candidate {
                    path: path.clone(),
                    array_only: false,
                    string_only: false,
                    stop_if_present: false,
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
                        string_only: false,
                        stop_if_present: false,
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
///
/// A plugin-level setting rather than part of [`ClaimMapConfig`], so it applies
/// to a preset named by `claim_mapper` and to an inline `claim_map` alike. The
/// bag is a separate output from the typed fields, and pinning the overrides to
/// one of the two ways of choosing a map would leave the other unable to reach
/// them.
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

impl ClaimsOverrides {
    /// Parse every name, and check the two lists do not disagree with each
    /// other.
    ///
    /// # Errors
    ///
    /// Returns a message naming every entry that does not address one
    /// top-level claim, or every claim that appears in both lists. A claim in
    /// both has no coherent intent to honour, and picking a winner silently
    /// would hide the mistake. Bad names across both lists at once, so fixing
    /// one does not uncover the next on the following startup. The overlap
    /// check waits for the names to parse, since an entry that is not a claim
    /// name cannot conflict with one.
    pub fn compile(&self) -> Result<CompiledClaimsOverrides, String> {
        let (exclude, mut problems) = compile_claim_names("exclude", &self.exclude);
        let (include, include_problems) = compile_claim_names("include", &self.include);
        problems.extend(include_problems);
        if !problems.is_empty() {
            return Err(problems.join("; "));
        }

        let both: BTreeSet<&str> = include.intersection(&exclude).map(String::as_str).collect();
        if both.is_empty() {
            return Ok(CompiledClaimsOverrides { exclude, include });
        }
        let named: Vec<String> = both.iter().map(|claim| format!("`{claim}`")).collect();
        Err(format!(
            "claims: {} in both `exclude` and `include`; pick one list for each",
            named.join(", ")
        ))
    }
}

/// Parse the names in one override list, returning the ones that address a
/// single top-level claim and a message for each entry that does not.
///
/// The bag is keyed by claim name, so a dotted entry such as
/// `realm_access.roles` would match nothing. Every other path-shaped field in
/// this config takes dotted syntax, which makes writing one here a plausible
/// mistake rather than a contrived one, so it fails at load instead. A claim
/// whose name really holds a dot is written `\.`, the escape a path already
/// uses.
///
/// Every bad entry is reported rather than the first, so an operator fixing a
/// list sees all of it. The nested ones share one message, since they share one
/// remedy; a malformed escape carries the parser's own reason.
fn compile_claim_names(list: &str, names: &[String]) -> (HashSet<String>, Vec<String>) {
    let mut parsed = HashSet::new();
    let mut problems = Vec::new();
    let mut nested = Vec::new();

    for name in names {
        match ClaimPath::parse(name) {
            Err(e) => problems.push(format!("claims.{list}: {e}")),
            Ok(path) => match path.single_segment() {
                Some(segment) => {
                    parsed.insert(segment.to_owned());
                },
                None => nested.push(format!("`{name}`")),
            },
        }
    }

    if !nested.is_empty() {
        let addresses = if nested.len() == 1 {
            "addresses a nested claim"
        } else {
            "address nested claims"
        };
        problems.push(format!(
            "claims.{list}: {} {addresses}, and the claims bag is keyed by top-level claim \
             name; name the top-level claim, or write a literal dot as `\\.`",
            nested.join(", ")
        ));
    }

    (parsed, problems)
}

/// The overrides with every name parsed: single top-level claim names,
/// unescaped, ready to match a key in the bag.
#[derive(Debug, Clone, Default)]
pub struct CompiledClaimsOverrides {
    exclude: HashSet<String>,
    include: HashSet<String>,
}

impl CompiledClaimsOverrides {
    /// Claims to drop even though nothing consumed them.
    pub fn exclude(&self) -> impl Iterator<Item = &str> {
        self.exclude.iter().map(String::as_str)
    }

    /// Claims to keep even though a path consumed them, or because the inferred
    /// exclusions always drop them.
    pub fn include(&self) -> impl Iterator<Item = &str> {
        self.include.iter().map(String::as_str)
    }

    /// Whether the operator asked for neither.
    pub fn is_empty(&self) -> bool {
        self.exclude.is_empty() && self.include.is_empty()
    }
}

/// One role's authored section: field name to field map.
///
/// Field names are checked against the role's own set during compilation, which
/// is where the role is known and can be named in the error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleMapConfig(pub BTreeMap<String, Value>);

/// The claim map an operator writes under `claim_map:`.
///
/// One section per role, and a resolver uses the section matching its own
/// `role:`. A field is written in one of three forms:
///
/// ```yaml
/// claim_map:
///   subject:
///     id: sub                          # a path
///     teams: [teams, groups]           # ordered candidates, first match wins
///     roles:                           # candidates plus options
///       paths:
///         - realm_access.roles
///         - resource_access.my-api.roles
///       merge: union                   # first_match (default) | union
///     permissions:
///       paths:
///         - { path: permissions, array_only: true }
///         - scope
///       split: whitespace              # break a delimited string into elements
///       on_missing: deny               # ignore (default) | deny
/// ```
///
/// The claims-bag overrides are a sibling of `claim_map`, not part of it, so they
/// work with a preset too:
///
/// ```yaml
/// claim_mapper: keycloak
/// claims:
///   exclude: [internal_debug]          # drop an otherwise-visible claim
///   include: [iss]                     # keep one the inference drops
/// ```
///
/// A field with no candidate that resolves is left empty and logged at debug,
/// naming every path tried. `on_missing: deny` makes that a refusal instead.
///
/// Three per-candidate flags control what satisfies a candidate and when the
/// chain stops:
///
/// | Flag | Effect |
/// |---|---|
/// | `array_only` | Only an array satisfies it; a string is skipped and the next candidate is tried. |
/// | `string_only` | Only a string satisfies it; an array is skipped. What a claim read as a delimited value needs, so an array-valued `scope` contributes nothing rather than contributing each element. |
/// | `stop_if_present` | The candidate claims the field the moment its path resolves at all, so a present but unusable value leaves the field empty instead of falling through. What a chain that picks the first claim that *exists* and only then requires a string of it needs. Valid only on a field holding one value. |
///
/// `array_only` and `string_only` together are rejected: nothing could satisfy
/// such a candidate. Both are also rejected on a field that holds one value,
/// which already requires a string, and `stop_if_present` is rejected on a field
/// that holds a collection. Each flag is valid exactly where it can mean
/// something.
///
/// # Escaping, and the quoting trap
///
/// `.` separates path segments and `\` escapes; every other character, `:` and
/// `/` included, is a literal. So `cognito:groups` is one segment written
/// plainly, and a claim whose whole name is a URL needs its dots escaped and
/// nothing else.
///
/// The plugin receives JSON, so how many backslashes to type depends on the YAML
/// scalar style. Both of these authorize the same path:
///
/// ```yaml
/// # double-quoted: YAML consumes one backslash, so double them
/// roles: "https://my-app\\.example\\.com/roles"
///
/// # plain or single-quoted: YAML passes the backslash through
/// roles: https://my-app\.example\.com/roles
/// roles: 'https://my-app\.example\.com/roles'
/// ```
///
/// Escaping the colon is the common mistake, and it is rejected rather than
/// accepted: a colon is already a literal, so `\:` is not an escape.
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
}

// =====================================================================
// Compiled form
// =====================================================================

/// A candidate with its path parsed.
#[derive(Debug, Clone)]
pub struct CompiledCandidate {
    path: ClaimPath,
    array_only: bool,
    string_only: bool,
    stop_if_present: bool,
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

    /// Whether only a string satisfies this candidate.
    pub fn string_only(&self) -> bool {
        self.string_only
    }

    /// Whether a present but unusable value ends the chain here.
    pub fn stop_if_present(&self) -> bool {
        self.stop_if_present
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
    claims: CompiledClaimsOverrides,
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
    pub fn claims(&self) -> &CompiledClaimsOverrides {
        &self.claims
    }

    /// Attach the plugin-level claims-bag overrides.
    ///
    /// Applied after the map compiles, so a preset and an inline map reach them
    /// the same way.
    #[must_use]
    pub fn with_claims(mut self, claims: CompiledClaimsOverrides) -> Self {
        self.claims = claims;
        self
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
        Ok(CompiledClaimMap {
            subject: compile_role("subject", SUBJECT_FIELDS, self.subject.as_ref())?,
            client: compile_role("client", CLIENT_FIELDS, self.client.as_ref())?,
            workload: compile_role("workload", WORKLOAD_FIELDS, self.workload.as_ref())?,
            claims: CompiledClaimsOverrides::default(),
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
        // A field holding one value takes the first candidate resolving to a
        // string, so the three collection options cannot mean anything on it.
        // Rejecting beats ignoring: an ignored `array_only` would make the field
        // resolve never, surfacing as a runtime denial instead of a load error.
        if SCALAR_FIELDS.contains(interned) {
            if authored_field.merge == MergeMode::Union {
                return Err(format!(
                    "{qualified}: `merge: union` needs a field that holds a collection, and \
                     {qualified} holds one value"
                ));
            }
            if authored_field.split.is_some() {
                return Err(format!(
                    "{qualified}: `split` needs a field that holds a collection, and {qualified} \
                     holds one value"
                ));
            }
            // The shape flags say nothing a field holding one value does not
            // already say: it requires a string, so `array_only` would let nothing
            // resolve. `stop_if_present` is a chain rule rather than a shape rule
            // and stays valid here, which is what the standard preset's client
            // anchor needs to reproduce the Rust mapper.
            if let Some((flag, candidate)) = authored_field.paths.iter().find_map(|candidate| {
                if candidate.array_only {
                    Some(("array_only", candidate))
                } else if candidate.string_only {
                    Some(("string_only", candidate))
                } else {
                    None
                }
            }) {
                return Err(format!(
                    "{qualified}: `{flag}` on '{}' says nothing a field holding one value does \
                     not already say",
                    candidate.path
                ));
            }
        }

        // `stop_if_present` decides which whole claim wins a chain, which only a
        // field holding one value has. On a collection it would truncate a union
        // mid-chain and drop the candidates behind it, so it is rejected there
        // rather than given a meaning nobody asked for.
        if !SCALAR_FIELDS.contains(interned)
            && let Some(candidate) = authored_field
                .paths
                .iter()
                .find(|candidate| candidate.stop_if_present)
        {
            return Err(format!(
                "{qualified}: `stop_if_present` on '{}' needs a field that holds one value, and \
                 {qualified} holds a collection",
                candidate.path
            ));
        }

        let mut candidates = Vec::with_capacity(authored_field.paths.len());
        for candidate in &authored_field.paths {
            let path = ClaimPath::parse(&candidate.path)
                .map_err(|reason| format!("{qualified}: {reason}"))?;
            candidates.push(CompiledCandidate {
                path,
                array_only: candidate.array_only,
                string_only: candidate.string_only,
                stop_if_present: candidate.stop_if_present,
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
    fn claims_overrides_deserialize_and_default_to_empty() {
        let with: ClaimsOverrides =
            serde_json::from_value(json!({"exclude": ["internal_debug"], "include": ["iss"]}))
                .expect("the overrides deserialize");
        assert_eq!(with.exclude, vec!["internal_debug"]);
        assert_eq!(with.include, vec!["iss"]);
        with.compile().expect("distinct lists are coherent");

        let without = ClaimsOverrides::default();
        assert!(without.exclude.is_empty());
        assert!(without.include.is_empty());
        without.compile().expect("empty lists are coherent");
    }

    #[test]
    fn a_claim_in_both_exclude_and_include_is_rejected_and_named() {
        let overrides: ClaimsOverrides =
            serde_json::from_value(json!({"exclude": ["tenant"], "include": ["tenant"]}))
                .expect("the overrides deserialize");
        let err = overrides
            .compile()
            .expect_err("a claim cannot be both dropped and kept");
        assert!(err.contains("tenant"), "{err}");
        assert!(err.contains("exclude") && err.contains("include"), "{err}");
    }

    /// Every overlap in one message: an operator fixing them one startup at a
    /// time is a round-trip per mistake.
    #[test]
    fn every_claim_in_both_lists_is_named_at_once() {
        let overrides: ClaimsOverrides = serde_json::from_value(json!({
            "exclude": ["tenant", "jti", "region"],
            "include": ["region", "iss", "tenant"],
        }))
        .expect("the overrides deserialize");
        let err = overrides
            .compile()
            .expect_err("two claims are both dropped and kept");
        assert!(err.contains("tenant"), "{err}");
        assert!(err.contains("region"), "{err}");
        assert!(
            !err.contains("jti") && !err.contains("iss"),
            "a claim in one list only is not a conflict: {err}"
        );
    }

    /// A name repeated within `include` is one conflict, not two.
    #[test]
    fn a_repeated_claim_is_named_once() {
        let overrides: ClaimsOverrides = serde_json::from_value(json!({
            "exclude": ["tenant"],
            "include": ["tenant", "tenant"],
        }))
        .expect("the overrides deserialize");
        let err = overrides.compile().expect_err("tenant conflicts");
        assert_eq!(err.matches("tenant").count(), 1, "{err}");
    }

    /// The bag is keyed by claim name, so a dotted entry would match nothing. It
    /// is a plausible mistake, since every other path-shaped field here takes
    /// dotted syntax, so it fails at load rather than quietly doing nothing.
    #[test]
    fn a_dotted_override_entry_is_rejected_and_named() {
        for list in ["exclude", "include"] {
            let overrides: ClaimsOverrides =
                serde_json::from_value(json!({list: ["realm_access.roles"]}))
                    .expect("the overrides deserialize");
            let err = overrides
                .compile()
                .expect_err("a nested path is not a claim name");
            assert!(err.contains("realm_access.roles"), "{err}");
            assert!(err.contains(list), "the message names the list: {err}");
        }
    }

    /// The doc promises every bad name at once. Two dotted entries in different
    /// lists, so a fix to one does not uncover the other on the next startup.
    #[test]
    fn every_bad_override_entry_is_named_at_once() {
        let overrides: ClaimsOverrides = serde_json::from_value(json!({
            "exclude": ["realm_access.roles", "tenant"],
            "include": ["resource_access.api", "tenant\\x"],
        }))
        .expect("the overrides deserialize");

        let err = overrides.compile().expect_err("three entries are unusable");
        assert!(err.contains("realm_access.roles"), "{err}");
        assert!(err.contains("resource_access.api"), "{err}");
        assert!(
            err.contains("tenant\\x"),
            "the malformed escape is named too: {err}"
        );
    }

    /// A claim name that really holds dots, an Auth0 namespaced claim being the
    /// usual one, stays reachable through the same escape a path uses.
    #[test]
    fn an_escaped_dot_names_a_claim_whose_name_holds_one() {
        let overrides: ClaimsOverrides = serde_json::from_value(json!({
            "exclude": ["https://my-app\\.example\\.com/roles"],
        }))
        .expect("the overrides deserialize");
        let compiled = overrides.compile().expect("an escaped dot is a claim name");
        assert_eq!(
            compiled.exclude().collect::<Vec<_>>(),
            vec!["https://my-app.example.com/roles"],
            "the name is stored unescaped, which is how it reaches the bag"
        );
    }

    /// A malformed escape is the operator's typo, not a claim name, so it says so
    /// rather than dropping a claim nothing is named after.
    #[test]
    fn a_malformed_escape_in_an_override_entry_is_rejected() {
        let overrides: ClaimsOverrides = serde_json::from_value(json!({"include": ["tenant\\x"]}))
            .expect("the overrides deserialize");
        let err = overrides.compile().expect_err("`\\x` is not an escape");
        assert!(err.contains("include"), "{err}");
    }

    /// The overrides are a plugin-level setting, so a `claims` block written inside
    /// a map is rejected and the valid sections are listed.
    #[test]
    fn a_claims_block_inside_a_map_is_rejected() {
        let err = serde_json::from_value::<ClaimMapConfig>(json!({
            "subject": {"id": "sub"},
            "claims": {"include": ["iss"]},
        }))
        .expect_err("`claims` is not part of a claim map");
        let message = err.to_string();
        assert!(message.contains("claims"), "{message}");
        assert!(
            message.contains("subject"),
            "the valid sections are listed: {message}"
        );
    }

    /// A malformed override names the field rather than dumping a serde type
    /// error, which is why the resolver reads it as a raw value first.
    #[test]
    fn a_malformed_claims_block_is_rejected() {
        for value in [
            json!({"exclude": "iss"}),
            json!({"include": 42}),
            json!({"excludes": ["iss"]}),
            json!(["iss"]),
        ] {
            serde_json::from_value::<ClaimsOverrides>(value.clone())
                .expect_err(&format!("{value} must be rejected"));
        }
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

    /// `split` and `array_only` are as meaningless on a field holding one value
    /// as `union` is. Ignoring `array_only` would be worse than rejecting it: it
    /// would let nothing resolve, turning a config mistake into a runtime denial.
    #[test]
    fn split_and_the_shape_flags_on_a_field_holding_one_value_are_rejected() {
        let split = compile_err(json!({
            "subject": {"id": {"paths": ["sub"], "split": "whitespace"}}
        }));
        assert!(
            split.contains("subject.id") && split.contains("split"),
            "{split}"
        );

        for flag in ["array_only", "string_only"] {
            let err = compile_err(json!({
                "subject": {"id": [{"path": "sub", flag: true}]}
            }));
            assert!(err.contains("subject.id"), "{flag}: {err}");
            assert!(err.contains(flag), "{flag}: {err}");
            assert!(err.contains("sub"), "the candidate is named: {err}");
        }
    }

    /// `stop_if_present` is a chain rule, not a shape rule, so a field holding one
    /// value accepts it. The standard preset's client anchor depends on that: it is
    /// how the first anchor key that exists claims the field.
    #[test]
    fn stop_if_present_is_accepted_on_a_field_holding_one_value() {
        let map = compiled(json!({
            "client": {"client_id": [{"path": "client_id", "stop_if_present": true}, "azp"]}
        }));
        let candidates = map
            .role(&TokenRole::Client)
            .unwrap()
            .field("client_id")
            .unwrap()
            .candidates();
        assert!(
            candidates
                .first()
                .is_some_and(CompiledCandidate::stop_if_present),
            "the flag must survive compilation on a scalar field"
        );
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
    fn the_candidate_flags_round_trip_and_default_to_unset() {
        // Shape flags belong to a collection field, the chain flag to a field
        // holding one value, so each is exercised where it is valid.
        let map = compiled(json!({
            "subject": {
                "permissions": {
                    "paths": [
                        {"path": "permissions", "array_only": true},
                        {"path": "scope", "string_only": true},
                        "plain",
                    ],
                    "split": "whitespace",
                }
            },
            "client": {
                "client_id": [{"path": "client_id", "stop_if_present": true}, "azp"],
            },
        }));

        let shapes: Vec<(bool, bool)> = map
            .role(&TokenRole::User)
            .unwrap()
            .field("permissions")
            .unwrap()
            .candidates()
            .iter()
            .map(|c| (c.array_only(), c.string_only()))
            .collect();
        assert_eq!(shapes, vec![(true, false), (false, true), (false, false)]);

        let chain: Vec<bool> = map
            .role(&TokenRole::Client)
            .unwrap()
            .field("client_id")
            .unwrap()
            .candidates()
            .iter()
            .map(CompiledCandidate::stop_if_present)
            .collect();
        assert_eq!(chain, vec![true, false]);
    }

    /// Nothing can be both an array and a string, so a candidate declaring both
    /// could never resolve. That is a config mistake, not a way to disable a
    /// candidate.
    #[test]
    fn a_candidate_declaring_both_shape_flags_is_rejected() {
        let err = compile_err(json!({
            "subject": {"roles": [{"path": "roles", "array_only": true, "string_only": true}]}
        }));
        assert!(
            err.contains("array_only") && err.contains("string_only"),
            "{err}"
        );
        assert!(err.contains("roles"), "{err}");
    }

    #[test]
    fn an_unknown_candidate_key_is_rejected() {
        let err = compile_err(json!({
            "subject": {"roles": [{"path": "roles", "arrayonly": true}]}
        }));
        assert!(err.contains("arrayonly"), "{err}");
    }

    /// The remaining shape-rejection branches. Each names the field rather than
    /// dumping a serde type error, which is the whole reason the field forms are
    /// read from the JSON value by hand.
    #[test]
    fn every_malformed_candidate_shape_names_the_field() {
        for (label, value) in [
            (
                "a non-string path",
                json!({"subject": {"roles": [{"path": 42}]}}),
            ),
            (
                "a numeric candidate",
                json!({"subject": {"roles": ["ok", 42]}}),
            ),
            ("a boolean candidate", json!({"subject": {"roles": [true]}})),
            ("a null candidate", json!({"subject": {"roles": [null]}})),
            (
                "a numeric paths value",
                json!({"subject": {"roles": {"paths": 42}}}),
            ),
            (
                "an object paths value",
                json!({"subject": {"roles": {"paths": {"path": "roles"}}}}),
            ),
        ] {
            let err = compile_err(value);
            assert!(err.contains("subject.roles"), "{label}: {err}");
            assert!(
                !err.contains("did not match any variant"),
                "{label}: must not be a serde variant dump: {err}"
            );
        }
    }

    /// Every field name the mapper resolves as a single value is in
    /// `SCALAR_FIELDS`, and nothing else is. Without this, adding a scalar field
    /// to one list and not the other lets `merge: union` and the shape flags
    /// compile with no effect.
    #[test]
    fn scalar_fields_is_exactly_what_the_mapper_resolves_as_one_value() {
        // The mapper's scalar call sites, per role. Kept here rather than derived
        // so a change to either side has to be made deliberately in both.
        const RESOLVED_AS_ONE_VALUE: &[&str] = &["id", "client_id", "client_name", "spiffe_id"];

        for name in RESOLVED_AS_ONE_VALUE {
            assert!(
                SCALAR_FIELDS.contains(name),
                "the mapper resolves `{name}` as one value, so it must be in SCALAR_FIELDS"
            );
        }
        for name in SCALAR_FIELDS {
            assert!(
                RESOLVED_AS_ONE_VALUE.contains(name),
                "`{name}` is in SCALAR_FIELDS but the mapper does not resolve it as one value"
            );
        }
        // And every scalar name is a real field of some role, so a typo in either
        // list fails here rather than silently never matching.
        for name in SCALAR_FIELDS {
            assert!(
                SUBJECT_FIELDS.contains(name)
                    || CLIENT_FIELDS.contains(name)
                    || WORKLOAD_FIELDS.contains(name),
                "`{name}` is in SCALAR_FIELDS but is not a field of any role"
            );
        }
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
