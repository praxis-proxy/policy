// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The typed `assertions:` block, and the checks that make a bad one a load
// error rather than a projection that silently does nothing.
//
// Every nested mapping carries a closed key table, enforced here because these
// shapes are only reachable through this deserializer. A misspelled key is the
// failure this is for: `replace_inherted: true` would otherwise load with the
// flag false and quietly stack what its author meant to drop, which is the bug
// the `authentication:` block was bitten by.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};

use super::{Direction, floor, source::SourcePath};
use crate::config::{ConfigScope, Pattern, unknown_keys_in, unknown_keys_message};

/// What a request or response contract asserts and removes.
///
/// Both directions are optional and independent: a level may declare one and
/// leave the other to the levels above it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AssertionsConfig {
    /// The contract applied toward the upstream, on a pre-phase hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<DirectionBlock>,

    /// The contract applied toward the client, on a post-phase hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<DirectionBlock>,
}

/// One direction's contract: what to assert, and what to remove beyond it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DirectionBlock {
    /// The headers this level asserts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderEntry>,

    /// Header names and trailing-glob patterns to remove beyond the names the
    /// entries target, which are removed whether or not this list exists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip: Vec<StripPattern>,

    /// Drop what accumulated from the levels above, for this direction only.
    #[serde(default)]
    pub replace_inherited: bool,
}

/// One asserted header: its name, where its value comes from, and what happens
/// when the source resolves to nothing.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderEntry {
    /// The target header name, as written.
    pub name: String,

    /// The one source, or the named members of a JSON object.
    #[serde(flatten)]
    pub source: AuthoredSource,

    /// What an absent source does.
    #[serde(default)]
    pub on_missing: OnMissing,

    /// How a value that is not a scalar renders into one header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encode: Option<Encoding>,
}

/// An entry's source, as authored. Parsed at resolution rather than here so a
/// bad path is reported with the config level it was written at.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredSource {
    /// One slot path, rendered as this header's whole value.
    From(String),

    /// Named members, rendered as one JSON object. Keys are operator chosen
    /// and ordered, so the rendered object's bytes are stable.
    Members(BTreeMap<String, String>),
}

/// What an entry does when its source resolves to nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMissing {
    /// Emit no header. The default: a slot the request did not carry is the
    /// ordinary case, not a fault.
    #[default]
    Omit,

    /// Deny the request. For a header the upstream's behavior turns on, where
    /// leaving the decision to its default is not the gateway's call.
    Deny,
}

/// How a value that is not a scalar renders into one header value.
///
/// Absent, a scalar renders bare and a structured value renders as compact
/// JSON. A statically collection-valued source must say which it wants, so
/// that a set does not reach an upstream in a shape nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// Compact JSON. A string renders quoted, which is what keeps it
    /// distinguishable from a structured value that spells the same text.
    Json,

    /// A comma-joined list. A scalar renders bare and an empty list renders
    /// as the empty string.
    Csv,
}

/// A header name or trailing-glob pattern a `strip:` entry names.
///
/// Compiled once at load, and lowercased before compiling, because removal
/// matches header names case-insensitively.
#[derive(Debug, Clone)]
pub struct StripPattern {
    /// The pattern as written, for a diagnostic and for the artifact.
    pattern: String,

    /// The compiled matcher, over the lowercased pattern.
    matcher: Pattern,
}

impl StripPattern {
    /// Compile a pattern as written.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let matcher = Pattern::new(pattern.to_lowercase());
        Self { pattern, matcher }
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Whether this pattern removes a header name. The name is lowercased by
    /// the caller so one fold covers a whole map.
    #[must_use]
    pub fn matches_lowercase(&self, lowercase_name: &str) -> bool {
        self.matcher.matches(lowercase_name)
    }
}

impl Serialize for StripPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.pattern)
    }
}

impl<'de> Deserialize<'de> for AssertionsConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let raw = serde_yaml::Value::deserialize(deserializer)?;
        parse_assertions(&raw).map_err(D::Error::custom)
    }
}

/// Parse an `assertions:` block from raw YAML.
///
/// Two-stage rather than derived so each nested mapping is checked against its
/// scope's key table, which is what reports a typo instead of dropping it.
fn parse_assertions(raw: &serde_yaml::Value) -> Result<AssertionsConfig, String> {
    let Some(map) = raw.as_mapping() else {
        return Err(
            "`assertions:` must be a mapping carrying `request:` and/or `response:`".to_owned(),
        );
    };
    let unknown = unknown_keys_in(ConfigScope::Assertions, map, &[]);
    if !unknown.is_empty() {
        return Err(format!(
            "`assertions:` has {}",
            unknown_keys_message(ConfigScope::Assertions, &unknown)
        ));
    }
    let mut parsed = AssertionsConfig::default();
    for direction in [Direction::Request, Direction::Response] {
        let key = serde_yaml::Value::String(direction_key(direction).to_owned());
        let Some(value) = map.get(&key) else { continue };
        if value.is_null() {
            continue;
        }
        let block = parse_direction(value, direction)?;
        match direction {
            Direction::Request => parsed.request = Some(block),
            Direction::Response => parsed.response = Some(block),
        }
    }
    Ok(parsed)
}

/// The YAML key one direction is written under.
const fn direction_key(direction: Direction) -> &'static str {
    match direction {
        Direction::Request => "request",
        Direction::Response => "response",
    }
}

/// Parse one direction's contract.
fn parse_direction(
    raw: &serde_yaml::Value,
    direction: Direction,
) -> Result<DirectionBlock, String> {
    let label = direction.label();
    let Some(map) = raw.as_mapping() else {
        return Err(format!(
            "`{label}` must be a mapping carrying `headers:`, `strip:`, or `replace_inherited:`"
        ));
    };
    // Before either list is read, so a block with both a typo and a bad
    // `headers:` shape is told about the typo.
    let unknown = unknown_keys_in(ConfigScope::AssertionsDirection, map, &[]);
    if !unknown.is_empty() {
        return Err(format!(
            "`{label}` has {}",
            unknown_keys_message(ConfigScope::AssertionsDirection, &unknown)
        ));
    }

    let replace_inherited = match map.get(serde_yaml::Value::String("replace_inherited".to_owned()))
    {
        None | Some(serde_yaml::Value::Null) => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("`{label}.replace_inherited` must be a boolean"))?,
    };

    let mut headers = Vec::new();
    match map.get(serde_yaml::Value::String("headers".to_owned())) {
        None | Some(serde_yaml::Value::Null) => {},
        Some(value) => {
            let items = value
                .as_sequence()
                .ok_or_else(|| format!("`{label}.headers` must be a list of header entries"))?;
            for (index, item) in items.iter().enumerate() {
                headers.push(parse_entry(item, index, label)?);
            }
        },
    }

    let mut strip = Vec::new();
    match map.get(serde_yaml::Value::String("strip".to_owned())) {
        None | Some(serde_yaml::Value::Null) => {},
        Some(value) => {
            let items = value.as_sequence().ok_or_else(|| {
                format!("`{label}.strip` must be a list of header names or glob patterns")
            })?;
            for item in items {
                let pattern = item.as_str().ok_or_else(|| {
                    format!("`{label}.strip` entries must be header names or glob patterns")
                })?;
                if pattern.is_empty() {
                    return Err(format!("`{label}.strip` carries an empty entry"));
                }
                strip.push(StripPattern::new(pattern));
            }
        },
    }

    Ok(DirectionBlock {
        headers,
        strip,
        replace_inherited,
    })
}

/// Parse one `headers:` entry.
fn parse_entry(raw: &serde_yaml::Value, index: usize, label: &str) -> Result<HeaderEntry, String> {
    let Some(map) = raw.as_mapping() else {
        return Err(format!(
            "`{label}.headers[{index}]` must be a mapping carrying `name:` and either `from:` or \
             `members:`"
        ));
    };
    let unknown = unknown_keys_in(ConfigScope::AssertionHeader, map, &[]);
    if !unknown.is_empty() {
        return Err(format!(
            "`{label}.headers[{index}]` has {}",
            unknown_keys_message(ConfigScope::AssertionHeader, &unknown)
        ));
    }

    let name = map
        .get(serde_yaml::Value::String("name".to_owned()))
        .and_then(serde_yaml::Value::as_str)
        .ok_or_else(|| format!("`{label}.headers[{index}]` needs a `name:` naming the header"))?;
    if let Some(defect) = field_name_defect(name) {
        return Err(format!("`{label}.headers[{index}]` name `{name}` {defect}"));
    }

    let from = map.get(serde_yaml::Value::String("from".to_owned()));
    let members = map.get(serde_yaml::Value::String("members".to_owned()));
    let source = match (from, members) {
        (Some(from), None) => AuthoredSource::From(
            from.as_str()
                .ok_or_else(|| format!("`{label}` header `{name}`: `from:` must be a slot path"))?
                .to_owned(),
        ),
        (None, Some(members)) => {
            let map = members.as_mapping().ok_or_else(|| {
                format!(
                    "`{label}` header `{name}`: `members:` must be a mapping of member name to \
                     slot path"
                )
            })?;
            let mut parsed = BTreeMap::new();
            for (key, value) in map {
                let key = key.as_str().ok_or_else(|| {
                    format!("`{label}` header `{name}`: a `members:` key must be a string")
                })?;
                let path = value.as_str().ok_or_else(|| {
                    format!("`{label}` header `{name}`: member `{key}` must name a slot path")
                })?;
                if parsed.insert(key.to_owned(), path.to_owned()).is_some() {
                    return Err(format!(
                        "`{label}` header `{name}` names member `{key}` twice"
                    ));
                }
            }
            if parsed.is_empty() {
                return Err(format!(
                    "`{label}` header `{name}`: `members:` is empty, so the entry can only render \
                     an empty object"
                ));
            }
            AuthoredSource::Members(parsed)
        },
        (Some(_), Some(_)) => {
            return Err(format!(
                "`{label}` header `{name}` declares both `from:` and `members:`; an entry takes \
                 one source or a set of named members, never both"
            ));
        },
        (None, None) => {
            return Err(format!(
                "`{label}` header `{name}` declares neither `from:` nor `members:`"
            ));
        },
    };

    let on_missing = match map.get(serde_yaml::Value::String("on_missing".to_owned())) {
        None | Some(serde_yaml::Value::Null) => OnMissing::Omit,
        Some(value) => match value.as_str() {
            Some("omit") => OnMissing::Omit,
            Some("deny") => OnMissing::Deny,
            _ => {
                return Err(format!(
                    "`{label}` header `{name}`: `on_missing:` accepts `omit` or `deny`"
                ));
            },
        },
    };

    let encode = match map.get(serde_yaml::Value::String("encode".to_owned())) {
        None | Some(serde_yaml::Value::Null) => None,
        Some(value) => match value.as_str() {
            Some("json") => Some(Encoding::Json),
            Some("csv") => Some(Encoding::Csv),
            _ => {
                return Err(format!(
                    "`{label}` header `{name}`: `encode:` accepts `json` or `csv`"
                ));
            },
        },
    };

    Ok(HeaderEntry {
        name: name.to_owned(),
        source,
        on_missing,
        encode,
    })
}

/// Why a header name is not an HTTP field name, or `None` when it is one.
///
/// A name outside the token set cannot be emitted, so a config carrying one
/// declares a projection that could never happen.
fn field_name_defect(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("is empty");
    }
    if !name.bytes().all(is_token_byte) {
        return Some(
            "is not an HTTP field name: a field name carries letters, digits, and any of \
             !#$%&'*+-.^_`|~",
        );
    }
    None
}

/// Whether a byte is legal in an HTTP field name.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

impl AssertionsConfig {
    /// Whether either direction declares a contract.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.request.is_none() && self.response.is_none()
    }

    /// Check both contracts, naming the level they were written at.
    ///
    /// Run over every declared block at config load, before any request is
    /// served, so a source that names nothing, a collection with no declared
    /// encoding, and a glob that would remove a floor header are all refusals
    /// rather than surprises.
    ///
    /// # Errors
    ///
    /// Returns the first defect, naming the level, the direction, and the
    /// header entry, since a bare path is not locatable in a large config.
    pub fn validate(&self, level: &str) -> Result<(), String> {
        for direction in [Direction::Request, Direction::Response] {
            if let Some(block) = direction.block_of(self) {
                validate_block(block, direction, level)?;
            }
        }
        Ok(())
    }
}

/// Check one direction's contract.
fn validate_block(block: &DirectionBlock, direction: Direction, level: &str) -> Result<(), String> {
    let label = direction.label();
    // Who is deprived of a floor header, and what they cannot read without it.
    let (side, deprived) = match direction {
        Direction::Request => ("request", "the upstream"),
        Direction::Response => ("response", "the client"),
    };
    let mut targeted: Vec<String> = Vec::new();
    for entry in &block.headers {
        let lower = entry.name.to_lowercase();
        if targeted.contains(&lower) {
            return Err(format!(
                "{level}: `{label}` targets header `{}` twice; two entries on one header in one \
                 block leave which value is asserted to declaration order",
                entry.name
            ));
        }
        targeted.push(lower.clone());

        // An entry whose source resolves to nothing still removes its target,
        // so an entry aimed at a floor header could remove one without a
        // `strip:` entry naming it. True in either direction, so the check runs
        // in both against that direction's own floor.
        if let Some(floor_name) = floor::floor_for(direction).iter().find(|f| f.name == lower) {
            return Err(format!(
                "{level}: `{label}` asserts header `{}`, which is in the {side} protocol floor \
                 ({}); an entry removes its target before injecting, so a request whose source \
                 resolved to nothing would leave {deprived} without it",
                entry.name, floor_name.reason
            ));
        }

        match &entry.source {
            AuthoredSource::From(path) => {
                let parsed = SourcePath::parse(path).map_err(|cause| {
                    format!("{level}: `{label}` header `{}`: {cause}", entry.name)
                })?;
                if parsed.is_collection() && entry.encode.is_none() {
                    return Err(format!(
                        "{level}: `{label}` header `{}` reads `{path}`, a collection, into a \
                         single-value header without saying how it encodes; write `encode: json` \
                         or `encode: csv`, or read it under `members:`",
                        entry.name
                    ));
                }
            },
            // A members entry needs no encoding: a JSON object holds a
            // collection natively, which is what `members:` is for. Declaring
            // one anyway is refused rather than ignored, because the renderer
            // always emits an object here: `encode: csv` would load and then
            // not happen.
            AuthoredSource::Members(members) => {
                if entry.encode.is_some() {
                    return Err(format!(
                        "{level}: `{label}` header `{}` reads `members:`, which always renders as \
                         a JSON object, so `encode:` cannot change it; drop `encode:`, or read a \
                         single collection under `from:` to choose its encoding",
                        entry.name
                    ));
                }
                for (member, path) in members {
                    SourcePath::parse(path).map_err(|cause| {
                        format!(
                            "{level}: `{label}` header `{}` member `{member}`: {cause}",
                            entry.name
                        )
                    })?;
                }
            },
        }
    }

    // `strip:` removes headers the engine did not originate and cannot
    // enumerate, which is the argument for a floor and is true both ways round.
    for pattern in &block.strip {
        if let Some(floor_name) = floor::glob_would_match_floor(direction, pattern.as_str()) {
            return Err(format!(
                "{level}: `{label}.strip` entry `{}` would remove `{floor_name}`, which is in the \
                 {side} protocol floor and cannot be removed: {deprived} needs it in order to \
                 interpret the {side} at all",
                pattern.as_str()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::config::{PolicyConfig, parse_config};

    /// The worked example from the plan, tracked as a fixture so a breaking
    /// config change shows up as a failing load rather than as stale prose.
    const WORKED_EXAMPLE: &str =
        include_str!("../../tests/fixtures/assertions_worked_example.yaml");

    fn load(yaml: &str) -> PolicyConfig {
        parse_config(yaml).expect("the config loads")
    }

    fn refuse(yaml: &str) -> String {
        parse_config(yaml)
            .expect_err("the config must not load")
            .to_string()
    }

    fn global(yaml: &str) -> String {
        format!("engine_settings:\n  dispatch: policy\nglobal:\n  assertions:\n{yaml}")
    }

    #[test]
    fn the_worked_example_loads() {
        let config = load(WORKED_EXAMPLE);
        let request = config
            .global
            .assertions
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .expect("the global request contract");
        assert_eq!(
            request
                .headers
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["x-auth-user-id", "x-auth-tenant-id", "x-auth-attributes"]
        );
        assert_eq!(
            request
                .strip
                .iter()
                .map(StripPattern::as_str)
                .collect::<Vec<_>>(),
            vec!["x-auth-*", "x-user-id", "x-tenant-id"]
        );
        assert_eq!(request.headers[1].on_missing, OnMissing::Deny);
        assert!(matches!(
            request.headers[2].source,
            AuthoredSource::Members(_)
        ));
        assert!(
            config
                .global
                .defaults
                .get("http")
                .and_then(|http| http.assertions.as_ref())
                .is_some(),
            "the entity default declares a contract"
        );
        assert!(
            config
                .global
                .bundles
                .get("files-backend")
                .and_then(|bundle| bundle.assertions.as_ref())
                .is_some(),
            "the bundle declares a contract"
        );
    }

    #[test]
    fn on_missing_defaults_to_omit_and_deny_parses() {
        let config = load(&global(
            "    request:
      headers:
        - name: x-a
          from: subject.id
        - name: x-b
          from: claim.tenant
          on_missing: deny
",
        ));
        let headers = &config
            .global
            .assertions
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .expect("a request contract")
            .headers;
        assert_eq!(headers[0].on_missing, OnMissing::Omit);
        assert_eq!(headers[1].on_missing, OnMissing::Deny);
    }

    /// The flag is read per direction, so a level can replace what it inherits
    /// one way while still stacking the other.
    #[test]
    fn replace_inherited_defaults_to_false_and_is_read_per_direction() {
        let config = load(&global(
            "    request:
      replace_inherited: true
      headers: []
    response:
      strip: [x-a]
",
        ));
        let assertions = config.global.assertions.as_ref().expect("a block");
        assert!(
            assertions
                .request
                .as_ref()
                .expect("request")
                .replace_inherited
        );
        assert!(
            !assertions
                .response
                .as_ref()
                .expect("response")
                .replace_inherited
        );
    }

    #[test]
    fn an_absent_block_leaves_every_level_none() {
        let config = load(
            "engine_settings:\n  dispatch: policy\nglobal:\n  defaults:\n    tool: {}\ngroups:\n  \
             hr: {}\nroutes:\n  - tool: get_weather\n    groups: hr\n",
        );
        assert!(config.global.assertions.is_none());
        assert!(config.global.defaults["tool"].assertions.is_none());
        assert!(config.global.bundles["hr"].assertions.is_none());
        assert!(config.routes[0].assertions.is_none());
    }

    #[test]
    fn one_direction_present_leaves_the_other_none() {
        let request_only = load(&global("    request:\n      strip: [x-a]\n"));
        let block = request_only.global.assertions.as_ref().expect("a block");
        assert!(block.request.is_some());
        assert!(block.response.is_none());

        let response_only = load(&global("    response:\n      strip: [x-a]\n"));
        let block = response_only.global.assertions.as_ref().expect("a block");
        assert!(block.request.is_none());
        assert!(block.response.is_some());
    }

    /// An empty list is a declared direction that contributes nothing, which is
    /// not the same as the direction being absent: the first still counts as a
    /// level having spoken.
    #[test]
    fn empty_lists_parse_as_a_declared_direction() {
        let config = load(&global(
            "    request:\n      headers: []\n      strip: []\n",
        ));
        let block = config
            .global
            .assertions
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .expect("the direction is declared");
        assert!(block.headers.is_empty());
        assert!(block.strip.is_empty());
    }

    #[test]
    fn a_block_under_an_entity_default_parses() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  defaults:
    http:
      assertions:
        request:
          headers:
            - name: x-served-by
              from: claim.namespace
",
        );
        assert!(config.global.defaults["http"].assertions.is_some());
    }

    #[test]
    fn an_entry_declaring_both_a_source_and_members_is_refused_naming_the_header() {
        let err = refuse(&global(
            "    request:
      headers:
        - name: x-auth-attributes
          from: subject.id
          members:
            roles: subject.roles
",
        ));
        assert!(err.contains("x-auth-attributes"), "{err}");
        assert!(err.contains("never both"), "{err}");
    }

    #[test]
    fn an_entry_declaring_no_source_is_refused() {
        let err = refuse(&global(
            "    request:\n      headers:\n        - name: x-a\n",
        ));
        assert!(err.contains("neither"), "{err}");
    }

    #[test]
    fn a_header_name_that_is_not_a_field_name_is_refused() {
        for name in ["x auth", "x:auth", "x/auth", ""] {
            let err = refuse(&global(&format!(
                "    request:\n      headers:\n        - name: \"{name}\"\n          from: \
                 subject.id\n"
            )));
            assert!(
                err.contains("field name") || err.contains("is empty"),
                "{name:?}: {err}"
            );
        }
    }

    #[test]
    fn an_unknown_on_missing_or_encode_spelling_is_refused() {
        for (key, value) in [("on_missing", "reject"), ("encode", "yaml")] {
            let err = refuse(&global(&format!(
                "    request:
      headers:
        - name: x-a
          from: subject.id
          {key}: {value}
"
            )));
            assert!(err.contains(key), "{err}");
        }
    }

    #[test]
    fn an_empty_members_mapping_is_refused() {
        let err = refuse(&global(
            "    request:\n      headers:\n        - name: x-a\n          members: {}\n",
        ));
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn a_credential_source_is_refused_naming_the_level_and_the_header() {
        let err = refuse(&global(
            "    request:
      headers:
        - name: x-auth-token
          from: raw_credentials.inbound
",
        ));
        assert!(err.contains("global"), "the level: {err}");
        assert!(err.contains("x-auth-token"), "the header: {err}");
        assert!(err.contains("never usable"), "the refusal: {err}");
    }

    /// A collection has to say how it encodes into one header value. Under
    /// `members:` it does not: a JSON object holds a collection natively.
    #[test]
    fn a_collection_into_a_single_value_header_needs_a_declared_encoding() {
        let err = refuse(&global(
            "    request:
      headers:
        - name: x-auth-roles
          from: subject.roles
",
        ));
        assert!(err.contains("encode"), "{err}");
        load(&global(
            "    request:
      headers:
        - name: x-auth-roles
          from: subject.roles
          encode: csv
",
        ));
        load(&global(
            "    request:
      headers:
        - name: x-auth-attributes
          members:
            roles: subject.roles
",
        ));
    }

    /// `encode:` on a `members:` entry never took effect: the renderer emits a
    /// JSON object either way. Refused at load rather than ignored, so an
    /// operator writing `encode: csv` is not told by the absence of CSV.
    #[test]
    fn an_encoding_on_a_members_entry_is_refused() {
        let err = refuse(&global(
            "    request:
      headers:
        - name: x-auth-attributes
          members:
            roles: subject.roles
          encode: csv
",
        ));
        assert!(err.contains("global"), "the level: {err}");
        assert!(err.contains("x-auth-attributes"), "the header: {err}");
        assert!(err.contains("encode"), "the refusal: {err}");
        // Same for `json`, which is what a members entry already renders: the
        // key is inert either way, so neither spelling loads.
        let err = refuse(&global(
            "    response:
      headers:
        - name: x-served-attributes
          members:
            tenant: claim.tenant
          encode: json
",
        ));
        assert!(err.contains("x-served-attributes"), "{err}");
    }

    #[test]
    fn two_entries_on_one_header_in_one_block_are_refused() {
        let err = refuse(&global(
            "    request:
      headers:
        - name: x-auth-user-id
          from: subject.id
        - name: X-Auth-User-Id
          from: claim.tenant
",
        ));
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn a_route_block_names_the_route_in_its_error() {
        let err = refuse(
            "
engine_settings:
  dispatch: policy
routes:
  - tool: get_weather
    assertions:
      request:
        headers:
          - name: x-a
            from: subject.nonexistent
",
        );
        assert!(err.contains("tool:get_weather"), "{err}");
    }

    #[test]
    fn a_member_source_is_checked_and_names_the_member() {
        let err = refuse(&global(
            "    request:
      headers:
        - name: x-auth-attributes
          members:
            tokens: raw_credentials.inbound
",
        ));
        assert!(err.contains("tokens"), "{err}");
        assert!(err.contains("never usable"), "{err}");
    }

    /// A response entry removes its target before injecting, so one aimed at a
    /// floor header would take it off a response whose source resolved to
    /// nothing.
    #[test]
    fn a_response_entry_targeting_a_floor_header_is_refused() {
        let err = refuse(&global(
            "    response:
      headers:
        - name: content-type
          from: claim.tenant
",
        ));
        assert!(err.contains("content-type"), "{err}");
        assert!(err.contains("floor"), "{err}");
    }

    #[test]
    fn a_response_strip_glob_reaching_the_floor_is_refused_naming_the_header() {
        let err = refuse(&global("    response:\n      strip: [content-*]\n"));
        assert!(err.contains("content-type"), "{err}");
        load(&global(
            "    response:\n      strip: [x-backend-*, server, set-cookie]\n",
        ));
    }

    /// The request direction has a floor too. `strip:` removes headers the
    /// engine did not originate and cannot enumerate, which is the argument for
    /// a floor and does not care which way the traffic is going.
    #[test]
    fn a_request_strip_glob_reaching_the_floor_is_refused_naming_the_header() {
        for (pattern, named) in [
            ("content-*", "content-type"),
            ("\"*\"", "host"),
            ("host", "host"),
            ("transfer-encoding", "transfer-encoding"),
        ] {
            let err = refuse(&global(&format!(
                "    request:\n      strip: [{pattern}]\n"
            )));
            assert!(
                err.contains(named),
                "`{pattern}` should name {named}: {err}"
            );
            assert!(err.contains("floor"), "`{pattern}`: {err}");
        }
    }

    /// `authorization` is outside the request floor on purpose: an upstream
    /// reached on a delegated credential should not also receive the client's
    /// own bearer, so removing it stays legal.
    #[test]
    fn a_request_strip_may_still_remove_the_clients_own_credential() {
        load(&global(
            "    request:\n      strip: [authorization, cookie, x-auth-*, x-user-id]\n",
        ));
    }

    /// An entry removes its target before injecting, so one aimed at a request
    /// floor header would take framing off a request whose source resolved to
    /// nothing. Same reason as the response side.
    #[test]
    fn a_request_entry_targeting_a_floor_header_is_refused() {
        let err = refuse(&global(
            "    request:
      headers:
        - name: host
          from: claim.tenant
",
        ));
        assert!(err.contains("host"), "{err}");
        assert!(err.contains("floor"), "{err}");
    }

    /// The floors are per direction, not one shared list: `etag` is a response
    /// concern and says nothing about what a request may strip, and `host` the
    /// other way round.
    #[test]
    fn each_direction_is_bound_by_its_own_floor_only() {
        load(&global(
            "    request:\n      strip: [etag, cache-control]\n",
        ));
        load(&global("    response:\n      strip: [host]\n"));
    }

    #[test]
    fn a_valid_block_loads_at_every_level_in_both_directions() {
        let config = load(
            "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-g
          from: subject.id
    response:
      strip: [x-g-out]
  defaults:
    tool:
      assertions:
        request:
          headers:
            - name: x-d
              from: claim.tenant
        response:
          strip: [x-d-out]
groups:
  hr:
    assertions:
      request:
        headers:
          - name: x-b
            from: claim.team
      response:
        strip: [x-b-out]
routes:
  - tool: get_weather
    groups: hr
    assertions:
      request:
        headers:
          - name: x-r
            from: claim.region
      response:
        strip: [x-r-out]
",
        );
        assert!(config.global.assertions.is_some());
        assert!(config.global.defaults["tool"].assertions.is_some());
        assert!(config.global.bundles["hr"].assertions.is_some());
        assert!(config.routes[0].assertions.is_some());
    }
}
