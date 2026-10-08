// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// AttributeBag — flat namespace for policy evaluation.
//
// The DSL evaluates predicates against a flat bag of named, typed values.
// Each attribute source (praxis-policy-core extensions, route args, session context,
// custom plugin namespaces) drops keys into the bag through the
// `AttributeExtractor` trait.
//
// A flat bag (rather than nested object access) means the evaluator never
// has to know which extension a key came from — it just queries by name.
// New attribute sources are additive: implement `AttributeExtractor` for
// them and the evaluator picks them up unchanged.
//
// Mapping from praxis-policy-core extensions into the bag lives in `praxis-policy-apl-cmf`, not
// here.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A single attribute value the evaluator can compare against.
///
/// The variants cover every shape the DSL needs:
/// `Bool` for `authenticated` / `role.*` / `perm.*`,
/// `Int` for counts and depths,
/// `Float` for confidences and ages,
/// `String` for identifiers,
/// `StringSet` for set-membership operators (`contains`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// A boolean.
    Bool(bool),
    /// A signed integer.
    Int(i64),
    /// A floating-point number.
    Float(f64),
    /// A string.
    String(String),
    /// A set of strings, for `contains` and `in` tests.
    StringSet(HashSet<String>),
    /// Present JSON object, null, or array that has no scalar bag value.
    /// Order comparisons on this value fail closed.
    NonScalar,
}

impl From<bool> for AttributeValue {
    fn from(v: bool) -> Self {
        AttributeValue::Bool(v)
    }
}
impl From<i64> for AttributeValue {
    fn from(v: i64) -> Self {
        AttributeValue::Int(v)
    }
}
impl From<f64> for AttributeValue {
    fn from(v: f64) -> Self {
        AttributeValue::Float(v)
    }
}
impl From<&str> for AttributeValue {
    fn from(v: &str) -> Self {
        AttributeValue::String(v.to_owned())
    }
}
impl From<String> for AttributeValue {
    fn from(v: String) -> Self {
        AttributeValue::String(v)
    }
}
impl From<HashSet<String>> for AttributeValue {
    fn from(v: HashSet<String>) -> Self {
        AttributeValue::StringSet(v)
    }
}

/// Flat key→value namespace consumed by the evaluator.
///
/// Populate via `set()` and/or `AttributeExtractor::extract()`; query via
/// the typed `get_*` methods. Once handed to the evaluator the bag is
/// read-only by convention (not enforced — `&mut` borrows are how you
/// build it up in the first place).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeBag {
    attrs: HashMap<String, AttributeValue>,
}

impl AttributeBag {
    /// An empty bag.
    pub fn new() -> Self {
        Self {
            attrs: HashMap::new(),
        }
    }

    /// Insert or replace the value at `key`.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<AttributeValue>) {
        self.attrs.insert(key.into(), value.into());
    }

    /// The value at `key`, if present.
    pub fn get(&self, key: &str) -> Option<&AttributeValue> {
        self.attrs.get(key)
    }

    /// Whether `key` is present, whatever its value.
    pub fn contains(&self, key: &str) -> bool {
        self.attrs.contains_key(key)
    }

    /// The value at `key` as a bool, or `None` if absent or another type.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key) {
            Some(AttributeValue::Bool(v)) => Some(*v),
            _ => None,
        }
    }

    /// The value at `key` as an integer, or `None` if absent or another type.
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(AttributeValue::Int(v)) => Some(*v),
            _ => None,
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "the caller asked for an f64; an integer past 2^53 cannot be \
                  represented exactly and there is no other common type"
    )]
    /// The value at `key` as an `f64`, promoting an integer if needed.
    pub fn get_float(&self, key: &str) -> Option<f64> {
        match self.get(key) {
            Some(AttributeValue::Float(v)) => Some(*v),
            // Promote int → float so `depth > 2.5`-style predicates work
            // when depth is stored as Int.
            Some(AttributeValue::Int(v)) => Some(*v as f64),
            _ => None,
        }
    }

    /// The value at `key` as a string, or `None` if absent or another type.
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(AttributeValue::String(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// The value at `key` as a string set, or `None` if absent or another type.
    pub fn get_string_set(&self, key: &str) -> Option<&HashSet<String>> {
        match self.get(key) {
            Some(AttributeValue::StringSet(v)) => Some(v),
            _ => None,
        }
    }

    /// DSL `<key> contains <value>` — false if the key is missing or not a set.
    pub fn set_contains(&self, key: &str, value: &str) -> bool {
        self.get_string_set(key)
            .map(|set| set.contains(value))
            .unwrap_or(false)
    }

    /// Resolve an attribute path to its concrete flat key, expanding any
    /// `[inner]` interpolation groups. Each `[inner]` looks
    /// `inner` up in this bag and substitutes `.` + its scalar value:
    /// `data.tenants[subject.tenant].data_region` with `subject.tenant =
    /// "acme-eu"` → `data.tenants.acme-eu.data_region`. The common
    /// bracket-free key is returned borrowed (no allocation).
    ///
    /// Returns `None` when any `inner` key is missing or not a scalar — the
    /// caller treats that as an absent attribute, so a lookup keyed on an
    /// unknown request value fails to match rather than hitting a
    /// half-substituted key. Shared by predicate evaluation and
    /// `restrict` field references.
    pub fn resolve_key<'a>(&self, key: &'a str) -> Option<std::borrow::Cow<'a, str>> {
        if !key.contains('[') {
            return Some(std::borrow::Cow::Borrowed(key));
        }
        let mut out = String::with_capacity(key.len());
        let mut rest = key;
        while let Some(open) = rest.find('[') {
            // `open` and `close` come from `find` on ASCII delimiters, so these
            // splits land on char boundaries. The lexer guarantees a matching
            // `]`; a missing one joins the absent-attribute path above, which
            // fails to match rather than half-substituting the key.
            let (before, after_open) = rest.split_at_checked(open)?;
            out.push_str(before);
            let after = after_open.get(1..)?;
            let close = after.find(']')?;
            let inner = after.get(..close)?.trim();
            out.push('.');
            out.push_str(&self.scalar_as_string(inner)?);
            rest = after.get(close + 1..)?;
        }
        out.push_str(rest);
        Some(std::borrow::Cow::Owned(out))
    }

    /// The scalar at `key`, stringified for use as a path segment. Numbers
    /// and bools coerce to their text form (a tenant id may be numeric); a
    /// `StringSet` cannot index a path, so it yields `None`.
    fn scalar_as_string(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            AttributeValue::String(s) => Some(s.clone()),
            AttributeValue::Int(i) => Some(i.to_string()),
            AttributeValue::Bool(b) => Some(b.to_string()),
            AttributeValue::Float(f) => Some(f.to_string()),
            AttributeValue::StringSet(_) | AttributeValue::NonScalar => None,
        }
    }

    /// How many keys the bag holds.
    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    /// Whether the bag holds no keys.
    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    /// Every key and value, in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &AttributeValue)> {
        self.attrs.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// Source of attributes. Implementors drop keys into the bag under a
/// consistent namespace prefix:
///
/// - praxis-policy-core `SecurityExtension.subject`  → `subject.*`, `role.*`, `perm.*`
/// - praxis-policy-core `SecurityExtension.client`   → `client.*`
/// - praxis-policy-core `DelegationExtension`        → `delegation.*`, `delegated`
/// - Route args                              → `args.*`
/// - Session context                         → `session.*`
///
/// Implementations for the praxis-policy-core extensions live in `praxis-policy-apl-cmf`, not here.
pub trait AttributeExtractor {
    /// Write this source's attributes into the bag.
    fn extract(&self, bag: &mut AttributeBag);
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

    #[test]
    fn basic_bag() {
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("delegation.depth", 2_i64);
        bag.set("subject.id", "alice@corp.com");
        bag.set("intent.confidence", 0.92_f64);

        assert_eq!(bag.get_bool("authenticated"), Some(true));
        assert_eq!(bag.get_int("delegation.depth"), Some(2));
        assert_eq!(bag.get_string("subject.id"), Some("alice@corp.com"));
        assert_eq!(bag.get_float("intent.confidence"), Some(0.92));
    }

    #[test]
    fn int_to_float_promotion() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2_i64);
        assert_eq!(bag.get_float("delegation.depth"), Some(2.0));
    }

    #[test]
    fn string_set_contains() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["PII".to_owned(), "financial".to_owned()]),
        );

        assert!(bag.set_contains("session.labels", "PII"));
        assert!(bag.set_contains("session.labels", "financial"));
        assert!(!bag.set_contains("session.labels", "PHI"));
    }

    #[test]
    fn missing_keys() {
        let bag = AttributeBag::new();
        assert_eq!(bag.get_bool("nonexistent"), None);
        assert_eq!(bag.get_int("nonexistent"), None);
        assert!(!bag.set_contains("nonexistent", "value"));
    }

    #[test]
    fn type_mismatch_returns_none() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        // Stored as String; asking for Bool returns None, not a coerced value.
        assert_eq!(bag.get_bool("subject.id"), None);
        assert_eq!(bag.get_int("subject.id"), None);
    }
}
