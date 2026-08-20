// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// JSON args/result payload → AttributeBag.
//
// Leaf scalars at any nesting depth land in the bag under their dotted
// path, prefixed with `args.` or `result.`. Nested objects recurse;
// scalar arrays flatten into a StringSet, numbers and bools rendered as
// strings (empty array → empty set); arrays holding a nested array or
// object are skipped (no list scalar in the bag).
//
// Examples:
//   args = { "include_ssn": true,
//            "user": { "id": "alice", "roles": ["hr", "manager"] } }
//   →  args.include_ssn      : Bool(true)
//      args.user.id          : String("alice")
//      args.user.roles       : StringSet({"hr", "manager"})
//
// Null values are skipped (consistent with bag's missing-key semantics).

use praxis_policy_apl_core::AttributeBag;
use serde_json::Value;
use std::collections::HashSet;

use crate::constants::{BAG_ARGS_PREFIX, BAG_RESULT_PREFIX};

/// Flatten an args object into `args.*` keys.
pub fn extract_args(args: &Value, bag: &mut AttributeBag) {
    // `walk` builds dotted paths itself; strip the trailing `.` from
    // the canonical prefix to match its signature.
    walk(args, BAG_ARGS_PREFIX.trim_end_matches('.'), bag);
}

/// Flatten a result object into `result.*` keys.
pub fn extract_result(result: &Value, bag: &mut AttributeBag) {
    walk(result, BAG_RESULT_PREFIX.trim_end_matches('.'), bag);
}

/// Flatten a static attribute tree into `data.*` keys. Same walk as
/// args/result — nested objects recurse, scalar arrays become
/// `StringSet`s (so `data.tenants.x.allowed_models` supports `contains`
/// and interpolated `restrict` references), an empty array an empty set.
pub fn extract_data(tree: &praxis_policy_apl_core::AttributeTree, bag: &mut AttributeBag) {
    walk(tree.as_value(), "data", bag);
}

pub(crate) fn walk(value: &Value, prefix: &str, bag: &mut AttributeBag) {
    match value {
        Value::Object(map) => {
            for (key, sub) in map {
                let dotted = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                walk(sub, &dotted, bag);
            }
        },
        Value::Array(items) => {
            // Promote scalar arrays to StringSet — supports
            // `args.tags contains "urgent"` predicates. Numbers and bools
            // render to their string form: a claim arrives in whatever
            // shape the IdP minted, and coercing beats denying every user
            // of a provider that emits `"group_ids": [1, 2]`.
            let mut set: HashSet<String> = HashSet::new();
            let mut ok = true;
            for item in items {
                match item {
                    Value::String(s) => {
                        set.insert(s.clone());
                    },
                    Value::Number(n) => {
                        set.insert(n.to_string());
                    },
                    Value::Bool(b) => {
                        set.insert(b.to_string());
                    },
                    // Null is absent, so it contributes no element.
                    Value::Null => {},
                    // Nested arrays/objects have no bag representation.
                    Value::Array(_) | Value::Object(_) => {
                        ok = false;
                        break;
                    },
                }
            }
            // Empty arrays included: a strict PDP errors on a missing key
            // but evaluates an empty set fine. See `security.rs`.
            if ok {
                bag.set(prefix, set);
            }
        },
        Value::String(s) => bag.set(prefix, s.clone()),
        Value::Bool(b) => bag.set(prefix, *b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                bag.set(prefix, i);
            } else if let Some(f) = n.as_f64() {
                bag.set(prefix, f);
            }
        },
        Value::Null => {}, // Skip — equivalent to "key not present."
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
    use serde_json::json;

    #[test]
    fn args_scalars_at_top_level() {
        let args = json!({ "include_ssn": true, "amount": 100, "name": "alice" });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert_eq!(bag.get_bool("args.include_ssn"), Some(true));
        assert_eq!(bag.get_int("args.amount"), Some(100));
        assert_eq!(bag.get_string("args.name"), Some("alice"));
    }

    #[test]
    fn args_nested_objects_dotted() {
        let args = json!({ "user": { "id": "alice", "profile": { "tier": "gold" } } });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert_eq!(bag.get_string("args.user.id"), Some("alice"));
        assert_eq!(bag.get_string("args.user.profile.tier"), Some("gold"));
    }

    #[test]
    fn args_string_array_becomes_string_set() {
        let args = json!({ "tags": ["urgent", "audit"] });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert!(bag.set_contains("args.tags", "urgent"));
        assert!(bag.set_contains("args.tags", "audit"));
        assert!(!bag.set_contains("args.tags", "missing"));
    }

    /// Dropping the key would deny every subject whose `IdP` minted
    /// `"roles": []`, since a missing key is a CEL error. The resolver's
    /// `membership_on_absent_key_denies_but_empty_set_evaluates` pins that.
    #[test]
    fn empty_array_becomes_an_empty_string_set_not_a_missing_key() {
        let args = json!({ "tags": [], "nested": { "roles": [] } });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert!(
            bag.contains("args.tags"),
            "an empty array must set the key, or membership errors",
        );
        assert!(!bag.set_contains("args.tags", "anything"), "and be empty");
        assert!(
            bag.contains("args.nested.roles"),
            "nested too — this is the Keycloak `realm_access.roles` shape",
        );
    }

    /// Numbers and bools render to their string form rather than costing
    /// the key, matching how the Cedar bridge carries a float claim.
    #[test]
    fn scalar_array_elements_are_coerced_to_strings() {
        let args = json!({ "mixed": ["a", 1, true], "ids": [1, 2], "n": ["a", null] });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert!(bag.set_contains("args.mixed", "a"));
        assert!(bag.set_contains("args.mixed", "1"));
        assert!(bag.set_contains("args.mixed", "true"));
        assert!(
            bag.set_contains("args.ids", "2"),
            "numeric ids are testable"
        );
        // Null is absent, so it drops out without costing the key.
        assert!(bag.contains("args.n"));
        assert!(!bag.set_contains("args.n", "null"));
    }

    /// A nested array or object has no bag representation, so the key is
    /// still skipped — the one remaining case that sets nothing.
    #[test]
    fn array_holding_a_nested_container_is_skipped() {
        let args = json!({ "deep": ["a", [1]], "objs": [{ "k": "v" }] });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert!(!bag.contains("args.deep"));
        assert!(!bag.contains("args.objs"));
    }

    #[test]
    fn args_null_is_treated_as_missing() {
        let args = json!({ "maybe": null, "yes": true });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert!(!bag.contains("args.maybe"));
        assert_eq!(bag.get_bool("args.yes"), Some(true));
    }

    #[test]
    fn result_uses_result_prefix() {
        let result = json!({ "ssn": "123-45-6789", "salary": 50000 });
        let mut bag = AttributeBag::new();
        extract_result(&result, &mut bag);
        assert_eq!(bag.get_string("result.ssn"), Some("123-45-6789"));
        assert_eq!(bag.get_int("result.salary"), Some(50000));
        // No args.* keys collected.
        assert!(!bag.contains("args.ssn"));
    }

    #[test]
    fn float_numbers_land_as_float() {
        let args = json!({ "score": 0.92 });
        let mut bag = AttributeBag::new();
        extract_args(&args, &mut bag);
        assert_eq!(bag.get_float("args.score"), Some(0.92));
    }

    #[test]
    fn data_tree_flattens_under_data_namespace() {
        let tree = praxis_policy_apl_core::AttributeTree::new(json!({
            "org": { "default_region": "us" },
            "tenants": {
                "acme-eu": { "data_region": "eu", "allowed_models": ["anthropic/*", "vllm/*"] }
            }
        }));
        let mut bag = AttributeBag::new();
        extract_data(&tree, &mut bag);

        assert_eq!(bag.get_string("data.org.default_region"), Some("us"));
        assert_eq!(
            bag.get_string("data.tenants.acme-eu.data_region"),
            Some("eu")
        );
        // String arrays become a StringSet (ready for `contains` /
        // interpolated path lookups).
        assert!(bag.set_contains("data.tenants.acme-eu.allowed_models", "anthropic/*"));
        assert!(bag.set_contains("data.tenants.acme-eu.allowed_models", "vllm/*"));
    }

    #[test]
    fn empty_data_tree_adds_nothing() {
        let mut bag = AttributeBag::new();
        extract_data(&praxis_policy_apl_core::AttributeTree::empty(), &mut bag);
        assert!(bag.is_empty());
    }
}
