// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Acquired metadata extension → AttributeBag.

use std::collections::HashSet;

use praxis_policy_apl_core::{AttributeBag, AttributeValue};
use praxis_policy_core::extensions::{AcquiredFacts, MetadataExtension};
use serde_json::Value;

use crate::constants::BAG_METADATA_PREFIX;

/// Flatten acquired metadata values and provenance into policy attributes.
pub fn extract_metadata(metadata: &MetadataExtension, bag: &mut AttributeBag) {
    for (instance, facts) in metadata.iter() {
        let prefix = format!("{BAG_METADATA_PREFIX}{instance}");
        bag.set(&prefix, AttributeValue::NonScalar);
        extract_value(facts, &prefix, bag);
        extract_provenance(facts, &prefix, bag);
    }
}

/// Project a successful structured value below one instance prefix.
fn extract_value(facts: &AcquiredFacts, prefix: &str, bag: &mut AttributeBag) {
    let Some(value) = facts.value() else { return };
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                walk(child, &format!("{prefix}.{key}"), bag);
            }
        },
        other => walk(other, &format!("{prefix}.value"), bag),
    }
}

/// Project the framework-stamped acquisition provenance leaves.
fn extract_provenance(facts: &AcquiredFacts, prefix: &str, bag: &mut AttributeBag) {
    if let Some(source) = facts.source() {
        bag.set(format!("{prefix}.$source"), source.kind.clone());
    }
    bag.set(
        format!("{prefix}.$outcome"),
        facts.outcome().as_str().to_owned(),
    );
    bag.set(
        format!("{prefix}.$cache"),
        facts.cache().as_str().to_owned(),
    );
    if let Some(fetched_at) = facts.fetched_at() {
        bag.set(
            format!("{prefix}.$fetched_at"),
            fetched_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
    }
    if let Some(status) = facts.status() {
        bag.set(format!("{prefix}.$status"), i64::from(status));
    }
    if facts.stale() {
        bag.set(format!("{prefix}.$stale"), true);
    }
    if let Some(error_code) = facts.error_code() {
        bag.set(format!("{prefix}.$error_code"), error_code.to_owned());
    }
}

/// Flatten APL-compatible leaves while retaining unsupported-node presence.
fn walk(value: &Value, prefix: &str, bag: &mut AttributeBag) {
    match value {
        Value::Object(map) => {
            bag.set(prefix, AttributeValue::NonScalar);
            for (key, child) in map {
                walk(child, &format!("{prefix}.{key}"), bag);
            }
        },
        Value::Array(items) => {
            let strings: Option<HashSet<String>> = items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect();
            match strings {
                Some(strings) => bag.set(prefix, strings),
                None => bag.set(prefix, AttributeValue::NonScalar),
            }
        },
        Value::String(value) => bag.set(prefix, value.clone()),
        Value::Bool(value) => bag.set(prefix, *value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                bag.set(prefix, value);
            } else if value.is_f64()
                && let Some(value) = value.as_f64()
            {
                bag.set(prefix, value);
            } else {
                bag.set(prefix, AttributeValue::NonScalar);
            }
        },
        Value::Null => bag.set(prefix, AttributeValue::NonScalar),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::extract_extensions;
    use praxis_policy_core::extensions::{Extensions, MetadataCacheDisposition, filter_extensions};
    use serde_json::json;

    #[test]
    fn object_record_projects_values_and_provenance() {
        let value = json!({
            "active": true,
            "count": 2,
            "ratio": 0.5,
            "name": "alice",
            "roles": ["reader", "writer"],
            "nested": {"value": "kept"},
            "mixed": ["reader", 2],
            "missing": null
        });
        let facts = AcquiredFacts::success(value, instant(), MetadataCacheDisposition::Miss)
            .with_status(200)
            .with_stale();
        let metadata = installed("account", facts);
        let mut bag = AttributeBag::new();

        extract_metadata(&metadata, &mut bag);

        assert_eq!(
            bag.get("metadata.account"),
            Some(&AttributeValue::NonScalar)
        );
        assert_eq!(bag.get_bool("metadata.account.active"), Some(true));
        assert_eq!(bag.get_int("metadata.account.count"), Some(2));
        assert_eq!(bag.get_float("metadata.account.ratio"), Some(0.5));
        assert_eq!(bag.get_string("metadata.account.name"), Some("alice"));
        assert!(bag.set_contains("metadata.account.roles", "reader"));
        assert_eq!(
            bag.get("metadata.account.nested"),
            Some(&AttributeValue::NonScalar)
        );
        assert_eq!(
            bag.get_string("metadata.account.nested.value"),
            Some("kept")
        );
        assert_eq!(
            bag.get("metadata.account.mixed"),
            Some(&AttributeValue::NonScalar)
        );
        assert_eq!(
            bag.get("metadata.account.missing"),
            Some(&AttributeValue::NonScalar)
        );
        assert_eq!(
            bag.get_string("metadata.account.$source"),
            Some("metadata/http")
        );
        assert_eq!(bag.get_string("metadata.account.$outcome"), Some("success"));
        assert_eq!(bag.get_string("metadata.account.$cache"), Some("stale"));
        assert_eq!(bag.get_int("metadata.account.$status"), Some(200));
        assert_eq!(bag.get_bool("metadata.account.$stale"), Some(true));
        assert_eq!(
            bag.get_string("metadata.account.$fetched_at"),
            Some("2026-10-19T12:00:00Z")
        );
        assert!(!bag.contains("metadata.account.$error_code"));
    }

    #[test]
    fn non_object_roots_use_the_value_leaf() {
        for (facts, expected) in [
            (
                success(json!("text")),
                AttributeValue::String("text".to_owned()),
            ),
            (success(json!(42)), AttributeValue::Int(42)),
            (success(json!(null)), AttributeValue::NonScalar),
        ] {
            let metadata = installed("lookup", facts);
            let mut bag = AttributeBag::new();
            extract_metadata(&metadata, &mut bag);
            assert_eq!(bag.get("metadata.lookup.value"), Some(&expected));
        }

        let metadata = installed("lookup", success(json!(["a", "b"])));
        let mut bag = AttributeBag::new();
        extract_metadata(&metadata, &mut bag);
        assert!(bag.set_contains("metadata.lookup.value", "a"));
    }

    #[test]
    fn error_record_projects_no_partial_value() {
        let facts = AcquiredFacts::error(
            "metadata.upstream_error",
            MetadataCacheDisposition::Disabled,
        )
        .with_status(503);
        let metadata = installed("account", facts);
        let mut bag = AttributeBag::new();

        extract_metadata(&metadata, &mut bag);

        assert_eq!(bag.get_string("metadata.account.$outcome"), Some("error"));
        assert_eq!(
            bag.get_string("metadata.account.$source"),
            Some("metadata/http")
        );
        assert_eq!(bag.get_string("metadata.account.$cache"), Some("disabled"));
        assert_eq!(
            bag.get_string("metadata.account.$error_code"),
            Some("metadata.upstream_error")
        );
        assert_eq!(bag.get_int("metadata.account.$status"), Some(503));
        assert!(!bag.contains("metadata.account.$stale"));
        assert!(!bag.contains("metadata.account.value"));
        assert!(!bag.contains("metadata.account.$fetched_at"));
    }

    #[test]
    fn integers_outside_the_apl_domain_remain_present_without_rounding() {
        let metadata = installed("lookup", success(json!(u64::MAX)));
        let mut bag = AttributeBag::new();

        extract_metadata(&metadata, &mut bag);

        assert_eq!(
            bag.get("metadata.lookup.value"),
            Some(&AttributeValue::NonScalar),
            "an out-of-range integer must not become a rounded float"
        );
    }

    #[test]
    fn child_projection_stays_empty_even_with_read_metadata() {
        let mut parent = Extensions::default();
        parent
            .install_metadata("account", "metadata/http", success(json!(true)))
            .expect("parent metadata installs");
        let child = parent.for_child_request();
        let filtered_child =
            filter_extensions(&child, &HashSet::from(["read_metadata".to_owned()]));
        let mut child_bag = AttributeBag::new();

        extract_extensions(&filtered_child, &mut child_bag);

        assert!(filtered_child.metadata.is_none());
        assert!(
            !child_bag
                .iter()
                .any(|(key, _)| key.starts_with("metadata.")),
            "child projection must not inherit the parent's metadata namespace"
        );
        assert!(
            parent
                .metadata
                .as_deref()
                .and_then(|metadata| metadata.get("account"))
                .is_some(),
            "scrubbing a child must leave its parent unchanged"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    fn installed(instance: &str, facts: AcquiredFacts) -> MetadataExtension {
        let mut extensions = Extensions::default();
        extensions
            .install_metadata(instance, "metadata/http", facts)
            .expect("test metadata installs");
        extensions
            .metadata
            .as_deref()
            .cloned()
            .expect("metadata is present")
    }

    fn instant() -> chrono::DateTime<chrono::Utc> {
        "2026-10-19T12:00:00Z"
            .parse()
            .expect("a literal RFC3339 instant")
    }

    fn success(value: Value) -> AcquiredFacts {
        AcquiredFacts::success(value, instant(), MetadataCacheDisposition::Disabled)
    }
}
