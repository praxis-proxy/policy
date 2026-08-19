// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// MetaExtension → AttributeBag.
//
// Namespace:
//   meta.entity_type        : String   ("tool" | "resource" | "prompt" | "llm")
//   meta.entity_name        : String
//   meta.tags               : StringSet (always) ← used by spec-level tag-driven policy inheritance
//   meta.scope              : String
//   meta.properties.<k>     : String

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::MetaExtension;

/// Write operational metadata into the bag.
pub fn extract_meta(meta: &MetaExtension, bag: &mut AttributeBag) {
    if let Some(v) = &meta.entity_type {
        bag.set("meta.entity_type", v.clone());
    }
    if let Some(v) = &meta.entity_name {
        bag.set("meta.entity_name", v.clone());
    }
    // Always emitted, empty rather than absent — see the empty-set note in
    // `security.rs`, which documents the rule for the whole bridge.
    bag.set("meta.tags", meta.tags.clone());
    if let Some(v) = &meta.scope {
        bag.set("meta.scope", v.clone());
    }
    for (k, v) in &meta.properties {
        bag.set(format!("meta.properties.{k}"), v.clone());
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
    use std::collections::{HashMap, HashSet};

    #[test]
    fn tags_and_properties_flatten() {
        let meta = MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some("get_compensation".into()),
            tags: HashSet::from(["pii".to_owned(), "sensitive".to_owned()]),
            scope: Some("hr".into()),
            properties: HashMap::from([("owner".to_owned(), "compliance".to_owned())]),
        };
        let mut bag = AttributeBag::new();
        extract_meta(&meta, &mut bag);
        assert_eq!(bag.get_string("meta.entity_type"), Some("tool"));
        assert_eq!(bag.get_string("meta.entity_name"), Some("get_compensation"));
        assert!(bag.set_contains("meta.tags", "pii"));
        assert!(bag.set_contains("meta.tags", "sensitive"));
        assert_eq!(bag.get_string("meta.scope"), Some("hr"));
        assert_eq!(bag.get_string("meta.properties.owner"), Some("compliance"));
    }
}
