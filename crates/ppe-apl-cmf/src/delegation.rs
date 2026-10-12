// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// DelegationExtension → AttributeBag.
//
// Namespace map:
//
//   del.depth                  → delegation.depth                : Int
//   del.delegated              → delegation.delegated, delegated : Bool
//   del.origin_subject_id      → delegation.origin_subject_id    : String
//   del.actor_subject_id       → delegation.actor_subject_id     : String
//   del.age_seconds            → delegation.age_seconds          : Float
//
// `chain` is not flattened, which makes `delegation.depth <= 2` expressible
// and "deny if any hop granted write:payroll" not. A plugin that needs per-hop
// grants reads the typed chain. Putting any of it on the bag first requires
// deciding aggregation semantics across hops, and they differ per field. A
// union over `scopes_granted` reports a scope that one hop granted and a later
// hop narrowed, so the key would claim more authority than the chain conveys.
// `from_cache` is an any-hop flag rather than a union, and whether one cached
// hop taints the chain is the operator's call, not this bridge's.

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::DelegationExtension;

/// Flatten a `DelegationExtension` into the bag.
pub fn extract_delegation(del: &DelegationExtension, bag: &mut AttributeBag) {
    bag.set("delegation.depth", i64::from(del.depth));
    bag.set("delegation.delegated", del.delegated);
    // Top-level alias — DSL idiom is `require(!delegated)`, unprefixed.
    bag.set("delegated", del.delegated);

    if let Some(origin) = &del.origin_subject_id {
        bag.set("delegation.origin_subject_id", origin.clone());
    }
    if let Some(actor) = &del.actor_subject_id {
        bag.set("delegation.actor_subject_id", actor.clone());
    }
    bag.set("delegation.age_seconds", del.age_seconds);
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
    use praxis_policy_core::extensions::{DelegationHop, DelegationStrategy};

    #[test]
    fn empty_delegation_sets_zero_depth_and_delegated_false() {
        let del = DelegationExtension::default();
        let mut bag = AttributeBag::new();
        extract_delegation(&del, &mut bag);
        assert_eq!(bag.get_int("delegation.depth"), Some(0));
        assert_eq!(bag.get_bool("delegation.delegated"), Some(false));
        assert_eq!(bag.get_bool("delegated"), Some(false));
        // Optional fields stay absent.
        assert!(!bag.contains("delegation.origin_subject_id"));
        assert!(!bag.contains("delegation.actor_subject_id"));
    }

    #[test]
    fn populated_chain_produces_attributes() {
        let mut del = DelegationExtension {
            origin_subject_id: Some("alice".into()),
            actor_subject_id: Some("service-b".into()),
            age_seconds: 12.5,
            ..Default::default()
        };
        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            audience: Some("service-b".into()),
            scopes_granted: vec!["read".into()],
            strategy: Some(DelegationStrategy::TokenExchange),
            ..Default::default()
        });
        del.append_hop(DelegationHop {
            subject_id: "service-b".into(),
            audience: Some("service-c".into()),
            scopes_granted: vec!["read".into()],
            ..Default::default()
        });

        let mut bag = AttributeBag::new();
        extract_delegation(&del, &mut bag);
        assert_eq!(bag.get_int("delegation.depth"), Some(2));
        assert_eq!(bag.get_bool("delegation.delegated"), Some(true));
        assert_eq!(bag.get_bool("delegated"), Some(true));
        assert_eq!(
            bag.get_string("delegation.origin_subject_id"),
            Some("alice")
        );
        assert_eq!(
            bag.get_string("delegation.actor_subject_id"),
            Some("service-b")
        );
        assert_eq!(bag.get_float("delegation.age_seconds"), Some(12.5));
    }
}
