// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The phase a hook is recorded under must be the phase the dispatcher
// installs it under. Nothing checked that, which is how `cmf.http_request`
// came to be installed as `Phase::Pre` while the metadata table had no row
// for it at all and every phase consumer read it as unphased.
//
// Completeness is not tested here. `define_hooks!` emits a hook's constant
// and its metadata row from one declaration, so a constant without a row is
// unrepresentable. What remains testable is agreement.
//
// This lives in praxis-policy-apl-runtime because the install sites do:
// `visitor.rs` resolves each entity type's hook pair and passes an explicit
// `Phase` for each half, and praxis-policy-core cannot see that.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code"
)]

use praxis_policy_apl_runtime::visitor::hook_pair_for_entity;
use praxis_policy_core::hooks::builtin_hook_types;
use praxis_policy_core::hooks::{HookPhase, lookup_hook_metadata};

/// Every entity type the metadata table names, taken from the table
/// rather than written out, so a new entity-typed hook joins this test on
/// its own.
fn entity_types_in_the_authority() -> Vec<&'static str> {
    let mut types: Vec<&'static str> = builtin_hook_types()
        .iter()
        .filter_map(|hook| lookup_hook_metadata(hook.as_str())?.entity_type)
        .collect();
    types.sort_unstable();
    types.dedup();
    types
}

#[test]
fn each_entity_types_hook_pair_matches_the_recorded_phases() {
    for entity_type in entity_types_in_the_authority() {
        let (pre, post) = hook_pair_for_entity(entity_type).unwrap_or_else(|| {
            panic!("{entity_type} has hooks in the table but the visitor resolves no pair for it")
        });

        let pre_meta = lookup_hook_metadata(pre)
            .unwrap_or_else(|| panic!("the visitor installs {pre} but the table has no row"));
        assert_eq!(
            pre_meta.phase,
            HookPhase::Pre,
            "{pre} is installed as the pre half for {entity_type} but recorded as {:?}",
            pre_meta.phase,
        );
        assert_eq!(pre_meta.entity_type, Some(entity_type), "{pre}");

        let post_meta = lookup_hook_metadata(post)
            .unwrap_or_else(|| panic!("the visitor installs {post} but the table has no row"));
        assert_eq!(
            post_meta.phase,
            HookPhase::Post,
            "{post} is installed as the post half for {entity_type} but recorded as {:?}",
            post_meta.phase,
        );
        assert_eq!(post_meta.entity_type, Some(entity_type), "{post}");
    }
}

#[test]
fn every_entity_typed_hook_is_one_half_of_its_types_pair() {
    // The other direction: a hook tied to an entity type that the pair
    // does not name would be routable in the table and unreachable in the
    // dispatcher.
    for hook in builtin_hook_types() {
        let name = hook.as_str();
        let Some(entity_type) = lookup_hook_metadata(name).expect("registered").entity_type else {
            continue;
        };
        let (pre, post) = hook_pair_for_entity(entity_type)
            .unwrap_or_else(|| panic!("{entity_type} resolves no hook pair"));
        assert!(
            name == pre || name == post,
            "{name} is recorded for entity type {entity_type} but is neither half of its pair",
        );
    }
}

#[test]
fn a_hook_the_visitor_never_installs_is_not_a_failure() {
    // Identity, delegation, and elicitation are dispatched by other paths
    // and are deliberately unphased, so the visitor resolving no pair for
    // them is correct rather than a gap.
    for hook in builtin_hook_types() {
        let meta = lookup_hook_metadata(hook.as_str()).expect("registered");
        if meta.entity_type.is_some() {
            continue;
        }
        assert_eq!(
            meta.phase,
            HookPhase::Unphased,
            "{hook} has no entity type, so no install site can give it a phase",
        );
    }
}
