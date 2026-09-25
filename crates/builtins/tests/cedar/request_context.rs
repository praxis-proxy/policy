// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The context block a Cedar policy reads, and the parse rejections that guard it.
//
// `parse` assembles `context.delegation`, `context.meta` and `context.security`
// from the bag, then overlays whatever the operator wrote in the step's
// `context:` key. Every scenario test uses a two-key bag and no operator
// context, so each of those branches and the overlay precedence rule were
// untested. Those paths are exactly what a policy author writes conditions
// against, so they are covered here through the public `parse`.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::step::{PdpCall, PdpDialect};
use praxis_policy_builtins::pdps::cedar_direct::request::parse;

fn call(args: &str) -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Cedar,
        args: serde_yaml::from_str(args).unwrap(),
    }
}

/// A minimal well-formed call. Tests vary the bag, not this.
fn read_doc() -> PdpCall {
    call("action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: doc-1\n")
}

/// Render the parsed Cedar context back to a string. Cedar's `Context` has no
/// field accessor, so its `Debug` output is the only way to assert on what a
/// policy would see.
fn context_of(bag: &AttributeBag, args: &PdpCall) -> String {
    let parsed = parse(args, bag, None).expect("call must parse");
    format!("{:?}", parsed.context)
}

// ---- the PPE-provided context blocks ------------------------------------

#[test]
fn delegation_depth_and_flag_reach_the_context() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("delegation.depth", 2_i64);
    bag.set("delegated", true);
    let ctx = context_of(&bag, &read_doc());
    assert!(ctx.contains("delegation"), "{ctx}");
    assert!(ctx.contains("depth"), "{ctx}");
    assert!(ctx.contains("delegated"), "{ctx}");
}

/// The delegation block is omitted entirely when nothing delegated, rather than
/// emitted empty. A policy checking `context has delegation` must be able to
/// tell the difference.
#[test]
fn no_delegation_keys_means_no_delegation_block() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    let ctx = context_of(&bag, &read_doc());
    assert!(
        !ctx.contains("delegation"),
        "absence, not an empty record: {ctx}"
    );
}

#[test]
fn meta_entity_scope_and_tags_reach_the_context() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("meta.entity_type", "tool");
    bag.set("meta.entity_name", "search_repos");
    bag.set("meta.scope", "read");
    bag.set(
        "meta.tags",
        ["urgent".to_owned()]
            .into_iter()
            .collect::<std::collections::HashSet<String>>(),
    );
    let ctx = context_of(&bag, &read_doc());
    for expected in ["entity_type", "search_repos", "scope", "tags", "urgent"] {
        assert!(ctx.contains(expected), "missing {expected} in {ctx}");
    }
}

#[test]
fn security_labels_and_classification_reach_the_context() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set(
        "security.labels",
        ["pii".to_owned()]
            .into_iter()
            .collect::<std::collections::HashSet<String>>(),
    );
    bag.set("security.classification", "internal");
    let ctx = context_of(&bag, &read_doc());
    assert!(ctx.contains("labels") && ctx.contains("pii"), "{ctx}");
    assert!(
        ctx.contains("classification") && ctx.contains("internal"),
        "{ctx}"
    );
}

#[test]
fn authenticated_is_passed_through_as_a_top_level_shorthand() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("authenticated", true);
    let ctx = context_of(&bag, &read_doc());
    assert!(ctx.contains("authenticated"), "{ctx}");
}

// ---- the operator overlay ------------------------------------------------

#[test]
fn an_operator_context_key_is_merged_in() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    let args = call(
        "action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: doc-1\ncontext:\n  \
         tenant: acme\n",
    );
    let ctx = context_of(&bag, &args);
    assert!(ctx.contains("tenant") && ctx.contains("acme"), "{ctx}");
}

/// The documented precedence: on a top-level collision the operator's value
/// replaces the PPE-provided one, because they wrote it explicitly. The merge is
/// deliberately shallow, so the whole block is replaced rather than deep-merged.
#[test]
fn an_operator_key_replaces_the_ppe_provided_block_on_collision() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("security.classification", "internal");
    let args = call(
        "action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: doc-1\ncontext:\n  \
         security:\n    custom: operator-value\n",
    );
    let ctx = context_of(&bag, &args);
    assert!(
        ctx.contains("operator-value"),
        "operator intent wins: {ctx}"
    );
    assert!(
        !ctx.contains("internal"),
        "the merge is shallow, so the block is replaced whole: {ctx}"
    );
}

/// A non-mapping `context:` is ignored rather than fatal. The merge helper
/// returns early, so the PPE-provided context still reaches the policy.
#[test]
fn a_non_mapping_operator_context_leaves_the_ppe_context_intact() {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("authenticated", true);
    let args = call(
        "action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: doc-1\ncontext: \
         just-a-string\n",
    );
    let ctx = context_of(&bag, &args);
    assert!(ctx.contains("authenticated"), "{ctx}");
}

// ---- parse rejections ----------------------------------------------------

fn parse_err(args: &str) -> String {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    let Err(e) = parse(&call(args), &bag, None) else {
        panic!("this call must be rejected")
    };
    e.to_string()
}

#[test]
fn args_that_are_not_a_mapping_are_rejected() {
    let e = parse_err("just-a-string\n");
    assert!(e.contains("must be a mapping"), "{e}");
}

#[test]
fn a_missing_action_is_rejected_and_the_message_shows_the_expected_form() {
    let e = parse_err("resource:\n  type: Document\n  id: doc-1\n");
    assert!(e.contains("`action` missing"), "{e}");
    assert!(
        e.contains("Action::"),
        "the message must show the shape to write: {e}"
    );
}

/// A bare action name is the likely mistake, and Cedar needs a fully-qualified
/// UID. The message has to say which value was wrong.
#[test]
fn an_action_that_is_not_a_valid_entity_uid_is_rejected() {
    let e = parse_err("action: read\nresource:\n  type: Document\n  id: doc-1\n");
    assert!(e.contains("not a valid EntityUid"), "{e}");
    assert!(e.contains("read"), "the message must quote the value: {e}");
}

#[test]
fn a_missing_resource_is_rejected() {
    let e = parse_err("action: 'Action::\"read\"'\n");
    assert!(e.contains("`resource` missing"), "{e}");
}
