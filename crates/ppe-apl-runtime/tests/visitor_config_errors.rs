// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What the APL visitor does with wiring config it cannot honour.
//
// `global.apl.pdp` and `global.apl.session_store` name a factory by `kind`. If
// the kind is missing, the block is the wrong shape, or no factory is registered
// for it, the load has to fail and say which. The alternative is a gateway that
// starts with no decision point and allows everything a `pdp(...)` step was
// meant to gate, or with the in-memory session store silently standing in for
// the shared one, which loses taint between requests.
//
// Every case here is reachable from operator-written YAML.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::sync::Arc;

use praxis_policy_apl_runtime::{AplOptions, register_apl};
use praxis_policy_core::engine::PolicyEngine;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// The control. Everything below differs from this by one deliberate mistake, so
/// without it a rejection could be attributable to something else in the block.
#[test]
fn a_config_with_no_wiring_block_loads() {
    loads("plugin_settings:\n  routing_enabled: true\n");
}

// global.apl.pdp

#[test]
fn a_pdp_entry_that_is_not_a_mapping_is_rejected_with_its_index() {
    let e = load_err("global:\n  apl:\n    pdp:\n      - just-a-string\n");
    assert!(
        e.contains("pdp[0]"),
        "the message must index the entry: {e}"
    );
    assert!(e.contains("mapping"), "{e}");
}

#[test]
fn a_pdp_entry_with_no_kind_is_rejected() {
    let e = load_err("global:\n  apl:\n    pdp:\n      - policy_text: \"permit\"\n");
    assert!(e.contains("pdp[0]"), "{e}");
    assert!(
        e.contains("`kind:`"),
        "the message must name the missing field: {e}"
    );
}

/// The case an operator hits most: a `kind` the host never registered. The
/// message has to say what to call, because otherwise the only symptom is a
/// `pdp(...)` step that never resolves.
#[test]
fn a_pdp_kind_with_no_registered_factory_is_rejected_and_says_what_to_call() {
    let e = load_err("global:\n  apl:\n    pdp:\n      - kind: nonexistent\n");
    assert!(
        e.contains("nonexistent"),
        "the message must quote the kind: {e}"
    );
    assert!(
        e.contains("register_pdp_factory"),
        "and name the call that fixes it: {e}"
    );
}

/// The index is not decoration: with several entries it is the only way to tell
/// which one is wrong.
#[test]
fn the_reported_index_identifies_which_pdp_entry_failed() {
    let e = load_err("global:\n  apl:\n    pdp:\n      - kind: cel\n      - kind: alsobad\n");
    assert!(
        e.contains("pdp[0]") || e.contains("pdp[1]"),
        "an index must appear: {e}"
    );
}

// global.apl.session_store

#[test]
fn a_session_store_that_is_not_a_mapping_is_rejected() {
    let e = load_err("global:\n  apl:\n    session_store: just-a-string\n");
    assert!(e.contains("session_store"), "{e}");
    assert!(e.contains("mapping"), "{e}");
}

#[test]
fn a_session_store_with_no_kind_is_rejected() {
    let e = load_err("global:\n  apl:\n    session_store:\n      ttl_seconds: 3600\n");
    assert!(e.contains("session_store"), "{e}");
    assert!(e.contains("`kind:`"), "{e}");
}

/// Falling back to the in-process store here would be the dangerous outcome: a
/// multi-node deployment would appear to work while losing accumulated taint
/// between requests that land on different nodes.
#[test]
fn a_session_store_kind_with_no_registered_factory_is_rejected() {
    let e = load_err("global:\n  apl:\n    session_store:\n      kind: valkey\n");
    assert!(e.contains("valkey"), "the message must quote the kind: {e}");
    assert!(
        e.contains("register_session_store_factory"),
        "and name the call that fixes it: {e}"
    );
}

// renamed and misplaced keys

/// `identity:` was renamed to `authentication:`, and a stale one is rejected
/// rather than ignored. An unknown field is dropped silently, which would leave
/// its authentication steps unrun: a fail-open. Checked at each scope the guard
/// covers, since one arm per scope means one arm that can be missed.
#[test]
fn the_renamed_identity_key_is_rejected_at_every_scope_it_guards() {
    for yaml in [
        "global:\n  identity:\n    - kind: jwt\n",
        "global:\n  defaults:\n    tool:\n      identity:\n        - kind: jwt\n",
        "global:\n  policies:\n    some-tag:\n      identity:\n        - kind: jwt\n",
    ] {
        let e = load_err(yaml);
        assert!(
            e.contains("renamed to `authentication`"),
            "a stale `identity:` must be refused, not dropped: {e}"
        );
    }
}

/// The scope is named, because with several blocks the message is the only thing
/// pointing at which one to edit.
#[test]
fn the_renamed_key_error_names_the_scope() {
    let e = load_err("global:\n  defaults:\n    tool:\n      identity:\n        - kind: jwt\n");
    assert!(
        e.contains("global.defaults.tool"),
        "the message must locate the stale key: {e}"
    );
}

/// Errors carry the visitor's name so an operator with several orchestrators
/// registered knows which one refused the config.
#[test]
fn a_visitor_error_is_attributed_to_the_visitor() {
    let e = load_err("global:\n  apl:\n    pdp:\n      - kind: nonexistent\n");
    assert!(
        e.contains("apl"),
        "the error must name the visitor that raised it: {e}"
    );
}

// global.apl.attribute_files

/// `attribute_files` supplies the static `data.*` tree a policy reads. Every way
/// of getting it wrong has to fail the load.
///
/// A silently ignored bad path is the failure that matters: every `data.*`
/// predicate would then read from an empty tree, so a rule like
/// `data.allowed_tools contains name` matches nothing and the route it guards
/// either opens or closes wholesale, with no error anywhere to explain it.
#[test]
fn a_malformed_attribute_files_block_is_rejected() {
    let e = load_err("global:\n  apl:\n    attribute_files: attrs.yaml\n");
    assert!(
        e.contains("attribute_files"),
        "the message must name the field: {e}"
    );
    assert!(e.contains("list"), "and say it wanted a list: {e}");
}

#[test]
fn an_attribute_files_entry_that_is_not_a_path_is_rejected_with_its_index() {
    let e = load_err("global:\n  apl:\n    attribute_files:\n      - 42\n");
    assert!(
        e.contains("attribute_files[0]"),
        "the message must index the bad entry: {e}"
    );
}

/// A path that does not exist is a load failure, not an empty tree.
#[test]
fn an_attribute_file_that_does_not_exist_is_rejected() {
    let e =
        load_err("global:\n  apl:\n    attribute_files:\n      - /nonexistent/praxis-attrs.yaml\n");
    assert!(
        e.contains("praxis-attrs.yaml") || e.contains("attribute"),
        "the message must point at the file it could not read: {e}"
    );
}

/// An empty list is not an error: it means the same as omitting the key. Without
/// this, the rejections above could be coming from the key being present at all.
#[test]
fn an_empty_attribute_files_list_loads() {
    loads("global:\n  apl:\n    attribute_files: []\n");
}

// Cross-layer elicitation stacking

/// The parser rejects two elicits written in a single route block; the visitor
/// adds the case the parser cannot see, because it only exists once layers are
/// stacked: an elicit inherited from the `global` layer plus one on the route,
/// landing in the same phase. Both would share the one per-request elicitation
/// id, so the second (a weaker `confirm`) would resolve against the first's
/// (`require_approval`) approval. It must be rejected at load, not mis-evaluated.
#[test]
fn a_global_and_route_elicit_in_one_phase_is_rejected() {
    let e = load_err(
        "plugin_settings:\n  routing_enabled: true\nglobal:\n  apl:\n    pre_invocation:\n      - \"require_approval(manager-approver, from: user.manager)\"\nroutes:\n  - tool: get_compensation\n    apl:\n      pre_invocation:\n        - \"confirm(user-confirm, from: user.sub)\"\n",
    );
    assert!(
        e.contains("at most one elicitation per phase"),
        "a global+route elicit stacked into one phase must be rejected: {e}"
    );
}

/// The control: the same two elicits split across the pre and post phases are
/// separate evaluation walks with separate ids, so the config loads. Without it,
/// the rejection above could be coming from having two elicits at all rather
/// than two in one phase.
#[test]
fn a_global_pre_elicit_and_route_post_elicit_load() {
    loads(
        "plugin_settings:\n  routing_enabled: true\nglobal:\n  apl:\n    pre_invocation:\n      - \"require_approval(manager-approver, from: user.manager)\"\nroutes:\n  - tool: get_compensation\n    apl:\n      post_invocation:\n        - \"confirm(user-confirm, from: user.sub)\"\n",
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load with the APL visitor installed and no factories registered, and return
/// the error text. Registering none is the point for most cases here: it is what
/// an operator hits when they name a `kind` the host never wired up.
fn load_err(yaml: &str) -> String {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(&mgr, AplOptions::in_process());
    match mgr.load_config_yaml(yaml) {
        Ok(()) => panic!("this config must not load"),
        Err(e) => format!("{e}"),
    }
}

fn loads(yaml: &str) {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(yaml).expect("this config must load");
}
