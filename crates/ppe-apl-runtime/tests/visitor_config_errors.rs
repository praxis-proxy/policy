// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What the APL visitor does with wiring config it cannot honour.
//
// `global.pdp` and `global.session_store` name a factory by `kind`. If
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

/// The blocks below are all policy-mode keys, so every case declares the mode.
/// Prefixing it here keeps each literal about the one mistake it encodes.
fn in_policy_mode(yaml: &str) -> String {
    format!("engine_settings:\n  dispatch: policy\n{yaml}")
}

/// Load with the APL visitor installed and no factories registered, and return
/// the error text. Registering none is the point for most cases here: it is what
/// an operator hits when they name a `kind` the host never wired up.
fn load_err(yaml: &str) -> String {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(&mgr, AplOptions::in_process());
    match mgr.load_config_yaml(&in_policy_mode(yaml)) {
        Ok(()) => panic!("this config must not load"),
        Err(e) => format!("{e}"),
    }
}

fn loads(yaml: &str) {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(&in_policy_mode(yaml))
        .expect("this config must load");
}

/// The control. Everything below differs from this by one deliberate mistake, so
/// without it a rejection could be attributable to something else in the block.
#[test]
fn a_config_with_no_wiring_block_loads() {
    loads("");
}

// ---- global.pdp ----------------------------------------------------

#[test]
fn a_pdp_entry_that_is_not_a_mapping_is_rejected_with_its_index() {
    let e = load_err("global:\n  pdp:\n    - just-a-string\n");
    assert!(
        e.contains("pdp[0]"),
        "the message must index the entry: {e}"
    );
    assert!(e.contains("mapping"), "{e}");
}

#[test]
fn a_pdp_entry_with_no_kind_is_rejected() {
    let e = load_err("global:\n  pdp:\n    - policy_text: \"permit\"\n");
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
    let e = load_err("global:\n  pdp:\n    - kind: nonexistent\n");
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
    let e = load_err("global:\n  pdp:\n    - kind: cel\n    - kind: alsobad\n");
    assert!(
        e.contains("pdp[0]") || e.contains("pdp[1]"),
        "an index must appear: {e}"
    );
}

// ---- global.session_store ------------------------------------------

#[test]
fn a_session_store_that_is_not_a_mapping_is_rejected() {
    let e = load_err("global:\n  session_store: just-a-string\n");
    assert!(e.contains("session_store"), "{e}");
    assert!(e.contains("mapping"), "{e}");
}

#[test]
fn a_session_store_with_no_kind_is_rejected() {
    let e = load_err("global:\n  session_store:\n    ttl_seconds: 3600\n");
    assert!(e.contains("session_store"), "{e}");
    assert!(e.contains("`kind:`"), "{e}");
}

/// Falling back to the in-process store here would be the dangerous outcome: a
/// multi-node deployment would appear to work while losing accumulated taint
/// between requests that land on different nodes.
#[test]
fn a_session_store_kind_with_no_registered_factory_is_rejected() {
    let e = load_err("global:\n  session_store:\n    kind: valkey\n");
    assert!(e.contains("valkey"), "the message must quote the kind: {e}");
    assert!(
        e.contains("register_session_store_factory"),
        "and name the call that fixes it: {e}"
    );
}

// ---- removed and misplaced keys ----------------------------------------

/// `identity:` was replaced by `authentication:`, and a stale one is rejected
/// rather than ignored. An unknown field is dropped silently, which would leave
/// its authentication steps unrun: a fail-open. Checked at each scope that reads
/// the block, since one arm per scope means one arm that can be missed.
#[test]
fn the_removed_identity_key_is_rejected_at_every_scope_that_reads_it() {
    for yaml in [
        "global:\n  identity:\n    - kind: jwt\n",
        "global:\n  defaults:\n    tool:\n      identity:\n        - kind: jwt\n",
        "groups:\n  some-tag:\n    identity:\n      - kind: jwt\n",
    ] {
        let e = load_err(yaml);
        assert!(
            e.contains("replaced by `authentication`"),
            "a stale `identity:` must be refused, not dropped: {e}"
        );
    }
}

/// The scope is named, because with several blocks the message is the only thing
/// pointing at which one to edit.
#[test]
fn the_removed_key_error_names_the_scope() {
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
    let e = load_err("global:\n  pdp:\n    - kind: nonexistent\n");
    assert!(
        e.contains("apl"),
        "the error must name the visitor that raised it: {e}"
    );
}

// ---- global.attribute_files ----------------------------------------

/// `attribute_files` supplies the static `data.*` tree a policy reads. Every way
/// of getting it wrong has to fail the load.
///
/// A silently ignored bad path is the failure that matters: every `data.*`
/// predicate would then read from an empty tree, so a rule like
/// `data.allowed_tools contains name` matches nothing and the route it guards
/// either opens or closes wholesale, with no error anywhere to explain it.
#[test]
fn a_malformed_attribute_files_block_is_rejected() {
    let e = load_err("global:\n  attribute_files: attrs.yaml\n");
    assert!(
        e.contains("attribute_files"),
        "the message must name the field: {e}"
    );
    assert!(e.contains("list"), "and say it wanted a list: {e}");
}

#[test]
fn an_attribute_files_entry_that_is_not_a_path_is_rejected_with_its_index() {
    let e = load_err("global:\n  attribute_files:\n    - 42\n");
    assert!(
        e.contains("attribute_files[0]"),
        "the message must index the bad entry: {e}"
    );
}

/// A path that does not exist is a load failure, not an empty tree.
#[test]
fn an_attribute_file_that_does_not_exist_is_rejected() {
    let e = load_err("global:\n  attribute_files:\n    - /nonexistent/praxis-attrs.yaml\n");
    assert!(
        e.contains("praxis-attrs.yaml") || e.contains("attribute"),
        "the message must point at the file it could not read: {e}"
    );
}

/// An empty list is not an error: it means the same as omitting the key. Without
/// this, the rejections above could be coming from the key being present at all.
#[test]
fn an_empty_attribute_files_list_loads() {
    loads("global:\n  attribute_files: []\n");
}

/// Cross-layer elicitations in one phase are rejected after route stacking.
#[test]
fn a_global_and_route_elicit_in_one_phase_is_rejected() {
    let e = load_err(
        r#"global:
  authorization:
    pre_invocation:
      - "require_approval(manager-approver, from: user.manager)"
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "confirm(user-confirm, from: user.sub)"
"#,
    );
    assert!(
        e.contains("at most one elicitation per phase"),
        "a global plus route elicit stacked into one phase must be rejected: {e}"
    );
}

/// Elicitations in separate phases remain valid.
#[test]
fn a_global_pre_elicit_and_route_post_elicit_load() {
    loads(
        r#"global:
  authorization:
    pre_invocation:
      - "require_approval(manager-approver, from: user.manager)"
routes:
  - tool: get_compensation
    authorization:
      post_invocation:
        - "confirm(user-confirm, from: user.sub)"
"#,
    );
}
