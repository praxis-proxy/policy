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

/// A mapping where a list was required used to be skipped, which left the
/// previous load's resolvers in place. A typo then keeps answering.
#[test]
fn a_pdp_value_that_is_not_a_list_is_rejected() {
    let e = load_err("global:\n  pdp:\n    kind: opa\n");
    assert!(
        e.contains("global.pdp"),
        "the message must name the field: {e}"
    );
    assert!(e.contains("list"), "and say it wanted a list: {e}");
}

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

// ---- writes to read-only envelope fields ------------------------------------

#[test]
fn an_args_block_writing_uri_on_a_resource_route_is_refused_as_read_only() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    args:
      uri: "str | redact"
"#,
    );
    assert!(
        e.contains("`args:`") && e.contains("`uri`") && e.contains("read-only"),
        "writing args.uri must be refused as read-only: {e}"
    );
}

#[test]
fn a_result_block_writing_uri_on_a_resource_route_is_refused_as_read_only() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    result:
      uri: "str | hash"
"#,
    );
    assert!(
        e.contains("`result:`") && e.contains("`uri`") && e.contains("read-only"),
        "writing result.uri must be refused as read-only: {e}"
    );
}

#[test]
fn writing_resource_type_on_a_resource_route_is_refused_in_either_block() {
    for block in ["args", "result"] {
        let e = load_err(&format!(
            "routes:\n  - resource: hr://employees/*\n    {block}:\n      resource_type: omit\n"
        ));
        assert!(
            e.contains(&format!("`{block}:`"))
                && e.contains("`resource_type`")
                && e.contains("read-only"),
            "writing {block}.resource_type must be refused as read-only: {e}"
        );
    }
}

#[test]
fn a_result_block_writing_icons_on_a_resource_route_is_refused_as_read_only() {
    let e = load_err(
        "routes:
  - resource: hr://employees/*
    result:
      icons: omit
",
    );
    assert!(
        e.contains("`icons`") && e.contains("read-only"),
        "writing result.icons must be refused as read-only: {e}"
    );
}

#[test]
fn a_result_block_writing_prompt_name_on_a_prompt_route_is_refused_as_read_only() {
    let e = load_err(
        "routes:
  - prompt: summarize-*
    result:
      prompt_name: redact
",
    );
    assert!(
        e.contains("`prompt_name`") && e.contains("`prompt:`") && e.contains("read-only"),
        "writing result.prompt_name must be refused as read-only: {e}"
    );
}

#[test]
fn a_result_block_writing_is_error_on_a_prompt_route_is_refused_as_read_only() {
    let e = load_err(
        r#"routes:
  - prompt: summarize-*
    result:
      is_error: "run(error-scrubber)"
"#,
    );
    assert!(
        e.contains("`is_error`") && e.contains("read-only"),
        "a plugin stage on result.is_error must be refused, since a plugin may rewrite it: {e}"
    );
}

#[test]
fn a_read_only_write_under_global_defaults_is_refused_naming_the_scope() {
    let e = load_err(
        "global:
  defaults:
    resource:
      result:
        uri: redact
routes:
  - resource: hr://employees/*
",
    );
    assert!(
        e.contains("global.defaults.resource") && e.contains("read-only"),
        "the refusal must name the defaults scope: {e}"
    );
}

#[test]
fn rules_reading_read_only_fields_still_load() {
    loads(
        r#"routes:
  - resource: hr://employees/*
    authorization:
      pre_invocation:
        - "args.uri == 'hr://employees/restricted': deny"
  - prompt: summarize-*
    authorization:
      post_invocation:
        - "result.is_error == true: deny"
"#,
    );
}

#[test]
fn a_check_only_stage_on_a_read_only_field_still_loads() {
    loads(
        r#"routes:
  - resource: hr://employees/*
    args:
      uri: "str | taint(hr_access)"
    result:
      uri: "str"
      content: "str | redact"
"#,
    );
}

#[test]
fn a_recursive_path_ending_in_a_read_only_field_is_refused() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    result:
      "**.uri": redact
"#,
    );
    assert!(
        e.contains("`**.uri`") && e.contains("read-only"),
        "a recursive path that can reach uri must be refused as read-only: {e}"
    );
}

#[test]
fn a_recursive_path_naming_a_read_only_field_in_another_case_is_refused() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    result:
      "**.URI": redact
"#,
    );
    assert!(
        e.contains("`**.URI`") && e.contains("read-only"),
        "redact matches keys without case, so `**.URI` reaches uri: {e}"
    );
    let e = load_err(
        r#"routes:
  - prompt: summarize-*
    result:
      "**.Is_Error": redact
"#,
    );
    assert!(
        e.contains("`**.Is_Error`") && e.contains("read-only"),
        "redact matches keys without case, so `**.Is_Error` reaches is_error: {e}"
    );
}

#[test]
fn a_recursive_path_through_a_non_root_field_is_not_refused() {
    // `**.annotations.uri` addresses `uri` inside `annotations`, not the
    // read-only root `uri`.  The segment after `**` is `annotations`.
    loads(
        r#"routes:
  - resource: hr://employees/*
    result:
      "**.annotations.uri": redact
"#,
    );
}

#[test]
fn a_rule_writing_uri_on_a_resource_route_is_refused_as_read_only() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    authorization:
      post_invocation:
        - when: "!perm.view_uri"
          do: "result.uri | redact"
"#,
    );
    assert!(
        e.contains("`post_invocation:` rule") && e.contains("`uri`") && e.contains("read-only"),
        "a rule's field operation on result.uri must be refused as read-only: {e}"
    );
}

#[test]
fn a_nested_rule_writing_prompt_name_is_refused_as_read_only() {
    let e = load_err(
        r#"routes:
  - prompt: summarize-*
    authorization:
      post_invocation:
        - when: "!perm.view_prompt"
          do:
            - "result.content | redact"
            - "result.prompt_name | redact"
"#,
    );
    assert!(
        e.contains("`prompt_name`") && e.contains("read-only"),
        "a field operation inside a do list must be checked too: {e}"
    );
}

// ---- unknown field paths on fixed envelopes ---------------------------------

#[test]
fn an_unknown_args_field_on_a_resource_route_is_refused_with_the_valid_fields() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    args:
      path: "str | redact"
"#,
    );
    assert!(
        e.contains("`args:`") && e.contains("`path`") && e.contains("selector"),
        "the refusal must name the block, the unknown field and the valid fields: {e}"
    );
}

#[test]
fn an_unknown_result_field_on_a_prompt_route_is_refused_with_the_valid_fields() {
    let e = load_err(
        r#"routes:
  - prompt: summarize-*
    result:
      body: "str | redact"
"#,
    );
    assert!(
        e.contains("`result:`")
            && e.contains("`body`")
            && e.contains("`prompt:`")
            && e.contains("error_message"),
        "the refusal must name the block, the field, the entity and the valid fields: {e}"
    );
}

#[test]
fn a_path_inside_resource_content_is_refused() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    result:
      content.ssn: "str | redact"
"#,
    );
    assert!(
        e.contains("`content.ssn`") && e.contains("single value"),
        "content is an opaque string, so a path inside it must be refused: {e}"
    );
}

#[test]
fn a_path_inside_annotations_loads() {
    loads(
        r#"routes:
  - resource: hr://employees/*
    result:
      annotations.audience: "str | redact"
"#,
    );
}

#[test]
fn a_rule_naming_an_unknown_result_field_on_a_resource_route_is_refused() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    authorization:
      post_invocation:
        - when: "!perm.view_ssn"
          do: "result.ssn | redact"
"#,
    );
    assert!(
        e.contains("`post_invocation:` rule") && e.contains("`ssn`") && e.contains("content"),
        "the refusal must name the rule, the unknown field and the valid fields: {e}"
    );
}

#[test]
fn a_group_naming_an_unknown_field_is_refused_on_a_resource_route_that_joins_it() {
    let e = load_err(
        r#"groups:
  pii:
    result:
      ssn: "str | redact"
routes:
  - resource: hr://employees/*
    groups: [pii]
"#,
    );
    assert!(
        e.contains("group 'pii'") && e.contains("resource:hr://employees/*") && e.contains("`ssn`"),
        "the refusal must name the group, the joining route and the field: {e}"
    );
}

#[test]
fn a_group_writing_a_read_only_field_is_refused_on_a_resource_route_that_joins_it() {
    let e = load_err(
        r#"groups:
  hide-uri:
    authorization:
      post_invocation:
        - when: "!perm.view_uri"
          do: "result.uri | redact"
routes:
  - resource: hr://employees/*
    meta:
      tags: [hide-uri]
"#,
    );
    assert!(
        e.contains("group 'hide-uri'") && e.contains("`uri`") && e.contains("read-only"),
        "a group joined through meta.tags must be checked too: {e}"
    );
}

#[test]
fn a_group_naming_a_tool_field_still_loads_on_a_tool_route() {
    loads(
        r#"groups:
  pii:
    result:
      ssn: "str | redact"
routes:
  - tool: get_compensation
    groups: [pii]
"#,
    );
}

#[test]
fn rules_writing_valid_fields_on_resource_and_prompt_routes_load() {
    loads(
        r#"routes:
  - resource: hr://employees/*
    authorization:
      pre_invocation:
        - when: "!perm.view_selector"
          do: "args.selector | redact"
      post_invocation:
        - when: "!perm.view_ssn"
          do:
            - "result.content | redact"
            - "result.annotations.audience | redact"
  - prompt: summarize-*
    authorization:
      pre_invocation:
        - when: "!perm.raw"
          do: "args.topic | redact"
      post_invocation:
        - when: "!perm.raw"
          do: "result.content | redact"
"#,
    );
}

#[test]
fn valid_fields_on_resource_and_prompt_routes_load() {
    loads(
        r#"routes:
  - resource: hr://employees/*
    args:
      selector: "str | redact"
      range_start: "int"
    result:
      content: "str | redact"
      mime_type: "str"
      size_bytes: "int"
  - prompt: summarize-*
    result:
      description: "str | redact"
      content: "str | redact"
      error_message: "str | redact"
"#,
    );
}

#[test]
fn a_recursive_path_loads_on_a_resource_route() {
    loads(
        r#"routes:
  - resource: hr://employees/*
    result:
      "**.ssn": redact
"#,
    );
}

#[test]
fn dynamic_argument_maps_are_not_checked_against_a_field_set() {
    loads(
        r#"routes:
  - prompt: summarize-*
    args:
      tone: "str | enum(terse, formal)"
  - tool: get_weather
    args:
      city: "str | redact"
    result:
      anything_at_all: "str | redact"
"#,
    );
}
