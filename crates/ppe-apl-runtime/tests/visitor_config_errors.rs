// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Invalid wiring must fail at load so a missing dependency cannot silently
// disable policy enforcement or discard session state.

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

#[test]
fn a_config_with_no_wiring_block_loads() {
    loads("");
}

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

#[test]
fn the_reported_index_identifies_which_pdp_entry_failed() {
    let e = load_err("global:\n  pdp:\n    - kind: cel\n    - kind: alsobad\n");
    assert!(
        e.contains("pdp[0]") || e.contains("pdp[1]"),
        "an index must appear: {e}"
    );
}

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

#[test]
fn a_session_store_kind_with_no_registered_factory_is_rejected() {
    let e = load_err("global:\n  session_store:\n    kind: valkey\n");
    assert!(e.contains("valkey"), "the message must quote the kind: {e}");
    assert!(
        e.contains("register_session_store_factory"),
        "and name the call that fixes it: {e}"
    );
}

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

#[test]
fn the_removed_key_error_names_the_scope() {
    let e = load_err("global:\n  defaults:\n    tool:\n      identity:\n        - kind: jwt\n");
    assert!(
        e.contains("global.defaults.tool"),
        "the message must locate the stale key: {e}"
    );
}

#[test]
fn a_visitor_error_is_attributed_to_the_visitor() {
    let e = load_err("global:\n  pdp:\n    - kind: nonexistent\n");
    assert!(
        e.contains("apl"),
        "the error must name the visitor that raised it: {e}"
    );
}

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

#[test]
fn an_attribute_file_that_does_not_exist_is_rejected() {
    let e = load_err("global:\n  attribute_files:\n    - /nonexistent/praxis-attrs.yaml\n");
    assert!(
        e.contains("praxis-attrs.yaml") || e.contains("attribute"),
        "the message must point at the file it could not read: {e}"
    );
}

#[test]
fn an_empty_attribute_files_list_loads() {
    loads("global:\n  attribute_files: []\n");
}

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
fn a_recursive_path_naming_an_unknown_field_on_a_prompt_result_is_refused() {
    let e = load_err(
        r#"routes:
  - prompt: summarize-*
    result:
      "**.contnet": redact
"#,
    );
    assert!(
        e.contains("`**.contnet`") && e.contains("no field `contnet`"),
        "a recursive path naming no prompt result field must be refused: {e}"
    );
}

#[test]
fn a_redacted_field_in_another_case_loads() {
    loads(
        r#"routes:
  - resource: hr://employees/*
    result:
      CONTENT: redact
      ANNOTATIONS.ssn: redact
    authorization:
      post_invocation:
        - when: "!perm.view_title"
          do: "result.Title | redact"
  - prompt: summarize-*
    result:
      Description: redact
"#,
    );
}

#[test]
fn a_non_redacting_field_in_another_case_is_refused() {
    let e = load_err(
        r#"routes:
  - resource: hr://employees/*
    result:
      CONTENT: "str"
"#,
    );
    assert!(
        e.contains("`CONTENT`") && e.contains("no field `CONTENT`"),
        "a non-redacting stage must keep strict spelling: {e}"
    );
}

#[test]
fn a_recursive_path_naming_a_prompt_result_field_in_another_case_loads() {
    loads(
        r#"routes:
  - prompt: summarize-*
    result:
      "**.Content": redact
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

#[test]
fn a_recursive_path_inside_opaque_content_is_refused() {
    let e = load_err(
        "routes:\n  - prompt: summarize-*\n    result:\n      \"**.content.ssn\": redact\n",
    );
    assert!(
        e.contains("single value"),
        "nested access inside opaque content must fail: {e}"
    );
}

#[test]
fn a_repeated_recursive_path_with_a_typo_is_refused() {
    let e = load_err(
        "routes:\n  - prompt: summarize-*\n    result:\n      \"**.**.contnet\": redact\n",
    );
    assert!(
        e.contains("contnet"),
        "unknown recursive path must fail: {e}"
    );
}

#[test]
fn a_repeated_recursive_write_to_a_read_only_field_is_refused() {
    let e = load_err(
        "routes:\n  - resource: hr://employees/*\n    result:\n      \"**.**.uri\": redact\n",
    );
    assert!(
        e.contains("read-only"),
        "recursive write reaching root uri must fail: {e}"
    );
}

#[test]
fn valid_recursive_paths_and_redaction_case_variants_load() {
    loads(
        "routes:\n  - resource: hr://employees/*\n    result:\n      \"**.annotations.uri\": redact\n      \"**.ssn\": redact\n      CONTENT: redact\n      ANNOTATIONS.ssn: redact\n  - prompt: summarize-*\n    result:\n      \"**.Content\": redact\n      \"**.**.Content\": redact\n      \"content.**\": redact\n",
    );
}

#[test]
fn recursive_icon_descendant_writes_are_refused() {
    for path in [
        "**.src",
        "**.MIME_TYPE",
        "**.sizes",
        "**.0.src",
        "**.3.src",
        "**.sizes.3",
        "**.**.src",
    ] {
        let e = load_err(&format!(
            "routes:\n  - resource: hr://employees/*\n    result:\n      \"{path}\": redact\n"
        ));
        assert!(
            e.contains("read-only"),
            "{path} must not rewrite icons: {e}"
        );
    }
    loads(
        "routes:\n  - resource: hr://employees/*\n    result:\n      annotations.src: redact\n      \"**.annotations.src\": redact\n",
    );
}

#[test]
fn icon_reads_and_writable_recursive_descendants_load() {
    loads(
        "routes:\n  - resource: hr://employees/*\n    result:\n      icons.src: str\n      icons.3.mime_type: str\n      icons.sizes.0: str\n      \"**.uri.label\": redact\n",
    );
    let e = load_err(
        "routes:\n  - resource: hr://employees/*\n    result:\n      icons.contnet: str\n",
    );
    assert!(e.contains("icons"), "unknown icon fields must fail: {e}");
}

#[test]
fn fixed_condition_fields_and_inherited_global_rules_are_validated() {
    for scope in [
        "routes:\n  - resource: '*'\n    authorization:\n      post_invocation:\n        - \"result.contnet == 'secret': deny\"\n",
        "routes:\n  - resource: '*'\n    authorization:\n      post_invocation:\n        - when: \"result.uri != ''\"\n          do: \"result.content | redact(result.contnet == 'secret')\"\n",
        "global:\n  authorization:\n    post_invocation:\n      - \"result.contnet == 'secret': deny\"\nroutes:\n  - resource: '*'\n",
        "global:\n  authorization:\n    post_invocation:\n      - when: \"result.uri != ''\"\n        do: \"result.uri | redact\"\nroutes:\n  - resource: '*'\n",
    ] {
        let e = load_err(scope);
        assert!(
            e.contains("contnet") || e.contains("read-only"),
            "fixed field errors must fail at load: {e}"
        );
    }
    loads(
        "global:\n  authorization:\n    post_invocation:\n      - \"result.content == 'secret': deny\"\nroutes:\n  - resource: '*'\n  - prompt: '*'\n",
    );
}

#[test]
fn icon_descendants_in_conditions_are_refused_as_unavailable_attributes() {
    let e = load_err(
        "routes:\n  - resource: '*'\n    authorization:\n      post_invocation:\n        - \"result.icons.0.src == 'bad': deny\"\n",
    );
    assert!(
        e.contains("field pipelines"),
        "icon objects have no descendant predicate attributes: {e}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn in_policy_mode(yaml: &str) -> String {
    format!("engine_settings:\n  dispatch: policy\n{yaml}")
}

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
