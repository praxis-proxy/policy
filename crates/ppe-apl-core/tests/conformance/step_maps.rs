// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The step-map key set, which the grammar states is closed.
//
// It was open: every key the earlier branches did not claim was split at `(` and
// its prefix resolved through a mapping that turned anything unknown into
// `Custom`. Two faults came out of that one fallback. A misspelling such as
// `whens:` compiled to a PDP lookup for a dialect named `whens`, so a typo became
// a runtime resolver miss rather than a load error. And `pdp(workload):`, the
// documented spelling for a custom dialect, resolved `pdp` with `workload` as its
// argument, so the resolver registered for `workload` could never be reached.

use praxis_policy_apl_core::test_util::compile_test_route;
use praxis_policy_apl_core::{Effect, PdpCall, PdpDialect};

/// Compile a one-step `pre_invocation:` block, which is how a step map reaches
/// the compiler. `body` is indented to sit under the key.
fn step_map(yaml_block: &str) -> Result<Effect, String> {
    let indented: String = yaml_block
        .lines()
        .map(|l| format!("        {l}\n"))
        .collect();
    let yaml = format!("route:\n  authorization:\n    pre_invocation:\n      -\n{indented}");
    let route = compile_test_route("test", &yaml).map_err(|e| e.to_string())?;
    route
        .pre_invocation
        .into_iter()
        .next()
        .ok_or_else(|| "the block compiled to no effect".to_owned())
}

fn step_err(yaml_block: &str) -> String {
    step_map(yaml_block).expect_err("this step map must be rejected")
}

/// The PDP call a step map compiled to, or a panic naming what came back.
fn pdp_of(yaml_block: &str) -> PdpCall {
    match step_map(yaml_block).expect("this step map must parse") {
        Effect::Pdp { call, .. } => call,
        other => panic!("expected Effect::Pdp, got {other:?}"),
    }
}

fn names_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "the message must name `{needle}`: {haystack}"
        );
    }
}

// ---- `pdp(name)` names the custom dialect -------------------------------

/// The whole point of the spelling. `pdp(workload):` has to resolve `workload`,
/// or a host that registers a `workload` resolver watches its steps go nowhere.
#[test]
fn a_custom_dialect_resolves_the_name_in_the_parens() {
    let call = pdp_of("pdp(workload):\n  on_deny: [deny]\n");
    assert_eq!(call.dialect, PdpDialect::Custom("workload".to_owned()));
}

/// A custom dialect carries no call signature, since the parens hold the name.
/// Its arguments come from the body map, the way `cedar:`'s do.
#[test]
fn a_custom_dialect_reads_its_args_from_the_body() {
    let call = pdp_of("pdp(workload):\n  path: hr/deny\n  on_deny: [deny]\n");
    assert_eq!(call.dialect, PdpDialect::Custom("workload".to_owned()));
    assert_eq!(
        call.args.get("path").and_then(serde_yaml::Value::as_str),
        Some("hr/deny"),
        "the body's non-reaction keys are the call's args: {:?}",
        call.args
    );
}

/// A quoted name is read as a literal, so the resolver sees what was written
/// without the quotes.
#[test]
fn a_quoted_custom_dialect_name_is_read_as_a_literal() {
    let call = pdp_of("pdp(\"workload-eu\"):\n  on_deny: [deny]\n");
    assert_eq!(call.dialect, PdpDialect::Custom("workload-eu".to_owned()));
}

#[test]
fn an_empty_custom_dialect_name_is_rejected() {
    names_all(
        &step_err("pdp():\n  on_deny: [deny]\n"),
        ["pdp(name)"].as_slice(),
    );
}

// ---- the closed key set ------------------------------------------------

/// The grammar's own example of a misspelling. It used to compile to a PDP
/// lookup for a dialect named `whens`.
#[test]
fn a_misspelled_when_key_is_rejected_naming_the_set() {
    names_all(
        &step_err("whens:\n  on_deny: [deny]\n"),
        ["whens", "when:", "pdp(whens)"].as_slice(),
    );
}

/// The refusal names `pdp(name):`, because a host that really did mean a custom
/// dialect needs to be told the spelling rather than left guessing.
#[test]
fn an_unknown_key_is_pointed_at_the_custom_dialect_spelling() {
    names_all(
        &step_err("workload:\n  on_deny: [deny]\n"),
        ["pdp(workload)"].as_slice(),
    );
}

// ---- the built-in dialects still parse in both spellings ---------------

#[test]
fn a_bare_builtin_dialect_parses() {
    for (block, expected) in [
        ("cedar:\n  action: read\n", PdpDialect::Cedar),
        ("cel:\n  expr: \"1 == 1\"\n", PdpDialect::Cel),
    ] {
        assert_eq!(pdp_of(block).dialect, expected, "for {block:?}");
    }
}

#[test]
fn a_builtin_dialect_call_signature_parses_and_strips_its_quotes() {
    let call = pdp_of("opa(\"hr/deny\"):\n  on_deny: [deny]\n");
    assert_eq!(call.dialect, PdpDialect::Opa);
    assert_eq!(
        call.args.as_str(),
        Some("hr/deny"),
        "quotes come off: {:?}",
        call.args
    );
}

/// A call signature has to be terminated by its `)`. Trailing text used to be
/// dropped, so `opa(x) y:` silently became `opa(x)`.
#[test]
fn text_after_the_closing_paren_is_rejected() {
    names_all(
        &step_err("opa(x) y:\n  on_deny: [deny]\n"),
        [")"].as_slice(),
    );
}

#[test]
fn a_missing_closing_paren_is_rejected() {
    names_all(
        &step_err("opa(x:\n  on_deny: [deny]\n"),
        ["missing `)`"].as_slice(),
    );
}

// ---- the keys that branch before the dialect logic --------------------

/// Each of these is claimed by its own production above the PDP read, so the
/// closure must not have swallowed them.
#[test]
fn the_non_pdp_step_map_keys_still_parse() {
    for block in [
        "when: authenticated\ndo: allow\n",
        "sequential:\n  - deny\n",
        "parallel:\n  - deny\n",
        "delegate:\n  plugin: workday-oauth\n  target: workday-api\n",
        "restrict:\n  allow_regions: [eu]\n",
    ] {
        step_map(block).unwrap_or_else(|e| panic!("`{block}` must parse: {e}"));
    }
}

/// A key quoted in YAML keeps the `:` the parse already consumed, which is what
/// `- 'opa("p/q"):':` produces. One redundant trailing colon is tolerated, so the
/// terminator check above is about text that would otherwise be dropped.
#[test]
fn one_redundant_trailing_colon_on_the_key_is_tolerated() {
    assert_eq!(
        pdp_of("'opa(\"p/q\"):':\n  on_deny: [deny]\n").dialect,
        PdpDialect::Opa
    );
    assert_eq!(
        pdp_of("'cedar:':\n  action: read\n").dialect,
        PdpDialect::Cedar
    );
}
