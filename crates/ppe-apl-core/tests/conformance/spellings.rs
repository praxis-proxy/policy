// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// One rule, written three ways, put through the same assertion.
//
// A rule is a predicate and an action, and a document may write that as a string,
// as `when:` / `do:`, or as the multi-effect shorthand. The three reach three
// parser entry points and only the string form goes through `parse_rule`, so a
// rule-level case that calls `parse_rule` covers one spelling out of three. Two
// guards were in that state: a field operation in rule position and
// `require(...): allow` were both accepted as maps.

use praxis_policy_apl_core::test_util::compile_test_route;

/// The three spellings of one predicate-and-action rule, as `pre_invocation:`
/// blocks. Single-quoted YAML so a predicate may carry `"` and `:`.
fn three_spellings(predicate: &str, action: &str) -> [(&'static str, String); 3] {
    let q = predicate.replace('\'', "''");
    [
        ("string", format!("      - '{q}: {action}'\n")),
        (
            "when/do",
            format!("      - when: '{q}'\n        do: {action}\n"),
        ),
        ("shorthand", format!("      - '{q}': [{action}]\n")),
    ]
}

fn compile_step_block(block: &str) -> Result<(), String> {
    let yaml = format!("route:\n  authorization:\n    pre_invocation:\n{block}");
    compile_test_route("test", &yaml)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Assert `predicate: action` is refused in all three spellings, each refusal
/// naming every one of `needles`.
///
/// The needles are what keeps this honest. A spelling that fails only incidentally,
/// on a generic lexer error rather than the named guard, passes an `is_err` check
/// and tells an operator nothing.
pub(crate) fn rejected_in_all_three_spellings(predicate: &str, action: &str, needles: &[&str]) {
    for (name, block) in three_spellings(predicate, action) {
        let message = compile_step_block(&block).expect_err(&format!(
            "`{predicate}: {action}` must be refused in its {name} spelling:\n{block}"
        ));
        for needle in needles {
            assert!(
                message.contains(needle),
                "the {name} spelling must name `{needle}`, and reports: {message}"
            );
        }
    }
}

/// The other half: a rule the guards must leave alone stays legal in all three
/// spellings, so a guard cannot be widened into refusing a legal document.
pub(crate) fn accepted_in_all_three_spellings(predicate: &str, action: &str) {
    for (name, block) in three_spellings(predicate, action) {
        compile_step_block(&block).unwrap_or_else(|e| {
            panic!("`{predicate}: {action}` must parse in its {name} spelling: {e}")
        });
    }
}
