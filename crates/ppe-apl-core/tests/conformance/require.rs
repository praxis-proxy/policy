// `require(P)` means `!P`, and composes like any other predicate.
//
// It used to be a rule-level shorthand with its own hand-written parser, which
// accepted a comma-or-pipe list of bare identifiers and nothing else. So
// `require(delegation.depth < 3)` could not be written, nor `require(!delegated)`,
// nor `require(a) & b`, and the reason was not that any of them are ambiguous:
// there was simply no code path.
//
// What makes this safe to change is that the equivalence is structural, not merely
// semantic. Normalizing `Not` down over the tree folds `Not(IsTrue)` to `IsFalse`
// and distributes over `And` / `Or`, so every form already in use compiles to the
// exact tree it compiled to before. The first three tests here assert that against
// the IR, which is what lets the parser lose its special case without anyone
// having to re-verify what a deployed policy decides.
//
// A rule is stored as the condition under which it DENIES. `require(P)` therefore
// stores `!P`: deny when the requirement is not met.

use praxis_policy_apl_core::rules::{Condition, Effect, Expression};
use praxis_policy_apl_core::{parse_predicate, parse_rule};

/// `IsFalse(key)`, the shape a required bare attribute normalizes to.
fn is_false(key: &str) -> Expression {
    Expression::Condition(Condition::IsFalse {
        key: key.to_owned(),
    })
}

/// `IsTrue(key)`.
fn is_true(key: &str) -> Expression {
    Expression::Condition(Condition::IsTrue {
        key: key.to_owned(),
    })
}

/// The condition a rule denies under.
fn condition_of(src: &str) -> Expression {
    parse_rule(src, "test")
        .unwrap_or_else(|e| panic!("`{src}` must parse: {e}"))
        .condition
}

// ---- the three forms already in use, asserted against the IR ----------
//
// These are the cases a deployed policy can contain. If any of them changed
// shape, a rule that denied would start allowing or the reverse, so they are
// asserted structurally rather than by round-tripping text.

#[test]
fn a_single_required_attribute_is_its_negation() {
    assert_eq!(condition_of("require(role.hr)"), is_false("role.hr"));
}

/// A comma is conjunction inside the parens, so denying is "any one missing".
#[test]
fn a_comma_list_denies_when_any_one_is_missing() {
    assert_eq!(
        condition_of("require(a, b)"),
        Expression::Or(vec![is_false("a"), is_false("b")]),
        "`require(a, b)` is `!(a & b)`, which is `!a | !b`"
    );
}

/// A pipe is disjunction, so denying is "all of them missing".
#[test]
fn a_pipe_list_denies_only_when_all_are_missing() {
    assert_eq!(
        condition_of("require(team.engineering | team.security)"),
        Expression::And(vec![
            is_false("team.engineering"),
            is_false("team.security")
        ]),
        "`require(x | y)` is `!(x | y)`, which is `!x & !y`"
    );
}

// ---- what it can express now that it could not ------------------------

#[test]
fn a_comparison_may_be_required() {
    // `require(delegation.depth < 3)` had no code path: the hand-written parser
    // accepted only bare identifiers between the parens.
    let cond = condition_of("require(delegation.depth < 3)");
    let rendered = format!("{cond:?}");
    assert!(
        rendered.contains("delegation.depth"),
        "the comparison survives into the condition: {rendered}"
    );
    assert!(
        matches!(cond, Expression::Not(_)),
        "and it is negated, since a rule stores when it denies: {rendered}"
    );
}

#[test]
fn a_negation_may_be_required_and_folds() {
    // `require(!delegated)` is "deny unless delegated is false", so the condition
    // is `!!delegated`, which normalizes to `delegated`.
    assert_eq!(
        condition_of("require(!delegated)"),
        is_true("delegated"),
        "a double negation folds rather than nesting"
    );
}

#[test]
fn require_composes_with_the_boolean_operators() {
    assert_eq!(
        condition_of("require(a) & b"),
        Expression::And(vec![is_false("a"), is_true("b")]),
        "`require(a) & b` is `!a & b`"
    );
}

#[test]
fn a_comma_binds_lower_than_the_operators_inside_it() {
    // `require(a, b | c)` is `!(a & (b | c))`, which distributes to
    // `!a | (!b & !c)`.
    assert_eq!(
        condition_of("require(a, b | c)"),
        Expression::Or(vec![
            is_false("a"),
            Expression::And(vec![is_false("b"), is_false("c")])
        ])
    );
}

#[test]
fn require_is_a_predicate_so_it_nests() {
    // Nesting used to be refused outright: `parse_atom` reported that
    // `require(...)` was a rule-level shorthand and not a sub-predicate.
    parse_predicate("require(a) | require(b)").expect("`require` is a predicate now");
    parse_predicate("!require(a)").expect("and it negates like one");
}

// ---- surface details --------------------------------------------------

#[test]
fn a_space_before_the_paren_parses() {
    assert_eq!(condition_of("require (a)"), is_false("a"));
}

#[test]
fn an_explicit_deny_action_parses() {
    let rule = parse_rule("require(a): deny", "test").expect("the action may be written out");
    assert_eq!(rule.condition, is_false("a"));
    assert!(matches!(rule.effects.first(), Some(Effect::Deny { .. })));
}

#[test]
fn a_reason_may_be_given() {
    let rule = parse_rule("require(a): deny('needs a')", "test").expect("a reason parses");
    match rule.effects.first() {
        Some(Effect::Deny { reason, .. }) => {
            assert_eq!(reason.as_deref(), Some("needs a"));
        },
        other => panic!("expected a deny with a reason, got {other:?}"),
    }
}

/// The construct is a refusal, so inverting its action is a contradiction rather
/// than a shorthand for something.
#[test]
fn an_allow_action_is_rejected_and_names_the_inversion() {
    let message = parse_rule("require(a): allow", "test")
        .expect_err("`require` denies; it cannot allow")
        .to_string();
    for needle in ["require", "deny"] {
        assert!(
            message.contains(needle),
            "the message must name `{needle}`: {message}"
        );
    }
}

/// The same refusal through every spelling. This one failed open: as
/// `when: "require(a)"` with `do: allow` it compiled to an allow on `IsFalse(a)`,
/// so a policy meant to admit only those satisfying `a` admitted everyone else.
#[test]
fn an_allow_action_is_rejected_in_all_three_spellings() {
    crate::spellings::rejected_in_all_three_spellings(
        "require(a)",
        "allow",
        ["require", "deny"].as_slice(),
    );
}

/// The restriction is on the rule shape, not the operator, in every spelling: a
/// nested `require` is just its negation and may allow.
#[test]
fn a_nested_require_may_allow_in_all_three_spellings() {
    crate::spellings::accepted_in_all_three_spellings("a & require(b)", "allow");
}

/// A bare `require(...)` line takes the deny action implicitly, which is the form
/// every in-repo fixture uses.
#[test]
fn a_bare_require_line_denies() {
    let rule = parse_rule("require(authenticated)", "test").expect("the implicit form parses");
    assert!(matches!(rule.effects.first(), Some(Effect::Deny { .. })));
}

#[test]
fn an_empty_require_is_rejected() {
    parse_rule("require()", "test").expect_err("requiring nothing is not a rule");
}

#[test]
fn an_unclosed_require_is_rejected() {
    parse_rule("require(a", "test").expect_err("the paren must close");
}

// ---- the restriction is on the rule shape, not the operator -------------

/// `require` nested inside a larger predicate is the negation it desugars to and
/// nothing more, so it composes with the boolean operators and may allow.
///
/// The guard tested a text prefix, which made it asymmetric: `require(a) & b`
/// was refused while `a & require(b)` was accepted, though the grammar documents
/// both. The restriction is on a rule whose *whole* predicate is the call.
#[test]
fn require_inside_a_larger_predicate_may_allow() {
    for src in [
        "require(a) & b: allow",
        "a & require(b): allow",
        "require(a) | require(b): allow",
        "require(a) & require(b) & c: allow",
    ] {
        parse_rule(src, "test").unwrap_or_else(|e| panic!("`{src}` is legal composition: {e}"));
    }
}

/// And a rule whose whole predicate is the call still cannot allow, in every
/// spelling of the call: with a comma list, with an operator inside, and with the
/// whitespace the lexer tolerates between the name and its paren.
#[test]
fn a_whole_predicate_require_still_cannot_allow() {
    for src in [
        "require(a): allow",
        "require(a, b): allow",
        "require(a | b): allow",
        "require (a): allow",
    ] {
        let e = parse_rule(src, "test").unwrap_err().to_string();
        assert!(
            e.contains("require(...)"),
            "`{src}` must be refused naming the form: {e}"
        );
    }
}
