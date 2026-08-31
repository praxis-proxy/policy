// APL's lexical rules, one case per rule.
//
// The grammar lived only in comments inside the parser, and those comments were
// wrong about quoting, escapes, attribute paths, and numbers. This file is the
// executable half of writing it down: every rule the lexer enforces has an
// accepted case and a rejected one here, and every rejection is asserted to name
// the construct it refused rather than only to be an error.
//
// Two habits this file keeps deliberately:
//
// * A rejection asserts on the message, not just on `is_err`. A tightening that
//   fails for the wrong reason passes an `is_err` test and tells an operator
//   nothing, which is the failure mode this work exists to remove.
// * A case that survives unchanged is written down too. Several of these pin
//   behavior that looks like an accident and is not, so a later reader does not
//   "fix" it: `007` is the integer 7, and `a & b` needs no spaces.

use praxis_policy_apl_core::test_util::compile_test_route;
use praxis_policy_apl_core::{parse_pipeline, parse_predicate, parse_rule};

/// The message a predicate is rejected with.
fn pred_err(src: &str) -> String {
    parse_predicate(src)
        .expect_err("this predicate must be rejected")
        .to_string()
}

/// The message a rule is rejected with.
fn rule_err(src: &str) -> String {
    parse_rule(src, "test")
        .expect_err("this rule must be rejected")
        .to_string()
}

/// Assert `haystack` names every one of `needles`.
fn names_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "the message must name `{needle}`: {haystack}"
        );
    }
}

// ---- quoting and escapes ----------------------------------------------
//
// The escape set is `\\`, `\'`, `\"` and nothing else. That is the minimum
// that closes the rule: without it there is no way to write a quote inside a
// literal delimited by that quote. `\n` and `\t` are excluded on purpose, since
// a deny reason rides in a violation field a host renders, and a multi-line
// reason there is a display problem rather than a missing capability.

#[test]
fn an_escaped_quote_closes_nothing_and_unescapes() {
    let cond = parse_predicate(r"a == 'it\'s'").expect("an escaped quote is content");
    let rendered = format!("{cond:?}");
    assert!(
        rendered.contains("it's"),
        "the value must carry one apostrophe and no backslash: {rendered}"
    );
    assert!(
        !rendered.contains(r"it\'s"),
        "the backslash must be consumed, not passed through: {rendered}"
    );
}

#[test]
fn an_escaped_double_quote_works_the_same_way() {
    let cond = parse_predicate(r#"a == "say \"hi\"""#).expect("an escaped quote is content");
    let rendered = format!("{cond:?}");
    assert!(
        rendered.contains(r#"say \"hi\""#) || rendered.contains("say \"hi\""),
        "the value must carry two quote characters: {rendered}"
    );
}

#[test]
fn an_escaped_backslash_is_one_backslash() {
    let cond = parse_predicate(r"a == 'c:\\tmp'").expect("a doubled backslash is one backslash");
    let rendered = format!("{cond:?}");
    assert!(
        !rendered.contains(r"\\\\"),
        "two backslashes in, one out: {rendered}"
    );
}

#[test]
fn a_deny_reason_carrying_an_escaped_quote_unescapes() {
    let rule = parse_rule(r"a: deny('it\'s bad')", "test").expect("the reason parses");
    let rendered = format!("{rule:?}");
    assert!(
        rendered.contains("it's bad"),
        "the reason reaches the violation with no backslash: {rendered}"
    );
}

#[test]
fn an_unrecognized_escape_is_rejected_and_named() {
    names_all(&pred_err(r#"a == "x\qy""#), ["escape", "q"].as_slice());
}

/// The case an operator most likely has in a running config: a regex character
/// class. It used to pass a backslash through, so the pattern worked by
/// accident; now the backslash must be doubled and the single form is refused
/// rather than silently meaning something else.
#[test]
fn a_regex_character_class_must_double_its_backslash() {
    names_all(
        &parse_pipeline(r#"regex("\d+")"#)
            .expect_err("a bare backslash is no longer passed through")
            .to_string(),
        ["escape", "d"].as_slice(),
    );
    parse_pipeline(r#"regex("\\d+")"#).expect("the doubled form is the pattern the author meant");
}

#[test]
fn an_unterminated_literal_is_named_as_one() {
    for src in [r#"a == "x"#, "a == 'x"] {
        names_all(&pred_err(src), ["unterminated"].as_slice());
    }
}

/// A closing paren inside a literal is content, not the end of the call. The
/// paren matcher used to be quote-blind, so a deny reason could not mention one.
#[test]
fn a_paren_inside_a_literal_does_not_end_the_call() {
    parse_rule("a: deny('why? see doc)')", "test").expect("a paren inside a literal is content");
    parse_rule(r#"a: deny("blocked (see policy)")"#, "test")
        .expect("balanced parens inside a literal are content");
}

/// A surviving wart, kept deliberately. A stage argument with no quotes at all
/// stays legal, so `enum(low, medium, high)` reads as three bare words and
/// `regex(^[A-Z]+$)` as one. The escape rule and the unterminated-literal rule
/// apply everywhere; only the "a quote is mandatory" half is not adopted, because
/// requiring quotes here would rewrite working field stages for no gain in
/// meaning.
#[test]
fn a_bare_stage_argument_is_still_legal() {
    parse_pipeline("enum(low, medium, high)").expect("bare words in a set");
    parse_pipeline("regex(^[A-Z]+$)").expect("a bare pattern");
    parse_pipeline(r#"regex("^[A-Z]+$")"#).expect("and the quoted form means the same");
}

/// But a quote, once opened, must close. That is the half of the rule that does
/// apply to a stage argument, and it is what made `regex(")` compile to a pattern
/// matching one quote character.
#[test]
fn a_stage_argument_may_not_open_a_literal_it_does_not_close() {
    for src in [r#"regex(")"#, r#"enum(")"#, "regex(')"] {
        names_all(
            &parse_pipeline(src)
                .expect_err("a lone quote does not read as content")
                .to_string(),
            ["unterminated"].as_slice(),
        );
    }
}

// ---- attribute paths --------------------------------------------------
//
// A path is a production now, so an empty segment and an empty subscript are
// refused by construction. Every one of these used to lex clean and then
// resolve to an absent attribute, which made a predicate silently false and a
// `require` silently deny: a policy that never matched and never said why.

#[test]
fn an_empty_path_segment_is_rejected() {
    for src in ["a..b == 'x'", "a. == 'x'", ".a == 'x'"] {
        let message = pred_err(src);
        names_all(&message, ["path"].as_slice());
    }
}

#[test]
fn an_empty_subscript_is_rejected() {
    names_all(&pred_err("data.t[] == 'x'"), ["subscript"].as_slice());
}

#[test]
fn a_subscript_holding_a_colon_is_rejected() {
    names_all(&pred_err("data.t[a:b] == 'x'"), ["subscript"].as_slice());
}

/// This used to fail claiming an unterminated string literal, an error about a
/// construct the author did not write: the bracket scan stopped at the `]`
/// inside the quotes and handed the rest to the string reader.
#[test]
fn a_quote_inside_a_subscript_is_rejected_as_a_subscript_fault() {
    let message = pred_err(r#"data.t["a]"] == 'x'"#);
    names_all(&message, ["subscript"].as_slice());
    assert!(
        !message.contains("unterminated string"),
        "the error must not blame a literal the author did not write: {message}"
    );
}

/// The interpolated form itself keeps working, colon-in-group and all: one
/// predicate, not a rule with an action.
#[test]
fn an_interpolated_path_is_one_predicate() {
    parse_predicate("data.t[subject.tenant] == 'y'").expect("an interpolated path is one path");
}

#[test]
fn a_rule_whose_subscript_holds_a_colon_does_not_split_there() {
    // `split_predicate_action` is bracket-aware now. Before, the bracket's colon
    // was the only depth-0 colon on a bare-predicate line, so the line split
    // into a predicate `data.t[a` and an action `b]`, and the error named
    // neither brackets nor quotes.
    let message = rule_err("data.t[a:b]");
    assert!(
        !message.contains("unsupported action"),
        "a colon inside a subscript is not an action separator: {message}"
    );
}

#[test]
fn a_colon_inside_a_literal_still_separates_nothing() {
    parse_rule(r#"session.labels contains "a:b": deny"#, "test")
        .expect("the action colon is the one outside the literal");
}

// ---- reserved words ---------------------------------------------------

/// `not` used to be a plain identifier outside the `not in` phrase, so
/// `not authenticated` read as an attribute named `not` followed by a stray
/// token, and the error mentioned neither `not` nor `!`.
#[test]
fn the_word_not_is_reserved_and_points_at_the_operator() {
    names_all(&pred_err("not authenticated"), ["not", "!"].as_slice());
}

#[test]
fn a_path_beginning_not_is_rejected_as_reserved() {
    names_all(&pred_err("not.admin"), ["not"].as_slice());
}

/// The phrase survives, because it is the set-membership negation and reads
/// better than the alternative.
#[test]
fn the_not_in_phrase_still_parses() {
    parse_predicate("subject.tenant not in blocked_tenants").expect("`not in` is one operator");
    parse_predicate("subject.tenant in allowed_tenants").expect("and so is `in`");
}

// ---- operators --------------------------------------------------------

#[test]
fn a_doubled_boolean_operator_names_the_single_form() {
    names_all(&pred_err("a && b"), ["&&", "&"].as_slice());
    names_all(&pred_err("a || b"), ["||", "|"].as_slice());
}

/// Whitespace around `&` is not significant and never was, despite a comment
/// in the lexer claiming a caller enforced it. Nothing did.
#[test]
fn whitespace_around_an_operator_is_insignificant() {
    let tight = format!("{:?}", parse_predicate("a&b").expect("no spaces"));
    let loose = format!("{:?}", parse_predicate("a  &  b").expect("many spaces"));
    assert_eq!(tight, loose, "spacing must not change the parse");
}

// ---- numbers ----------------------------------------------------------

/// Kept as it is, deliberately. Reading `007` as octal would change a value
/// silently, which is the failure mode this work exists to remove.
#[test]
fn a_leading_zero_does_not_change_a_number_s_value() {
    let rendered = format!(
        "{:?}",
        parse_predicate("a == 007").expect("still an integer")
    );
    assert!(rendered.contains('7'), "`007` is the integer 7: {rendered}");
}

#[test]
fn a_number_with_no_fractional_digits_is_rejected() {
    names_all(&pred_err("a == 1."), ["number"].as_slice());
}

#[test]
fn a_number_with_no_integer_digits_is_rejected_both_ways() {
    // `.5` was already an error, but `-.5` parsed as a float. One rule now.
    for src in ["a == .5", "a == -.5"] {
        let message = pred_err(src);
        names_all(&message, ["number"].as_slice());
    }
}

#[test]
fn an_exponent_is_rejected_by_name_rather_than_as_a_stray_token() {
    names_all(&pred_err("a == 1e5"), ["number"].as_slice());
}

// ---- positions --------------------------------------------------------

/// Positions are character offsets, not byte offsets. A non-ASCII identifier
/// used to be reported at a byte index, and the character itself was rendered by
/// casting one byte to `char`, so the message named a character that was not in
/// the input.
#[test]
fn a_position_counts_characters_and_names_the_real_character() {
    let message = pred_err("café == 'x'");
    assert!(
        !message.contains('Ã'),
        "the message must not render a byte as a character: {message}"
    );
}

/// The subscript lexer is a second path to the same diagnostic and had the same
/// byte cast. Both read the character through `char_at_cursor` now.
#[test]
fn a_subscript_names_the_real_character_too() {
    let message = pred_err("data.t[café] == 'x'");
    assert!(
        !message.contains('Ã'),
        "the subscript message must not render a byte as a character: {message}"
    );
    assert!(
        message.contains('é'),
        "the subscript message must name the character in the input: {message}"
    );
}

// ---- every site reads a literal the same way ---------------------------

/// The PDP paren form used to keep its quotes, so a resolver registered for
/// `p/q` received `"p/q"` with them still attached and matched nothing.
///
/// Reached through a step map, which is the only place the paren form appears.
/// `parse_rule` refuses a step by design, so a case written against it tests the
/// wrong door.
#[test]
fn a_pdp_paren_argument_arrives_without_its_quotes() {
    let yaml = concat!(
        "route:\n",
        "  authorization:\n",
        "    pre_invocation:\n",
        "      - 'opa(\"p/q\"):':\n",
        "          on_deny:\n",
        "            - deny\n",
    );
    let route = compile_test_route("test", yaml).expect("the paren form compiles");
    let rendered = format!("{route:?}");
    assert!(
        rendered.contains("p/q"),
        "the resolver gets the path: {rendered}"
    );
    assert!(
        !rendered.contains("\\\"p/q\\\""),
        "and not the quotes around it, which is what it used to receive: {rendered}"
    );
}

/// A closing paren inside a literal is content in a field stage too, not only in
/// a call. Paren matching there was quote-blind, so `regex("(")` was refused as
/// having no stage identifier: the paren in the pattern closed the call early.
#[test]
fn a_paren_inside_a_stage_argument_is_content() {
    parse_pipeline(r#"regex("(")"#).expect("a paren inside a literal is pattern text");
    parse_pipeline(r#"regex("(\\d+)")"#).expect("and so is a balanced pair");
}

/// A comma inside a literal does not split a delegate argument list, and the
/// escape rule there is the lexer's rather than one of its own.
#[test]
fn a_comma_inside_a_literal_does_not_split_delegate_args() {
    compile_test_route(
        "test",
        "route:\n  authorization:\n    pre_invocation:\n      - \"delegate(oauth, \
         target: api, audience: 'a,b')\"\n",
    )
    .expect("the comma is inside a literal, so there are three arguments not four");
}
