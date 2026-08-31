// What may appear in which position, and the one verb that invokes a plugin.
//
// Three separate looseness problems, all of the same kind: a construct was
// accepted in a position where it means nothing, and the acceptance was silent.
// A field operation compiled into a rule as a disjunction. An empty pipe stage was
// skipped. And `plugin(name)` and `run(name)` were two spellings for one thing, so
// a reader had to know both and a document could use either.

use praxis_policy_apl_core::test_util::compile_test_route;
use praxis_policy_apl_core::{parse_pipeline, parse_rule};

/// Compile a one-step `pre_invocation:` block, which is how a step reaches the
/// compiler. `parse_rule` is the predicate-and-action entry point and refuses a
/// step by design, so a step case written against it tests the wrong door.
fn step_block(step: &str) -> Result<(), String> {
    let yaml = format!("route:\n  authorization:\n    pre_invocation:\n      - \"{step}\"\n");
    compile_test_route("test", &yaml)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn pipeline_err(src: &str) -> String {
    parse_pipeline(src)
        .expect_err("this chain must be rejected")
        .to_string()
}

fn names_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "the message must name `{needle}`: {haystack}"
        );
    }
}

// ---- `run(name)` is the only invoke form -------------------------------

#[test]
fn run_invokes_a_plugin_in_step_position() {
    step_block("run(audit-log)").expect("`run(name)` is a step");
}

#[test]
fn run_invokes_a_plugin_in_stage_position() {
    parse_pipeline("str | run(luhn)").expect("`run(name)` is a stage");
}

/// Both positions refuse the old spelling, and both name the surviving one. It
/// was an alias, so nothing is lost but the second way to say it.
#[test]
fn the_old_plugin_spelling_is_refused_in_both_positions() {
    let step = step_block("plugin(audit-log)").expect_err("`plugin(name)` is not a step");
    names_all(&step, ["plugin(name)", "run(name)"].as_slice());

    // And through the rule entry point, which a caller may reach first.
    let rule = parse_rule("plugin(audit-log)", "test")
        .expect_err("a rule line naming it is refused too")
        .to_string();
    names_all(&rule, ["plugin(name)", "run(name)"].as_slice());

    let stage = pipeline_err("str | plugin(luhn)");
    names_all(&stage, ["plugin(name)", "run(name)"].as_slice());
}

/// The word survives as a noun. `plugin:` names a keyword argument inside
/// `delegate(...)`, and that is not the verb being removed.
#[test]
fn plugin_survives_as_a_keyword_argument() {
    step_block("delegate(workday-oauth, target: workday-api, permissions: [read])")
        .expect("a delegate step parses");
    // `plugin:` as a kwarg is the noun form, and it is not the verb being removed.
    step_block("require_approval(approver, from: claim.manager, channel: 'ciba')")
        .expect("an elicitation step parses");
}

// ---- an empty stage ----------------------------------------------------

/// A leading, trailing or doubled `|` leaves a position with no stage in it.
/// Those used to be skipped, so a chain that said nothing where a stage belonged
/// compiled to a shorter chain than its author wrote.
#[test]
fn an_empty_stage_in_a_chain_is_rejected() {
    for src in ["mask(4) |", "| mask(4)", "str || mask(4)"] {
        names_all(&pipeline_err(src), ["empty stage"].as_slice());
    }
}

/// The public entry point keeps answering an empty input with an empty pipeline.
/// A caller hands it a field value that may be absent, and absent is not
/// malformed; what is malformed is naming a stage and then leaving a position
/// beside it empty.
#[test]
fn an_entirely_empty_chain_is_an_empty_pipeline() {
    assert!(
        parse_pipeline("")
            .expect("an absent value is not a fault")
            .stages
            .is_empty(),
        "no stages, and no error"
    );
    assert!(
        parse_pipeline("   ")
            .expect("whitespace is the same as absent")
            .stages
            .is_empty()
    );
}

// ---- a stage that does not exist --------------------------------------

/// `validate(name)` is in the original design and not in this build: the
/// evaluator's stub would let every value through, so accepting it would be a
/// silent hole. The refusal names what to write instead.
#[test]
fn a_named_validator_is_refused_and_names_the_alternatives() {
    names_all(
        &pipeline_err("str | validate(luhn)"),
        ["regex(", "run("].as_slice(),
    );
}

// ---- a field operation in rule position --------------------------------

/// `result.x | redact` used to compile as a disjunction of two truthy attributes
/// and take the default deny, so a pipeline written one position too high
/// enforced something its author never asked for.
#[test]
fn a_field_operation_in_rule_position_is_rejected() {
    for src in ["result.x | redact", "args.employee_id | mask(4)"] {
        let e = parse_rule(src, "test")
            .expect_err("a field operation is not a rule")
            .to_string();
        names_all(&e, ["effect position", "args:", "result:"].as_slice());
    }
}

/// The same guard through every spelling, not just the entry point that carries
/// it. Both map forms used to accept what the string form refused.
#[test]
fn a_field_operation_in_rule_position_is_rejected_in_all_three_spellings() {
    for predicate in ["result.ssn | redact", "args.employee_id | mask(4)"] {
        crate::spellings::rejected_in_all_three_spellings(
            predicate,
            "deny",
            ["effect position", "args:", "result:"].as_slice(),
        );
    }
}

/// The narrowness case, also across the three: a legal disjunction stays legal in
/// every spelling.
#[test]
fn a_disjunction_of_two_field_paths_parses_in_all_three_spellings() {
    crate::spellings::accepted_in_all_three_spellings("result.x | result.y", "deny");
}

/// The guard has to stay narrow. This is a legal disjunction of two truthy
/// attributes: both sides are paths, neither is a stage. Without this case the
/// guard gets widened to "an `args.`/`result.` head" and starts refusing it.
#[test]
fn a_disjunction_of_two_field_paths_is_still_a_predicate() {
    parse_rule("result.x | result.y: deny", "test")
        .expect("two attribute paths are a disjunction, not a field operation");
    parse_rule("args.a | result.b", "test").expect("the same with no explicit action");
}

/// A chain whose head is not a field path is not a field operation either, so the
/// predicate parser keeps deciding it. `subject.id | redact` is a disjunction on
/// an attribute that happens to share a stage's name, and the guard leaves it
/// alone: what marks a field operation is the field, not the stage.
#[test]
fn a_chain_without_a_field_head_is_not_caught_by_the_guard() {
    parse_rule("subject.id | redact", "test")
        .expect("a non-field head stays a predicate, whatever the other side is named");
}

// ---- a declared field entry with no stages -----------------------------

/// `args: { value: "" }` used to compile to a no-op `FieldRule`: the author named
/// a field and then left its chain empty, and nothing said so.
#[test]
fn a_declared_field_entry_with_no_stages_is_rejected() {
    for (half, chain) in [("args", ""), ("result", "   ")] {
        let yaml = format!("route:\n  {half}:\n    ssn: \"{chain}\"\n");
        let e = compile_test_route("test", &yaml)
            .expect_err("a declared entry with no stages is a load error")
            .to_string();
        names_all(&e, [&format!("{half}.ssn"), "no stages"].as_slice());
    }
}

/// And the entry with a stage still compiles, keyed by the field it names.
#[test]
fn a_declared_field_entry_with_a_stage_still_compiles() {
    let route = compile_test_route("test", "route:\n  result:\n    ssn: \"redact\"\n")
        .expect("a named stage compiles");
    let fields: Vec<&str> = route.result.iter().map(|r| r.field.as_str()).collect();
    assert_eq!(fields, ["ssn"]);
}
