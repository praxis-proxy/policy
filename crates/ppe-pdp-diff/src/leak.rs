// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Payload text never reaches a deny. Each probe denies a request whose
//! request and tool arguments carry a marker through distinct deny paths, and the
//! whole decision (reason, rule source, diagnostics) must not hold it.

#![expect(clippy::panic, reason = "tests")]

use std::sync::Arc;

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::route::StructuredInput;
use serde_json::{Value, json};

use super::cases::{Case, Expect};
use super::classify::classify;
use super::drivers::{Dialect, evaluate};
use super::outcome::{CauseKind, Outcome};

const MARKER: &str = "SECRET-MARKER";

/// One policy on one dialect, and the deny it must produce.
struct Probe {
    dialect: Dialect,
    policy: &'static str,
    want: CauseKind,
}

const fn probe(dialect: Dialect, policy: &'static str, want: CauseKind) -> Probe {
    Probe {
        dialect,
        policy,
        want,
    }
}

fn probes() -> Vec<Probe> {
    use CauseKind::{DefaultDeny, EvalError, ForbidMatched, PolicyFalse};
    use Dialect::{Cedar, Cel, Opa};
    vec![
        probe(
            Cedar,
            r#"permit(principal, action, resource)
when { context.llm.request.tools.contains({"type": "none"}) };"#,
            DefaultDeny,
        ),
        probe(
            Cedar,
            r#"@id("no-messages")
forbid(principal, action, resource) when { context.llm.request has messages };
permit(principal, action, resource);"#,
            ForbidMatched,
        ),
        probe(
            Cedar,
            "permit(principal, action, resource) when { context.llm.request.messages > 1 };",
            EvalError,
        ),
        probe(
            Cedar,
            r#"permit(principal, action, resource)
when { context.llm.request.tools like "x*" };"#,
            EvalError,
        ),
        probe(
            Cedar,
            r#"permit(principal, action, resource)
when { context.args.items.contains({"classification": "public"}) };"#,
            DefaultDeny,
        ),
        probe(
            Cel,
            r#"llm.request.messages.exists(m, m.content == "x")"#,
            PolicyFalse,
        ),
        probe(Cel, "llm.request.messages[0].content + 1 == 2", EvalError),
        probe(Cel, "llm.request.tools", PolicyFalse),
        probe(
            Cel,
            r#"llm.request.tools[0].function.missing == "x""#,
            EvalError,
        ),
        probe(Cel, "args.items[0].classification + 1 == 2", EvalError),
        probe(
            Opa,
            "default allow := false\nallow if input.llm.request.messages[0].content == \"x\"",
            PolicyFalse,
        ),
        probe(
            Opa,
            "allow if to_number(input.llm.request.messages[0].content) > 1",
            EvalError,
        ),
        probe(Opa, "allow := input.llm.request", PolicyFalse),
        probe(
            Opa,
            "allow contains t if some t in input.llm.request.tools",
            PolicyFalse,
        ),
        probe(
            Opa,
            "allow if to_number(input.args.items[0].classification) > 1",
            EvalError,
        ),
    ]
}

/// A request whose prompt, tool name, tool description, and a client key
/// all carry the marker.
fn marked_request() -> Value {
    json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": format!("{MARKER} prompt")}],
        "tools": [{
            "type": "function",
            "function": {"name": format!("{MARKER}-tool"), "description": MARKER},
            format!("{MARKER}-key"): 1,
        }],
    })
}

fn marked_args() -> Value {
    json!({
        "items": [{"classification": MARKER}],
        format!("{MARKER}-key"): MARKER,
    })
}

fn probe_case(probe: &Probe, document: Value) -> Case {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    let pick = |dialect: Dialect| {
        if probe.dialect == dialect {
            probe.policy.to_owned()
        } else {
            String::new()
        }
    };
    Case {
        name: "leak-probe",
        bag,
        structured: StructuredInput::new(Some(Arc::new(document)), Some(Arc::new(marked_args()))),
        cedar_policy: pick(Dialect::Cedar),
        cel_expr: pick(Dialect::Cel),
        opa_module: format!("package diff\n{}\n", pick(Dialect::Opa)),
        opa_query: "data.diff.allow".to_owned(),
        cedar_resource_attrs: None,
        apl_rule: None,
        expect: Expect::AgreeAllow,
    }
}

async fn assert_no_marker(case: &Case, dialect: Dialect, want: CauseKind, label: &str) {
    let raw = evaluate(dialect, case).await;
    let text = match &raw {
        Ok(decision) => format!("{decision:?}"),
        Err(e) => format!("{e:?} / {e}"),
    };
    assert_eq!(
        classify(raw),
        Outcome::deny(want),
        "{}: `{label}` must deny with {want:?}; got {text}",
        dialect.kind(),
    );
    assert!(
        !text.contains(MARKER),
        "{}: `{label}` leaked payload text: {text}",
        dialect.kind(),
    );
}

#[tokio::test]
async fn denies_never_echo_request_payload() {
    for probe in probes() {
        let case = probe_case(&probe, marked_request());
        assert_no_marker(&case, probe.dialect, probe.want, probe.policy).await;
    }
}

#[tokio::test]
async fn cedar_withheld_input_never_echoes_request_payload() {
    let mut document = marked_request();
    let Some(tools) = document.get_mut("tools").and_then(Value::as_array_mut) else {
        panic!("the marked request has a tools array");
    };
    tools.push(json!({"__entity": {"type": "User", "id": MARKER}}));
    let probe = probe(
        Dialect::Cedar,
        "permit(principal, action, resource);",
        CauseKind::ForbidMatched,
    );
    let case = probe_case(&probe, document);
    assert_no_marker(&case, probe.dialect, probe.want, "withheld").await;
}
