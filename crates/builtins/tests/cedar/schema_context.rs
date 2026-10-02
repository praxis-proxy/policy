// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Structured input under a Cedar schema, and errors that must not echo values.
//
// With a schema, `Request::new` checks the context against the action's
// context type, which is a closed record. Direct resolver construction keeps
// structured input opt-in; route configuration validates the opt-in at load.

use std::sync::Arc;

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{PdpCall, PdpDialect, PdpResolver as _};
use praxis_policy_builtins::pdps::cedar_direct::CedarDirectResolver;

const MARKER: &str = "SECRET-MARKER";

/// A schema declaring every principal attribute the resolver builds, with the
/// given context type for `read`.
fn schema(context: &str) -> String {
    format!(
        r#"
entity User = {{
  "id": String,
  "type": String,
  "roles": Set<String>,
  "permissions": Set<String>,
  "teams": Set<String>,
  "claims": {{}},
}};
entity Document = {{ "owner"?: Long }};
action read appliesTo {{ principal: User, resource: Document, context: {context} }};
"#
    )
}

fn resolver(policy: &str, context: &str, structured_context: Option<bool>) -> CedarDirectResolver {
    let mut yaml = serde_yaml::Mapping::new();
    yaml.insert("policy_text".into(), policy.into());
    yaml.insert("schema_text".into(), schema(context).into());
    if let Some(flag) = structured_context {
        yaml.insert("structured_context".into(), flag.into());
    }
    CedarDirectResolver::from_config(&serde_yaml::Value::Mapping(yaml)).expect("config builds")
}

fn call(args: &str) -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Cedar,
        args: serde_yaml::from_str(args).unwrap(),
    }
}

fn read_doc() -> PdpCall {
    call("action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: doc-1\n")
}

fn alice() -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    bag
}

fn tool_args(args: serde_json::Value) -> StructuredInput {
    StructuredInput::new(None, Some(Arc::new(args)))
}

const PERMIT_ALL: &str = "permit(principal, action, resource);";

/// Direct resolver use keeps structured input absent when it is not enabled.
#[tokio::test]
async fn schema_without_the_flag_ignores_structured_input() {
    let decision = resolver(PERMIT_ALL, "{}", None)
        .evaluate_structured(
            &read_doc(),
            &alice(),
            &tool_args(serde_json::json!({"repo": "r1"})),
        )
        .await
        .expect("an undeclared structured input must not fail validation");
    assert_eq!(decision.decision, Decision::Allow);
}

/// Without the flag nothing is sanitized, so an escape key is not withheld.
#[tokio::test]
async fn schema_without_the_flag_does_not_withhold_escape_keys() {
    let args = serde_json::json!({"who": {"__entity": {"type": "User", "id": "admin"}}});
    let decision = resolver(PERMIT_ALL, "{}", Some(false))
        .evaluate_structured(&read_doc(), &alice(), &tool_args(args))
        .await
        .expect("evaluate");
    assert_eq!(decision.decision, Decision::Allow);
}

#[tokio::test]
async fn schema_with_the_flag_evaluates_declared_structured_context() {
    let policy = r#"permit(principal, action, resource)
when { context has args && context.args.repo == "r1" };"#;
    let resolver = resolver(policy, "{ args?: { repo: String } }", Some(true));
    for (repo, allowed) in [("r1", true), ("r2", false)] {
        let decision = resolver
            .evaluate_structured(
                &read_doc(),
                &alice(),
                &tool_args(serde_json::json!({"repo": repo})),
            )
            .await
            .expect("declared structured context must validate");
        assert_eq!(
            decision.decision == Decision::Allow,
            allowed,
            "{repo}: {decision:?}"
        );
    }
}

/// An undeclared structured input fails validation, which the evaluator turns
/// into a deny. The reason names a category, never the context.
#[tokio::test]
async fn schema_with_the_flag_and_undeclared_context_fails_without_values() {
    let Err(e) = resolver(PERMIT_ALL, "{}", Some(true))
        .evaluate_structured(
            &read_doc(),
            &alice(),
            &tool_args(serde_json::json!({"repo": MARKER})),
        )
        .await
    else {
        panic!("an undeclared context attribute must fail validation");
    };
    let text = format!("{e} / {e:?}");
    assert!(!text.contains(MARKER), "{text}");
    assert!(
        text.contains(
            "Cedar request validation failed: context does not match the action's context type"
        ),
        "{text}"
    );
}

#[test]
fn a_non_bool_structured_context_is_rejected() {
    let yaml =
        "policy_text: 'permit(principal, action, resource);'\nstructured_context: yes-please\n";
    let Err(e) = CedarDirectResolver::from_config(&serde_yaml::from_str(yaml).unwrap()) else {
        panic!("a non-bool flag must be rejected");
    };
    assert!(
        e.to_string()
            .contains("`structured_context` must be a bool"),
        "{e}"
    );
}

/// Templated call arguments that fail to parse or type-check name the entity
/// type at most, never the value `${args.X}` put there.
#[tokio::test]
async fn templated_values_that_fail_never_reach_the_error() {
    let mut bag = alice();
    bag.set("args.repo", format!("{MARKER}-repo"));
    bag.set("args.owner", MARKER);
    bag.set("args.kind", format!("{MARKER} kind"));
    bag.set("args.action", MARKER);
    let cases = [
        (
            "action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: ${args.repo}\n  \
             attributes:\n    owner: ${args.owner}\n",
            "failed to construct resource entity:",
        ),
        (
            "action: 'Action::\"read\"'\nresource:\n  type: ${args.kind}\n  id: ${args.repo}\n",
            "failed to construct resource entity:",
        ),
        (
            "action: ${args.action}\nresource:\n  type: Document\n  id: ${args.repo}\n",
            "`action` is not a valid EntityUid",
        ),
    ];
    for (args, expected) in cases {
        let Err(e) = resolver(PERMIT_ALL, "{}", None)
            .evaluate_structured(&call(args), &bag, &StructuredInput::default())
            .await
        else {
            panic!("{args}: must fail");
        };
        let text = format!("{e} / {e:?}");
        assert!(!text.contains(MARKER), "{args}: {text}");
        assert!(text.contains(expected), "{args}: {text}");
    }
}

/// A templated resource type that parses as a Cedar type name is still not
/// named when the resource entity fails to build.
#[tokio::test]
async fn a_valid_templated_resource_type_is_not_named() {
    const TYPE_MARKER: &str = "Secretmarkertype";
    let mut bag = alice();
    bag.set("args.kind", TYPE_MARKER);
    bag.set("args.owner", MARKER);
    let args = "action: 'Action::\"read\"'\nresource:\n  type: ${args.kind}\n  id: r1\n  \
                attributes:\n    owner: ${args.owner}\n";
    let Err(e) = resolver(PERMIT_ALL, "{}", None)
        .evaluate_structured(&call(args), &bag, &StructuredInput::default())
        .await
    else {
        panic!("an undeclared resource type must fail");
    };
    let text = format!("{e} / {e:?}");
    assert!(!text.contains(TYPE_MARKER), "{text}");
    assert!(!text.contains(MARKER), "{text}");
    assert!(
        text.contains("failed to construct resource entity"),
        "{text}"
    );
}

/// Hosts that attach a schema in code opt in through the builder.
#[tokio::test]
async fn the_builder_opts_a_code_attached_schema_in() {
    let (schema, _) =
        cedar_policy::Schema::from_cedarschema_str(&schema("{ args?: { repo: String } }"))
            .expect("schema parses");
    let policy = r#"permit(principal, action, resource) when { context.args.repo == "r1" };"#;
    let base = || {
        CedarDirectResolver::from_policy_text(policy)
            .expect("policy parses")
            .with_schema(schema.clone())
    };
    let input = tool_args(serde_json::json!({"repo": "r1"}));
    let without = base()
        .evaluate_structured(&read_doc(), &alice(), &input)
        .await
        .expect("evaluate");
    assert_ne!(
        without.decision,
        Decision::Allow,
        "`context.args` is absent without the flag"
    );
    let with = base()
        .with_structured_context(true)
        .evaluate_structured(&read_doc(), &alice(), &input)
        .await
        .expect("evaluate");
    assert_eq!(with.decision, Decision::Allow);
}
