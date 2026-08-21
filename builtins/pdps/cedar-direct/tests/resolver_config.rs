// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Every shape an operator can write in a `cedar:` PDP config block.
//
// One existing test covers `policy_text` with no schema. Everything else was
// untested: the file-backed variants, the precedence between text and file, the
// schema paths, the custom dialect, the namespace, and each rejection. These are
// what an operator gets wrong, and a resolver that silently built with no policy
// or no schema would authorize against nothing.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use praxis_policy_apl_core::step::{PdpDialect, PdpResolver as _};
use praxis_policy_pdp_cedar_direct::CedarDirectResolver;

/// Fixtures live next to this file so the tests need no `tempfile`
/// dev-dependency; the workspace does not have one.
fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn cfg(yaml: &str) -> serde_yaml::Value {
    serde_yaml::from_str(yaml).expect("test yaml parses")
}

fn err_of(yaml: &str) -> String {
    match CedarDirectResolver::from_config(&cfg(yaml)) {
        Ok(_) => panic!("this config must be rejected"),
        Err(e) => e.to_string(),
    }
}

// ---- the policy source --------------------------------------------------

#[test]
fn a_policy_file_is_read_from_disk() {
    let yaml = format!("policy_file: {}\n", fixture("allow-all.cedar"));
    assert!(
        CedarDirectResolver::from_config(&cfg(&yaml)).is_ok(),
        "a readable policy file must build"
    );
}

/// `policy_text` wins when both are given. Silently preferring the file would
/// make an operator's inline edit disappear.
#[test]
fn policy_text_takes_precedence_over_policy_file() {
    let yaml = format!(
        "policy_text: |\n  permit(principal, action, resource);\npolicy_file: {}\n",
        fixture("does-not-exist.cedar")
    );
    assert!(
        CedarDirectResolver::from_config(&cfg(&yaml)).is_ok(),
        "policy_text must be used, so the unreadable file is never opened"
    );
}

#[test]
fn a_missing_policy_file_names_the_path() {
    let e = err_of("policy_file: /nonexistent/ppe-test/p.cedar\n");
    assert!(e.contains("p.cedar"), "the message must name the file: {e}");
}

#[test]
fn neither_policy_text_nor_policy_file_is_rejected() {
    let e = err_of("dialect: cedar\n");
    assert!(
        e.contains("policy_text") && e.contains("policy_file"),
        "the message must name both options: {e}"
    );
}

/// A policy that does not parse has to fail at config load. Building with an
/// empty policy set would authorize nothing and read as a deny-all.
#[test]
fn an_unparseable_policy_is_rejected() {
    let e = err_of("policy_text: \"this is not cedar\"\n");
    assert!(!e.is_empty(), "a parse failure must surface");
}

// ---- the schema source --------------------------------------------------

#[test]
fn a_schema_file_is_read_from_disk() {
    let yaml = format!(
        "policy_text: |\n  permit(principal, action, resource);\nschema_file: {}\n",
        fixture("minimal.cedarschema")
    );
    assert!(
        CedarDirectResolver::from_config(&cfg(&yaml)).is_ok(),
        "a readable schema file must build"
    );
}

#[test]
fn schema_text_is_accepted_inline() {
    let yaml = "policy_text: |\n  permit(principal, action, resource);\nschema_text: |\n  entity User;\n  entity Document;\n  action read appliesTo { principal: User, resource: Document };\n";
    CedarDirectResolver::from_config(&cfg(yaml)).unwrap();
}

#[test]
fn a_missing_schema_file_names_the_path() {
    let yaml = "policy_text: |\n  permit(principal, action, resource);\nschema_file: /nonexistent/ppe-test/s.cedarschema\n";
    let e = err_of(yaml);
    assert!(
        e.contains("s.cedarschema"),
        "the message must name the file: {e}"
    );
}

#[test]
fn an_unparseable_schema_is_rejected() {
    let yaml = "policy_text: |\n  permit(principal, action, resource);\nschema_text: \"}}not a schema{{\"\n";
    assert!(!err_of(yaml).is_empty());
}

// ---- dialect and namespace ---------------------------------------------

/// The dialect key is how two Cedar engines coexist on one router. Absent or
/// `cedar` is the built-in; anything else registers under that custom name, and
/// getting this wrong means a route's `cedar:` step reaches the wrong engine.
#[test]
fn the_dialect_defaults_to_cedar_and_any_other_value_becomes_custom() {
    let base = "policy_text: |\n  permit(principal, action, resource);\n";

    let default = CedarDirectResolver::from_config(&cfg(base)).unwrap();
    assert_eq!(default.dialect(), PdpDialect::Cedar);

    let explicit =
        CedarDirectResolver::from_config(&cfg(&format!("{base}dialect: cedar\n"))).unwrap();
    assert_eq!(explicit.dialect(), PdpDialect::Cedar);

    let custom =
        CedarDirectResolver::from_config(&cfg(&format!("{base}dialect: workload\n"))).unwrap();
    assert_eq!(
        custom.dialect(),
        PdpDialect::Custom("workload".to_owned()),
        "an unrecognized dialect registers under its own name rather than \
         silently falling back to cedar"
    );
}

/// The namespace reaches the principal UID, which is half of what a policy
/// matches on. A config that accepted it and dropped it would make every
/// namespaced policy fail to match.
#[tokio::test]
async fn an_entity_namespace_from_config_reaches_the_principal() {
    use praxis_policy_apl_core::attributes::AttributeBag;
    use praxis_policy_apl_core::step::PdpCall;

    // No schema here on purpose. With one, Cedar also validates the entity's
    // attribute shape, and the principal always carries `roles` / `permissions` /
    // `teams` / `claims`, so a schema would have to declare all of them. That is
    // a separate concern from whether the namespace reaches the UID.
    let yaml = "policy_text: |\n  @id(\"ns\")\n  permit(principal == Acme::User::\"alice\", action, resource);\nentity_namespace: Acme\n";
    let resolver = CedarDirectResolver::from_config(&cfg(yaml)).expect("namespaced config builds");

    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    let call = PdpCall {
        dialect: PdpDialect::Cedar,
        args: serde_yaml::from_str(
            "action: 'Acme::Action::\"read\"'\nresource:\n  type: Acme::Document\n  id: doc-1\n",
        )
        .unwrap(),
    };
    let decision = resolver.evaluate(&call, &bag).await.expect("evaluates");
    assert!(
        matches!(
            decision.decision,
            praxis_policy_apl_core::evaluator::Decision::Allow
        ),
        "the namespace must reach the principal UID, got {decision:?}"
    );
}

// ---- shape rejection ---------------------------------------------------

#[test]
fn a_config_that_is_not_a_mapping_is_rejected() {
    let e = err_of("just-a-string\n");
    assert!(e.contains("must be a mapping"), "{e}");
}
