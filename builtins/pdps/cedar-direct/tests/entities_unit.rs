// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Direct tests for the bag-to-Cedar-entity translation.
//
// The scenario tests reach this code only through `evaluate`, and they all use
// a two-key bag (`subject.id`, `subject.type`). That leaves most of the
// translation dark: teams, the `claim.*` record and its five value types, the
// `perm.` prefix, an operator-supplied namespace, and every rejection in
// `build_resource`. Those are what an operator's policy actually reads, so they
// are tested here against the public `build_principal` / `build_resource`
// rather than through a full authorization round trip.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_pdp_cedar_direct::entities::{build_principal, build_resource};

fn set_of<const N: usize>(items: [&str; N]) -> std::collections::HashSet<String> {
    items.into_iter().map(str::to_owned).collect()
}

fn bag_with(pairs: &[(&str, &str)]) -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    for (k, v) in pairs {
        bag.set(*k, *v);
    }
    bag
}

/// Cedar cannot authorize without a principal, so an absent `subject.id` has to
/// be a clear dispatch error naming the fix rather than a silent anonymous
/// principal.
#[test]
fn a_bag_with_no_subject_id_is_rejected_and_says_what_to_install() {
    let bag = AttributeBag::new();
    let err = build_principal(&bag, None, None).expect_err("no subject.id must fail");
    let msg = err.to_string();
    assert!(msg.contains("subject.id"), "{msg}");
    assert!(
        msg.contains("identity-hook plugin"),
        "the message must say how to fix it: {msg}"
    );
}

/// `subject.type` defaults to `User`, and an operator can override it. Both
/// matter: the entity type is half of the Cedar UID a policy matches on.
#[test]
fn subject_type_defaults_to_user_and_is_overridable() {
    let default = build_principal(&bag_with(&[]), None, None).unwrap();
    assert_eq!(default.uid().type_name().to_string(), "User");

    let bag = bag_with(&[("subject.type", "Service")]);
    let overridden = build_principal(&bag, None, None).unwrap();
    assert_eq!(overridden.uid().type_name().to_string(), "Service");
}

/// Operators with a namespaced Cedar schema write `Acme::User`, and the
/// namespace is applied here so no policy author has to hand-prefix. Nothing
/// set `entity_namespace` before, so only the bare path had run.
#[test]
fn an_entity_namespace_qualifies_the_principal_type() {
    let bag = bag_with(&[("subject.type", "User")]);
    let e = build_principal(&bag, None, Some("Acme")).unwrap();
    assert_eq!(e.uid().type_name().to_string(), "Acme::User");
}

/// An empty namespace string is the same as none, so a blank YAML value does
/// not produce a `::User` type that matches nothing.
#[test]
fn an_empty_namespace_is_treated_as_absent() {
    let bag = bag_with(&[("subject.type", "User")]);
    let e = build_principal(&bag, None, Some("")).unwrap();
    assert_eq!(e.uid().type_name().to_string(), "User");
}

/// `role.*` and `perm.*` are presence-only bag keys, and only a `true` value
/// counts. A `false` key must not grant the role: that would invert the meaning
/// of an explicit denial upstream.
#[test]
fn only_true_role_and_perm_keys_become_attributes() {
    let mut bag = bag_with(&[]);
    bag.set("role.engineer", true);
    bag.set("role.revoked", false);
    bag.set("perm.read", true);
    bag.set("perm.write", false);
    let e = build_principal(&bag, None, None).unwrap();

    let roles = format!("{:?}", e.attr("roles").unwrap().unwrap());
    assert!(roles.contains("engineer"), "{roles}");
    assert!(
        !roles.contains("revoked"),
        "a role.X = false key must not grant X: {roles}"
    );

    let perms = format!("{:?}", e.attr("permissions").unwrap().unwrap());
    assert!(perms.contains("read"), "{perms}");
    assert!(!perms.contains("write"), "{perms}");
}

#[test]
fn subject_teams_reaches_the_principal() {
    let mut bag = bag_with(&[]);
    bag.set("subject.teams", set_of(["platform", "security"]));
    let e = build_principal(&bag, None, None).unwrap();
    let teams = format!("{:?}", e.attr("teams").unwrap().unwrap());
    assert!(teams.contains("platform"), "{teams}");
    assert!(teams.contains("security"), "{teams}");
}

/// The `claim.*` record carries each value at its own JSON type so Cedar's
/// record-of-records comparisons work. No test had put a `claim.` key in the
/// bag, so none of the value arms had run.
#[test]
fn claim_keys_become_a_record_preserving_each_value_type() {
    let mut bag = bag_with(&[]);
    bag.set("claim.verified", true);
    bag.set("claim.level", 3_i64);
    bag.set("claim.tenant", "acme");
    bag.set("claim.groups", set_of(["a", "b"]));

    let e = build_principal(&bag, None, None).unwrap();
    let claims = format!("{:?}", e.attr("claims").unwrap().unwrap());
    for expected in ["verified", "level", "tenant", "groups", "acme"] {
        assert!(claims.contains(expected), "missing {expected} in {claims}");
    }
    assert!(
        !claims.contains("subject.id"),
        "only claim.* keys belong in the record: {claims}"
    );
}

/// Cedar has no floating-point type, but a claim is not the operator's to fix —
/// it arrives in whatever shape the `IdP` minted. So a float claim is carried as
/// its string form and the request proceeds, rather than every user of a
/// provider that emits one being denied. Contrast
/// `a_float_resource_attribute_is_refused_with_a_message_naming_the_key` below,
/// where the value *is* operator-authored and rejecting it is the help.
///
/// Note the assertion pins survival, not the string form — Cedar has no
/// double, so there is no rival rendering to rule out.
#[test]
fn a_float_claim_is_carried_as_a_string_rather_than_failing_the_request() {
    let mut bag = bag_with(&[]);
    bag.set("claim.score", 1.5_f64);
    let entity =
        build_principal(&bag, None, None).expect("a float claim must not fail the request");
    let claims = format!("{entity:?}");
    assert!(
        claims.contains("1.5"),
        "the claim must survive as its string form, not be dropped: {claims}"
    );
}

/// An integer claim keeps its numeric type — the string fallback above is only
/// for the values Cedar genuinely cannot hold, so a policy comparing
/// `principal.claims.level > 2` still works.
#[test]
fn an_integer_claim_stays_numeric() {
    let mut bag = bag_with(&[]);
    bag.set("claim.level", 3_i64);
    let entity = build_principal(&bag, None, None).expect("an integer claim is representable");
    let dbg = format!("{entity:?}");
    assert!(
        dbg.contains("Long(3)") || dbg.contains("Int(3)"),
        "an integer claim must not be stringified: {dbg}"
    );
}

/// Empty defaults are deliberate: Cedar's strict evaluation errors when a policy
/// probes a missing attribute, and the resolver's fail-closed path would turn
/// that into a deny. So a bare principal still carries every attribute, empty.
#[test]
fn a_bare_principal_still_carries_every_attribute_empty() {
    let e = build_principal(&bag_with(&[]), None, None).unwrap();
    for attr in ["id", "type", "roles", "permissions", "teams", "claims"] {
        assert!(
            e.attr(attr).is_some(),
            "{attr} must exist even when empty, or a policy probing it errors"
        );
    }
}

// ---- build_resource -----------------------------------------------------

fn yaml(s: &str) -> serde_yaml::Value {
    serde_yaml::from_str(s).unwrap()
}

#[test]
fn a_resource_with_type_and_id_builds() {
    let v = yaml("type: Document\nid: doc-42\n");
    let e = build_resource(&v, None).unwrap();
    assert_eq!(e.uid().type_name().to_string(), "Document");
    assert!(e.uid().id().escaped().contains("doc-42"));
}

#[test]
fn resource_attributes_are_carried_through() {
    let v = yaml("type: Document\nid: doc-42\nattributes:\n  classification: internal\n");
    let e = build_resource(&v, None).unwrap();
    let cls = format!("{:?}", e.attr("classification").unwrap().unwrap());
    assert!(cls.contains("internal"), "{cls}");
}

#[test]
fn a_resource_that_is_not_a_mapping_is_rejected() {
    let err = build_resource(&yaml("just-a-string"), None).expect_err("must fail");
    assert!(err.to_string().contains("must be a mapping"), "{err}");
}

#[test]
fn a_resource_missing_type_or_id_is_rejected() {
    let no_type = build_resource(&yaml("id: doc-42\n"), None).expect_err("must fail");
    assert!(no_type.to_string().contains("`resource.type`"), "{no_type}");

    let no_id = build_resource(&yaml("type: Document\n"), None).expect_err("must fail");
    assert!(no_id.to_string().contains("`resource.id`"), "{no_id}");
}

/// A non-string `type` or `id` is rejected rather than coerced. Silently
/// stringifying `id: 42` would produce a UID the policy author did not write.
#[test]
fn a_non_string_resource_type_or_id_is_rejected() {
    let e = build_resource(&yaml("type: Document\nid: 42\n"), None).expect_err("must fail");
    assert!(e.to_string().contains("`resource.id`"), "{e}");
}

/// Regression. `attributes:` is operator-authored YAML, so `score: 1.5` is an
/// easy thing to write, and Cedar's value model has no floating-point type. It
/// used to reach Cedar and come back as "error during entity deserialization",
/// which the resolver turns into a fail-closed deny: every request through the
/// step denied, with nothing saying which value to change.
#[test]
fn a_float_resource_attribute_is_refused_with_a_message_naming_the_key() {
    let err = build_resource(&yaml("type: D\nid: d1\nattributes:\n  score: 1.5\n"), None)
        .expect_err("Cedar cannot hold a float");
    let msg = err.to_string();
    assert!(msg.contains("floating-point"), "{msg}");
    assert!(
        msg.contains("score"),
        "the message must name the offending key: {msg}"
    );
}

/// The float check walks nested values, because an operator can nest a mapping
/// under `attributes:` and the failure is identical.
#[test]
fn a_nested_float_resource_attribute_is_found_and_named_by_path() {
    let err = build_resource(
        &yaml("type: D\nid: d1\nattributes:\n  meta:\n    ratio: 0.75\n"),
        None,
    )
    .expect_err("a nested float must be caught too");
    assert!(
        err.to_string().contains("meta.ratio"),
        "the message must give the path to the value: {err}"
    );
}

/// Integers stay fine. Cedar's numeric type is a 64-bit integer, so this is the
/// shape operators should be steered toward.
#[test]
fn an_integer_resource_attribute_is_accepted() {
    let e = build_resource(&yaml("type: D\nid: d1\nattributes:\n  score: 2\n"), None)
        .expect("an integer attribute must build");
    let score = format!("{:?}", e.attr("score").unwrap().unwrap());
    assert!(score.contains('2'), "{score}");
}
