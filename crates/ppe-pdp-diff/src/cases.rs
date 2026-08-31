// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Catalog of equivalent policy intents. Hand-written: a generator cannot
//! invent three dialect texts that mean the same thing.
//!
//! Cedar only sees what `build_principal` surfaces (`subject.*`, `role.*`,
//! `perm.*`, `subject.teams`, `claim.*`). Subset cases use that vocabulary so
//! agreement is actually testable.

use std::collections::HashSet;

use praxis_policy_apl_core::attributes::AttributeBag;

use crate::outcome::CauseKind;

/// What the harness asserts after all three dialects evaluate.
pub(crate) enum Expect {
    /// Every dialect allows.
    AgreeAllow,
    /// Every dialect denies; cause kinds are named per dialect because a
    /// Cedar no-match is `DefaultDeny` while CEL/OPA `false` is `PolicyFalse`.
    AgreeDeny {
        cedar: CauseKind,
        cel: CauseKind,
        opa: CauseKind,
    },
    /// Look up [`crate::allowlist::allowlist`] by id. An unknown id fails.
    Diverge(&'static str),
}

/// One bag, one intent, three dialect texts.
pub(crate) struct Case {
    pub(crate) name: &'static str,
    pub(crate) bag: AttributeBag,
    pub(crate) cedar_policy: String,
    pub(crate) cel_expr: String,
    pub(crate) opa_module: String,
    pub(crate) opa_query: String,
    pub(crate) cedar_resource_attrs: Option<serde_yaml::Mapping>,
    pub(crate) expect: Expect,
}

const OPA_QUERY: &str = "data.diff.allow";

/// Every case the harness runs.
pub(crate) fn catalog() -> Vec<Case> {
    vec![
        string_id_allow(),
        string_id_deny(),
        bool_role_true(),
        bool_role_false(),
        int_depth_allow(),
        int_depth_deny(),
        set_contains(),
        set_member_absent(),
        float_claim(),
        float_whole(),
        float_resource(),
        empty_set(),
        missing_collection(),
        missing_subject_id(),
    ]
}

fn alice() -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    bag
}

fn cedar_when(when: &str) -> String {
    format!(
        r#"
@id("diff")
permit(principal, action == Action::"read", resource)
when {{ {when} }};
"#
    )
}

fn opa_allow(rule: &str, default_false: bool) -> String {
    let default = if default_false {
        "default allow := false\n"
    } else {
        ""
    };
    format!("package diff\n{default}{rule}\n")
}

fn case(
    name: &'static str,
    bag: AttributeBag,
    cedar_when_body: &str,
    cel_expr: &str,
    opa_rule: &str,
    opa_default: bool,
    expect: Expect,
) -> Case {
    Case {
        name,
        bag,
        cedar_policy: cedar_when(cedar_when_body),
        cel_expr: cel_expr.to_owned(),
        opa_module: opa_allow(opa_rule, opa_default),
        opa_query: OPA_QUERY.to_owned(),
        cedar_resource_attrs: None,
        expect,
    }
}

fn string_id_allow() -> Case {
    case(
        "string-id-allow",
        alice(),
        r#"principal.id == "alice""#,
        r#"subject.id == "alice""#,
        r#"allow if input.subject.id == "alice""#,
        true,
        Expect::AgreeAllow,
    )
}

fn string_id_deny() -> Case {
    let mut bag = alice();
    bag.set("subject.id", "eve");
    case(
        "string-id-deny",
        bag,
        r#"principal.id == "alice""#,
        r#"subject.id == "alice""#,
        r#"allow if input.subject.id == "alice""#,
        true,
        Expect::AgreeDeny {
            cedar: CauseKind::DefaultDeny,
            cel: CauseKind::PolicyFalse,
            opa: CauseKind::PolicyFalse,
        },
    )
}

fn bool_role_true() -> Case {
    let mut bag = alice();
    bag.set("role.hr", true);
    case(
        "bool-role-true",
        bag,
        r#"principal.roles.contains("hr")"#,
        "has(role.hr) && role.hr",
        "allow if input.role.hr == true",
        true,
        Expect::AgreeAllow,
    )
}

fn bool_role_false() -> Case {
    let mut bag = alice();
    bag.set("role.hr", false);
    case(
        "bool-role-false",
        bag,
        r#"principal.roles.contains("hr")"#,
        "has(role.hr) && role.hr",
        "allow if input.role.hr == true",
        true,
        Expect::AgreeDeny {
            cedar: CauseKind::DefaultDeny,
            cel: CauseKind::PolicyFalse,
            opa: CauseKind::PolicyFalse,
        },
    )
}

fn int_depth_allow() -> Case {
    let mut bag = alice();
    bag.set("claim.depth", 2_i64);
    case(
        "int-depth-allow",
        bag,
        "principal.claims.depth <= 2",
        "claim.depth <= 2",
        "allow if input.claim.depth <= 2",
        true,
        Expect::AgreeAllow,
    )
}

fn int_depth_deny() -> Case {
    let mut bag = alice();
    bag.set("claim.depth", 3_i64);
    case(
        "int-depth-deny",
        bag,
        "principal.claims.depth <= 2",
        "claim.depth <= 2",
        "allow if input.claim.depth <= 2",
        true,
        Expect::AgreeDeny {
            cedar: CauseKind::DefaultDeny,
            cel: CauseKind::PolicyFalse,
            opa: CauseKind::PolicyFalse,
        },
    )
}

fn set_contains() -> Case {
    let mut bag = alice();
    bag.set(
        "subject.teams",
        HashSet::from(["eng".to_owned(), "ops".to_owned()]),
    );
    case(
        "set-contains",
        bag,
        r#"principal.teams.contains("eng")"#,
        r#""eng" in subject.teams"#,
        r#"allow if "eng" in input.subject.teams"#,
        true,
        Expect::AgreeAllow,
    )
}

fn set_member_absent() -> Case {
    let mut bag = alice();
    bag.set("subject.teams", HashSet::from(["ops".to_owned()]));
    case(
        "set-member-absent",
        bag,
        r#"principal.teams.contains("eng")"#,
        r#""eng" in subject.teams"#,
        r#"allow if "eng" in input.subject.teams"#,
        true,
        Expect::AgreeDeny {
            cedar: CauseKind::DefaultDeny,
            cel: CauseKind::PolicyFalse,
            opa: CauseKind::PolicyFalse,
        },
    )
}

fn float_claim() -> Case {
    let mut bag = alice();
    // 0.75 and 0.5 are exact in binary floating point (clippy
    // `lossy_float_literal`).
    bag.set("claim.confidence", 0.75_f64);
    case(
        "float-claim",
        bag,
        "principal.claims.confidence > decimal(\"0.5\")",
        "claim.confidence > 0.5",
        "allow if input.claim.confidence > 0.5",
        true,
        Expect::Diverge("floats-claim"),
    )
}

fn float_whole() -> Case {
    let mut bag = alice();
    bag.set("claim.n", 2.0_f64);
    case(
        "float-whole",
        bag,
        "principal.claims.n == 2",
        "claim.n == 2",
        "allow if input.claim.n == 2",
        true,
        Expect::Diverge("floats-whole"),
    )
}

fn cedar_permit() -> String {
    r#"
@id("diff")
permit(principal, action == Action::"read", resource);
"#
    .to_owned()
}

fn float_resource() -> Case {
    let mut bag = alice();
    bag.set("resource.score", 1.5_f64);
    let mut attrs = serde_yaml::Mapping::new();
    attrs.insert(
        serde_yaml::Value::String("score".to_owned()),
        serde_yaml::Value::Number(serde_yaml::Number::from(1.5_f64)),
    );
    Case {
        name: "float-resource",
        bag,
        cedar_policy: cedar_permit(),
        cel_expr: "resource.score > 1.0".to_owned(),
        opa_module: opa_allow("allow if input.resource.score > 1.0", true),
        opa_query: OPA_QUERY.to_owned(),
        cedar_resource_attrs: Some(attrs),
        expect: Expect::Diverge("floats-resource"),
    }
}

fn empty_set() -> Case {
    let mut bag = alice();
    bag.set("subject.teams", HashSet::<String>::new());
    case(
        "empty-set",
        bag,
        r#"principal.teams.contains("eng")"#,
        r#""eng" in subject.teams"#,
        r#"allow if "eng" in input.subject.teams"#,
        true,
        Expect::Diverge("empty-set"),
    )
}

fn missing_collection() -> Case {
    case(
        "missing-collection",
        alice(),
        r#"principal.roles.contains("hr")"#,
        "role.hr",
        "allow if input.role.hr == true",
        false,
        Expect::Diverge("missing-collection"),
    )
}

fn missing_subject_id() -> Case {
    Case {
        name: "missing-subject-id",
        bag: AttributeBag::new(),
        cedar_policy: cedar_permit(),
        cel_expr: r#"subject.id == "alice""#.to_owned(),
        opa_module: opa_allow(r#"allow if input.subject.id == "alice""#, false),
        opa_query: OPA_QUERY.to_owned(),
        cedar_resource_attrs: None,
        expect: Expect::Diverge("missing-subject-id"),
    }
}
