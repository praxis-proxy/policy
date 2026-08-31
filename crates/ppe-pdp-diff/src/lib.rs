// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Differential testing across Cedar, CEL, and OPA.
//!
//! Three PDP resolvers read the same [`praxis_policy_apl_core::AttributeBag`].
//! Each crate tests itself. This crate feeds one bag and an equivalent policy
//! intent to all three and compares verdicts (and cause kinds). An unlisted
//! disagreement fails the build.
//!
//! The semantic subset and the known-divergence allowlist are documented in
//! this crate's `README.md`. That document is the contract; the catalog and
//! allowlist here are the executable form.

/// Factory `kind:` strings this harness drives.
///
/// Keep in lockstep with `praxis_policy::builtin_pdp_factories` (see the
/// facade crate test `every_builtin_pdp_kind_is_in_the_differential_harness`).
/// Public so that test imports this constant instead of duplicating the list.
pub const HARNESS_PDP_KINDS: &[&str] = &["cedar-direct", "cel", "opa"];

// The harness runs from this crate's own test module and from nowhere else, so
// a non-test build reaches none of it. `HARNESS_PDP_KINDS` above is the one
// item a dependent reads, which is why it sits here rather than in `drivers`.
#[cfg(test)]
mod allowlist;
#[cfg(test)]
mod cases;
#[cfg(test)]
mod classify;
#[cfg(test)]
mod drivers;
#[cfg(test)]
mod outcome;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use praxis_policy_apl_core::attributes::AttributeValue;

    use super::HARNESS_PDP_KINDS;
    use super::allowlist::{allowlist, allowlist_by_id};
    use super::cases::{Case, Expect, catalog};
    use super::classify::classify;
    use super::drivers::{Dialect, evaluate};
    use super::outcome::{Outcome, Verdict};

    #[tokio::test]
    async fn differential_catalog_agrees_or_is_allowlisted() {
        for case in catalog() {
            run_case(&case).await;
        }
    }

    #[test]
    fn catalog_names_are_unique() {
        let mut names: Vec<&str> = catalog().iter().map(|c| c.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "catalog case names must be unique, got {names:?}"
        );
    }

    #[test]
    fn catalog_covers_all_attribute_value_variants() {
        let mut saw_bool = false;
        let mut saw_int = false;
        let mut saw_float = false;
        let mut saw_string = false;
        let mut saw_set = false;
        let mut saw_empty_set = false;
        for case in catalog() {
            for (_key, value) in case.bag.iter() {
                match value {
                    AttributeValue::Bool(_) => saw_bool = true,
                    AttributeValue::Int(_) => saw_int = true,
                    AttributeValue::Float(_) => saw_float = true,
                    AttributeValue::String(_) => saw_string = true,
                    AttributeValue::StringSet(set) if set.is_empty() => saw_empty_set = true,
                    AttributeValue::StringSet(_) => saw_set = true,
                }
            }
        }
        assert!(saw_bool, "catalog must include AttributeValue::Bool");
        assert!(saw_int, "catalog must include AttributeValue::Int");
        assert!(saw_float, "catalog must include AttributeValue::Float");
        assert!(saw_string, "catalog must include AttributeValue::String");
        assert!(
            saw_set,
            "catalog must include a non-empty AttributeValue::StringSet"
        );
        assert!(
            saw_empty_set,
            "catalog must include an empty AttributeValue::StringSet"
        );
    }

    #[test]
    fn every_allowlist_entry_is_used_and_justified() {
        let catalog = catalog();
        for entry in allowlist() {
            assert!(
                !entry.reason.trim().is_empty(),
                "allowlist entry '{}' has no reason",
                entry.id
            );
            let used = catalog.iter().any(|c| match c.expect {
                Expect::Diverge(id) => id == entry.id,
                Expect::AgreeAllow | Expect::AgreeDeny { .. } => false,
            });
            assert!(
                used,
                "allowlist entry '{}' is unused — not justified",
                entry.id
            );
        }
    }

    #[test]
    fn every_diverge_id_is_on_the_allowlist() {
        for case in catalog() {
            if let Expect::Diverge(id) = case.expect {
                assert!(
                    allowlist_by_id(id).is_some(),
                    "case '{}' cites unknown allowlist id '{id}'",
                    case.name
                );
            }
        }
    }

    #[test]
    fn harness_kinds_match_drivers() {
        let mut from_const: Vec<&str> = HARNESS_PDP_KINDS.to_vec();
        let mut from_enum: Vec<&str> = Dialect::all().iter().map(|d| d.kind()).collect();
        from_const.sort_unstable();
        from_enum.sort_unstable();
        assert_eq!(
            from_const, from_enum,
            "HARNESS_PDP_KINDS must list every Dialect::kind"
        );
    }

    async fn run_case(case: &Case) {
        let mut got: HashMap<&str, (Outcome, String)> = HashMap::new();
        for dialect in Dialect::all() {
            let raw = evaluate(dialect, case).await;
            let detail = match &raw {
                Ok(d) => format!("{d:?}"),
                Err(e) => format!("Err({e})"),
            };
            got.insert(dialect.kind(), (classify(raw), detail));
        }

        match &case.expect {
            Expect::AgreeAllow => {
                for (kind, (outcome, detail)) in &got {
                    assert_eq!(
                        *outcome,
                        Outcome::allow(),
                        "case '{}': {kind} must Allow; got {detail}",
                        case.name
                    );
                }
            },
            Expect::AgreeDeny { cedar, cel, opa } => {
                assert_eq!(
                    got.len(),
                    HARNESS_PDP_KINDS.len(),
                    "case '{}': expected {} dialects, got {:?}",
                    case.name,
                    HARNESS_PDP_KINDS.len(),
                    got.keys().collect::<Vec<_>>()
                );
                let (cedar_out, cedar_detail) = by_kind(&got, "cedar-direct");
                let (cel_out, cel_detail) = by_kind(&got, "cel");
                let (opa_out, opa_detail) = by_kind(&got, "opa");
                assert_eq!(
                    cedar_out.kind, *cedar,
                    "case '{}': cedar cause kind; got {cedar_detail}",
                    case.name
                );
                assert_eq!(
                    cel_out.kind, *cel,
                    "case '{}': cel cause kind; got {cel_detail}",
                    case.name
                );
                assert_eq!(
                    opa_out.kind, *opa,
                    "case '{}': opa cause kind; got {opa_detail}",
                    case.name
                );
                for (kind, (outcome, detail)) in &got {
                    assert_eq!(
                        outcome.verdict,
                        Verdict::Deny,
                        "case '{}': {kind} must Deny; got {detail}",
                        case.name
                    );
                }
            },
            Expect::Diverge(id) => {
                let entry = allowlist_by_id(id)
                    .unwrap_or_else(|| panic!("case '{}': unknown allowlist id '{id}'", case.name));
                let (cedar_out, cedar_detail) = by_kind(&got, "cedar-direct");
                let (cel_out, cel_detail) = by_kind(&got, "cel");
                let (opa_out, opa_detail) = by_kind(&got, "opa");
                assert_eq!(
                    *cedar_out, entry.cedar,
                    "case '{}': cedar vs allowlist '{id}'; got {cedar_detail}",
                    case.name
                );
                assert_eq!(
                    *cel_out, entry.cel,
                    "case '{}': cel vs allowlist '{id}'; got {cel_detail}",
                    case.name
                );
                assert_eq!(
                    *opa_out, entry.opa,
                    "case '{}': opa vs allowlist '{id}'; got {opa_detail}",
                    case.name
                );
            },
        }
    }

    fn by_kind<'a>(got: &'a HashMap<&str, (Outcome, String)>, kind: &str) -> &'a (Outcome, String) {
        got.get(kind).unwrap_or_else(|| {
            panic!(
                "missing dialect '{kind}' (got keys: {:?})",
                got.keys().collect::<Vec<_>>()
            )
        })
    }
}
