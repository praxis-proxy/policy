// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Dialect cells for the safety catalog: missing attribute and malformed
//! policy, plus `{cedar, cel, opa} × {panic, error, timeout}` driven
//! through the evaluator so a new [`Dialect`] without a cell fails to
//! compile.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]

use std::sync::Arc;

use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::fault_testing::{FaultPdp, InjectedFailure, drive_pdp};
use praxis_policy_apl_core::step::{PdpDialect, PdpResolver};

use super::allowlist::allowlist_by_id;
use super::cases::catalog;
use super::classify::classify;
use super::drivers::{Dialect, evaluate};
use super::outcome::{CauseKind, Verdict};

fn pdp_dialect(dialect: Dialect) -> PdpDialect {
    match dialect {
        Dialect::Cedar => PdpDialect::Cedar,
        Dialect::Cel => PdpDialect::Cel,
        Dialect::Opa => PdpDialect::Opa,
    }
}

fn case_named(name: &str) -> super::cases::Case {
    catalog()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("catalog must contain {name}"))
}

#[tokio::test(start_paused = true)]
async fn every_dialect_has_panic_error_timeout_cells() {
    for dialect in Dialect::all() {
        let pdp_d = pdp_dialect(dialect);
        for failure in InjectedFailure::all() {
            let pdp: Arc<dyn PdpResolver> = Arc::new(FaultPdp::new(pdp_d.clone(), failure));
            let decision = drive_pdp(pdp).await;
            match failure {
                InjectedFailure::None => {
                    assert_eq!(
                        decision,
                        Decision::Allow,
                        "{:?} × {failure:?}: control must allow",
                        dialect.kind()
                    );
                },
                InjectedFailure::Error | InjectedFailure::Hang | InjectedFailure::Panic => {
                    assert!(
                        matches!(decision, Decision::Deny { .. }),
                        "{:?} × {failure:?}: expected Deny, got {decision:?}",
                        dialect.kind()
                    );
                },
            }
        }
    }
}

#[tokio::test]
async fn every_dialect_missing_attribute_is_not_allow() {
    let case = case_named("missing-subject-id");
    let expected = allowlist_by_id("missing-subject-id")
        .expect("missing-subject-id is on the differential allowlist");
    for dialect in Dialect::all() {
        let out = classify(evaluate(dialect, &case).await);
        let want = match dialect {
            Dialect::Cedar => expected.cedar.clone(),
            Dialect::Cel => expected.cel.clone(),
            Dialect::Opa => expected.opa.clone(),
        };
        assert_eq!(
            out,
            want,
            "{:?} missing subject.id must match the allowlist",
            dialect.kind()
        );
        assert_ne!(out.verdict, Verdict::Allow);
    }
}

#[tokio::test]
async fn every_dialect_malformed_policy_is_not_allow() {
    let mut case = case_named("string-id-allow");
    case.cedar_policy = "this is not a Cedar policy".to_owned();
    case.cel_expr = "!!!not cel".to_owned();
    case.opa_module = "package diff\nthis is not rego\n".to_owned();
    for dialect in Dialect::all() {
        let out = classify(evaluate(dialect, &case).await);
        assert_ne!(
            out.verdict,
            Verdict::Allow,
            "{:?} malformed policy must not allow ({out:?})",
            dialect.kind()
        );
        match dialect {
            Dialect::Cedar => {
                assert_eq!(
                    out.kind,
                    CauseKind::DispatchError,
                    "{:?} malformed Cedar is a load/dispatch error, got {out:?}",
                    dialect.kind()
                );
            },
            Dialect::Cel => {
                assert_eq!(
                    out.kind,
                    CauseKind::CompileError,
                    "{:?} malformed CEL is a compile error, got {out:?}",
                    dialect.kind()
                );
            },
            Dialect::Opa => {
                assert!(
                    matches!(out.kind, CauseKind::CompileError | CauseKind::DispatchError),
                    "{:?} malformed Rego is compile or dispatch, got {out:?}",
                    dialect.kind()
                );
            },
        }
    }
}
