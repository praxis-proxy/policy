// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Safety invariant catalog for the PDP evaluator seam.
//!
//! `{cedar, cel, opa} × {none, error, hang, panic}`. Panic, error, and
//! hang deny. The control allows. A new `PdpDialect` builtin used here
//! is an exhaustive match on the three shipped dialects.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::sync::Arc;

use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::fault_testing::{
    FaultPdp, InjectedFailure, drive_pdp, shipped_harness_dialects,
};
use praxis_policy_apl_core::step::{PdpDialect, PdpResolver};

#[tokio::test(start_paused = true)]
async fn pdp_fault_catalog_asserts_the_safe_verdict() {
    for dialect in shipped_harness_dialects() {
        for failure in InjectedFailure::all() {
            let pdp: Arc<dyn PdpResolver> = Arc::new(FaultPdp::new(dialect.clone(), failure));
            let decision = drive_pdp(pdp).await;
            match failure {
                InjectedFailure::None => {
                    assert_eq!(
                        decision,
                        Decision::Allow,
                        "{dialect:?} × {failure:?}: control must allow"
                    );
                },
                InjectedFailure::Error => {
                    assert_deny_reason(&decision, "PDP error", dialect.clone(), failure);
                },
                InjectedFailure::Hang => {
                    assert_deny_reason(&decision, "PDP timed out", dialect.clone(), failure);
                },
                InjectedFailure::Panic => {
                    assert_deny_reason(&decision, "panicked", dialect.clone(), failure);
                },
            }
        }
    }
}

fn assert_deny_reason(
    decision: &Decision,
    needle: &str,
    dialect: PdpDialect,
    failure: InjectedFailure,
) {
    match decision {
        Decision::Deny { reason, .. } => {
            let reason = reason.as_deref().unwrap_or("");
            assert!(
                reason.contains(needle),
                "{dialect:?} × {failure:?}: deny reason {reason:?} must contain {needle:?}"
            );
        },
        other => panic!("{dialect:?} × {failure:?}: expected Deny, got {other:?}"),
    }
}
