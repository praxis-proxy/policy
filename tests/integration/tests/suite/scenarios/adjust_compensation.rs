// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 10: an adjustment under the $10k threshold applies with no approval.

use praxis_policy_test_utils::host::{Call, RefHost};
use praxis_policy_test_utils::idp::{CIBA_BACKCHANNEL_URL, Persona};

use super::{adjust, audit_for, each_pdp, planted, upstream_calls};

/// An amount below the gate must apply without contacting the CIBA OP.
#[tokio::test]
async fn a_small_adjustment_applies_without_approval() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Bob, "adjust_compensation").args(adjust(5000));
        let planted = planted(&call);
        let out = host.call(call).await;
        assert!(out.allowed(), "{:?}", out.violation);
        assert_eq!(upstream_calls(&host), 1);
        assert_eq!(
            host.transport().call_count_for(CIBA_BACKCHANNEL_URL),
            0,
            "no approval was requested"
        );
        let record = out.record().expect("a record");
        assert_eq!(record["status"], "applied");
        assert_eq!(record["new_salary"], 130_000);
        assert_eq!(audit_for(&out, "adjust_compensation").len(), 1);
        out.assert_no_leaks(&planted);
    })
    .await;
}
