// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 01: Bob, holding `view_ssn`, reads compensation through a delegated
//! `workday-api` token.

use praxis_policy_test_utils::host::{Call, RefHost};
use praxis_policy_test_utils::idp::Persona;

use super::{SSN_PROBE, each_pdp, jane, plant_minted, planted, upstream_calls};

/// The permitted HR read uses a route-scoped delegated token.
#[tokio::test]
async fn bob_reads_compensation_with_a_delegated_token() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Bob, "get_compensation").args(jane(true));
        let mut planted = planted(&call);
        let out = host.call(call).await;
        assert!(out.allowed(), "{:?}", out.violation);
        assert_eq!(upstream_calls(&host), 1);

        let seen = out.upstream.as_ref().expect("the upstream was called");
        let bearer = seen.jwt_claims("authorization").expect("a bearer");
        assert_eq!(
            bearer["aud"], "workday-api",
            "the tool gets its own audience"
        );
        assert!(
            !seen.headers.contains_key("x-user-token"),
            "{:?}",
            seen.headers.keys()
        );
        assert_eq!(seen.arguments["ssn"], SSN_PROBE, "no redact for view_ssn");
        assert_eq!(out.record().expect("a record")["ssn"], "123-45-6789");

        // AE1: the minted token stays between the gateway and the tool.
        plant_minted(&mut planted, &out);
        out.assert_no_leaks(&planted);
    })
    .await;
}
