// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 03: Eve, HR without `view_ssn`, gets through with `ssn` redacted on the
//! way in and on the way out.

use praxis_policy_test_utils::host::{Call, RefHost};
use praxis_policy_test_utils::idp::Persona;

use super::{each_pdp, jane, plant_minted, planted, upstream_calls};

/// The SSN must be hidden from both the returned record and diagnostics.
#[tokio::test]
async fn eve_gets_compensation_with_the_ssn_redacted_both_ways() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Eve, "get_compensation").args(jane(true));
        let mut planted = planted(&call);
        planted.plant("ssn", "123-45-6789");
        let out = host.call(call).await;
        assert!(out.allowed(), "{:?}", out.violation);
        assert_eq!(upstream_calls(&host), 1);

        let seen = out.upstream.as_ref().expect("the upstream was called");
        assert_eq!(seen.arguments["ssn"], "[REDACTED]", "request rewrite");
        assert_eq!(seen.arguments["include_ssn"], true, "only ssn is redacted");
        let record = out.record().expect("a record");
        assert_eq!(record["ssn"], "[REDACTED]", "response rewrite");
        assert_eq!(record["salary"], 125_000);

        plant_minted(&mut planted, &out);
        out.assert_no_leaks(&planted);
    })
    .await;
}
