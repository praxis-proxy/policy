// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 02: Alice, an engineer, fails the `require(role.hr)` gate before any
//! delegation runs.

use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{Persona, TOKEN_EXCHANGE_URL};

use super::{each_pdp, jane, planted, upstream_calls};

/// A role denial must stop before token exchange or upstream dispatch.
#[tokio::test]
async fn alice_is_denied_compensation_at_the_role_gate() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Alice, "get_compensation").args(jane(false));
        let planted = planted(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request));
        assert_eq!(
            out.violation_code(),
            Some("routes.tool:get_compensation.pre_invocation[0]")
        );
        assert_eq!(out.proto_error_code(), None, "a plain -32001 deny");
        assert_eq!(upstream_calls(&host), 0);
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "the deny precedes the exchange"
        );
        out.assert_no_leaks(&planted);
    })
    .await;
}
