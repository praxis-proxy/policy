// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 12: the request assertions contract. The upstream reads identity the
//! engine rendered, never a value the caller set.

use praxis_policy_test_utils::host::{Call, RefHost};
use praxis_policy_test_utils::idp::Persona;

use super::{each_pdp, jane, plant_minted, planted, upstream_calls};

/// Only asserted identity may reach upstream; the raw user token stays private.
#[tokio::test]
async fn the_upstream_sees_asserted_identity_and_no_user_token() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Bob, "get_compensation").args(jane(true));
        let mut planted = planted(&call);
        let out = host.call(call).await;
        assert!(out.allowed(), "{:?}", out.violation);
        assert_eq!(upstream_calls(&host), 1);

        let seen = out.upstream.as_ref().expect("the upstream was called");
        let header = |name: &str| seen.headers.get(name).map(String::as_str);
        assert_eq!(header("x-auth-user-id"), Some(Persona::Bob.sub()));
        assert_eq!(header("x-auth-username"), Some("bob"));
        assert_eq!(header("x-auth-roles"), Some("hr"));
        assert_eq!(header("x-user-token"), None);

        plant_minted(&mut planted, &out);
        out.assert_no_leaks(&planted);
    })
    .await;
}

/// A client-supplied asserted identity cannot override the verified subject.
#[tokio::test]
async fn a_spoofed_asserted_header_is_replaced_with_the_real_subject() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Bob, "get_compensation")
            .args(jane(true))
            .header("x-auth-user-id", "root");
        let mut planted = planted(&call);
        let out = host.call(call).await;
        assert!(out.allowed(), "{:?}", out.violation);
        assert_eq!(upstream_calls(&host), 1);

        let seen = out.upstream.as_ref().expect("the upstream was called");
        assert_eq!(
            seen.headers.get("x-auth-user-id").map(String::as_str),
            Some(Persona::Bob.sub())
        );

        plant_minted(&mut planted, &out);
        out.assert_no_leaks(&planted);
    })
    .await;
}
