// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 08 and 09: session taint. Reading compensation labels the session
//! `secret`, and a later email in it is refused. The label is keyed by
//! subject and session id together. One host per scenario, so the session
//! store persists across its calls. The bodies take the host, so live mode
//! runs them against Valkey.

use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::Persona;

use super::{clean_email, each_pdp, jane, plant_minted, planted, upstream_calls};

/// 08: a clean email, then a tainting read, then an email in the tainted
/// session.
#[tokio::test]
async fn an_email_from_a_tainted_session_is_denied() {
    each_pdp(|fixture| async move { tainted_session(RefHost::hermetic(fixture).await).await })
        .await;
}

/// 09: Eve taints a session id, and Bob under the same id is unaffected.
#[tokio::test]
async fn taint_does_not_cross_principals_sharing_a_session_id() {
    each_pdp(|fixture| async move { shared_session_id(RefHost::hermetic(fixture).await).await })
        .await;
}

/// The body of 08.
pub(super) async fn tainted_session(host: RefHost) {
    let call = Call::new(Persona::Bob, "send_email")
        .args(clean_email())
        .session("clean-1");
    let mut secrets = planted(&call);
    let s1 = host.call(call).await;
    assert!(s1.allowed(), "S1: {:?}", s1.violation);
    assert_eq!(upstream_calls(&host), 1, "S1");
    s1.assert_no_leaks(&secrets);

    let call = Call::new(Persona::Bob, "get_compensation")
        .args(jane(true))
        .session("taint-1");
    secrets.extend(&planted(&call));
    let s2 = host.call(call).await;
    assert!(s2.allowed(), "S2: {:?}", s2.violation);
    assert_eq!(upstream_calls(&host), 2, "S2");
    plant_minted(&mut secrets, &s2);
    s2.assert_no_leaks(&secrets);

    let call = Call::new(Persona::Bob, "send_email")
        .args(clean_email())
        .session("taint-1");
    secrets.extend(&planted(&call));
    let s3 = host.call(call).await;
    assert_eq!(s3.denied_at, Some(Stage::Request), "S3");
    assert_eq!(s3.violation_code(), Some("session_tainted_secret"), "S3");
    assert_eq!(s3.proto_error_code(), None, "S3: a plain -32001 deny");
    assert_eq!(upstream_calls(&host), 2, "S3 reaches no upstream");
    s3.assert_no_leaks(&secrets);
}

/// The body of 09.
pub(super) async fn shared_session_id(host: RefHost) {
    let call = Call::new(Persona::Bob, "send_email")
        .args(clean_email())
        .session("baseline-1");
    let mut secrets = planted(&call);
    let s1 = host.call(call).await;
    assert!(s1.allowed(), "S1: {:?}", s1.violation);
    s1.assert_no_leaks(&secrets);

    let call = Call::new(Persona::Eve, "get_compensation")
        .args(jane(true))
        .session("shared-1");
    secrets.extend(&planted(&call));
    let s2 = host.call(call).await;
    assert!(s2.allowed(), "S2: {:?}", s2.violation);
    plant_minted(&mut secrets, &s2);
    s2.assert_no_leaks(&secrets);

    let before = upstream_calls(&host);
    let call = Call::new(Persona::Bob, "send_email")
        .args(clean_email())
        .session("shared-1");
    secrets.extend(&planted(&call));
    let s3 = host.call(call).await;
    assert!(s3.allowed(), "S3: {:?}", s3.violation);
    assert_eq!(upstream_calls(&host), before + 1, "S3 is delivered");
    assert_eq!(s3.record().expect("a record")["status"], "sent", "S3");
    s3.assert_no_leaks(&secrets);
}
