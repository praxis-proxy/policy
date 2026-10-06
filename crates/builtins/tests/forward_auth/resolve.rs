// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What the resolver does with each answer: a valid session becomes a subject,
//! a rejected one stays unauthenticated, and only an unreachable endpoint denies.

use std::sync::Arc;

use praxis_policy_core::http::Method;
use praxis_policy_core::http_testing::FakeTransport;

use crate::support;

/// A success status with the identity headers projects onto the subject, with
/// groups on `teams` and email kept in the claims bag.
#[tokio::test]
async fn a_valid_session_becomes_a_subject() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(
        202,
        &[
            ("x-auth-request-user", "alice"),
            ("x-auth-request-email", "alice@example.com"),
            ("x-auth-request-groups", "admins"),
        ],
    );

    let result = support::resolve(&resolver, support::with_cookie("_session=abc"), transport).await;

    let subject = support::subject_of(&result).expect("a valid session fills the subject");
    assert_eq!(subject.id.as_deref(), Some("alice"));
    assert!(subject.teams.contains("admins"), "groups map to teams");
    assert_eq!(
        subject
            .claims
            .get("x-auth-request-email")
            .and_then(|v| v.as_str()),
        Some("alice@example.com"),
        "email is kept in the claims bag"
    );
    assert!(result.violation.is_none(), "a valid session is not a deny");
    assert!(
        result
            .modified_payload
            .as_ref()
            .is_some_and(|payload| payload.raw_credentials.is_none()),
        "the session must not be stashed for forwarding"
    );
}

/// 200 is a success too, not only 202.
#[tokio::test]
async fn the_configured_success_statuses_all_authenticate() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(200, &[("x-auth-request-user", "bob")]);

    let result = support::resolve(&resolver, support::with_cookie("session=1"), transport).await;

    assert_eq!(
        support::subject_of(&result).and_then(|s| s.id),
        Some("bob".to_owned())
    );
}

/// A reachable endpoint that rejects the session resolves unauthenticated: no
/// subject, and crucially no deny, so the authorization layer can bounce to
/// login rather than the host answering a fixed 401.
#[tokio::test]
async fn a_rejected_session_is_unauthenticated_not_a_deny() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(401, &[]);

    let result = support::resolve(
        &resolver,
        support::with_cookie("stale=1"),
        Arc::clone(&transport),
    )
    .await;

    assert!(
        result.violation.is_none(),
        "a rejected session must not deny"
    );
    assert!(
        support::subject_of(&result).is_none(),
        "a rejected session fills no subject"
    );
    assert!(
        result.modified_payload.is_some(),
        "the payload is still threaded on, just without an identity"
    );
    assert_eq!(
        transport.call_count_for(support::FRAGMENT),
        1,
        "the endpoint was asked before the session was rejected"
    );
}

/// Header names are matched case-insensitively: a config written in HTTP
/// title-case still forwards the lowercase host `cookie` and maps the subject,
/// matching the casing coverage in `api_key/extraction.rs`.
#[tokio::test]
async fn header_names_are_matched_case_insensitively() {
    let block = serde_json::json!({
        "endpoint": support::ENDPOINT,
        "forward_headers": ["Cookie"],
        "identity_headers": ["X-Auth-Request-User"],
        "claim_map": { "subject": { "id": "x-auth-request-user" } },
    });
    let resolver = support::resolver(block).expect("the config builds");
    let transport = support::response(202, &[("x-auth-request-user", "alice")]);

    let result = support::resolve(
        &resolver,
        support::with_cookie("_session=abc"),
        Arc::clone(&transport),
    )
    .await;

    assert_eq!(
        support::subject_of(&result).and_then(|s| s.id),
        Some("alice".to_owned()),
        "a title-case identity header still maps"
    );
    let request = transport.last_request().expect("a request was made");
    assert_eq!(
        request.headers.get("cookie").and_then(|v| v.to_str().ok()),
        Some("_session=abc"),
        "the lowercase host `cookie` is forwarded despite the title-case config"
    );
}

/// A `403` is the endpoint reaching a verdict and refusing the session: a denied
/// caller under its own code, kept apart from an outage or a sign-out.
#[tokio::test]
async fn a_forbidden_session_denies_as_forbidden() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(403, &[]);

    let result = support::resolve(&resolver, support::with_cookie("session=1"), transport).await;

    assert_eq!(
        support::denial_code(&result).as_deref(),
        Some("auth.forbidden")
    );
}

/// A `503` is no credential verdict. It fails closed rather than signing the
/// caller out on an endpoint fault. RFC 9110 §15.6.4 defines 503 as the service
/// being unable to handle the request, not a statement about the session.
#[tokio::test]
async fn a_server_error_denies_fail_closed() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(503, &[]);

    let result = support::resolve(&resolver, support::with_cookie("session=1"), transport).await;

    assert_eq!(
        support::denial_code(&result).as_deref(),
        Some("auth.endpoint_unavailable"),
        "an endpoint 5xx is a fault, not a rejected session"
    );
}

/// An endpoint that bounces with `302` instead of `401` resolves unauthenticated
/// once that status is configured, leaving the login redirect to the
/// authorization layer.
#[tokio::test]
async fn a_configured_redirect_status_is_unauthenticated() {
    let mut block = support::config();
    block["unauthenticated_status"] = serde_json::json!([302]);
    let resolver = support::resolver(block).expect("the config builds");
    let transport = support::response(302, &[]);

    let result = support::resolve(&resolver, support::with_cookie("stale=1"), transport).await;

    assert!(
        result.violation.is_none(),
        "a configured redirect is not a deny"
    );
    assert!(
        support::subject_of(&result).is_none(),
        "a redirect fills no subject"
    );
}

/// With no forwardable header on the request there is no session to delegate, so
/// the handler resolves unauthenticated without spending a round trip.
#[tokio::test]
async fn a_missing_credential_costs_no_request() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(202, &[("x-auth-request-user", "alice")]);

    let result = support::resolve(
        &resolver,
        std::collections::HashMap::new(),
        Arc::clone(&transport),
    )
    .await;

    assert!(result.violation.is_none(), "no credential is not a deny");
    assert!(support::subject_of(&result).is_none());
    assert_eq!(
        transport.call_count(),
        0,
        "nothing should have been sent for a request with no credential"
    );
}

/// A host that wired no transport, or withheld it, is a deployment fault. It
/// fails closed so a browser is held at the edge rather than let through.
#[tokio::test]
async fn no_transport_denies_fail_closed() {
    let resolver = support::resolver(support::config()).expect("the config builds");

    let result =
        support::resolve_without_transport(&resolver, support::with_cookie("session=1")).await;

    assert_eq!(
        support::denial_code(&result).as_deref(),
        Some("auth.endpoint_unavailable")
    );
}

/// A transport that runs and fails also denies fail-closed, rather than letting
/// an unverified session through.
#[tokio::test]
async fn a_transport_failure_denies_fail_closed() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = Arc::new(FakeTransport::new().fail(
        support::FRAGMENT,
        praxis_policy_core::http::HttpTransportError::Timeout,
    ));

    let result = support::resolve(&resolver, support::with_cookie("session=1"), transport).await;

    assert_eq!(
        support::denial_code(&result).as_deref(),
        Some("auth.endpoint_unavailable")
    );
}

/// A success status with no mappable identity is the BFF not emitting the
/// identity headers — a deployment fault, denied so it surfaces rather than
/// bouncing a signed-in user to login forever.
#[tokio::test]
async fn a_success_without_identity_denies_as_mapping_failed() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(202, &[("x-some-other-header", "x")]);

    let result = support::resolve(&resolver, support::with_cookie("session=1"), transport).await;

    assert_eq!(
        support::denial_code(&result).as_deref(),
        Some("auth.mapping_failed")
    );
}

/// The credential is forwarded verbatim onto the sub-request, and only the
/// configured headers are — nothing else on the inbound request leaks.
#[tokio::test]
async fn the_credential_is_forwarded_verbatim() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(202, &[("x-auth-request-user", "alice")]);

    let mut headers = support::with_cookie("_session=opaque-value");
    headers.insert(
        "authorization".to_owned(),
        "Bearer should-not-leak".to_owned(),
    );
    let _ = support::resolve(&resolver, headers, Arc::clone(&transport)).await;

    let request = transport.last_request().expect("a request was made");
    assert_eq!(
        request.headers.get("cookie").and_then(|v| v.to_str().ok()),
        Some("_session=opaque-value"),
        "the cookie rides the sub-request unchanged"
    );
    assert!(
        request.headers.get("authorization").is_none(),
        "a header not in forward_headers must not be forwarded"
    );
}

/// The default method is GET, which is what a `ForwardAuth` endpoint expects.
#[tokio::test]
async fn the_default_method_is_get() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(202, &[("x-auth-request-user", "alice")]);

    let _ = support::resolve(
        &resolver,
        support::with_cookie("session=1"),
        Arc::clone(&transport),
    )
    .await;

    assert_eq!(
        transport.last_request().expect("a request").method,
        Method::GET
    );
}

/// A configured method is honored on the sub-request.
#[tokio::test]
async fn a_configured_method_reaches_the_request() {
    let mut block = support::config();
    block["method"] = serde_json::json!("POST");
    let resolver = support::resolver(block).expect("the config builds");
    let transport = support::response(202, &[("x-auth-request-user", "alice")]);

    let _ = support::resolve(
        &resolver,
        support::with_cookie("session=1"),
        Arc::clone(&transport),
    )
    .await;

    assert_eq!(
        transport.last_request().expect("a request").method,
        Method::POST
    );
}

/// A repeated identity header becomes a multi-valued record, so a repeated
/// `X-Auth-Request-Groups` maps to several teams with no splitting.
#[tokio::test]
async fn repeated_identity_headers_map_to_several_values() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(
        202,
        &[
            ("x-auth-request-user", "alice"),
            ("x-auth-request-groups", "admins"),
            ("x-auth-request-groups", "readers"),
        ],
    );

    let result = support::resolve(&resolver, support::with_cookie("session=1"), transport).await;

    let subject = support::subject_of(&result).expect("a valid session fills the subject");
    assert!(subject.teams.contains("admins"));
    assert!(subject.teams.contains("readers"));
}

/// A forwarded header whose value cannot be rendered onto the sub-request denies
/// rather than silently dropping the credential.
#[tokio::test]
async fn an_unforwardable_header_value_denies() {
    let resolver = support::resolver(support::config()).expect("the config builds");
    let transport = support::response(202, &[("x-auth-request-user", "alice")]);

    // A newline is a legal `String` but not a legal header value.
    let result = support::resolve(
        &resolver,
        support::with_cookie("line1\nline2"),
        Arc::clone(&transport),
    )
    .await;

    assert_eq!(
        support::denial_code(&result).as_deref(),
        Some("auth.endpoint_unavailable")
    );
    assert_eq!(
        transport.call_count(),
        0,
        "a request that could not be built is never sent"
    );
}

/// `connect_timeout_secs` reaches the request rather than being parsed and
/// dropped.
#[tokio::test]
async fn the_connect_timeout_reaches_the_request() {
    let mut block = support::config();
    block["timeout_secs"] = serde_json::json!(9);
    block["connect_timeout_secs"] = serde_json::json!(2);
    let resolver = support::resolver(block).expect("the config builds");
    let transport = support::response(202, &[("x-auth-request-user", "alice")]);

    let _ = support::resolve(
        &resolver,
        support::with_cookie("session=1"),
        Arc::clone(&transport),
    )
    .await;

    let request = transport.last_request().expect("a request was made");
    assert_eq!(request.timeout, std::time::Duration::from_secs(9));
    assert_eq!(
        request.connect_timeout,
        Some(std::time::Duration::from_secs(2))
    );
}
