// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The bundled hyper transport against a real socket.
//
// The unit tests in `http_hyper` cover the paths that never reach the
// network — a malformed URL, a refused connection. These cover the ones
// that do, because the bounds this transport is responsible for
// (deadline, body ceiling, header round-trip) only mean anything against
// a server that actually answers.

//! End-to-end coverage for the bundled hyper transport.
#![cfg(feature = "http-hyper")]
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::time::Duration;

use bytes::Bytes;
use praxis_policy::HyperTransport;
use praxis_policy_core::http::{HttpRequest, HttpTransport as _, HttpTransportError};

#[tokio::test]
async fn a_plain_http_get_round_trips() {
    // `https_or_http`, not `https_only`: identity-jwt exposes an explicit
    // `insecure_http: true` for local development. If this transport
    // enforced TLS, that setting would silently stop working.
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_header("cache-control", "max-age=300")
        .with_body(r#"{"keys":[]}"#)
        .create_async()
        .await;

    let t = HyperTransport::new();
    let resp = t
        .execute(HttpRequest::get(format!("{}/jwks", server.url())))
        .await
        .expect("the mock answers");

    m.assert_async().await;
    assert_eq!(resp.status, 200);
    assert!(resp.is_success());
    assert_eq!(&*resp.body, br#"{"keys":[]}"#);
    assert_eq!(resp.etag(), Some("\"v1\""));
    assert_eq!(resp.cache_max_age(), Some(Duration::from_secs(300)));
}

#[tokio::test]
async fn request_headers_and_a_post_body_reach_the_server() {
    // The token-exchange shape. If either half were dropped the IdP would
    // reject the exchange, and the failure would look like an IdP problem
    // rather than a transport one.
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/token")
        .match_header("content-type", "application/x-www-form-urlencoded")
        .match_header("authorization", "Basic abc")
        .match_body("grant_type=client_credentials")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let req = HttpRequest::post(
        format!("{}/token", server.url()),
        Bytes::from_static(b"grant_type=client_credentials"),
    )
    .header("content-type", "application/x-www-form-urlencoded")
    .expect("legal header")
    .header("authorization", "Basic abc")
    .expect("legal header");

    let resp = HyperTransport::new()
        .execute(req)
        .await
        .expect("mock answers");
    m.assert_async().await;
    assert_eq!(resp.status, 200);
}

#[tokio::test]
async fn a_non_2xx_status_is_a_response_not_an_error() {
    // The caller interprets status: a 404 from a JWKS endpoint is a
    // config problem, a 400 from a token endpoint is a definitive
    // rejection. Collapsing either into a transport error loses that.
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/missing")
        .with_status(404)
        .with_body("nope")
        .create_async()
        .await;

    let resp = HyperTransport::new()
        .execute(HttpRequest::get(format!("{}/missing", server.url())))
        .await
        .expect("a 404 is still a response");
    assert_eq!(resp.status, 404);
    assert!(!resp.is_success());
}

#[tokio::test]
async fn a_304_is_not_a_success_but_is_not_a_failure_either() {
    // The conditional-request happy path. `is_success()` is false for
    // 304, so a caller reaching for the reflexive `if !is_success()
    // { Err }` would turn every successful revalidation into a
    // fail-closed denial.
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/jwks")
        .match_header("if-none-match", "\"v1\"")
        .with_status(304)
        .create_async()
        .await;

    let req = HttpRequest::get(format!("{}/jwks", server.url()))
        .header("if-none-match", "\"v1\"")
        .expect("legal header");
    let resp = HyperTransport::new()
        .execute(req)
        .await
        .expect("mock answers");

    assert!(resp.is_not_modified());
    assert!(!resp.is_success());
}

#[tokio::test]
async fn an_oversized_body_is_refused_rather_than_truncated() {
    // A truncated JWKS document is indistinguishable from a malformed
    // one, so the ceiling has to fail loudly. This is also the bound
    // reqwest never gave us: without it a hostile endpoint streams until
    // the process dies.
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/big")
        .with_status(200)
        .with_body("x".repeat(4096))
        .create_async()
        .await;

    let req = HttpRequest::get(format!("{}/big", server.url())).max_response_bytes(128);
    let err = HyperTransport::new()
        .execute(req)
        .await
        .expect_err("4096 bytes exceeds a 128-byte ceiling");

    match err {
        HttpTransportError::ResponseTooLarge { limit, .. } => assert_eq!(limit, 128),
        other => panic!("expected ResponseTooLarge, got {other:?}"),
    }
}

/// Answers with a complete response head promising a body, then never
/// sends one and holds the connection open.
///
/// This is the shape a connect timeout does not cover and the head-only
/// deadline did not either: an earlier version of the transport wrapped
/// only `client.request()`, which resolves as soon as the head arrives,
/// leaving body collection unbounded. Against this server that hung
/// forever. `mockito` cannot express it, because its response is written
/// as a unit.
async fn spawn_stalling_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt as _;
                // Consume whatever the client sends; we never parse it.
                let mut buf = [0_u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                // A head promising 100 bytes, followed by silence.
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    .await;
                let _ = sock.flush().await;
                // Hold the connection open without ever sending the body.
                std::future::pending::<()>().await;
            });
        }
    });

    format!("http://{addr}")
}

#[tokio::test]
async fn a_server_that_stalls_mid_body_trips_the_deadline() {
    // Regression guard. The deadline must cover the whole exchange, not
    // just the response head — otherwise a peer that answers `200` and
    // then stops hangs the call forever, which is precisely what hangs
    // gateway startup when a JWKS endpoint goes bad.
    let base = spawn_stalling_server().await;

    let req = HttpRequest::get(format!("{base}/jwks")).timeout(Duration::from_millis(200));
    let started = std::time::Instant::now();
    let err = HyperTransport::new()
        .execute(req)
        .await
        .expect_err("the server never finishes the body");

    assert_eq!(err, HttpTransportError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the deadline must fire promptly, not wait on a body that never arrives"
    );
    assert!(
        err.may_have_reached_peer(),
        "a timeout cannot prove the request never landed, so it must not license a retry \
         of a non-idempotent call"
    );
}

#[tokio::test]
async fn one_transport_serves_many_requests_from_one_pool() {
    // Centralization, end to end: the same instance handles repeated
    // calls, reusing its pool rather than standing up a client per
    // request.
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_body("{}")
        .expect(3)
        .create_async()
        .await;

    let t = HyperTransport::new();
    for _ in 0..3 {
        let resp = t
            .execute(HttpRequest::get(format!("{}/jwks", server.url())))
            .await
            .expect("mock answers");
        assert_eq!(resp.status, 200);
    }
    m.assert_async().await;
}

/// The transport survives the runtime it was constructed on being
/// dropped.
///
/// This is the host shape that motivates the lazy pool. A sync filter
/// factory cannot await, so it drives async initialization on a
/// throwaway current-thread runtime and drops it as soon as
/// initialization returns. A transport built there that eagerly opened
/// connections would bind them to a reactor that no longer exists, and
/// the first real request would fail for reasons pointing nowhere near
/// the cause.
///
/// Constructing must therefore touch no reactor at all, and the pool
/// must be built on whichever runtime first serves traffic.
#[tokio::test]
async fn a_transport_built_on_a_dropped_runtime_still_works() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_body(r#"{"keys":[]}"#)
        .expect(1)
        .create_async()
        .await;
    let url = format!("{}/jwks", server.url());

    // Build it on a runtime that is then dropped, exactly as a sync
    // filter factory would.
    let transport = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("init runtime");
        rt.block_on(async { HyperTransport::new() })
        // `rt` drops here.
    })
    .join()
    .expect("init thread");

    // First use is on this runtime, which is a different one entirely.
    let resp = transport
        .execute(HttpRequest::get(url))
        .await
        .expect("the pool must be built on the runtime that serves the request");
    assert_eq!(resp.status, 200);
}
