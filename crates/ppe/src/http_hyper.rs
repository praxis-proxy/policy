// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A default `HttpTransport` on hyper, for hosts that inject none.
//
// PPE performs no HTTP itself: a host installs a transport and plugins
// borrow it, so the process has one connection pool, one TLS trust
// store, and one egress path. A proxy embedding PPE injects its own. But
// a CLI, a test harness, or anyone using PPE standalone has no client to
// lend, and "PPE cannot fetch a JWKS unless you write a transport first"
// is a bad first experience. This is the batteries.
//
// hyper rather than a client library, because reqwest *is* hyper plus a
// convenience layer and that layer is what we are removing. The stack
// below was already in the tree underneath reqwest, so taking it
// directly adds nothing and drops the ~28 crates reachable only through
// reqwest — most of them the ICU block that `url` pulls for IDNA-correct
// parsing, which `http::Uri` does not need and JWKS endpoints do not use.
//
// What we give up with the convenience layer, and why each is fine or
// better here:
//
//   * Redirect following — a JWKS URL that redirects is a URL that can
//     be redirected to an attacker's host. Not following is the safer
//     default and reqwest had to be told to stop.
//   * Automatic decompression — the documents are small.
//   * A JSON helper — callers parse with serde anyway.
//   * Cookie handling — irrelevant to a token endpoint.
//
// Not auto-wired. `install_default_http_transport` is an explicit call,
// so a stray feature unification cannot silently give a host a second
// HTTP stack it did not ask for.

use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};

/// The pooling client, shared by every request this transport serves.
type HyperClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// A `HttpTransport` backed by hyper with rustls.
///
/// One instance serves the whole process. The pool, the TLS
/// configuration, and every keepalive connection live inside it, which
/// is the point: a second instance would be a second pool against the
/// same `IdP`.
///
/// # Lazy by construction
///
/// The client is built on first use, not in the constructor. A host may
/// build this during `PolicyEngine::initialize()`, and some hosts drive
/// that on a short-lived runtime that is dropped before the first
/// request arrives — Praxis does exactly this, because its filter
/// factory signature is sync. Connections created eagerly would be bound
/// to that dead reactor. Building on first use means the pool lands on
/// whichever runtime actually serves traffic.
#[derive(Debug)]
pub struct HyperTransport {
    client: OnceLock<HyperClient>,
    connect_timeout: Duration,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    tcp_keepalive: Option<Duration>,
    http2: bool,
}

impl Default for HyperTransport {
    fn default() -> Self {
        Self {
            client: OnceLock::new(),
            // A fixed default rather than "whatever the first request
            // asked for": the connector is built once and shared, so
            // deferring to a request would make the pool-wide bound
            // depend on which call happened to arrive first.
            connect_timeout: praxis_policy_core::http::DEFAULT_CONNECT_TIMEOUT,
            // hyper-util's own default, but only if a timer is wired —
            // see `client()`.
            pool_idle_timeout: Some(Duration::from_secs(90)),
            // Matches what reqwest resolved to. Idle eviction is what
            // actually bounds the pool; this is the second line.
            pool_max_idle_per_host: usize::MAX,
            // Off in both reqwest and hyper-util by default. On here,
            // deliberately — see the field docs on `with_tcp_keepalive`.
            tcp_keepalive: Some(Duration::from_secs(60)),
            // ALPN offers h2 and falls back to http/1.1, so this costs
            // nothing against a peer that does not speak it.
            http2: true,
        }
    }
}

impl HyperTransport {
    /// A transport that builds its pool on first use.
    pub fn new() -> Self {
        Self::default()
    }

    /// How long an idle pooled connection is kept before eviction.
    ///
    /// `None` keeps idle connections indefinitely, which is rarely what
    /// anyone wants against an `IdP` behind a load balancer.
    #[must_use]
    pub fn with_pool_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.pool_idle_timeout = timeout;
        self
    }

    /// Cap idle connections retained per host.
    ///
    /// Defaults to unlimited, matching reqwest, because idle eviction is
    /// the primary bound. Set this when an embedder needs a hard ceiling
    /// on sockets rather than a time-based one.
    #[must_use]
    pub fn with_pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.pool_max_idle_per_host = max;
        self
    }

    /// TCP keepalive probe interval on pooled connections.
    ///
    /// On by default at 60s, which differs from both reqwest and
    /// hyper-util. The reason is the retry contract rather than
    /// throughput: a NAT or load balancer that silently drops an idle
    /// connection leaves the pool holding a socket it believes is good.
    /// The next request writes into it and gets a reset, which surfaces
    /// as [`HttpTransportError::Io`] — and `Io` reads as *may have
    /// reached the peer*, so a token mint will refuse to retry a request
    /// that in truth never left the process. Keepalive shrinks that
    /// window by detecting the dead peer before a request is handed the
    /// socket.
    ///
    /// `None` disables it.
    #[must_use]
    pub fn with_tcp_keepalive(mut self, interval: Option<Duration>) -> Self {
        self.tcp_keepalive = interval;
        self
    }

    /// The connect bound applied to every request.
    ///
    /// Defaults to [`DEFAULT_CONNECT_TIMEOUT`]. It is fixed at
    /// construction because the connector is built once and shared; a
    /// per-request connect bound would mean a per-request connector, and
    /// therefore a per-request pool, which is the whole thing this
    /// transport exists to avoid.
    ///
    /// So this transport does not honor [`HttpRequest::connect_timeout`],
    /// which is documented as a hint for that reason. A request asking
    /// for a tighter bound is still bounded by its overall `timeout`.
    ///
    /// [`DEFAULT_CONNECT_TIMEOUT`]: praxis_policy_core::http::DEFAULT_CONNECT_TIMEOUT
    /// [`HttpRequest::connect_timeout`]: praxis_policy_core::http::HttpRequest::connect_timeout
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Offer HTTP/2 during TLS negotiation.
    ///
    /// On by default. ALPN advertises `h2` and `http/1.1`, so a peer that
    /// does not speak HTTP/2 simply negotiates HTTP/1.1 and nothing
    /// changes. Plaintext connections stay HTTP/1.1 regardless, since
    /// there is no ALPN to negotiate over.
    ///
    /// It is worth having: a delegating deployment mints a token per
    /// request, and HTTP/2 carries those concurrently over one connection
    /// instead of one connection each. That removes both the per-request
    /// connection churn and the head-of-line blocking an HTTP/1.1 pool
    /// has, where a slow response holds its connection against every
    /// other request waiting for one.
    ///
    /// Set `false` to force HTTP/1.1. The reason to reach for it is an
    /// `IdP` whose HTTP/2 implementation misbehaves — rare, but the
    /// failure would otherwise be a puzzling one to diagnose, so the
    /// escape hatch is worth its two lines.
    #[must_use]
    pub fn with_http2(mut self, enabled: bool) -> Self {
        self.http2 = enabled;
        self
    }

    /// The shared client, built on first call.
    fn client(&self) -> &HyperClient {
        self.client.get_or_init(|| {
            let mut http = HttpConnector::new();
            // The HTTPS connector wraps this one, so it must accept the
            // `https` scheme rather than rejecting it as non-HTTP.
            http.enforce_http(false);
            http.set_connect_timeout(Some(self.connect_timeout));
            // hyper-util defaults this to false; reqwest sets it true.
            // Leaving Nagle on would let a small request body — a token
            // exchange form is a couple of hundred bytes — sit waiting to
            // coalesce with data that never comes, adding tens of
            // milliseconds to a call on the request path.
            http.set_nodelay(true);
            http.set_keepalive(self.tcp_keepalive);

            let tls = hyper_rustls::HttpsConnectorBuilder::new()
                // Webpki roots rather than the system store, matching
                // what the reqwest path resolved to and keeping the
                // trust set identical across every deployment.
                .with_webpki_roots()
                // `https_or_http`, not `https_only`: `identity-jwt`
                // supports an explicit `insecure_http: true` for local
                // development, and it already refuses plaintext by
                // default one layer up. Enforcing here as well would
                // make that setting silently ineffective.
                .https_or_http();

            // `enable_all_versions` advertises ALPN `h2, http/1.1`;
            // `enable_http1` advertises none. Either way a peer that
            // cannot do HTTP/2 gets HTTP/1.1, and plaintext gets it
            // regardless since there is no ALPN without TLS.
            let https = if self.http2 {
                tls.enable_all_versions().wrap_connector(http)
            } else {
                tls.enable_http1().wrap_connector(http)
            };

            Client::builder(TokioExecutor::new())
                // Without a timer, `pool_idle_timeout` silently does
                // nothing and idle connections are never evicted. With
                // `pool_max_idle_per_host` defaulting to unlimited, that
                // is unbounded socket growth against a busy `IdP`, which
                // is a slow leak rather than an error anyone would see.
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(self.pool_idle_timeout)
                .pool_max_idle_per_host(self.pool_max_idle_per_host)
                .build(https)
        })
    }
}

/// Map a hyper client error onto the transport vocabulary.
///
/// The distinction that matters is whether the peer could have acted on
/// the request: a caller uses it to decide between retrying and
/// recording an indeterminate outcome. `is_connect()` is the only signal
/// hyper gives us that nothing was sent, so anything else is `Io`, which
/// reads as "may have reached the peer" and is the safe direction to err
/// in. Guessing `Connect` for an ambiguous failure would license a retry
/// that mints a second token.
fn classify(err: &hyper_util::client::legacy::Error) -> HttpTransportError {
    if err.is_connect() {
        HttpTransportError::Connect(err.to_string())
    } else {
        HttpTransportError::Io(err.to_string())
    }
}

#[async_trait]
impl HttpTransport for HyperTransport {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let uri: http::Uri = req
            .url
            .parse()
            .map_err(|e| HttpTransportError::InvalidRequest(format!("url '{}': {e}", req.url)))?;

        if uri.host().is_none() {
            return Err(HttpTransportError::InvalidRequest(format!(
                "url '{}' has no host",
                req.url
            )));
        }

        let mut builder = http::Request::builder().method(req.method.clone()).uri(uri);
        // Safe: `Request::builder()` starts with an empty header map and
        // no error, so the map is present until a fallible step runs.
        if let Some(headers) = builder.headers_mut() {
            headers.clone_from(&req.headers);
        }
        let hyper_req = builder
            .body(Full::new(req.body.clone()))
            .map_err(|e| HttpTransportError::InvalidRequest(e.to_string()))?;

        // `req.connect_timeout` is not consulted: the bound belongs to the
        // shared connector. See `with_connect_timeout`. The overall
        // deadline below still covers the connect phase.
        let client = self.client();
        let limit = req.max_response_bytes;

        // The deadline covers the *whole* exchange, headers and body.
        //
        // Wrapping only `client.request()` would bound nothing useful:
        // that future resolves as soon as the response head arrives, so
        // a peer that answers `200` and then stalls mid-body would hang
        // here forever — the precise failure a deadline exists to stop,
        // and the one that hangs gateway startup when a JWKS endpoint
        // goes bad. Both legs go inside one timeout.
        let exchange = async {
            let resp = client.request(hyper_req).await.map_err(|e| classify(&e))?;
            let (parts, body) = resp.into_parts();

            // Bound the body *during* collection, not after. Reading it
            // all and then checking the length is what the ceiling
            // exists to prevent: a hostile endpoint would already have
            // been buffered by the time we looked.
            //
            // `Limited` fails for two unrelated reasons — the ceiling was
            // exceeded, or the underlying body errored mid-stream — and
            // they must not collapse. Reporting a truncated connection as
            // `ResponseTooLarge` would send an operator to raise a limit
            // that was never the problem, and it lies about delivery:
            // an oversized response was answered in full, a broken one
            // was not.
            let body = match Limited::new(body, limit).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
                    return Err(HttpTransportError::ResponseTooLarge {
                        actual: limit.saturating_add(1),
                        limit,
                    });
                },
                Err(e) => return Err(HttpTransportError::Io(e.to_string())),
            };

            Ok::<_, HttpTransportError>(
                HttpResponse::new(parts.status.as_u16(), body).with_headers(parts.headers),
            )
        };

        tokio::time::timeout(req.timeout, exchange)
            .await
            // `Elapsed` carries no detail worth keeping; the deadline is
            // already on the request the caller built.
            .map_err(|_elapsed| HttpTransportError::Timeout)?
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unparseable_url_is_a_request_error_not_a_connect_error() {
        // The distinction is load-bearing: `Connect` reads as "nothing
        // was sent, safe to retry", and retrying a malformed URL is a
        // busy loop against a bug.
        let t = HyperTransport::new();
        let err = t
            .execute(HttpRequest::get("not a url at all"))
            .await
            .expect_err("that is not a URL");
        assert!(
            matches!(err, HttpTransportError::InvalidRequest(_)),
            "got {err:?}"
        );
        assert!(!err.may_have_reached_peer());
    }

    #[tokio::test]
    async fn a_url_with_no_host_is_rejected_before_dialling() {
        let t = HyperTransport::new();
        let err = t
            .execute(HttpRequest::get("file:///etc/passwd"))
            .await
            .expect_err("no host to dial");
        assert!(matches!(err, HttpTransportError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn a_connection_refused_reports_connect_and_is_retryable() {
        // Port 1 on loopback: nothing listens, and the refusal arrives
        // without anything being sent — so a caller may safely retry
        // even a token mint.
        let t = HyperTransport::new();
        let err = t
            .execute(HttpRequest::get("http://127.0.0.1:1/jwks"))
            .await
            .expect_err("nothing listens there");
        assert!(
            matches!(err, HttpTransportError::Connect(_)),
            "expected Connect, got {err:?}"
        );
        assert!(
            !err.may_have_reached_peer(),
            "a refused connection sent nothing, so a retry cannot duplicate anything"
        );
    }

    #[tokio::test]
    async fn the_pool_is_not_built_until_the_first_request() {
        // The runtime-binding guard. A host may construct this during
        // `initialize()` on a runtime that is dropped before any request
        // arrives; connections created eagerly would be bound to a dead
        // reactor. Constructing must therefore touch no reactor at all.
        let t = HyperTransport::new();
        assert!(
            t.client.get().is_none(),
            "constructing must not build the pool"
        );
        let _ = t.execute(HttpRequest::get("http://127.0.0.1:1/x")).await;
        assert!(t.client.get().is_some(), "first use must build the pool");
    }

    #[test]
    fn the_defaults_bound_the_pool_and_disable_nagle() {
        // These three are the difference between "works in a demo" and
        // "survives a week against a busy IdP", and each defaults the
        // wrong way somewhere in the stack:
        //
        //   * hyper-util defaults nodelay off; reqwest turned it on.
        //   * `pool_idle_timeout` does nothing without `pool_timer`, so
        //     idle sockets are never evicted.
        //   * `pool_max_idle_per_host` is unlimited, so eviction is the
        //     only thing bounding the pool.
        let t = HyperTransport::new();
        assert_eq!(
            t.pool_idle_timeout,
            Some(Duration::from_secs(90)),
            "idle connections must be evicted, or the pool grows without bound"
        );
        assert!(
            t.tcp_keepalive.is_some(),
            "keepalive is what stops a silently-dropped connection being handed to a request"
        );
    }

    #[test]
    fn http2_is_offered_by_default_and_can_be_forced_off() {
        // ALPN advertises h2 alongside http/1.1, so this is free against
        // a peer that cannot do it. The escape hatch exists for an IdP
        // whose HTTP/2 misbehaves, which would otherwise be a puzzling
        // failure to track down.
        assert!(HyperTransport::new().http2);
        assert!(!HyperTransport::new().with_http2(false).http2);
    }

    #[test]
    fn pool_bounds_are_tunable_by_the_embedder() {
        // A host embedding PPE standalone needs to bound sockets to its
        // own deployment, not to ours.
        let t = HyperTransport::new()
            .with_pool_idle_timeout(Some(Duration::from_secs(5)))
            .with_pool_max_idle_per_host(4)
            .with_tcp_keepalive(None);
        assert_eq!(t.pool_idle_timeout, Some(Duration::from_secs(5)));
        assert_eq!(t.pool_max_idle_per_host, 4);
        assert!(t.tcp_keepalive.is_none());
    }

    #[test]
    fn the_connect_bound_comes_from_the_transport_not_from_a_request() {
        // The connector is built once and shared, so this has to be
        // decided before any request arrives. Taking it from a request
        // instead would mean whichever plugin called first — JWKS at 2s,
        // a token exchange at its own value — silently set the bound for
        // every other plugin, and which one that is depends on ordering.
        assert_eq!(
            HyperTransport::new().connect_timeout,
            praxis_policy_core::http::DEFAULT_CONNECT_TIMEOUT,
        );
        assert_eq!(
            HyperTransport::new()
                .with_connect_timeout(Duration::from_millis(250))
                .connect_timeout,
            Duration::from_millis(250),
        );
    }

    #[test]
    fn constructing_outside_a_runtime_does_not_panic() {
        // Deliberately not a `#[tokio::test]`: there is no reactor here
        // at all. If construction ever starts needing one, this fails
        // rather than surfacing as dead connections in production.
        let t = HyperTransport::new().with_connect_timeout(Duration::from_secs(1));
        assert!(t.client.get().is_none());
    }
}
