// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Outbound HTTP — the transport seam.
//
// PPE performs no HTTP of its own. A plugin needing an outbound call (a
// JWKS fetch, an IdP token exchange, a CIBA backchannel) borrows a
// host-installed `HttpTransport` through `HostServices`, gated by the
// `perform_http` capability.
//
// The indirection is the point. A proxy embedding PPE already owns an
// HTTP stack: a connection pool, a TLS trust store, an egress policy, a
// circuit breaker, outbound tracing. A client compiled into PPE would be
// a *second* one — a second pool against the same IdP, a second trust
// store the operator configures separately, and an egress path the
// host's own policy never sees. Borrowing the host's transport keeps one
// stack in the process.
//
// It is also what makes PPE embeddable where a bundled client could not
// go. A WASM host with no sockets of its own supplies an implementation
// backed by host imports; nothing in this module names a runtime, a TLS
// backend, or a socket.
//
// The trait is deliberately one method. Everything a caller might want
// to layer on top — form encoding, retries, redirect policy, JSON
// decoding — stays caller-side, so every implementation sees identical
// bytes. Push encoding into the implementations and two of them can
// encode differently, which surfaces in production rather than in
// review.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue};

/// Re-exported because they appear in this module's public API.
///
/// `HttpRequest::method` and `headers` are public fields, and
/// `HttpResponse::with_headers` takes a `HeaderMap` — so without this a
/// host implementing [`HttpTransport`], or a test using
/// [`FakeTransport::respond`], would have to add a direct `http`
/// dependency just to name a type this crate handed it.
///
/// [`FakeTransport::respond`]: crate::http_testing::FakeTransport::respond
pub use http::{HeaderMap, Method};

/// Default overall deadline for a request that does not set one.
///
/// Five seconds matches the JWKS fetch bound `identity-jwt` already
/// applied, which was chosen so a slow or hostile endpoint cannot hang
/// gateway startup.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default connect bound for a request that does not set one.
///
/// Separate from the overall deadline so a half-open endpoint fails
/// while the connection is still being established rather than
/// consuming the whole budget.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Default ceiling on a buffered response body, in bytes.
///
/// One mebibyte is generous for what PPE actually fetches — a JWKS
/// document runs to single-digit kilobytes and an OAuth token response
/// to hundreds of bytes. The ceiling exists because a hand-rolled read
/// loop against an untrusted endpoint will otherwise buffer whatever it
/// is sent. `reqwest` imposed no limit here either, so this closes a gap
/// rather than tightening a bound.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// One outbound HTTP request.
///
/// Construct with [`HttpRequest::get`] / [`HttpRequest::post`] /
/// [`HttpRequest::new`] and refine with the builder methods. The struct
/// is `#[non_exhaustive]`, so fields can be added without breaking
/// callers; reading the fields from an implementation stays fine.
///
/// Bounds are per-request rather than per-transport because the three
/// call sites differ: a JWKS fetch at startup can afford a longer
/// deadline than a token exchange sitting in a request's critical path.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request method.
    pub method: Method,

    /// Absolute request URL, including scheme.
    ///
    /// A `String` rather than a parsed type so this crate takes no
    /// opinion on URL parsing. Implementations parse with whatever their
    /// stack already uses, and an unparseable URL surfaces as
    /// [`HttpTransportError::InvalidRequest`].
    pub url: String,

    /// Request headers. `Host` is the implementation's to set, since it
    /// derives from the URL and from any connection reuse the transport
    /// performs.
    pub headers: HeaderMap,

    /// Request body. Empty for a bodyless method.
    pub body: Bytes,

    /// Overall deadline covering connect and I/O. Exceeding it is
    /// [`HttpTransportError::Timeout`].
    pub timeout: Duration,

    /// Bound on connection establishment alone. `None` leaves it to the
    /// implementation.
    ///
    /// A hint rather than a guarantee. A transport that pools connections
    /// configures the connect bound once for the pool, so a per-request
    /// value it cannot apply is ignored — the bundled hyper transport
    /// does exactly this. `timeout` is the bound that always holds, and
    /// it covers the connect phase, so ignoring this one shortens no
    /// deadline and loses no safety.
    ///
    /// Set it when the caller wants connect to fail faster than the
    /// overall deadline would allow, and treat honoring it as a bonus.
    pub connect_timeout: Option<Duration>,

    /// Ceiling on the buffered response body. Exceeding it is
    /// [`HttpTransportError::ResponseTooLarge`] rather than a truncated
    /// body, because a truncated JWKS document is indistinguishable from
    /// a malformed one.
    pub max_response_bytes: usize,
}

impl HttpRequest {
    /// A request with the given method and URL, carrying the default
    /// bounds and no headers or body.
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: Some(DEFAULT_CONNECT_TIMEOUT),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// A `GET` for `url`.
    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::GET, url)
    }

    /// A `POST` to `url` carrying `body`.
    pub fn post(url: impl Into<String>, body: Bytes) -> Self {
        let mut req = Self::new(Method::POST, url);
        req.body = body;
        req
    }

    /// Set a header, replacing any existing value for that name.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::InvalidRequest`] when the name or
    /// value is not a legal header. Taking the error here rather than
    /// panicking matters because both can come from operator config.
    pub fn header(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, HttpTransportError> {
        let name = HeaderName::try_from(name.as_ref())
            .map_err(|e| HttpTransportError::InvalidRequest(format!("header name: {e}")))?;
        let value = HeaderValue::try_from(value.as_ref())
            .map_err(|e| HttpTransportError::InvalidRequest(format!("header value: {e}")))?;
        self.headers.insert(name, value);
        Ok(self)
    }

    /// Replace the request body.
    #[must_use]
    pub fn body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }

    /// Set the overall deadline.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the connect bound.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Set the response body ceiling.
    #[must_use]
    pub fn max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }
}

/// Encode `pairs` as an `application/x-www-form-urlencoded` body.
///
/// Caller-side rather than a transport concern, deliberately. Every OAuth
/// exchange PPE performs is a form POST, and if each transport encoded
/// its own, two of them could encode differently — which surfaces as an
/// `IdP` rejecting an exchange in production rather than as a diff in
/// review. One encoder means every transport sees identical bytes.
///
/// Follows the WHATWG URL form-urlencoded serializer: unreserved
/// characters pass through, a space becomes `+`, and everything else is
/// percent-encoded. Note `*`, `-`, `.` and `_` are unreserved here, so a
/// scope string such as `read:users` percent-encodes only the colon.
///
/// The caller still sets `Content-Type: application/x-www-form-urlencoded`;
/// this produces the body, not the header, because a transport must not
/// have to guess which of the two a caller meant.
pub fn form_urlencode(pairs: &[(&str, &str)]) -> Bytes {
    fn encode_into(out: &mut String, raw: &str) {
        for byte in raw.as_bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                    out.push(*byte as char);
                },
                b' ' => out.push('+'),
                other => {
                    out.push('%');
                    out.push(
                        char::from_digit(u32::from(other >> 4), 16)
                            .unwrap_or('0')
                            .to_ascii_uppercase(),
                    );
                    out.push(
                        char::from_digit(u32::from(other & 0xF), 16)
                            .unwrap_or('0')
                            .to_ascii_uppercase(),
                    );
                },
            }
        }
    }

    let mut out = String::new();
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode_into(&mut out, key);
        out.push('=');
        encode_into(&mut out, value);
    }
    Bytes::from(out)
}

/// A buffered HTTP response.
///
/// Buffered rather than streaming because every PPE call site parses a
/// small document in full — a JWKS set, a token response. A streaming
/// variant can be added later without disturbing this one.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Response status code.
    pub status: u16,

    /// Response headers.
    pub headers: HeaderMap,

    /// Response body, already bounded by the request's
    /// `max_response_bytes`.
    pub body: Bytes,
}

impl HttpResponse {
    /// A response with the given status and body and no headers.
    ///
    /// Chiefly for test transports; a real implementation fills
    /// `headers` from the wire.
    pub fn new(status: u16, body: Bytes) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body,
        }
    }

    /// Attach response headers.
    ///
    /// [`HttpResponse`] is `#[non_exhaustive]`, so a transport outside
    /// this crate — which is every real one — cannot build it with a
    /// struct literal. This is the supported path, and it keeps adding a
    /// field later from breaking implementations.
    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Whether the status is in the 2xx range.
    ///
    /// A non-2xx status is *not* an error at this layer. Interpreting a
    /// status is the caller's job: a `404` from a JWKS endpoint and a
    /// `400` from a token endpoint mean different things and map to
    /// different deny codes.
    ///
    /// Note this is **false for `304 Not Modified`**, which is a
    /// successful revalidation rather than a failure. A caller making
    /// conditional requests must check [`is_not_modified`] first; see
    /// that method for why.
    ///
    /// [`is_not_modified`]: Self::is_not_modified
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Whether the peer answered `304 Not Modified`.
    ///
    /// The happy path of a conditional request: the cached copy is still
    /// current and the body was not resent. A JWKS refresh that sends
    /// `If-None-Match` gets this on every poll where the `IdP` has not
    /// rotated, which is nearly all of them.
    ///
    /// This exists as its own method because `304` sits outside the 2xx
    /// range, so the reflexive `if !resp.is_success() { return Err }`
    /// turns every successful revalidation into a failure — and for
    /// `identity-jwt` that failure is fail-closed.
    pub fn is_not_modified(&self) -> bool {
        self.status == 304
    }

    /// The `ETag` header, when the peer sent a valid one.
    ///
    /// Feed it back as `If-None-Match` on the next fetch to make a
    /// refresh cost a round trip instead of a document.
    pub fn etag(&self) -> Option<&str> {
        self.headers.get("etag").and_then(|v| v.to_str().ok())
    }

    /// The `max-age` directive from `Cache-Control`, in seconds.
    ///
    /// A caller uses this to decide when its cached copy is stale rather
    /// than guessing with a fixed interval. Absent, unparseable, or
    /// `no-store`/`no-cache` all yield `None`, so the caller falls back
    /// to its configured default rather than caching something the peer
    /// asked it not to.
    pub fn cache_max_age(&self) -> Option<Duration> {
        let raw = self.headers.get("cache-control")?.to_str().ok()?;
        let mut max_age = None;
        for directive in raw.split(',') {
            let directive = directive.trim();
            if directive.eq_ignore_ascii_case("no-store")
                || directive.eq_ignore_ascii_case("no-cache")
            {
                return None;
            }
            if let Some(v) = directive
                .split_once('=')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("max-age"))
                .map(|(_, v)| v.trim())
            {
                max_age = v.parse::<u64>().ok().map(Duration::from_secs);
            }
        }
        max_age
    }
}

/// Why an outbound request did not produce a response.
///
/// Transport-level only. A response with a discouraging status code is
/// an `Ok(HttpResponse)`, because only the caller knows what a given
/// status means for its own protocol.
///
/// `#[non_exhaustive]` because a host may distinguish failures this
/// crate has no vocabulary for yet; a caller matching exhaustively today
/// should not break when one is added.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpTransportError {
    /// The request exceeded its deadline.
    ///
    /// Distinct from [`Self::Connect`] and [`Self::Io`] because callers
    /// act on it differently. `identity-jwt` treats a timed-out JWKS
    /// fetch as soft-fail-at-boot rather than a configuration error, and
    /// a delegation timeout must map to "unknown" rather than
    /// "rejected", since a token may still have been minted.
    Timeout,

    /// The connection could not be established.
    Connect(String),

    /// The connection was established but the exchange failed.
    Io(String),

    /// The request could not be formed — an unparseable URL, an illegal
    /// header. Always a bug or a configuration error, never transient.
    InvalidRequest(String),

    /// The response body exceeded the request's ceiling. The body is
    /// discarded rather than truncated.
    ResponseTooLarge {
        /// Bytes seen before the read was abandoned.
        actual: usize,
        /// The ceiling that was exceeded.
        limit: usize,
    },

    /// The host declined to make the request at all.
    ///
    /// Egress policy, an SSRF guard, admission control, or an open
    /// circuit. Deliberately distinct from [`Self::Connect`]: "we
    /// declined to try" and "we tried and failed" send an operator to
    /// different places, and collapsing them turns a blocked destination
    /// into a phantom network problem.
    Rejected(String),
}

impl HttpTransportError {
    /// Whether the peer may have received and acted on the request.
    ///
    /// This is the question a caller actually needs, and it is not the
    /// same as "should I retry". Retry safety is idempotency plus this;
    /// only the caller knows the first half. A JWKS `GET` is safe to
    /// repeat regardless. An RFC 8693 token exchange is not: repeat one
    /// that already landed and the `IdP` mints a second credential
    /// nobody is tracking.
    ///
    /// `true` means *unknown*, not *certain*. A timeout cannot
    /// distinguish "never arrived" from "arrived, and the response was
    /// lost on the way back", so it answers `true` and the caller must
    /// treat the outcome as indeterminate rather than failed.
    ///
    /// This maps onto the effect-log triad a delegating plugin records:
    /// `false` is a clean `rejected`, `true` is `unknown` and wants
    /// reconciliation rather than an assumption.
    pub fn may_have_reached_peer(&self) -> bool {
        match self {
            // Nothing was ever sent.
            Self::Connect(_) | Self::InvalidRequest(_) | Self::Rejected(_) => false,
            // Sent, and the outcome is genuinely unknown.
            Self::Timeout | Self::Io(_) => true,
            // Definitely delivered and answered — we just refused to
            // buffer the answer.
            Self::ResponseTooLarge { .. } => true,
        }
    }
}

impl fmt::Display for HttpTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "request timed out"),
            Self::Connect(m) => write!(f, "connection failed: {m}"),
            Self::Io(m) => write!(f, "transport error: {m}"),
            Self::InvalidRequest(m) => write!(f, "malformed request: {m}"),
            Self::ResponseTooLarge { actual, limit } => write!(
                f,
                "response body exceeded the {limit}-byte ceiling (saw at least {actual} bytes)"
            ),
            Self::Rejected(m) => write!(f, "request refused by the host: {m}"),
        }
    }
}

impl std::error::Error for HttpTransportError {}

/// Performs outbound HTTP on PPE's behalf.
///
/// Implemented by the host, never by this crate. A proxy implements it
/// over its own client so PPE's outbound calls share the process's pool,
/// TLS material, egress policy, and tracing. A WASM host implements it
/// over host imports. Tests implement it over a canned table, which is
/// how timeout and error mapping become assertable without socket
/// timing.
///
/// # One instance, shared
///
/// An implementation is **never cloned**. The host constructs exactly
/// one, hands it over as `Arc<dyn HttpTransport>`, and every holder
/// downstream — the engine, each request's `Extensions`, each plugin's
/// filtered view — carries a refcount bump on that same object. So the
/// connection pool, the TLS material, and any circuit-breaker state are
/// process-wide by construction rather than by discipline. That is the
/// whole point: a second instance would be a second pool against the
/// same `IdP`, which is what this seam exists to prevent.
///
/// The trait therefore does not require `Clone`, and an implementation
/// holding a pool need not make one cheap to copy. It does need interior
/// mutability and to be safe to call concurrently from many tasks, since
/// one instance serves every request in the process.
///
/// # Retries
///
/// An implementation **must not** retry at the application level. Two of
/// PPE's three callers issue non-idempotent `POST`s — a token exchange
/// and a CIBA backchannel registration — where a blind repeat mints a
/// second credential or asks a human to approve the same thing twice.
/// The transport cannot know which requests are safe to repeat; the
/// caller can, and owns the decision. See
/// [`HttpTransportError::may_have_reached_peer`].
///
/// One narrow exception is not an application retry and is expected: if
/// a connection came from a keepalive pool and turned out to be closed
/// before any request bytes were written, resending on a fresh
/// connection is invisible to the peer and correct even for a `POST`.
/// The distinction is whether the peer could have observed the request,
/// never whether the failure looked transient.
///
/// # Runtime binding
///
/// An implementation **must not** bind pooled connections to whichever
/// runtime happened to construct it. A host may build the transport
/// during a short-lived initialization runtime that is dropped before
/// the first request arrives, at which point connections created eagerly
/// are already dead. Build pools lazily on first use.
#[async_trait]
pub trait HttpTransport: Send + Sync + fmt::Debug {
    /// Perform one request and buffer the response.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError`] when no response was obtained. A
    /// response carrying any status, including 5xx, is `Ok`.
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError>;
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

    #[test]
    fn form_encoding_matches_what_an_idp_expects() {
        // The OAuth shapes PPE actually sends. An encoder that differs
        // here fails at the IdP, not in review.
        assert_eq!(
            &*form_urlencode(&[("grant_type", "client_credentials")]),
            b"grant_type=client_credentials"
        );
        assert_eq!(&*form_urlencode(&[("a", "1"), ("b", "2")]), b"a=1&b=2");
        // A space is `+`, not `%20`, in form encoding specifically —
        // this is the classic way a hand-rolled encoder goes wrong, and
        // a space-separated `scope` is exactly where it bites.
        assert_eq!(
            &*form_urlencode(&[("scope", "read write")]),
            b"scope=read+write"
        );
        // Reserved characters percent-encode uppercase.
        assert_eq!(
            &*form_urlencode(&[("scope", "read:users")]),
            b"scope=read%3Ausers"
        );
        // Unreserved pass through untouched.
        assert_eq!(&*form_urlencode(&[("k", "a*-._z")]), b"k=a*-._z");
        // A JWT assertion is base64url, whose `-` and `_` must survive
        // and whose `=` padding must not.
        assert_eq!(
            &*form_urlencode(&[("client_assertion", "aB-_9.xY=")]),
            b"client_assertion=aB-_9.xY%3D"
        );
        assert!(form_urlencode(&[]).is_empty());
    }

    #[test]
    fn form_encoding_escapes_the_separators_it_uses() {
        // A value containing `&` or `=` must not be able to forge extra
        // parameters. Getting this wrong lets a crafted scope inject a
        // `grant_type` the caller never asked for.
        assert_eq!(&*form_urlencode(&[("x", "a&b=c")]), b"x=a%26b%3Dc");
    }

    // ---- response cache headers ----------------------------------------
    //
    // These decide how long a caller may hold a JWKS document and whether
    // a revalidation counts as success. Both failure directions are
    // expensive: caching past a rotation denies valid tokens, and treating
    // a `304` as a failure turns the cheap path into a fail-closed one.

    /// A response carrying `headers`, given as `(name, value)` pairs.
    fn resp_with(status: u16, headers: &[(&str, &str)]) -> HttpResponse {
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        HttpResponse::new(status, Bytes::new()).with_headers(map)
    }

    #[test]
    fn a_revalidation_is_recognized_as_one() {
        // `304` is outside the 2xx range, so the two must not be confused:
        // the reflexive `if !is_success() { return Err }` would turn every
        // successful revalidation into a JWKS fetch failure.
        assert!(resp_with(304, &[]).is_not_modified());
        assert!(!resp_with(304, &[]).is_success());
        assert!(!resp_with(200, &[]).is_not_modified());
        assert!(!resp_with(404, &[]).is_not_modified());
    }

    #[test]
    fn an_etag_is_returned_only_when_the_peer_sent_a_usable_one() {
        // Quotes are part of the tag and must survive: an `If-None-Match`
        // sent without them never matches, so every refresh silently
        // re-downloads the document.
        assert_eq!(resp_with(200, &[("etag", "\"v1\"")]).etag(), Some("\"v1\""));
        assert_eq!(
            resp_with(200, &[("etag", "W/\"weak\"")]).etag(),
            Some("W/\"weak\"")
        );
        assert_eq!(resp_with(200, &[]).etag(), None);
    }

    #[test]
    fn max_age_is_read_from_cache_control() {
        assert_eq!(
            resp_with(200, &[("cache-control", "max-age=300")]).cache_max_age(),
            Some(Duration::from_secs(300))
        );
        // Multi-directive, in either order, with the whitespace a real
        // `IdP` sends.
        assert_eq!(
            resp_with(200, &[("cache-control", "public, max-age=600")]).cache_max_age(),
            Some(Duration::from_secs(600))
        );
        assert_eq!(
            resp_with(200, &[("cache-control", "max-age=600, must-revalidate")]).cache_max_age(),
            Some(Duration::from_secs(600))
        );
        // Directive names are case-insensitive per RFC 9111.
        assert_eq!(
            resp_with(200, &[("cache-control", "Max-Age=42")]).cache_max_age(),
            Some(Duration::from_secs(42))
        );
        assert_eq!(
            resp_with(200, &[("cache-control", "max-age=0")]).cache_max_age(),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn no_store_and_no_cache_beat_a_max_age_in_the_same_header() {
        // The peer asking us not to hold the document wins over the
        // lifetime it also stated. Order must not matter: a caller that
        // honored `max-age=300` because it appeared first would cache a
        // document the `IdP` explicitly said not to.
        for raw in [
            "no-store",
            "no-cache",
            "no-store, max-age=300",
            "max-age=300, no-store",
            "max-age=300, no-cache",
            "public, No-Cache, max-age=300",
        ] {
            assert_eq!(
                resp_with(200, &[("cache-control", raw)]).cache_max_age(),
                None,
                "`{raw}` must not yield a cacheable lifetime"
            );
        }
    }

    #[test]
    fn an_unusable_cache_control_yields_no_lifetime() {
        // `None` means "the caller falls back to its configured default",
        // so every one of these has to reach it rather than producing a
        // number invented from a malformed header.
        for raw in [
            // No header at all is covered separately below.
            "",
            "max-age",
            "max-age=",
            "max-age=abc",
            // Negative and overflowing values do not parse as `u64`.
            "max-age=-1",
            "max-age=99999999999999999999999",
            // A directive that merely starts the same way is not `max-age`.
            "s-maxage=600",
            "public",
        ] {
            assert_eq!(
                resp_with(200, &[("cache-control", raw)]).cache_max_age(),
                None,
                "`{raw}` must not yield a lifetime"
            );
        }
        assert_eq!(resp_with(200, &[]).cache_max_age(), None);
    }

    #[test]
    fn an_unparseable_max_age_does_not_leave_an_earlier_one_standing() {
        // A repeated directive is malformed input. The later value wins,
        // including when it is the unusable one, so a peer cannot get a
        // lifetime honored by appending garbage after it.
        assert_eq!(
            resp_with(200, &[("cache-control", "max-age=300, max-age=abc")]).cache_max_age(),
            None
        );
        assert_eq!(
            resp_with(200, &[("cache-control", "max-age=abc, max-age=300")]).cache_max_age(),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn a_qualified_no_cache_is_not_treated_as_a_bare_one() {
        // `no-cache="set-cookie"` restricts one field rather than the
        // whole response, so the stated `max-age` still applies. Pinned
        // because the bare-string comparison that implements the
        // unqualified form is what makes this fall through, and someone
        // "fixing" it with `starts_with` would break this case.
        assert_eq!(
            resp_with(
                200,
                &[("cache-control", "no-cache=\"set-cookie\", max-age=300")]
            )
            .cache_max_age(),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn a_new_request_carries_the_default_bounds() {
        // The defaults are the safety net for a caller that sets
        // nothing. An unbounded default would mean a hostile endpoint
        // could hang or exhaust memory through any plugin that forgot.
        let req = HttpRequest::get("https://idp.example.com/jwks");
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.timeout, DEFAULT_TIMEOUT);
        assert_eq!(req.connect_timeout, Some(DEFAULT_CONNECT_TIMEOUT));
        assert_eq!(req.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert!(req.body.is_empty());
    }

    #[test]
    fn builders_override_the_defaults() {
        let req = HttpRequest::post("https://idp.example.com/token", Bytes::from_static(b"a=1"))
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(1))
            .max_response_bytes(64);
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.timeout, Duration::from_secs(30));
        assert_eq!(req.connect_timeout, Some(Duration::from_secs(1)));
        assert_eq!(req.max_response_bytes, 64);
        assert_eq!(&*req.body, b"a=1");
    }

    #[test]
    fn an_illegal_header_is_an_error_rather_than_a_panic() {
        // Header names and values can come from operator config, so a
        // bad one must be reportable rather than fatal.
        let err = HttpRequest::get("https://example.com")
            .header("not a header name", "v")
            .expect_err("a header name with a space is not legal");
        assert!(matches!(err, HttpTransportError::InvalidRequest(_)));

        let err = HttpRequest::get("https://example.com")
            .header("x-ok", "bad\nvalue")
            .expect_err("a header value with a newline is not legal");
        assert!(matches!(err, HttpTransportError::InvalidRequest(_)));
    }

    #[test]
    fn a_non_success_status_is_not_a_transport_error() {
        // The caller decides what a status means. A 404 from a JWKS
        // endpoint is a configuration problem; a 400 from a token
        // endpoint is a definitive rejection. Collapsing either into a
        // transport error would lose that.
        let resp = HttpResponse::new(404, Bytes::new());
        assert!(!resp.is_success());
        let resp = HttpResponse::new(204, Bytes::new());
        assert!(resp.is_success());
    }

    #[test]
    fn rejected_and_connect_render_differently() {
        // "We declined to try" and "we tried and failed" send an
        // operator to different places. The messages have to say which.
        let rejected = HttpTransportError::Rejected("egress policy".to_owned()).to_string();
        let connect = HttpTransportError::Connect("refused".to_owned()).to_string();
        assert!(rejected.contains("refused by the host"), "{rejected}");
        assert!(connect.contains("connection failed"), "{connect}");
        assert_ne!(rejected, connect);
    }

    #[test]
    fn delivery_is_reported_separately_from_failure() {
        // The caller pairs this with its own idempotency knowledge to
        // decide on a retry, and a delegating plugin uses it to choose
        // between recording a mint as `rejected` and as `unknown`.
        // Getting `Timeout` wrong here mints duplicate credentials.
        assert!(!HttpTransportError::Connect("refused".to_owned()).may_have_reached_peer());
        assert!(!HttpTransportError::InvalidRequest("bad url".to_owned()).may_have_reached_peer());
        assert!(!HttpTransportError::Rejected("egress".to_owned()).may_have_reached_peer());

        assert!(
            HttpTransportError::Timeout.may_have_reached_peer(),
            "a timeout cannot distinguish 'never arrived' from 'the reply was lost', \
             so it must read as indeterminate rather than failed"
        );
        assert!(HttpTransportError::Io("reset".to_owned()).may_have_reached_peer());
        assert!(
            HttpTransportError::ResponseTooLarge {
                actual: 2,
                limit: 1
            }
            .may_have_reached_peer(),
            "the peer answered; we declined to buffer the answer"
        );
    }

    #[test]
    fn response_too_large_names_both_numbers() {
        // An operator hitting this needs to know the ceiling to decide
        // whether to raise it or distrust the endpoint.
        let msg = HttpTransportError::ResponseTooLarge {
            actual: 2048,
            limit: 1024,
        }
        .to_string();
        assert!(msg.contains("1024"), "{msg}");
        assert!(msg.contains("2048"), "{msg}");
    }
}
