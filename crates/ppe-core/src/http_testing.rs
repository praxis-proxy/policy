// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A scripted `HttpTransport` for tests.
//
// Once outbound HTTP is a seam, a plugin's tests no longer need a real
// server to exercise it. That is worth more than the convenience: a
// mock server can serve a document, but it cannot easily produce a
// connect failure, a timeout, or a response that arrives and then
// stalls — and those are the paths where a plugin's behaviour actually
// matters, because they decide between denying, retrying, and recording
// an outcome as indeterminate.
//
// So this exists to make the awkward half assertable. Wire mechanics are
// the transport's own concern and are tested against real sockets where
// the transport lives; what a plugin does with a `Timeout` is tested
// here, deterministically and without sleeping.
//
// Matching is by URL substring rather than by exact URL because test
// servers hand out ephemeral ports, and a test that has to thread a base
// URL through three layers to assert on a path is a test nobody updates.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;

use crate::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};

/// What a [`FakeTransport`] should do for one matching request.
type Reply = Result<HttpResponse, HttpTransportError>;

/// One programmed rule: a URL fragment and the replies queued for it.
struct Rule {
    fragment: String,
    /// Replies are consumed in order. The last one repeats once the
    /// queue is down to it, so a test that cares about rotation queues
    /// two and a test that does not queues one.
    replies: VecDeque<Reply>,
}

/// An `HttpTransport` that answers from a script and records what it was
/// asked.
///
/// ```
/// # use praxis_policy_core::http_testing::FakeTransport;
/// # use praxis_policy_core::http::HttpTransportError;
/// let http = FakeTransport::new()
///     .json("/jwks", 200, r#"{"keys":[]}"#)
///     .fail("/token", HttpTransportError::Timeout);
/// ```
#[derive(Default)]
pub struct FakeTransport {
    rules: Mutex<Vec<Rule>>,
    seen: Mutex<Vec<HttpRequest>>,
    /// Held open for this long before answering. See
    /// [`FakeTransport::with_latency`].
    latency: Option<Duration>,
}

impl std::fmt::Debug for FakeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTransport")
            .field("calls", &self.call_count())
            .finish()
    }
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("fragment", &self.fragment)
            .field("queued", &self.replies.len())
            .finish()
    }
}

impl FakeTransport {
    /// A transport with no rules. An unmatched request fails with
    /// [`HttpTransportError::Connect`], so a test that forgets to
    /// program an endpoint sees a clear failure rather than a
    /// mysterious success.
    pub fn new() -> Self {
        Self::default()
    }

    fn push(self, fragment: &str, reply: Reply) -> Self {
        {
            let mut rules = self
                .rules
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(existing) = rules.iter_mut().find(|r| r.fragment == fragment) {
                existing.replies.push_back(reply);
            } else {
                rules.push(Rule {
                    fragment: fragment.to_owned(),
                    replies: VecDeque::from([reply]),
                });
            }
        }
        self
    }

    /// Answer any URL containing `fragment` with `status` and `body`.
    ///
    /// Calling twice for the same fragment queues a second reply, which
    /// is how a rotation test says "first this key set, then that one".
    #[must_use]
    pub fn json(self, fragment: &str, status: u16, body: &str) -> Self {
        self.push(
            fragment,
            Ok(HttpResponse::new(
                status,
                Bytes::copy_from_slice(body.as_bytes()),
            )),
        )
    }

    /// Answer with a fully-specified response, for tests that care about
    /// headers such as `ETag` or `Cache-Control`.
    #[must_use]
    pub fn respond(self, fragment: &str, status: u16, body: &str, headers: HeaderMap) -> Self {
        self.push(
            fragment,
            Ok(
                HttpResponse::new(status, Bytes::copy_from_slice(body.as_bytes()))
                    .with_headers(headers),
            ),
        )
    }

    /// Hold every call open for `latency` before answering.
    ///
    /// An instant transport cannot express concurrency. Two calls never
    /// overlap, so a test cannot tell a caller that collapses concurrent
    /// requests into one from a caller that simply runs them fast enough
    /// that they never meet — and single-flight, `try_lock` and
    /// wait-budget behaviour are exactly the things that only show up
    /// when calls do overlap.
    ///
    /// Keep it small. It is real wall clock in the test suite, and its
    /// only job is to make overlap certain rather than likely.
    #[must_use]
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Fail any URL containing `fragment` with `err`.
    ///
    /// The point of the whole type: `Timeout` and `Connect` mean
    /// different things to a caller deciding whether to retry, and a
    /// mock server cannot produce either on demand.
    #[must_use]
    pub fn fail(self, fragment: &str, err: HttpTransportError) -> Self {
        self.push(fragment, Err(err))
    }

    /// How many requests this transport has been given.
    pub fn call_count(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// How many requests matched `fragment`.
    ///
    /// Use this to assert a caller retried, or did not — the assertion
    /// that catches a non-idempotent call being repeated.
    pub fn call_count_for(&self, fragment: &str) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|r| r.url.contains(fragment))
            .count()
    }

    /// Every request seen, in order, for asserting on headers, bodies,
    /// and the bounds the caller chose.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The most recent request, if any.
    pub fn last_request(&self) -> Option<HttpRequest> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .cloned()
    }
}

/// An [`InitExtensions`] granting `transport`, for a test calling a
/// function that takes `&dyn HostServices` directly rather than going
/// through the engine.
///
/// [`InitExtensions`]: crate::host::InitExtensions
pub fn granting(transport: Arc<FakeTransport>) -> crate::host::InitExtensions {
    crate::host::InitExtensions::new().with_http(transport)
}

#[async_trait]
impl HttpTransport for FakeTransport {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let url = req.url.clone();
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(req);

        // Take the reply first, then sleep, so the reply queue advances
        // in arrival order rather than in wake order. The `rules` guard
        // is dropped before the await: it is a `std::sync::Mutex`, and
        // holding one across a yield point would deadlock the moment two
        // calls overlap — which is the whole point of `latency`.
        let reply = {
            let mut rules = self
                .rules
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            let Some(rule) = rules.iter_mut().find(|r| url.contains(&r.fragment)) else {
                return Err(HttpTransportError::Connect(format!(
                    "FakeTransport has no rule matching '{url}'"
                )));
            };

            // Keep the last reply rather than draining to empty: a caller
            // that polls or retries should keep seeing the programmed
            // behaviour instead of falling off the end into a confusing
            // "no rule" error.
            if rule.replies.len() > 1 {
                rule.replies.pop_front()
            } else {
                rule.replies.front().cloned()
            }
            .unwrap_or_else(|| Err(HttpTransportError::Connect("empty rule queue".to_owned())))
        };

        if let Some(latency) = self.latency {
            tokio::time::sleep(latency).await;
        }

        reply
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
    async fn a_programmed_url_answers_and_is_recorded() {
        let t = FakeTransport::new().json("/jwks", 200, r#"{"keys":[]}"#);
        let resp = t
            .execute(HttpRequest::get("https://idp.example.com/jwks"))
            .await
            .expect("programmed");
        assert_eq!(resp.status, 200);
        assert_eq!(t.call_count_for("/jwks"), 1);
        assert_eq!(
            t.last_request().map(|r| r.url).as_deref(),
            Some("https://idp.example.com/jwks")
        );
    }

    #[tokio::test]
    async fn an_unprogrammed_url_fails_loudly() {
        // A forgotten rule must not look like a passing test.
        let t = FakeTransport::new();
        let err = t
            .execute(HttpRequest::get("https://idp.example.com/jwks"))
            .await
            .expect_err("nothing was programmed");
        assert!(err.to_string().contains("no rule"), "{err}");
    }

    #[tokio::test]
    async fn queued_replies_are_consumed_in_order_then_the_last_repeats() {
        // The rotation shape: first fetch sees one key set, the refresh
        // sees another, and anything after keeps seeing the second
        // rather than falling off the end.
        let t = FakeTransport::new()
            .json("/jwks", 200, "first")
            .json("/jwks", 200, "second");

        let one = t.execute(HttpRequest::get("http://x/jwks")).await.unwrap();
        let two = t.execute(HttpRequest::get("http://x/jwks")).await.unwrap();
        let three = t.execute(HttpRequest::get("http://x/jwks")).await.unwrap();

        assert_eq!(&*one.body, b"first");
        assert_eq!(&*two.body, b"second");
        assert_eq!(&*three.body, b"second");
    }

    #[tokio::test]
    async fn failures_are_programmable_which_a_mock_server_cannot_do() {
        let t = FakeTransport::new().fail("/token", HttpTransportError::Timeout);
        let err = t
            .execute(HttpRequest::post("https://idp/token", Bytes::new()))
            .await
            .expect_err("programmed to fail");
        assert_eq!(err, HttpTransportError::Timeout);
        assert!(err.may_have_reached_peer());
    }
}
