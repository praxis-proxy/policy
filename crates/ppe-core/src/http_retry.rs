// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Retry policy for outbound HTTP.
//
// Deliberately not in the transport. Two of PPE's three callers issue
// non-idempotent POSTs — an RFC 8693 token exchange and a CIBA
// backchannel registration — and a transport sees both as "POST to an
// HTTPS URL". Repeat the first and the IdP mints a credential nobody
// holds; repeat the second and a human is asked to approve the same
// thing twice. Only the caller knows which is which.
//
// So the rule lives here, once, rather than three times across the
// plugins that need it. A plugin picks a policy that matches its
// operation's idempotency and the shared code decides the rest.
//
// Two conditions gate a retry, and conflating them is how this goes
// wrong:
//
//   * Could the peer have acted on the request? If yes, a repeat may
//     duplicate a side effect. `HttpTransportError::may_have_reached_peer`
//     answers this, and a timeout answers *yes* because it cannot tell
//     "never arrived" from "the reply was lost".
//   * Is a repeat worth anything? An open circuit or an egress refusal
//     never reached the peer, so a repeat is *safe* — and pointless,
//     because it fails identically while counting as fresh failures
//     against the host's breaker.
//
// Budget, not just attempts. Each attempt carries its own timeout, so
// three attempts plus backoff can outlive the request that triggered
// them. A total budget bounds the whole loop, and the loop stops rather
// than starting an attempt it cannot finish.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};

/// Process-wide counter used to decorrelate backoff between concurrent
/// callers.
///
/// When an `IdP` restarts, every in-flight request fails at once. Pure
/// exponential backoff would then retry them all at the same instant,
/// reproducing the thundering herd one backoff interval later. Mixing a
/// per-call counter into the delay spreads them out.
///
/// A counter rather than a random source because it needs no dependency
/// and gives what herd avoidance actually wants: adjacent callers get
/// different delays. Hashing the URL instead would give every caller of
/// the *same* endpoint identical jitter, which is exactly the case that
/// matters.
static JITTER_SEQ: AtomicU64 = AtomicU64::new(0);

/// How hard to retry, and whether repeating is safe at all.
///
/// Build with [`RetryPolicy::idempotent`] or
/// [`RetryPolicy::undelivered_only`] rather than by hand, so the choice
/// of `retry_delivered` is made by naming the operation's idempotency
/// instead of by setting a flag.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total attempts including the first. `1` disables retrying.
    pub max_attempts: u32,

    /// Delay before the second attempt. Doubles each time, capped by
    /// `max_backoff`, with jitter applied.
    pub initial_backoff: Duration,

    /// Ceiling on a single backoff interval.
    pub max_backoff: Duration,

    /// Ceiling on the whole loop, covering every attempt and every
    /// backoff. `None` bounds the loop only by `max_attempts`, which is
    /// appropriate at startup and wrong on a request path.
    pub total_budget: Option<Duration>,

    /// Whether to retry when the peer may already have acted.
    ///
    /// True only for an operation that is safe to repeat — a `GET`, or a
    /// `POST` the peer treats idempotently. False for anything that
    /// mints, charges, or notifies.
    pub retry_delivered: bool,
}

impl RetryPolicy {
    /// Never retry. The honest default for an operation whose
    /// idempotency has not been reasoned about.
    pub const fn none() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            total_budget: None,
            retry_delivered: false,
        }
    }

    /// For an operation that is safe to repeat, such as a JWKS fetch.
    ///
    /// Retries timeouts, because repeating a `GET` that may already have
    /// been served costs nothing but a round trip.
    pub const fn idempotent() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            total_budget: None,
            retry_delivered: true,
        }
    }

    /// For an operation that must not be duplicated, such as a token
    /// mint or a CIBA dispatch.
    ///
    /// Retries only failures that provably never reached the peer. A
    /// timeout ends the loop and leaves the outcome indeterminate, which
    /// the caller records as `unknown` and reconciles later rather than
    /// assuming either way.
    pub const fn undelivered_only() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(500),
            total_budget: None,
            retry_delivered: false,
        }
    }

    /// Bound the whole loop, backoff included.
    ///
    /// Use this on a request path. Without it, `max_attempts` times the
    /// per-attempt timeout plus backoff is the real worst case, and it
    /// can outlive the request that asked for the call.
    #[must_use]
    pub const fn with_total_budget(mut self, budget: Duration) -> Self {
        self.total_budget = Some(budget);
        self
    }

    /// Cap the number of attempts.
    #[must_use]
    pub const fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Whether `err` should be retried under this policy.
    ///
    /// Both conditions, in the order that matters: a refusal is never
    /// worth repeating even though it is safe to, and a delivered
    /// request is only repeated when the caller declared the operation
    /// idempotent.
    pub fn should_retry(&self, err: &HttpTransportError) -> bool {
        match err {
            // Safe to repeat, but it will fail identically and each
            // attempt feeds the host's circuit breaker.
            HttpTransportError::Rejected(_) => false,
            // A malformed request is deterministic. Repeating it is a
            // busy loop against a bug.
            HttpTransportError::InvalidRequest(_) => false,
            // The peer answered; we declined the answer. A repeat gets
            // the same oversized body.
            HttpTransportError::ResponseTooLarge { .. } => false,
            other => self.retry_delivered || !other.may_have_reached_peer(),
        }
    }

    /// Backoff before the attempt after `completed_attempts`, jittered.
    ///
    /// Full jitter over `[0, exponential]` rather than a fixed fraction:
    /// it spreads a synchronized herd across the whole window instead of
    /// bunching it at the end.
    pub fn backoff_after(&self, completed_attempts: u32) -> Duration {
        let shift = completed_attempts.saturating_sub(1).min(16);
        let exponential = self
            .initial_backoff
            .saturating_mul(1_u32 << shift)
            .min(self.max_backoff);

        // `max_backoff` caps this long before it could approach u64, but
        // take the lossless conversion rather than assert that.
        let Ok(ceiling) = u64::try_from(exponential.as_millis()) else {
            return self.max_backoff;
        };
        if ceiling == 0 {
            return Duration::ZERO;
        }
        // Cheap decorrelation: adjacent callers land on different
        // multiples rather than all waking together.
        let seq = JITTER_SEQ.fetch_add(1, Ordering::Relaxed);
        // Multiplicative mix so consecutive sequence numbers do not map
        // to consecutive delays.
        let spread = seq.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32;
        Duration::from_millis(spread % (ceiling + 1))
    }
}

impl Default for RetryPolicy {
    /// [`RetryPolicy::none`] — retrying is opt-in, because the cost of
    /// wrongly retrying a mint is higher than the cost of a failed call.
    fn default() -> Self {
        Self::none()
    }
}

/// Perform `req` through `transport`, retrying per `policy`.
///
/// Crate-internal: a plugin never holds a transport, so it reaches this
/// through [`HostServices::http_request`](crate::host::HostServices::http_request),
/// which takes the policy as an argument. Exposing it would mean handing
/// out a transport for it to act on, which is the thing the operation
/// shape exists to avoid.
///
/// Returns the first success, or the last error. Every attempt sends the
/// identical request; nothing is mutated between tries.
///
/// # Errors
///
/// Returns the final [`HttpTransportError`] once the policy stops
/// retrying — attempts exhausted, budget spent, or the error was one
/// this policy will not repeat. The error is the last one observed, so a
/// caller inspecting [`HttpTransportError::may_have_reached_peer`] sees
/// the state of the attempt that actually ran last.
pub(crate) async fn execute_with_retry(
    transport: &dyn HttpTransport,
    req: HttpRequest,
    policy: RetryPolicy,
) -> Result<HttpResponse, HttpTransportError> {
    let started = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        let err = match transport.execute(req.clone()).await {
            Ok(resp) => return Ok(resp),
            Err(e) => e,
        };

        if attempt >= policy.max_attempts || !policy.should_retry(&err) {
            return Err(err);
        }

        let delay = policy.backoff_after(attempt);

        // Stop rather than start an attempt the budget cannot cover.
        // Beginning one anyway would overrun the caller's deadline and
        // report a timeout that the retry loop, not the peer, caused.
        if let Some(budget) = policy.total_budget {
            let spent = started.elapsed();
            let per_attempt = req.timeout;
            if spent + delay + per_attempt > budget {
                return Err(err);
            }
        }

        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
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
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;

    /// Fails `fail_times` times, then succeeds. Counts every attempt.
    #[derive(Debug)]
    struct FlakyTransport {
        attempts: Arc<AtomicU32>,
        fail_times: u32,
        err: HttpTransportError,
    }

    impl FlakyTransport {
        fn new(fail_times: u32, err: HttpTransportError) -> (Arc<Self>, Arc<AtomicU32>) {
            let attempts = Arc::new(AtomicU32::new(0));
            let t = Arc::new(Self {
                attempts: Arc::clone(&attempts),
                fail_times,
                err,
            });
            (t, attempts)
        }
    }

    #[async_trait]
    impl HttpTransport for FlakyTransport {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            let n = self.attempts.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                Err(self.err.clone())
            } else {
                Ok(HttpResponse::new(200, Bytes::new()))
            }
        }
    }

    fn fast(policy: RetryPolicy) -> RetryPolicy {
        // Keep tests off the clock; the backoff arithmetic is covered
        // separately.
        RetryPolicy {
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            ..policy
        }
    }

    #[tokio::test]
    async fn an_undelivered_failure_is_retried_and_can_succeed() {
        let (t, attempts) = FlakyTransport::new(2, HttpTransportError::Connect("refused".into()));
        let resp = execute_with_retry(
            t.as_ref(),
            HttpRequest::get("https://idp.example.com/jwks"),
            fast(RetryPolicy::undelivered_only()),
        )
        .await
        .expect("the third attempt succeeds");
        assert_eq!(resp.status, 200);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_timeout_is_not_retried_for_a_non_idempotent_call() {
        // The case that mints duplicate credentials if we get it wrong.
        // A timeout may mean the token exchange landed, so the loop must
        // stop and let the caller record the outcome as indeterminate.
        let (t, attempts) = FlakyTransport::new(5, HttpTransportError::Timeout);
        let err = execute_with_retry(
            t.as_ref(),
            HttpRequest::post("https://idp.example.com/token", Bytes::new()),
            fast(RetryPolicy::undelivered_only()),
        )
        .await
        .expect_err("a timed-out mint must not be repeated");
        assert_eq!(err, HttpTransportError::Timeout);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "exactly one attempt: repeating could mint a second token"
        );
    }

    #[tokio::test]
    async fn a_timeout_is_retried_for_an_idempotent_call() {
        // The same error, the opposite decision, because a JWKS GET can
        // be repeated with no side effect.
        let (t, attempts) = FlakyTransport::new(1, HttpTransportError::Timeout);
        let resp = execute_with_retry(
            t.as_ref(),
            HttpRequest::get("https://idp.example.com/jwks"),
            fast(RetryPolicy::idempotent()),
        )
        .await
        .expect("the second attempt succeeds");
        assert_eq!(resp.status, 200);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_host_refusal_is_never_retried() {
        // Safe to repeat, but pointless: it fails identically, and each
        // attempt counts as a fresh failure against the host's circuit
        // breaker — so retrying makes the outage worse.
        let (t, attempts) =
            FlakyTransport::new(5, HttpTransportError::Rejected("circuit open".into()));
        let err = execute_with_retry(
            t.as_ref(),
            HttpRequest::get("https://idp.example.com/jwks"),
            fast(RetryPolicy::idempotent()),
        )
        .await
        .expect_err("a refusal stands");
        assert!(matches!(err, HttpTransportError::Rejected(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_malformed_request_is_never_retried() {
        // Deterministic. Repeating is a busy loop against a bug.
        let (t, attempts) =
            FlakyTransport::new(5, HttpTransportError::InvalidRequest("bad url".into()));
        let _ = execute_with_retry(
            t.as_ref(),
            HttpRequest::get("not a url"),
            fast(RetryPolicy::idempotent()),
        )
        .await
        .expect_err("a malformed request stands");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn attempts_are_capped() {
        let (t, attempts) = FlakyTransport::new(99, HttpTransportError::Connect("refused".into()));
        let _ = execute_with_retry(
            t.as_ref(),
            HttpRequest::get("https://idp.example.com/jwks"),
            fast(RetryPolicy::idempotent().with_max_attempts(4)),
        )
        .await
        .expect_err("every attempt fails");
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn the_default_policy_does_not_retry() {
        // Retrying is opt-in: wrongly repeating a mint costs more than a
        // failed call.
        let (t, attempts) = FlakyTransport::new(1, HttpTransportError::Connect("refused".into()));
        let _ = execute_with_retry(
            t.as_ref(),
            HttpRequest::get("https://idp.example.com/jwks"),
            RetryPolicy::default(),
        )
        .await
        .expect_err("no retry means the first failure stands");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// Consumes real time before failing, so the budget has something to
    /// spend. A transport that fails instantly never exercises the check.
    #[derive(Debug)]
    struct SlowFailingTransport {
        attempts: Arc<AtomicU32>,
        delay: Duration,
    }

    #[async_trait]
    impl HttpTransport for SlowFailingTransport {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Err(HttpTransportError::Connect("refused".into()))
        }
    }

    #[tokio::test]
    async fn the_budget_stops_a_loop_that_cannot_finish_in_time() {
        // Per-attempt timeouts do not bound the loop: `max_attempts`
        // times the timeout, plus backoff, is the real worst case, and
        // on a request path that outlives the request that asked for it.
        //
        // The loop must refuse to *start* an attempt the budget cannot
        // cover, rather than starting one and reporting a timeout the
        // retry loop caused rather than the peer.
        let attempts = Arc::new(AtomicU32::new(0));
        let t = SlowFailingTransport {
            attempts: Arc::clone(&attempts),
            delay: Duration::from_millis(50),
        };
        // One attempt burns 50ms of a 100ms budget; a second could take
        // its full 60ms timeout, which would overrun.
        let req =
            HttpRequest::get("https://idp.example.com/jwks").timeout(Duration::from_millis(60));
        let _ = execute_with_retry(
            &t,
            req,
            fast(RetryPolicy::idempotent().with_total_budget(Duration::from_millis(100))),
        )
        .await
        .expect_err("every attempt fails");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "a second attempt could overrun the budget, so it must not start"
        );
    }

    #[tokio::test]
    async fn a_generous_budget_still_allows_the_full_attempt_count() {
        // The complement: the budget must bound the loop without
        // silently disabling retries whenever one is set.
        let attempts = Arc::new(AtomicU32::new(0));
        let t = SlowFailingTransport {
            attempts: Arc::clone(&attempts),
            delay: Duration::from_millis(10),
        };
        let req =
            HttpRequest::get("https://idp.example.com/jwks").timeout(Duration::from_millis(20));
        let _ = execute_with_retry(
            &t,
            req,
            fast(RetryPolicy::idempotent().with_total_budget(Duration::from_secs(10))),
        )
        .await
        .expect_err("every attempt fails");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let policy = RetryPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(400),
            ..RetryPolicy::idempotent()
        };
        // Full jitter means each delay is bounded by the exponential,
        // not equal to it — so assert the ceiling, which is the property
        // that actually matters.
        assert!(policy.backoff_after(1) <= Duration::from_millis(100));
        assert!(policy.backoff_after(2) <= Duration::from_millis(200));
        assert!(policy.backoff_after(9) <= Duration::from_millis(400));
    }

    #[test]
    fn concurrent_callers_do_not_share_a_backoff() {
        // The herd-avoidance property. If every caller computed the same
        // delay, an IdP restart would be followed by a synchronized
        // stampede one interval later.
        let policy = RetryPolicy {
            initial_backoff: Duration::from_millis(1000),
            max_backoff: Duration::from_millis(1000),
            ..RetryPolicy::idempotent()
        };
        let delays: Vec<_> = std::iter::repeat_with(|| policy.backoff_after(3))
            .take(16)
            .collect();
        let distinct = delays
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            distinct > 1,
            "sixteen callers produced one delay: {delays:?}"
        );
    }
}
