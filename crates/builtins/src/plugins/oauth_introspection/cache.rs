// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The answer cache in front of the introspection endpoint.
//
// # The TTL is the revocation window
//
// A token revoked at the issuer keeps passing here until its cached `active`
// answer expires. That is the trade every cache makes, and the API-key cache
// documents the same one. The default TTL is zero, so every check is live
// unless an operator chooses a window, and a route can set zero to keep one
// tool live while the rest are cached.
//
// # Failures are never cached
//
// moka's `try_get_with` inserts nothing on `Err`, so an endpoint that could
// not answer is asked again on the next check. It also coalesces concurrent
// lookups of one token into one call, which stops a burst from one agent
// fanning out to the issuer.
//
// # One map
//
// The API-key cache keeps unknown credentials in their own bounded map so a
// flood of guesses cannot evict real keys. Tokens reach this checker only
// after authentication verified them, so a caller cannot mint new keys here,
// and one bounded map is enough.
//
// # The key is a digest
//
// SHA-256 through the Policy crypto backend, so the cache holds no live
// credential and a FIPS build hashes with OpenSSL.
//
// # No answer outlives its `exp`
//
// RFC 7662 section 4 says a response carrying `exp` must not be cached past
// it. Each entry is kept for the TTL or until `exp`, whichever comes first.
// An `exp` that has passed, or that cannot be read as a time, keeps the
// answer for no time at all, so the next check asks again.
//
// moka expires entries on a monotonic clock, which can stall across a host
// suspend. With a TTL of seconds that stretches the window by at most one TTL
// after resume, so no wall-clock check is added. `exp` is converted to a
// duration against the wall clock once, when the answer is stored.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use praxis_policy_core::crypto::sha256;

/// What the issuer said about one token.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Answer {
    /// The response's `active`.
    pub(crate) active: bool,
    /// The response's `exp`, in seconds since the Unix epoch, when present.
    pub(crate) exp: Option<f64>,
}

/// Cached answers, keyed by the token's digest.
pub(crate) struct StatusCache {
    inner: moka::future::Cache<[u8; 32], Answer>,
}

/// Keeps each answer for the TTL, or until its `exp` when that is sooner.
struct KeepUntilExp {
    ttl: Duration,
}

impl moka::Expiry<[u8; 32], Answer> for KeepUntilExp {
    fn expire_after_create(
        &self,
        _key: &[u8; 32],
        answer: &Answer,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(keep_for(self.ttl, answer.exp, SystemTime::now()))
    }
}

/// How long an answer stored at `now` may be reused: `ttl`, cut short by
/// `exp` when present. An `exp` that has passed or is not a valid time gives
/// zero.
fn keep_for(ttl: Duration, exp: Option<f64>, now: SystemTime) -> Duration {
    let Some(exp) = exp else {
        return ttl;
    };
    Duration::try_from_secs_f64(exp)
        .ok()
        .and_then(|since_epoch| UNIX_EPOCH.checked_add(since_epoch))
        .and_then(|deadline| deadline.duration_since(now).ok())
        .map_or(Duration::ZERO, |left| left.min(ttl))
}

impl StatusCache {
    /// A cache holding up to `max_entries` answers for at most `ttl`, or
    /// `None` when `ttl` is zero.
    pub(crate) fn new(ttl: Duration, max_entries: u64) -> Option<Self> {
        (!ttl.is_zero()).then(|| Self {
            inner: moka::future::Cache::builder()
                .max_capacity(max_entries)
                .expire_after(KeepUntilExp { ttl })
                .build(),
        })
    }

    /// The cached answer for `token`, or the result of `fetch`, stored only
    /// when it succeeded.
    ///
    /// # Errors
    ///
    /// Returns `fetch`'s error, or a message when the token could not be
    /// hashed.
    pub(crate) async fn get_or_fetch(
        &self,
        token: &str,
        fetch: impl Future<Output = Result<Answer, String>>,
    ) -> Result<Answer, String> {
        let key = sha256(token.as_bytes()).map_err(|error| {
            tracing::error!(alarm = "policy_crypto_failure", op = "revocation_cache", %error);
            "cache key could not be computed".to_owned()
        })?;
        self.inner
            .try_get_with(key, fetch)
            .await
            .map_err(|error| error.as_ref().clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn a_zero_ttl_builds_no_cache() {
        assert!(
            StatusCache::new(Duration::ZERO, 100).is_none(),
            "zero means live"
        );
        assert!(
            StatusCache::new(Duration::from_secs(1), 100).is_some(),
            "a window caches"
        );
    }

    const TTL: Duration = Duration::from_secs(60);

    fn answer(active: bool, exp: Option<f64>) -> Answer {
        Answer { active, exp }
    }

    fn epoch_secs(at: SystemTime) -> f64 {
        at.duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
    }

    #[tokio::test]
    async fn an_answer_is_reused_and_a_failure_is_not() {
        let cache = StatusCache::new(TTL, 100).unwrap();
        let calls = AtomicUsize::new(0);
        let fetch = |answer: Result<Answer, String>| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { answer }
        };

        let failed = cache.get_or_fetch("a", fetch(Err("down".into()))).await;
        let answered = cache
            .get_or_fetch("a", fetch(Ok(answer(false, None))))
            .await;
        let reused = cache
            .get_or_fetch("a", async { Ok(answer(true, None)) })
            .await;

        assert_eq!(failed, Err("down".into()), "the failure is returned");
        assert_eq!(
            answered,
            Ok(answer(false, None)),
            "the failure was not stored"
        );
        assert_eq!(reused, Ok(answer(false, None)), "the answer was stored");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "two fetches ran");
    }

    /// A whole second, so `exp` arithmetic in `f64` is exact.
    fn fixed_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    #[test]
    fn exp_cuts_the_ttl_short_and_never_extends_it() {
        let now = fixed_now();
        let at = |offset: Duration| Some(epoch_secs(now + offset));

        assert_eq!(keep_for(TTL, None, now), TTL, "no exp keeps the TTL");
        assert_eq!(
            keep_for(TTL, at(Duration::from_secs(5)), now),
            Duration::from_secs(5),
            "an exp inside the TTL wins"
        );
        assert_eq!(
            keep_for(TTL, at(Duration::from_secs(3600)), now),
            TTL,
            "an exp past the TTL does not extend it"
        );
    }

    #[test]
    fn an_exp_that_passed_or_is_not_a_time_keeps_nothing() {
        let now = fixed_now();

        for exp in [
            epoch_secs(now),
            epoch_secs(now) - 1.0,
            -1.0,
            f64::NAN,
            f64::INFINITY,
        ] {
            assert_eq!(keep_for(TTL, Some(exp), now), Duration::ZERO, "{exp}");
        }
    }

    #[tokio::test]
    async fn an_answer_at_its_exp_is_not_stored() {
        let cache = StatusCache::new(TTL, 100).unwrap();
        let expired = Some(epoch_secs(SystemTime::now()) - 1.0);

        let first = cache
            .get_or_fetch("a", async { Ok(answer(true, expired)) })
            .await;
        let second = cache
            .get_or_fetch("a", async { Ok(answer(false, None)) })
            .await;

        assert_eq!(first, Ok(answer(true, expired)), "the answer is returned");
        assert_eq!(second, Ok(answer(false, None)), "but not reused");
    }
}
