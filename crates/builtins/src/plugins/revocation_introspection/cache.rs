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
// moka expires entries on a monotonic clock, which can stall across a host
// suspend. With a TTL of seconds that stretches the window by at most one TTL
// after resume, so no wall-clock check is added.

use std::time::Duration;

use praxis_policy_core::crypto::sha256;

/// Cached `active` answers, keyed by the token's digest.
pub(crate) struct StatusCache {
    inner: moka::future::Cache<[u8; 32], bool>,
}

impl StatusCache {
    /// A cache holding up to `max_entries` answers for `ttl`, or `None` when
    /// `ttl` is zero.
    pub(crate) fn new(ttl: Duration, max_entries: u64) -> Option<Self> {
        (!ttl.is_zero()).then(|| Self {
            inner: moka::future::Cache::builder()
                .max_capacity(max_entries)
                .time_to_live(ttl)
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
        fetch: impl Future<Output = Result<bool, String>>,
    ) -> Result<bool, String> {
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

    #[tokio::test]
    async fn an_answer_is_reused_and_a_failure_is_not() {
        let cache = StatusCache::new(Duration::from_secs(60), 100).unwrap();
        let calls = AtomicUsize::new(0);
        let fetch = |answer: Result<bool, String>| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { answer }
        };

        let failed = cache.get_or_fetch("a", fetch(Err("down".into()))).await;
        let answered = cache.get_or_fetch("a", fetch(Ok(false))).await;
        let reused = cache.get_or_fetch("a", async { Ok(true) }).await;

        assert_eq!(failed, Err("down".into()), "the failure is returned");
        assert_eq!(answered, Ok(false), "the failure was not stored");
        assert_eq!(reused, Ok(false), "the answer was stored");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "two fetches ran");
    }
}
