// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The bounded, coalescing store behind the delegated-token cache.
//
// This module is mechanism. It holds no opinion about what makes two
// delegations the same — that is `key`'s job, and it is where the
// security argument lives. Everything here assumes it has been handed a
// correct key and concerns itself with three properties:
//
//   * **Bounded.** A caller able to vary any key component can create
//     entries. `max_entries` with LRU eviction is what stops that
//     growing without limit, so it is a mitigation rather than a tuning
//     knob.
//   * **Coalesced.** N concurrent requests for one uncached key must
//     produce one exchange, not N. A rotation or a cold start otherwise
//     points a stampede at the `IdP` at the moment it can least absorb
//     one.
//   * **Never wrong about failure.** A failed exchange is not an entry.
//     Neither is one that may or may not have reached the `IdP`.
//
// # Why moka rather than a guard map
//
// The obvious way to coalesce is a `HashMap<Key, Arc<Mutex<()>>>`
// alongside the cache. `oauth2-broker` does exactly that, and its guard
// map is inserted into and never pruned — so the structure that exists
// to protect the cache grows without the bound that protects the cache.
// Under the flooding scenario `max_entries` is there to survive, the
// guard map is the leak.
//
// moka's coalescing lives inside the bounded map, so one bound covers
// both. That is the reason for the dependency; the ergonomics are
// incidental.
//
// # Two clocks
//
// moka retires entries on a monotonic clock, which is the right choice
// for a cache and the wrong one for a credential. `Instant` does not
// advance across a host suspend on Linux or macOS, so a process resumed
// after an hour sees a monotonic clock that barely moved and a token
// that expired long ago.
//
// So retirement is monotonic, via [`ServeWindow`], and every read
// additionally re-runs that decision on the wall clock: both against
// the token's own `expires_at` and against the serve window the entry
// was created with, which is where `ttl_ceiling_seconds` lives. The
// first avoids a downstream 401; the second is what keeps the ceiling
// meaningful, since a long-lived token stays valid to the `IdP` well
// past the point the cache was supposed to stop reusing it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use moka::Expiry;
use moka::future::Cache;
use praxis_policy_core::extensions::raw_credentials::RawDelegatedToken;

use super::config::CacheConfig;
use super::key::{CacheKey, KeySecret};

/// What one exchange produced, before the cache decides how long it may
/// be reused.
#[derive(Debug, Clone)]
pub(crate) struct Mint {
    /// The minted credential.
    pub(crate) token: RawDelegatedToken,
    /// The `issued_token_type` the `IdP` reported, carried so a cache
    /// hit reconstructs exactly the payload a fresh mint would have.
    pub(crate) issued_token_type: String,
}

/// A mint plus the cache's decision about it.
#[derive(Debug, Clone)]
pub(crate) struct CachedMint {
    /// The mint itself.
    pub(crate) mint: Mint,
    /// When the exchange happened, in wall-clock terms.
    pub(crate) minted_at: DateTime<Utc>,
    /// How long this entry may be served for, or `None` when the
    /// staleness margin consumes the token's entire lifetime.
    ///
    /// `None` is stored rather than rejected because the decision is
    /// made inside the coalesced init, where the only way to decline is
    /// to return an error and errors are not what this is. The entry is
    /// created already expired instead: see [`ServeWindow`].
    serve_for: Option<Duration>,
}

impl CachedMint {
    /// Whether this entry may still be handed downstream.
    ///
    /// Wall-clock, deliberately. [`ServeWindow`] has already made the
    /// monotonic decision; this catches the case where the two clocks
    /// disagree, which in practice means the host suspended.
    ///
    /// Both halves of that decision are restated here, not just the
    /// token's own expiry. A token the `IdP` issued for an hour, held
    /// under a five-minute `ttl_ceiling_seconds`, is still perfectly
    /// valid to the `IdP` long after its entry was due to retire, so a
    /// check against `expires_at` alone would serve it straight through
    /// the ceiling once the monotonic clock stopped advancing. The
    /// ceiling is the whole of the bound this cache documents on an
    /// `IdP`-side revocation, so it has to hold on both clocks.
    fn is_servable_now(&self, config: &CacheConfig) -> bool {
        let now = Utc::now();
        let floor = chrono::Duration::seconds(
            i64::try_from(config.staleness.floor_seconds).unwrap_or(i64::MAX),
        );
        // Checked throughout: a saturated `floor` or `serve_for` would
        // otherwise panic on overflow, and "cannot be served" is the
        // answer that keeps a credential out of the response either way.
        let Some(with_floor) = now.checked_add_signed(floor) else {
            return false;
        };
        if with_floor > self.mint.token.expires_at {
            return false;
        }
        // The monotonic retirement, restated on the wall clock. `None`
        // is an entry created already expired, which is never servable
        // however far the clocks have drifted apart.
        let Some(serve_for) = self.serve_for else {
            return false;
        };
        // Whole seconds, so the wall-clock window is if anything a shade
        // shorter than the monotonic one rather than longer.
        let serve_for =
            chrono::Duration::seconds(i64::try_from(serve_for.as_secs()).unwrap_or(i64::MAX));
        self.minted_at
            .checked_add_signed(serve_for)
            .is_some_and(|retires_at| now <= retires_at)
    }
}

/// Per-entry expiry: each token is retired on its own serve window
/// rather than on one TTL for the whole cache.
///
/// A cache-wide TTL would have to be the shortest lifetime any `IdP`
/// might return, which throws away most of the reuse available from the
/// longer ones.
struct ServeWindow;

/// `expire_after_read` is deliberately left at its default, which keeps
/// the existing expiry rather than extending it. Reads must not renew a
/// credential: a sliding window would let a token in constant use be
/// served indefinitely past the point `ttl_ceiling_seconds` was supposed
/// to retire it, which would quietly remove the only lever there is
/// against an `IdP`-side revocation. That default is the behaviour we
/// want, and this note exists so it is not "fixed" into a sliding one.
impl Expiry<CacheKey, CachedMint> for ServeWindow {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CachedMint,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        // `ZERO` for an unservable window, which creates the entry
        // already expired. That is how a mint whose margin swallows its
        // lifetime gets returned to the caller exactly once without ever
        // being served to a second one.
        Some(value.serve_for.unwrap_or(Duration::ZERO))
    }

    /// Recompute from the *new* value rather than inheriting the old
    /// entry's remaining time.
    ///
    /// The default implementation returns `duration_until_expiry`, which
    /// keeps whatever the replaced entry had left. For a cache of plain
    /// values that is harmless; for a cache of credentials it means a
    /// freshly minted token silently inherits the retirement schedule of
    /// the expiring one it replaced, and is dropped early or — worse, if
    /// the ceiling later rises — served past its own window.
    ///
    /// No path in this module overwrites a live key today: a stale entry
    /// is invalidated before the mint that replaces it, and
    /// `or_try_insert_with` only fires on an absent key. This is here so
    /// that the first `insert` someone adds is not a silent bug.
    fn expire_after_update(
        &self,
        _key: &CacheKey,
        value: &CachedMint,
        _updated_at: std::time::Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.serve_for.unwrap_or(Duration::ZERO))
    }
}

/// Where a token came from, for telemetry and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// Served from an existing entry.
    Cache,
    /// Freshly exchanged with the `IdP`.
    Mint,
}

/// A token handed back to the delegator, and where it came from.
#[derive(Debug, Clone)]
pub(crate) struct Served {
    /// The mint.
    pub(crate) mint: Mint,
    /// Whether this call performed an exchange.
    pub(crate) source: Source,
    /// When the exchange that produced this token happened.
    ///
    /// Carried rather than recomputed by the caller, because on a hit
    /// "now" is not when the token was minted. `DelegationPayload`
    /// records this for audit, and a cached token that claims to have
    /// been minted on every request it serves would make the delegation
    /// chain say something untrue.
    pub(crate) minted_at: DateTime<Utc>,
}

/// Bounded, coalescing store of live delegated tokens.
pub(crate) struct DelegatedTokenCache {
    inner: Cache<CacheKey, CachedMint>,
    config: CacheConfig,
    secret: KeySecret,
    /// Latches once the "margin swallows the lifetime" warning has
    /// fired. That condition is a property of the configuration against
    /// an `IdP`'s chosen lifetime, so it holds for every mint or none;
    /// logging per request would be one line per request forever.
    warned_unservable: AtomicBool,
}

impl std::fmt::Debug for DelegatedTokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedTokenCache")
            .field("entries", &self.inner.entry_count())
            .field("max_entries", &self.config.max_entries)
            .finish_non_exhaustive()
    }
}

impl DelegatedTokenCache {
    /// Build a cache, or `None` when the operator has not enabled one.
    ///
    /// `None` rather than a cache that always misses: a disabled cache
    /// should cost nothing at all, and the delegator's `Option` makes
    /// the uncached path visibly the same code it was before.
    ///
    /// # Errors
    ///
    /// Returns a message when the settings cannot describe a working
    /// cache, or when the host cannot produce a key secret.
    pub(crate) fn new(config: CacheConfig) -> Result<Option<Self>, String> {
        config.validate()?;
        if !config.enabled {
            return Ok(None);
        }
        let secret = KeySecret::random()?;
        let inner = Cache::builder()
            .max_capacity(config.max_entries)
            .expire_after(ServeWindow)
            .build();
        Ok(Some(Self {
            inner,
            config,
            secret,
            warned_unservable: AtomicBool::new(false),
        }))
    }

    /// The key secret, for deriving keys against this cache.
    pub(crate) fn secret(&self) -> &KeySecret {
        &self.secret
    }

    /// The settings this cache was built with.
    pub(crate) fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Serve `key` from cache, or run `mint` and store the result.
    ///
    /// Concurrent calls on the same uncached key are coalesced into one
    /// evaluation of `mint`; the rest await its outcome. An `Err` from
    /// `mint` is propagated to every waiter and **not** stored, so a
    /// failed or indeterminate exchange can never become a cache entry.
    ///
    /// # Errors
    ///
    /// Returns whatever `mint` returned, shared behind an `Arc` because
    /// one failure may have to be reported to several waiters.
    pub(crate) async fn get_or_mint<E, Fut>(
        &self,
        key: CacheKey,
        mint: Fut,
    ) -> Result<Served, Arc<E>>
    where
        Fut: Future<Output = Result<Mint, E>>,
        E: Send + Sync + 'static,
    {
        // Wall-clock check ahead of the coalesced path. A `get` is a map
        // lookup, so the cost on the hit path is negligible, and doing it
        // here rather than after `or_try_insert_with` means a stale entry
        // is gone before anyone queues behind it.
        if let Some(existing) = self.inner.get(&key).await {
            if existing.is_servable_now(&self.config) {
                tracing::trace!(
                    target: "praxis_policy::delegation",
                    cache_key = ?key,
                    "serving a delegated token from cache",
                );
                return Ok(Served {
                    mint: existing.mint,
                    source: Source::Cache,
                    minted_at: existing.minted_at,
                });
            }
            // Monotonic and wall clock disagree; a host suspend is the
            // realistic cause. Drop it and let the mint below replace it.
            tracing::debug!(
                target: "praxis_policy::delegation",
                cache_key = ?key,
                "discarding a cached delegated token that the wall clock says has expired or \
                 outlived its serve window; the monotonic clock had not retired it yet, which \
                 usually means the host suspended",
            );
            self.inner.invalidate(&key).await;
        }

        let config = self.config.clone();
        let jitter = key.jitter_byte();
        let entry = self
            .inner
            .entry(key)
            .or_try_insert_with(async move {
                mint.await.map(|mint| {
                    let lifetime = (mint.token.expires_at - Utc::now())
                        .to_std()
                        .unwrap_or(Duration::ZERO);
                    CachedMint {
                        minted_at: Utc::now(),
                        serve_for: config.serve_window(lifetime, jitter),
                        mint,
                    }
                })
            })
            .await?;

        let fresh = entry.is_fresh();
        let value = entry.into_value();

        if value.serve_for.is_none() && !self.warned_unservable.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "praxis_policy::delegation",
                floor_seconds = self.config.staleness.floor_seconds,
                fraction = self.config.staleness.fraction,
                token_lifetime_seconds = (value.mint.token.expires_at - value.minted_at).num_seconds(),
                "the delegated-token cache is enabled but the staleness margin covers the whole \
                 lifetime of the tokens this IdP issues, so nothing can be cached; lower \
                 cache.staleness.floor_seconds or cache.staleness.fraction, or turn the cache off. \
                 (Further occurrences on this delegator are suppressed.)",
            );
        }

        Ok(Served {
            minted_at: value.minted_at,
            mint: value.mint,
            source: if fresh { Source::Mint } else { Source::Cache },
        })
    }

    /// Drop every entry.
    ///
    /// The only lever an operator has against an `IdP`-side revocation
    /// besides waiting out `ttl_ceiling_seconds`. Not wired to anything
    /// yet; tests exercise it so the invalidate path stays covered until
    /// a host-facing flush exists.
    #[cfg(test)]
    pub(crate) async fn flush(&self) {
        self.inner.invalidate_all();
        self.inner.run_pending_tasks().await;
    }

    /// Live entries. Approximate unless `run_pending_tasks` has just
    /// run, since eviction is performed off the caller's thread.
    #[cfg(test)]
    async fn entry_count(&self) -> u64 {
        self.inner.run_pending_tasks().await;
        self.inner.entry_count()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests assert on known-good values"
)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use praxis_policy_core::delegation::{DelegationPayload, DelegationSubject};

    use super::super::config::StalenessConfig;
    use super::super::key::{DelegatorIdentity, derive};
    use super::*;

    /// A distinct error type so the tests assert on the real
    /// `try_get_with` error path rather than on a stringly one.
    #[derive(Debug, PartialEq, Eq)]
    struct MintFailed;

    fn enabled_config() -> CacheConfig {
        CacheConfig {
            enabled: true,
            subjects: vec![DelegationSubject::User, DelegationSubject::ThisWorkload],
            max_entries: 100,
            ttl_ceiling_seconds: 3600,
            staleness: StalenessConfig {
                fraction: 0.20,
                floor_seconds: 30,
                jitter_seconds: 0,
            },
        }
    }

    fn cache() -> DelegatedTokenCache {
        DelegatedTokenCache::new(enabled_config())
            .expect("valid config")
            .expect("enabled")
    }

    fn delegator() -> DelegatorIdentity<'static> {
        DelegatorIdentity {
            instance: "delegator-a",
            token_endpoint: "https://idp.example.com/token",
            client_id: "gateway",
        }
    }

    fn key_for(cache: &DelegatedTokenCache, bearer: &str) -> CacheKey {
        let payload = DelegationPayload::new(bearer, "billing-api")
            .with_target_audience("https://billing.example.com");
        derive(cache.secret(), delegator(), &payload).expect("cacheable")
    }

    /// A mint that lives `ttl` seconds from now.
    fn mint_lasting(ttl: i64, token: &str) -> Mint {
        Mint {
            token: RawDelegatedToken::new(
                token,
                "Authorization",
                "https://billing.example.com",
                vec!["invoices:read".to_owned()],
                Utc::now() + chrono::Duration::seconds(ttl),
            ),
            issued_token_type: "urn:ietf:params:oauth:token-type:access_token".to_owned(),
        }
    }

    #[test]
    fn a_disabled_config_builds_no_cache() {
        let built = DelegatedTokenCache::new(CacheConfig::default()).expect("valid");
        assert!(
            built.is_none(),
            "a disabled cache must cost nothing, not miss on every lookup"
        );
    }

    #[test]
    fn an_invalid_config_is_rejected_at_construction() {
        let config = CacheConfig {
            max_entries: 0,
            ..enabled_config()
        };
        DelegatedTokenCache::new(config).unwrap_err();
    }

    #[tokio::test]
    async fn a_second_call_is_served_from_cache() {
        let cache = cache();
        let key = key_for(&cache, "alice-token");
        let mints = AtomicUsize::new(0);

        let first = cache
            .get_or_mint::<MintFailed, _>(key, async {
                mints.fetch_add(1, Ordering::SeqCst);
                Ok(mint_lasting(300, "minted-1"))
            })
            .await
            .unwrap();
        assert_eq!(first.source, Source::Mint);

        let second = cache
            .get_or_mint::<MintFailed, _>(key, async {
                mints.fetch_add(1, Ordering::SeqCst);
                Ok(mint_lasting(300, "minted-2"))
            })
            .await
            .unwrap();

        assert_eq!(second.source, Source::Cache);
        assert_eq!(
            mints.load(Ordering::SeqCst),
            1,
            "the second call must not mint"
        );
        assert_eq!(
            &*second.mint.token.token, "minted-1",
            "the cached token must be the one that was stored"
        );
    }

    #[tokio::test]
    async fn different_keys_do_not_share_an_entry() {
        let cache = cache();
        let alice = key_for(&cache, "alice-token");
        let bob = key_for(&cache, "bob-token");

        cache
            .get_or_mint::<MintFailed, _>(alice, async { Ok(mint_lasting(300, "alice-minted")) })
            .await
            .unwrap();
        let served = cache
            .get_or_mint::<MintFailed, _>(bob, async { Ok(mint_lasting(300, "bob-minted")) })
            .await
            .unwrap();

        assert_eq!(
            served.source,
            Source::Mint,
            "bob must not hit alice's entry"
        );
        assert_eq!(&*served.mint.token.token, "bob-minted");
    }

    /// The acceptance criterion: N concurrent requests for one uncached
    /// key produce exactly one exchange.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_for_one_key_mint_once() {
        let cache = Arc::new(cache());
        let key = key_for(&cache, "alice-token");
        let mints = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(16));

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let mints = Arc::clone(&mints);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                cache
                    .get_or_mint::<MintFailed, _>(key, async {
                        mints.fetch_add(1, Ordering::SeqCst);
                        // Long enough that every other task is queued
                        // behind this one rather than arriving after it.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(mint_lasting(300, "minted-once"))
                    })
                    .await
                    .map(|served| served.source)
            }));
        }

        let mut sources = Vec::new();
        for task in tasks {
            sources.push(task.await.unwrap().unwrap());
        }

        assert_eq!(
            mints.load(Ordering::SeqCst),
            1,
            "16 concurrent requests for one uncached key must produce one exchange"
        );
        assert_eq!(
            sources.iter().filter(|s| **s == Source::Mint).count(),
            1,
            "exactly one caller should report having minted"
        );
    }

    #[tokio::test]
    async fn a_failed_mint_is_not_cached() {
        let cache = cache();
        let key = key_for(&cache, "alice-token");
        let attempts = AtomicUsize::new(0);

        let failed = cache
            .get_or_mint::<MintFailed, _>(key, async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(MintFailed)
            })
            .await;
        failed.unwrap_err();

        // The next caller must reach the IdP, not inherit the failure.
        let recovered = cache
            .get_or_mint::<MintFailed, _>(key, async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok(mint_lasting(300, "minted-after-failure"))
            })
            .await
            .unwrap();

        assert_eq!(recovered.source, Source::Mint);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(&*recovered.mint.token.token, "minted-after-failure");
    }

    /// A failure reaches every waiter, and none of them caches it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failure_is_shared_with_every_waiter() {
        let cache = Arc::new(cache());
        let key = key_for(&cache, "alice-token");
        let attempts = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(8));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let attempts = Arc::clone(&attempts);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                cache
                    .get_or_mint::<MintFailed, _>(key, async {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Err(MintFailed)
                    })
                    .await
                    .is_err()
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap(), "every waiter must see the failure");
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            cache.entry_count().await,
            0,
            "a failure must leave no entry"
        );
    }

    /// A token whose whole lifetime sits inside the staleness margin is
    /// handed to the caller that minted it and never served again. This
    /// is the configuration that silently produces a permanent zero
    /// percent hit rate in other implementations.
    #[tokio::test]
    async fn a_token_the_margin_swallows_is_never_served() {
        let cache = cache();
        let key = key_for(&cache, "alice-token");
        let mints = AtomicUsize::new(0);

        for _ in 0..3 {
            let served = cache
                .get_or_mint::<MintFailed, _>(key, async {
                    mints.fetch_add(1, Ordering::SeqCst);
                    // 20s against a 30s floor.
                    Ok(mint_lasting(20, "short-lived"))
                })
                .await
                .unwrap();
            assert_eq!(served.source, Source::Mint);
        }

        assert_eq!(
            mints.load(Ordering::SeqCst),
            3,
            "an unservable token must not be served to a later caller"
        );
    }

    /// The wall-clock guard. An entry whose token has already expired is
    /// discarded on read even though moka's monotonic clock has not
    /// retired it, which is what a host suspend looks like.
    #[tokio::test]
    async fn an_entry_past_its_wall_clock_expiry_is_discarded() {
        let cache = cache();
        let key = key_for(&cache, "alice-token");
        let mints = AtomicUsize::new(0);

        // A long serve window, so moka will not retire it, paired with a
        // token that is already expired in wall-clock terms. Only the
        // wall-clock check can catch this.
        let first = cache
            .get_or_mint::<MintFailed, _>(key, async {
                mints.fetch_add(1, Ordering::SeqCst);
                Ok(Mint {
                    token: RawDelegatedToken::new(
                        "stale",
                        "Authorization",
                        "https://billing.example.com",
                        Vec::new(),
                        Utc::now() - chrono::Duration::seconds(60),
                    ),
                    issued_token_type: "access_token".to_owned(),
                })
            })
            .await
            .unwrap();
        assert_eq!(first.source, Source::Mint);

        let second = cache
            .get_or_mint::<MintFailed, _>(key, async {
                mints.fetch_add(1, Ordering::SeqCst);
                Ok(mint_lasting(300, "fresh"))
            })
            .await
            .unwrap();

        assert_eq!(second.source, Source::Mint);
        assert_eq!(&*second.mint.token.token, "fresh");
        assert_eq!(mints.load(Ordering::SeqCst), 2);
    }

    /// The other half of the wall-clock guard: the ceiling. A token the
    /// `IdP` issued for two hours is still valid to it long after a
    /// five-minute `ttl_ceiling_seconds` was supposed to retire the
    /// entry, so `expires_at` cannot catch this one — only the serve
    /// window can. Without that check a suspended host resumes and
    /// keeps serving a token straight through the ceiling, which is the
    /// only bound the cache offers against an `IdP`-side revocation.
    #[tokio::test]
    async fn an_entry_past_its_serve_window_is_discarded_though_its_token_lives_on() {
        let config = CacheConfig {
            ttl_ceiling_seconds: 300,
            ..enabled_config()
        };
        let cache = DelegatedTokenCache::new(config).unwrap().unwrap();
        let key = key_for(&cache, "alice-token");

        // What a suspend leaves behind. moka's monotonic clock has
        // barely moved, so the entry is still in the map with time on
        // its window, while the wall clock is an hour past a ceiling of
        // five minutes.
        let serve_for = cache
            .config
            .serve_window(Duration::from_secs(7200), key.jitter_byte());
        assert!(serve_for.is_some(), "the entry must start out servable");
        cache
            .inner
            .insert(
                key,
                CachedMint {
                    mint: mint_lasting(7200, "past-the-ceiling"),
                    minted_at: Utc::now() - chrono::Duration::seconds(3600),
                    serve_for,
                },
            )
            .await;

        let served = cache
            .get_or_mint::<MintFailed, _>(key, async { Ok(mint_lasting(7200, "fresh")) })
            .await
            .unwrap();

        assert_eq!(
            served.source,
            Source::Mint,
            "an entry an hour past a five-minute ceiling must not be served"
        );
        assert_eq!(&*served.mint.token.token, "fresh");
    }

    /// The bound is the flooding mitigation, so it has to hold against a
    /// burst of distinct keys rather than merely be configured.
    #[tokio::test]
    async fn a_burst_of_distinct_keys_cannot_grow_the_cache_past_its_bound() {
        let config = CacheConfig {
            max_entries: 10,
            ..enabled_config()
        };
        let cache = DelegatedTokenCache::new(config).unwrap().unwrap();

        for i in 0..500 {
            let key = key_for(&cache, &format!("invented-token-{i}"));
            cache
                .get_or_mint::<MintFailed, _>(key, async move {
                    Ok(mint_lasting(300, &format!("minted-{i}")))
                })
                .await
                .unwrap();
        }

        let count = cache.entry_count().await;
        assert!(
            count <= 10,
            "500 distinct keys against a bound of 10 left {count} entries"
        );
    }

    /// Replacing a live entry must reschedule on the new token, not
    /// inherit the old one's remaining time. moka's default
    /// `expire_after_update` does the latter, which is why this is
    /// implemented rather than defaulted.
    #[test]
    fn an_update_reschedules_on_the_new_token() {
        let config = enabled_config();
        let fresh = CachedMint {
            mint: mint_lasting(600, "replacement"),
            minted_at: Utc::now(),
            serve_for: config.serve_window(Duration::from_secs(600), 0),
        };
        let key = CacheKey::from_bytes_for_test([7_u8; 32]);

        let rescheduled = ServeWindow.expire_after_update(
            &key,
            &fresh,
            std::time::Instant::now(),
            // What the replaced entry had left: nearly nothing.
            Some(Duration::from_secs(1)),
        );

        assert_eq!(
            rescheduled, fresh.serve_for,
            "the new token's own window must win over the old entry's remainder"
        );
        assert_ne!(rescheduled, Some(Duration::from_secs(1)));
    }

    /// The unservable case survives the update path too, or a replacement
    /// token whose margin swallows its lifetime would become servable by
    /// the back door.
    #[test]
    fn an_update_with_an_unservable_window_expires_immediately() {
        let unservable = CachedMint {
            mint: mint_lasting(20, "too-short"),
            minted_at: Utc::now(),
            serve_for: None,
        };
        let key = CacheKey::from_bytes_for_test([7_u8; 32]);

        assert_eq!(
            ServeWindow.expire_after_update(
                &key,
                &unservable,
                std::time::Instant::now(),
                Some(Duration::from_secs(300)),
            ),
            Some(Duration::ZERO)
        );
    }

    #[tokio::test]
    async fn flush_drops_everything() {
        let cache = cache();
        let key = key_for(&cache, "alice-token");
        cache
            .get_or_mint::<MintFailed, _>(key, async { Ok(mint_lasting(300, "minted")) })
            .await
            .unwrap();
        assert_eq!(cache.entry_count().await, 1);

        cache.flush().await;
        assert_eq!(cache.entry_count().await, 0);

        let after = cache
            .get_or_mint::<MintFailed, _>(key, async { Ok(mint_lasting(300, "re-minted")) })
            .await
            .unwrap();
        assert_eq!(after.source, Source::Mint, "a flushed key must miss");
    }
}
