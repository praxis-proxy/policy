// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A cache in front of a directory.
//
// Wraps any `KeyDirectory`, so what it caches is answers rather than anything
// backend specific.
//
// # The positive TTL is the revocation window
//
// A record revoked at the directory keeps authenticating here until its entry
// expires. That is the same property the file backend's `refresh_secs` has and
// the same one MaaS documents for Authorino's `--metadata-cache-ttl`, whose
// default is 60 seconds; their docs say plainly that a revoked key can keep
// succeeding for up to the TTL, and that they considered lowering it and chose
// not to on performance grounds. Naming it is the honest thing to do, because
// it cannot be designed away: a cache that could not serve a stale answer
// would not be a cache.
//
// # Why misses are cached at all
//
// A directory lookup is a network round trip and an unknown credential costs
// the same as a known one. Without a negative entry, a caller working through
// guesses turns PPE into a load generator pointed at the key service, one
// request per guess, indefinitely. The negative TTL puts a ceiling on that.
//
// # Why misses are counted and bounded separately
//
// Caching misses moves the problem rather than solving it if the cache is
// unbounded: every guess then allocates an entry, and the flood becomes memory
// growth instead of directory load. Positives and negatives get their own maps
// and their own ceilings, so a flood of guesses can only ever evict other
// guesses. Legitimate credentials already cached keep their entries.
//
// # Failures are never cached
//
// A directory that could not answer is asked again. Caching that would turn a
// blip into an outage lasting the TTL, and would do it at exactly the moment
// an operator is trying to recover the directory.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use praxis_policy_core::host::HostServices;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::directory::{DirectoryError, KeyDirectory, KeyRecord, PresentedKey};

fn default_max_entries() -> usize {
    10_000
}

/// How long answers are reused, and how many are held.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// How long a resolved record is reused.
    ///
    /// **This interval is the revocation window.** A record revoked at the
    /// directory keeps authenticating until its entry expires.
    pub ttl_secs: u64,

    /// How long an unknown credential is remembered as unknown.
    ///
    /// Short by default relative to the positive TTL: the cost of forgetting a
    /// miss is one extra lookup, while the cost of remembering one too long is
    /// that a key issued a moment ago is refused.
    #[serde(default)]
    pub negative_ttl_secs: u64,

    /// How many resolved records are held before new ones stop being cached.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,

    /// How many unknown credentials are held.
    ///
    /// Its own ceiling rather than a share of `max_entries`, so a flood of
    /// guesses cannot evict the credentials that are actually in use.
    #[serde(default = "default_max_entries")]
    pub max_negative_entries: usize,
}

impl CacheConfig {
    /// Reject settings that cannot mean what they say.
    ///
    /// # Errors
    ///
    /// A zero positive TTL, which would cache nothing while still paying for
    /// the bookkeeping, or a zero capacity, which is the same thing said
    /// differently. Omitting the whole `cache:` block is how an operator turns
    /// caching off.
    pub fn validate(&self) -> Result<(), String> {
        if self.ttl_secs == 0 {
            return Err(
                "`cache.ttl_secs` is zero, which caches nothing. Remove the `cache:` block to \
                 turn caching off"
                    .to_owned(),
            );
        }
        if self.max_entries == 0 {
            return Err(
                "`cache.max_entries` is zero, which caches nothing. Remove the `cache:` block to \
                 turn caching off"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// One cached answer.
#[derive(Debug, Clone)]
struct Entry {
    /// `None` for a credential the directory did not recognise.
    record: Option<KeyRecord>,
    /// Milliseconds since the cache was built, after which this is stale.
    expires_at_ms: u64,
}

/// A directory whose answers are reused for a while.
#[derive(Debug)]
pub struct CachingDirectory {
    inner: std::sync::Arc<dyn KeyDirectory>,
    config: CacheConfig,
    started: Instant,
    /// Resolved records, keyed by digest.
    hits: RwLock<HashMap<[u8; 32], Entry>>,
    /// Credentials the directory did not recognise, keyed by digest.
    misses: RwLock<HashMap<[u8; 32], Entry>>,
}

impl CachingDirectory {
    /// Put `config` in front of `inner`.
    ///
    /// # Errors
    ///
    /// Whatever [`CacheConfig::validate`] rejects.
    pub fn new(
        inner: std::sync::Arc<dyn KeyDirectory>,
        config: CacheConfig,
    ) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            inner,
            config,
            started: Instant::now(),
            hits: RwLock::new(HashMap::new()),
            misses: RwLock::new(HashMap::new()),
        })
    }

    /// How many resolved records are held.
    pub fn len(&self) -> usize {
        self.hits.read().map_or(0, |map| map.len())
    }

    /// How many unknown credentials are held.
    pub fn negative_len(&self) -> usize {
        self.misses.read().map_or(0, |map| map.len())
    }

    /// Whether any resolved record is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn now_ms(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// The cache key.
    ///
    /// A digest, never the credential. A cache keyed by the key itself is a
    /// store of live credentials in process memory, readable by anything that
    /// can read the heap, for as long as the entry lives. Hashing costs one
    /// SHA-256 per lookup and removes that entirely. It is also what makes the
    /// entry safe to count, log and size.
    fn key_of(presented: &PresentedKey) -> [u8; 32] {
        Sha256::digest(presented.as_bytes()).into()
    }

    /// A live entry for `key`, if there is one.
    fn get(map: &RwLock<HashMap<[u8; 32], Entry>>, key: &[u8; 32], now: u64) -> Option<Entry> {
        let guard = map.read().ok()?;
        let entry = guard.get(key)?;
        // Expired entries are left in place for the insert path to clear.
        // Removing here would make every read take a write lock, which is the
        // lock the request path most wants to avoid.
        (entry.expires_at_ms > now).then(|| entry.clone())
    }

    /// Store `entry`, unless the map is full of live entries.
    fn put(
        map: &RwLock<HashMap<[u8; 32], Entry>>,
        capacity: usize,
        key: [u8; 32],
        entry: Entry,
        now: u64,
    ) {
        let Ok(mut guard) = map.write() else {
            return;
        };
        if guard.len() >= capacity && !guard.contains_key(&key) {
            // Clear what has expired before deciding the map is full. This is
            // the only place expired entries are reclaimed, so it runs on the
            // path that would otherwise grow the map.
            guard.retain(|_, held| held.expires_at_ms > now);
            if guard.len() >= capacity {
                // Still full of live entries, so this answer goes uncached
                // rather than evicting one that is in use. The entry would
                // expire on its own soon enough; refusing keeps the ceiling
                // meaningful and keeps a flood from displacing real traffic.
                return;
            }
        }
        guard.insert(key, entry);
    }
}

#[async_trait::async_trait]
impl KeyDirectory for CachingDirectory {
    async fn lookup(
        &self,
        presented: &PresentedKey,
        services: &dyn HostServices,
    ) -> Result<Option<KeyRecord>, DirectoryError> {
        let key = Self::key_of(presented);
        let now = self.now_ms();

        if let Some(entry) = Self::get(&self.hits, &key, now) {
            return Ok(entry.record);
        }
        if self.config.negative_ttl_secs > 0
            && let Some(entry) = Self::get(&self.misses, &key, now)
        {
            return Ok(entry.record);
        }

        // A failure is returned without being remembered: asking again is the
        // behaviour an operator recovering a directory needs.
        let answer = self.inner.lookup(presented, services).await?;

        match &answer {
            Some(_) => Self::put(
                &self.hits,
                self.config.max_entries,
                key,
                Entry {
                    record: answer.clone(),
                    expires_at_ms: now.saturating_add(self.config.ttl_secs.saturating_mul(1000)),
                },
                now,
            ),
            None if self.config.negative_ttl_secs > 0 => Self::put(
                &self.misses,
                self.config.max_negative_entries,
                key,
                Entry {
                    record: None,
                    expires_at_ms: now
                        .saturating_add(self.config.negative_ttl_secs.saturating_mul(1000)),
                },
                now,
            ),
            None => {},
        }

        Ok(answer)
    }

    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
}
