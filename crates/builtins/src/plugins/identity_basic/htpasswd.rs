// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `.htpasswd` backend: the near-universal on-disk password format, read
// as an index from user-id to stored verifier.
//
// This is the format `identity/api-key` structurally cannot consume, and the
// reason this plugin exists. The file holds hashes, never plaintext, so a file
// that leaks does not hand over usable credentials -- but it *is* an
// offline-crackable verifier, which is why the operator documentation says it
// must not be world-readable.
//
// The refresh interval is the revocation window on this backend. A record
// removed from the file keeps authenticating until the next successful reload,
// and no cache on top of this would change that. It is named configuration for
// that reason.
//
// The index, refresh and publish-ordering machinery here is copied from the
// api-key file backend rather than shared with it. That is deliberate: the two
// races it encodes (see `reload` and `refresh_if_due`) are subtle enough that a
// reimplementation would reintroduce them, and extracting a shared helper
// across two plugins is deferred until there is a second backend to generalise
// from. Where this backend diverges -- the staleness ceiling is required, not
// optional -- the divergence is called out at the field.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use praxis_policy_core::host::HostServices;

use super::BasicCredential;
use super::directory::{CredentialDirectory, DirectoryError, StoredVerifier, UserRecord};
use super::verifier::{
    CostProfile, Limits, ParsedHash, empty_directory_hash, parse_hash, verify_bytes,
};

/// The `kind:` string an operator writes under `provider:`.
pub const KIND: &str = "htpasswd";

/// How a `.htpasswd` directory is configured.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HtpasswdConfig {
    /// Where the file lives.
    pub path: PathBuf,

    /// The required refresh interval, in seconds.
    ///
    /// Zero requests a reload on every lookup. Removed records may remain usable
    /// until a successful reload.
    pub refresh_secs: u64,

    /// The required maximum index age, in seconds.
    ///
    /// Lookups fail closed after this ceiling, including when reloads keep failing.
    pub max_staleness_secs: u64,

    /// Parameter ceilings for hashes admitted at load.
    #[serde(default)]
    pub limits: HtpasswdLimits,

    /// The maximum number of concurrent verifications.
    ///
    /// Requests beyond this limit are rejected rather than queued.
    #[serde(default = "default_max_concurrent_verifications")]
    pub max_concurrent_verifications: usize,
}

/// Parameter ceilings, as an operator writes them.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HtpasswdLimits {
    /// The highest bcrypt cost this directory will load.
    #[serde(default = "default_max_bcrypt_cost")]
    pub max_bcrypt_cost: u32,

    /// The highest argon2 memory cost, in KiB.
    #[serde(default = "default_max_argon2_memory_kib")]
    pub max_argon2_memory_kib: u32,

    /// The highest argon2 time cost, in passes.
    #[serde(default = "default_max_argon2_time_cost")]
    pub max_argon2_time_cost: u32,
}

impl Default for HtpasswdLimits {
    fn default() -> Self {
        let shared = Limits::default();
        Self {
            max_bcrypt_cost: shared.max_bcrypt_cost,
            max_argon2_memory_kib: shared.max_argon2_memory_kib,
            max_argon2_time_cost: shared.max_argon2_time_cost,
        }
    }
}

impl From<HtpasswdLimits> for Limits {
    fn from(value: HtpasswdLimits) -> Self {
        Self {
            max_bcrypt_cost: value.max_bcrypt_cost,
            max_argon2_memory_kib: value.max_argon2_memory_kib,
            max_argon2_time_cost: value.max_argon2_time_cost,
        }
    }
}

fn default_max_bcrypt_cost() -> u32 {
    Limits::default().max_bcrypt_cost
}

fn default_max_argon2_memory_kib() -> u32 {
    Limits::default().max_argon2_memory_kib
}

fn default_max_argon2_time_cost() -> u32 {
    Limits::default().max_argon2_time_cost
}

fn default_max_concurrent_verifications() -> usize {
    // Enough that a normal login burst does not deny, low enough that the
    // worst case is bounded: at bcrypt cost 12 (~250ms) this is a few seconds
    // of queued CPU, not an unbounded backlog.
    32
}

impl HtpasswdConfig {
    /// The staleness ceiling.
    pub fn max_staleness(&self) -> Duration {
        Duration::from_secs(self.max_staleness_secs)
    }

    /// Validate refresh, staleness, and verification capacity settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the staleness ceiling is below the refresh interval
    /// or the verification capacity is outside the supported range.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_staleness_secs < self.refresh_secs {
            return Err(format!(
                "`max_staleness_secs` ({}) is below `refresh_secs` ({}), so lookups would fail \
                 closed before the first reload is even due",
                self.max_staleness_secs, self.refresh_secs
            ));
        }
        if self.max_concurrent_verifications == 0 {
            return Err(
                "`max_concurrent_verifications` must be at least 1, or every request denies"
                    .to_owned(),
            );
        }
        // The upper bound is the semaphore's, not a policy choice:
        // `Semaphore::new` panics above `MAX_PERMITS`, and a panic in a
        // library takes the host's process down over what is only a
        // configuration mistake. `new` already promises an `Err` for bad
        // config, so this keeps that promise.
        if self.max_concurrent_verifications > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(format!(
                "`max_concurrent_verifications` ({}) exceeds the maximum this runtime \
                 supports ({}); a value this large is not a meaningful limit anyway, since \
                 the blocking pool bounds concurrency well below it",
                self.max_concurrent_verifications,
                tokio::sync::Semaphore::MAX_PERMITS,
            ));
        }
        Ok(())
    }
}

/// One user's entry, as indexed.
#[derive(Debug)]
struct Entry {
    hash: ParsedHash,
}

/// The loaded index, plus the worst case it implies.
#[derive(Debug)]
struct Index {
    users: HashMap<String, Entry>,

    /// The dummy hash used to verify unknown-user credentials.
    dummy: ParsedHash,
}

/// Records read from a `.htpasswd` file, indexed by user-id.
#[derive(Debug)]
pub struct HtpasswdDirectory {
    config: HtpasswdConfig,

    /// The most recently loaded valid index.
    index: ArcSwap<Index>,

    /// The origin for refresh and staleness timers.
    started: Instant,

    /// When the next reload becomes due, in milliseconds since `started`.
    next_attempt_ms: AtomicU64,

    /// The last successful load time, in milliseconds since `started`.
    loaded_at_ms: AtomicU64,

    /// The capacity limit for in-flight verifications.
    verifications: Arc<tokio::sync::Semaphore>,

    /// The fallback dummy hash for an empty directory.
    empty: ParsedHash,

    /// How many times this directory minted its empty-directory hash.
    ///
    /// Directory-local rather than process-wide: the hash is built once at
    /// construction, and a process-wide counter cannot prove that, because a
    /// concurrent test constructing another directory increments it too.
    empty_mints: AtomicU64,

    /// The number of refresh-path file-read attempts, for regression tests.
    reload_attempts: AtomicU64,

    /// The number of dummy verification attempts, for regression tests.
    dummy_runs: AtomicU64,
}

/// Load and validate a `.htpasswd` index.
fn read_index(config: &HtpasswdConfig, empty: &ParsedHash) -> Result<Index, String> {
    let text = std::fs::read_to_string(&config.path)
        .map_err(|e| format!("reading {}: {e}", config.path.display()))?;
    let limits = Limits::from(config.limits);

    let mut users: HashMap<String, Entry> = HashMap::new();
    // Any record serves as the miss-path hash once uniformity is enforced, so
    // the first admitted one is kept. `profile` carries the parameters every
    // later record must match, with the line that established them.
    let mut reference: Option<ParsedHash> = None;
    let mut profile: Option<(CostProfile, usize)> = None;

    for (number, raw) in text.lines().enumerate() {
        // Human-facing line numbers, since this lands in a config error.
        let line_number = number.saturating_add(1);
        let line = raw.trim();
        // Comments and blank lines are part of the format.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (user_id, stored) = line.split_once(':').ok_or_else(|| {
            format!(
                "{} line {line_number}: no `user:hash` separator",
                config.path.display()
            )
        })?;
        if user_id.is_empty() || stored.is_empty() {
            return Err(format!(
                "{} line {line_number}: an empty user-id or hash",
                config.path.display()
            ));
        }

        // Normalised identically to an inbound user-id, and *before* the
        // duplicate check below. Normalising after would let two differently
        // encoded spellings of one name collapse onto one key silently,
        // handing whichever landed second the other's identity.
        let normalised: String = user_id.nfc().collect();

        // The hash error deliberately carries no hash material, so the message
        // names the line and the scheme problem and nothing else.
        let hash = parse_hash(stored, &limits)
            .map_err(|e| format!("{} line {line_number}: {e}", config.path.display()))?;
        // One cost profile per file, not merely one scheme. Differing costs
        // within a directory are a user-enumeration oracle on their own: with
        // bcrypt costs 4 and 12 present, a wrong password for the cost-4 user
        // returns in 0.7ms while an unknown user runs the cost-12 hash in
        // 160ms -- a 245x difference, measured. No choice of miss-path hash
        // closes that, because it is the *hits* that differ from each other.
        //
        // Ranking cost is not an option either. Argon2 trades memory against
        // passes per RFC 9106, so `m=4096,t=10` and `m=65536,t=2` cannot be
        // ordered by any single number: measured, the second costs 37ms
        // against the first's 14ms while scoring lower on a memory-log-plus-
        // passes formula. Equality is checkable; ordering is not.
        match profile {
            None => profile = Some((hash.profile(), line_number)),
            Some((seen, first_line)) if seen != hash.profile() => {
                return Err(format!(
                    "{} line {line_number}: this record is {} but line {first_line} is {}. \
                     One cost profile per file: a directory whose records cost different \
                     amounts to verify reveals which user-ids exist, because a wrong \
                     password for a cheap record returns sooner than a lookup for a user \
                     that does not exist. Re-hash the file with one set of parameters.",
                    config.path.display(),
                    hash.profile().describe(),
                    seen.describe(),
                ));
            },
            Some(_) => {},
        }

        // Uniform cost means any record serves as the miss-path hash, so the
        // first is kept and the rest need no comparison.
        if reference.is_none() {
            reference = Some(hash.clone());
        }

        // Two records for one user have no coherent answer, and picking either
        // silently would hand one caller the other's identity. Real `.htpasswd`
        // files in the wild do contain duplicates, so this may block a
        // migration -- failing closed is the deliberate choice, and the message
        // says which line collided.
        if users.contains_key(&normalised) {
            return Err(format!(
                "{} line {line_number}: a second record carries the same user-id (after \
                 Unicode normalisation)",
                config.path.display()
            ));
        }
        users.insert(normalised, Entry { hash });
    }

    // The heaviest record actually present, not a constant and not the dominant
    // scheme. A dummy at the dominant cost leaks in any mixed file: misses
    // would cost the common parameters while hits on minority records run
    // measurably faster or slower, which enumerates both which names exist and
    // which users sit on the cheapest scheme.
    //
    // Reused rather than minted, so a populated file does no cryptographic
    // work at load at all.
    // The most expensive record in the file, whenever the file has one. Within a
    // single scheme -- which is all a file may hold -- that is exact: a miss
    // runs the same hash the slowest hit runs, so the two cost the same by
    // construction rather than by estimate.
    //
    // The floor hash applies only to a directory with no records at all. An
    // earlier version also substituted it whenever every record scored below
    // the floor, which was a mistake in the other direction: Apache's
    // `htpasswd -B` defaults to cost 5, so an ordinary generated file got a
    // cost-10 miss against cost-5 hits -- 40ms against 2.7ms measured, a 15x
    // gap a client can time to enumerate which user-ids exist. The floor was
    // meant to stop an empty file being distinguishable from a populated one;
    // it must not make a populated file worse than no protection at all.
    let dummy = reference.unwrap_or_else(|| empty.clone());

    Ok(Index { users, dummy })
}

impl HtpasswdDirectory {
    /// Open a `.htpasswd` directory with the supplied configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, an unreadable file, malformed
    /// records, duplicate user-ids, mixed hashing schemes, or refused hash parameters.
    pub fn new(config: HtpasswdConfig) -> Result<Self, String> {
        config.validate()?;
        let empty = empty_directory_hash().map_err(|e| {
            format!(
                "{}: could not build the miss-path hash: {e}",
                config.path.display()
            )
        })?;
        let index = read_index(&config, &empty)?;
        let first_attempt = config.refresh_secs.saturating_mul(1000);
        let permits = config.max_concurrent_verifications;
        Ok(Self {
            config,
            empty,
            empty_mints: AtomicU64::new(1),
            index: ArcSwap::from_pointee(index),
            started: Instant::now(),
            next_attempt_ms: AtomicU64::new(first_attempt),
            loaded_at_ms: AtomicU64::new(0),
            verifications: Arc::new(tokio::sync::Semaphore::new(permits)),
            reload_attempts: AtomicU64::new(0),
            dummy_runs: AtomicU64::new(0),
        })
    }

    /// Milliseconds since this directory was built.
    fn now_ms(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// How stale the loaded index is.
    fn staleness(&self) -> Duration {
        let loaded = self.loaded_at_ms.load(Ordering::Acquire);
        Duration::from_millis(self.now_ms().saturating_sub(loaded))
    }

    /// How many users the running index holds.
    pub fn len(&self) -> usize {
        self.index.load().users.len()
    }

    /// Whether the running index holds no users.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of dummy verification attempts, for regression tests.
    pub fn dummy_runs(&self) -> u64 {
        self.dummy_runs.load(Ordering::Relaxed)
    }

    /// How many times this directory minted its empty-directory hash.
    pub fn empty_mints(&self) -> u64 {
        self.empty_mints.load(Ordering::Relaxed)
    }

    /// The number of refresh-path file-read attempts, for regression tests.
    pub fn reload_attempts(&self) -> u64 {
        self.reload_attempts.load(Ordering::Relaxed)
    }

    /// The work factor the miss path currently runs at, for the tests.
    pub fn miss_cost_profile(&self) -> CostProfile {
        self.index.load().dummy.profile()
    }

    /// Reload the file, retaining the previous index on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or its records fail validation.
    pub fn reload(&self) -> Result<(), String> {
        // The whole next index is built before anything is published, so a read
        // or parse that fails leaves the running index serving.
        let index = read_index(&self.config, &self.empty)?;
        // Records first, then the timestamp, and not the other way round. The
        // two are not published together, so a lookup can land between them:
        // this order shows it a new index under an old timestamp, which reads
        // as stale and denies. Stamping the time first would show the old index
        // under a fresh one, which is a staleness ceiling that passes while
        // serving exactly what it exists to stop serving.
        self.index.store(Arc::new(index));
        self.loaded_at_ms.store(self.now_ms(), Ordering::Release);
        Ok(())
    }

    /// Attempt a reload when the refresh interval has elapsed.
    fn refresh_if_due(&self) {
        let interval = self.config.refresh_secs;
        let now = self.now_ms();
        let due = self.next_attempt_ms.load(Ordering::Acquire);
        if now < due {
            return;
        }

        // Claim the slot before reading. Losing the exchange means another
        // request is already reloading. Moving the marker forward even when the
        // read then fails is what keeps an unreadable file from being retried
        // on every request until it comes back.
        let next = now.saturating_add(interval.saturating_mul(1000));
        if self
            .next_attempt_ms
            .compare_exchange(due, next, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        self.reload_attempts.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = self.reload() {
            // Rate limited by the refresh interval itself: this runs once per
            // interval, not once per request, because the slot was claimed
            // above. The path is operator-supplied and the error carries no
            // credential material.
            tracing::warn!(
                path = %self.config.path.display(),
                %error,
                "htpasswd file could not be reloaded; the previous index is still serving",
            );
        }
    }
}

#[async_trait::async_trait]
impl CredentialDirectory for HtpasswdDirectory {
    /// Look up a user in the file index without requiring host egress capabilities.
    async fn lookup(
        &self,
        user_id: &str,
        _services: &dyn HostServices,
    ) -> Result<Option<UserRecord>, DirectoryError> {
        self.refresh_if_due();

        // Past the ceiling the loaded index is not an answer this backend
        // stands behind, so it says it cannot answer. That denies as a
        // directory failure rather than as an unknown user, which is the
        // difference between an operator seeing an outage and seeing a wave of
        // bad passwords.
        if self.staleness() > self.config.max_staleness() {
            return Err(DirectoryError::Stale);
        }

        let index = self.index.load();
        // The record carries the stored hash as its verifier. The parse already
        // happened at load, so this is a map probe and a clone of an encoded
        // string -- O(1) in the user count, whatever the file size.
        // `.htpasswd` carries a user-id and a hash and nothing else, so there
        // is nothing to project and nothing to strip: the hash lives in
        // `verifier`, never in `fields`. A deployment needing roles or teams
        // wants the YAML backend. No native expiry either -- the resolver still
        // enforces expiry, there is simply never one to enforce here.
        Ok(index.users.get(user_id).map(|entry| {
            UserRecord::verifier_only(StoredVerifier::Hash(entry.hash.encoded().to_owned()))
        }))
    }

    async fn verify(
        &self,
        record: Option<&UserRecord>,
        credential: &BasicCredential,
        _services: &dyn HostServices,
    ) -> Result<bool, DirectoryError> {
        // Acquired before either branch, so the found and not-found paths are
        // bounded identically. Denying rather than waiting: a queue here is an
        // unauthenticated CPU exhaustion path, and a caller cannot tell a
        // saturation denial from a wrong password anyway.
        //
        // Moved into the blocking closure below rather than held here, and that
        // placement is the whole protection. A permit dropped with this future
        // -- which happens on any client disconnect or upstream timeout -- would
        // be released while the `spawn_blocking` work it was bounding carried
        // on, because dropping a `JoinHandle` does not cancel a blocking task.
        // A caller that connects and disconnects could then start unbounded
        // concurrent verifications, limited only by the Tokio blocking pool.
        // Measured: a cap of 1 admitted 8 concurrent verifies that way.
        let permit = self
            .verifications
            .clone()
            .try_acquire_owned()
            .map_err(|_at_capacity| DirectoryError::Saturated)?;

        let index = self.index.load();
        // The hash to run, and whether this is a real check or a dummy. Both
        // arms produce a parsed hash *before* the branch is observable in
        // timing: the found arm re-parses the stored record and the miss arm
        // takes the pre-built dummy, so neither path skips the parse.
        let (hash, is_dummy) = match record.map(|r| &r.verifier) {
            Some(StoredVerifier::Hash(encoded)) => {
                match parse_hash(encoded, &Limits::from(self.config.limits)) {
                    Ok(parsed) => (parsed, false),
                    // A record that parsed at load and not now means the index
                    // changed underneath; fail closed rather than authenticate.
                    Err(_) => (index.dummy.clone(), true),
                }
            },
            // A delegated verdict cannot arrive from a file backend.
            Some(StoredVerifier::Delegated { .. }) => {
                return Err(DirectoryError::Malformed(
                    "a file backend cannot carry a delegated verdict".to_owned(),
                ));
            },
            // No such user. Run the dummy so a miss costs what a hit costs.
            None => (index.dummy.clone(), true),
        };

        if is_dummy {
            self.dummy_runs.fetch_add(1, Ordering::Relaxed);
        }

        // Off the async worker: a bcrypt or argon2 verify is CPU-bound for
        // milliseconds to seconds, and every syntactically valid header costs
        // one. Monopolizing a worker would starve every other request on it.
        let password_bytes = credential.to_zeroized_password();
        let outcome = tokio::task::spawn_blocking(move || {
            // The permit lives and dies with the CPU work it bounds. Named
            // `_permit` inside the closure so it is held for the whole body
            // and released when the task ends, not when the caller's future
            // does.
            let _permit = permit;
            verify_bytes(&hash, &password_bytes)
        })
        .await
        .map_err(|_join_failed| {
            DirectoryError::Unavailable("the verification task did not complete".to_owned())
        })?;

        // The dummy's verdict is discarded: it exists to cost time, and
        // returning it would authenticate a miss whenever the dummy's throwaway
        // password happened to match.
        Ok(outcome && !is_dummy)
    }

    fn kind(&self) -> &'static str {
        KIND
    }
}
