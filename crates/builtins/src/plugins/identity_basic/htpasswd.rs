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
// from. Where this backend diverges -- the staleness ceiling is required
// rather than optional, and the refresh interval has a one-second floor --
// the divergence is called out at the field.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use praxis_policy_core::host::HostServices;

use super::BasicCredential;
use super::directory::{CredentialDirectory, DirectoryError, StoredVerifier, UserRecord};
use super::verifier::{
    BCRYPT_TRUNCATION_BYTES, CostProfile, Limits, ParsedHash, empty_directory_hash, parse_hash,
    verify_bytes,
};

/// The `kind:` string an operator writes under `provider:`.
pub const KIND: &str = "htpasswd";

/// How a `.htpasswd` directory is configured.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HtpasswdConfig {
    /// Where the file lives.
    pub path: PathBuf,

    /// The required refresh interval, in seconds. At least one.
    ///
    /// This is the revocation window: a record removed from the file stays
    /// usable until the next successful reload.
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

    /// The highest sha-crypt round count this directory will load.
    #[serde(default = "default_max_sha_crypt_rounds")]
    pub max_sha_crypt_rounds: u32,
}

impl Default for HtpasswdLimits {
    fn default() -> Self {
        let shared = Limits::default();
        Self {
            max_bcrypt_cost: shared.max_bcrypt_cost,
            max_argon2_memory_kib: shared.max_argon2_memory_kib,
            max_argon2_time_cost: shared.max_argon2_time_cost,
            max_sha_crypt_rounds: shared.max_sha_crypt_rounds,
        }
    }
}

impl From<HtpasswdLimits> for Limits {
    fn from(value: HtpasswdLimits) -> Self {
        Self {
            max_bcrypt_cost: value.max_bcrypt_cost,
            max_argon2_memory_kib: value.max_argon2_memory_kib,
            max_argon2_time_cost: value.max_argon2_time_cost,
            max_sha_crypt_rounds: value.max_sha_crypt_rounds,
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

fn default_max_sha_crypt_rounds() -> u32 {
    Limits::default().max_sha_crypt_rounds
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
    /// Returns an error if the refresh interval is zero, the staleness ceiling
    /// is zero or below the refresh interval, or the verification capacity is
    /// outside the supported range.
    pub fn validate(&self) -> Result<(), String> {
        // Zero is not a usable ceiling in either reading an operator might
        // give it. As a bound it denies everything: `reload` stamps
        // `loaded_at_ms`, `staleness()` reads the clock again, and the
        // comparison is `>` against zero, so a lookup that crosses a
        // millisecond boundary -- or one that loses the refresh slot and
        // reads an index already 1ms old -- fails as `Stale`. That is an
        // outage from a config that loaded without complaint, and an
        // intermittent one. As "no ceiling" it is the opposite of what the
        // field means, which is the reading the api-key sibling invites by
        // treating its ceiling as optional; here the ceiling is required, so
        // there is no value that means unbounded.
        if self.max_staleness_secs == 0 {
            return Err(
                "`max_staleness_secs` must be at least 1: a zero ceiling denies every lookup \
                 that reads the clock a millisecond after a reload, and there is no value \
                 meaning `no ceiling` on this backend"
                    .to_owned(),
            );
        }
        if self.max_staleness_secs < self.refresh_secs {
            return Err(format!(
                "`max_staleness_secs` ({}) is below `refresh_secs` ({}), so lookups would fail \
                 closed before the first reload is even due",
                self.max_staleness_secs, self.refresh_secs
            ));
        }
        // `refresh_if_due` claims the next slot at `now + interval`, so a zero
        // interval leaves every later lookup immediately due again. Each one
        // then wins its own compare-exchange and dispatches its own reload.
        // The reload runs on a blocking thread, so this no longer stalls an
        // async worker -- but it still queues one file read and full parse per
        // lookup onto the blocking pool, all of them serialized on
        // `publishing` and none of them bounded by the verification semaphore.
        // Measured at 16 concurrent lookups, that is 16 reload attempts
        // waiting on one mutex to re-read a file nothing has changed.
        //
        // Rejected rather than made safe, because the value it buys is a
        // revocation window no operator can use: a one-second floor already
        // reloads as fast as the file's own mtime granularity.
        if self.refresh_secs == 0 {
            return Err(
                "`refresh_secs` must be at least 1: zero makes every lookup read and parse \
                 the file, and one second is already the tightest revocation window this \
                 backend can serve"
                    .to_owned(),
            );
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
    /// Everything a reload touches, shared so a blocking task can own a clone.
    ///
    /// Behind an `Arc` because the request-triggered reload runs on
    /// [`tokio::task::spawn_blocking`], whose closure must be `'static`: it
    /// cannot borrow from `self`. A dropped `JoinHandle` does not cancel the
    /// task, so the state has to outlive the caller's future rather than be
    /// borrowed from it.
    state: Arc<ReloadState>,

    /// The capacity limit for in-flight verifications.
    verifications: Arc<tokio::sync::Semaphore>,

    /// The number of dummy verification attempts, for regression tests.
    dummy_runs: AtomicU64,
}

/// The index, timers and counters a reload reads and publishes.
#[derive(Debug)]
struct ReloadState {
    config: HtpasswdConfig,

    /// The resolver's password-length ceiling, if it enforces one,
    /// reconciled with the file's scheme on every load.
    ///
    /// Held here rather than checked once at config load because the scheme
    /// can change under a reload: only a load that reads the file knows
    /// whether the ceiling is still coherent with it.
    max_password_bytes: Option<usize>,

    /// The most recently loaded valid index.
    index: ArcSwap<Index>,

    /// The origin for refresh and staleness timers.
    started: Instant,

    /// When the next reload becomes due, in milliseconds since `started`.
    next_attempt_ms: AtomicU64,

    /// The last successful load time, in milliseconds since `started`.
    loaded_at_ms: AtomicU64,

    /// The fallback dummy hash for an empty directory, minted on first need.
    ///
    /// A populated file supplies its own miss-path hash from a stored record,
    /// so the floor hash exists only for a file with no records at all. Minting
    /// it is a full bcrypt hash at [`EMPTY_DIRECTORY_COST`], so it is deferred
    /// rather than paid by every construction and reload.
    empty: OnceLock<ParsedHash>,

    /// How many times the floor hash has been minted, for regression tests.
    floor_mints: AtomicU64,

    /// Serializes the read-parse-publish sequence in [`Self::reload`].
    ///
    /// Without it two reloads can read opposite sides of a file replacement
    /// and publish in the reverse order, which restores a revoked record and
    /// stamps it fresh until the next refresh.
    ///
    /// [`Self::reload`]: ReloadState::reload
    publishing: std::sync::Mutex<()>,

    /// The number of refresh-path file-read attempts, for regression tests.
    reload_attempts: AtomicU64,

    /// The most reloads ever observed inside [`Self::reload`] at once.
    ///
    /// Exists so a test can assert the serialization rather than infer it from
    /// a timing window it cannot control.
    ///
    /// [`Self::reload`]: ReloadState::reload
    peak_concurrent_reloads: AtomicU64,

    /// How many reloads are inside [`Self::reload`] right now.
    ///
    /// [`Self::reload`]: ReloadState::reload
    reloads_in_flight: AtomicU64,
}

/// Tracks how many reloads are in flight, and the most ever at once.
struct ReloadGuard<'a> {
    in_flight: &'a AtomicU64,
}

impl<'a> ReloadGuard<'a> {
    /// Record one more reload in flight, raising the peak if this is a new one.
    fn enter(in_flight: &'a AtomicU64, peak: &AtomicU64) -> Self {
        let now = in_flight.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        peak.fetch_max(now, Ordering::AcqRel);
        Self { in_flight }
    }
}

impl Drop for ReloadGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The floor hash for an empty directory, minted once and then reused.
///
/// Minting is a full bcrypt hash at [`EMPTY_DIRECTORY_COST`], so a reload that
/// finds the file still empty reuses the first one rather than paying again.
fn mint_floor_hash(
    path: &std::path::Path,
    cell: &OnceLock<ParsedHash>,
    mints: &AtomicU64,
) -> Result<ParsedHash, String> {
    if let Some(minted) = cell.get() {
        return Ok(minted.clone());
    }
    let minted = empty_directory_hash().map_err(|e| {
        format!(
            "{}: could not build the miss-path hash: {e}",
            path.display()
        )
    })?;
    mints.fetch_add(1, Ordering::Relaxed);
    Ok(cell.get_or_init(|| minted).clone())
}

/// Load and validate a `.htpasswd` index.
///
/// `max_password_bytes` is the resolver's credential ceiling, if it enforces
/// one. It is checked against the file's scheme here rather than at config
/// load so that a reload which replaces an argon2 file with a bcrypt one is
/// refused instead of published.
///
/// `floor` supplies the miss-path hash for a file with no records. It is a
/// closure rather than a value so that a populated file never mints one.
fn read_index(
    config: &HtpasswdConfig,
    max_password_bytes: Option<usize>,
    floor: impl FnOnce() -> Result<ParsedHash, String>,
) -> Result<Index, String> {
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

    // The scheme is only knowable once the file has been read, so the
    // resolver's password ceiling is reconciled with it here. Checked on every
    // load, which is what makes it hold across a reload: a resolver that
    // started on an argon2 file with a ceiling above bcrypt's truncation point
    // would otherwise publish a bcrypt file and then deny every password
    // longer than 72 bytes as though it were simply wrong.
    //
    // Keyed on a record the file actually holds, not on `dummy` below: the
    // miss-path hash for an empty file is a synthesized bcrypt one, and
    // reading the ceiling off it refused an emptied argon2 directory -- the
    // revocation reload -- with a message naming bcrypt records it does not
    // contain. A file with no records constrains the ceiling not at all, and
    // the first record a later reload admits re-runs this check.
    if let Some(CostProfile::Bcrypt { .. }) = reference.as_ref().map(ParsedHash::profile)
        && let Some(ceiling) = max_password_bytes
        && ceiling > BCRYPT_TRUNCATION_BYTES
    {
        return Err(format!(
            "{}: `limits.max_password_bytes` is {ceiling} on a bcrypt \
             directory, above bcrypt's {BCRYPT_TRUNCATION_BYTES}-byte truncation \
             point. A longer password is admitted here and then always rejected \
             by the verifier, which locks out every user who chooses one with no \
             denial an operator can read. Lower the ceiling to \
             {BCRYPT_TRUNCATION_BYTES} or re-hash the file with argon2 or \
             sha-crypt, which consume the whole password",
            config.path.display(),
        ));
    }

    // Any record in the file costs what every other one does, so reusing one
    // of them makes a miss cost exactly what a hit costs -- by construction
    // rather than by estimate. The synthesized hash is for a file with no
    // records at all, which otherwise answers in nanoseconds and is
    // distinguishable from a populated one by timing alone.
    let dummy = match reference {
        Some(stored) => stored,
        None => floor()?,
    };

    Ok(Index { users, dummy })
}

impl HtpasswdDirectory {
    /// Open a `.htpasswd` directory with the supplied configuration.
    ///
    /// Accepts bcrypt, argon2, sha256crypt (`$5$`), and sha512crypt (`$6$`)
    /// records, provided every record in the file shares one cost profile.
    ///
    /// Applies no password-length ceiling of its own. A resolver that enforces
    /// one should use [`with_password_ceiling`] so the ceiling is re-checked
    /// against the file's scheme on every reload.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, an unreadable file, malformed
    /// records, duplicate user-ids, mixed hashing schemes, or refused hash parameters.
    ///
    /// [`with_password_ceiling`]: HtpasswdDirectory::with_password_ceiling
    pub fn new(config: HtpasswdConfig) -> Result<Self, String> {
        Self::build(config, None)
    }

    /// Open a `.htpasswd` directory that also honours a password ceiling.
    ///
    /// `max_password_bytes` is the resolver's credential ceiling. A bcrypt file
    /// is refused while it sits above bcrypt's truncation point, at this load
    /// and at every reload, so a file swapped from argon2 to bcrypt is rejected
    /// rather than published under a ceiling the verifier cannot honour.
    ///
    /// # Errors
    ///
    /// Returns an error for anything [`new`] rejects, and for a bcrypt file
    /// under a ceiling above bcrypt's truncation point.
    ///
    /// [`new`]: HtpasswdDirectory::new
    pub fn with_password_ceiling(
        config: HtpasswdConfig,
        max_password_bytes: usize,
    ) -> Result<Self, String> {
        Self::build(config, Some(max_password_bytes))
    }

    fn build(config: HtpasswdConfig, max_password_bytes: Option<usize>) -> Result<Self, String> {
        config.validate()?;
        let empty = OnceLock::new();
        let floor_mints = AtomicU64::new(0);
        let index = read_index(&config, max_password_bytes, || {
            mint_floor_hash(&config.path, &empty, &floor_mints)
        })?;
        let first_attempt = config.refresh_secs.saturating_mul(1000);
        let permits = config.max_concurrent_verifications;
        Ok(Self {
            state: Arc::new(ReloadState {
                config,
                empty,
                floor_mints,
                index: ArcSwap::from_pointee(index),
                max_password_bytes,
                publishing: std::sync::Mutex::new(()),
                started: Instant::now(),
                next_attempt_ms: AtomicU64::new(first_attempt),
                loaded_at_ms: AtomicU64::new(0),
                reload_attempts: AtomicU64::new(0),
                peak_concurrent_reloads: AtomicU64::new(0),
                reloads_in_flight: AtomicU64::new(0),
            }),
            verifications: Arc::new(tokio::sync::Semaphore::new(permits)),
            dummy_runs: AtomicU64::new(0),
        })
    }

    /// How many users the running index holds.
    pub fn len(&self) -> usize {
        self.state.index.load().users.len()
    }

    /// Whether the running index holds no users.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of dummy verification attempts, for regression tests.
    pub fn dummy_runs(&self) -> u64 {
        self.dummy_runs.load(Ordering::Relaxed)
    }

    /// The most reloads ever in flight at once, for regression tests.
    pub fn peak_concurrent_reloads(&self) -> u64 {
        self.state.peak_concurrent_reloads.load(Ordering::Relaxed)
    }

    /// How many times the empty-directory floor hash was minted, for the tests.
    pub fn floor_mints(&self) -> u64 {
        self.state.floor_mints.load(Ordering::Relaxed)
    }

    /// The number of refresh-path file-read attempts, for regression tests.
    pub fn reload_attempts(&self) -> u64 {
        self.state.reload_attempts.load(Ordering::Relaxed)
    }

    /// The work factor the miss path currently runs at, for the tests.
    pub fn miss_cost_profile(&self) -> CostProfile {
        self.state.index.load().dummy.profile()
    }

    /// Reload the file, retaining the previous index on failure.
    ///
    /// Blocking and I/O-bound: call it from a blocking context, or let the
    /// refresh interval drive it from a lookup, which runs it off the async
    /// worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or its records fail validation.
    pub fn reload(&self) -> Result<(), String> {
        self.state.reload()
    }
}

impl ReloadState {
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

    /// Reload the file, retaining the previous index on failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or its records fail validation.
    fn reload(&self) -> Result<(), String> {
        // Read, parse and publish under one lock, so concurrent reloads cannot
        // interleave. Two unserialized reloads that straddle a file
        // replacement can read opposite sides of it and then publish in the
        // reverse order, which republishes a revoked record *and* stamps it
        // fresh -- it then keeps authenticating for a whole refresh interval,
        // which is the revocation window this backend exists to bound. The
        // read is the wide part of the race, so narrowing the lock to the two
        // stores would not close it.
        //
        // Held across the file read, but never across an `.await`: `reload` is
        // synchronous, and its request-path caller (`refresh_if_due`) runs the
        // whole call inside `spawn_blocking`, so a thread that waits here is a
        // blocking-pool thread rather than an async worker. A poisoned lock
        // means a previous holder panicked mid-reload; the index is still
        // whatever was last published, so this recovers the guard and
        // continues rather than propagating a panic into the host.
        let _publishing = self
            .publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Counted inside the lock, so a test can assert the exclusion holds
        // instead of trying to catch a reverse publish in a window it cannot
        // schedule. A guard rather than a pair of calls, because `read_index`
        // below returns early with `?` on any unreadable or invalid file.
        let _in_flight = ReloadGuard::enter(&self.reloads_in_flight, &self.peak_concurrent_reloads);

        // The whole next index is built before anything is published, so a read
        // or parse that fails leaves the running index serving.
        let index = read_index(&self.config, self.max_password_bytes, || {
            mint_floor_hash(&self.config.path, &self.empty, &self.floor_mints)
        })?;
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
    ///
    /// The reload itself runs on a blocking thread. The slot claim stays here,
    /// so losing it still costs a lookup nothing but two atomic loads.
    async fn refresh_if_due(state: &Arc<Self>) {
        let interval = state.config.refresh_secs;
        let now = state.now_ms();
        let due = state.next_attempt_ms.load(Ordering::Acquire);
        if now < due {
            return;
        }

        // Claim the slot before reading. Losing the exchange means another
        // request is already reloading. Moving the marker forward even when the
        // read then fails is what keeps an unreadable file from being retried
        // on every request until it comes back.
        let next = now.saturating_add(interval.saturating_mul(1000));
        if state
            .next_attempt_ms
            .compare_exchange(due, next, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        state.reload_attempts.fetch_add(1, Ordering::Relaxed);

        // Off the async worker. A reload is a whole-file read, a parse of every
        // record, a wait on `publishing`, and -- for a file with no records --
        // a bcrypt mint at `EMPTY_DIRECTORY_COST`. None of that is bounded by
        // the verification semaphore, which guards only the verify step, so
        // inline it would stall every unrelated task on that worker for as long
        // as the file takes to read. A reload running longer than the interval
        // also makes the next claimant wait on `publishing`, and that wait
        // belongs on a blocking thread too.
        //
        // The `Arc` clone is what lets this be a `'static` closure: the task
        // outlives the caller's future, because dropping a `JoinHandle` does
        // not cancel a blocking task. Serialization, last-good-index retention
        // and the staleness stamp are all inside `reload`, so moving the call
        // changes where it runs and nothing about what it guarantees.
        let reloading = Arc::clone(state);
        let outcome = tokio::task::spawn_blocking(move || reloading.reload()).await;

        let error = match outcome {
            Ok(Ok(())) => return,
            Ok(Err(error)) => error,
            Err(_join_failed) => "the reload task did not complete".to_owned(),
        };

        // Rate limited by the refresh interval itself: this runs once per
        // interval, not once per request, because the slot was claimed above.
        // The path is operator-supplied and the error carries no credential
        // material.
        tracing::warn!(
            path = %state.config.path.display(),
            %error,
            "htpasswd file could not be reloaded; the previous index is still serving",
        );
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
        ReloadState::refresh_if_due(&self.state).await;

        // Past the ceiling the loaded index is not an answer this backend
        // stands behind, so it says it cannot answer. That denies as a
        // directory failure rather than as an unknown user, which is the
        // difference between an operator seeing an outage and seeing a wave of
        // bad passwords.
        if self.state.staleness() > self.state.config.max_staleness() {
            return Err(DirectoryError::Stale);
        }

        let index = self.state.index.load();
        // The admitted hash travels into the record as it was admitted at
        // load, so this is a map probe and a clone -- O(1) in the user count,
        // whatever the file size. What carrying it forward saves is the
        // admission checks, not the decode: `verify_bytes` still decodes the
        // encoding on every call, equally for a hit and for the dummy.
        // `.htpasswd` carries a user-id and a hash and nothing else, so there
        // is nothing to project and nothing to strip: the hash lives in the
        // verifier, never in `fields`. A deployment needing roles or teams
        // wants the YAML backend. No native expiry either -- the resolver still
        // enforces expiry, there is simply never one to enforce here.
        Ok(index
            .users
            .get(user_id)
            .map(|entry| UserRecord::verifier_only(StoredVerifier::Hash(entry.hash.clone()))))
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

        // The hash to run, and whether this is a real check or a dummy. Both
        // arms hold an admitted hash *before* the branch is observable in
        // timing: the found arm takes the one the record carries and the miss
        // arm the pre-built dummy, so neither path pays a parse the other
        // skips.
        //
        // The miss arm loads the index inside the arm, not before the match.
        // An `arc_swap` guard taken here would stay alive across the
        // `spawn_blocking` await below -- milliseconds to seconds of hashing --
        // which occupies one of the thread's debt slots for that whole span
        // and keeps a superseded index alive past the reload that replaced it.
        // The hit arm never reads the index at all.
        let (hash, is_dummy) = match record {
            Some(found) => found.verify_against(|verifier| match verifier {
                StoredVerifier::Hash(admitted) => Ok((admitted.clone(), false)),
                // A delegated verdict cannot arrive from a file backend.
                StoredVerifier::Delegated { .. } => Err(DirectoryError::Malformed(
                    "a file backend cannot carry a delegated verdict".to_owned(),
                )),
            })?,
            // No such user. Run the dummy so a miss costs what a hit costs.
            None => (self.state.index.load().dummy.clone(), true),
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
