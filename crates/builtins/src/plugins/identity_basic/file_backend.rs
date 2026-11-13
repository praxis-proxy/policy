// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What every on-disk Basic directory shares: an atomically swapped index, a
// CAS-claimed refresh slot, a fail-closed staleness ceiling, and a bounded
// verification pool.
//
// This is the shared helper KTD8 deferred. The deferral was conditional --
// "extracting a shared helper across two plugins is deferred until there is a
// second backend to generalise from" -- and the YAML backend is that second
// backend. Copying the machinery a third time is the thing KTD8 was actually
// guarding against, because the two races it encodes are not visible in the
// code that encodes them:
//
//   * `reload` holds one lock across read-parse-publish. Two unserialized
//     reloads straddling a file replacement can read opposite sides of it and
//     publish in reverse order, which restores a revoked record *and* stamps
//     it fresh. The read is the wide part of the race, so narrowing the lock
//     to the two stores does not close it.
//   * The index is stored *before* the timestamp. A lookup landing between
//     them then sees a new index under an old timestamp, which reads as stale
//     and denies. The other order shows an old index under a fresh timestamp,
//     which is a staleness ceiling that passes while serving exactly what it
//     exists to stop serving.
//
// What stays with each backend is the part that differs: how a file's bytes
// become records. That arrives as an `IndexSource`, so this module never
// learns a file format.
//
// The api-key file backend is deliberately *not* folded in here. Its index is
// keyed by digest with no verifier, no cost profile and no semaphore, its
// staleness ceiling is optional where this one is required, and it has no
// uniform-cost rule at all -- so sharing would mean widening this contract to
// a shape neither side wants. That extraction stays deferred.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use super::BasicCredential;
use super::directory::{DirectoryError, StoredVerifier, UserRecord};
use super::verifier::{CostProfile, ParsedHash, empty_directory_hash, verify_bytes};

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// One user's entry, as indexed.
///
/// The projectable fields travel with the entry so a lookup is a probe and a
/// clone. A backend with nothing to project leaves them empty.
#[derive(Debug)]
pub struct Entry {
    /// The admitted stored hash this record verifies against.
    pub hash: ParsedHash,

    /// Projectable subject attributes, with the backend's storage fields
    /// already stripped.
    pub fields: HashMap<String, serde_json::Value>,

    /// The record's expiry, for a format that carries one.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A loaded index, plus the miss-path hash its records imply.
///
/// Private: a caller reaches these numbers through [`FileBackend`], which is
/// what holds the `ArcSwap` and therefore the only thing that can read a
/// consistent snapshot of them.
#[derive(Debug)]
struct Index {
    users: HashMap<String, Entry>,

    /// The hash an unknown user is verified against.
    ///
    /// One of the file's own records whenever it holds any, which is what
    /// makes a miss cost exactly what a hit costs rather than approximately.
    dummy: ParsedHash,
}

impl Index {
    /// How many users this index holds.
    fn len(&self) -> usize {
        self.users.len()
    }

    /// Whether this index holds no users.
    fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// The work factor the miss path runs at.
    fn miss_cost_profile(&self) -> CostProfile {
        self.dummy.profile()
    }
}

/// How a file's bytes become an index.
///
/// Implemented by each backend, so this module carries the timing, publishing
/// and capacity rules without learning a file format.
pub trait IndexSource: std::fmt::Debug + Send + Sync + 'static {
    /// Read the file and produce admitted records keyed by normalised user-id.
    ///
    /// Implementations must normalise user-ids identically to an inbound one
    /// and *before* the duplicate check, must reject a duplicate rather than
    /// taking either record, and must keep stored hash material out of
    /// [`Entry::fields`].
    ///
    /// `max_password_bytes` is the resolver's credential ceiling when it
    /// enforces one. It is reconciled with the file's scheme here, on every
    /// load, because only a load that reads the file knows the scheme: a
    /// reload replacing an argon2 file with a bcrypt one has to be refused
    /// rather than published under a ceiling the verifier cannot honour.
    ///
    /// # Errors
    ///
    /// An operator-facing message for an unreadable file, a malformed record,
    /// a duplicate user-id, a refused or over-parameterised hash, or records
    /// that do not share one cost profile.
    ///
    /// The message must carry no credential or hash material, and that
    /// obligation is the implementor's: a reload failure is logged on every
    /// refresh interval while the previous index keeps serving, so anything
    /// in the message reaches operator logs repeatedly and quietly. A parser
    /// error must not be forwarded verbatim -- `serde_yaml` and friends quote
    /// the offending input back, which for a record file is a stored hash.
    /// Reduce such an error to its location before returning it.
    fn read(&self, max_password_bytes: Option<usize>) -> Result<HashMap<String, Entry>, String>;

    /// The file this source reads, for a load error and the reload warning.
    fn path(&self) -> &Path;

    /// The refresh interval, in seconds. The revocation window.
    fn refresh_secs(&self) -> u64;

    /// The age at which a loaded index stops being an answer, in seconds.
    fn max_staleness_secs(&self) -> u64;

    /// How many verifications may run at once.
    fn max_concurrent_verifications(&self) -> usize;

    /// A name for this backend, for diagnostics and the effect log.
    fn kind(&self) -> &'static str;
}

/// A file-backed directory: index, refresh timers, and verification capacity.
#[derive(Debug)]
pub struct FileBackend {
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

// -----------------------------------------------------------------------------
// Internal state
// -----------------------------------------------------------------------------

/// The index, timers and counters a reload reads and publishes.
#[derive(Debug)]
struct ReloadState {
    source: Box<dyn IndexSource>,

    /// The resolver's password-length ceiling, if it enforces one,
    /// reconciled with the file's scheme on every load.
    max_password_bytes: Option<usize>,

    /// The most recently loaded valid index.
    index: ArcSwap<Index>,

    /// The origin for refresh and staleness timers.
    ///
    /// Monotonic, so a wall-clock adjustment cannot make a stale index look
    /// fresh or expire a ceiling that has not passed.
    started: Instant,

    /// When the next reload becomes due, in milliseconds since `started`.
    next_attempt_ms: AtomicU64,

    /// The last successful load time, in milliseconds since `started`.
    loaded_at_ms: AtomicU64,

    /// The fallback dummy hash for an empty directory, minted on first need.
    ///
    /// A populated file supplies its own miss-path hash from a stored record,
    /// so the floor hash exists only for a file with no records at all.
    /// Minting it is a full bcrypt hash, so it is deferred rather than paid by
    /// every construction and reload.
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

// -----------------------------------------------------------------------------
// Shared load-time rules
// -----------------------------------------------------------------------------

/// Reject settings that cannot mean what they say.
///
/// Shared so every file backend rejects the same incoherent combinations with
/// the same message, rather than each one re-deriving which values are
/// unusable.
///
/// # Errors
///
/// A zero refresh interval or staleness ceiling, a ceiling below the refresh
/// interval, or a verification capacity of zero or above the semaphore's
/// maximum.
pub fn validate_timers(
    refresh_secs: u64,
    max_staleness_secs: u64,
    max_concurrent_verifications: usize,
) -> Result<(), String> {
    // Zero is not a usable ceiling in either reading an operator might give
    // it. As a bound it denies everything: `reload` stamps `loaded_at_ms`,
    // `staleness()` reads the clock again, and the comparison is `>` against
    // zero, so a lookup that crosses a millisecond boundary -- or one that
    // loses the refresh slot and reads an index already 1ms old -- fails as
    // `Stale`. That is an outage from a config that loaded without complaint,
    // and an intermittent one. As "no ceiling" it is the opposite of what the
    // field means, which is the reading the api-key sibling invites by
    // treating its ceiling as optional; here the ceiling is required, so there
    // is no value that means unbounded.
    if max_staleness_secs == 0 {
        return Err(
            "`max_staleness_secs` must be at least 1: a zero ceiling denies every lookup \
             that reads the clock a millisecond after a reload, and there is no value \
             meaning `no ceiling` on this backend"
                .to_owned(),
        );
    }
    if max_staleness_secs < refresh_secs {
        return Err(format!(
            "`max_staleness_secs` ({max_staleness_secs}) is below `refresh_secs` \
             ({refresh_secs}), so lookups would fail closed before the first reload is even due"
        ));
    }
    // `refresh_if_due` claims the next slot at `now + interval`, so a zero
    // interval leaves every later lookup immediately due again. Each one then
    // wins its own compare-exchange and dispatches its own reload. The reload
    // runs on a blocking thread, so this no longer stalls an async worker --
    // but it still queues one file read and full parse per lookup onto the
    // blocking pool, all of them serialized on `publishing` and none of them
    // bounded by the verification semaphore. Measured at 16 concurrent
    // lookups, that is 16 reload attempts waiting on one mutex to re-read a
    // file nothing has changed.
    //
    // Rejected rather than made safe, because the value it buys is a
    // revocation window no operator can use: a one-second floor already
    // reloads as fast as the file's own mtime granularity.
    if refresh_secs == 0 {
        return Err(
            "`refresh_secs` must be at least 1: zero makes every lookup read and parse \
             the file, and one second is already the tightest revocation window this \
             backend can serve"
                .to_owned(),
        );
    }
    if max_concurrent_verifications == 0 {
        return Err(
            "`max_concurrent_verifications` must be at least 1, or every request denies".to_owned(),
        );
    }
    // The upper bound is the semaphore's, not a policy choice:
    // `Semaphore::new` panics above `MAX_PERMITS`, and a panic in a library
    // takes the host's process down over what is only a configuration
    // mistake. `new` already promises an `Err` for bad config, so this keeps
    // that promise.
    if max_concurrent_verifications > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(format!(
            "`max_concurrent_verifications` ({max_concurrent_verifications}) exceeds the \
             maximum this runtime supports ({}); a value this large is not a meaningful \
             limit anyway, since the blocking pool bounds concurrency well below it",
            tokio::sync::Semaphore::MAX_PERMITS,
        ));
    }
    Ok(())
}

/// Enforce one cost profile across a file, record by record.
///
/// `seen` carries the profile every later record must match and the record
/// label that established it. `label` names the record under inspection the
/// way that format's operator reads it -- a line number for `.htpasswd`, a
/// username for YAML.
///
/// One cost profile per file, not merely one scheme. Differing costs within a
/// directory are a user-enumeration oracle on their own: with bcrypt costs 4
/// and 12 present, a wrong password for the cost-4 user returns in 0.7ms while
/// an unknown user runs the cost-12 hash in 160ms -- a 245x difference,
/// measured. No choice of miss-path hash closes that, because it is the *hits*
/// that differ from each other.
///
/// Ranking cost is not an option either. Argon2 trades memory against passes
/// per RFC 9106, so `m=4096,t=10` and `m=65536,t=2` cannot be ordered by any
/// single number: measured, the second costs 37ms against the first's 14ms
/// while scoring lower on a memory-log-plus-passes formula. Equality is
/// checkable; ordering is not.
///
/// # Errors
///
/// A record whose cost profile differs from the one already established,
/// naming both records and the fix.
pub fn enforce_uniform_cost(
    seen: &mut Option<(CostProfile, String)>,
    hash: &ParsedHash,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    match seen {
        None => {
            *seen = Some((hash.profile(), label.to_owned()));
            Ok(())
        },
        Some((profile, first)) if *profile != hash.profile() => Err(format!(
            "{} {label}: this record is {} but {first} is {}. One cost profile per file: a \
             directory whose records cost different amounts to verify reveals which \
             user-ids exist, because a wrong password for a cheap record returns sooner \
             than a lookup for a user that does not exist. Re-hash the file with one set \
             of parameters.",
            path.display(),
            hash.profile().describe(),
            profile.describe(),
        )),
        Some(_) => Ok(()),
    }
}

/// Reject a bcrypt file under a password ceiling bcrypt cannot honour.
///
/// `reference` is a record the file actually holds, not the miss-path hash:
/// the hash for an empty file is a synthesized bcrypt one, and reading the
/// ceiling off it refused an emptied argon2 directory -- the revocation reload
/// -- with a message naming bcrypt records it does not contain. A file with no
/// records constrains the ceiling not at all, and the first record a later
/// reload admits re-runs this check.
///
/// # Errors
///
/// A bcrypt file under a ceiling above bcrypt's truncation point, which the
/// verifier would admit at load and then always reject.
pub fn check_password_ceiling(
    reference: Option<&ParsedHash>,
    max_password_bytes: Option<usize>,
    path: &Path,
) -> Result<(), String> {
    use super::verifier::BCRYPT_TRUNCATION_BYTES;

    if let Some(CostProfile::Bcrypt { .. }) = reference.map(ParsedHash::profile)
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
            path.display(),
        ));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Construction and accessors
// -----------------------------------------------------------------------------

/// The floor hash for an empty directory, minted once and then reused.
///
/// Minting is a full bcrypt hash, so a reload that finds the file still empty
/// reuses the first one rather than paying again.
fn mint_floor_hash(
    path: &Path,
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

/// Build an index from a source, selecting the miss-path hash.
///
/// Any record in the file costs what every other one does, so reusing one of
/// them makes a miss cost exactly what a hit costs -- by construction rather
/// than by estimate. The synthesized hash is for a file with no records at
/// all, which otherwise answers in nanoseconds and is distinguishable from a
/// populated one by timing alone.
fn build_index(
    source: &dyn IndexSource,
    max_password_bytes: Option<usize>,
    empty: &OnceLock<ParsedHash>,
    floor_mints: &AtomicU64,
) -> Result<Index, String> {
    let users = source.read(max_password_bytes)?;
    // `values().next()` is a `HashMap` order, which is neither the file's
    // order nor stable across processes -- and that is fine here, not a
    // latent bug. The source has already refused any file whose records
    // differ in cost, so every candidate carries the same `CostProfile` and
    // the choice cannot change what a miss costs. If the uniformity rule were
    // ever relaxed, this line would become load-bearing and would have to
    // pick deliberately.
    let dummy = match users.values().next() {
        Some(entry) => entry.hash.clone(),
        None => mint_floor_hash(source.path(), empty, floor_mints)?,
    };
    Ok(Index { users, dummy })
}

impl FileBackend {
    /// Read the file once and build the index.
    ///
    /// `max_password_bytes` is the resolver's credential ceiling, when it
    /// enforces one. It is passed to the source on this load and on every
    /// reload rather than checked once here, because only a load that reads
    /// the file knows its scheme.
    ///
    /// # Errors
    ///
    /// Invalid timers or capacity, or whatever the source rejects.
    pub fn new(
        source: Box<dyn IndexSource>,
        max_password_bytes: Option<usize>,
    ) -> Result<Self, String> {
        validate_timers(
            source.refresh_secs(),
            source.max_staleness_secs(),
            source.max_concurrent_verifications(),
        )?;
        let empty = OnceLock::new();
        let floor_mints = AtomicU64::new(0);
        let index = build_index(source.as_ref(), max_password_bytes, &empty, &floor_mints)?;
        let first_attempt = source.refresh_secs().saturating_mul(1000);
        let permits = source.max_concurrent_verifications();
        Ok(Self {
            state: Arc::new(ReloadState {
                empty,
                floor_mints,
                index: ArcSwap::from_pointee(index),
                loaded_at_ms: AtomicU64::new(0),
                max_password_bytes,
                next_attempt_ms: AtomicU64::new(first_attempt),
                peak_concurrent_reloads: AtomicU64::new(0),
                publishing: std::sync::Mutex::new(()),
                reload_attempts: AtomicU64::new(0),
                reloads_in_flight: AtomicU64::new(0),
                source,
                started: Instant::now(),
            }),
            verifications: Arc::new(tokio::sync::Semaphore::new(permits)),
            dummy_runs: AtomicU64::new(0),
        })
    }

    /// How many users the running index holds.
    pub fn len(&self) -> usize {
        self.state.index.load().len()
    }

    /// Whether the running index holds no users.
    pub fn is_empty(&self) -> bool {
        self.state.index.load().is_empty()
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
        self.state.index.load().miss_cost_profile()
    }

    /// The path this backend reads.
    pub fn path(&self) -> PathBuf {
        self.state.source.path().to_path_buf()
    }

    /// Reload the file, retaining the previous index on failure.
    ///
    /// Blocking and I/O-bound: call it from a blocking context, or let the
    /// refresh interval drive it from a lookup, which runs it off the async
    /// worker.
    ///
    /// # Errors
    ///
    /// Whatever made the read or the parse fail. The index is unchanged either
    /// way.
    pub fn reload(&self) -> Result<(), String> {
        self.state.reload()
    }

    /// Look up a normalised user-id, refreshing the index when it is due.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::Stale`] past the staleness ceiling, where the loaded
    /// index is no longer an answer this backend stands behind.
    ///
    /// [`DirectoryError::Stale`]: super::directory::DirectoryError::Stale
    pub async fn lookup(&self, user_id: &str) -> Result<Option<UserRecord>, DirectoryError> {
        ReloadState::refresh_if_due(&self.state).await;

        // Past the ceiling the loaded index is not an answer this backend
        // stands behind, so it says it cannot answer. That denies as a
        // directory failure rather than as an unknown user, which is the
        // difference between an operator seeing an outage and seeing a wave of
        // bad passwords.
        if self.state.staleness() > Duration::from_secs(self.state.source.max_staleness_secs()) {
            return Err(DirectoryError::Stale);
        }

        let index = self.state.index.load();
        // The admitted hash travels into the record as it was admitted at
        // load, so this is a map probe and a clone -- O(1) in the user count,
        // whatever the file size. What carrying it forward saves is the
        // admission checks, not the decode: `verify_bytes` still decodes the
        // encoding on every call, equally for a hit and for the dummy.
        Ok(index.users.get(user_id).map(|entry| {
            UserRecord::new(
                entry.fields.clone(),
                StoredVerifier::Hash(entry.hash.clone()),
                entry.expires_at,
            )
        }))
    }

    /// Verify a credential against a record from this backend, or run the
    /// dummy for an unknown user.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::Saturated`] at the concurrency cap,
    /// [`DirectoryError::Malformed`] for a delegated verdict a file backend
    /// cannot carry, and [`DirectoryError::Unavailable`] when the blocking
    /// task does not complete.
    ///
    /// [`DirectoryError::Saturated`]: super::directory::DirectoryError::Saturated
    /// [`DirectoryError::Malformed`]: super::directory::DirectoryError::Malformed
    /// [`DirectoryError::Unavailable`]: super::directory::DirectoryError::Unavailable
    pub async fn verify(
        &self,
        record: Option<&UserRecord>,
        credential: &BasicCredential,
    ) -> Result<bool, DirectoryError> {
        // Acquired before either branch, so the found and not-found paths are
        // bounded identically. Denying rather than waiting: a queue here is an
        // unauthenticated CPU exhaustion path, and a caller cannot tell a
        // saturation denial from a wrong password anyway.
        //
        // Moved into the blocking closure below rather than held here, and
        // that placement is the whole protection. A permit dropped with this
        // future -- which happens on any client disconnect or upstream timeout
        // -- would be released while the `spawn_blocking` work it was bounding
        // carried on, because dropping a `JoinHandle` does not cancel a
        // blocking task. A caller that connects and disconnects could then
        // start unbounded concurrent verifications, limited only by the Tokio
        // blocking pool. Measured: a cap of 1 admitted 8 concurrent verifies
        // that way.
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
        // `spawn_blocking` await below -- milliseconds to seconds of hashing
        // -- which occupies one of the thread's debt slots for that whole span
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
        // returning it would authenticate a miss whenever the dummy's
        // throwaway password happened to match.
        Ok(outcome && !is_dummy)
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
    /// Whatever made the read or the parse fail.
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
        // schedule. A guard rather than a pair of calls, because `build_index`
        // below returns early with `?` on any unreadable or invalid file.
        let _in_flight = ReloadGuard::enter(&self.reloads_in_flight, &self.peak_concurrent_reloads);

        // The whole next index is built before anything is published, so a
        // read or parse that fails leaves the running index serving.
        let index = build_index(
            self.source.as_ref(),
            self.max_password_bytes,
            &self.empty,
            &self.floor_mints,
        )?;
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
        let interval = state.source.refresh_secs();
        let now = state.now_ms();
        let due = state.next_attempt_ms.load(Ordering::Acquire);
        if now < due {
            return;
        }

        // Claim the slot before reading. Losing the exchange means another
        // request is already reloading. Moving the marker forward even when
        // the read then fails is what keeps an unreadable file from being
        // retried on every request until it comes back.
        let next = now.saturating_add(interval.saturating_mul(1000));
        if state
            .next_attempt_ms
            .compare_exchange(due, next, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        state.reload_attempts.fetch_add(1, Ordering::Relaxed);

        // Off the async worker. A reload is a whole-file read, a parse of
        // every record, a wait on `publishing`, and -- for a file with no
        // records -- a bcrypt mint. None of that is bounded by the
        // verification semaphore, which guards only the verify step, so inline
        // it would stall every unrelated task on that worker for as long as
        // the file takes to read. A reload running longer than the interval
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
        //
        // The path is operator-supplied. The error is whatever the source
        // returned, and a source is required by `IndexSource::read` to keep
        // credential and hash material out of it -- this line is why that is
        // a contract rather than a courtesy: a reload error lands in operator
        // logs on every refresh interval, post-startup, while the plugin goes
        // on serving the previous index. A source that forwards a parser error
        // verbatim will leak whatever that parser quotes back.
        tracing::warn!(
            backend = state.source.kind(),
            path = %state.source.path().display(),
            %error,
            "the directory file could not be reloaded; the previous index is still serving",
        );
    }
}
