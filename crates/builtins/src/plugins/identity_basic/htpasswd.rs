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
    Limits, ParsedHash, Scheme, WorkFactor, floor_hash, parse_hash, verify_bytes,
};

/// The `kind:` string an operator writes under `provider:`.
pub const KIND: &str = "htpasswd";

/// How a `.htpasswd` directory is configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtpasswdConfig {
    /// Where the file lives.
    pub path: PathBuf,

    /// How often to re-read it, in seconds.
    ///
    /// The revocation window, and **required**. An earlier shape made this
    /// optional and documented omission as "read once at startup and never
    /// again" -- but `validate()` then rejected `None` outright, so the
    /// documented behaviour was unreachable and the `Option` only encoded a
    /// state that could not load. A plain `u64` makes that unrepresentable
    /// instead of rejected at runtime.
    ///
    /// Zero means re-read on every lookup, which is coherent (and what the
    /// tests use) though rarely what a deployment wants.
    pub refresh_secs: u64,

    /// How stale the index may get before lookups fail closed, in seconds.
    ///
    /// **Required**, which is this backend's one deliberate divergence from the
    /// api-key file backend, where it is optional. The reason is the failure
    /// this bounds: a reload that keeps failing -- a syntax error introduced
    /// while deleting a user, a file replaced by a broken generator -- would
    /// otherwise keep serving the previous index forever, which makes a
    /// revocation silently not happen. Passwords are long-lived and reused, so
    /// "the revocation did not take and nobody was told" is a worse default
    /// than a visible outage. An operator who genuinely wants unbounded
    /// staleness sets a very large value and has said so.
    pub max_staleness_secs: u64,

    /// Ceilings a stored hash's parameters must sit under.
    ///
    /// A nested block rather than a flattened one. serde does not support
    /// `flatten` together with `deny_unknown_fields`, and while the current
    /// `yaml_serde` happens to reject an unknown key through a flattened
    /// field, that is incidental rather than guaranteed -- a serde or backend
    /// bump could start silently accepting `max_bcrypt_cst: 20`, leaving the
    /// real ceiling at its default while an operator believes a limit is in
    /// force. Nesting removes the reliance entirely and matches every other
    /// config struct here.
    #[serde(default)]
    pub limits: HtpasswdLimits,

    /// How many verifications may run at once.
    ///
    /// Beyond this, lookups deny rather than queueing. Every syntactically
    /// valid header costs a full hash verify -- including a miss, by design --
    /// so an unbounded queue here is an unauthenticated CPU and memory
    /// exhaustion path.
    #[serde(default = "default_max_concurrent_verifications")]
    pub max_concurrent_verifications: usize,
}

/// Parameter ceilings, as an operator writes them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

    /// Reject settings that cannot mean what they say.
    ///
    /// # Errors
    ///
    /// A ceiling below the refresh interval, which would deny before the first
    /// scheduled reload could run, or a zero concurrency cap, which would deny
    /// every request.
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

    /// The hash a miss is verified against, so a miss costs what a hit costs.
    ///
    /// This is the *heaviest record actually in the file*, reused rather than
    /// synthesized. An earlier version minted a fresh bcrypt hash at a cost
    /// derived from the worst work factor, which was wrong twice over: minting
    /// is itself expensive, and a work factor derived from argon2 parameters
    /// is an ordering key on a different scale from a bcrypt cost. Feeding one
    /// to `bcrypt::hash` made loading a single ordinary argon2 record take
    /// 7.9s, and a miss then cost far *more* than any hit -- reversing the
    /// very oracle KTD9 exists to close.
    ///
    /// Reusing a real record is strictly better: it costs nothing to obtain,
    /// it is exactly as expensive as the dearest hit by construction, and it
    /// stays correct across schemes without a conversion. A fresh floor-cost
    /// hash is minted only when the directory has no record reaching the
    /// floor, which is the empty-or-all-cheap case.
    ///
    /// Reselected on every load, because the heaviest record changes when the
    /// file does.
    dummy: ParsedHash,
}

/// Records read from a `.htpasswd` file, indexed by user-id.
#[derive(Debug)]
pub struct HtpasswdDirectory {
    config: HtpasswdConfig,

    /// The current index.
    ///
    /// Replaced wholesale on a successful reload and left alone on a failed
    /// one. A reload that emptied the index on a transient read error would
    /// turn a blip into a total authentication outage, and the records already
    /// loaded are still the best answer available.
    index: ArcSwap<Index>,

    /// The clock both timers below are read against.
    ///
    /// Monotonic, so a wall-clock adjustment cannot make the index look fresh
    /// when it is stale, or expire a ceiling that has not passed.
    started: Instant,

    /// When the next reload becomes due, in milliseconds since `started`.
    ///
    /// Claimed by one lookup at a time. Whoever moves it forward does the read;
    /// everyone else answers from the index already loaded, so a burst of
    /// requests costs one file read rather than one each.
    next_attempt_ms: AtomicU64,

    /// When the index last loaded successfully. What the ceiling measures.
    loaded_at_ms: AtomicU64,

    /// Permits for in-flight verifications, bounding CPU under load.
    verifications: Arc<tokio::sync::Semaphore>,

    /// The fallback miss-path hash, for an empty or all-cheap directory.
    ///
    /// Built once at construction. It does not depend on file content, and
    /// minting one is a cost-10 bcrypt hash -- tens of milliseconds that would
    /// otherwise land on whichever request claims the reload slot.
    floor: ParsedHash,

    /// How many file reads the refresh path has attempted, for the tests.
    ///
    /// Counts attempts rather than successes, because the CAS-claimed slot is
    /// what the burst case is asserting about: a thundering herd past the due
    /// time must cost one read, not one per request, whether or not the read
    /// then parses.
    reload_attempts: AtomicU64,

    /// How many dummy verifications have run, for the tests.
    ///
    /// A miss is by design indistinguishable in its output, so a test cannot
    /// observe the dummy through the result. Timing would be flaky in CI. A
    /// counter is the only honest assertion available, and it proves a dummy
    /// *ran* -- not that it cost the same, which the work-factor assertion
    /// covers separately.
    dummy_runs: AtomicU64,
}

/// Parse a `.htpasswd` file into an index.
///
/// Free rather than a method so a reload can build the whole next index before
/// anything is published, which is what makes a failed reload leave the running
/// one untouched.
///
/// Fully fallible by construction: no slicing, no unwrap, no panic on a
/// hostile line. A password file is operator-authored but also machine-written,
/// and a generator that emits one bad line must fail the load rather than
/// drop a user silently.
fn read_index(config: &HtpasswdConfig, floor: &ParsedHash) -> Result<Index, String> {
    let text = std::fs::read_to_string(&config.path)
        .map_err(|e| format!("reading {}: {e}", config.path.display()))?;
    let limits = Limits::from(config.limits);

    let mut users: HashMap<String, Entry> = HashMap::new();
    // The heaviest record seen, kept to serve as the miss-path hash, plus the
    // scheme every record must share for that comparison to mean anything.
    let mut heaviest: Option<ParsedHash> = None;
    let mut scheme: Option<(Scheme, usize)> = None;

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
        // One scheme per file. A `WorkFactor` orders records within a scheme
        // and is meaningless across them -- bcrypt cost is a CPU exponent,
        // argon2's dominant term is memory bandwidth -- so a mixed file has no
        // well-defined dearest record to serve as the miss-path hash. Picking
        // one anyway inverted the real cost by 28x in measurement (a
        // `m=4096,t=3` argon2 record scored above `bcrypt cost=12` while
        // verifying 28 times faster), which made a miss far cheaper than a hit
        // and re-opened the user-enumeration oracle KTD9 exists to close.
        //
        // Refused at load, naming both lines, because re-hashing onto one
        // scheme is a file-level decision only an operator can make. A
        // calibrated cross-scheme estimate was considered and rejected: the
        // ratio moves with memory bandwidth and core speed, so a constant here
        // would silently mis-rank on hardware it was not measured on.
        match scheme {
            None => scheme = Some((hash.scheme(), line_number)),
            Some((seen, first_line)) if seen != hash.scheme() => {
                return Err(format!(
                    "{} line {line_number}: this record uses {:?} but line {first_line} uses \
                     {seen:?}. One hash scheme per file: their cost parameters are not \
                     comparable, so a directory mixing them cannot make an unknown user cost \
                     the same as a known one -- which is what stops the file from revealing \
                     which usernames exist. Re-hash onto a single scheme.",
                    config.path.display(),
                    hash.scheme(),
                ));
            },
            Some(_) => {},
        }

        if heaviest
            .as_ref()
            .is_none_or(|h| hash.work_factor() > h.work_factor())
        {
            heaviest = Some(hash.clone());
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
    // work at load at all. Only an empty or all-cheap directory mints.
    // Within one scheme the dearest record is well defined, so it is reused as
    // the miss-path hash: exactly as expensive as the dearest hit, and free to
    // obtain. The floor hash is only the fallback for an empty or all-cheap
    // directory, and is built once in the constructor rather than minted here
    // -- `reload` runs from `refresh_if_due` on the request path, and a
    // cost-10 bcrypt mint would block an executor worker for tens of
    // milliseconds once per refresh interval. It does not depend on file
    // content, so there is nothing to recompute.
    let dummy = match heaviest {
        Some(hash) if hash.work_factor() >= WorkFactor::FLOOR => hash,
        _ => floor.clone(),
    };

    Ok(Index { users, dummy })
}

impl HtpasswdDirectory {
    /// Read the file once and build the index.
    ///
    /// # Errors
    ///
    /// The file is unreadable, holds a malformed line, carries a duplicate
    /// user-id, or holds a hash whose scheme or parameters this plugin
    /// refuses. A bad file fails here rather than denying every request at
    /// runtime, which reads as an outage instead of the configuration mistake
    /// it is.
    pub fn new(config: HtpasswdConfig) -> Result<Self, String> {
        config.validate()?;
        let floor = floor_hash(WorkFactor::FLOOR).map_err(|e| {
            format!(
                "{}: could not build the miss-path hash: {e}",
                config.path.display()
            )
        })?;
        let index = read_index(&config, &floor)?;
        let first_attempt = config.refresh_secs.saturating_mul(1000);
        let permits = config.max_concurrent_verifications;
        Ok(Self {
            config,
            floor,
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

    /// How many dummy verifications have run, for the tests.
    pub fn dummy_runs(&self) -> u64 {
        self.dummy_runs.load(Ordering::Relaxed)
    }

    /// How many file reads the refresh path has attempted, for the tests.
    pub fn reload_attempts(&self) -> u64 {
        self.reload_attempts.load(Ordering::Relaxed)
    }

    /// The work factor the miss path currently runs at, for the tests.
    pub fn miss_work_factor(&self) -> WorkFactor {
        self.index.load().dummy.work_factor()
    }

    /// Re-read the file, keeping the previous index if it fails.
    ///
    /// # Errors
    ///
    /// Whatever made the read or the parse fail. The caller signals it; the
    /// index is unchanged either way.
    pub fn reload(&self) -> Result<(), String> {
        // The whole next index is built before anything is published, so a read
        // or parse that fails leaves the running index serving.
        let index = read_index(&self.config, &self.floor)?;
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

    /// Reload if the index is due, at most once per interval.
    ///
    /// Blocking, on the request path, and deliberately so. The read is of a
    /// local file and happens once per `refresh_secs` rather than once per
    /// request, so the cost lands on one caller per interval. The alternative
    /// is a spawned task, and a spawned task does not survive every host.
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
    /// The file index needs no egress, so `services` goes unread: a deployment
    /// on a password file must not be made to declare `perform_http` for a call
    /// this backend never makes.
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
