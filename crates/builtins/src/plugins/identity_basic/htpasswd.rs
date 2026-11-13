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
// What is left here is the file format and nothing else. The index, refresh,
// publish-ordering, staleness and verification-capacity machinery lives in
// `file_backend`, which this module and the YAML backend share -- the
// extraction KTD8 deferred until a second file backend existed to generalise
// from. Where this backend diverges from the api-key sibling the extraction
// grew out of -- the staleness ceiling is required rather than optional, and
// the refresh interval has a one-second floor -- the divergence is in
// `file_backend::validate_timers`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use praxis_policy_core::host::HostServices;

use super::BasicCredential;
use super::directory::{CredentialDirectory, DirectoryError, UserRecord};
use super::file_backend::{
    Entry, FileBackend, IndexSource, check_password_ceiling, enforce_uniform_cost, validate_timers,
};
use super::verifier::{CostProfile, Limits, ParsedHash, parse_hash};

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

/// The shared default verification capacity.
///
/// Enough that a normal login burst does not deny, low enough that the worst
/// case is bounded: at bcrypt cost 12 (~250ms) this is a few seconds of queued
/// CPU, not an unbounded backlog.
pub(super) const DEFAULT_MAX_CONCURRENT_VERIFICATIONS: usize = 32;

fn default_max_concurrent_verifications() -> usize {
    DEFAULT_MAX_CONCURRENT_VERIFICATIONS
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
        validate_timers(
            self.refresh_secs,
            self.max_staleness_secs,
            self.max_concurrent_verifications,
        )
    }
}

/// Reads `.htpasswd` lines into admitted records.
#[derive(Debug)]
struct HtpasswdSource {
    config: HtpasswdConfig,
}

impl IndexSource for HtpasswdSource {
    fn read(&self, max_password_bytes: Option<usize>) -> Result<HashMap<String, Entry>, String> {
        let config = &self.config;
        let text = std::fs::read_to_string(&config.path)
            .map_err(|e| format!("reading {}: {e}", config.path.display()))?;
        let limits = Limits::from(config.limits);

        let mut users: HashMap<String, Entry> = HashMap::new();
        // Any record serves as the miss-path hash once uniformity is enforced.
        // `profile` carries the parameters every later record must match, with
        // the line that established them.
        let mut reference: Option<ParsedHash> = None;
        let mut profile: Option<(CostProfile, String)> = None;

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
            // duplicate check below. Normalising after would let two
            // differently encoded spellings of one name collapse onto one key
            // silently, handing whichever landed second the other's identity.
            let normalised: String = user_id.nfc().collect();

            // The hash error deliberately carries no hash material, so the
            // message names the line and the scheme problem and nothing else.
            let hash = parse_hash(stored, &limits)
                .map_err(|e| format!("{} line {line_number}: {e}", config.path.display()))?;
            enforce_uniform_cost(
                &mut profile,
                &hash,
                &config.path,
                &format!("line {line_number}"),
            )?;

            // Uniform cost means any record serves as the miss-path hash, so
            // the first is kept and the rest need no comparison.
            if reference.is_none() {
                reference = Some(hash.clone());
            }

            // Two records for one user have no coherent answer, and picking
            // either silently would hand one caller the other's identity.
            // Real `.htpasswd` files in the wild do contain duplicates, so
            // this may block a migration -- failing closed is the deliberate
            // choice, and the message says which line collided.
            if users.contains_key(&normalised) {
                return Err(format!(
                    "{} line {line_number}: a second record carries the same user-id (after \
                     Unicode normalisation)",
                    config.path.display()
                ));
            }
            // `.htpasswd` carries a user-id and a hash and nothing else, so
            // there is nothing to project and nothing to strip: the hash lives
            // in the verifier, never in `fields`. A deployment needing roles
            // or teams wants the YAML backend. No native expiry either -- the
            // resolver still enforces expiry, there is simply never one to
            // enforce here.
            users.insert(
                normalised,
                Entry {
                    hash,
                    fields: HashMap::new(),
                    expires_at: None,
                },
            );
        }

        // The scheme is only knowable once the file has been read, so the
        // resolver's password ceiling is reconciled with it here. Checked on
        // every load, which is what makes it hold across a reload: a resolver
        // that started on an argon2 file with a ceiling above bcrypt's
        // truncation point would otherwise publish a bcrypt file and then deny
        // every password longer than 72 bytes as though it were simply wrong.
        check_password_ceiling(reference.as_ref(), max_password_bytes, &config.path)?;

        Ok(users)
    }

    fn path(&self) -> &Path {
        &self.config.path
    }

    fn refresh_secs(&self) -> u64 {
        self.config.refresh_secs
    }

    fn max_staleness_secs(&self) -> u64 {
        self.config.max_staleness_secs
    }

    fn max_concurrent_verifications(&self) -> usize {
        self.config.max_concurrent_verifications
    }

    fn kind(&self) -> &'static str {
        KIND
    }
}

/// Records read from a `.htpasswd` file, indexed by user-id.
#[derive(Debug)]
pub struct HtpasswdDirectory {
    backend: FileBackend,
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
        let backend = FileBackend::new(Box::new(HtpasswdSource { config }), max_password_bytes)?;
        Ok(Self { backend })
    }

    /// How many users the running index holds.
    pub fn len(&self) -> usize {
        self.backend.len()
    }

    /// Whether the running index holds no users.
    pub fn is_empty(&self) -> bool {
        self.backend.is_empty()
    }

    /// The number of dummy verification attempts, for regression tests.
    pub fn dummy_runs(&self) -> u64 {
        self.backend.dummy_runs()
    }

    /// The most reloads ever in flight at once, for regression tests.
    pub fn peak_concurrent_reloads(&self) -> u64 {
        self.backend.peak_concurrent_reloads()
    }

    /// How many times the empty-directory floor hash was minted, for the tests.
    pub fn floor_mints(&self) -> u64 {
        self.backend.floor_mints()
    }

    /// The number of refresh-path file-read attempts, for regression tests.
    pub fn reload_attempts(&self) -> u64 {
        self.backend.reload_attempts()
    }

    /// The work factor the miss path currently runs at, for the tests.
    pub fn miss_cost_profile(&self) -> CostProfile {
        self.backend.miss_cost_profile()
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
        self.backend.reload()
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
        self.backend.lookup(user_id).await
    }

    async fn verify(
        &self,
        record: Option<&UserRecord>,
        credential: &BasicCredential,
        _services: &dyn HostServices,
    ) -> Result<bool, DirectoryError> {
        self.backend.verify(record, credential).await
    }

    fn kind(&self) -> &'static str {
        KIND
    }
}
