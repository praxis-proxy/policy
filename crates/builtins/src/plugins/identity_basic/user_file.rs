// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The username-indexed YAML backend: a verifier, the fields a policy is
// written against, and an optional expiry.
//
// This is what `.htpasswd` cannot express. That format carries a user-id and a
// hash and nothing else, so a deployment needing roles or teams has to project
// them from somewhere, and a deployment needing a credential that stops
// working on a date has nowhere to put it. This backend is the only one here
// with native expiry.
//
// The index, refresh, publish-ordering, staleness and verification-capacity
// machinery is shared with the `.htpasswd` backend through `file_backend`, so
// what this module owns is the record shape and the rules that shape implies.
//
// The file holds hashes, never plaintext, with the same consequence as
// `.htpasswd`: a leaked file does not hand over usable credentials, but it is
// an offline-crackable verifier, so it must not be world-readable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization as _;

use praxis_policy_core::host::HostServices;

use super::BasicCredential;
use super::directory::{CredentialDirectory, DirectoryError, UserRecord};
use super::file_backend::{
    Entry, FileBackend, IndexSource, check_password_ceiling, enforce_uniform_cost, validate_timers,
};
use super::htpasswd::{DEFAULT_MAX_CONCURRENT_VERIFICATIONS, HtpasswdLimits};
use super::verifier::{CostProfile, Limits, ParsedHash, parse_hash};

/// The `kind:` string an operator writes under `provider:`.
pub const KIND: &str = "user_file";

// -----------------------------------------------------------------------------
// The file as authored
// -----------------------------------------------------------------------------

/// One user's record, as authored.
///
/// Deliberately *not* `deny_unknown_fields`. The whole point of this backend
/// is that an operator can carry the attributes their policy is written
/// against, and those names are theirs to choose -- a record rejecting unknown
/// keys could carry only the three fields below, which is `.htpasswd` with
/// extra syntax. What is still caught at load is a missing required storage
/// field, an `expires_at` that does not parse, and a duplicate username.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserFileRecord {
    /// The index key, normalised at load the way an inbound user-id is.
    pub username: String,

    /// The stored hash this record verifies against.
    ///
    /// Named `password_hash` rather than `hash` so a file cannot read as
    /// though it carried a password.
    pub password_hash: String,

    /// When this record stops being valid.
    ///
    /// Typed, so a value that is not a timestamp fails at load rather than
    /// deserializing to `None` and silently meaning "never expires". R25 names
    /// that specific failure, and it is the one a `String` field would
    /// reintroduce.
    ///
    /// A present-but-null value is refused for the same reason. `expires_at:`
    /// with nothing after it, or an explicit `~`, reads to a human as "an
    /// expiry is set here" and to serde as `None`, which is the silent
    /// never-expires outcome spelled a second way. Omitting the key is the
    /// only way to say a record does not expire.
    #[serde(default, deserialize_with = "required_if_present")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Everything else, which is what the `record_map` block projects.
    ///
    /// The three storage fields above are named, so serde routes them there
    /// and they never land here. That is how this backend strips them: not a
    /// drop list applied after the fact, but a shape in which there is no path
    /// for a hash to reach the claims bag. A drop list would be a second
    /// mechanism that could disagree with the field names, and the thing it
    /// would be guarding -- `subject.claim.password_hash` rendering a verifier
    /// into an upstream header -- is worth closing structurally.
    #[serde(flatten)]
    pub fields: HashMap<String, Value>,
}

/// Accept a timestamp, refuse a null, and leave an absent key as `None`.
///
/// `#[serde(default)]` supplies the absent case, so this is only reached when
/// the key is present: a null there is an operator writing an expiry they did
/// not write, and treating it as "no expiry" is the failure R25 exists to
/// prevent.
///
/// # Errors
///
/// A null value, or anything that is not an RFC 3339 timestamp.
fn required_if_present<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    match Option::<DateTime<Utc>>::deserialize(deserializer)? {
        Some(at) => Ok(Some(at)),
        None => Err(D::Error::custom(
            "`expires_at` is present but empty; write a timestamp, or remove the key \
             entirely to mean the record does not expire",
        )),
    }
}

/// The file as authored.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserFile {
    /// The records.
    ///
    /// A strict envelope, unlike the records inside it: a top-level key this
    /// backend does not know is a mistake an operator wants to hear about,
    /// because the only thing a file at this level can carry is the record
    /// list. A misspelled `user:` would otherwise load as an empty directory
    /// that denies every request.
    pub users: Vec<UserFileRecord>,
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// How a YAML user directory is configured.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserFileConfig {
    /// Where the file lives.
    pub path: PathBuf,

    /// The required refresh interval, in seconds. At least one.
    ///
    /// This is the revocation window: a record removed from the file stays
    /// usable until the next successful reload.
    pub refresh_secs: u64,

    /// The required maximum index age, in seconds.
    ///
    /// Lookups fail closed after this ceiling, including when reloads keep
    /// failing.
    pub max_staleness_secs: u64,

    /// Parameter ceilings for hashes admitted at load.
    ///
    /// The same ceilings the `.htpasswd` backend applies, and the same type:
    /// the limits bound what the shared verifier will run, so a second spelling
    /// of them would be two places an operator could set a different bound on
    /// one verifier.
    #[serde(default)]
    pub limits: HtpasswdLimits,

    /// The maximum number of concurrent verifications.
    ///
    /// Requests beyond this limit are rejected rather than queued.
    #[serde(default = "default_max_concurrent_verifications")]
    pub max_concurrent_verifications: usize,
}

fn default_max_concurrent_verifications() -> usize {
    DEFAULT_MAX_CONCURRENT_VERIFICATIONS
}

impl UserFileConfig {
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

// -----------------------------------------------------------------------------
// Reading the file
// -----------------------------------------------------------------------------

/// Reads a YAML user file into admitted records.
#[derive(Debug)]
struct UserFileSource {
    config: UserFileConfig,
}

impl IndexSource for UserFileSource {
    fn read(&self, max_password_bytes: Option<usize>) -> Result<HashMap<String, Entry>, String> {
        let config = &self.config;
        let text = std::fs::read_to_string(&config.path)
            .map_err(|e| format!("reading {}: {e}", config.path.display()))?;
        // A malformed document, an unknown top-level key, a missing
        // `username` or `password_hash`, and an `expires_at` that is not a
        // timestamp all land here, at load, rather than denying requests later
        // as though the passwords were wrong.
        //
        // The error is forwarded only when it cannot carry record content.
        // `serde_yaml` names fields and keys in almost every message --
        // "missing field `password_hash`", "unknown field `user`",
        // "users[0].expires_at: input contains invalid characters" -- and that
        // is exactly what an operator needs. The one variant that quotes the
        // input back is `invalid type`, which a record written as a bare
        // scalar triggers: a pasted `.htpasswd` line, the mistake a migrating
        // operator makes, yields `invalid type: string "bob:$2b$..."` carrying
        // a stored hash. That string reaches the refresh path's
        // `tracing::warn!`, so a verifier would land in operator logs on every
        // reload while the plugin kept serving and nothing prompted anyone to
        // look. Blanket redaction was the first fix here and was wrong: it
        // also erased the field names, so a malformed `expires_at` reported
        // only a line and column. So the leaky variant is reduced to its
        // location and the rest pass through.
        let file: UserFile = serde_yaml::from_str(&text).map_err(|e| {
            let path = config.path.display();
            let detail = e.to_string();
            if detail.contains("invalid type") {
                return match e.location() {
                    Some(at) => format!(
                        "parsing {path}: a record at line {}, column {} is not a `username` / \
                         `password_hash` mapping; a `.htpasswd` line pasted into the list \
                         looks like this. The parser's own message is withheld because it \
                         quotes the offending text, which for this file is a stored hash",
                        at.line(),
                        at.column(),
                    ),
                    None => format!(
                        "parsing {path}: a record is not a `username` / `password_hash` \
                         mapping; the parser's own message is withheld because it quotes the \
                         offending text, which for this file is a stored hash"
                    ),
                };
            }
            format!("parsing {path}: {detail}")
        })?;
        let limits = Limits::from(config.limits);

        let mut users: HashMap<String, Entry> = HashMap::with_capacity(file.users.len());
        // Any record serves as the miss-path hash once uniformity is enforced.
        // `profile` carries the parameters every later record must match, with
        // the record that established them.
        let mut reference: Option<ParsedHash> = None;
        let mut profile: Option<(CostProfile, String)> = None;

        for (position, record) in file.users.into_iter().enumerate() {
            // Normalised identically to an inbound user-id, and *before* the
            // duplicate check below. Normalising after would let two
            // differently encoded spellings of one name collapse onto one key
            // silently, handing whichever landed second the other's identity.
            let normalised: String = record.username.nfc().collect();
            if normalised.is_empty() {
                return Err(format!(
                    "{} record {position}: an empty username",
                    config.path.display()
                ));
            }

            // The operator's own spelling of the name, for the messages below.
            // Indexed by position as well, because two records can carry the
            // same name and that is exactly the case being reported.
            let label = format!("record {position} (`{normalised}`)");

            // The hash error deliberately carries no hash material, so the
            // message names the record and the scheme problem and nothing
            // else.
            let hash = parse_hash(&record.password_hash, &limits)
                .map_err(|e| format!("{} {label}: {e}", config.path.display()))?;
            enforce_uniform_cost(&mut profile, &hash, &config.path, &label)?;

            // Uniform cost means any record serves as the miss-path hash, so
            // the first is kept and the rest need no comparison.
            if reference.is_none() {
                reference = Some(hash.clone());
            }

            // Two records for one user have no coherent answer, and picking
            // either silently would hand one caller the other's identity.
            if users.contains_key(&normalised) {
                return Err(format!(
                    "{} {label}: a second record carries the same username (after Unicode \
                     normalisation)",
                    config.path.display()
                ));
            }

            users.insert(
                normalised,
                Entry {
                    hash,
                    // `username`, `password_hash` and `expires_at` are typed
                    // fields on the record, so `flatten` never collected them
                    // and there is nothing to strip here. The resolver injects
                    // the verified user-id under its own name, so the username
                    // does not need to travel as a field either.
                    fields: record.fields,
                    expires_at: record.expires_at,
                },
            );
        }

        // The scheme is only knowable once the file has been read, so the
        // resolver's password ceiling is reconciled with it here, on every
        // load: a reload that replaces an argon2 file with a bcrypt one is
        // refused rather than published under a ceiling the verifier cannot
        // honour.
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

// -----------------------------------------------------------------------------
// The directory
// -----------------------------------------------------------------------------

/// Records read from a YAML user file, indexed by username.
#[derive(Debug)]
pub struct UserFileDirectory {
    backend: FileBackend,
}

impl UserFileDirectory {
    /// Open a YAML user directory with the supplied configuration.
    ///
    /// Accepts the same schemes the `.htpasswd` backend does -- bcrypt,
    /// argon2, sha256crypt and sha512crypt -- provided every record in the
    /// file shares one cost profile.
    ///
    /// Applies no password-length ceiling of its own. A resolver that enforces
    /// one should use [`with_password_ceiling`] so the ceiling is re-checked
    /// against the file's scheme on every reload.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, an unreadable or malformed
    /// file, a missing required storage field, an unparseable `expires_at`,
    /// duplicate usernames, mixed cost profiles, or refused hash parameters.
    ///
    /// [`with_password_ceiling`]: UserFileDirectory::with_password_ceiling
    pub fn new(config: UserFileConfig) -> Result<Self, String> {
        Self::build(config, None)
    }

    /// Open a YAML user directory that also honours a password ceiling.
    ///
    /// `max_password_bytes` is the resolver's credential ceiling. A bcrypt
    /// file is refused while it sits above bcrypt's truncation point, at this
    /// load and at every reload.
    ///
    /// # Errors
    ///
    /// Returns an error for anything [`new`] rejects, and for a bcrypt file
    /// under a ceiling above bcrypt's truncation point.
    ///
    /// [`new`]: UserFileDirectory::new
    pub fn with_password_ceiling(
        config: UserFileConfig,
        max_password_bytes: usize,
    ) -> Result<Self, String> {
        Self::build(config, Some(max_password_bytes))
    }

    fn build(config: UserFileConfig, max_password_bytes: Option<usize>) -> Result<Self, String> {
        let backend = FileBackend::new(Box::new(UserFileSource { config }), max_password_bytes)?;
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
    /// Returns an error if the file cannot be read or its records fail
    /// validation.
    pub fn reload(&self) -> Result<(), String> {
        self.backend.reload()
    }
}

#[async_trait::async_trait]
impl CredentialDirectory for UserFileDirectory {
    /// Look up a user in the file index without requiring host egress
    /// capabilities.
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
