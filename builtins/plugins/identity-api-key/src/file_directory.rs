// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The hash indexed file backend.
//
// Records are authored by an operator, or written by something that projects
// them out of a platform. Either way the file holds digests, never plaintext,
// so a file that leaks does not hand over usable credentials.
//
// The refresh interval is the revocation window on this backend. A record
// removed from the file keeps authenticating until the next successful reload,
// and no cache on top of this would change that. It is named configuration for
// that reason.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use praxis_policy_core::host::HostServices;

use crate::directory::{DirectoryError, KeyDirectory, KeyRecord, PresentedKey};

/// The `kind:` string an operator writes under `directory:`.
pub const KIND: &str = "file";

/// Field names the backend consumes, which never reach a projected record.
///
/// `hash` is the lookup key. It is not plaintext, but it is what a hash indexed
/// directory matches on, and `subject.claim.<name>` is a legal assertion
/// source, so a record leaving it in the bag lets an operator render a
/// credential-equivalent into an upstream header.
pub const CONSUMED_FIELDS: &[&str] = &["hash", "expires_at"];

/// One authored record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    /// The credential's digest, as `sha256:<hex>`.
    pub hash: String,

    /// When this record stops being valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Everything else, which is what the `record_map` block projects.
    #[serde(flatten)]
    pub fields: HashMap<String, Value>,
}

/// The file as authored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordFile {
    /// The records.
    pub keys: Vec<FileRecord>,
}

/// How the file's digests were computed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IndexKind {
    /// `sha256:<hex>` of the credential as presented.
    #[default]
    Sha256,
}

/// The file backend's config block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDirectoryConfig {
    /// Where the records live.
    pub path: PathBuf,

    /// How the digests were computed.
    #[serde(default)]
    pub index: IndexKind,

    /// How stale the record set may get before a lookup reloads it.
    ///
    /// **This interval is the revocation window.** A record removed from the
    /// file keeps authenticating until the next successful reload, and nothing
    /// layered on top would change that.
    ///
    /// Reloading happens on the request path, when a lookup finds the set due,
    /// rather than on a timer. A spawned ticker binds to whichever runtime
    /// called `initialize`, and a host that drives async init on a short-lived
    /// runtime has the task cancelled before it ticks once: rotation then never
    /// happens and nothing says so. The JWT resolver reached the same
    /// conclusion for its key sets.
    ///
    /// Omitted means the set is read once at startup and never again, so
    /// revocation needs a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_secs: Option<u64>,

    /// How stale the record set may get before lookups start failing closed.
    ///
    /// Only meaningful alongside `refresh_secs`. A reload that fails leaves the
    /// previous records serving, which is right for a blip and wrong forever:
    /// without a ceiling, a file that stays unreadable turns the revocation
    /// window into no window at all, silently.
    ///
    /// Past the ceiling a lookup returns a directory failure, so requests deny
    /// as `auth.directory_unavailable` rather than as unknown credentials. An
    /// operator then sees an outage, which is what it is.
    ///
    /// Omitted means serve stale indefinitely and warn on every failed reload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_staleness_secs: Option<u64>,
}

impl FileDirectoryConfig {
    /// The staleness ceiling, when one is configured.
    pub fn max_staleness(&self) -> Option<Duration> {
        self.max_staleness_secs.map(Duration::from_secs)
    }

    /// Reject settings that cannot mean what they say.
    ///
    /// # Errors
    ///
    /// A ceiling below the refresh interval, which would deny before the first
    /// scheduled reload could ever run, or a ceiling with no interval to
    /// measure against.
    pub fn validate(&self) -> Result<(), String> {
        match (self.refresh_secs, self.max_staleness_secs) {
            (Some(refresh), Some(ceiling)) if ceiling < refresh => Err(format!(
                "`max_staleness_secs` ({ceiling}) is below `refresh_secs` ({refresh}), so lookups \
                 would fail closed before the first reload is even due"
            )),
            (None, Some(_)) => Err(
                "`max_staleness_secs` needs `refresh_secs`: with no reloading, the record set is \
                 as old as the process and the ceiling would deny every request once it passed"
                    .to_owned(),
            ),
            _ => Ok(()),
        }
    }
}

/// Records read from a file, indexed by digest.
#[derive(Debug)]
pub struct FileDirectory {
    config: FileDirectoryConfig,

    /// The current record set.
    ///
    /// Replaced wholesale on a successful reload and left alone on a failed
    /// one. A reload that emptied the index on a transient read error would
    /// turn a blip into a total authentication outage, and the previous records
    /// are still the best answer available.
    records: ArcSwap<HashMap<String, KeyRecord>>,

    /// The clock both timers below are read against.
    ///
    /// Monotonic, so a wall-clock adjustment cannot make the record set look
    /// fresh when it is stale, or expire a ceiling that has not passed.
    started: Instant,

    /// When the next reload becomes due, in milliseconds since `started`.
    ///
    /// Claimed by one lookup at a time. Whoever moves it forward does the read;
    /// everyone else answers from the index already loaded, so a burst of
    /// requests costs one file read rather than one each.
    next_attempt_ms: AtomicU64,

    /// When the records last loaded successfully, in milliseconds since
    /// `started`. What the staleness ceiling measures.
    loaded_at_ms: AtomicU64,
}

/// Read and index the file named by `config`.
///
/// Free rather than a method so a reload can build the whole next index before
/// anything is published, which is what makes a failed reload leave the running
/// one untouched.
fn read_index(config: &FileDirectoryConfig) -> Result<HashMap<String, KeyRecord>, String> {
    let text = std::fs::read_to_string(&config.path)
        .map_err(|e| format!("reading {}: {e}", config.path.display()))?;
    let file: RecordFile = serde_yaml::from_str(&text)
        .map_err(|e| format!("parsing {}: {e}", config.path.display()))?;

    let mut index = HashMap::with_capacity(file.keys.len());
    for (position, record) in file.keys.into_iter().enumerate() {
        let digest = normalize_digest(&record.hash, config.index)
            .map_err(|e| format!("{} record {position}: {e}", config.path.display()))?;
        // Two records for one credential have no coherent answer, and picking
        // either silently would hand one caller the other's identity.
        if index.contains_key(&digest) {
            return Err(format!(
                "{} record {position}: a second record carries the same hash",
                config.path.display()
            ));
        }
        index.insert(
            digest,
            KeyRecord {
                fields: record.fields,
                expires_at: record.expires_at,
            },
        );
    }
    Ok(index)
}

/// Check an authored digest and reduce it to the form lookups compare.
///
/// Hex is lowercased so a file written by hand matches one written by a tool.
fn normalize_digest(authored: &str, index: IndexKind) -> Result<String, String> {
    let (algorithm, hex) = authored
        .split_once(':')
        .ok_or_else(|| "hash has no `<algorithm>:` prefix".to_owned())?;
    let expected = match index {
        IndexKind::Sha256 => "sha256",
    };
    if !algorithm.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "hash algorithm does not match the configured '{expected}' index"
        ));
    }
    if hex.len() != SHA256_HEX_LEN || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("hash is not {SHA256_HEX_LEN} hex characters"));
    }
    Ok(format!("{expected}:{}", hex.to_ascii_lowercase()))
}

/// A SHA-256 digest, hex encoded.
const SHA256_HEX_LEN: usize = 64;

impl FileDirectory {
    /// Read the file once and build the index.
    ///
    /// # Errors
    ///
    /// The file is unreadable, is not the expected shape, or holds a digest
    /// that does not parse. A bad record set fails here rather than denying
    /// every request at runtime, which reads as an outage instead of the
    /// configuration mistake it is.
    pub fn new(config: FileDirectoryConfig) -> Result<Self, String> {
        config.validate()?;
        let index = read_index(&config)?;
        let started = Instant::now();
        let first_attempt = config
            .refresh_secs
            .map_or(u64::MAX, |secs| secs.saturating_mul(1000));
        Ok(Self {
            config,
            records: ArcSwap::from_pointee(index),
            started,
            next_attempt_ms: AtomicU64::new(first_attempt),
            loaded_at_ms: AtomicU64::new(0),
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

    /// Reload if the record set is due, at most once per interval.
    ///
    /// Blocking, on the request path, and deliberately so. The read is of a
    /// local file and happens once per `refresh_secs` rather than once per
    /// request, so the cost lands on one caller per interval. The alternative
    /// is a spawned task, and a spawned task does not survive every host: see
    /// `refresh_secs`.
    fn refresh_if_due(&self) {
        let Some(interval) = self.config.refresh_secs else {
            return;
        };
        let now = self.now_ms();
        let due = self.next_attempt_ms.load(Ordering::Acquire);
        if now < due {
            return;
        }

        // Claim the slot before reading. Losing the exchange means another
        // request is already reloading. Moving the marker forward even when the
        // read then fails is what keeps an unreadable file from being retried on
        // every request until it comes back.
        let next = now.saturating_add(interval.saturating_mul(1000));
        if self
            .next_attempt_ms
            .compare_exchange(due, next, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        if let Err(error) = self.reload() {
            tracing::warn!(
                path = %self.config.path.display(),
                %error,
                "api key record file could not be reloaded; the previous records are still serving",
            );
        }
    }

    /// How stale the loaded records are.
    fn staleness(&self) -> Duration {
        let loaded = self.loaded_at_ms.load(Ordering::Acquire);
        Duration::from_millis(self.now_ms().saturating_sub(loaded))
    }

    /// How many records the running index holds.
    pub fn len(&self) -> usize {
        self.records.load().len()
    }

    /// Whether the running index holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Re-read the file, keeping the previous records if it fails.
    ///
    /// # Errors
    ///
    /// Whatever made the read or the parse fail. The caller signals it; the
    /// index is unchanged either way.
    pub fn reload(&self) -> Result<(), String> {
        // The whole next index is built before anything is published, so a
        // read or parse that fails leaves the running records serving. Emptying
        // the index on a transient error would turn a blip into an
        // authentication outage, and the records already loaded are still the
        // best answer available.
        let index = read_index(&self.config)?;
        // Records first, then the timestamp, and not the other way round. The
        // two are not published together, so a lookup can land between them:
        // this order shows it new records under an old timestamp, which reads
        // as stale and denies. Stamping the time first would show old records
        // under a fresh one, which is a staleness ceiling that passes while
        // serving exactly what it exists to stop serving.
        self.records.store(Arc::new(index));
        self.loaded_at_ms.store(self.now_ms(), Ordering::Release);
        Ok(())
    }

    /// The digest of a presented credential, in the file's index format.
    ///
    /// The index is keyed by digest, so a lookup is one hash and one map probe
    /// whatever the record count. That is also why no constant-time compare
    /// appears here: nothing walks the records comparing candidates, and the
    /// only value compared is a digest the caller would have to invert SHA-256
    /// to choose.
    fn digest(&self, presented: &PresentedKey) -> String {
        match self.config.index {
            IndexKind::Sha256 => {
                let digest = Sha256::digest(presented.as_bytes());
                let mut out = String::with_capacity("sha256:".len() + SHA256_HEX_LEN);
                out.push_str("sha256:");
                for byte in digest {
                    use std::fmt::Write as _;
                    // Writing to a String cannot fail.
                    let _ = write!(out, "{byte:02x}");
                }
                out
            },
        }
    }
}

#[async_trait::async_trait]
impl KeyDirectory for FileDirectory {
    /// The file index needs no egress, so `services` goes unread: a
    /// deployment on a records file must not be made to declare
    /// `perform_http` for a call this backend never makes.
    async fn lookup(
        &self,
        presented: &PresentedKey,
        _services: &dyn HostServices,
    ) -> Result<Option<KeyRecord>, DirectoryError> {
        if presented.is_empty() {
            return Ok(None);
        }

        self.refresh_if_due();

        // Past the ceiling the loaded records are not an answer this backend
        // stands behind, so it says it cannot answer. That denies as a
        // directory failure rather than as an unknown credential, which is the
        // difference between an operator seeing an outage and seeing a wave of
        // bad keys.
        if let Some(ceiling) = self.config.max_staleness()
            && self.staleness() > ceiling
        {
            return Err(DirectoryError::Unavailable(format!(
                "the records at {} are {}s stale, past the {}s ceiling",
                self.config.path.display(),
                self.staleness().as_secs(),
                ceiling.as_secs(),
            )));
        }

        let digest = self.digest(presented);
        Ok(self.records.load().get(&digest).cloned())
    }

    fn kind(&self) -> &'static str {
        KIND
    }
}

/// The index a record set compiles to, so a caller can hold one without the
/// file behind it.
pub type RecordIndex = Arc<HashMap<String, KeyRecord>>;
