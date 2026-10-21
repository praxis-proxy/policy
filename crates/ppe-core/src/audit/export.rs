// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Audit export: delivering finished audit records.
//
// A sink decides what a record looks like, including any fingerprint, chain
// link and signature. An exporter decides where the finished bytes go and
// writes them unchanged: a verifier recomputes over exactly the bytes the
// sink produced, so nothing here may re-encode, reorder or wrap them. The
// only thing an exporter adds is framing a consumer can strip without
// ambiguity, which for every exporter in this module is one newline per
// record.
//
// `export` is blocking. Callers run it off the async runtime, because a
// write to a full pipe or a slow disk blocks inside the call where an async
// timeout cannot cut it off.

//! Exporters that write finished audit records to stderr, stdout or a file.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::decision::DecisionLog;

/// Where a record sits in the engine's audit stream: the stamp the executor
/// assigns before a sink sees the verdict.
///
/// A consumer reads `stream_seq` per `(epoch, stream_id)` to find loss: the
/// sequence is dense, so a missing value is a record that existed and did
/// not arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditStamp {
    /// The executor's boot epoch. A restart or reload opens a new one.
    pub epoch: u64,
    /// The stream the record belongs to, for example `gw-1:decision`.
    pub stream_id: String,
    /// Dense position within `(epoch, stream_id)`, from 0.
    pub stream_seq: u64,
    /// Position across every stream the executor emits, decisions and
    /// effects together.
    pub emission_seq: u64,
}

impl AuditStamp {
    /// The stamp the executor put on `decisions`, or `None` when it was
    /// never stamped (no sink was attached when the verdict was emitted).
    #[must_use]
    pub fn from_decisions(decisions: &DecisionLog) -> Option<Self> {
        Some(Self {
            epoch: decisions.epoch()?,
            stream_id: decisions.stream_id()?.to_owned(),
            stream_seq: decisions.stream_seq()?,
            emission_seq: decisions.emission_seq()?,
        })
    }
}

/// One finished audit record, ready to export.
///
/// `bytes` is the record exactly as its sink produced it. Exporters never
/// change it. The other fields describe the record so an exporter or a
/// metric can route or count it without parsing the body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SerializedRecord {
    /// The record. For a JSON record, one compact JSON document.
    pub bytes: Bytes,
    /// The media type of `bytes`.
    pub content_type: &'static str,
    /// The executor's stream stamp, when the record renders a stamped event.
    pub stamp: Option<AuditStamp>,
    /// The record's own identifier, which a consumer deduplicates on when a
    /// record arrives through more than one exporter.
    pub uid: Option<String>,
}

impl SerializedRecord {
    /// A JSON record. `bytes` must be one compact JSON document.
    #[must_use]
    pub fn json(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            content_type: "application/json",
            stamp: None,
            uid: None,
        }
    }

    /// Attach the executor's stream stamp.
    #[must_use]
    pub fn with_stamp(mut self, stamp: Option<AuditStamp>) -> Self {
        self.stamp = stamp;
        self
    }

    /// Attach the record's identifier.
    #[must_use]
    pub fn with_uid(mut self, uid: Option<String>) -> Self {
        self.uid = uid;
        self
    }
}

/// Why an export failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// The destination could not be opened or written.
    #[error("audit exporter `{exporter}`: {source}")]
    Io {
        /// The exporter that failed.
        exporter: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// A record could not be framed without changing its bytes. Line framing
    /// needs records with no newline in them; compact JSON never has one.
    #[error("audit exporter `{exporter}`: {reason}")]
    Framing {
        /// The exporter that refused the record.
        exporter: String,
        /// What was wrong with the record.
        reason: String,
    },

    /// The exporter configuration is not usable.
    #[error("audit exporter: {0}")]
    Config(String),
}

/// Delivers finished audit records.
///
/// An exporter writes the bytes it is given and adds only framing a consumer
/// can strip without ambiguity. It never interprets, re-encodes or reorders
/// a record, because a verifier recomputes over exactly those bytes.
///
/// `export` blocks. Call it off the async runtime.
pub trait AuditExporter: Send + Sync + fmt::Debug {
    /// A short name for logs and errors, such as `stderr` or `file`.
    fn name(&self) -> &str;

    /// Write `batch` in order. Batch boundaries carry no meaning: a consumer
    /// cannot tell where one batch ended and the next began.
    ///
    /// # Errors
    ///
    /// The destination failed, or a record cannot be framed. Records before
    /// the failing one may already be written.
    fn export(&self, batch: &[SerializedRecord]) -> Result<(), ExportError>;

    /// Push anything buffered to the destination.
    ///
    /// # Errors
    ///
    /// The destination failed.
    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// When the file exporter asks the OS to make writes durable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsyncPolicy {
    /// Never. The OS flushes on its own schedule, so records written just
    /// before a power loss can be lost. A consumer sees that as missing
    /// trailing `stream_seq` values.
    #[default]
    Never,
    /// Once per `export` call, after the whole batch is written.
    Batch,
    /// After every record.
    Always,
}

/// A built-in exporter, as it appears in configuration.
///
/// ```yaml
/// exporters:
///   - { kind: file, path: /var/log/ppe/audit.ndjson, fsync: batch }
///   - { kind: stderr }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExporterConfig {
    /// One record per line to the process's stderr.
    Stderr,
    /// One record per line to the process's stdout.
    Stdout,
    /// One record per line, appended to a file.
    File {
        /// Absolute path. Created if missing, with owner-only permissions
        /// on Unix; never truncated.
        path: PathBuf,
        /// When to make writes durable.
        #[serde(default)]
        fsync: FsyncPolicy,
    },
}

impl ExporterConfig {
    /// Build the exporter this entry names.
    ///
    /// # Errors
    ///
    /// A `file` path that is not absolute, or a file that cannot be opened
    /// for appending.
    pub fn build(&self) -> Result<Arc<dyn AuditExporter>, ExportError> {
        Ok(match self {
            Self::Stderr => Arc::new(StderrExporter),
            Self::Stdout => Arc::new(StdoutExporter),
            Self::File { path, fsync } => Arc::new(FileExporter::open(path, *fsync)?),
        })
    }
}

/// Append each record and its newline to `buf`, refusing a record whose
/// bytes contain a newline: line framing could not carry it intact.
fn frame_line(
    exporter: &str,
    buf: &mut Vec<u8>,
    record: &SerializedRecord,
) -> Result<(), ExportError> {
    validate_lines(exporter, std::slice::from_ref(record))?;
    buf.extend_from_slice(&record.bytes);
    buf.push(b'\n');
    Ok(())
}

fn validate_lines(exporter: &str, batch: &[SerializedRecord]) -> Result<(), ExportError> {
    for record in batch {
        if record.bytes.contains(&b'\n') {
            return Err(ExportError::Framing {
                exporter: exporter.to_owned(),
                reason: "record contains a newline, so line framing would split it".to_owned(),
            });
        }
    }
    Ok(())
}

/// Frame the whole batch, then write it with one `write_all` under the
/// stream's lock, so records from concurrent exports never interleave.
fn write_lines(
    exporter: &str,
    out: &mut dyn io::Write,
    batch: &[SerializedRecord],
) -> Result<(), ExportError> {
    let mut buf = Vec::with_capacity(batch.iter().map(|r| r.bytes.len() + 1).sum());
    for record in batch {
        frame_line(exporter, &mut buf, record)?;
    }
    let io_err = |source| ExportError::Io {
        exporter: exporter.to_owned(),
        source,
    };
    out.write_all(&buf).map_err(io_err)?;
    out.flush().map_err(io_err)
}

/// One record per line to stderr.
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrExporter;

impl AuditExporter for StderrExporter {
    fn name(&self) -> &str {
        "stderr"
    }

    fn export(&self, batch: &[SerializedRecord]) -> Result<(), ExportError> {
        write_lines(self.name(), &mut io::stderr().lock(), batch)
    }
}

/// One record per line to stdout.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdoutExporter;

impl AuditExporter for StdoutExporter {
    fn name(&self) -> &str {
        "stdout"
    }

    fn export(&self, batch: &[SerializedRecord]) -> Result<(), ExportError> {
        write_lines(self.name(), &mut io::stdout().lock(), batch)
    }
}

/// One record per line, appended to a file.
///
/// The file is opened in append mode when the exporter is built, so a path
/// that cannot be written fails the configuration load rather than the first
/// verdict. The exporter never truncates or rotates it.
///
/// An external rotator is supported. On Unix, before each write the exporter
/// compares the file at `path` with the one it holds open, and reopens `path`
/// when it was renamed away, replaced or removed, so rename-based rotation
/// (logrotate's default `create` mode) needs no signal or restart. A record
/// written while the rename happens lands in the rotated file, so keep that
/// file uncompressed until the next cycle (`delaycompress`). Copy-and-truncate
/// rotation (`copytruncate`) loses whatever is written between the copy and
/// the truncate; the stream's `stream_seq` gap shows it, but prefer renaming.
pub struct FileExporter {
    path: PathBuf,
    fsync: FsyncPolicy,
    file: Mutex<FileState>,
}

struct FileState {
    file: File,
    /// File sync alone cannot make a newly opened pathname durable.
    parent_sync_pending: bool,
    /// Avoid one warning per record while inspection or reopening fails.
    rotation_warning: bool,
}

impl fmt::Debug for FileExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileExporter")
            .field("path", &self.path)
            .field("fsync", &self.fsync)
            .finish_non_exhaustive()
    }
}

impl FileExporter {
    /// Open `path` for appending, creating it if missing.
    ///
    /// # Errors
    ///
    /// `path` is not absolute, or the file cannot be opened for appending.
    pub fn open(path: &Path, fsync: FsyncPolicy) -> Result<Self, ExportError> {
        if !path.is_absolute() {
            return Err(ExportError::Config(format!(
                "file exporter path `{}` must be absolute",
                path.display()
            )));
        }
        let file = open_append(path).map_err(|source| ExportError::Io {
            exporter: format!("file:{}", path.display()),
            source,
        })?;
        Ok(Self {
            path: path.to_owned(),
            fsync,
            file: Mutex::new(FileState {
                file,
                parent_sync_pending: true,
                rotation_warning: false,
            }),
        })
    }

    fn io_err(&self, source: io::Error) -> ExportError {
        ExportError::Io {
            exporter: format!("file:{}", self.path.display()),
            source,
        }
    }

    fn sync_file_and_parent(&self, state: &mut FileState) -> Result<(), ExportError> {
        state.file.sync_data().map_err(|e| self.io_err(e))?;
        #[cfg(unix)]
        if state.parent_sync_pending {
            let parent = self.path.parent().unwrap_or_else(|| Path::new("/"));
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| self.io_err(e))?;
            state.parent_sync_pending = false;
        }
        #[cfg(not(unix))]
        {
            state.parent_sync_pending = false;
        }
        Ok(())
    }

    /// Reopen `path` if the file there is no longer the one `held` is
    /// writing to: a rotator renamed it away and created a new one, or
    /// removed it.
    ///
    /// Only a clear answer causes a reopen. If `path` cannot be inspected for
    /// another reason, or the reopen itself fails, the exporter keeps writing
    /// to the handle it holds: that file still exists, so the record is kept
    /// somewhere rather than dropped.
    #[cfg(unix)]
    fn follow_rotation(&self, state: &mut FileState) {
        use std::os::unix::fs::MetadataExt as _;
        let ours = match state.file.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                self.warn_rotation(state, &err, "could not inspect open audit file");
                return;
            },
        };
        match std::fs::metadata(&self.path) {
            Ok(current) if current.dev() == ours.dev() && current.ino() == ours.ino() => {
                state.rotation_warning = false;
            },
            Ok(_) => self.reopen(state),
            Err(err) if err.kind() == io::ErrorKind::NotFound => self.reopen(state),
            Err(err) => self.warn_rotation(state, &err, "could not inspect audit file path"),
        }
    }

    /// Without inode numbers there is no cheap way to tell a rotated file
    /// from the current one, so the handle is kept.
    #[cfg(not(unix))]
    fn follow_rotation(&self, _state: &mut FileState) {}

    #[cfg(unix)]
    fn warn_rotation(&self, state: &mut FileState, err: &io::Error, message: &str) {
        if !state.rotation_warning {
            tracing::warn!(path = %self.path.display(), error = %err, "{message}; writing to the open file");
            state.rotation_warning = true;
        }
    }

    #[cfg(unix)]
    fn reopen(&self, state: &mut FileState) {
        match open_append(&self.path) {
            Ok(fresh) => {
                state.file = fresh;
                state.parent_sync_pending = true;
                state.rotation_warning = false;
            },
            Err(err) => self.warn_rotation(state, &err, "could not reopen rotated audit file"),
        }
    }
}

/// Open `path` for appending, creating it owner-only on Unix if missing.
///
/// Append mode makes every write land at the current end of the file, so a
/// rotator that truncates the file in place leaves no gap of zeros behind
/// the next record.
fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

impl AuditExporter for FileExporter {
    fn name(&self) -> &str {
        "file"
    }

    fn export(&self, batch: &[SerializedRecord]) -> Result<(), ExportError> {
        validate_lines(self.name(), batch)?;
        // A poisoned lock is recovered: the guarded state is the file handle,
        // and a panic mid-write cannot leave it in a state a later append
        // would make worse than the partial line already on disk.
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.follow_rotation(&mut file);
        if self.fsync == FsyncPolicy::Always {
            for record in batch {
                write_lines(self.name(), &mut file.file, std::slice::from_ref(record))?;
                self.sync_file_and_parent(&mut file)?;
            }
            return Ok(());
        }
        write_lines(self.name(), &mut file.file, batch)?;
        if self.fsync == FsyncPolicy::Batch {
            self.sync_file_and_parent(&mut file)?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.sync_file_and_parent(&mut file)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn record(json: &str) -> SerializedRecord {
        SerializedRecord::json(json.as_bytes().to_vec())
    }

    /// A directory nothing else is using, removed when the guard drops.
    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_path(name: &str) -> (TempDir, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ppe-audit-export-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        (TempDir(dir), path)
    }

    #[test]
    fn file_exporter_appends_one_line_per_record_unchanged() {
        let (_dir, path) = temp_path("audit.ndjson");
        let exporter = FileExporter::open(&path, FsyncPolicy::Batch).unwrap();
        exporter
            .export(&[record(r#"{"a":1}"#), record(r#"{"b":"x y"}"#)])
            .unwrap();
        exporter.export(&[record(r#"{"c":0.1}"#)]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"a\":1}\n{\"b\":\"x y\"}\n{\"c\":0.1}\n"
        );
    }

    #[test]
    fn file_exporter_never_truncates_an_existing_file() {
        let (_dir, path) = temp_path("audit.ndjson");
        std::fs::write(&path, "{\"old\":true}\n").unwrap();
        FileExporter::open(&path, FsyncPolicy::Never)
            .unwrap()
            .export(&[record(r#"{"new":true}"#)])
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"old\":true}\n{\"new\":true}\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_exporter_creates_an_owner_only_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path) = temp_path("audit.ndjson");
        FileExporter::open(&path, FsyncPolicy::Never).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn file_exporter_follows_a_rename_rotation() {
        let (_dir, path) = temp_path("audit.ndjson");
        let rotated = path.with_extension("ndjson.1");
        let exporter = FileExporter::open(&path, FsyncPolicy::Never).unwrap();
        exporter.export(&[record(r#"{"n":1}"#)]).unwrap();

        std::fs::rename(&path, &rotated).unwrap();
        std::fs::File::create(&path).unwrap();
        exporter.export(&[record(r#"{"n":2}"#)]).unwrap();

        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "{\"n\":1}\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"n\":2}\n");
    }

    #[cfg(unix)]
    #[test]
    fn file_exporter_recreates_a_removed_file_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path) = temp_path("audit.ndjson");
        let exporter = FileExporter::open(&path, FsyncPolicy::Never).unwrap();
        exporter.export(&[record(r#"{"n":1}"#)]).unwrap();

        std::fs::remove_file(&path).unwrap();
        exporter.export(&[record(r#"{"n":2}"#)]).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"n\":2}\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// `copytruncate` keeps the inode, so there is nothing to reopen; append
    /// mode puts the next record at offset 0 rather than after a run of
    /// zeros where the old content was.
    #[test]
    fn file_exporter_writes_cleanly_after_a_truncation() {
        let (_dir, path) = temp_path("audit.ndjson");
        let exporter = FileExporter::open(&path, FsyncPolicy::Never).unwrap();
        exporter.export(&[record(r#"{"n":1}"#)]).unwrap();

        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        exporter.export(&[record(r#"{"n":2}"#)]).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"n\":2}\n");
    }

    #[test]
    fn every_kind_builds_and_names_itself() {
        let (_dir, path) = temp_path("audit.ndjson");
        let names: Vec<String> = [
            ExporterConfig::Stderr,
            ExporterConfig::Stdout,
            ExporterConfig::File {
                path,
                fsync: FsyncPolicy::Never,
            },
        ]
        .iter()
        .map(|cfg| cfg.build().unwrap().name().to_owned())
        .collect();
        assert_eq!(names, ["stderr", "stdout", "file"]);
    }

    #[test]
    fn stream_exporters_write_and_refuse_a_newline() {
        let exporters: [&dyn AuditExporter; 2] = [&StderrExporter, &StdoutExporter];
        for exporter in exporters {
            exporter.export(&[record("{}")]).unwrap();
            exporter.flush().unwrap();
            let err = exporter.export(&[record("{\n}")]).unwrap_err();
            assert!(err.to_string().contains(exporter.name()), "{err}");
        }
    }

    /// A destination that fails partway reports which exporter failed.
    #[test]
    fn a_failing_write_is_an_io_error_naming_the_exporter() {
        struct Broken;
        impl io::Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("disk on fire"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let err = write_lines("broken", &mut Broken, &[record("{}")]).unwrap_err();
        assert!(matches!(err, ExportError::Io { .. }), "{err}");
        assert!(err.to_string().contains("broken"), "{err}");
    }

    #[test]
    fn records_carry_their_metadata() {
        let stamp = AuditStamp {
            epoch: 1,
            stream_id: "gw-1:decision".to_owned(),
            stream_seq: 2,
            emission_seq: 3,
        };
        let rec = SerializedRecord::json(b"{}".to_vec())
            .with_stamp(Some(stamp.clone()))
            .with_uid(Some("uid-1".to_owned()));
        assert_eq!(rec.content_type, "application/json");
        assert_eq!(rec.stamp, Some(stamp));
        assert_eq!(rec.uid.as_deref(), Some("uid-1"));
    }

    #[test]
    fn file_exporter_rejects_a_relative_path() {
        let err = FileExporter::open(Path::new("audit.ndjson"), FsyncPolicy::Never).unwrap_err();
        assert!(matches!(err, ExportError::Config(_)), "{err}");
    }

    #[test]
    fn file_exporter_fails_at_open_when_the_directory_is_missing() {
        let (_dir, path) = temp_path("missing/audit.ndjson");
        let err = FileExporter::open(&path, FsyncPolicy::Never).unwrap_err();
        assert!(matches!(err, ExportError::Io { .. }), "{err}");
    }

    #[test]
    fn a_record_with_a_newline_is_refused_and_nothing_is_written() {
        let (_dir, path) = temp_path("audit.ndjson");
        let exporter = FileExporter::open(&path, FsyncPolicy::Never).unwrap();
        let err = exporter
            .export(&[record(r#"{"a":1}"#), record("{\"a\":\n1}")])
            .unwrap_err();
        assert!(matches!(err, ExportError::Framing { .. }), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn fsync_always_refuses_the_whole_batch_before_writing() {
        let (_dir, path) = temp_path("audit.ndjson");
        let exporter = FileExporter::open(&path, FsyncPolicy::Always).unwrap();
        let err = exporter
            .export(&[record(r#"{"a":1}"#), record("{\"b\":\n2}")])
            .unwrap_err();
        assert!(matches!(err, ExportError::Framing { .. }), "{err}");
        assert!(std::fs::read(&path).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn parent_directory_is_synced_after_open_and_reopen() {
        let (_dir, path) = temp_path("audit.ndjson");
        let rotated = path.with_extension("ndjson.1");
        let exporter = FileExporter::open(&path, FsyncPolicy::Never).unwrap();
        assert!(exporter.file.lock().unwrap().parent_sync_pending);

        exporter.export(&[record("{}")]).unwrap();
        assert!(exporter.file.lock().unwrap().parent_sync_pending);
        exporter.flush().unwrap();
        assert!(!exporter.file.lock().unwrap().parent_sync_pending);

        std::fs::rename(&path, rotated).unwrap();
        std::fs::File::create(&path).unwrap();
        let mut state = exporter.file.lock().unwrap();
        exporter.follow_rotation(&mut state);
        assert!(state.parent_sync_pending);
        drop(state);
        exporter.flush().unwrap();
        assert!(!exporter.file.lock().unwrap().parent_sync_pending);
    }

    #[test]
    fn fsync_always_writes_every_record() {
        let (_dir, path) = temp_path("audit.ndjson");
        let exporter = FileExporter::open(&path, FsyncPolicy::Always).unwrap();
        exporter.export(&[record("{}"), record("[]")]).unwrap();
        exporter.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}\n[]\n");
    }

    #[test]
    fn concurrent_exports_never_interleave_within_a_line() {
        let (_dir, path) = temp_path("audit.ndjson");
        let exporter = Arc::new(FileExporter::open(&path, FsyncPolicy::Never).unwrap());
        let line = format!("{{\"pad\":\"{}\"}}", "x".repeat(8192));
        std::thread::scope(|s| {
            for _ in 0..8 {
                let exporter = Arc::clone(&exporter);
                let line = line.clone();
                s.spawn(move || {
                    for _ in 0..25 {
                        exporter.export(&[record(&line)]).unwrap();
                    }
                });
            }
        });
        let written = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 200);
        assert!(lines.iter().all(|l| *l == line));
    }

    #[test]
    fn config_parses_each_kind_and_rejects_unknown_fields() {
        let parsed: Vec<ExporterConfig> = serde_yaml::from_str(
            "- { kind: stderr }\n- { kind: stdout }\n- { kind: file, path: /tmp/a.ndjson, fsync: always }\n",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ExporterConfig::Stderr,
                ExporterConfig::Stdout,
                ExporterConfig::File {
                    path: PathBuf::from("/tmp/a.ndjson"),
                    fsync: FsyncPolicy::Always,
                },
            ]
        );
        let err = serde_yaml::from_str::<ExporterConfig>("{ kind: file, path: /a, mode: 1 }")
            .unwrap_err()
            .to_string();
        assert!(err.contains("mode"), "{err}");
        let err = serde_yaml::from_str::<ExporterConfig>("{ kind: kafka }")
            .unwrap_err()
            .to_string();
        assert!(err.contains("kafka"), "{err}");
    }

    #[test]
    fn file_fsync_defaults_to_never() {
        let parsed: ExporterConfig = serde_yaml::from_str("{ kind: file, path: /a }").unwrap();
        assert_eq!(
            parsed,
            ExporterConfig::File {
                path: PathBuf::from("/a"),
                fsync: FsyncPolicy::Never,
            }
        );
    }

    #[test]
    fn stamp_comes_from_a_stamped_decision_log_only() {
        let mut log = DecisionLog::new();
        assert_eq!(AuditStamp::from_decisions(&log), None);
        log.set_stream(7, "gw-1:decision".to_owned(), 3, 9);
        assert_eq!(
            AuditStamp::from_decisions(&log),
            Some(AuditStamp {
                epoch: 7,
                stream_id: "gw-1:decision".to_owned(),
                stream_seq: 3,
                emission_seq: 9,
            })
        );
    }
}
