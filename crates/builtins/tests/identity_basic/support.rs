// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Fixtures the cases share: building a credential location gate and driving
//! the RFC 7617 decode step over a header value.

use praxis_policy_builtins::plugins::identity_basic::credential::{
    BasicCredential, CredentialLocation, DecodeError, decode_basic,
};
use praxis_policy_core::extensions::raw_credentials::Credential;
use praxis_policy_core::identity::credential::ExtractionError;

/// The default ceiling the cases use when they are not exercising R26.
pub const CEILING: usize = 255;

/// An `Authorization: Basic` gate, as the plugin configures one.
pub fn gate() -> CredentialLocation {
    CredentialLocation::new(
        Credential::Header {
            name: "Authorization".to_owned(),
        },
        Some("Basic ".to_owned()),
    )
}

/// Which phase rejected a header, and with which exact reason.
///
/// Typed rather than a formatted string. A string let every rejection assert
/// the same way, so a regression returning `NotBase64` where
/// `ControlCharacter` belonged still passed — verified by mutating the source
/// and watching the suite stay green. It also made `Empty` (the extraction
/// phase) indistinguishable from `EmptyHalf` (the decode phase) under a
/// `contains` check, which is exactly the confusion these two phases must not
/// have.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The shared gate refused the header before decoding began.
    Extraction(ExtractionError),

    /// The gate produced a payload and the RFC 7617 decode refused it.
    Decode(DecodeError),
}

impl Failure {
    /// Whether this is a decode-phase rejection of any kind.
    ///
    /// For the handful of cases whose point is the phase rather than the
    /// variant — a decline must not read as a denial. A case asserting *which*
    /// rejection occurred matches on [`Failure::Decode`] directly instead.
    pub fn is_decode(&self) -> bool {
        matches!(self, Self::Decode(_))
    }
}

/// Run the gate and the decode step over one header value.
///
/// Mirrors the resolver's own order: extract, then decode. Returns the
/// extraction error as a string so a case can assert on which phase failed
/// without this helper needing a third error type.
pub fn extract_and_decode(header: &str) -> Result<BasicCredential, Failure> {
    extract_and_decode_with(header, CEILING, CEILING)
}

/// As [`extract_and_decode`], with explicit length ceilings for R26.
pub fn extract_and_decode_with(
    header: &str,
    max_user_id: usize,
    max_password: usize,
) -> Result<BasicCredential, Failure> {
    let location = gate();
    let headers =
        std::collections::HashMap::from([("authorization".to_owned(), header.to_owned())]);
    let raw = location.raw(&headers, None).map_err(Failure::Extraction)?;
    decode_basic(raw, max_user_id, max_password).map_err(Failure::Decode)
}

/// Base64 of a raw credential, for building the malformed cases.
pub fn b64(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// The error from decoding a header that must not decode.
///
/// A separate helper rather than `expect_err` on the result, because
/// `BasicCredential` deliberately implements no `Debug` — the type exists to
/// make a credential unprintable, and a test must not be the reason a `Debug`
/// impl gets added. So the Ok case is discarded here and reported as a plain
/// panic message carrying nothing from the credential.
pub fn decode_failure(header: &str) -> Failure {
    match extract_and_decode(header) {
        Ok(_) => panic!("expected this header to be rejected, but it decoded"),
        Err(e) => e,
    }
}

/// As [`decode_failure`], with explicit length ceilings for R26.
pub fn decode_failure_with(header: &str, max_user_id: usize, max_password: usize) -> Failure {
    match extract_and_decode_with(header, max_user_id, max_password) {
        Ok(_) => panic!("expected this header to be rejected, but it decoded"),
        Err(e) => e,
    }
}

/// Verify a password against a parsed stored hash.
///
/// A thin wrapper so a case can pass plain bytes: the production path takes a
/// `Password`, whose constructor is private to the plugin, and the only public
/// way to build one is to decode a credential. This routes through that same
/// path rather than widening the plugin's API for the tests.
pub fn verify_password(
    hash: &praxis_policy_builtins::plugins::identity_basic::verifier::ParsedHash,
    password: &[u8],
) -> bool {
    let encoded = b64(&[b"u:".as_slice(), password].concat());
    let credential = extract_and_decode_with(
        &format!("Basic {encoded}"),
        CEILING,
        // The R26 case deliberately presents a password longer than the
        // default ceiling, so the decode step must not be what rejects it --
        // the verifier's own truncation guard is what is under test.
        usize::MAX,
    )
    .expect("the fixture credential decodes");
    praxis_policy_builtins::plugins::identity_basic::verifier::verify_credential(hash, &credential)
}

/// A `.htpasswd` file written to a temporary path.
///
/// Removed when the guard drops, so a failing case does not leave a file with
/// password hashes in `/tmp` for the next run to pick up. A counter rather
/// than a temp-file crate: one dependency for a handful of tests is not worth
/// it, and the name only has to be unique in-process.
pub struct HtpasswdFile {
    path: std::path::PathBuf,
}

impl HtpasswdFile {
    /// Write `contents` to a uniquely named file.
    pub fn write(contents: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ppe-basic-{}-{n}.htpasswd", std::process::id()));
        std::fs::write(&path, contents).expect("the fixture file is writable");
        Self { path }
    }

    /// The path, as the `provider.path` config value wants it.
    pub fn path(&self) -> &str {
        self.path.to_str().expect("the temp path is utf-8")
    }

    /// Replace the contents, which is what a reload reads.
    ///
    /// Written to a sibling and renamed over the target, so a reader never
    /// sees a half-written file. `std::fs::write` truncates first, which
    /// leaves a window where a concurrent reload parses a prefix, and a test
    /// that raced that window would be measuring the fixture rather than the
    /// code. It is also how anything writing these files in production should
    /// do it.
    pub fn rewrite(&self, contents: &str) {
        let staging = self.path.with_extension("staging");
        std::fs::write(&staging, contents).expect("the fixture file is writable");
        std::fs::rename(&staging, &self.path).expect("the rename lands");
    }

    /// Delete the file while the guard is still alive, for the
    /// unreadable-path and failed-reload cases.
    pub fn unlink(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for HtpasswdFile {
    fn drop(&mut self) {
        // Best effort: a case that already unlinked the file is not an error,
        // and a failure here must not mask the assertion that was running.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A `HostServices` that offers nothing.
///
/// The file backend needs no egress, and saying so here is part of what the
/// tests assert: nothing on this path should make a deployment declare
/// `perform_http`.
pub fn services() -> praxis_policy_core::host::InitExtensions {
    praxis_policy_core::host::InitExtensions::new()
}

/// A backend config over a fixture path, with a coherent refresh and ceiling.
pub fn config_for(path: &str) -> praxis_policy_builtins::plugins::identity_basic::HtpasswdConfig {
    serde_yaml::from_str(&format!(
        "path: {path}\nrefresh_secs: 30\nmax_staleness_secs: 300\n"
    ))
    .expect("the backend config parses")
}

/// One `.htpasswd` line: a user-id and a freshly minted bcrypt hash.
///
/// Minted at test time rather than checked in, so no hash in this repo is a
/// verifier for a password anyone might reuse, and so the cost is explicit at
/// the call site -- several cases turn on which record is the most expensive.
pub fn bcrypt_line(user_id: &str, password: &str, cost: u32) -> String {
    let hash = bcrypt::hash(password, cost).expect("bcrypt mints at a legal cost");
    format!("{user_id}:{hash}")
}

/// The work factor a `.htpasswd` line's hash parses to.
pub fn work_factor_of(line: &str) -> praxis_policy_builtins::plugins::identity_basic::WorkFactor {
    let (_, stored) = line
        .split_once(':')
        .expect("the fixture line has a separator");
    praxis_policy_builtins::plugins::identity_basic::verifier::parse_hash(
        stored,
        &praxis_policy_builtins::plugins::identity_basic::Limits::default(),
    )
    .expect("the fixture hash parses")
    .work_factor()
}

/// A credential carrying `plaintext` as its password.
///
/// The password type's constructor is private to the plugin, which is
/// deliberate -- a password should only ever come from a decoded header. The
/// tests go through that same path rather than widening the API.
pub fn password(plaintext: &str) -> BasicCredential {
    let encoded = b64(format!("u:{plaintext}").as_bytes());
    extract_and_decode_with(&format!("Basic {encoded}"), CEILING, usize::MAX)
        .expect("the fixture credential decodes")
}
