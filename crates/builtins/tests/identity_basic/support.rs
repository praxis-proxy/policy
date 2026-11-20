// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities for Basic credential and directory cases.

use praxis_policy_builtins::plugins::identity_basic::ShaCryptVariant;
use praxis_policy_builtins::plugins::identity_basic::credential::{
    BasicCredential, CredentialLocation, DecodeError, decode_basic,
};
use praxis_policy_core::extensions::raw_credentials::Credential;
use praxis_policy_core::identity::credential::ExtractionError;

/// The default credential length ceiling for test utilities.
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
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The shared gate refused the header before decoding began.
    Extraction(ExtractionError),

    /// The gate produced a payload and the RFC 7617 decode refused it.
    Decode(DecodeError),
}

impl Failure {
    /// Whether this is a decode-phase rejection of any kind.
    pub fn is_decode(&self) -> bool {
        matches!(self, Self::Decode(_))
    }
}

/// Extract and decode a header, preserving the phase and reason of rejection.
pub fn extract_and_decode(header: &str) -> Result<BasicCredential, Failure> {
    extract_and_decode_with(header, CEILING, CEILING)
}

/// Extract and decode a header with explicit length ceilings.
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

/// An argon2 record at the given parameters, minted rather than checked in.
///
/// Minted because a checked-in PHC string can only be parsed: its digest
/// matches no password anyone knows, so it cannot prove a verify.
pub fn argon2_at(memory_kib: u32, time_cost: u32, password: &str) -> String {
    use argon2::PasswordHasher as _;

    let params = argon2::Params::new(memory_kib, time_cost, 1, None)
        .expect("argon2 accepts these parameters");
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_with_salt(password.as_bytes(), b"saltsaltsalt")
        .expect("argon2 mints with a legal salt")
        .to_string()
}

/// One `.htpasswd` line: a user-id and a freshly minted argon2 hash.
pub fn argon2_line(user_id: &str, password: &str, memory_kib: u32, time_cost: u32) -> String {
    format!("{user_id}:{}", argon2_at(memory_kib, time_cost, password))
}

/// A sha-crypt record at the given variant and rounds, minted rather than
/// checked in.
///
/// Minted for the same reason as the argon2 helper: a checked-in digest
/// matches no password anyone knows, so it cannot prove a verify.
pub fn sha_crypt_at(variant: ShaCryptVariant, rounds: u32, password: &str) -> String {
    use sha_crypt::PasswordHasher as _;

    let algorithm = match variant {
        ShaCryptVariant::Sha256 => sha_crypt::Algorithm::Sha256Crypt,
        ShaCryptVariant::Sha512 => sha_crypt::Algorithm::Sha512Crypt,
        _ => panic!("the fixture covers only the two sha-crypt variants"),
    };
    let params = sha_crypt::Params::new(rounds).expect("sha-crypt accepts these rounds");

    // Twelve raw bytes, not sixteen: the hasher base64-encodes whatever it is
    // given before hashing, so a 16-byte salt would land as a 22-character
    // field and exceed the format's 16-character cap. Twelve encodes to
    // exactly sixteen, which is the width every published `$5$`/`$6$` vector
    // carries.
    sha_crypt::ShaCrypt::new(algorithm, params)
        .hash_password_with_salt(password.as_bytes(), b"saltsaltsalt")
        .expect("sha-crypt mints with a legal salt")
        .to_string()
}

/// One `.htpasswd` line: a user-id and a freshly minted sha-crypt hash.
pub fn sha_crypt_line(
    user_id: &str,
    password: &str,
    variant: ShaCryptVariant,
    rounds: u32,
) -> String {
    format!("{user_id}:{}", sha_crypt_at(variant, rounds, password))
}

/// Base64 of a raw credential, for building the malformed cases.
pub fn b64(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// The error from decoding a header that must not decode.
pub fn decode_failure(header: &str) -> Failure {
    match extract_and_decode(header) {
        Ok(_) => panic!("expected this header to be rejected, but it decoded"),
        Err(e) => e,
    }
}

/// Return the rejection reason for a header with explicit length ceilings.
pub fn decode_failure_with(header: &str, max_user_id: usize, max_password: usize) -> Failure {
    match extract_and_decode_with(header, max_user_id, max_password) {
        Ok(_) => panic!("expected this header to be rejected, but it decoded"),
        Err(e) => e,
    }
}

/// Verify a password against a parsed stored hash.
pub fn verify_password(
    hash: &praxis_policy_builtins::plugins::identity_basic::verifier::ParsedHash,
    password: &[u8],
) -> bool {
    let encoded = b64(&[b"u:".as_slice(), password].concat());
    let credential = extract_and_decode_with(&format!("Basic {encoded}"), CEILING, usize::MAX)
        .expect("the fixture credential decodes");
    praxis_policy_builtins::plugins::identity_basic::verifier::verify_credential(hash, &credential)
}

/// A temporary `.htpasswd` file removed when its guard drops.
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

    /// Atomically replace the contents for reload tests.
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
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A `HostServices` that offers nothing.
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
pub fn bcrypt_line(user_id: &str, password: &str, cost: u32) -> String {
    let hash = bcrypt::hash(password, cost).expect("bcrypt mints at a legal cost");
    format!("{user_id}:{hash}")
}

/// The work factor a `.htpasswd` line's hash parses to.
pub fn cost_profile_of(line: &str) -> praxis_policy_builtins::plugins::identity_basic::CostProfile {
    let (_, stored) = line
        .split_once(':')
        .expect("the fixture line has a separator");
    praxis_policy_builtins::plugins::identity_basic::verifier::parse_hash(
        stored,
        &praxis_policy_builtins::plugins::identity_basic::Limits::default(),
    )
    .expect("the fixture hash parses")
    .profile()
}

/// A credential carrying `plaintext` as its password.
pub fn password(plaintext: &str) -> BasicCredential {
    let encoded = b64(format!("u:{plaintext}").as_bytes());
    extract_and_decode_with(&format!("Basic {encoded}"), CEILING, usize::MAX)
        .expect("the fixture credential decodes")
}
