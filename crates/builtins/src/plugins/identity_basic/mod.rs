// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Credential decoding and directory backends for HTTP Basic authentication.
//!
//! Basic sends a reusable password on every request. TLS is required; base64
//! is not encryption ([RFC 7617 Section 4]). Hosts must redact credential
//! headers from logs and remove them before forwarding when appropriate.
//!
//! [RFC 7617 Section 4]: https://datatracker.ietf.org/doc/html/rfc7617#section-4

/// The RFC 7617 decode step and the credential types it produces.
pub mod credential;
/// The directory contract every Basic backend implements.
pub mod directory;
/// The `.htpasswd` backend.
pub mod htpasswd;
/// Stored-hash admission and password verification.
pub mod verifier;

pub use credential::{BasicCredential, DecodeError, decode_basic};
pub use directory::{CredentialDirectory, DirectoryError, StoredVerifier, UserRecord};
pub use htpasswd::{HtpasswdConfig, HtpasswdDirectory};
pub use verifier::{CostProfile, HashError, Limits, ParsedHash, Scheme};
