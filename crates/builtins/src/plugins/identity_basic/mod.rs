// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Credential decoding and directory backends for HTTP Basic authentication.
//!
//! Basic sends a reusable password on every request. TLS is required; base64
//! is not encryption ([RFC 7617 Section 4]). Hosts must redact credential
//! headers from logs and remove them before forwarding when appropriate.
//!
//! [RFC 7617 Section 4]: https://datatracker.ietf.org/doc/html/rfc7617#section-4

/// Plugin configuration and its validation.
pub mod config;
/// The RFC 7617 decode step and the credential types it produces.
pub mod credential;
/// The directory contract every Basic backend implements.
pub mod directory;
/// Constructs the resolver from configuration.
pub mod factory;
/// A bound on repeated failures for one user-id.
pub mod failure_limit;
/// The index, refresh and capacity machinery the file backends share.
pub mod file_backend;
/// The `.htpasswd` backend.
pub mod htpasswd;
/// Record fields onto the identity slots.
pub mod record_map;
/// The identity hook handler.
pub mod resolver;
/// The username-indexed YAML backend.
pub mod user_file;
/// Stored-hash admission and password verification.
pub mod verifier;

pub use config::{
    BasicResolverConfig, CredentialLimits, ExpiryPolicy, FailureLimitConfig, ProviderConfig,
};
pub use credential::{BasicCredential, DecodeError, decode_basic};
pub use directory::{CredentialDirectory, DirectoryError, StoredVerifier, UserRecord};
pub use factory::{BasicIdentityFactory, KIND};
pub use failure_limit::{FailureLimiter, Refusal};
pub use htpasswd::{HtpasswdConfig, HtpasswdDirectory};
pub use praxis_policy_core::extensions::raw_credentials::Credential;
pub use resolver::{BasicIdentityResolver, codes};
pub use user_file::{UserFileConfig, UserFileDirectory};
pub use verifier::{CostProfile, HashError, Limits, ParsedHash, Scheme, ShaCryptVariant};
