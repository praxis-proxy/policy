// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Resolves an API key to an identity by looking it up in a directory.
//!
//! # Why this is a lookup and not a validation
//!
//! A JWT is self describing: it carries signed claims, so verifying one is
//! local and stateless. An API key is an opaque handle that carries nothing.
//! Authenticating one means finding the record keyed by it, and that record's
//! fields become the identity. Every design decision here follows from that.
//!
//! # Error handling
//!
//! Two surfaces, matching the JWT plugin:
//!
//!   * **Build / config errors** — constructors return
//!     `Result<Self, Box<PluginError>>`, surfacing as `PluginError::Config`.
//!   * **Runtime rejection** — the handler returns
//!     `PluginResult::deny(PluginViolation::new(code, reason))`, with `code`
//!     from `resolver::codes`.
//!
//! An API key carries nothing, so authentication is a lookup: find the record
//! this credential keys, and project its fields onto the subject, client, or
//! workload slot. Which fields fill which slot is configuration, written as a
//! [`record_map`] block in the same shape as the JWT plugin's `claim_map`,
//! because both are the same problem: a JSON object filling typed identity
//! slots.
//!
//! Where the records live is also configuration. The file backend reads a hash
//! indexed file and needs no network.
//!
//! The presented key never leaves this plugin. It is not written to
//! `raw_credentials`, so no downstream step can forward a caller's own
//! credential to an upstream that never authenticated it.
//!
//! [`record_map`]: crate::plugins::identity_api_key::config::ApiKeyResolverConfig::record_map

/// A cache in front of a directory.
pub mod cache;
/// Plugin configuration and its validation.
pub mod config;
/// Where the key is read from, and the prefix gate.
pub mod credential;
/// Where identity records live.
pub mod directory;
/// Constructs the resolver from configuration.
pub mod factory;
/// The hash indexed file backend.
pub mod file_directory;
/// The backend for a directory behind an HTTP API.
pub mod http_directory;
/// Record fields onto the identity slots.
pub mod record_map;
/// The identity hook handler.
pub mod resolver;

pub use cache::{CacheConfig, CachingDirectory};
pub use config::{ApiKeyResolverConfig, ExpiryPolicy, OnDirectoryError, ProviderConfig};
pub use credential::{Credential, CredentialLocation, Extraction};
pub use directory::{DirectoryError, KeyDirectory, KeyRecord, PresentedKey};
pub use factory::{ApiKeyIdentityFactory, KIND};
pub use file_directory::{FileDirectory, FileDirectoryConfig, FileRecord, IndexKind, RecordFile};
pub use http_directory::{HttpDirectory, HttpDirectoryConfig};
pub use resolver::{ApiKeyIdentityResolver, codes};
