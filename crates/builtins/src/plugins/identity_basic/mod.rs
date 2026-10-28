// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `identity/basic` — HTTP Basic authentication ([RFC 7617]) as an identity
//! resolver.
//!
//! Decodes `Authorization: Basic <base64(user-id:password)>`, looks the user up
//! by user-id, verifies the password against a stored hash, and projects the
//! record through the shared `ClaimMapper`.
//!
//! # Why this is not `identity/api-key` with a `Basic` prefix
//!
//! That configuration works and stays supported as an Authorino-parity escape
//! hatch, but it indexes on `base64(user:password)` — the secret *is* the
//! lookup key. So a stored hash is impossible, a password rotation is a new
//! record rather than an update, `.htpasswd` cannot be read at all, and every
//! rule that wants the username re-decodes the header. This plugin indexes on
//! the user-id instead, which is what makes hashing, rotation and `.htpasswd`
//! possible.
//!
//! # Operator obligations this plugin cannot discharge
//!
//! Basic sends a reusable password in cleartext on every request, so some of
//! what makes a deployment safe is necessarily outside the engine:
//!
//! - **TLS is required.** Base64 is not encryption ([RFC 7617 Section 4]).
//! - **The `Authorization` header is not stripped by this plugin.** It cannot
//!   be: the identity hook has no channel for mutating the forwarded request,
//!   so removing the header before it reaches an upstream is a host or
//!   route-level obligation. What the plugin does guarantee is that it never
//!   populates `raw_credentials`, so no *downstream policy step* can forward
//!   the password.
//! - **A `WWW-Authenticate` challenge is carried, not delivered.** A denial
//!   sets the status and the header value in the violation's details for the
//!   host to render.
//!
//! [RFC 7617]: https://datatracker.ietf.org/doc/html/rfc7617
//! [RFC 7617 Section 4]: https://datatracker.ietf.org/doc/html/rfc7617#section-4

/// The RFC 7617 decode step and the credential types it produces.
pub mod credential;
/// The directory contract every Basic backend implements.
pub mod directory;

pub use credential::{BasicCredential, DecodeError, decode_basic};
pub use directory::{CredentialDirectory, DirectoryError, StoredVerifier, UserRecord};
