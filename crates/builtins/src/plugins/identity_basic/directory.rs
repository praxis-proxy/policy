// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `CredentialDirectory` — where user records live, and how a user-id resolves
// to one that can verify a password.
//
// A sibling of `KeyDirectory`, not an extension of it. The epic proposed
// adding a `verify(user_id, password)` method there, and the shapes do not fit:
// `KeyDirectory::lookup` takes one opaque credential and returns a record,
// because for an API key *finding the digest is the match*. Basic has to look
// up by a public index key and then verify a secret against whatever the found
// record stores — two steps, with a verifier the resolver must never hold. A
// defaulted `verify` on the existing trait would leave `FileDirectory`,
// `HttpDirectory` and `CachingDirectory` each carrying a method they cannot
// serve.
//
// Be honest about the cost: this is pattern reuse, not code reuse. The api-key
// `CachingDirectory` holds a concrete `Arc<dyn KeyDirectory>` and its `lookup`
// takes `&PresentedKey`, so it cannot be composed against this trait without
// genericising it. The caching and HTTP backends here are therefore parallel
// implementations that follow the sibling's structure and reasoning rather than
// calling into it. Genericising the working api-key cache for a second consumer
// that does not exist yet would touch live authentication code for no present
// benefit, so the duplication is accepted deliberately and revisited when there
// are two implementations to generalise from.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use praxis_policy_core::host::HostServices;
use serde_json::Value;

use super::BasicCredential;

/// A recognized user record with projectable fields and a separate verifier.
///
/// Stored hash material must remain in `verifier`, never in `fields`.
#[derive(Debug)]
#[non_exhaustive]
pub struct UserRecord {
    /// Projectable subject attributes, excluding storage and lifecycle fields.
    pub fields: HashMap<String, Value>,

    /// How the stored secret is checked. Never projectable, never logged.
    pub verifier: StoredVerifier,

    /// The expiry instant, when supplied by the backend.
    ///
    /// Callers must reject expired records.
    pub expires_at: Option<DateTime<Utc>>,
}

impl UserRecord {
    /// Create a record with a verifier, no projectable fields, and no expiry.
    pub fn verifier_only(verifier: StoredVerifier) -> Self {
        Self {
            fields: HashMap::new(),
            verifier,
            expires_at: None,
        }
    }
}

/// A local password hash or a delegated verification verdict.
#[derive(Clone)]
#[non_exhaustive]
pub enum StoredVerifier {
    /// A complete encoded password hash for local verification.
    Hash(String),

    /// The backend already verified the password itself, remotely.
    Delegated {
        /// The service's verdict for the credential it was sent.
        valid: bool,
    },
}

impl std::fmt::Debug for StoredVerifier {
    /// Format the verifier without exposing stored hash material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Deliberately not the length or the scheme prefix either: the
            // scheme narrows an offline attack, and the length distinguishes
            // one scheme from another.
            Self::Hash(_) => f.write_str("Hash(<redacted>)"),
            Self::Delegated { valid } => f.debug_struct("Delegated").field("valid", valid).finish(),
        }
    }
}

/// A directory failure, distinct from an unknown user.
///
/// Callers should distinguish outages in diagnostics while returning the same
/// external rejection for an unknown user and an incorrect password.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DirectoryError {
    /// The directory was unreachable, timed out, or refused the query.
    #[error("directory unavailable: {0}")]
    Unavailable(String),

    /// The directory answered in a shape this backend cannot read.
    #[error("directory answered unreadably: {0}")]
    Malformed(String),

    /// The loaded index is older than its configured staleness ceiling.
    #[error("directory index is past its staleness ceiling")]
    Stale,

    /// Verification capacity is saturated; the request cannot be queued.
    #[error("verification capacity is saturated")]
    Saturated,
}

/// A backend for user lookup and password verification.
#[async_trait::async_trait]
pub trait CredentialDirectory: std::fmt::Debug + Send + Sync {
    /// Look up an NFC-normalised user-id, returning `None` for an unknown user.
    ///
    /// Backends must normalise stored user-ids identically and use indexed lookup.
    /// `services` supplies host capabilities to backends requiring egress.
    async fn lookup(
        &self,
        user_id: &str,
        services: &dyn HostServices,
    ) -> Result<Option<UserRecord>, DirectoryError>;

    /// Verify a credential against a record returned by this directory.
    ///
    /// For `None`, perform dummy verification at the directory's worst admitted
    /// work factor and return `false`. This prevents a cheap unknown-user path.
    /// Use the same verification capacity limit for known and unknown users.
    async fn verify(
        &self,
        record: Option<&UserRecord>,
        credential: &BasicCredential,
        services: &dyn HostServices,
    ) -> Result<bool, DirectoryError>;

    /// A name for this backend, for diagnostics and the effect log.
    fn kind(&self) -> &'static str;
}
