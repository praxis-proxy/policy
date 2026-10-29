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

/// What a directory returned for a user-id it recognized.
///
/// The verifier is held apart from `fields` rather than inside it, which is the
/// one structural difference from [`KeyRecord`]. A stored hash is an
/// offline-crackable verifier: if it lived in `fields` it would be projectable
/// through the `record_map` and renderable into an upstream header, and the only
/// thing standing between it and a log line would be a backend remembering to
/// strip it. Here the type system holds that line — `fields` is what may be
/// projected, and there is no path from a projection to the verifier.
///
/// [`KeyRecord`]: crate::plugins::identity_api_key::KeyRecord
#[derive(Debug)]
#[non_exhaustive]
pub struct UserRecord {
    /// The record's projectable fields, as the backend gave them, minus
    /// whatever it strips. A backend's own index and lifecycle fields never
    /// appear here: they are storage, not subject attributes.
    pub fields: HashMap<String, Value>,

    /// How the stored secret is checked. Never projectable, never logged.
    pub verifier: StoredVerifier,

    /// When the record stops being valid, if it says.
    ///
    /// Always enforced by the resolver. Unlike the api-key plugin there is no
    /// mode delegating this to the directory, because `.htpasswd` has no native
    /// expiry and nothing else would be positioned to enforce it.
    pub expires_at: Option<DateTime<Utc>>,
}

impl UserRecord {
    /// A record with no projectable fields and no expiry.
    ///
    /// The shape a format carrying only a user-id and a hash produces, which
    /// is what `.htpasswd` is. A constructor rather than a struct literal
    /// because the type is `#[non_exhaustive]`: a field added later must not
    /// break every backend, and the compiler cannot help a literal.
    pub fn verifier_only(verifier: StoredVerifier) -> Self {
        Self {
            fields: HashMap::new(),
            verifier,
            expires_at: None,
        }
    }
}

/// How a backend checks a presented password.
///
/// An enum rather than a trait object because the set is closed by what the
/// storage formats can express, and because a `Box<dyn Fn>` here would be a
/// place to accidentally capture the plaintext.
#[derive(Clone)]
#[non_exhaustive]
pub enum StoredVerifier {
    /// A password hash in its storage encoding, checked locally.
    ///
    /// The string is the full modular-crypt record — scheme prefix, cost
    /// parameters and salt — so the verifier parses it rather than the backend
    /// pre-splitting it. Carrying it whole means the parse happens on both the
    /// found and not-found paths, which is what keeps a miss from being
    /// cheaper than a hit.
    Hash(String),

    /// The backend already verified the password itself, remotely.
    ///
    /// A delegated verdict, for the HTTP backend: there is no local hash to
    /// check, and the service's answer *is* the decision.
    Delegated {
        /// The service's verdict for the credential it was sent.
        valid: bool,
    },
}

impl std::fmt::Debug for StoredVerifier {
    /// Redacts the stored hash.
    ///
    /// Hand-written rather than derived, and that is the whole point: a
    /// derived `Debug` prints the full modular-crypt record — scheme, cost and
    /// salt — and `UserRecord` derives `Debug` over this type, so a single
    /// `tracing::debug!("{record:?}")` or a failed `unwrap()` message would
    /// write an offline-crackable verifier into the log. The field doc says
    /// "never logged"; a derive would make that doc a lie at the first
    /// diagnostic someone adds.
    ///
    /// `Delegated` keeps its `valid` flag, which is a boolean verdict and
    /// carries nothing crackable.
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

/// Why a directory could not answer.
///
/// Distinct from `Ok(None)` throughout, and for the same reason as the sibling
/// trait: both deny, but a spike of these is an outage and a spike of `None` is
/// a wave of bad credentials, and an operator reading a denial count cannot act
/// without knowing which.
///
/// Note what is *not* distinguished downstream. The resolver maps `Ok(None)`
/// and a failed verification onto one external code, because telling a client
/// which one it hit is a username-enumeration oracle. This distinction is for
/// operators, in logs and metrics, not for callers.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum DirectoryError {
    /// The directory was unreachable, timed out, or refused the query.
    #[error("directory unavailable: {0}")]
    Unavailable(String),

    /// The directory answered in a shape this backend cannot read.
    #[error("directory answered unreadably: {0}")]
    Malformed(String),

    /// The directory is serving an index older than its staleness ceiling.
    ///
    /// Fails closed rather than keeping a revoked user authenticated forever: a
    /// syntax error introduced while deleting a record must not become that
    /// record's permanent reprieve.
    #[error("directory index is past its staleness ceiling")]
    Stale,

    /// Concurrent verifications are at the configured cap.
    ///
    /// Denies rather than queueing. Every syntactically valid header costs a
    /// full hash verify, including a miss, so an unbounded queue here is an
    /// unauthenticated memory-and-CPU exhaustion path.
    #[error("verification capacity is saturated")]
    Saturated,
}

/// Where user records live.
///
/// `Debug` is a supertrait so the resolver holding `Arc<dyn CredentialDirectory>`
/// can derive it.
#[async_trait::async_trait]
pub trait CredentialDirectory: std::fmt::Debug + Send + Sync {
    /// The record for this user-id, or `None` when no such user exists.
    ///
    /// The user-id arrives NFC-normalised; a backend must normalise its stored
    /// user-ids identically at load, or a non-NFC stored name becomes
    /// unreachable.
    ///
    /// The lookup must not cost more as the record count grows: a directory
    /// that scans is a directory that times out under the user population it
    /// was bought for.
    ///
    /// `services` is the host's, carried by whatever the caller had. A backend
    /// that needs no egress ignores it, and must not be made to declare
    /// `perform_http` for a call it never makes.
    async fn lookup(
        &self,
        user_id: &str,
        services: &dyn HostServices,
    ) -> Result<Option<UserRecord>, DirectoryError>;

    /// Verify a presented password against a record this directory returned.
    ///
    /// On the directory rather than on the resolver for two reasons. Only the
    /// backend knows which schemes it admitted at load, and the dummy
    /// verification a miss must perform has to run at the worst-case work
    /// factor *present in this directory* — which only the directory can know,
    /// and which changes on every reload.
    ///
    /// Takes the decoded [`BasicCredential`] rather than a bare password: the
    /// password type is private to this plugin, and a trait method with an
    /// unnameable parameter could not be implemented or called from anywhere
    /// else -- which would make the trait pointless. The credential is the
    /// public carrier, and the backend reaches the secret through it.
    ///
    /// Takes the whole [`UserRecord`] option rather than a verifier so the
    /// not-found case is this method's business too: `None` must still perform
    /// a full dummy verification, or the absence of a user is measurable from
    /// outside and the directory becomes a user-enumeration oracle.
    async fn verify(
        &self,
        record: Option<&UserRecord>,
        credential: &BasicCredential,
        services: &dyn HostServices,
    ) -> Result<bool, DirectoryError>;

    /// A name for this backend, for diagnostics and the effect log.
    fn kind(&self) -> &'static str;
}
