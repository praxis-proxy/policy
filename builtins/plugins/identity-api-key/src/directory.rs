// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `KeyDirectory` — where identity records live, and how a presented
// credential resolves to one.
//
// The opposite direction from a secret provider. `get_secret(name)` is a fetch
// by an operator-chosen name, resolved once at startup, returning bytes to
// render into a request. `lookup(presented)` is a verification by the presented
// value itself, resolved one at a time on the request path, returning an
// identity. A trait widened to serve both is bad at each.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use praxis_policy_core::host::HostServices;
use serde_json::Value;
use zeroize::Zeroizing;

/// The credential as presented, after the configured location and the prefix
/// gate.
///
/// Octets, not text. An API key is an opaque handle that happens to arrive in
/// a header: nothing about it is linguistic, and every text operation a
/// `String` invites is a way to authenticate the wrong caller. Case folding,
/// trimming, or Unicode normalization all map two different credentials onto
/// one lookup, and `==` on `str` is not constant time. Holding bytes means
/// none of those compile.
///
/// No `Debug`, no `Display`, no `Serialize`: a key reaching a log line or a
/// serialized payload is the failure this type exists to make impossible. The
/// octets are readable only through [`as_bytes`], which the hash consumes
/// directly, and the buffer is zeroized on drop.
///
/// Zeroizing here is partial, and honestly so. The host hands the engine its
/// headers as `HashMap<String, String>`, so an unzeroized copy of the
/// credential already exists in `IdentityPayload` for the life of the request.
/// Clearing this one shortens the exposure rather than ending it.
///
/// [`as_bytes`]: PresentedKey::as_bytes
pub struct PresentedKey(Zeroizing<Vec<u8>>);

impl PresentedKey {
    /// Wrap a credential read off the request.
    pub fn new(raw: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(raw.into()))
    }

    /// The octets, for hashing them.
    ///
    /// The only reader. Every caller must consume these within the expression
    /// that calls this: copying them into an owned value takes the credential
    /// out from under the zeroizing buffer, and that copy is not cleared.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the credential is empty, which denies before any lookup.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What a directory returned for a credential it recognized.
///
/// The fields stay as the backend gave them. The `record_map` block is what
/// gives a record shape, so a typed struct per backend would only be a second
/// place for the projection to disagree with itself.
#[derive(Debug, Clone, Default)]
pub struct KeyRecord {
    /// The record's fields, as the directory returned them, minus whatever the
    /// backend strips. A backend's own index and lifecycle fields never appear
    /// here: they are storage, not subject attributes, and a hash reaching
    /// `subject.claims` is renderable into an upstream header.
    pub fields: HashMap<String, Value>,

    /// When the record stops being valid, if it says.
    ///
    /// Enforced by the resolver under `expiry: enforce`, which is the default,
    /// because on the file path nothing else is positioned to. Deleting expired
    /// records belongs to whatever owns the storage.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Why a directory could not answer.
///
/// Distinct from `Ok(None)` throughout. Both deny, but a spike of these is an
/// outage and a spike of `None` is a wave of bad credentials, and an operator
/// reading a denial count cannot act without knowing which.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum DirectoryError {
    /// The directory was unreachable, timed out, or refused the query.
    #[error("directory unavailable: {0}")]
    Unavailable(String),

    /// The directory answered in a shape this backend cannot read.
    #[error("directory answered unreadably: {0}")]
    Malformed(String),
}

/// Where identity records live.
///
/// `Debug` is a supertrait so the resolver holding `Arc<dyn KeyDirectory>` can
/// derive it.
#[async_trait::async_trait]
pub trait KeyDirectory: std::fmt::Debug + Send + Sync {
    /// The record matching this credential, or `None` when none does.
    ///
    /// The lookup must not cost more as the record count grows: a directory
    /// that scans is a directory that times out under the key population it was
    /// bought for.
    ///
    /// `services` is the host's, carried by whatever the caller had: the
    /// `Extensions` of the request being resolved, or an `InitExtensions` when
    /// something calls this outside a request. A backend that needs no egress
    /// ignores it, and must not be made to declare `perform_http` for a call it
    /// never makes.
    async fn lookup(
        &self,
        presented: &PresentedKey,
        services: &dyn HostServices,
    ) -> Result<Option<KeyRecord>, DirectoryError>;

    /// A name for this backend, for diagnostics and the effect log.
    fn kind(&self) -> &'static str;
}
