// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Hashing a presented credential, for an index or a cache key.

use praxis_policy_core::crypto::sha256;

use crate::token_lookup::directory::{DirectoryError, PresentedKey};

/// How a hashing failure is reported, so the alarm names the plugin that
/// raised it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HashLabels {
    /// The message the lookup fails with.
    pub(crate) failure: &'static str,
    /// The alarm's `op` field.
    pub(crate) op: &'static str,
}

/// The labels the API key cache reports with, which `CachingDirectory::new`
/// keeps as its default.
pub(crate) const API_KEY_CACHE: HashLabels = HashLabels {
    failure: "API key hashing failed",
    op: "api_key_cache",
};

/// Hash a credential without exposing backend failures to directory clients.
pub(crate) fn hash_credential(
    presented: &PresentedKey,
    labels: HashLabels,
) -> Result<[u8; 32], DirectoryError> {
    sha256(presented.as_bytes()).map_err(|error| {
        tracing::error!(alarm = "policy_crypto_failure", op = labels.op, %error);
        DirectoryError::Unavailable(labels.failure.to_owned())
    })
}
