// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Hashing a presented credential, for an index or a cache key.

use praxis_policy_core::crypto::sha256;

use crate::token_lookup::directory::{DirectoryError, PresentedKey};

/// Hash a credential without exposing backend failures to directory clients.
pub(crate) fn hash_credential(
    presented: &PresentedKey,
    op: &'static str,
) -> Result<[u8; 32], DirectoryError> {
    sha256(presented.as_bytes()).map_err(|error| {
        tracing::error!(alarm = "policy_crypto_failure", op, %error);
        DirectoryError::Unavailable("API key hashing failed".to_owned())
    })
}
