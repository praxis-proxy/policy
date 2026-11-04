// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Backend used to hash API-key credentials.

use praxis_policy_core::crypto::sha256;

use crate::plugins::identity_api_key::directory::{DirectoryError, PresentedKey};

pub use praxis_policy_core::{
    CryptoBackend as ApiKeyCryptoBackend, CryptoError as ApiKeyCryptoError,
};

/// Identify the API-key SHA-256 implementation in this build.
#[must_use]
pub const fn api_key_crypto_backend() -> ApiKeyCryptoBackend {
    praxis_policy_core::crypto_backend()
}

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
