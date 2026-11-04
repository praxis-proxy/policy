// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Backend used to hash API-key credentials.

pub(crate) use praxis_policy_core::crypto::sha256;
pub use praxis_policy_core::{
    CryptoBackend as ApiKeyCryptoBackend, CryptoError as ApiKeyCryptoError,
};

/// Identify the API-key SHA-256 implementation in this build.
#[must_use]
pub const fn api_key_crypto_backend() -> ApiKeyCryptoBackend {
    praxis_policy_core::crypto_backend()
}

/// Check that the selected API-key hash operation is available at startup.
///
/// # Errors
/// Returns an error if the selected backend cannot perform SHA-256.
pub fn validate_api_key_crypto() -> Result<(), ApiKeyCryptoError> {
    sha256(&[])?;
    Ok(())
}
