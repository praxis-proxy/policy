// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Backend used to hash API-key credentials.

pub use praxis_policy_core::crypto::CryptoError as ApiKeyCryptoError;
pub(crate) use praxis_policy_core::crypto::sha256;

/// The backend compiled for API-key SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKeyCryptoBackend {
    /// SHA-256 from the OpenSSL FIPS provider, selected with `fips=yes`.
    OpenSslFips,
    /// SHA-256 from `RustCrypto`.
    RustCrypto,
}

/// Identify the API-key SHA-256 implementation in this build.
#[must_use]
pub const fn api_key_crypto_backend() -> ApiKeyCryptoBackend {
    #[cfg(feature = "fips")]
    {
        ApiKeyCryptoBackend::OpenSslFips
    }
    #[cfg(not(feature = "fips"))]
    {
        ApiKeyCryptoBackend::RustCrypto
    }
}

/// Check that the selected API-key hash operation is available at startup.
///
/// # Errors
/// Returns an error if the selected backend cannot perform SHA-256.
#[allow(
    clippy::unnecessary_wraps,
    reason = "The FIPS backend can fail; keep the startup API fallible across profiles."
)]
pub fn validate_api_key_crypto() -> Result<(), ApiKeyCryptoError> {
    let _ = praxis_policy_core::crypto::sha256(&[])?;
    Ok(())
}
