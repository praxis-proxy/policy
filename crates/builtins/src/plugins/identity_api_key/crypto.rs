// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Backend used to hash API-key credentials.

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

/// Failure while validating or using the selected API-key hash backend.
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyCryptoError {
    /// The selected backend returned a digest with an unexpected size.
    #[error("API-key SHA-256 returned an invalid digest length")]
    DigestLength,
    /// SHA-256 could not be fetched from OpenSSL with the FIPS property.
    #[cfg(feature = "fips")]
    #[error("OpenSSL SHA-256 with fips=yes is unavailable: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

/// Check that the selected API-key hash operation is available at startup.
///
/// # Errors
/// Returns an error if the OpenSSL FIPS provider cannot supply SHA-256.
#[allow(
    clippy::unnecessary_wraps,
    reason = "The FIPS backend can fail; keep the startup API fallible across profiles."
)]
pub fn validate_api_key_crypto() -> Result<(), ApiKeyCryptoError> {
    #[cfg(feature = "fips")]
    {
        openssl::md::Md::fetch(None, "SHA256", Some("fips=yes"))?;
    }
    Ok(())
}

/// Hash an API-key credential using the backend reported by
/// [`api_key_crypto_backend`].
///
/// # Errors
/// Returns an error if OpenSSL cannot supply FIPS SHA-256.
#[allow(
    clippy::unnecessary_wraps,
    reason = "The FIPS backend can fail; keep the hashing API fallible across profiles."
)]
pub(crate) fn sha256(bytes: &[u8]) -> Result<[u8; 32], ApiKeyCryptoError> {
    #[cfg(feature = "fips")]
    {
        let digest = openssl::md::Md::fetch(None, "SHA256", Some("fips=yes"))?;
        let mut context = openssl::md_ctx::MdCtx::new()?;
        context.digest_init(&digest)?;
        context.digest_update(bytes)?;
        let mut output = [0_u8; 32];
        let length = context.digest_final(&mut output)?;
        if length != output.len() {
            return Err(ApiKeyCryptoError::DigestLength);
        }
        Ok(output)
    }
    #[cfg(feature = "crypto-rustcrypto")]
    {
        use sha2::Digest as _;
        Ok(sha2::Sha256::digest(bytes).into())
    }
}
