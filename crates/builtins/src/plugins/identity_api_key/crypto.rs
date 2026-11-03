// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Backend used to hash API-key credentials.

#[cfg(feature = "fips")]
use std::sync::{Arc, OnceLock};

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

#[cfg(feature = "fips")]
static FIPS_SHA256: OnceLock<Arc<openssl::md::Md>> = OnceLock::new();

#[cfg(feature = "fips")]
fn retained_digest<T, E>(
    slot: &OnceLock<Arc<T>>,
    fetch: impl FnOnce() -> Result<T, E>,
) -> Result<Arc<T>, E> {
    if let Some(value) = slot.get() {
        return Ok(Arc::clone(value));
    }

    let value = Arc::new(fetch()?);
    match slot.set(Arc::clone(&value)) {
        Ok(()) => Ok(value),
        Err(raced_value) => Ok(slot.get().cloned().unwrap_or(raced_value)),
    }
}

#[cfg(feature = "fips")]
fn fips_sha256() -> Result<Arc<openssl::md::Md>, ApiKeyCryptoError> {
    retained_digest(&FIPS_SHA256, || {
        openssl::md::Md::fetch(None, "SHA256", Some("fips=yes"))
    })
    .map_err(ApiKeyCryptoError::from)
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
        let digest = fips_sha256()?;
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
        let _ = fips_sha256()?;
    }
    Ok(())
}

#[cfg(all(test, feature = "fips"))]
mod tests {
    use super::retained_digest;
    use std::sync::Arc;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn fetched_digest_is_retained_after_success() -> Result<(), &'static str> {
        let slot = OnceLock::new();
        let fetches = AtomicUsize::new(0);
        let first = retained_digest(&slot, || {
            fetches.fetch_add(1, Ordering::Relaxed);
            Ok::<_, &'static str>([7_u8; 32])
        })?;
        let second = retained_digest(&slot, || {
            fetches.fetch_add(1, Ordering::Relaxed);
            Ok([8_u8; 32])
        })?;

        assert!(
            Arc::ptr_eq(&first, &second),
            "a successful provider fetch must be reused"
        );
        assert_eq!(
            fetches.load(Ordering::Relaxed),
            1,
            "fetch once after success"
        );
        Ok(())
    }

    #[test]
    fn failed_digest_fetch_is_retried() -> Result<(), &'static str> {
        let slot = OnceLock::new();
        let failed = retained_digest(&slot, || Err::<[u8; 32], _>("provider unavailable"));
        assert_eq!(failed, Err("provider unavailable"));

        let digest = retained_digest(&slot, || Ok::<_, &'static str>([7_u8; 32]))?;
        assert_eq!(digest.as_ref(), &[7_u8; 32]);
        Ok(())
    }
}
