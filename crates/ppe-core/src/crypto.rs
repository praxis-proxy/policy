// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Feature-selected cryptographic operations shared by Policy crates.

#[cfg(feature = "fips")]
use std::sync::{Arc, OnceLock};

/// The backend used for Policy's always-enabled SHA-256 operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoBackend {
    /// SHA-256 uses OpenSSL with the `fips=yes` property.
    OpenSslFips,
    /// SHA-256 and HMAC from `RustCrypto`.
    RustCrypto,
}

/// Identify the backend selected for this Policy build.
#[must_use]
pub const fn crypto_backend() -> CryptoBackend {
    #[cfg(feature = "fips")]
    {
        CryptoBackend::OpenSslFips
    }
    #[cfg(feature = "crypto-rustcrypto")]
    {
        CryptoBackend::RustCrypto
    }
}

/// Failure while hashing with the selected Policy backend.
///
/// The variant set depends on the backend: `OpenSsl` and `HmacUnavailable`
/// exist with `fips`, `HmacInitialization` with `crypto-rustcrypto`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The selected backend returned an unexpected digest length.
    #[error("Policy SHA-256 returned an invalid digest length")]
    DigestLength,
    /// OpenSSL could not perform the requested operation.
    #[cfg(feature = "fips")]
    #[error("OpenSSL FIPS cryptographic operation failed: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    /// HMAC is unavailable in the FIPS profile.
    #[cfg(feature = "fips")]
    #[error("HMAC-SHA256 is unavailable with the FIPS feature")]
    HmacUnavailable,
    /// `RustCrypto` rejected an HMAC key.
    #[cfg(feature = "crypto-rustcrypto")]
    #[error("RustCrypto HMAC key initialization failed: {0}")]
    HmacInitialization(#[source] hmac::digest::InvalidLength),
}

/// Incremental SHA-256 input builder used by CMF and runtime hashes.
pub struct Sha256(Sha256State);

impl Sha256 {
    /// Start an empty SHA-256 input.
    ///
    /// # Errors
    /// Returns an error if the selected provider cannot initialize SHA-256.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the FIPS provider can fail, so initialization remains fallible across backends"
    )]
    pub fn new() -> Result<Self, CryptoError> {
        #[cfg(feature = "fips")]
        {
            let digest = fips_sha256()?;
            let mut context = openssl::md_ctx::MdCtx::new()?;
            context.digest_init(&digest)?;
            Ok(Self(Sha256State::OpenSsl(context)))
        }
        #[cfg(feature = "crypto-rustcrypto")]
        {
            use sha2::Digest as _;
            Ok(Self(Sha256State::RustCrypto(sha2::Sha256::new())))
        }
    }

    /// Finish hashing the accumulated input.
    ///
    /// # Errors
    /// Returns an error if the selected provider cannot perform SHA-256.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the FIPS provider can fail, so finalization remains fallible across backends"
    )]
    pub fn finalize(self) -> Result<[u8; 32], CryptoError> {
        match self.0 {
            #[cfg(feature = "fips")]
            Sha256State::OpenSsl(mut context) => {
                let mut output = [0_u8; 32];
                let length = context.digest_final(&mut output)?;
                if length != output.len() {
                    return Err(CryptoError::DigestLength);
                }
                Ok(output)
            },
            #[cfg(feature = "crypto-rustcrypto")]
            Sha256State::RustCrypto(context) => {
                use sha2::Digest as _;
                Ok(context.finalize().into())
            },
        }
    }

    /// Append bytes to the hash input.
    ///
    /// # Errors
    /// Returns an error if the selected provider cannot update SHA-256.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the FIPS provider can fail, so updates remain fallible across backends"
    )]
    pub fn update(&mut self, bytes: impl AsRef<[u8]>) -> Result<(), CryptoError> {
        match &mut self.0 {
            #[cfg(feature = "fips")]
            Sha256State::OpenSsl(context) => context.digest_update(bytes.as_ref())?,
            #[cfg(feature = "crypto-rustcrypto")]
            Sha256State::RustCrypto(context) => {
                use sha2::Digest as _;
                context.update(bytes.as_ref());
            },
        }
        Ok(())
    }
}

/// Hash bytes with the backend selected for this Policy build.
///
/// # Errors
/// Returns an error if the selected provider cannot perform SHA-256.
pub fn sha256(bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut digest = Sha256::new()?;
    digest.update(bytes)?;
    digest.finalize()
}

/// Compute HMAC-SHA256 with the `RustCrypto` backend.
///
/// # Errors
/// Returns an error if the key is invalid or the `fips` feature is enabled.
pub fn hmac_sha256(key: &[u8], bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    #[cfg(feature = "fips")]
    {
        let _ = (key, bytes);
        Err(CryptoError::HmacUnavailable)
    }
    #[cfg(feature = "crypto-rustcrypto")]
    {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use sha2::Sha256 as Sha256Digest;

        let mut mac =
            Hmac::<Sha256Digest>::new_from_slice(key).map_err(CryptoError::HmacInitialization)?;
        mac.update(bytes);
        Ok(mac.finalize().into_bytes().into())
    }
}

/// The backend's in-progress digest behind [`Sha256`].
enum Sha256State {
    #[cfg(feature = "fips")]
    OpenSsl(openssl::md_ctx::MdCtx),
    #[cfg(feature = "crypto-rustcrypto")]
    RustCrypto(sha2::Sha256),
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

#[cfg(feature = "fips")]
fn fips_sha256() -> Result<Arc<openssl::md::Md>, CryptoError> {
    static FIPS_SHA256: OnceLock<Arc<openssl::md::Md>> = OnceLock::new();

    if let Some(digest) = FIPS_SHA256.get() {
        return Ok(Arc::clone(digest));
    }

    let digest = Arc::new(openssl::md::Md::fetch(None, "SHA256", Some("fips=yes"))?);
    match FIPS_SHA256.set(Arc::clone(&digest)) {
        Ok(()) => Ok(digest),
        Err(raced_value) => Ok(FIPS_SHA256.get().cloned().unwrap_or(raced_value)),
    }
}

/// Known-answer tests. Under `fips` they need a loaded provider: CI runs them
/// in the provider job and runs `a_missing_fips_provider_fails_closed` where
/// none is loaded. `PRAXIS_REQUIRE_FIPS_PROVIDER` states which one applies,
/// so a misconfigured job fails instead of passing vacuously.
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    /// FIPS 180-2 examples: empty, one block, and a two-block message.
    const SHA256_VECTORS: [(&[u8], &str); 3] = [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];

    #[test]
    fn sha256_matches_the_standard_vectors() {
        for (input, expected) in SHA256_VECTORS {
            assert_eq!(hex(&sha256(input).unwrap()), expected);
        }
    }

    #[test]
    fn incremental_updates_match_one_shot_at_every_split() {
        let (input, expected) = SHA256_VECTORS[2];
        for split in 0..=input.len() {
            let mut digest = Sha256::new().unwrap();
            let (head, tail) = input.split_at(split);
            digest.update(head).unwrap();
            digest.update(tail).unwrap();
            assert_eq!(
                hex(&digest.finalize().unwrap()),
                expected,
                "split at {split}"
            );
        }
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        let cases: [(&[u8], &[u8], &str); 2] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
        ];
        for (key, data, expected) in cases {
            assert_eq!(hex(&hmac_sha256(key, data).unwrap()), expected);
        }
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn the_rustcrypto_build_reports_its_backend() {
        assert_eq!(crypto_backend(), CryptoBackend::RustCrypto);
    }

    #[cfg(feature = "fips")]
    #[test]
    fn the_fips_build_reports_its_backend() {
        assert_eq!(crypto_backend(), CryptoBackend::OpenSslFips);
    }

    #[cfg(feature = "fips")]
    #[test]
    fn hmac_is_unavailable_under_fips() {
        assert!(matches!(
            hmac_sha256(b"key", b"data"),
            Err(CryptoError::HmacUnavailable)
        ));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn a_missing_fips_provider_fails_closed() {
        assert!(
            std::env::var_os("PRAXIS_REQUIRE_FIPS_PROVIDER").is_none(),
            "this test asserts provider absence; do not select it in the provider job"
        );
        assert!(matches!(sha256(b"abc"), Err(CryptoError::OpenSsl(_))));
        assert!(matches!(Sha256::new(), Err(CryptoError::OpenSsl(_))));
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
