// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Feature-selected cryptographic operations shared by Policy crates.

/// The backend used for Policy's always-enabled SHA-256 and HMAC operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoBackend {
    /// SHA-256 and HMAC operations use OpenSSL with the `fips=yes` property.
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
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The selected backend returned an unexpected digest length.
    #[error("Policy SHA-256 returned an invalid digest length")]
    DigestLength,
    /// OpenSSL could not perform the requested operation.
    #[cfg(feature = "fips")]
    #[error("OpenSSL FIPS cryptographic operation failed: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    /// `RustCrypto` rejected an HMAC key.
    #[cfg(feature = "crypto-rustcrypto")]
    #[error("RustCrypto HMAC key initialization failed: {0}")]
    HmacInitialization(#[source] hmac::digest::InvalidLength),
}

/// Incremental SHA-256 input builder used by CMF and runtime hashes.
enum Sha256State {
    #[cfg(feature = "fips")]
    OpenSsl(openssl::md_ctx::MdCtx),
    #[cfg(feature = "crypto-rustcrypto")]
    RustCrypto(sha2::Sha256),
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
            let digest = openssl::md::Md::fetch(None, "SHA256", Some("fips=yes"))?;
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

/// Compute HMAC-SHA256 with the backend selected for this Policy build.
///
/// # Errors
/// Returns an error if the selected provider cannot perform HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    #[cfg(feature = "fips")]
    {
        let digest = openssl::md::Md::fetch(None, "SHA256", Some("fips=yes"))?;
        let pkey = openssl::pkey::PKey::hmac(key)?;
        let mut context = openssl::md_ctx::MdCtx::new()?;
        context.digest_sign_init(Some(&digest), &pkey)?;
        context.digest_sign_update(bytes)?;
        let mut output = Vec::new();
        context.digest_sign_final_to_vec(&mut output)?;
        output.try_into().map_err(|_| CryptoError::DigestLength)
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
