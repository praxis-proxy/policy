// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Feature-selected cryptographic operations shared by Policy crates.

#[cfg(feature = "fips")]
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// The violation code for a request denied because the crypto backend failed.
pub const CRYPTO_FAILED_CODE: &str = "policy.crypto_failed";

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

/// Failure of an operation on the selected Policy backend.
///
/// The variant set depends on the backend: `OpenSsl`, `HmacUnavailable`,
/// `NonFipsDefault` and `ProviderConflict` exist with `fips`;
/// `HmacInitialization` and `Random` with `crypto-rustcrypto`.
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
    /// OpenSSL's default properties reach non-FIPS implementations, so an
    /// operation without an explicit property query could leave the FIPS
    /// provider.
    #[cfg(feature = "fips")]
    #[error("OpenSSL default properties do not restrict operations to the FIPS provider")]
    NonFipsDefault,
    /// Another crypto provider was installed for `jsonwebtoken` in this
    /// process, so Policy cannot verify JWTs with OpenSSL.
    #[cfg(feature = "fips")]
    #[error("another jsonwebtoken crypto provider is installed in this process")]
    ProviderConflict,
    /// `RustCrypto` rejected an HMAC key.
    #[cfg(feature = "crypto-rustcrypto")]
    #[error("RustCrypto HMAC key initialization failed: {0}")]
    HmacInitialization(#[source] hmac::digest::InvalidLength),
    /// The operating system could not supply random bytes.
    #[cfg(feature = "crypto-rustcrypto")]
    #[error("the OS random number generator failed: {0}")]
    Random(#[source] getrandom::Error),
}

/// Admits one log line per interval and counts the ones it holds back, for
/// alarms a request can repeat.
#[derive(Debug)]
pub struct IntervalLog {
    interval_secs: u64,
    next_at: AtomicU64,
    suppressed: AtomicU64,
}

impl IntervalLog {
    /// A log admitting at most one line per `interval_secs`.
    #[must_use]
    pub const fn new(interval_secs: u64) -> Self {
        Self {
            interval_secs,
            next_at: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// The count held back since the last admitted line, when a line is due.
    pub fn admit(&self) -> Option<u64> {
        // Monotonic, so a wall-clock step back cannot silence alarms. The
        // offset lets the first call pass the initial `next_at` of 0.
        static START: OnceLock<Instant> = OnceLock::new();
        let now = START
            .get_or_init(Instant::now)
            .elapsed()
            .as_secs()
            .saturating_add(1);
        let next = self.next_at.load(Ordering::Relaxed);
        let due = now >= next
            && self
                .next_at
                .compare_exchange(
                    next,
                    now.saturating_add(self.interval_secs),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok();
        if due {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// The interval between admitted lines, in seconds.
    #[must_use]
    pub const fn interval_secs(&self) -> u64 {
        self.interval_secs
    }
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

/// Fill `buf` with random bytes suitable for keys and other secrets.
///
/// With `crypto-rustcrypto` the bytes come from the operating system. With
/// `fips` they come from OpenSSL's private DRBG, which is the FIPS DRBG only
/// when the FIPS provider is the process default; the call fails unless
/// `require_fips_default` passes.
///
/// # Errors
/// Returns an error if the backend cannot produce random bytes, or under
/// `fips` if the FIPS provider is not the process default.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    #[cfg(feature = "fips")]
    {
        require_fips_default()?;
        openssl::rand::rand_priv_bytes(buf)?;
        Ok(())
    }
    #[cfg(feature = "crypto-rustcrypto")]
    {
        getrandom::fill(buf).map_err(CryptoError::Random)
    }
}

/// Check that OpenSSL operations without a property query use the FIPS
/// provider.
///
/// Signature verification and random generation select their OpenSSL
/// implementation from the default properties, as configured by
/// `default_properties = fips=yes` or a FIPS-mode host. This passes when
/// FIPS SHA-256 is available and a non-FIPS algorithm (MD5) is not reachable
/// by default.
///
/// # Errors
/// Returns [`CryptoError::OpenSsl`] if FIPS SHA-256 is unavailable, or
/// [`CryptoError::NonFipsDefault`] if the default reaches other providers.
#[cfg(feature = "fips")]
pub fn require_fips_default() -> Result<(), CryptoError> {
    fips_sha256()?;
    if openssl::md::Md::fetch(None, "MD5", None).is_ok() {
        return Err(CryptoError::NonFipsDefault);
    }
    Ok(())
}

/// Check that the selected Policy backend can perform SHA-256 at startup.
///
/// [`PolicyEngine::initialize`] calls this automatically. Call it directly
/// for an earlier preflight check or when using core without an engine.
///
/// Covers SHA-256 users of the shared backend. Plugins with independent
/// crypto require their own checks; HMAC remains unavailable under FIPS.
///
/// # Errors
/// Returns an error if the selected backend cannot perform SHA-256.
///
/// ```
/// praxis_policy_core::validate_crypto_backend()?;
/// # Ok::<(), praxis_policy_core::CryptoError>(())
/// ```
///
/// [`PolicyEngine::initialize`]: crate::engine::PolicyEngine::initialize
pub fn validate_crypto_backend() -> Result<(), CryptoError> {
    sha256(&[])?;
    Ok(())
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

    // -----------------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------------

    #[cfg(feature = "fips")]
    const FIPS_RECOVERY_CHILD: &str = "PPE_FIPS_RECOVERY_CHILD";

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

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn an_available_backend_passes_startup_validation() -> Result<(), CryptoError> {
        validate_crypto_backend()
    }

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

    #[test]
    fn interval_log_admits_one_line_per_interval_and_counts_the_rest() {
        let log = IntervalLog::new(3_600);
        assert_eq!(log.admit(), Some(0), "the first line is admitted");
        assert_eq!(
            log.admit(),
            None,
            "a repeat inside the interval is held back"
        );
        assert_eq!(log.admit(), None, "and so is the next");

        let open = IntervalLog::new(0);
        assert_eq!(
            open.admit(),
            Some(0),
            "a zero interval admits the first line"
        );
        assert_eq!(open.admit(), Some(0), "and every line after it");
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn random_bytes_fills_the_buffer_and_two_draws_differ() -> Result<(), CryptoError> {
        let (mut a, mut b) = ([0_u8; 32], [0_u8; 32]);
        random_bytes(&mut a)?;
        random_bytes(&mut b)?;
        assert_ne!(a, b, "two 32-byte draws must differ");
        assert_ne!(a, [0_u8; 32], "the buffer must be filled");
        random_bytes(&mut [])?;
        Ok(())
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
        assert!(matches!(
            validate_crypto_backend(),
            Err(CryptoError::OpenSsl(_))
        ));
    }

    #[cfg(feature = "fips")]
    #[tokio::test]
    async fn a_failed_startup_recovers_when_the_provider_becomes_available()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if std::env::var_os(FIPS_RECOVERY_CHILD).is_none() {
            assert!(
                std::env::var_os("PRAXIS_REQUIRE_FIPS_PROVIDER").is_some(),
                "recovery requires an installed provider; select this test in the provider job"
            );
            let output = std::process::Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("crypto::tests::a_failed_startup_recovers_when_the_provider_becomes_available")
                .arg("--format=pretty")
                .arg("--color=never")
                .env(FIPS_RECOVERY_CHILD, "1")
                .env(
                    "OPENSSL_CONF",
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../.github/fips-no-provider.cnf"
                    ),
                )
                .output()?;
            assert!(
                output.status.success(),
                "isolated provider recovery failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
                "the recovery child must execute one test: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            return Ok(());
        }

        let engine = crate::engine::PolicyEngine::default();
        for _ in 0..2 {
            let Err(error) = engine.initialize().await else {
                return Err("startup succeeded without a FIPS provider".into());
            };
            assert!(matches!(
                error.as_ref(),
                crate::error::PluginError::Crypto {
                    source: CryptoError::OpenSsl(_)
                }
            ));
            assert!(!engine.is_initialized());
        }

        let _provider = openssl::provider::Provider::load(None, "fips")?;
        engine.initialize().await?;
        assert!(
            engine.is_initialized(),
            "startup must succeed after provider loading"
        );
        validate_crypto_backend()?;
        assert_eq!(hex(&sha256(b"abc")?), SHA256_VECTORS[1].1);
        engine.initialize().await?;
        engine.shutdown().await;
        assert!(!engine.is_initialized());
        Ok(())
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
