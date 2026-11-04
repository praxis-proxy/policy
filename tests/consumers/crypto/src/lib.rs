// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Consumer checks outside the engine workspace's feature unification.

#[cfg(test)]
mod tests {
    use policy::CryptoBackend;

    #[cfg(all(feature = "crypto-rustcrypto", not(feature = "api-key")))]
    #[test]
    fn ordinary_engine_reports_no_api_key_backend() {
        assert_report(CryptoBackend::RustCrypto, None, false);
    }

    #[cfg(all(feature = "crypto-rustcrypto", feature = "api-key"))]
    #[test]
    fn ordinary_api_key_reports_rustcrypto() {
        assert_report(
            CryptoBackend::RustCrypto,
            Some(CryptoBackend::RustCrypto),
            false,
        );
    }

    #[cfg(all(feature = "fips", feature = "api-key"))]
    #[test]
    fn supported_api_key_reports_fips() {
        assert_report(
            CryptoBackend::OpenSslFips,
            Some(CryptoBackend::OpenSslFips),
            true,
        );
    }

    #[cfg(feature = "api-key")]
    #[test]
    fn api_key_aliases_are_the_core_types() {
        let api_backend: policy::ApiKeyCryptoBackend = policy::api_key_crypto_backend();
        let core_backend: policy::praxis_policy_core::CryptoBackend = api_backend;
        assert_eq!(core_backend, policy::praxis_policy_core::crypto_backend());

        let api_error: policy::ApiKeyCryptoError = policy::CryptoError::DigestLength;
        let core_error: policy::praxis_policy_core::CryptoError = api_error;
        assert!(matches!(core_error, policy::CryptoError::DigestLength));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn callers_can_match_errors_with_a_fallback() {
        let error = policy::CryptoError::HmacUnavailable;
        let reason = match error {
            policy::CryptoError::HmacUnavailable => "unsupported",
            policy::CryptoError::OpenSsl(_) => "provider",
            _ => "other",
        };
        assert_eq!(reason, "unsupported");
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn assert_report(
        policy_backend: CryptoBackend,
        api_backend: Option<CryptoBackend>,
        safe: bool,
    ) {
        let report = policy::crypto_capability_report();
        assert_eq!(report.policy_backend, policy_backend);
        assert_eq!(report.api_key_backend, api_backend);
        assert!(report.default_builtin_crypto.is_empty());
        assert_eq!(report.fips_profile_is_safe(), safe);
    }
}
