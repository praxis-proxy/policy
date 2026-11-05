// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Consumer checks outside the engine workspace's feature unification.

#[cfg(test)]
mod tests {
    use policy::CryptoBackend;

    #[cfg(all(feature = "crypto-rustcrypto", not(feature = "api-key")))]
    #[test]
    fn ordinary_engine_reports_no_api_key_backend() -> Result<(), policy::CryptoError> {
        policy::validate_crypto_backend()?;
        assert_report(CryptoBackend::RustCrypto, None, false);
        Ok(())
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

    #[cfg(all(
        feature = "fips",
        not(feature = "api-key"),
        not(feature = "jwt-openssl-fips")
    ))]
    #[test]
    fn engine_only_fips_reports_safe() {
        assert_report(CryptoBackend::OpenSslFips, None, true);
    }

    #[cfg(all(feature = "fips", feature = "jwt-openssl-fips"))]
    #[test]
    fn openssl_jwt_keeps_the_fips_profile_safe() {
        let api_key = cfg!(feature = "api-key").then_some(CryptoBackend::OpenSslFips);
        assert_report(CryptoBackend::OpenSslFips, api_key, true);
        assert_eq!(
            policy::JWT_KIND,
            "identity/jwt",
            "the JWT kind is the same under jwt-openssl-fips"
        );
    }

    #[cfg(all(feature = "fips", feature = "jwt-openssl-fips"))]
    #[test]
    fn openssl_jwt_registers_its_factory() {
        let engine = std::sync::Arc::new(policy::PolicyEngine::default());
        policy::register_builtin_plugins(&engine);
        let yaml =
            "plugins:\n  - name: jwt\n    kind: identity/jwt\n    hooks: [identity.resolve]\n";
        let error = engine
            .load_config_yaml(yaml)
            .expect_err("a JWT plugin without a config block cannot load");
        assert!(
            !error.to_string().contains("no factory registered"),
            "identity/jwt must resolve to a factory: {error}"
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
