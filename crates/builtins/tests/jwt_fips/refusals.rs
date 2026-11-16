// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Resolver construction refuses when FIPS verification cannot be guaranteed.

use praxis_policy_core::CryptoError;
use praxis_policy_core::error::PluginError;
use serde_json::json;

use crate::oracle::{audience, issuer, text};
use crate::support::{Openssl, build, capturing, config, isolated};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn a_missing_provider_fails_with_the_shared_backend_error() {
    isolated(
        "refusals::a_missing_provider_fails_with_the_shared_backend_error",
        Openssl::NoFips,
        || {
            let (events, _guard) = capturing();
            let error = crypto_error();
            assert!(
                matches!(error, CryptoError::OpenSsl(_)),
                "the shared SHA-256 check fails first: {error}"
            );
            events.assert_crypto_alarms("jwt_provider", 1);
            assert!(
                matches!(
                    praxis_policy_core::crypto::random_bytes(&mut [0_u8; 32]),
                    Err(CryptoError::OpenSsl(_))
                ),
                "random_bytes fails closed without the provider"
            );
        },
    );
}

#[test]
fn a_non_fips_default_is_refused() {
    isolated(
        "refusals::a_non_fips_default_is_refused",
        Openssl::FipsLoaded,
        || {
            let (events, _guard) = capturing();
            let error = crypto_error();
            assert!(
                matches!(error, CryptoError::NonFipsDefault),
                "FIPS SHA-256 works, but signatures could use the default provider: {error}"
            );
            events.assert_crypto_alarms("jwt_provider", 1);
        },
    );
}

#[test]
fn a_conflicting_provider_is_refused() {
    isolated(
        "refusals::a_conflicting_provider_is_refused",
        Openssl::FipsDefault,
        || {
            static OTHER: jsonwebtoken::crypto::CryptoProvider =
                jsonwebtoken::crypto::CryptoProvider {
                    signer_factory: |_, _| {
                        Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into())
                    },
                    verifier_factory: |_, _| {
                        Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into())
                    },
                    key_utils: jsonwebtoken::crypto::KeyUtils::new_unimplemented(),
                };
            assert!(OTHER.install_default().is_ok(), "the host installs first");
            let (events, _guard) = capturing();
            for _ in 0..2 {
                let error = crypto_error();
                assert!(
                    matches!(error, CryptoError::ProviderConflict),
                    "Policy refuses rather than verify with another provider: {error}"
                );
            }
            events.assert_crypto_alarms("jwt_provider", 2);
        },
    );
}

#[test]
fn random_bytes_draws_from_the_fips_drbg() {
    isolated(
        "refusals::random_bytes_draws_from_the_fips_drbg",
        Openssl::FipsDefault,
        || {
            let (mut a, mut b) = ([0_u8; 32], [0_u8; 32]);
            praxis_policy_core::crypto::random_bytes(&mut a).unwrap();
            praxis_policy_core::crypto::random_bytes(&mut b).unwrap();
            assert_ne!(a, b, "two draws differ");
            assert_ne!(a, [0_u8; 32], "the buffer is filled");
        },
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn crypto_error() -> CryptoError {
    let settings = config(
        issuer(),
        audience(),
        &["RS256"],
        json!({ "kind": "pem", "pem": text("rsa_public_pem") }),
    );
    match build(settings).map(drop).map_err(|e| *e) {
        Err(PluginError::Crypto { source }) => source,
        other => panic!("expected a crypto failure, got {other:?}"),
    }
}
