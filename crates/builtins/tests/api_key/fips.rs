// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! API-key behavior with the OpenSSL FIPS feature selected.

use praxis_policy_builtins::plugins::identity_api_key::{
    ApiKeyCryptoError, validate_api_key_crypto,
};

use crate::support::{RecordFile, denial_code, file_config, hash, resolve_with_header, resolver};

const KEY: &str = "sk-oai-fips-test";

#[tokio::test]
async fn fips_api_key_allow_and_deny_follow_provider_availability() {
    let provider_required = std::env::var_os("PRAXIS_REQUIRE_FIPS_PROVIDER").is_some();
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash(KEY)
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    match validate_api_key_crypto() {
        Ok(()) => {
            let known = resolve_with_header(&resolver, KEY).await;
            assert!(
                denial_code(&known).is_none(),
                "a known API key must resolve with the FIPS provider available"
            );

            let unknown = resolve_with_header(&resolver, "sk-oai-unknown").await;
            assert_eq!(
                denial_code(&unknown).as_deref(),
                Some("auth.key_unknown"),
                "an unknown API key must be denied after successful hashing"
            );
        },
        Err(error) => {
            assert!(
                !provider_required,
                "the FIPS provider is required in this environment: {error}"
            );
            assert!(
                matches!(error, ApiKeyCryptoError::OpenSsl(_)),
                "FIPS provider failures must be returned as OpenSSL errors: {error}"
            );

            let known = resolve_with_header(&resolver, KEY).await;
            assert_eq!(
                denial_code(&known).as_deref(),
                Some("auth.directory_unavailable"),
                "an unavailable FIPS provider must fail closed for a known key"
            );
        },
    }
}
