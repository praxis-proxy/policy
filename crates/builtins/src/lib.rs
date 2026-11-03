// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bundled extensions for the Praxis Policy Engine: decision points, identity
//! and delegation plugins, a session store, and a secret provider.
//!
//! Every extension sits behind its own Cargo feature and nothing is enabled by
//! default. Hosts normally reach these through the `praxis-policy` facade,
//! which maps its own feature of the same name onto each one and registers the
//! factories; depend on this crate directly only to use an extension without
//! the facade.
//!
//! Module paths are written as plain code spans rather than intra-doc links.
//! They cannot be links: every module here is feature-gated and `make doc` runs
//! a default-features pass under `-D warnings`, where most of them are absent.
//! docs.rs builds with all features, so the modules are reachable from the
//! sidebar.
//!
//! | Feature | Module |
//! |---|---|
//! | `jwt` | `plugins::identity_jwt` |
//! | `api-key` | `plugins::identity_api_key` |
//! | `crypto-rustcrypto` | RustCrypto SHA-256 for API-key hashing |
//! | `fips` | OpenSSL FIPS SHA-256 and HMAC for Policy and API-key hashing |
//! | `oauth` | `plugins::delegator_oauth` |
//! | `elicitation-ciba` | `plugins::elicitation_ciba` |
//! | `quota/limitador` | `plugins::quota` |
//! | `ratelimit/limitador` | `plugins::ratelimit` |
//! | `cedar` | `pdps::cedar_direct` |
//! | `cel` | `pdps::cel` |
//! | `opa` | `pdps::opa` |
//! | `valkey` | `session::valkey` |
//! | `secrets-vault` | `secrets::vault` |

// Each group is gated on a private marker feature that every extension in it
// implies, rather than on an `any(feature = ...)` list. `unexpected_cfgs`
// catches a `cfg` naming a feature that does not exist, but not an alternative
// missing from such a list, so a marker is what keeps a tenth extension from
// silently failing to declare its module.
#[cfg(all(feature = "crypto-rustcrypto", feature = "fips"))]
compile_error!("select one API-key crypto backend: crypto-rustcrypto or fips");
#[cfg(all(
    feature = "api-key",
    not(any(feature = "crypto-rustcrypto", feature = "fips"))
))]
compile_error!("api-key requires crypto-rustcrypto or fips");
#[cfg(all(feature = "fips", not(feature = "api-key")))]
compile_error!("the FIPS profile requires the api-key feature");
#[cfg(feature = "_plugins")]
pub mod plugins;

#[cfg(feature = "_pdps")]
pub mod pdps;

#[cfg(feature = "_secrets")]
pub mod secrets;

#[cfg(feature = "_session")]
pub mod session;

/// A builtin crypto operation that uses the default RustCrypto backend.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultCryptoCapability {
    /// JWT signature verification and `DPoP` token hashing.
    Jwt,
    /// OAuth delegation cache-key HMAC.
    OAuth,
    /// Vault delegation cache-key hashing.
    VaultDelegation,
    /// Valkey session-key hashing.
    Valkey,
}

/// List builtin crypto operations enabled by the unified feature set.
#[doc(hidden)]
#[must_use]
pub fn default_crypto_capabilities() -> Vec<DefaultCryptoCapability> {
    vec![
        #[cfg(feature = "jwt")]
        DefaultCryptoCapability::Jwt,
        #[cfg(feature = "oauth")]
        DefaultCryptoCapability::OAuth,
        #[cfg(feature = "delegator-vault")]
        DefaultCryptoCapability::VaultDelegation,
        #[cfg(feature = "valkey")]
        DefaultCryptoCapability::Valkey,
    ]
}

#[cfg(any(feature = "valkey", feature = "elicitation-ciba"))]
mod env_secret;

#[cfg(test)]
mod crypto_capability_tests {
    use super::default_crypto_capabilities;

    #[cfg(any(
        feature = "jwt",
        feature = "oauth",
        feature = "delegator-vault",
        feature = "valkey"
    ))]
    use super::DefaultCryptoCapability;

    #[test]
    fn builtin_crypto_report_matches_the_unified_features() {
        let expected = vec![
            #[cfg(feature = "jwt")]
            DefaultCryptoCapability::Jwt,
            #[cfg(feature = "oauth")]
            DefaultCryptoCapability::OAuth,
            #[cfg(feature = "delegator-vault")]
            DefaultCryptoCapability::VaultDelegation,
            #[cfg(feature = "valkey")]
            DefaultCryptoCapability::Valkey,
        ];
        assert_eq!(default_crypto_capabilities(), expected);
    }
}
