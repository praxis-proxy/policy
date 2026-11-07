// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bundled extensions for the Praxis Policy Engine: decision points, identity
//! and delegation plugins, a session store, and a secret provider.
//!
//! Every extension sits behind its own Cargo feature and none is enabled by
//! default; the default selects only the `RustCrypto` backend. Hosts normally reach these through the `praxis-policy` facade,
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
//! | `jwt` | `plugins::identity_jwt`, verified with AWS-LC |
//! | `jwt-openssl-fips` | `plugins::identity_jwt`, verified with OpenSSL FIPS; requires `fips` |
//! | `api-key` | `plugins::identity_api_key` |
//! | `crypto-rustcrypto` | RustCrypto SHA-256 and HMAC; on by default |
//! | `fips` | OpenSSL FIPS SHA-256, shared by Policy, API-key and DPoP; no HMAC |
//! | `basic` | `plugins::identity_basic` |
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
compile_error!("select one Policy crypto backend: crypto-rustcrypto or fips");
#[cfg(all(
    feature = "api-key",
    not(any(feature = "crypto-rustcrypto", feature = "fips"))
))]
compile_error!("api-key requires crypto-rustcrypto or fips");
#[cfg(all(feature = "jwt", feature = "jwt-openssl-fips"))]
compile_error!("select one JWT backend: jwt or jwt-openssl-fips");
#[cfg(all(feature = "jwt-openssl-fips", not(feature = "fips")))]
compile_error!("jwt-openssl-fips requires the fips feature");
#[cfg(feature = "_plugins")]
pub mod plugins;

#[cfg(feature = "_pdps")]
pub mod pdps;

#[cfg(feature = "_secrets")]
pub mod secrets;

#[cfg(feature = "_session")]
pub mod session;

/// An enabled builtin that does its own crypto with `RustCrypto`, outside
/// the selected Policy backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BundledCryptoCapability {
    /// Basic `.htpasswd` password verification.
    ///
    /// The `basic` feature bundles argon2, bcrypt and sha-crypt, so all three
    /// are present whichever one a directory holds. Of the three, only
    /// sha-crypt (`$5$` / `$6$`) iterates a hash function FIPS 180-4
    /// specifies; that approves the function and not the password scheme
    /// built on it, and the implementation here is `RustCrypto`'s rather than
    /// a validated provider's.
    ///
    /// Which scheme a directory uses is settled when its file is read, after
    /// this report is computable, so an operator who has chosen sha-crypt
    /// confirms it from the directory's own configuration rather than here.
    BasicPasswordHashing,
    /// JWT signature verification and `DPoP` hashing with AWS-LC. Not
    /// listed under `jwt-openssl-fips`.
    Jwt,
    /// OAuth delegation cache-key HMAC.
    OAuth,
    /// Vault delegation cache-key hashing.
    VaultDelegation,
    /// Valkey session-key hashing.
    Valkey,
}

/// List the enabled builtins that do their own crypto.
#[must_use]
pub fn bundled_crypto_capabilities() -> Vec<BundledCryptoCapability> {
    vec![
        #[cfg(feature = "basic")]
        BundledCryptoCapability::BasicPasswordHashing,
        #[cfg(feature = "jwt")]
        BundledCryptoCapability::Jwt,
        #[cfg(feature = "oauth")]
        BundledCryptoCapability::OAuth,
        #[cfg(feature = "delegator-vault")]
        BundledCryptoCapability::VaultDelegation,
        #[cfg(feature = "valkey")]
        BundledCryptoCapability::Valkey,
    ]
}

#[cfg(any(feature = "valkey", feature = "elicitation-ciba"))]
mod env_secret;
