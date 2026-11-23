// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The config block an operator writes, and what it rejects at load.

use std::path::PathBuf;

use praxis_policy_core::extensions::raw_credentials::{Credential, TokenRole};
use praxis_policy_core::identity::credential::CredentialLocation;
use praxis_policy_core::identity::mapping::{
    ClaimMapConfig, ClaimsOverrides, ConfiguredClaimMap, MappingProfile,
};
use serde::{Deserialize, Serialize};

use crate::token_lookup::cache::CacheConfig;
use crate::validation::https::require_https_url;

/// What a mapped workload identity records as its attestor.
pub const ATTESTOR: &str = "kubernetes_token_review";

fn default_refresh_secs() -> u64 {
    60
}

fn default_role() -> TokenRole {
    TokenRole::User
}

fn default_timeout_secs() -> u64 {
    5
}

/// The `config:` block under a `kind: identity/kubernetes-token-review` plugin.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenReviewResolverConfig {
    /// The API server the token is reviewed by.
    pub api_server: ApiServerConfig,

    /// Audiences the token must be intended for, checked against
    /// `status.audiences`. Empty means the API server's own audience.
    #[serde(default)]
    pub audiences: Vec<String>,

    /// Reuse the API server's answers. **`ttl_secs` is the revocation window**,
    /// capped by a JWT's own `exp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,

    /// Which fields the projected claims bag keeps or drops.
    #[serde(default)]
    pub claims: ClaimsOverrides,

    /// Where the token sits on the request.
    pub credential: Credential,

    /// What a value at that location must start with to be one this resolver
    /// services. An auth scheme in it is stripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,

    /// `status.user` fields onto the identity slots: `username`, `uid`,
    /// `groups` and `extra`.
    pub record_map: ClaimMapConfig,

    /// Which identity slot this resolver fills.
    #[serde(default = "default_role")]
    pub role: TokenRole,
}

/// Where the API server is, and how PPE authenticates to it. TLS trust belongs
/// to the host's transport.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiServerConfig {
    /// Bound on connection establishment alone. Left to the transport when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,

    /// PPE's own bearer token, which needs `create` on `tokenreviews`.
    pub reviewer_token: ReviewerTokenSource,

    /// Overall deadline for one review, covering connect and I/O.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// The API server's base URL, such as `https://kubernetes.default.svc`.
    pub url: String,
}

/// Where PPE's own token comes from.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum ReviewerTokenSource {
    /// An environment variable, read once at load.
    Env {
        /// The variable holding the token.
        name: String,
    },
    /// A file, re-read once `refresh_secs` has passed so a projected token
    /// rotates.
    File {
        /// Path to the token, such as
        /// `/var/run/secrets/kubernetes.io/serviceaccount/token`.
        path: PathBuf,
        /// How long a read is reused before the file is read again.
        #[serde(default = "default_refresh_secs")]
        refresh_secs: u64,
    },
}

impl TokenReviewResolverConfig {
    /// The location and its prefix, paired as the extraction path wants them.
    pub fn location(&self) -> CredentialLocation {
        CredentialLocation::new(self.credential.clone(), self.prefix.clone())
    }

    /// Reject what cannot work, and return the mapper the checking produced.
    ///
    /// # Errors
    ///
    /// A location no request can satisfy, a `record_map` the shared compiler
    /// refuses or with no section for the configured role, a URL that is not
    /// an HTTPS base URL with a host, a zero timeout or refresh interval, or
    /// an empty audience.
    pub fn validate(&self) -> Result<ConfiguredClaimMap, String> {
        self.location().validate()?;
        let compiled = self
            .record_map
            .compile()?
            .with_claims(self.claims.compile()?);
        let mapper = ConfiguredClaimMap::new(
            compiled,
            MappingProfile {
                reserved_names: &[],
                attestor: ATTESTOR,
            },
        );
        mapper.compiled().role(&self.role).map_err(|e| {
            format!(
                "`record_map` has no section for `role: {:?}`: {e}",
                self.role
            )
        })?;

        validate_api_server_url(&self.api_server.url)?;
        if self.api_server.timeout_secs == 0 {
            return Err("`api_server.timeout_secs` is zero, so every review would time out".into());
        }
        if let ReviewerTokenSource::File {
            refresh_secs: 0, ..
        } = self.api_server.reviewer_token
        {
            return Err("`reviewer_token.refresh_secs` is zero; omit it for the default".into());
        }
        if self
            .audiences
            .iter()
            .any(|audience| audience.trim().is_empty())
        {
            return Err("`audiences` has an empty entry".into());
        }
        Ok(mapper)
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Require an HTTPS base URL the review path can be appended to. A query or
/// fragment would end up in front of the appended path.
fn validate_api_server_url(raw: &str) -> Result<(), String> {
    let url = require_https_url("api_server.url", raw)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "`api_server.url` must be a base URL without a query or fragment, got '{raw}'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_api_server_url;

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn an_https_base_url_with_a_host_is_accepted() {
        for url in [
            "https://kubernetes.default.svc",
            "https://localhost:6443",
            "https://proxy.example/k8s/",
        ] {
            assert_eq!(
                validate_api_server_url(url),
                Ok(()),
                "{url} should be accepted"
            );
        }
    }

    #[test]
    fn a_query_or_a_fragment_is_rejected() {
        for url in [
            "https://kubernetes.default.svc?x=1",
            "https://kubernetes.default.svc#frag",
        ] {
            assert!(
                validate_api_server_url(url).is_err(),
                "{url} must be rejected"
            );
        }
    }
}
