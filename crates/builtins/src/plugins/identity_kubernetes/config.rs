// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use praxis_policy_core::extensions::raw_credentials::{Credential, TokenRole};
use praxis_policy_core::identity::credential::CredentialLocation;
use praxis_policy_core::identity::mapping::{
    ClaimMapConfig, ClaimsOverrides, ConfiguredClaimMap, MappingProfile,
};
use serde::{Deserialize, Serialize};

pub use crate::kubernetes::{ApiServerConfig, ReviewerTokenSource};
use crate::token_lookup::cache::CacheConfig;

/// What a mapped workload identity records as its attestor.
pub const ATTESTOR: &str = "kubernetes_token_review";

fn default_role() -> TokenRole {
    TokenRole::User
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

    /// Cache answers for up to `ttl_secs`, capped by a JWT's own `exp`.
    /// This adds to the API server's own revocation delay.
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

impl TokenReviewResolverConfig {
    /// The location and its prefix, paired as the extraction path wants them.
    pub fn location(&self) -> CredentialLocation {
        CredentialLocation::new(self.credential.clone(), self.prefix.clone())
    }

    /// Validate the settings and compile the identity mapping.
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

        self.api_server.validate()?;
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
