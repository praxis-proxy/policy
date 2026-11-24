// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::plugins::identity_kubernetes::config::TokenReviewResolverConfig;
use crate::plugins::identity_kubernetes::token_review::TokenReviewDirectory;
use crate::token_lookup::crypto::HashLabels;
use crate::token_lookup::resolver::{
    LookupProfile, LookupResolver, check_location_capability, config_error, parse_settings,
    with_cache,
};

/// Denial codes, which a host maps to a status.
///
/// Extraction codes, `DIRECTORY_UNAVAILABLE` and `MAPPING_FAILED` are shared
/// with the API key resolver. `TOKEN_EXPIRED` matches the JWT resolver's.
pub mod codes {
    pub use crate::token_lookup::resolver::codes::{
        AMBIGUOUS_CREDENTIAL, DIRECTORY_UNAVAILABLE, EMPTY_CREDENTIAL, MALFORMED_CREDENTIAL,
        MAPPING_FAILED, MISSING_CREDENTIAL,
    };

    /// The API server answered and did not authenticate the token, or
    /// authenticated it for none of the configured audiences.
    pub const TOKEN_UNAUTHENTICATED: &str = "auth.token_unauthenticated";
    /// A cached answer outlived the token's own `exp`.
    pub const TOKEN_EXPIRED: &str = "auth.token_expired";
}

/// How a failure to hash a token for the cache is reported.
const CACHE_HASH: HashLabels = HashLabels {
    failure: "token hashing failed",
    op: "kubernetes_token_review_cache",
};

/// Plugin-specific denial codes and cache labels.
const PROFILE: LookupProfile = LookupProfile {
    cache_hash: CACHE_HASH,
    expired_code: codes::TOKEN_EXPIRED,
    unknown_code: codes::TOKEN_UNAUTHENTICATED,
};

/// Resolves a bearer token to an identity through Kubernetes `TokenReview`.
#[derive(Debug)]
pub struct TokenReviewIdentityResolver {
    config: PluginConfig,
    lookup: LookupResolver,
}

impl TokenReviewIdentityResolver {
    /// Build a resolver from its `config:` block.
    ///
    /// # Errors
    ///
    /// `PluginError::Config` for anything the settings or the record map
    /// reject, a reviewer token that cannot be read, or a plugin entry without
    /// the `perform_http` capability, which every review needs.
    pub fn new(config: PluginConfig) -> Result<Self, Box<PluginError>> {
        let settings: TokenReviewResolverConfig = parse_settings(&config)?;
        let mapper = settings.validate().map_err(|e| config_error(&config, e))?;
        if !config.capabilities.contains("perform_http") {
            return Err(config_error(
                &config,
                "every review calls the API server, so the plugin needs the `perform_http` \
                 capability",
            ));
        }

        let location = settings.location();
        check_location_capability(&config, &location)?;

        if settings.audiences.is_empty() {
            tracing::warn!(
                plugin = %config.name,
                "no `audiences` set: any token the cluster accepts for its own API signs a \
                 caller in here, including one minted to call the API server",
            );
        }
        let directory = TokenReviewDirectory::new(&settings.api_server, settings.audiences)
            .map_err(|e| config_error(&config, e))?;
        let directory = with_cache(
            &config,
            Arc::new(directory),
            settings.cache.as_ref(),
            &PROFILE,
        )?;

        let lookup = LookupResolver::new(directory, true, location, mapper, PROFILE, settings.role);
        Ok(Self { config, lookup })
    }
}

#[async_trait::async_trait]
impl Plugin for TokenReviewIdentityResolver {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<IdentityHook> for TokenReviewIdentityResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        self.lookup.resolve(payload, ext).await
    }
}
