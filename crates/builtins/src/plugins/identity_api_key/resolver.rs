// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::plugins::identity_api_key::config::{
    ApiKeyResolverConfig, ExpiryPolicy, ProviderConfig,
};
use crate::plugins::identity_api_key::file_directory::FileDirectory;
use crate::plugins::identity_api_key::http_directory::HttpDirectory;
use crate::token_lookup::crypto::API_KEY_CACHE;
use crate::token_lookup::directory::KeyDirectory;
use crate::token_lookup::resolver::{
    LookupProfile, LookupResolver, check_location_capability, config_error, parse_settings,
    with_cache,
};

/// Denial codes, which a host maps to a status.
///
/// Two phases, named differently on purpose.
///
/// **Extraction** codes are shared with the JWT resolver. Reading a credential
/// off the wire fails consistently across both plugins, so an operator's
/// runbook for `auth.missing_credential` applies to both.
///
/// **Lookup** codes are this plugin's own, because nothing else has them. In
/// particular `KEY_UNKNOWN` and `DIRECTORY_UNAVAILABLE` stay apart: both deny,
/// and an operator watching a spike cannot act until they know whether the
/// credentials are bad or the directory is down.
pub mod codes {
    pub use crate::token_lookup::resolver::codes::{
        AMBIGUOUS_CREDENTIAL, DIRECTORY_UNAVAILABLE, EMPTY_CREDENTIAL, MALFORMED_CREDENTIAL,
        MAPPING_FAILED, MISSING_CREDENTIAL,
    };

    /// The directory answered, and no record matched.
    pub const KEY_UNKNOWN: &str = "auth.key_unknown";
    /// A record matched and has expired.
    pub const KEY_EXPIRED: &str = "auth.key_expired";
}

/// Plugin-specific denial codes and cache labels.
const PROFILE: LookupProfile = LookupProfile {
    cache_hash: API_KEY_CACHE,
    expired_code: codes::KEY_EXPIRED,
    unknown_code: codes::KEY_UNKNOWN,
};

/// Resolves an API key to an identity.
#[derive(Debug)]
pub struct ApiKeyIdentityResolver {
    config: PluginConfig,
    lookup: LookupResolver,
}

impl ApiKeyIdentityResolver {
    /// Build a resolver from its `config:` block.
    ///
    /// # Errors
    ///
    /// `PluginError::Config` for anything the settings, the record map, or the
    /// directory backend reject. The record file is read here, at config load,
    /// so an unreadable or malformed one stops startup instead of denying every
    /// request as though the credentials were bad.
    pub fn new(config: PluginConfig) -> Result<Self, Box<PluginError>> {
        let settings: ApiKeyResolverConfig = parse_settings(&config)?;
        // The mapper falls out of validation rather than being compiled a
        // second time from the same block.
        let mapper = settings.validate().map_err(|e| config_error(&config, e))?;

        let location = settings.location();
        check_location_capability(&config, &location)?;

        let directory: Arc<dyn KeyDirectory> = match &settings.provider {
            ProviderConfig::File(file) => {
                Arc::new(FileDirectory::new(file.clone()).map_err(|e| config_error(&config, e))?)
            },
            ProviderConfig::Http(http) => {
                Arc::new(HttpDirectory::new(http.clone()).map_err(|e| config_error(&config, e))?)
            },
        };
        let directory = with_cache(&config, directory, settings.cache.as_ref(), &PROFILE)?;

        let lookup = LookupResolver::new(
            directory,
            settings.expiry == ExpiryPolicy::Enforce,
            location,
            mapper,
            PROFILE,
            settings.role,
        );
        Ok(Self { config, lookup })
    }
}

#[async_trait::async_trait]
impl Plugin for ApiKeyIdentityResolver {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<IdentityHook> for ApiKeyIdentityResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        self.lookup.resolve(payload, ext).await
    }
}
