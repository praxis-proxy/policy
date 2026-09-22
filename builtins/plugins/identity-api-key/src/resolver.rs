// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `identity.resolve` handler.
//
// Read the credential, resolve it to a record, project the record onto the
// identity slots. The presented key is never written back: it does not reach
// `raw_credentials`, so nothing downstream can forward the caller's own
// credential to an upstream that never authenticated it.

use std::sync::Arc;

use chrono::Utc;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::extensions::raw_credentials::TokenRole;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::mapping::{ClaimMapper as _, ConfiguredClaimMap};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::config::{ApiKeyResolverConfig, DirectoryConfig, ExpiryPolicy};
use crate::credential::{CredentialLocation, Extraction};
use crate::directory::KeyDirectory;
use crate::file_directory::FileDirectory;
use crate::http_directory::HttpDirectory;
use crate::record_map;

/// Denial codes, which a host maps to a status.
///
/// Two phases, named differently on purpose.
///
/// **Extraction** codes are shared with the JWT resolver, spelled as PR #96
/// spells them. Reading a credential off the wire fails the same way whatever
/// the credential turns out to be, so an operator's runbook for
/// `auth.missing_credential` has to hold across plugins.
///
/// **Lookup** codes are this plugin's own, because nothing else has them. In
/// particular `KEY_UNKNOWN` and `DIRECTORY_UNAVAILABLE` stay apart: both deny,
/// and an operator watching a spike cannot act until they know whether the
/// credentials are bad or the directory is down.
pub mod codes {
    /// Nothing was supplied at the configured location.
    pub const MISSING_CREDENTIAL: &str = "auth.missing_credential";
    /// The location held a value and it was empty.
    pub const EMPTY_CREDENTIAL: &str = "auth.empty_credential";
    /// The directory answered, and no record matched.
    pub const KEY_UNKNOWN: &str = "auth.key_unknown";
    /// A record matched and has expired.
    pub const KEY_EXPIRED: &str = "auth.key_expired";
    /// The directory could not answer.
    pub const DIRECTORY_UNAVAILABLE: &str = "auth.directory_unavailable";
    /// A record resolved and the map could not project it.
    pub const MAPPING_FAILED: &str = "auth.mapping_failed";
}

/// Resolves an API key to an identity.
#[derive(Debug)]
pub struct ApiKeyIdentityResolver {
    config: PluginConfig,
    settings: ApiKeyResolverConfig,
    directory: Arc<dyn KeyDirectory>,
    mapper: ConfiguredClaimMap,
    location: CredentialLocation,
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
        let block = config.config.clone().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!("{}: `config:` block is required", config.name),
            })
        })?;
        let settings: ApiKeyResolverConfig =
            serde_json::from_value(block).map_err(|e| PluginError::Config {
                message: format!("{}: {e}", config.name),
            })?;
        settings.validate().map_err(|e| PluginError::Config {
            message: format!("{}: {e}", config.name),
        })?;

        let mapper = record_map::compile(&settings.record_map, &settings.claims).map_err(|e| {
            PluginError::Config {
                message: format!("{}: {e}", config.name),
            }
        })?;

        let directory: Arc<dyn KeyDirectory> = match &settings.directory {
            DirectoryConfig::File(file) => Arc::new(FileDirectory::new(file.clone()).map_err(
                |e| PluginError::Config {
                    message: format!("{}: {e}", config.name),
                },
            )?),
            DirectoryConfig::Http(http) => Arc::new(HttpDirectory::new(http.clone()).map_err(
                |e| PluginError::Config {
                    message: format!("{}: {e}", config.name),
                },
            )?),
        };

        let location = settings.location();
        Ok(Self {
            config,
            settings,
            directory,
            mapper,
            location,
        })
    }

    /// The backend this resolver queries.
    pub fn directory(&self) -> &Arc<dyn KeyDirectory> {
        &self.directory
    }

    /// The compiled record map.
    pub fn mapper(&self) -> &ConfiguredClaimMap {
        &self.mapper
    }

    /// The settings this resolver runs.
    pub fn settings(&self) -> &ApiKeyResolverConfig {
        &self.settings
    }

    /// The plugin config this resolver was built from.
    pub fn plugin_config(&self) -> &PluginConfig {
        &self.config
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
        let location = &self.location;

        let presented = match location.extract(payload.headers()) {
            Extraction::Found => match location.presented(payload.headers()) {
                Some(key) => key,
                // `extract` said Found, so this is unreachable. Denying rather
                // than unwrapping keeps a future divergence between the two a
                // rejected request instead of a panicked worker.
                None => {
                    return PluginResult::deny(PluginViolation::new(
                        codes::MISSING_CREDENTIAL,
                        format!("no credential at {}", location.credential),
                    ));
                },
            },
            Extraction::Missing => {
                return PluginResult::deny(PluginViolation::new(
                    codes::MISSING_CREDENTIAL,
                    format!("no credential at {}", location.credential),
                ));
            },
            Extraction::Empty => {
                return PluginResult::deny(PluginViolation::new(
                    codes::EMPTY_CREDENTIAL,
                    format!("{} holds an empty credential", location.credential),
                ));
            },
            // Another resolver's key population. Declining leaves the payload
            // untouched for whoever does service it; denying here would make
            // two populations on one route impossible.
            Extraction::WrongPrefix => return PluginResult::allow(),
        };

        // `Extensions` is the request's carrier of host services, already
        // capability filtered by the executor, so a backend that needs egress
        // reaches it through the same value every hook receives.
        let record = match self.directory.lookup(&presented, ext).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                return PluginResult::deny(PluginViolation::new(
                    codes::KEY_UNKNOWN,
                    "no record matches the presented credential",
                ));
            },
            Err(error) => {
                // Deliberately not the same code as a miss. An operator
                // watching a denial spike cannot act until they know whether
                // the credentials are bad or the directory is down.
                tracing::warn!(
                    directory = self.directory.kind(),
                    %error,
                    "api key directory could not answer",
                );
                return PluginResult::deny(PluginViolation::new(
                    codes::DIRECTORY_UNAVAILABLE,
                    "the key directory could not answer",
                ));
            },
        };

        if self.settings.expiry == ExpiryPolicy::Enforce
            && let Some(expires_at) = record.expires_at
            && expires_at <= Utc::now()
        {
            return PluginResult::deny(PluginViolation::new(
                codes::KEY_EXPIRED,
                "the credential's record has expired",
            ));
        }

        let mut updated = payload.clone();
        match &self.settings.role {
            TokenRole::User => match self.mapper.map_subject(&record.fields) {
                Some(subject) => updated.subject = Some(subject),
                None => return mapping_failed("subject"),
            },
            TokenRole::Client => match self.mapper.map_client(&record.fields) {
                Some(client) => updated.client = Some(client),
                None => return mapping_failed("client"),
            },
            TokenRole::CallerWorkload => match self.mapper.map_workload(&record.fields) {
                Some(workload) => updated.caller_workload = Some(workload),
                None => return mapping_failed("workload"),
            },
            // `TokenRole` is `#[non_exhaustive]`, and `validate` refuses a role
            // with no section. Surfacing as misconfigured rather than silently
            // authenticating nobody.
            other => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.misconfigured",
                    format!("role {other:?} is not supported"),
                ));
            },
        }

        updated.resolved_at = Some(Utc::now());
        // `raw_credentials` is deliberately not populated. The presented key
        // stops here, so no downstream step can forward a caller's own
        // credential to an upstream that never authenticated it.
        PluginResult::modify_payload(updated)
    }
}

/// The denial for a record the map could not project.
fn mapping_failed(slot: &str) -> PluginResult<IdentityPayload> {
    PluginResult::deny(PluginViolation::new(
        codes::MAPPING_FAILED,
        format!(
            "the record map produced no {slot}: no candidate resolved for the anchor, or a \
             field declaring `on_missing: deny` resolved nothing. Raise the log level to debug \
             to see which fields and which paths were tried"
        ),
    ))
}
