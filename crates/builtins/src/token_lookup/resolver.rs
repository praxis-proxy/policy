// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Presented tokens must not reach `raw_credentials`, where downstream plugins
// could forward them to an upstream that never authenticated the caller.

use std::sync::Arc;

use chrono::Utc;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::extensions::raw_credentials::{Credential, TokenRole};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::PluginResult;
use praxis_policy_core::identity::IdentityPayload;
use praxis_policy_core::identity::credential::{CredentialLocation, ExtractionError};
use praxis_policy_core::identity::mapping::{ClaimMapper as _, ConfiguredClaimMap};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};
use serde::de::DeserializeOwned;

use crate::token_lookup::cache::{CacheConfig, CachingDirectory};
use crate::token_lookup::crypto::HashLabels;
use crate::token_lookup::directory::{KeyDirectory, PresentedKey};

/// Denial codes every lookup resolver shares.
///
/// `DIRECTORY_UNAVAILABLE` distinguishes backend outages from unrecognized
/// credentials. Extraction codes match the JWT resolver's.
pub(crate) mod codes {
    /// Nothing was supplied at the configured location.
    pub const MISSING_CREDENTIAL: &str = "auth.missing_credential";
    /// The location held a value and it was empty.
    pub const EMPTY_CREDENTIAL: &str = "auth.empty_credential";
    /// The credential name appeared more than once.
    pub const AMBIGUOUS_CREDENTIAL: &str = "auth.ambiguous_credential";
    /// The credential input is structurally malformed.
    pub const MALFORMED_CREDENTIAL: &str = "auth.malformed_credential";
    /// The directory could not answer.
    pub const DIRECTORY_UNAVAILABLE: &str = "auth.directory_unavailable";
    /// A record resolved and the map could not project it.
    pub const MAPPING_FAILED: &str = "auth.mapping_failed";
}

/// What differs between one lookup resolver and another.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LookupProfile {
    /// How the cache reports a failure to hash a credential.
    pub(crate) cache_hash: HashLabels,
    /// Denial code for a record past its `expires_at`.
    pub(crate) expired_code: &'static str,
    /// Denial code for a credential the directory did not recognise.
    pub(crate) unknown_code: &'static str,
}

/// Resolves a presented credential to an identity through a directory.
#[derive(Debug)]
pub(crate) struct LookupResolver {
    directory: Arc<dyn KeyDirectory>,
    enforce_expiry: bool,
    location: CredentialLocation,
    mapper: ConfiguredClaimMap,
    profile: LookupProfile,
    role: TokenRole,
}

impl LookupResolver {
    /// Assemble a resolver from parts a plugin has already validated.
    pub(crate) fn new(
        directory: Arc<dyn KeyDirectory>,
        enforce_expiry: bool,
        location: CredentialLocation,
        mapper: ConfiguredClaimMap,
        profile: LookupProfile,
        role: TokenRole,
    ) -> Self {
        Self {
            directory,
            enforce_expiry,
            location,
            mapper,
            profile,
            role,
        }
    }

    /// The `identity.resolve` outcome for one request.
    pub(crate) async fn resolve(
        &self,
        payload: &IdentityPayload,
        ext: &Extensions,
    ) -> PluginResult<IdentityPayload> {
        let location = &self.location;

        let presented = match location.raw_from_ext(payload.headers(), ext) {
            Ok(key) => PresentedKey::new(key.into_bytes()),
            Err(ExtractionError::Missing) => {
                return PluginResult::deny(PluginViolation::new(
                    codes::MISSING_CREDENTIAL,
                    format!("no credential at {}", location.credential),
                ));
            },
            Err(ExtractionError::Empty) => {
                return PluginResult::deny(PluginViolation::new(
                    codes::EMPTY_CREDENTIAL,
                    format!("{} holds an empty credential", location.credential),
                ));
            },
            // Another resolver's credential population. Carry the decline to
            // the executor while leaving identity slots untouched for whoever
            // services it; denying here would make two populations impossible.
            Err(ExtractionError::WrongPrefix) => {
                let mut updated = payload.clone();
                updated.mark_credential_declined();
                return PluginResult::modify_payload(updated);
            },
            Err(ExtractionError::Ambiguous) => {
                return PluginResult::deny(PluginViolation::new(
                    codes::AMBIGUOUS_CREDENTIAL,
                    format!("ambiguous credential at {}", location.credential),
                ));
            },
            Err(ExtractionError::Malformed) => {
                return PluginResult::deny(PluginViolation::new(
                    codes::MALFORMED_CREDENTIAL,
                    format!("malformed credential at {}", location.credential),
                ));
            },
            Err(_) => {
                return PluginResult::deny(PluginViolation::new(
                    codes::MISSING_CREDENTIAL,
                    format!("unexpected extraction outcome at {}", location.credential),
                ));
            },
        };

        // The invocation's filtered services keep directory egress under its grants.
        let record = match self.directory.lookup(&presented, ext).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                return PluginResult::deny(PluginViolation::new(
                    self.profile.unknown_code,
                    "no record matches the presented credential",
                ));
            },
            Err(error) => {
                tracing::warn!(
                    directory = self.directory.kind(),
                    %error,
                    "credential directory could not answer",
                );
                return PluginResult::deny(PluginViolation::new(
                    codes::DIRECTORY_UNAVAILABLE,
                    "the key directory could not answer",
                ));
            },
        };

        if self.enforce_expiry
            && let Some(expires_at) = record.expires_at
            && expires_at <= Utc::now()
        {
            return PluginResult::deny(PluginViolation::new(
                self.profile.expired_code,
                "the credential's record has expired",
            ));
        }

        let mut updated = payload.clone();
        match &self.role {
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
            // Unsupported roles must fail instead of authenticating without an identity.
            other => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.misconfigured",
                    format!("role {other:?} is not supported"),
                ));
            },
        }

        updated.resolved_at = Some(Utc::now());
        PluginResult::modify_payload(updated)
    }
}

/// Parse a lookup resolver's `config:` block, refusing a plugin entry it
/// cannot run under.
///
/// # Errors
///
/// `PluginError::Config` for a mode other than `sequential` with `on_error:
/// fail`, a missing `config:` block, or one that does not deserialize.
pub(crate) fn parse_settings<T: DeserializeOwned>(
    config: &PluginConfig,
) -> Result<T, Box<PluginError>> {
    if config.mode != PluginMode::Sequential || config.on_error != OnError::Fail {
        return Err(config_error(
            config,
            "an identity resolver needs `mode: sequential` and `on_error: fail`",
        ));
    }
    let block = config
        .config
        .clone()
        .ok_or_else(|| config_error(config, "`config:` block is required"))?;
    serde_json::from_value(block).map_err(|e| config_error(config, e))
}

/// Refuse a query parameter location the plugin was not granted.
///
/// # Errors
///
/// `PluginError::Config` when `location` reads a query parameter and the
/// plugin lacks `read_query`.
pub(crate) fn check_location_capability(
    config: &PluginConfig,
    location: &CredentialLocation,
) -> Result<(), Box<PluginError>> {
    if matches!(location.credential, Credential::QueryParam { .. })
        && !config.capabilities.contains("read_query")
    {
        return Err(config_error(
            config,
            "`credential.kind: query_param` needs the `read_query` capability",
        ));
    }
    Ok(())
}

/// Put a cache in front of `directory` when one is configured.
///
/// # Errors
///
/// `PluginError::Config` for whatever [`CacheConfig::validate`] rejects.
///
/// [`CacheConfig::validate`]: crate::token_lookup::cache::CacheConfig::validate
pub(crate) fn with_cache(
    config: &PluginConfig,
    directory: Arc<dyn KeyDirectory>,
    cache: Option<&CacheConfig>,
    profile: &LookupProfile,
) -> Result<Arc<dyn KeyDirectory>, Box<PluginError>> {
    match cache {
        Some(cache) => Ok(Arc::new(
            CachingDirectory::new(directory, cache.clone())
                .map_err(|e| config_error(config, e))?
                .with_hash_labels(profile.cache_hash),
        )),
        None => Ok(directory),
    }
}

/// A config error that names the plugin entry it came from.
pub(crate) fn config_error(
    config: &PluginConfig,
    error: impl std::fmt::Display,
) -> Box<PluginError> {
    Box::new(PluginError::Config {
        message: format!("{}: {error}", config.name),
    })
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
