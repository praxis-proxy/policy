// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The config block an operator writes, and what it rejects at load.
//
// Everything checkable is checked here. A resolver that builds and then denies
// every request reads as an outage, and the operator looking at it is reading
// the wrong logs.

use praxis_policy_core::extensions::raw_credentials::TokenRole;
use praxis_policy_core::identity::mapping::{ClaimMapConfig, ClaimsOverrides};
use serde::{Deserialize, Serialize};

use crate::credential::{Credential, CredentialLocation};
use crate::file_directory::FileDirectoryConfig;

/// Which backend holds the records.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DirectoryConfig {
    /// Records in a file, indexed by digest.
    File(FileDirectoryConfig),
}

/// What to do when the directory cannot answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDirectoryError {
    /// Deny, with a reason that says the directory failed rather than that the
    /// credential was unknown.
    #[default]
    Deny,
}

/// Who enforces a record's expiry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryPolicy {
    /// Compare `expires_at` here when the record carries one.
    ///
    /// The default, because on the file path nothing else is positioned to.
    /// This is enforcement only: removing expired records belongs to whatever
    /// owns the storage.
    #[default]
    Enforce,
    /// Trust the directory to have applied it.
    Directory,
}

/// The `config:` block under a `kind: identity/api-key` plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyResolverConfig {
    /// Where the credential sits on the request.
    ///
    /// Exactly PR #96's `Credential` shape, so adopting the shared type when it
    /// merges changes no operator's YAML.
    pub credential: Credential,

    /// What a value at that location must start with to be one this resolver
    /// services.
    ///
    /// An auth scheme in it is stripped; the rest stays part of the credential,
    /// because it is part of the credential. With `Bearer sk-oai-`, a request
    /// carrying `Bearer sk-oai-abc` looks up `sk-oai-abc`.
    ///
    /// A sibling of `credential:` rather than a field inside it: a prefix says
    /// which key population a credential is from, not where it was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,

    /// Where the records live.
    pub directory: DirectoryConfig,

    /// Record fields onto the identity slots.
    #[serde(default)]
    pub record_map: ClaimMapConfig,

    /// Which fields the projected claims bag keeps or drops.
    #[serde(default)]
    pub claims: ClaimsOverrides,

    /// Which identity slot this resolver fills.
    ///
    /// An API key names a workload as often as it names a person, so this is
    /// not fixed to the subject.
    #[serde(default = "default_role")]
    pub role: TokenRole,

    /// What a directory failure does.
    #[serde(default)]
    pub on_directory_error: OnDirectoryError,

    /// Who enforces a record's expiry.
    #[serde(default)]
    pub expiry: ExpiryPolicy,
}

fn default_role() -> TokenRole {
    TokenRole::User
}

impl ApiKeyResolverConfig {
    /// The location and its prefix, paired as the extraction path wants them.
    pub fn location(&self) -> CredentialLocation {
        CredentialLocation::new(self.credential.clone(), self.prefix.clone())
    }

    /// Reject what cannot work, before a request depends on it.
    ///
    /// # Errors
    ///
    /// A location no request can satisfy, a `record_map` the shared compiler
    /// refuses, or a map with no section for the configured role, which would
    /// decline every credential.
    pub fn validate(&self) -> Result<(), String> {
        self.location().validate()?;
        let mapper = crate::record_map::compile(&self.record_map, &self.claims)?;
        // A map that declares no section for the role this resolver fills maps
        // nothing, every time, and the resulting `auth.mapping_failed` names a
        // record rather than the config that cannot project one.
        mapper.compiled().role(&self.role).map_err(|e| {
            format!(
                "`record_map` has no section for `role: {:?}`: {e}",
                self.role
            )
        })?;
        Ok(())
    }
}
