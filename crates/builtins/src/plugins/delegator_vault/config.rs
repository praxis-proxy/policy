// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Top-level configuration for the Vault delegator plugin.
///
/// ```yaml
/// config:
///   vault_addr: "https://vault.example.com:8200"
///   kv_mount: "secret"
///   secret_path_template: "agents/{{sub}}/github"
///   secret_field: "token"
///   identity_claim: "sub"
///   outbound_header: "Authorization"
///   timeout_seconds: 5
///   auth:
///     user:
///       method: jwt
///       mount: "jwt"
///       role: "ppe-user"
///     this_workload:
///       method: approle
///       mount: "approle"
///       role_id_source: { kind: env_var, name: VAULT_ROLE_ID }
///       secret_id_source: { kind: env_var, name: VAULT_SECRET_ID }
///   cache:
///     enabled: true
///     ttl_seconds: 300
///     max_entries: 10000
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultDelegatorConfig {
    /// Vault base URL (e.g. `https://vault.example.com:8200`).
    pub vault_addr: String,

    /// KV v2 mount path.
    #[serde(default = "default_kv_mount")]
    pub kv_mount: String,

    /// Secret path template. `{{<identity_claim>}}` is replaced with the
    /// resolved claim value at delegation time.
    ///
    /// This template is the contract between the enrollment workflow (how
    /// users store credentials in Vault) and this handler. For example,
    /// if the template is `agents/{{sub}}/github`, a user with `sub=alice`
    /// must write their GitHub PAT to `secret/data/agents/alice/github`
    /// in the configured KV v2 mount. The enrollment mechanism is out of
    /// scope for this handler — it may be Vault CLI, a self-service UI,
    /// or an infrastructure pipeline — but the path convention must be
    /// documented for operators and communicated to end-users.
    pub secret_path_template: String,

    /// Which field in the KV v2 data object holds the credential.
    #[serde(default = "default_secret_field")]
    pub secret_field: String,

    /// Claim name resolved from the authenticated principal for path
    /// templating. The claim source depends on the delegation subject.
    #[serde(default = "default_identity_claim")]
    pub identity_claim: String,

    /// Header name for the outbound credential. The host's outbound
    /// filter adds the scheme (`Bearer`, `token`, …) — the token value
    /// stored here is unprefixed.
    #[serde(default = "default_outbound_header")]
    pub outbound_header: String,

    /// HTTP timeout for Vault calls, in seconds.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    /// Allow `http://` (for development only).
    #[serde(default)]
    pub insecure_http: bool,

    /// Auth method per delegation subject. Keys are subject names:
    /// `user`, `client`, `caller_workload`, `this_workload`.
    /// No default — if a subject is not listed, delegation for that
    /// subject fails with a clear error.
    pub auth: HashMap<String, VaultAuthMethod>,

    /// Credential cache configuration.
    #[serde(default)]
    pub cache: CacheConfig,
}

/// Vault authentication method.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum VaultAuthMethod {
    /// Vault JWT auth — PPE sends the caller's JWT to Vault.
    Jwt {
        /// Auth method mount path (default `"jwt"`).
        #[serde(default = "default_jwt_mount")]
        mount: String,
        /// Vault role name.
        role: String,
    },
    /// Vault `AppRole` auth — PPE authenticates as itself.
    #[serde(rename = "approle")]
    AppRole {
        /// Auth method mount path (default `"approle"`).
        #[serde(default = "default_approle_mount")]
        mount: String,
        /// Source for the `role_id` credential.
        role_id_source: CredentialSource,
        /// Source for the `secret_id` credential.
        secret_id_source: CredentialSource,
    },
}

/// Where to read a secret value at construction time.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialSource {
    /// Read from an environment variable.
    EnvVar {
        /// Environment variable holding the secret.
        name: String,
    },
    /// Read from a file path (e.g. a Kubernetes secret volume).
    File {
        /// Path to the file holding the secret.
        path: PathBuf,
    },
    /// Inline value. Avoid outside local development.
    Literal {
        /// The secret inline.
        secret: String,
    },
}

impl std::fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvVar { name } => f.debug_struct("EnvVar").field("name", name).finish(),
            Self::File { path } => f.debug_struct("File").field("path", path).finish(),
            Self::Literal { .. } => f
                .debug_struct("Literal")
                .field("secret", &"[REDACTED]")
                .finish(),
        }
    }
}

impl CredentialSource {
    /// Zeroize inline literal secrets after they have been resolved.
    pub(crate) fn redact(&mut self) {
        if let CredentialSource::Literal { secret } = self {
            zeroize::Zeroize::zeroize(secret);
        }
    }

    /// Resolve the secret at construction time.
    ///
    /// The secret itself never appears in the error message.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the environment variable is unset or the file is
    /// unreadable.
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            Self::EnvVar { name } => {
                std::env::var(name).map_err(|e| format!("env var '{name}' unavailable: {e}"))
            },
            Self::File { path } => std::fs::read_to_string(path)
                .map(|s| s.trim().to_owned())
                .map_err(|e| format!("secret file '{}' unreadable: {e}", path.display())),
            Self::Literal { secret } => Ok(secret.clone()),
        }
    }
}

/// Credential cache configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Whether caching is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// How long a resolved credential is reused before re-reading from
    /// Vault. Also sets `expires_at` on `RawDelegatedToken`, documenting
    /// the upper bound on how long a revoked credential stays usable.
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,

    /// Maximum cache entries.
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: default_ttl_seconds(),
            max_entries: default_max_entries(),
        }
    }
}

impl CacheConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.ttl_seconds == 0 {
            return Err("cache.ttl_seconds must be > 0".into());
        }
        let secs = i64::try_from(self.ttl_seconds)
            .map_err(|_overflow| "cache.ttl_seconds exceeds i64::MAX".to_owned())?;
        if chrono::TimeDelta::try_seconds(secs).is_none() {
            return Err("cache.ttl_seconds is too large for duration arithmetic".into());
        }
        if self.enabled && self.max_entries == 0 {
            return Err("cache.max_entries must be > 0 when cache is enabled".into());
        }
        Ok(())
    }
}

impl VaultAuthMethod {
    /// Zeroize literal secrets embedded in credential sources after resolution.
    pub(crate) fn redact_sources(&mut self) {
        if let VaultAuthMethod::AppRole {
            role_id_source,
            secret_id_source,
            ..
        } = self
        {
            role_id_source.redact();
            secret_id_source.redact();
        }
    }
}

impl VaultDelegatorConfig {
    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

fn default_kv_mount() -> String {
    "secret".to_owned()
}

fn default_secret_field() -> String {
    "token".to_owned()
}

fn default_identity_claim() -> String {
    "sub".to_owned()
}

fn default_outbound_header() -> String {
    "Authorization".to_owned()
}

fn default_timeout_seconds() -> u64 {
    5
}

fn default_jwt_mount() -> String {
    "jwt".to_owned()
}

fn default_approle_mount() -> String {
    "approle".to_owned()
}

fn default_ttl_seconds() -> u64 {
    300
}

fn default_max_entries() -> u64 {
    10_000
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::assertions_on_result_states,
    reason = "tests"
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_deserializes_with_defaults() {
        let raw = json!({
            "vault_addr": "https://vault.example.com:8200",
            "secret_path_template": "agents/{{sub}}/github",
            "auth": {
                "user": {
                    "method": "jwt",
                    "role": "ppe-user"
                }
            }
        });
        let cfg: VaultDelegatorConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.vault_addr, "https://vault.example.com:8200");
        assert_eq!(cfg.kv_mount, "secret");
        assert_eq!(cfg.secret_field, "token");
        assert_eq!(cfg.identity_claim, "sub");
        assert_eq!(cfg.outbound_header, "Authorization");
        assert_eq!(cfg.timeout_seconds, 5);
        assert!(!cfg.insecure_http);
        assert!(!cfg.cache.enabled);
    }

    #[test]
    fn jwt_auth_method_deserializes() {
        let raw = json!({
            "method": "jwt",
            "mount": "jwt-prod",
            "role": "ppe-user"
        });
        let auth: VaultAuthMethod = serde_json::from_value(raw).unwrap();
        match auth {
            VaultAuthMethod::Jwt { mount, role } => {
                assert_eq!(mount, "jwt-prod");
                assert_eq!(role, "ppe-user");
            },
            _ => panic!("expected Jwt variant"),
        }
    }

    #[test]
    fn approle_auth_method_deserializes() {
        let raw = json!({
            "method": "approle",
            "role_id_source": { "kind": "literal", "secret": "role-id" },
            "secret_id_source": { "kind": "env_var", "name": "VAULT_SECRET_ID" }
        });
        let auth: VaultAuthMethod = serde_json::from_value(raw).unwrap();
        match auth {
            VaultAuthMethod::AppRole { mount, .. } => {
                assert_eq!(mount, "approle");
            },
            _ => panic!("expected AppRole variant"),
        }
    }

    #[test]
    fn literal_source_resolves() {
        let src = CredentialSource::Literal {
            secret: "test-secret".into(),
        };
        assert_eq!(src.resolve().unwrap(), "test-secret");
    }

    #[test]
    fn missing_env_var_errors() {
        let src = CredentialSource::EnvVar {
            name: "_PPE_TEST_UNSET_VAR_".into(),
        };
        let err = src.resolve().unwrap_err();
        assert!(err.contains("_PPE_TEST_UNSET_VAR_"));
    }

    #[test]
    fn cache_config_validates() {
        let mut cfg = CacheConfig {
            enabled: true,
            ttl_seconds: 0,
            max_entries: 100,
        };
        assert!(cfg.validate().is_err());

        cfg.ttl_seconds = 300;
        cfg.max_entries = 0;
        assert!(cfg.validate().is_err());

        cfg.max_entries = 100;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn disabled_cache_skips_max_entries_validation() {
        let cfg = CacheConfig {
            enabled: false,
            ttl_seconds: 300,
            max_entries: 0,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_zero_ttl_even_when_disabled() {
        let cfg = CacheConfig {
            enabled: false,
            ttl_seconds: 0,
            max_entries: 0,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_ttl_too_large_for_duration_arithmetic() {
        let cfg = CacheConfig {
            enabled: false,
            ttl_seconds: u64::MAX,
            max_entries: 0,
        };
        assert!(cfg.validate().is_err());

        // A value within i64 range but too large for chrono::TimeDelta
        let cfg2 = CacheConfig {
            enabled: false,
            ttl_seconds: i64::MAX as u64,
            max_entries: 0,
        };
        assert!(cfg2.validate().is_err());
    }

    #[test]
    fn literal_debug_redacts_secret() {
        let src = CredentialSource::Literal {
            secret: "super-secret".into(),
        };
        let debug = format!("{src:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn unknown_field_rejected_by_deny_unknown() {
        let raw = json!({
            "vault_addr": "https://vault.example.com:8200",
            "secret_path_template": "agents/{{sub}}/github",
            "scheme_prefix": "Bearer ",
            "auth": {
                "user": { "method": "jwt", "role": "r" }
            }
        });
        assert!(serde_json::from_value::<VaultDelegatorConfig>(raw).is_err());
    }
}
