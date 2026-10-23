// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Typed configuration for `CibaApprover`. Deserializes from the
// plugin's `PluginConfig.config` field; the approver's constructor reads
// it and builds the runtime state (the shared `reqwest::Client`, the
// loaded client secret).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What operators write under `plugins[<name>].config:` in unified
/// config YAML for a CIBA elicitation handler.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CibaConfig {
    /// OIDC CIBA backchannel authentication endpoint — where the
    /// `dispatch` POST lands (e.g.
    /// `https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth`).
    pub backchannel_endpoint: String,

    /// OP token endpoint — where the `check` poll lands with
    /// `grant_type=urn:openid:params:grant-type:ciba` (e.g.
    /// `https://kc/realms/corp/protocol/openid-connect/token`).
    pub token_endpoint: String,

    /// OAuth `client_id` identifying our gateway to the OP. The gateway
    /// is the CIBA *client* that initiates the backchannel request.
    pub client_id: String,

    /// Where to load the client secret from. See [`ClientSecretSource`].
    pub client_secret_source: ClientSecretSource,

    /// OAuth scopes to request on the backchannel auth request. CIBA
    /// requires at least `openid`. This is the *OAuth* scope (what the
    /// minted token may do), distinct from the APL `scope` arg-binding
    /// expression — that one is checked by the praxis-policy-apl-core runtime.
    #[serde(default = "default_scope")]
    pub scope: String,

    /// Default `requested_expiry` (seconds) for the elicitation when the
    /// step doesn't carry a `timeout`. How long the approval stays
    /// pollable.
    #[serde(default = "default_requested_expiry_seconds")]
    pub default_requested_expiry_seconds: u64,

    /// Per-call HTTP timeout. Each dispatch/check/validate is a short
    /// round-trip; 5s keeps the request hot path bounded.
    #[serde(default = "default_http_timeout_seconds")]
    pub http_timeout_seconds: u64,

    /// Which token claim names the approver, cross-checked at `validate`
    /// against the `login_hint`. Keycloak's default username claim is
    /// `preferred_username`; deployments keyed on `sub` set that instead.
    #[serde(default = "default_approver_claim")]
    pub approver_claim: String,

    /// Explicitly allow `http://` for the endpoints. By default the
    /// constructor rejects plaintext because the requests carry
    /// `client_id:client_secret`. Set `true` ONLY for `http://localhost`
    /// development against a docker-compose Keycloak.
    #[serde(default)]
    pub insecure_http: bool,

    /// Where pending approvals live. Select process memory explicitly when
    /// approvals need not survive a restart or cross replicas.
    pub store: StoreConfig,
}

/// The correlation store a CIBA plugin uses.
#[derive(Clone, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StoreConfig {
    /// Process memory. Pending approvals do not survive a restart or reach
    /// another replica.
    Memory(MemoryStoreConfig),
    /// Valkey, shared across replicas. Requires the `valkey` feature.
    Valkey(serde_json::Map<String, serde_json::Value>),
}

/// `kind: memory` takes no settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "a braced struct is what lets `deny_unknown_fields` refuse stray settings"
)]
#[serde(deny_unknown_fields)]
pub struct MemoryStoreConfig {}

/// Where the gateway's OAuth client secret is loaded from. Mirrors
/// `apl-delegator-oauth`'s source enum — env var (production), file
/// (k8s secret volume), or literal (tests/dev only).
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientSecretSource {
    /// Read from an environment variable.
    EnvVar {
        /// The environment variable holding the secret.
        name: String,
    },
    /// Read from a file, which suits a mounted secret.
    File {
        /// Path to a file holding the secret.
        path: PathBuf,
    },
    /// Given inline in the config.
    Literal {
        /// The secret inline. Avoid outside local development.
        secret: String,
    },
}

impl std::fmt::Debug for CibaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaConfig")
            .field("client_id", &self.client_id)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(_) => f.write_str("Memory"),
            Self::Valkey(_) => f.write_str("Valkey([REDACTED])"),
        }
    }
}

impl std::fmt::Debug for ClientSecretSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvVar { name } => f.debug_struct("EnvVar").field("name", name).finish(),
            Self::File { path } => f.debug_struct("File").field("path", path).finish(),
            Self::Literal { .. } => f.write_str("Literal([REDACTED])"),
        }
    }
}

fn default_scope() -> String {
    "openid".to_owned()
}

fn default_requested_expiry_seconds() -> u64 {
    300
}

fn default_http_timeout_seconds() -> u64 {
    5
}

fn default_approver_claim() -> String {
    "preferred_username".to_owned()
}

impl CibaConfig {
    /// Per-call HTTP timeout as a `Duration`.
    pub fn http_timeout(&self) -> Duration {
        Duration::from_secs(self.http_timeout_seconds)
    }
}

impl ClientSecretSource {
    /// Resolve the secret at construction time. Errors as a string the
    /// caller wraps in `PluginError::Config`.
    /// # Errors
    ///
    /// Returns a message when the named environment variable is unset or the
    /// file cannot be read. The secret itself never appears in the error.
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            Self::EnvVar { name } => std::env::var(name)
                .map_err(|error| crate::env_secret::error("client secret", name, error)),
            Self::File { path } => std::fs::read_to_string(path)
                .map(|s| s.trim().to_owned())
                .map_err(|e| format!("secret file '{}' unreadable: {e}", path.display())),
            Self::Literal { secret } => Ok(secret.clone()),
        }
    }
}

/// Reject `http://` for endpoints that carry credentials. `https://` is
/// always allowed; `http://` only when `insecure_http` is set. Other
/// schemes defer to the upstream URL parser. Returns a short fragment
/// the caller prefixes with field + plugin name.
pub(in crate::plugins::elicitation_ciba) fn require_https(
    url: &str,
    insecure_http: bool,
) -> Result<(), String> {
    let lowered = url.trim_start().to_ascii_lowercase();
    if lowered.starts_with("https://") {
        return Ok(());
    }
    if lowered.starts_with("http://") {
        if insecure_http {
            return Ok(());
        }
        return Err(format!(
            "must use https:// (got '{url}'). Set `insecure_http: true` to allow \
             plaintext for localhost/dev only — never production."
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_deserializes_with_defaults() {
        let raw = json!({
            "backchannel_endpoint": "https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth",
            "token_endpoint": "https://kc/realms/corp/protocol/openid-connect/token",
            "client_id": "praxis-policy-gateway",
            "client_secret_source": { "kind": "literal", "secret": "dev-only" },
            "store": { "kind": "memory" },
        });
        let cfg: CibaConfig = serde_json::from_value(raw).unwrap();
        assert_eq!(cfg.client_id, "praxis-policy-gateway");
        assert_eq!(cfg.scope, "openid");
        assert_eq!(cfg.default_requested_expiry_seconds, 300);
        assert_eq!(cfg.http_timeout_seconds, 5);
        assert_eq!(cfg.approver_claim, "preferred_username");
        assert!(!cfg.insecure_http);
        assert!(matches!(cfg.store, StoreConfig::Memory(_)));
    }

    #[test]
    fn omitted_store_is_rejected() {
        let raw = json!({
            "backchannel_endpoint": "https://kc/ciba/auth",
            "token_endpoint": "https://kc/token",
            "client_id": "praxis-policy-gateway",
            "client_secret_source": { "kind": "literal", "secret": "dev-only" },
        });
        let error = serde_json::from_value::<CibaConfig>(raw).unwrap_err();
        assert!(error.to_string().contains("store"), "{error}");
    }

    #[test]
    fn literal_secret_resolves() {
        let src = ClientSecretSource::Literal {
            secret: "hush".into(),
        };
        assert_eq!(src.resolve().unwrap(), "hush");
    }

    #[test]
    fn invalid_unicode_secret_env_error_omits_the_value() {
        let message = crate::env_secret::error(
            "client secret",
            "CIBA_SECRET",
            std::env::VarError::NotUnicode(std::ffi::OsString::from("sensitive-value")),
        );
        assert!(message.contains("CIBA_SECRET"), "got {message}");
        assert!(message.contains("not valid Unicode"), "got {message}");
        assert!(!message.contains("sensitive-value"), "got {message}");
        assert!(
            crate::env_secret::error(
                "client secret",
                "CIBA_SECRET",
                std::env::VarError::NotPresent
            )
            .contains("not set"),
            "a missing variable must be distinguishable from invalid Unicode"
        );
    }

    #[test]
    fn config_debug_hides_inline_client_and_store_secrets() {
        let config: CibaConfig = serde_json::from_value(serde_json::json!({
            "backchannel_endpoint": "https://op.example/ciba",
            "token_endpoint": "https://op.example/token",
            "client_id": "gateway",
            "client_secret_source": { "kind": "literal", "secret": "oauth-secret" },
            "store": { "kind": "valkey", "endpoint": "localhost:6379", "password": "store-secret" }
        }))
        .unwrap();
        let debug = format!("{config:?} {:?}", config.client_secret_source);
        assert!(!debug.contains("oauth-secret"));
        assert!(!debug.contains("store-secret"));
    }

    #[test]
    fn https_gate() {
        require_https("https://kc/", false).unwrap();
        require_https("http://localhost:8080/", false).unwrap_err();
        require_https("http://localhost:8080/", true).unwrap();
    }
}
