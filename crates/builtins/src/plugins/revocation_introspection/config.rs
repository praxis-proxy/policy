// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Typed configuration for the introspection checker, deserialized from
// `PluginConfig.config` once at construction. A route's step `config:` is
// merged over this before construction, which is how a route tightens the
// check.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What operators write under `plugins[<name>].config:`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntrospectionConfig {
    /// The issuer whose tokens this checker covers, compared exactly with a
    /// token's `iss` claim. A token from any other issuer is never sent to
    /// the introspection endpoint.
    pub issuer: String,

    /// The issuer's RFC 7662 introspection endpoint.
    pub introspection_endpoint: String,

    /// The `client_id` this checker authenticates to the endpoint with.
    pub client_id: String,

    /// Where to load the client secret from. See [`ClientSecretSource`].
    pub client_secret_source: ClientSecretSource,

    /// Per-call timeout in milliseconds. Must be nonzero. Default 500.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Allow a plaintext `http://` endpoint. Default false: the call carries
    /// the client secret and the caller's token. Set true only for a
    /// localhost or demo issuer.
    #[serde(default)]
    pub insecure_http: bool,
}

/// Where the checker's client secret is loaded from.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Given inline in the config. Avoid outside local development.
    Literal {
        /// The secret inline.
        secret: String,
    },
}

const fn default_timeout_ms() -> u64 {
    500
}

impl IntrospectionConfig {
    /// The per-call timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

impl ClientSecretSource {
    /// Read the secret.
    ///
    /// # Errors
    ///
    /// Returns a message when the environment variable is unset or the file
    /// cannot be read. The secret never appears in the message.
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            Self::EnvVar { name } => {
                std::env::var(name).map_err(|e| crate::env_secret::error("client secret", name, e))
            },
            Self::File { path } => std::fs::read_to_string(path)
                .map(|s| s.trim().to_owned())
                .map_err(|e| format!("secret file '{}' unreadable: {e}", path.display())),
            Self::Literal { secret } => Ok(secret.clone()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use serde_json::json;

    use super::*;

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn the_timeout_defaults_to_half_a_second() {
        let config: IntrospectionConfig = serde_json::from_value(json!({
            "issuer": "https://idp.example/realms/demo",
            "introspection_endpoint": "https://idp.example/introspect",
            "client_id": "ppe",
            "client_secret_source": { "kind": "literal", "secret": "s" },
        }))
        .unwrap();

        assert_eq!(config.timeout(), Duration::from_millis(500), "timeout");
        assert!(!config.insecure_http, "plaintext is off by default");
    }

    #[test]
    fn an_unknown_key_is_rejected() {
        let parsed = serde_json::from_value::<IntrospectionConfig>(json!({
            "issuer": "https://idp.example/realms/demo",
            "introspection_endpoint": "https://idp.example/introspect",
            "client_id": "ppe",
            "client_secret_source": { "kind": "literal", "secret": "s" },
            "timeout": 5,
        }));

        assert!(parsed.is_err(), "a misspelled key must not default");
    }

    #[test]
    fn a_missing_env_var_names_the_variable_not_the_secret() {
        let source = ClientSecretSource::EnvVar {
            name: "_PPE_INTROSPECTION_SECRET_NOT_SET_".into(),
        };

        let error = source.resolve().unwrap_err();

        assert!(
            error.contains("_PPE_INTROSPECTION_SECRET_NOT_SET_"),
            "{error}"
        );
    }
}
