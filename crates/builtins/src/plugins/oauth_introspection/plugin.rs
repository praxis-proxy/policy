// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The plugin behind `kind: oauth/introspection`: its settings, validated once
// at construction, and the client its hook handlers share.

use praxis_policy_core::error::PluginError;
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use crate::plugins::oauth_introspection::KIND;
use crate::plugins::oauth_introspection::client::IntrospectionClient;
use crate::plugins::oauth_introspection::config::IntrospectionConfig;

/// RFC 7662 token introspection against one issuer.
pub struct IntrospectionPlugin {
    pub(crate) config: PluginConfig,
    pub(crate) settings: IntrospectionConfig,
    pub(crate) client: IntrospectionClient,
}

impl std::fmt::Debug for IntrospectionPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionPlugin")
            .field("name", &self.config.name)
            .field("issuer", &self.settings.issuer)
            .field("introspection_endpoint", &self.client.endpoint())
            .field("authorization", &"<elided>")
            .field("cache_ttl_seconds", &self.settings.cache_ttl_seconds)
            .finish_non_exhaustive()
    }
}

impl IntrospectionPlugin {
    /// Build the plugin from its config.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Config`] when the `config:` block is missing or
    /// malformed, a required field is empty, the endpoint is not `https://`
    /// without `insecure_http`, the timeout is zero, caching is on with a zero
    /// bound, or the client secret cannot be read.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let fail = |message: String| {
            PluginError::Config {
                message: format!("plugin '{}' ({KIND}): {message}", cfg.name),
            }
            .boxed()
        };
        let raw = cfg
            .config
            .as_ref()
            .ok_or_else(|| fail("requires a `config:` block".to_owned()))?;
        let settings: IntrospectionConfig = serde_json::from_value(raw.clone())
            .map_err(|e| fail(format!("config parse failed: {e}")))?;

        if settings.issuer.trim().is_empty() {
            return Err(fail("issuer must be non-empty".to_owned()));
        }
        if settings.client_id.trim().is_empty() {
            return Err(fail("client_id must be non-empty".to_owned()));
        }
        if settings.timeout_ms == 0 {
            return Err(fail("timeout_ms must be nonzero".to_owned()));
        }
        if settings.cache_ttl_seconds > 0 && settings.cache_max_entries == 0 {
            return Err(fail(
                "cache_max_entries is zero, which caches nothing; set cache_ttl_seconds to 0 \
                 to turn caching off"
                    .to_owned(),
            ));
        }
        let client = IntrospectionClient::new(&settings).map_err(fail)?;

        Ok(Self {
            config: cfg,
            settings,
            client,
        })
    }
}

impl Plugin for IntrospectionPlugin {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::plugins::oauth_introspection::test_support::{ISSUER, plugin};

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn a_plaintext_endpoint_needs_insecure_http() {
        let config = |insecure: bool| PluginConfig {
            name: "introspect".into(),
            kind: KIND.into(),
            config: Some(json!({
                "issuer": ISSUER,
                "introspection_endpoint": "http://localhost:8080/introspect",
                "client_id": "ppe",
                "client_secret_source": { "kind": "literal", "secret": "s" },
                "insecure_http": insecure,
            })),
            ..Default::default()
        };

        assert!(
            IntrospectionPlugin::new(config(false)).is_err(),
            "http:// is refused by default"
        );
        assert!(
            IntrospectionPlugin::new(config(true)).is_ok(),
            "insecure_http allows it"
        );
    }

    #[test]
    fn construction_rejects_each_unusable_setting() {
        for (key, value) in [
            ("issuer", json!(" ")),
            ("client_id", json!("")),
            ("timeout_ms", json!(0)),
            (
                "introspection_endpoint",
                json!("ftp://idp.example/introspect"),
            ),
            (
                "client_secret_source",
                json!({ "kind": "env_var", "name": "_PPE_INTROSPECTION_SECRET_NOT_SET_" }),
            ),
        ] {
            let mut config = json!({
                "issuer": ISSUER,
                "introspection_endpoint": "https://idp.example/introspect",
                "client_id": "ppe",
                "client_secret_source": { "kind": "literal", "secret": "s" },
            });
            config[key] = value;

            let error = IntrospectionPlugin::new(PluginConfig {
                name: "introspect".into(),
                kind: KIND.into(),
                config: Some(config),
                ..Default::default()
            })
            .expect_err(key);

            assert!(
                matches!(*error, PluginError::Config { .. }),
                "{key}: {error}"
            );
        }
    }

    #[test]
    fn caching_with_a_zero_bound_is_rejected() {
        let error = IntrospectionPlugin::new(PluginConfig {
            name: "introspect".into(),
            kind: KIND.into(),
            config: Some(json!({
                "issuer": ISSUER,
                "introspection_endpoint": "https://idp.example/introspect",
                "client_id": "ppe",
                "client_secret_source": { "kind": "literal", "secret": "s" },
                "cache_ttl_seconds": 10,
                "cache_max_entries": 0,
            })),
            ..Default::default()
        })
        .expect_err("a cache that holds nothing");

        assert!(matches!(*error, PluginError::Config { .. }), "{error}");
    }

    #[test]
    fn debug_output_elides_the_client_secret() {
        let rendered = format!("{:?}", plugin(json!({})));

        assert!(!rendered.contains("s3cret"), "{rendered}");
        assert!(!rendered.contains("Basic "), "{rendered}");
    }
}
