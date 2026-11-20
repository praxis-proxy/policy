// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` for the RFC 7662 revocation checker, so every host wires it
// the same way.
//
// Operators declare it as:
//
//     plugins:
//       - name: kc-introspect
//         kind: revocation/introspection
//         hooks: [revocation.check]
//         capabilities: [read_inbound_credentials, perform_http]
//         config:
//           issuer: https://keycloak.example/realms/demo
//           introspection_endpoint: https://keycloak.example/realms/demo/protocol/openid-connect/token/introspect
//           client_id: ppe-introspect
//           client_secret_source: { kind: env_var, name: PPE_INTROSPECT_SECRET }
//
// The `kind: revocation/introspection` string is part of this crate's public
// API.

use std::sync::Arc;

use praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
    revocation::{HOOK_REVOCATION_CHECK, RevocationHook},
};

use crate::plugins::revocation_introspection::IntrospectionChecker;

/// The plugin `kind:` string operators write in PPE YAML.
pub const KIND: &str = "revocation/introspection";

/// Factory for `kind: revocation/introspection` plugins.
pub struct IntrospectionFactory;

impl PluginFactory for IntrospectionFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let checker = Arc::new(IntrospectionChecker::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<RevocationHook, _>::new(Arc::clone(
            &checker,
        )));
        Ok(PluginInstance {
            plugin: checker,
            handlers: vec![(HOOK_REVOCATION_CHECK, handler)],
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn registers_one_handler_on_the_revocation_hook() {
        let instance = IntrospectionFactory
            .create(&PluginConfig {
                name: "introspect".into(),
                kind: KIND.into(),
                hooks: vec![HOOK_REVOCATION_CHECK.to_owned()],
                config: Some(serde_json::json!({
                    "issuer": "https://idp.example/realms/demo",
                    "introspection_endpoint": "https://idp.example/introspect",
                    "client_id": "ppe",
                    "client_secret_source": { "kind": "literal", "secret": "s" },
                })),
                ..Default::default()
            })
            .expect("a valid config builds");

        assert_eq!(instance.handlers.len(), 1, "one checker, one handler");
        assert_eq!(
            instance.handlers[0].0, HOOK_REVOCATION_CHECK,
            "the checker lands on revocation.check"
        );
    }

    #[test]
    fn a_config_the_checker_rejects_fails_the_factory() {
        let error = IntrospectionFactory
            .create(&PluginConfig {
                name: "introspect".into(),
                kind: KIND.into(),
                hooks: vec![HOOK_REVOCATION_CHECK.to_owned()],
                config: Some(serde_json::json!({ "issuer": "https://idp.example" })),
                ..Default::default()
            })
            .err()
            .expect("an incomplete config does not build");

        assert!(matches!(*error, PluginError::Config { .. }), "{error:?}");
    }
}
