// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` for RFC 7662 introspection, so every host wires it the same
// way.
//
// Operators declare it as:
//
//     plugins:
//       - name: kc-introspect
//         kind: oauth/introspection
//         hooks: [revocation.check]
//         capabilities: [read_inbound_credentials, perform_http]
//         config:
//           issuer: https://keycloak.example/realms/demo
//           introspection_endpoint: https://keycloak.example/realms/demo/protocol/openid-connect/token/introspect
//           client_id: ppe-introspect
//           client_secret_source: { kind: env_var, name: PPE_INTROSPECT_SECRET }
//
// The `kind: oauth/introspection` string is part of this crate's public API.

use std::sync::Arc;

use praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook},
    plugin::PluginConfig,
    registry::AnyHookHandler,
    revocation::{HOOK_REVOCATION_CHECK, RevocationHook},
};

use crate::plugins::oauth_introspection::IntrospectionPlugin;

/// The plugin `kind:` string operators write in PPE YAML.
pub const KIND: &str = "oauth/introspection";

/// Factory for `kind: oauth/introspection` plugins.
pub struct IntrospectionFactory;

impl PluginFactory for IntrospectionFactory {
    /// Build the plugin, with a handler for each hook it declares: the engine
    /// registers every handler an instance returns, so one the operator did
    /// not ask for must not be returned.
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(IntrospectionPlugin::new(config.clone())?);
        let mut handlers: Vec<(&'static str, Arc<dyn AnyHookHandler>)> = Vec::new();
        for hook in &config.hooks {
            match hook.as_str() {
                HOOK_IDENTITY_RESOLVE => handlers.push((
                    HOOK_IDENTITY_RESOLVE,
                    Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(
                        &plugin,
                    ))),
                )),
                HOOK_REVOCATION_CHECK => handlers.push((
                    HOOK_REVOCATION_CHECK,
                    Arc::new(TypedHandlerAdapter::<RevocationHook, _>::new(Arc::clone(
                        &plugin,
                    ))),
                )),
                other => {
                    return Err(PluginError::Config {
                        message: format!(
                            "plugin '{}' ({KIND}): serves `{HOOK_IDENTITY_RESOLVE}` and \
                             `{HOOK_REVOCATION_CHECK}`, not `{other}`",
                            config.name
                        ),
                    }
                    .boxed());
                },
            }
        }
        if handlers.is_empty() {
            return Err(PluginError::Config {
                message: format!(
                    "plugin '{}' ({KIND}): declare `{HOOK_IDENTITY_RESOLVE}`, \
                     `{HOOK_REVOCATION_CHECK}` or both in `hooks:`",
                    config.name
                ),
            }
            .boxed());
        }
        Ok(PluginInstance { plugin, handlers })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    fn create(hooks: &[&str]) -> Result<PluginInstance, Box<PluginError>> {
        IntrospectionFactory.create(&PluginConfig {
            name: "introspect".into(),
            kind: KIND.into(),
            hooks: hooks.iter().map(|&hook| hook.to_owned()).collect(),
            config: Some(serde_json::json!({
                "issuer": "https://idp.example/realms/demo",
                "introspection_endpoint": "https://idp.example/introspect",
                "client_id": "ppe",
                "client_secret_source": { "kind": "literal", "secret": "s" },
                "identity": {},
            })),
            ..Default::default()
        })
    }

    fn registered(instance: &PluginInstance) -> Vec<&'static str> {
        instance.handlers.iter().map(|(hook, _)| *hook).collect()
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn registers_a_handler_for_each_declared_hook_and_no_other() {
        let checker = IntrospectionFactory
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
            .expect("a checker builds");
        let resolver = create(&[HOOK_IDENTITY_RESOLVE]).expect("a resolver builds");
        let both = create(&[HOOK_IDENTITY_RESOLVE, HOOK_REVOCATION_CHECK]).expect("both build");

        assert_eq!(registered(&checker), [HOOK_REVOCATION_CHECK], "checker");
        assert_eq!(registered(&resolver), [HOOK_IDENTITY_RESOLVE], "resolver");
        assert_eq!(
            registered(&both),
            [HOOK_IDENTITY_RESOLVE, HOOK_REVOCATION_CHECK],
            "one instance, both hooks"
        );
    }

    #[test]
    fn a_hook_it_does_not_serve_or_none_at_all_fails_the_factory() {
        for hooks in [&["cmf.tool_pre_invoke"][..], &[][..]] {
            let error = create(hooks).err().expect("refused");

            assert!(
                matches!(*error, PluginError::Config { .. }),
                "{hooks:?}: {error:?}"
            );
        }
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
