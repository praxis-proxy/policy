// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` impl for the CIBA elicitation handler. Lives here
// (alongside the approver) so every host wires it up the same way.
//
// Operators declare it in PPE YAML as:
//
//     plugins:
//       - name: manager-approver
//         kind: elicitation/ciba
//         hooks: [elicit]
//         config:
//           backchannel_endpoint: https://kc/realms/corp/protocol/openid-connect/ext/ciba/auth
//           token_endpoint:       https://kc/realms/corp/protocol/openid-connect/token
//           client_id: praxis-policy-gateway
//           client_secret_source: { kind: env_var, name: CIBA_CLIENT_SECRET }
//           store: { kind: memory }
//
// Then policy routes name it: `require_approval(manager-approver, from: claim.manager, ...)`.
//
// Hosts call
// `mgr.register_factory("elicitation/ciba", Box::new(CibaApproverFactory))`
// before loading config.

use std::sync::Arc;

use praxis_policy_core::{
    elicitation::{ElicitationHook, HOOK_ELICIT},
    error::PluginError,
    factory::{FactoryContext, PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::plugins::elicitation_ciba::CibaApprover;

/// The plugin `kind:` string operators write in PPE YAML to declare a
/// CIBA elicitation handler.
pub const KIND: &str = "elicitation/ciba";

/// Factory for `kind: elicitation/ciba` plugins. Instantiates a
/// `CibaApprover` from the `config:` block and registers it on the
/// `elicit` hook.
pub struct CibaApproverFactory;

impl PluginFactory for CibaApproverFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        self.create_with(config, &FactoryContext::default())
    }

    fn create_with(
        &self,
        config: &PluginConfig,
        context: &FactoryContext,
    ) -> Result<PluginInstance, Box<PluginError>> {
        let approver = Arc::new(CibaApprover::with_context(config.clone(), context)?);
        let handler = Arc::new(TypedHandlerAdapter::<ElicitationHook, _>::new(Arc::clone(
            &approver,
        )));
        Ok(PluginInstance {
            plugin: approver,
            handlers: vec![(HOOK_ELICIT, handler)],
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn cfg(config: serde_json::Value) -> PluginConfig {
        PluginConfig {
            name: "manager-approver".into(),
            kind: KIND.into(),
            hooks: vec![HOOK_ELICIT.to_owned()],
            config: Some(config),
            ..Default::default()
        }
    }

    /// No request is made at construction time, so https endpoints that do not
    /// exist are fine here and keep the test off the network.
    fn valid_config() -> serde_json::Value {
        serde_json::json!({
            "backchannel_endpoint": "https://idp.example/ciba/auth",
            "token_endpoint": "https://idp.example/token",
            "client_id": "praxis-policy-gateway",
            "client_secret_source": { "kind": "literal", "secret": "shh" },
            "store": { "kind": "memory" },
        })
    }

    /// The hook name is fixed in code rather than read from `config.hooks`, so
    /// this pins the registration point an operator's `hooks:` list has to match.
    #[test]
    fn registers_one_handler_on_the_elicit_hook() {
        let inst = CibaApproverFactory
            .create(&cfg(valid_config()))
            .expect("a valid approver config must build");
        assert_eq!(inst.handlers.len(), 1, "one approver, one handler");
        assert_eq!(
            inst.handlers[0].0, HOOK_ELICIT,
            "the approver must land on the elicit hook"
        );
    }

    /// Plaintext endpoints are refused unless the operator opts in, and that
    /// refusal has to stop the factory rather than register an approver that
    /// would ship credentials in the clear.
    #[test]
    fn a_config_the_approver_rejects_fails_the_factory() {
        let mut bad = valid_config();
        bad["backchannel_endpoint"] = serde_json::json!("http://idp.example/ciba/auth");
        // `.err()` rather than `expect_err`: PluginInstance is not Debug.
        let err = CibaApproverFactory
            .create(&cfg(bad))
            .err()
            .expect("a plaintext endpoint without insecure_http must not build");
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a config error, got {err:?}"
        );
    }

    fn create_err(config: serde_json::Value) -> String {
        CibaApproverFactory
            .create(&cfg(config))
            .err()
            .expect("this config must be refused")
            .to_string()
    }

    fn with_store(store: serde_json::Value) -> serde_json::Value {
        let mut c = valid_config();
        c["store"] = store;
        c
    }

    #[test]
    fn an_unknown_top_level_field_names_the_field_and_the_plugin() {
        let mut bad = valid_config();
        bad["stroe"] = serde_json::json!({ "kind": "valkey" });
        let msg = create_err(bad);
        assert!(msg.contains("stroe"), "names the field: {msg}");
        assert!(msg.contains("manager-approver"), "names the plugin: {msg}");
    }

    #[test]
    fn an_explicit_memory_store_builds() {
        let inst = CibaApproverFactory
            .create(&cfg(with_store(serde_json::json!({ "kind": "memory" }))))
            .expect("memory is always available");
        assert_eq!(inst.handlers.len(), 1);
    }

    #[test]
    fn a_memory_store_with_settings_is_refused() {
        let msg = create_err(with_store(
            serde_json::json!({ "kind": "memory", "endpoint": "x" }),
        ));
        assert!(msg.contains("endpoint"), "names the stray setting: {msg}");
    }

    #[test]
    fn an_unknown_store_kind_lists_the_supported_ones() {
        let msg = create_err(with_store(serde_json::json!({ "kind": "dynamo" })));
        assert!(
            msg.contains("memory") && msg.contains("valkey"),
            "lists the kinds: {msg}"
        );
    }

    #[cfg(not(feature = "valkey"))]
    #[test]
    fn a_valkey_store_without_the_feature_names_the_feature() {
        let msg = create_err(with_store(
            serde_json::json!({ "kind": "valkey", "endpoint": "localhost:6379" }),
        ));
        assert!(msg.contains("`valkey` feature"), "names the feature: {msg}");
    }
}
