// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::delegation::{HOOK_TOKEN_DELEGATE, TokenDelegateHook};
use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::TypedHandlerAdapter;
use praxis_policy_core::plugin::PluginConfig;

use super::delegator::VaultDelegator;

/// The `kind:` value operators write in PPE YAML to select this plugin.
///
/// ```yaml
/// plugins:
///   - name: vault-github
///     kind: delegator/vault
///     hooks: [token.delegate]
///     …
/// ```
pub const KIND: &str = "delegator/vault";

/// Factory that constructs a [`VaultDelegator`] from its plugin
/// configuration.
pub struct VaultDelegatorFactory;

impl PluginFactory for VaultDelegatorFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let delegator = Arc::new(VaultDelegator::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<TokenDelegateHook, _>::new(
            Arc::clone(&delegator),
        ));
        Ok(PluginInstance {
            plugin: delegator,
            handlers: vec![(HOOK_TOKEN_DELEGATE, handler)],
        })
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_config() -> PluginConfig {
        PluginConfig {
            name: "vault-test".into(),
            kind: KIND.into(),
            config: Some(json!({
                "vault_addr": "https://vault.test:8200",
                "secret_path_template": "agents/{{sub}}/github",
                "auth": {
                    "user": { "method": "jwt", "role": "ppe-user" }
                }
            })),
            ..Default::default()
        }
    }

    #[test]
    fn factory_creates_one_handler_on_token_delegate() {
        let factory = VaultDelegatorFactory;
        let instance = factory.create(&valid_config()).expect("valid config");
        assert_eq!(instance.handlers.len(), 1);
        assert_eq!(instance.handlers[0].0, HOOK_TOKEN_DELEGATE);
    }

    #[test]
    fn factory_rejects_bad_config() {
        let factory = VaultDelegatorFactory;
        let cfg = PluginConfig {
            name: "bad".into(),
            kind: KIND.into(),
            config: None,
            ..Default::default()
        };
        assert!(factory.create(&cfg).is_err());
    }

    #[test]
    fn kind_matches_convention() {
        assert_eq!(KIND, "delegator/vault");
    }
}
