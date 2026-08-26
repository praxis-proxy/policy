// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` impl for the OAuth 2.0 (RFC 8693) token-exchange
// delegator. Lives here (alongside the delegator) so every host —
// Praxis filter, Envoy bridge, CLI runner, test harness — wires it
// up the same way.
//
// Operators declare it in PPE YAML as:
//
//     plugins:
//       - name: workday-oauth
//         kind: delegator/oauth
//         hooks: [token.delegate]
//         config:
//           token_endpoint: https://idp.example.com/token
//           client_id: praxis-gateway
//           client_secret_source: { kind: env_var, name: OAUTH_CLIENT_SECRET }
//
// The `kind: delegator/oauth` string is part of this crate's public
// API. Hosts call
// `mgr.register_factory("delegator/oauth", Box::new(OAuthDelegatorFactory))`
// before `load_config_yaml`.

use std::sync::Arc;

use praxis_policy_core::{
    delegation::{HOOK_TOKEN_DELEGATE, TokenDelegateHook},
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::OAuthDelegator;

/// The plugin `kind:` string operators write in PPE YAML to declare
/// an OAuth RFC 8693 token-exchange delegator.
pub const KIND: &str = "delegator/oauth";

/// Factory for `kind: delegator/oauth` plugins. Instantiates an
/// `OAuthDelegator` from the `config:` block and registers it on the
/// `token.delegate` hook.
pub struct OAuthDelegatorFactory;

impl PluginFactory for OAuthDelegatorFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let delegator = Arc::new(OAuthDelegator::new(config.clone())?);
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
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn cfg(config: serde_json::Value) -> PluginConfig {
        PluginConfig {
            name: "oauth".into(),
            kind: KIND.into(),
            hooks: vec![HOOK_TOKEN_DELEGATE.to_owned()],
            config: Some(config),
            ..Default::default()
        }
    }

    /// No request is made at construction time, so an https endpoint that does
    /// not exist is fine here and keeps the test off the network.
    fn valid_config() -> serde_json::Value {
        serde_json::json!({
            "token_endpoint": "https://idp.example/token",
            "client_id": "gateway-client",
            "client_secret_source": { "kind": "literal", "secret": "test-secret" },
        })
    }

    /// The hook name is fixed in code rather than read from `config.hooks`, so
    /// this pins the registration point an operator's `hooks:` list has to match.
    #[test]
    fn registers_one_handler_on_the_token_delegate_hook() {
        let inst = OAuthDelegatorFactory
            .create(&cfg(valid_config()))
            .expect("a valid delegator config must build");
        assert_eq!(inst.handlers.len(), 1, "one delegator, one handler");
        assert_eq!(
            inst.handlers[0].0, HOOK_TOKEN_DELEGATE,
            "the delegator must land on the token.delegate hook"
        );
    }

    /// Construction failure has to propagate. A registered delegator built from
    /// a bad config would fail on every delegation attempt at request time
    /// instead of at load time.
    #[test]
    fn a_config_the_delegator_rejects_fails_the_factory() {
        // `.err()` rather than `expect_err`: PluginInstance is not Debug.
        let err = OAuthDelegatorFactory
            .create(&cfg(serde_json::json!({ "client_id": "gateway-client" })))
            .err()
            .expect("a config with no token_endpoint must not build");
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a config error, got {err:?}"
        );
    }
}
