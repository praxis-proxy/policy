// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::TypedHandlerAdapter;
use praxis_policy_core::metadata::{HOOK_METADATA_FETCH, MetadataFetchHook};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use super::config::CompiledConfig;
use super::handler::MetadataHttp;

/// The plugin `kind:` string operators write in PPE YAML.
pub const KIND: &str = "metadata/http";

/// Builds one typed HTTP metadata source.
pub struct MetadataHttpFactory;

impl PluginFactory for MetadataHttpFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        validate_registration(config).map_err(|message| config_error(config, message))?;
        let compiled =
            CompiledConfig::compile(config).map_err(|message| config_error(config, message))?;
        let source = Arc::new(MetadataHttp::new(config.clone(), compiled));
        let handler = Arc::new(TypedHandlerAdapter::<MetadataFetchHook, _>::new(
            Arc::clone(&source),
        ));
        Ok(PluginInstance {
            plugin: source,
            handlers: vec![(HOOK_METADATA_FETCH, handler)],
        })
    }
}

fn validate_registration(config: &PluginConfig) -> Result<(), String> {
    if !valid_instance_name(&config.name) {
        return Err(format!(
            "instance name `{}` must match [A-Za-z_][A-Za-z0-9_]*",
            config.name
        ));
    }
    if config.hooks.as_slice() != [HOOK_METADATA_FETCH] {
        return Err("`hooks` must contain exactly `metadata.fetch`".to_owned());
    }
    if config.mode != PluginMode::Sequential {
        return Err("metadata fetch sources must use `mode: sequential`".to_owned());
    }
    if !matches!(config.on_error, OnError::Fail | OnError::Ignore) {
        return Err("metadata fetch sources support only `on_error: fail` or `ignore`".to_owned());
    }
    if !config.capabilities.contains("perform_http") {
        return Err("metadata/http requires capability `perform_http`".to_owned());
    }
    Ok(())
}

fn valid_instance_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn config_error(config: &PluginConfig, message: impl Into<String>) -> Box<PluginError> {
    PluginError::Config {
        message: format!("metadata/http plugin `{}`: {}", config.name, message.into()),
    }
    .boxed()
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> PluginConfig {
        PluginConfig {
            name: "account_status".to_owned(),
            kind: KIND.to_owned(),
            hooks: vec![HOOK_METADATA_FETCH.to_owned()],
            mode: PluginMode::Sequential,
            capabilities: ["perform_http".to_owned()].into(),
            config: Some(json!({
                "require_authenticated": false,
                "request": {
                    "method": "GET",
                    "url": "https://metadata.example"
                }
            })),
            ..PluginConfig::default()
        }
    }

    #[test]
    fn registers_exactly_one_typed_metadata_handler() {
        let instance = MetadataHttpFactory
            .create(&config())
            .expect("minimal source config");
        assert_eq!(instance.handlers.len(), 1);
        assert_eq!(
            instance.handlers.first().expect("one handler").0,
            HOOK_METADATA_FETCH
        );
    }

    #[test]
    fn rejects_mismatched_hook_name_mode_and_instance() {
        let mut wrong_hook = config();
        wrong_hook.hooks = vec!["cmf.tool_pre_invoke".to_owned()];
        assert!(MetadataHttpFactory.create(&wrong_hook).is_err());

        let mut wrong_mode = config();
        wrong_mode.mode = PluginMode::Concurrent;
        assert!(MetadataHttpFactory.create(&wrong_mode).is_err());

        let mut wrong_name = config();
        wrong_name.name = "account.status".to_owned();
        assert!(MetadataHttpFactory.create(&wrong_name).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_missing_http_capability() {
        let mut unknown = config();
        unknown.config.as_mut().expect("config")["surprise"] = json!(true);
        assert!(MetadataHttpFactory.create(&unknown).is_err());

        let mut missing_capability = config();
        missing_capability.capabilities.clear();
        let error = MetadataHttpFactory
            .create(&missing_capability)
            .err()
            .expect("perform_http is required")
            .to_string();
        assert!(error.contains("perform_http"));
    }

    #[test]
    fn secret_auth_stays_blocked_on_the_exact_prerequisite() {
        let mut auth = config();
        auth.config.as_mut().expect("config")["auth"] = json!({
            "kind": "shared_secret",
            "scheme": "bearer",
            "secret": "metadata-token"
        });
        let error = MetadataHttpFactory
            .create(&auth)
            .err()
            .expect("secret grants are not on main")
            .to_string();
        assert!(error.contains("#384"));
    }
}
