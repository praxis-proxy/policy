// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The provider trait, its factory, and the registry of factories by kind.
//
// A provider reads one backend and returns raw bytes as a string. It does not
// interpret what it read: a PEM, a JWK, a password and an API key are all the
// same thing here, and the consumer that knows which one it asked for is the
// one that parses it. That is what lets a deployment move a value from a file
// to a vault without the consumer changing.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use super::config::SecretProviderConfig;
use super::error::SecretError;

/// One backend a secret can be read from.
///
/// Implementations return the value as it is stored, with no parsing and no
/// interpretation. The return is [`Zeroizing`] so a value dropped on a failed
/// refresh, or when the last consumer releases it, does not stay in freed
/// memory.
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Read the value at `reference`.
    ///
    /// Called at startup for every value bound to this provider, and again on
    /// each refresh. Never called on the request path: consumers read a
    /// resolved value, so a slow backend costs startup time and refresh time
    /// and never request latency.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError`] naming which of the four faults applies. The
    /// error must not carry the value, and must not carry the credentials the
    /// provider used to read it.
    async fn get_secret(&self, reference: &str) -> Result<Zeroizing<String>, SecretError>;
}

/// Builds providers of one kind from their config.
pub trait SecretProviderFactory: Send + Sync {
    /// The `kind:` discriminator this factory builds, such as `"file"`.
    fn kind(&self) -> &str;

    /// Build one provider instance from its declared settings.
    ///
    /// Construction only. A factory must not read a secret here: resolution is
    /// ordered separately so every value fails at one point, with one message
    /// shape, rather than some failing during construction and some later.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Config`] when the settings are missing,
    /// malformed, or contradictory.
    fn build(&self, config: &SecretProviderConfig) -> Result<Arc<dyn SecretProvider>, SecretError>;
}

/// Factories by `kind`.
///
/// The host populates this before loading config, exactly as it populates
/// [`PluginFactoryRegistry`](crate::factory::PluginFactoryRegistry). A kind
/// with no registered factory is a config error naming what is registered, so
/// an operator who built without a backend's feature is told that rather than
/// left with an unexplained failure.
pub struct SecretProviderRegistry {
    factories: HashMap<String, Arc<dyn SecretProviderFactory>>,
}

impl SecretProviderRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// A registry holding the backends that need no dependencies: `env` and
    /// `file`.
    #[must_use]
    pub fn with_builtin_backends() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(super::backends::EnvSecretProviderFactory));
        registry.register(Box::new(super::backends::FileSecretProviderFactory));
        registry
    }

    /// Register a factory under the kind it reports.
    ///
    /// Last-writer-wins, so a host can replace a builtin backend, and a
    /// replacement is logged because a silent one would make a kind resolve to
    /// something other than what the operator read in the docs.
    pub fn register(&mut self, factory: Box<dyn SecretProviderFactory>) {
        let kind = factory.kind().to_owned();
        if self
            .factories
            .insert(kind.clone(), Arc::from(factory))
            .is_some()
        {
            tracing::warn!(kind = %kind, "secret provider factory overrides an existing registration");
        }
    }

    /// Build the provider a declaration asks for.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Config`] when no factory is registered for the
    /// declared kind, or when the factory refuses the settings.
    pub fn build(
        &self,
        name: &str,
        config: &SecretProviderConfig,
    ) -> Result<Arc<dyn SecretProvider>, SecretError> {
        let Some(factory) = self.factories.get(&config.kind) else {
            let mut kinds: Vec<&str> = self.factories.keys().map(String::as_str).collect();
            kinds.sort_unstable();
            return Err(SecretError::config(format!(
                "secret provider `{name}` declares kind `{}`, which is not registered; \
                 registered kinds are [{}]",
                config.kind,
                kinds.join(", ")
            )));
        };
        factory.build(config).map_err(|e| match e {
            SecretError::Config { message } => {
                SecretError::config(format!("secret provider `{name}`: {message}"))
            },
            other => other,
        })
    }
}

impl Default for SecretProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn declaration(kind: &str) -> SecretProviderConfig {
        SecretProviderConfig {
            kind: kind.to_owned(),
            settings: serde_yaml::Value::Null,
        }
    }

    #[test]
    fn an_unregistered_kind_names_what_is_registered() {
        let registry = SecretProviderRegistry::with_builtin_backends();
        let Err(err) = registry.build("vault-prod", &declaration("vault")) else {
            panic!("vault is not a builtin backend");
        };
        let msg = format!("{err}");
        assert!(msg.contains("vault-prod"), "{msg}");
        assert!(msg.contains("env"), "{msg}");
        assert!(msg.contains("file"), "{msg}");
    }

    #[test]
    fn a_build_failure_names_the_provider_instance() {
        let registry = SecretProviderRegistry::with_builtin_backends();
        let mut settings = serde_yaml::Mapping::new();
        settings.insert("base_dir".into(), serde_yaml::Value::Bool(true));
        let built = registry.build(
            "local",
            &SecretProviderConfig {
                kind: "file".to_owned(),
                settings: serde_yaml::Value::Mapping(settings),
            },
        );
        let Err(err) = built else {
            panic!("base_dir is not a string");
        };
        assert!(format!("{err}").contains("local"), "{err}");
    }

    #[test]
    fn the_builtin_backends_are_registered() {
        let registry = SecretProviderRegistry::with_builtin_backends();
        registry
            .build("shell", &declaration("env"))
            .expect("env is builtin");
        registry
            .build("local", &declaration("file"))
            .expect("file is builtin");
    }
}
