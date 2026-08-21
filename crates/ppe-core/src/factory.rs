// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Plugin factory registry.
//
// Provides a factory pattern for creating plugin instances from
// config. The host registers factories by `kind` name before
// loading config. When the engine processes a config file, it
// looks up the factory for each plugin's `kind` and calls create().
//
// This decouples plugin instantiation from the engine — the
// engine doesn't know how to create a "builtin" vs "wasm"
// The factory does.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::PluginError;
use crate::plugin::{Plugin, PluginConfig};
use crate::registry::AnyHookHandler;

/// Factory for creating plugin instances from config.
///
/// The host registers factories by `kind` name before loading
/// config. When the engine processes a config file, it looks up
/// the factory for each plugin's `kind` and calls `create()`.
///
/// The factory returns both the plugin and its handler because it
/// knows the concrete types — which handler traits the plugin
/// implements and which hooks it handles.
///
/// # Examples
///
/// ```rust,ignore
/// struct RateLimiterFactory;
///
/// impl PluginFactory for RateLimiterFactory {
///     fn create(&self, config: &PluginConfig)
///         -> Result<PluginInstance, Box<PluginError>>
///     {
///         let plugin = Arc::new(RateLimiter::from_config(config)?);
///         let handler = Arc::new(TypedHandlerAdapter::<RequestHeadersReceived, _>::new(
///             Arc::clone(&plugin),
///         ));
///         Ok(PluginInstance { plugin, handler })
///     }
/// }
///
/// let mut factories = PluginFactoryRegistry::new();
/// factories.register("security/rate_limit", Box::new(RateLimiterFactory));
/// ```
pub trait PluginFactory: Send + Sync {
    /// Create a plugin instance and its handler from config.
    ///
    /// The `config` is the plugin's entry from the YAML file.
    /// # Errors
    ///
    /// Returns `PluginError::Config` when the entry's settings are missing,
    /// malformed, or out of range for this plugin.
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>>;
}

/// A created plugin instance — the plugin and its type-erased handlers.
///
/// Each handler is paired with the hook name it handles. A plugin
/// that implements multiple hook types (e.g., `ToolPreInvoke` and
/// `ToolPostInvoke`) returns one entry per hook.
pub struct PluginInstance {
    /// The plugin implementation.
    pub plugin: Arc<dyn Plugin>,

    /// Type-erased handlers paired with their hook names.
    /// Each entry maps a hook name to the adapter for that hook type.
    pub handlers: Vec<(&'static str, Arc<dyn AnyHookHandler>)>,
}

/// Registry of plugin factories keyed by `kind` name.
///
/// The host populates this before calling `PolicyEngine::from_config()`.
/// Each factory knows how to create plugins of a specific kind.
///
/// # Examples
///
/// ```rust,ignore
/// let mut factories = PluginFactoryRegistry::new();
/// factories.register("builtin/rate_limit", Box::new(RateLimiterFactory));
/// factories.register("builtin/identity", Box::new(IdentityFactory));
///
/// let engine = PolicyEngine::from_config(path, &factories)?;
/// ```
pub struct PluginFactoryRegistry {
    factories: HashMap<String, Arc<dyn PluginFactory>>,
}

impl PluginFactoryRegistry {
    /// Create an empty factory registry.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a factory for a given `kind` name.
    ///
    /// Registration is last-writer-wins: re-registering an existing `kind`
    /// overrides it (this is intentional — a host can swap a builtin's impl).
    /// Because silent override is a footgun, a warning is logged when an
    /// existing registration is replaced.
    /// Takes a `Box` and stores an `Arc`. Callers keep the `Box::new(...)`
    /// spelling; the shared handle exists so a lookup can hand back an owned
    /// factory and let the registry lock go before the factory is invoked.
    pub fn register(&mut self, kind: impl Into<String>, factory: Box<dyn PluginFactory>) {
        let kind = kind.into();
        if self
            .factories
            .insert(kind.clone(), Arc::from(factory))
            .is_some()
        {
            tracing::warn!(kind = %kind, "plugin factory overrides an existing registration");
        }
    }

    /// Look up a factory by `kind` name, returning an owned handle.
    ///
    /// Owned rather than borrowed on purpose: the engine holds this registry
    /// behind an `RwLock`, and a borrow would keep the read guard alive across
    /// the `create` call. `create` runs host-supplied factory code that may
    /// re-enter the engine, and taking the write side while a read guard is
    /// still held on the same thread deadlocks. Cloning the `Arc` lets the
    /// caller drop the guard first.
    pub fn get(&self, kind: &str) -> Option<Arc<dyn PluginFactory>> {
        self.factories.get(kind).map(Arc::clone)
    }

    /// Whether a factory exists for the given `kind`.
    pub fn has(&self, kind: &str) -> bool {
        self.factories.contains_key(kind)
    }

    /// All registered kind names.
    pub fn kinds(&self) -> Vec<&str> {
        self.factories
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }
}

impl Default for PluginFactoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct StubFactory(&'static str);

    impl PluginFactory for StubFactory {
        fn create(&self, _config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
            Err(Box::new(PluginError::Config {
                message: format!("stub {}", self.0),
            }))
        }
    }

    #[test]
    fn a_registered_kind_is_found_and_an_unregistered_one_is_not() {
        let mut reg = PluginFactoryRegistry::default();
        assert!(!reg.has("a/b"), "an empty registry knows nothing");
        assert!(reg.get("a/b").is_none());

        reg.register("a/b", Box::new(StubFactory("first")));
        assert!(reg.has("a/b"));
        assert!(reg.get("a/b").is_some());
        assert!(
            !reg.has("c/d"),
            "registering one kind must not answer for another"
        );
    }

    /// Registration is last-writer-wins on purpose, so a host can swap a
    /// builtin's implementation. The replacement has to actually take effect, or
    /// the host's override would be silently ignored.
    #[test]
    fn re_registering_a_kind_replaces_the_previous_factory() {
        let mut reg = PluginFactoryRegistry::default();
        reg.register("a/b", Box::new(StubFactory("first")));
        reg.register("a/b", Box::new(StubFactory("second")));
        let factory = reg.get("a/b").expect("kind is registered");
        // The stub reports its identity through its error message, which is the
        // only observable difference between the two.
        let Err(e) = factory.create(&PluginConfig::default()) else {
            panic!("the stub always errors")
        };
        assert!(
            e.to_string().contains("second"),
            "the later registration must win: {e}"
        );
        assert_eq!(reg.kinds().len(), 1, "an override is not a second entry");
    }

    #[test]
    fn kinds_lists_every_registered_name() {
        let mut reg = PluginFactoryRegistry::default();
        reg.register("a/b", Box::new(StubFactory("x")));
        reg.register("c/d", Box::new(StubFactory("y")));
        let mut kinds = reg.kinds();
        kinds.sort_unstable();
        assert_eq!(kinds, vec!["a/b", "c/d"]);
    }

    /// `get` hands back an owned handle rather than a borrow, so the engine can
    /// drop its read guard before calling host-supplied `create` code. Holding
    /// the guard across that call deadlocks if the factory re-enters the engine,
    /// so this pins the ownership contract.
    #[test]
    fn get_returns_an_owned_handle_that_outlives_the_registry() {
        let factory = {
            let mut reg = PluginFactoryRegistry::default();
            reg.register("a/b", Box::new(StubFactory("kept")));
            reg.get("a/b").expect("kind is registered")
        };
        let Err(e) = factory.create(&PluginConfig::default()) else {
            panic!("the stub always errors")
        };
        assert!(e.to_string().contains("kept"));
    }
}
