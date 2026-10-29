// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Typed policy dispatch for externally acquired metadata.

use crate::executor::PipelineResult;
use crate::extensions::AcquiredFacts;
use crate::hooks::payload::PluginPayload;
use crate::hooks::trait_def::PluginResult;

crate::define_hooks! {
    /// The metadata family's rows in the built-in hook metadata table.
    METADATA_HOOK_METADATA;

    /// Acquire one record from a named metadata source. This operation is
    /// invoked from policy evaluation rather than at a wire lifecycle phase.
    HOOK_METADATA_FETCH: "metadata.fetch" =>
        family: MetadataFetchHook, entity: None, phase: Unphased;
}

/// Typed request and result accumulator for one metadata source invocation.
///
/// The instance name selects exactly one plugin registered on
/// [`HOOK_METADATA_FETCH`]. A handler returns its record with
/// [`Self::with_facts`] through [`PluginResult::modify_payload`]. The record is
/// not installed into extensions here; framework policy evaluation validates,
/// stamps, and installs it after dispatch.
#[derive(Clone, Debug, PartialEq)]
pub struct MetadataFetchRequest {
    instance: String,
    facts: Option<AcquiredFacts>,
}

impl MetadataFetchRequest {
    /// Request acquisition from the configured source instance `instance`.
    #[must_use]
    pub fn new(instance: impl Into<String>) -> Self {
        Self {
            instance: instance.into(),
            facts: None,
        }
    }

    /// Configured source instance selected for this dispatch.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Return the source record produced by the handler, when present.
    #[must_use]
    pub const fn facts(&self) -> Option<&AcquiredFacts> {
        self.facts.as_ref()
    }

    /// Attach the acquired record returned by a source handler.
    #[must_use]
    pub fn with_facts(mut self, facts: AcquiredFacts) -> Self {
        self.facts = Some(facts);
        self
    }

    /// Borrow the typed result still held by a metadata dispatch.
    ///
    /// Returns `None` when the pipeline was denied or the payload is not a
    /// [`MetadataFetchRequest`]. The caller that installs the record into
    /// extensions clones it there, where ownership is required.
    #[must_use]
    pub fn from_pipeline_result(result: &PipelineResult) -> Option<&Self> {
        result
            .modified_payload
            .as_ref()
            .and_then(|payload| payload.as_any().downcast_ref::<Self>())
    }
}

impl PluginPayload for MetadataFetchRequest {
    fn clone_boxed(&self) -> Box<dyn PluginPayload> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Result returned by a typed metadata source handler.
pub type MetadataFetchResult = PluginResult<MetadataFetchRequest>;

crate::define_hook! {
    /// Metadata acquisition hook dispatched to one configured source instance.
    MetadataFetchHook, "metadata.fetch" => {
        payload: MetadataFetchRequest,
        result: MetadataFetchResult,
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::cmf::{CmfHook, MessagePayload};
    use crate::config::parse_config;
    use crate::context::PluginContext;
    use crate::engine::PolicyEngine;
    use crate::error::PluginError;
    use crate::extensions::{Extensions, MetaExtension, MetadataCacheDisposition};
    use crate::factory::{PluginFactory, PluginInstance};
    use crate::hooks::TypedHandlerAdapter;
    use crate::hooks::trait_def::HookHandler;
    use crate::plugin::{Plugin, PluginConfig, PluginMode};
    use crate::registry::AnyHookHandler;

    struct Source {
        config: PluginConfig,
        calls: Arc<AtomicUsize>,
        saw_metadata: Arc<AtomicBool>,
        forge_metadata: bool,
    }

    impl Plugin for Source {
        fn config(&self) -> &PluginConfig {
            &self.config
        }
    }

    impl HookHandler<MetadataFetchHook> for Source {
        async fn handle(
            &self,
            request: &MetadataFetchRequest,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> MetadataFetchResult {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.saw_metadata
                .store(extensions.metadata.is_some(), Ordering::Relaxed);

            let facts = AcquiredFacts::success(
                json!({"source": self.config.name}),
                Utc::now(),
                MetadataCacheDisposition::Disabled,
            );
            let response = request.clone().with_facts(facts);
            if !self.forge_metadata {
                return PluginResult::modify_payload(response);
            }

            let mut forged = Extensions::default();
            forged
                .install_metadata(
                    "forged",
                    "test/source",
                    AcquiredFacts::success(
                        json!(true),
                        Utc::now(),
                        MetadataCacheDisposition::Disabled,
                    ),
                )
                .unwrap();
            let mut owned = extensions.cow_copy();
            owned.metadata = forged.metadata;
            PluginResult::modify(response, owned)
        }
    }

    fn config(name: &str, read_metadata: bool) -> PluginConfig {
        PluginConfig {
            name: name.to_owned(),
            kind: "test/source".to_owned(),
            hooks: vec![HOOK_METADATA_FETCH.to_owned()],
            mode: PluginMode::Sequential,
            capabilities: if read_metadata {
                HashSet::from(["read_metadata".to_owned()])
            } else {
                HashSet::new()
            },
            ..PluginConfig::default()
        }
    }

    fn source(
        config: PluginConfig,
        calls: Arc<AtomicUsize>,
        saw_metadata: Arc<AtomicBool>,
        forge_metadata: bool,
    ) -> Arc<Source> {
        Arc::new(Source {
            config,
            calls,
            saw_metadata,
            forge_metadata,
        })
    }

    #[tokio::test]
    async fn direct_registration_dispatches_only_the_named_source() {
        let engine = PolicyEngine::default();
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let second_saw_metadata = Arc::new(AtomicBool::new(false));
        let first = source(
            config("first", false),
            Arc::clone(&first_calls),
            Arc::new(AtomicBool::new(false)),
            false,
        );
        let second = source(
            config("second", false),
            Arc::clone(&second_calls),
            Arc::clone(&second_saw_metadata),
            false,
        );
        engine
            .register_handler_for_names::<MetadataFetchHook, _>(
                first,
                config("first", false),
                &[HOOK_METADATA_FETCH],
            )
            .unwrap();
        engine
            .register_handler_for_names::<MetadataFetchHook, _>(
                second,
                config("second", false),
                &[HOOK_METADATA_FETCH],
            )
            .unwrap();

        let mut extensions = Extensions::default();
        extensions
            .install_metadata(
                "existing",
                "host/source",
                AcquiredFacts::success(json!(true), Utc::now(), MetadataCacheDisposition::Disabled),
            )
            .unwrap();
        let (result, _) = engine
            .invoke_named::<MetadataFetchHook>(
                HOOK_METADATA_FETCH,
                MetadataFetchRequest::new("second"),
                extensions,
                None,
            )
            .await;

        assert!(
            result.continue_processing,
            "dispatch to a registered source should continue",
        );
        assert_eq!(
            first_calls.load(Ordering::Relaxed),
            0,
            "unselected source 'first' must not be dispatched",
        );
        assert_eq!(
            second_calls.load(Ordering::Relaxed),
            1,
            "selected source 'second' must be dispatched once",
        );
        assert!(
            !second_saw_metadata.load(Ordering::Relaxed),
            "source without read_metadata must not see existing metadata",
        );
        let response = MetadataFetchRequest::from_pipeline_result(&result)
            .expect("dispatch should return the metadata response");
        assert_eq!(
            response.instance(),
            "second",
            "response should name the selected source",
        );
        assert_eq!(
            response
                .facts()
                .expect("response should carry acquired facts")
                .value(),
            Some(&json!({"source": "second"})),
            "facts should come from the selected source",
        );
    }

    #[tokio::test]
    async fn typed_invoke_dispatches_only_the_named_source() {
        let engine = PolicyEngine::default();
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        for (name, calls) in [
            ("first", Arc::clone(&first_calls)),
            ("second", Arc::clone(&second_calls)),
        ] {
            engine
                .register_handler_for_names::<MetadataFetchHook, _>(
                    source(
                        config(name, false),
                        calls,
                        Arc::new(AtomicBool::new(false)),
                        false,
                    ),
                    config(name, false),
                    &[HOOK_METADATA_FETCH],
                )
                .unwrap();
        }

        let (result, _) = engine
            .invoke::<MetadataFetchHook>(
                MetadataFetchRequest::new("second"),
                Extensions::default(),
                None,
            )
            .await;

        assert!(
            result.continue_processing,
            "typed dispatch to a registered source should continue",
        );
        assert_eq!(
            first_calls.load(Ordering::Relaxed),
            0,
            "unselected source 'first' must not be dispatched",
        );
        assert_eq!(
            second_calls.load(Ordering::Relaxed),
            1,
            "selected source 'second' must be dispatched once",
        );
    }

    #[tokio::test]
    async fn dynamic_invoke_dispatches_only_the_named_source() {
        let engine = PolicyEngine::default();
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        for (name, calls) in [
            ("first", Arc::clone(&first_calls)),
            ("second", Arc::clone(&second_calls)),
        ] {
            engine
                .register_handler_for_names::<MetadataFetchHook, _>(
                    source(
                        config(name, false),
                        calls,
                        Arc::new(AtomicBool::new(false)),
                        false,
                    ),
                    config(name, false),
                    &[HOOK_METADATA_FETCH],
                )
                .unwrap();
        }

        let (result, _) = engine
            .invoke_by_name(
                HOOK_METADATA_FETCH,
                Box::new(MetadataFetchRequest::new("second")),
                Extensions::default(),
                None,
            )
            .await;

        assert!(
            result.continue_processing,
            "dynamic dispatch to a registered source should continue",
        );
        assert_eq!(
            first_calls.load(Ordering::Relaxed),
            0,
            "unselected source 'first' must not be dispatched",
        );
        assert_eq!(
            second_calls.load(Ordering::Relaxed),
            1,
            "selected source 'second' must be dispatched once",
        );
    }

    #[tokio::test]
    async fn unknown_named_source_denies_with_an_actionable_error() {
        let engine = PolicyEngine::default();
        let (result, _) = engine
            .invoke_named::<MetadataFetchHook>(
                HOOK_METADATA_FETCH,
                MetadataFetchRequest::new("missing"),
                Extensions::default(),
                None,
            )
            .await;
        assert!(!result.continue_processing, "unknown source must deny");
        let violation = result.violation.expect("unknown source must deny");
        assert_eq!(violation.code, "plugin.not_found");
        assert!(violation.reason.contains("metadata.fetch"));
        assert!(violation.reason.contains("missing"));
    }

    #[tokio::test]
    async fn capabilities_filter_metadata_and_merge_back_rejects_forged_records() {
        let engine = PolicyEngine::default();
        let saw_metadata = Arc::new(AtomicBool::new(false));
        let plugin = source(
            config("account", true),
            Arc::new(AtomicUsize::new(0)),
            Arc::clone(&saw_metadata),
            true,
        );
        engine
            .register_handler_for_names::<MetadataFetchHook, _>(
                plugin,
                config("account", true),
                &[HOOK_METADATA_FETCH],
            )
            .unwrap();
        let mut extensions = Extensions::default();
        extensions
            .install_metadata(
                "existing",
                "host/source",
                AcquiredFacts::success(
                    json!("trusted"),
                    Utc::now(),
                    MetadataCacheDisposition::Disabled,
                ),
            )
            .unwrap();

        let (result, _) = engine
            .invoke_named::<MetadataFetchHook>(
                HOOK_METADATA_FETCH,
                MetadataFetchRequest::new("account"),
                extensions,
                None,
            )
            .await;

        assert!(
            saw_metadata.load(Ordering::Relaxed),
            "source with read_metadata should see existing metadata",
        );
        let returned = result
            .modified_extensions
            .expect("allowed dispatch returns final extensions");
        let metadata = returned.metadata.expect("parent metadata is retained");
        assert!(
            metadata.get("existing").is_some(),
            "parent metadata should be retained",
        );
        assert!(
            metadata.get("forged").is_none(),
            "handler must not install a forged metadata record",
        );
    }

    struct SourceFactory {
        calls: Arc<AtomicUsize>,
    }

    impl PluginFactory for SourceFactory {
        fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
            if config.hooks.as_slice() != [HOOK_METADATA_FETCH] {
                return Err(Box::new(PluginError::Config {
                    message: "test/source requires hooks: [metadata.fetch]".to_owned(),
                }));
            }
            let plugin = source(
                config.clone(),
                Arc::clone(&self.calls),
                Arc::new(AtomicBool::new(false)),
                false,
            );
            let handler: Arc<dyn AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<MetadataFetchHook, Source>::new(
                    Arc::clone(&plugin),
                ));
            Ok(PluginInstance {
                plugin,
                handlers: vec![(HOOK_METADATA_FETCH, handler)],
            })
        }
    }

    #[tokio::test]
    async fn configuration_factory_registers_a_typed_named_source() {
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = PolicyEngine::default();
        engine.register_factory(
            "test/source",
            Box::new(SourceFactory {
                calls: Arc::clone(&calls),
            }),
        );
        let policy = parse_config(
            "
engine_settings:
  dispatch: policy
plugins:
  - name: account
    kind: test/source
    hooks: [metadata.fetch]
    mode: sequential
routes:
  - tool: checkout
",
        )
        .unwrap();
        engine.load_config(policy).unwrap();

        let (result, _) = engine
            .invoke_named::<MetadataFetchHook>(
                HOOK_METADATA_FETCH,
                MetadataFetchRequest::new("account"),
                Extensions {
                    meta: Some(Arc::new(MetaExtension {
                        entity_type: Some("tool".to_owned()),
                        entity_name: Some("checkout".to_owned()),
                        ..MetaExtension::default()
                    })),
                    ..Extensions::default()
                },
                None,
            )
            .await;

        assert!(
            result.continue_processing,
            "configured source dispatch should continue",
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "configured source 'account' must be dispatched once",
        );
        assert!(
            MetadataFetchRequest::from_pipeline_result(&result)
                .is_some_and(|response| response.facts().is_some()),
            "configured source should return acquired facts",
        );
    }

    struct WrongFamily {
        config: PluginConfig,
    }

    impl Plugin for WrongFamily {
        fn config(&self) -> &PluginConfig {
            &self.config
        }
    }

    impl HookHandler<CmfHook> for WrongFamily {
        async fn handle(
            &self,
            _payload: &MessagePayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<MessagePayload> {
            PluginResult::allow()
        }
    }

    struct WrongFamilyFactory;

    impl PluginFactory for WrongFamilyFactory {
        fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
            let plugin = Arc::new(WrongFamily {
                config: config.clone(),
            });
            let handler: Arc<dyn AnyHookHandler> =
                Arc::new(TypedHandlerAdapter::<CmfHook, WrongFamily>::new(
                    Arc::clone(&plugin),
                ));
            Ok(PluginInstance {
                plugin,
                handlers: vec![(HOOK_METADATA_FETCH, handler)],
            })
        }
    }

    #[test]
    fn metadata_hook_rejects_a_mismatched_handler_family_at_registration() {
        let engine = PolicyEngine::default();
        let config = config("wrong", false);
        let plugin = Arc::new(WrongFamily {
            config: config.clone(),
        });
        let error = engine
            .register_handler_for_names::<CmfHook, _>(plugin, config, &[HOOK_METADATA_FETCH])
            .expect_err("CMF handler must not register as a metadata source");
        let message = error.to_string();
        assert!(
            message.contains("wrong"),
            "registration error should name the plugin",
        );
        assert!(
            message.contains("metadata.fetch"),
            "registration error should name the hook",
        );
        assert!(
            message.contains("cmf"),
            "registration error should name the handler family",
        );
    }

    #[test]
    fn configuration_load_rejects_a_mismatched_handler_family() {
        let engine = PolicyEngine::default();
        engine.register_factory("test/wrong", Box::new(WrongFamilyFactory));
        let policy = parse_config(
            "
engine_settings:
  dispatch: hooks
plugins:
  - name: wrong
    kind: test/wrong
    hooks: [metadata.fetch]
    mode: sequential
",
        )
        .unwrap();
        let error = engine
            .load_config(policy)
            .expect_err("config load must reject the mismatched family");
        let message = error.to_string();
        assert!(
            message.contains("wrong"),
            "config load error should name the plugin",
        );
        assert!(
            message.contains("metadata.fetch"),
            "config load error should name the hook",
        );
        assert!(
            message.contains("cmf"),
            "config load error should name the handler family",
        );
    }
}
