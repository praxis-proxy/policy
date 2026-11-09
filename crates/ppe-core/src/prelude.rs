// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Curated surface for plugin authors.
//!
//! Everything needed to write a plugin and hand it to a host: the `Plugin`
//! trait, the hook traits, the payload and result types, the CMF domain objects,
//! and the factory types a plugin exposes so a host can construct it. Import it
//! as a block rather than tracking which module each name lives in.
//!
//! A whole plugin, from this module alone. The example is compiled, not
//! `ignore`d, so that a name dropped from the groups below fails here rather
//! than only in a downstream crate.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use praxis_policy_core::prelude::*;
//!
//! /// Denies any message whose text mentions a banned word.
//! struct WordBlocker {
//!     cfg: PluginConfig,
//! }
//!
//! impl Plugin for WordBlocker {
//!     fn config(&self) -> &PluginConfig {
//!         &self.cfg
//!     }
//! }
//!
//! impl HookHandler<CmfHook> for WordBlocker {
//!     async fn handle(
//!         &self,
//!         payload: &MessagePayload,
//!         _ext: &Extensions,
//!         _ctx: &mut PluginContext,
//!     ) -> PluginResult<MessagePayload> {
//!         if payload.message.get_text_content().contains("banned") {
//!             return PluginResult::deny(PluginViolation::new(
//!                 "example.banned_word",
//!                 "the payload mentions a banned word",
//!             ));
//!         }
//!         PluginResult::allow()
//!     }
//! }
//!
//! /// What the host registers, via `PolicyEngine::register_factory`.
//! struct WordBlockerFactory;
//!
//! impl PluginFactory for WordBlockerFactory {
//!     fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
//!         let plugin = Arc::new(WordBlocker { cfg: config.clone() });
//!         let adapter: Arc<dyn AnyHookHandler> =
//!             Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
//!         Ok(PluginInstance {
//!             plugin,
//!             handlers: vec![("cmf.tool_pre_invoke", adapter)],
//!         })
//!     }
//! }
//! ```
//!
//! This is a module rather than a companion crate because it offers a namespace,
//! not a smaller dependency tree: every name here is re-exported from this crate,
//! so depending on a wrapper would pull the same graph.
//!
//! Note that `PluginFactory` belongs here even though a *host* is what calls it.
//! The plugin is what implements it, so a plugin crate that cannot name it cannot
//! expose itself at all.

// Plugin lifecycle

pub use crate::plugin::{OnError, Plugin, PluginConfig, PluginMode};

// Hook system
pub use crate::hooks::{Extensions, HookHandler, HookTypeDef, PluginPayload, PluginResult};
pub use crate::metadata::{
    HOOK_METADATA_FETCH, MetadataFetchHook, MetadataFetchRequest, MetadataFetchResult,
};

// Construction. A plugin implements `PluginFactory` and returns a
// `PluginInstance`; `TypedHandlerAdapter` is how a typed `HookHandler` is
// type-erased into the `AnyHookHandler` list that instance carries, and naming
// that trait is unavoidable because the handler vec's element type is explicit.
pub use crate::factory::{PluginFactory, PluginInstance};
pub use crate::hooks::TypedHandlerAdapter;
pub use crate::registry::AnyHookHandler;

// Context
pub use crate::context::PluginContext;

// Errors
pub use crate::error::{PluginError, PluginViolation};

// The define_hook! macro. Exported at the crate root by `#[macro_export]`, so it
// is named through `crate::` rather than the module it is written in.
pub use crate::define_hook;

// CMF types
pub use crate::cmf::{
    // Content parts and domain objects
    AudioSource,
    // Enums
    Channel,
    // Message and payload
    CmfHook,
    ContentPart,
    ContentType,
    DocumentSource,
    ImageSource,
    Message,
    MessagePayload,
    PromptRequest,
    PromptResult,
    Resource,
    ResourceReference,
    ResourceType,
    Role,
    ToolCall,
    ToolResult,
    VideoSource,
};
