// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Hook system.
//
// Provides the core abstractions for defining and dispatching hooks:
//
// - [`HookTypeDef`] — marker trait associating a typed payload + result with a hook name.
// - [`PluginPayload`] — base trait for all hook payloads.
// - [`PluginResult`] — result type with separate payload and extension modifications.
// - [`Extensions`] — capability-gated extension view passed to handlers.
// - [`define_hook!`] — macro for declaring new hook types with handler traits.
// - [`define_hooks!`] — macro co-declaring a hook name and its routing metadata.
//
// Hook types are open — hosts define their own using define_hook! alongside the built-ins.

/// Adapters that erase a typed handler behind the dispatch trait.
pub mod adapter;
/// The `define_hooks!` macro, which co-declares a hook name and its metadata.
pub mod declare;
/// The `define_hook!` macro, which declares a hook in one place.
pub mod macros;
/// Hook descriptions used for introspection.
pub mod metadata;
/// The payload trait and the extension container passed alongside it.
pub mod payload;
/// The handler trait and its result type.
pub mod trait_def;
/// Hook type identity and the open name registry.
pub mod types;

// Re-export core types at the hooks level
pub use adapter::TypedHandlerAdapter;
pub use metadata::{
    HookMetadata, HookPhase, lookup as lookup_hook_metadata, register_hook_metadata,
};
pub use payload::{Extensions, PluginPayload};
pub use trait_def::{HookHandler, HookTypeDef, PluginResult};
pub use types::{HookType, builtin_hook_types, hook_type_from_str};
