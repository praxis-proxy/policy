// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// PPE Core library root.
//
// Pure Rust plugin runtime with no FFI, WASM, or PyO3 dependencies.
// Provides the PolicyEngine, 5-phase executor, hook registry,
// unified config parser, and all core types.
//
// # Modules
//
// - [`plugin`] — Plugin trait, PluginRef, PluginMetadata, PluginConfig
// - [`hooks`]  — HookType (open string registry), payload/result traits
// - [`executor`] — 5-phase execution engine (sequential → transform → audit → concurrent → fire_and_forget)
// - [`engine`] — PolicyEngine lifecycle and hook dispatch
// - [`registry`] — PluginInstanceRegistry and HookRegistry
// - [`config`] — Unified YAML configuration parsing
// - [`factory`] — Plugin factory registry for config-driven instantiation
// - [`context`] — PluginContext (local_state + global_state)
// - [`cmf`] — ContextForge Message Format (Message, ContentPart, enums)
// - [`identity`] — IdentityResolve hook family (subject / client /
//                   workload resolution from raw credentials)
// - [`delegation`] — TokenDelegate hook family (outbound credential
//                     minting for downstream calls)
// - [`elicitation`] — Elicitation hook family (human-in-the-loop:
//                     approval, confirmation, step-up, …)
// - [`error`] — Error types, violations, and result types

//! The plugin runtime: engine, executor, hook registry, and config parser.
//!
//! Pure Rust with no FFI, WASM, or Python bindings. Plugins register against
//! named hooks and the executor dispatches them in five phases, reading every
//! scheduling decision from trusted config rather than from the plugin.

/// The common message format: messages, content parts, and read-only views.
pub mod cmf;
/// YAML configuration parsing for plugins, routes, and policies.
pub mod config;
/// Per-plugin state carried across hook invocations.
pub mod context;
/// The token delegation hook and its payload.
pub mod delegation;
/// The elicitation hook, for out-of-band human approval.
pub mod elicitation;
/// Plugin lifecycle and hook dispatch.
pub mod engine;
/// Plugin errors and policy violations.
pub mod error;
/// Five-phase plugin dispatch.
pub mod executor;
/// Typed request attributes that plugins read and write.
pub mod extensions;
/// Config-driven plugin construction.
pub mod factory;
/// Hook types, payloads, and the handler traits.
pub mod hooks;
/// Host-provided services and the carriers that lend them to a plugin.
pub mod host;
/// The outbound-HTTP seam. Types and a trait; PPE performs no HTTP itself.
pub mod http;
/// Which IP addresses an outbound policy call must not reach. The shared
/// range table; a transport enforces it where it dials.
pub mod http_addr;
/// Retry policy for outbound HTTP, keyed to whether a repeat is safe.
pub mod http_retry;
/// A scripted `HttpTransport` for tests, including the failure paths a
/// mock server cannot produce. Requires the `test-util` feature.
#[cfg(any(test, feature = "test-util"))]
pub mod http_testing;
/// The identity resolution hook and its payload.
pub mod identity;
/// The `Plugin` trait and its trusted configuration.
pub mod plugin;
/// Curated re-exports for plugin authors.
pub mod prelude;
/// Plugin instance and hook registries.
pub mod registry;
/// Config visitors, which let a dialect compile its own route blocks at load time.
pub mod visitor;
