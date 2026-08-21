// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! **PPE is a policy enforcement runtime for AI agents.**
//!
//! It is a deterministic reference monitor between an agent and every
//! capability it invokes: tools, prompts, resources, inference providers, and
//! A2A methods. Each operation runs through a policy-defined pipeline that can
//! resolve identity, make an authorization decision (delegated to an engine
//! like Cedar or CEL), exchange and reduce credentials before a downstream
//! call, redact inputs and outputs, track information flow across calls, and
//! audit. You write that policy declaratively in APL, the configuration that
//! defines each operation's pipeline; PPE evaluates and enforces it at the
//! boundary, against state the model cannot observe or forge.
//!
//! - Source and issues: <https://github.com/praxis-proxy/policy>
//!
//! # This crate
//!
//! `praxis-policy` is the **host facade**: one dependency that re-exports the PPE
//! runtime (`praxis-policy-core`, `praxis-policy-apl-core`, `praxis-policy-apl-cmf`, `praxis-policy-apl-runtime`), so a host depends
//! on this crate instead of pinning each of them separately.
//!
//! By default it is the **engine only**: no builtin plugins are compiled in.
//! The bundled plugins, PDPs and session stores are registered from here, each
//! behind a feature, and only what you enable is compiled.
//!
//! # Usage
//!
//! Engine only (register your own factories):
//!
//! ```no_run
//! use std::sync::Arc;
//! use praxis_policy::PolicyEngine;
//!
//! let mgr = Arc::new(PolicyEngine::default());
//! // ... register host factories, then `praxis_policy_apl_runtime::register_apl(&mgr, opts)`.
//! ```
//!
//! With the bundled builtins (enable the `builtins` feature):
//!
//! ```ignore
//! use std::sync::Arc;
//! use praxis_policy::PolicyEngine;
//!
//! let mgr = Arc::new(PolicyEngine::default());
//! // Register every enabled builtin factory and install the APL config
//! // visitor (in-process defaults) in one call:
//! praxis_policy::install_builtins(&mgr);
//! // ... then load a config that references the enabled `kind`s.
//! ```
//!
//! # Features
//!
//! No plugins are on by default (`praxis-policy` alone is the engine).
//! `builtins` enables every bundled extension, including the Valkey session
//! store; or pick a granular subset (`jwt`, `oauth`, `elicitation-ciba`,
//! `cedar`, `cel`, `opa`, `valkey`). Any of them brings in the registration
//! helpers, and each one re-exports its own concrete factory type here.
//!
//! # Plugins the host supplies
//!
//! A plugin does not have to be bundled. Implement [`PluginFactory`] and hand it
//! to [`PolicyEngine::register_factory`] under the `kind:` your YAML names;
//! [`prelude`] is the surface to write it against. An unrecognised `kind` is a
//! load-time error, so a missing registration fails at startup rather than
//! silently skipping the plugin.
//!
//! `reference/plugins/` in this repository holds two worked examples, a PII
//! scanner and an audit logger. Neither is published or bundled; a host registers
//! them.

// Whole-crate re-exports for advanced use (types not surfaced below).

pub use {
    praxis_policy_apl_cmf, praxis_policy_apl_core, praxis_policy_apl_runtime, praxis_policy_core,
};

pub use praxis_policy_apl_core::step::PdpFactory;
pub use praxis_policy_apl_runtime::{
    AplOptions, DispatchCache, MemorySessionStore, SessionStore, SessionStoreFactory, register_apl,
};
pub use praxis_policy_core::engine::PolicyEngine;

/// The two types a host needs to accept a plugin it did not compile in:
/// [`PolicyEngine::register_factory`] takes a `Box<dyn PluginFactory>`, and
/// [`PluginInstance`] is what that factory returns.
///
/// Surfaced here so a host embedding the engine can name them without reaching
/// through to `praxis_policy_core`. Plugin *authors* get the same two names from
/// [`prelude`].
pub use praxis_policy_core::factory::{PluginFactory, PluginInstance};

/// Curated re-exports for plugin authors, so a plugin crate can depend on this
/// facade alone. See [`praxis_policy_core::prelude`].
pub use praxis_policy_core::prelude;

// Concrete factory types + KIND consts, each behind its feature.
#[cfg(feature = "cedar")]
pub use praxis_policy_pdp_cedar_direct::CedarDirectPdpFactory;
#[cfg(feature = "cel")]
pub use praxis_policy_pdp_cel::CelPdpFactory;
#[cfg(feature = "opa")]
pub use praxis_policy_pdp_opa::OpaPdpFactory;
#[cfg(feature = "oauth")]
pub use praxis_policy_plugin_delegator_oauth::{KIND as OAUTH_KIND, OAuthDelegatorFactory};
#[cfg(feature = "elicitation-ciba")]
pub use praxis_policy_plugin_elicitation_ciba::{CibaApproverFactory, KIND as CIBA_KIND};
#[cfg(feature = "jwt")]
pub use praxis_policy_plugin_identity_jwt::{JwtIdentityFactory, KIND as JWT_KIND};
#[cfg(feature = "valkey")]
pub use praxis_policy_session_valkey::{
    KIND as VALKEY_KIND, ValkeyConfig, ValkeySessionStoreFactory,
};

// =============================================================================
// Builtin registration
// =============================================================================
//
// The feature list, the factory re-exports above, and the registration table
// below all describe the same set, so they belong in one crate. Split across two,
// each side needs its own umbrella feature forwarding to the other, and the two
// can disagree: an umbrella that compiles every builtin in while exporting none
// of their types still builds.

/// Generate [`register_builtin_plugins`] from a feature to factory table. Each
/// entry expands to a `#[cfg(feature = ...)]`-gated, **explicit**
/// `register_factory(KIND, Box::new(Factory))` call keyed off the builtin
/// crate's own `KIND` const.
///
/// Explicit calls (rather than `inventory` / `linkme` link-section registration)
/// are deliberate: when this engine is linked into an FFI staticlib the linker
/// garbage-collects
/// sections nothing references, which would silently drop auto-registered
/// plugins. Naming each factory here keeps its object code alive.
#[cfg(feature = "_builtin")]
macro_rules! register_builtins {
    ( $( feature $feat:literal => $krate:ident :: $factory:ident ),* $(,)? ) => {
        /// Register every enabled by-kind plugin factory on `mgr`: identity
        /// (`jwt`), delegators (`oauth`), and elicitation approvers
        /// (`elicitation-ciba`). Call before loading a config so the engine can
        /// instantiate plugins whose YAML `kind:` matches.
        ///
        /// A host adds its own with [`PolicyEngine::register_factory`], after
        /// this call so a host registration wins on a shared `kind`.
        ///
        /// PDP and session-store factories are wired through [`AplOptions`]
        /// instead; see [`builtin_pdp_factories`] and
        /// [`builtin_session_store_factories`], or use [`install_builtins`].
        #[allow(unused_variables)]
        pub fn register_builtin_plugins(mgr: &std::sync::Arc<PolicyEngine>) {
            $(
                #[cfg(feature = $feat)]
                mgr.register_factory($krate::KIND, Box::new($krate::$factory));
            )*
        }
    };
}

#[cfg(feature = "_builtin")]
register_builtins! {
    feature "jwt"              => praxis_policy_plugin_identity_jwt::JwtIdentityFactory,
    feature "oauth"            => praxis_policy_plugin_delegator_oauth::OAuthDelegatorFactory,
    feature "elicitation-ciba" => praxis_policy_plugin_elicitation_ciba::CibaApproverFactory,
}

/// The enabled PDP factories, ready to drop into
/// [`AplOptions::pdp_factories`]. A route's `cedar:`, `cel:` or `opa:` step
/// selects which one runs.
// `vec![]` can't replace the conditional pushes: each element is
// `#[cfg]`-gated on its feature, so the set is built incrementally.
#[cfg(feature = "_builtin")]
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_pdp_factories() -> Vec<std::sync::Arc<dyn PdpFactory>> {
    let mut factories: Vec<std::sync::Arc<dyn PdpFactory>> = Vec::new();
    #[cfg(feature = "cedar")]
    factories.push(std::sync::Arc::new(CedarDirectPdpFactory::new()));
    #[cfg(feature = "cel")]
    factories.push(std::sync::Arc::new(CelPdpFactory::new()));
    #[cfg(feature = "opa")]
    factories.push(std::sync::Arc::new(OpaPdpFactory::new()));
    factories
}

/// The enabled session-store factories, ready to drop into
/// [`AplOptions::session_store_factories`]. A `global.apl.session_store:
/// { kind: ... }` config block selects one; absent that, the in-process
/// [`MemorySessionStore`] default stays active.
#[cfg(feature = "_builtin")]
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_session_store_factories() -> Vec<std::sync::Arc<dyn SessionStoreFactory>> {
    let mut factories: Vec<std::sync::Arc<dyn SessionStoreFactory>> = Vec::new();
    #[cfg(feature = "valkey")]
    factories.push(std::sync::Arc::new(ValkeySessionStoreFactory::new()));
    factories
}

/// Register every enabled plugin factory and install the APL config visitor on
/// `mgr` with in-process defaults (a [`MemorySessionStore`] and the default
/// baseline capabilities). The enabled PDP and session-store factories are wired
/// in, so a later config load can reference any of them by `kind`.
///
/// This is the one-call path; reach for [`register_builtin_plugins`] and
/// [`AplOptions`] directly when you need to customize capabilities or the
/// default store.
#[cfg(feature = "_builtin")]
pub fn install_builtins(mgr: &std::sync::Arc<PolicyEngine>) {
    register_builtin_plugins(mgr);

    let mut opts = AplOptions::in_process();
    opts.pdp_factories = builtin_pdp_factories();
    opts.session_store_factories = builtin_session_store_factories();

    let _visitor = register_apl(mgr, opts);
}

/// A default `HttpTransport` on hyper, for hosts that inject none.
///
/// Available with the `http-hyper` feature.
#[cfg(feature = "http-hyper")]
pub mod http_hyper;

#[cfg(feature = "http-hyper")]
pub use http_hyper::HyperTransport;

/// Install the bundled hyper transport so plugins can perform outbound
/// HTTP.
///
/// PPE performs no HTTP itself, so without a transport a plugin that
/// needs one — a JWKS fetch, a token exchange — fails at initialization
/// with a message saying so. A host embedding PPE in a process that
/// already has an HTTP stack should install *that* instead, via
/// [`PolicyEngine::set_http_transport`], so the process keeps one
/// connection pool and one egress path.
///
/// Deliberately not folded into [`install_builtins`]. A host calling
/// `install_builtins` should not acquire a second HTTP stack because
/// some unrelated crate in its dependency graph happened to turn this
/// feature on. Wiring an egress path is worth one explicit line.
///
/// The transport builds its pool on first use, so calling this from a
/// short-lived initialization runtime is safe.
///
/// Returns `false` if a transport was already installed, in which case
/// the existing one is kept.
#[cfg(feature = "http-hyper")]
pub fn install_default_http_transport(mgr: &std::sync::Arc<PolicyEngine>) -> bool {
    mgr.set_http_transport(std::sync::Arc::new(http_hyper::HyperTransport::new()))
}

#[cfg(all(test, feature = "_builtin"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn install_builtins_runs_without_panic() {
        let mgr = Arc::new(PolicyEngine::default());
        install_builtins(&mgr);
    }

    #[test]
    fn pdp_factories_track_enabled_features() {
        let expected = usize::from(cfg!(feature = "cedar"))
            + usize::from(cfg!(feature = "cel"))
            + usize::from(cfg!(feature = "opa"));
        assert_eq!(
            builtin_pdp_factories().len(),
            expected,
            "one PDP factory per enabled feature",
        );
    }

    #[test]
    fn session_store_factories_track_enabled_features() {
        let expected = usize::from(cfg!(feature = "valkey"));
        assert_eq!(
            builtin_session_store_factories().len(),
            expected,
            "one session-store factory per enabled feature",
        );
    }

    /// Load a one-plugin config against a engine with the builtins installed,
    /// and return the error text (empty string on success).
    ///
    /// Goes through `load_config_yaml` rather than inspecting the registry
    /// because that is the path an operator hits: the question is whether their
    /// YAML `kind:` resolves, not what the map contains.
    fn load_error_for_kind(kind: &str) -> String {
        let mgr = Arc::new(PolicyEngine::default());
        install_builtins(&mgr);
        let yaml =
            format!("plugins:\n  - name: probe\n    kind: {kind}\n    hooks: [identity.resolve]\n");
        match mgr.load_config_yaml(&yaml) {
            Ok(()) => String::new(),
            Err(e) => format!("{e}"),
        }
    }

    /// The by-kind plugin table had no test, unlike the PDP and session-store
    /// lists. So a builtin could leave the umbrella, or quietly rejoin it, with
    /// nothing failing. This pins the set.
    ///
    /// Each enabled builtin must resolve its `kind`. The probe config is
    /// deliberately minimal, so most of these still fail on their own settings —
    /// what matters is that they fail on settings rather than on a missing
    /// factory, which is a different message and a different operator problem.
    #[test]
    fn every_enabled_builtin_resolves_its_kind() {
        let expected = [
            (cfg!(feature = "jwt"), "identity/jwt"),
            (cfg!(feature = "oauth"), "delegator/oauth"),
            (cfg!(feature = "elicitation-ciba"), "elicitation/ciba"),
        ];
        for (enabled, kind) in expected {
            if !enabled {
                continue;
            }
            let err = load_error_for_kind(kind);
            assert!(
                !err.contains("no factory registered"),
                "{kind} is enabled, so its factory must be registered; got: {err}"
            );
        }
    }

    /// The PII scanner and audit logger are reference implementations now, so the
    /// umbrella must not register them. A host supplies them instead.
    ///
    /// Asserted as the exact operator-visible failure, because that message is
    /// what tells someone their config needs a host registration rather than a
    /// different feature flag.
    #[test]
    fn the_reference_plugins_are_not_registered_by_the_umbrella() {
        for kind in ["validator/pii-scan", "audit/logger"] {
            let err = load_error_for_kind(kind);
            assert!(
                err.contains("no factory registered"),
                "{kind} must not be bundled; got: {err}"
            );
            assert!(
                err.contains(kind),
                "the error must name the unresolved kind: {err}"
            );
        }
    }
}
