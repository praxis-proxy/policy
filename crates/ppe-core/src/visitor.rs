// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `ConfigVisitor` — extension point for external orchestrators (APL,
// future Rego/Cedar-direct/custom) to participate in unified-config
// loading without praxis-policy-core taking a dep on any specific orchestrator.
//
// # How it fits
//
// The host calls `PolicyEngine::load_config_yaml(yaml)`. praxis-policy-core
// parses the YAML twice (once into a typed `PolicyConfig`, once into a
// raw `serde_yaml::Value`), lets visitors validate the document, runs its own
// plugin instantiation, then walks each visitor in registration order:
//
//   0. `validate_before_load` — before the new runtime snapshot is published
//   1. `visit_plugins`       — once per visitor, immediately after
//                              praxis-policy-core's own plugin instantiation,
//                              receiving the parsed `&[PluginConfig]`
//                              so the visitor doesn't have to re-parse
//                              the root `plugins:` block from raw YAML.
//   2. `visit_global`        — global config block
//   3. `visit_default`       — once per entity_type with a default
//   4. `visit_policy_bundle` — once per named policy group (tag)
//   5. `visit_route`         — once per route
//
// Each visitor sees the **raw YAML** so it can find its own block
// (e.g. a `rego:` block) under any section without praxis-policy-core having
// to know about it. Parsed sibling data is passed alongside (`RouteEntry` for
// routes) for convenience: an orchestrator building an annotation key
// reads which selector a route declares from
// `crate::config::route_entity_identity` rather than inspecting the
// selector fields itself.
//
// # Why visit per-section rather than per-whole-config
//
// Visitors typically accumulate state across the hierarchy (e.g. APL's
// visitor compiles globals/defaults/tag-bundles into `CompiledRoute`s
// kept in visitor state, then merges them into each route at
// `visit_route`). Per-section calls give the orchestrator a natural
// place to do that accumulation without re-parsing.
//
// # Visit order
//
// All sections for one visitor run before the next visitor starts. For
// single-visitor deployments (the common case) this is identical to
// any other ordering; for multi-visitor it gives each visitor a
// consistent view of its own internal state. Visitor methods are
// invoked synchronously — no async runtime needed at load time.

use std::sync::Arc;

use crate::config::RouteEntry;
use crate::engine::PolicyEngine;
use crate::plugin::PluginConfig;

/// Error type returned by a config visitor. Boxed `dyn Error` so each
/// orchestrator can carry its own error variants (parse errors, missing
/// plugin references, etc.) without praxis-policy-core having to enumerate them.
pub type VisitorError = Box<dyn std::error::Error + Send + Sync>;

/// Extension point for external orchestrators to participate in unified
/// config loading. Register via [`PolicyEngine::register_visitor`];
/// invoked during [`PolicyEngine::load_config_yaml`].
///
/// All methods have default no-op implementations — a visitor only
/// overrides the sections it cares about.
pub trait ConfigVisitor: Send + Sync {
    /// Stable identifier for diagnostics — included in error contexts
    /// if a visitor method returns Err. Convention: short kebab-case naming
    /// the orchestrator (e.g. `"apl"`, `"rego"`). A label, not a dispatch key:
    /// nothing looks a visitor up by it, and a visitor need not have a YAML key
    /// of its own — APL reads the policy terms written on each section.
    fn name(&self) -> &str;

    /// Validate the complete raw document before the engine publishes its new
    /// runtime snapshot. Use this only for checks that can run without
    /// instantiating plugins or mutating visitor state.
    /// # Errors
    ///
    /// Returns `VisitorError` when the document must be rejected atomically,
    /// leaving the currently active runtime snapshot unchanged.
    fn validate_before_load(&self, _yaml: &serde_yaml::Value) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit the typed plugin declarations from the root `plugins:`
    /// block. Called once per visitor, immediately after praxis-policy-core's
    /// own plugin instantiation completes and before any hierarchy
    /// section is walked. Visitors that need a per-name registry of
    /// hook / capability / `on_error` metadata can populate it here
    /// without re-parsing the YAML — praxis-policy-core has already validated
    /// the block (no duplicate names, etc.) by this point.
    /// # Errors
    ///
    /// Returns `VisitorError` when the implementor rejects this section. The
    /// error aborts the config load, and earlier sections are not rolled back.
    fn visit_plugins(
        &self,
        _mgr: &Arc<PolicyEngine>,
        _plugins: &[PluginConfig],
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit the top-level `global:` block. `yaml` is the raw value at
    /// that path, or `Value::Null` if `global:` is absent.
    /// # Errors
    ///
    /// Returns `VisitorError` when the implementor rejects this section. The
    /// error aborts the config load, and earlier sections are not rolled back.
    fn visit_global(
        &self,
        _mgr: &Arc<PolicyEngine>,
        _yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit one entry in `global.defaults`. Called once per
    /// `(entity_type, default_block)` pair. `yaml` is the raw value at
    /// `global.defaults.<entity_type>`.
    /// # Errors
    ///
    /// Returns `VisitorError` when the implementor rejects this section. The
    /// error aborts the config load, and earlier sections are not rolled back.
    fn visit_default(
        &self,
        _mgr: &Arc<PolicyEngine>,
        _entity_type: &str,
        _yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit one entry in top-level `groups:` (a named policy bundle).
    /// Called once per `(tag, policy_group)` pair. `yaml` is the raw
    /// value at `groups.<tag>`.
    /// # Errors
    ///
    /// Returns `VisitorError` when the implementor rejects this section. The
    /// error aborts the config load, and earlier sections are not rolled back.
    fn visit_policy_bundle(
        &self,
        _mgr: &Arc<PolicyEngine>,
        _tag: &str,
        _yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Visit one route entry. `yaml` is the raw value at `routes[i]`
    /// (so an orchestrator can find its own block there); `parsed`
    /// is the typed `RouteEntry` praxis-policy-core deserialized (so the
    /// orchestrator can read `meta.scope`, `meta.tags`, etc. without
    /// re-parsing). For the selector a route declares and the names it
    /// contributes, call [`crate::config::route_entity_identity`] rather
    /// than reading `tool`/`resource`/`prompt`/`llm`/`http` directly, so
    /// every annotation key comes from one mapping.
    /// # Errors
    ///
    /// Returns `VisitorError` when the implementor rejects this section. The
    /// error aborts the config load, and earlier sections are not rolled back.
    fn visit_route(
        &self,
        _mgr: &Arc<PolicyEngine>,
        _yaml: &serde_yaml::Value,
        _parsed: &RouteEntry,
    ) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Called once per visitor after its own route walk, with no arguments
    /// beyond the engine. The last thing a visitor sees on a load.
    ///
    /// The other methods each see one section, and several of them may not run
    /// at all: `visit_global` fires before any route is known, and a config
    /// with no `global:`, `groups:`, or `routes:` fires nothing after
    /// `visit_plugins`. A check whose input is the union of every section, such
    /// as which declared plugins any policy reaches, has nowhere else to run.
    ///
    /// # Errors
    ///
    /// Returns `VisitorError` when the implementor rejects the config as a
    /// whole. The error aborts the config load, and earlier sections are not
    /// rolled back.
    fn visit_complete(&self, _mgr: &Arc<PolicyEngine>) -> Result<(), VisitorError> {
        Ok(())
    }

    /// Config keys this visitor reads that praxis-policy-core does not model.
    /// A configuration load rejects a key nothing recognizes, on a route and in
    /// the sections above it, so an orchestrator naming its block something
    /// praxis-policy-core has never heard of declares it here to stay
    /// loadable.
    ///
    /// Only consulted on the `load_config_yaml` path, the one that walks
    /// visitors at all.
    fn extra_route_keys(&self) -> &[&str] {
        &[]
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    /// A visitor that overrides nothing but `name`. That is the documented
    /// contract: a visitor opts into the sections it cares about and inherits a
    /// no-op for the rest. Every visitor in the test suite overrides the
    /// interesting methods, so the defaults themselves had never run, and a
    /// default that returned an error rather than `Ok(())` would break any
    /// partial visitor without a single test noticing.
    #[derive(Debug)]
    struct SilentVisitor;

    impl ConfigVisitor for SilentVisitor {
        fn name(&self) -> &str {
            "silent"
        }
    }

    #[test]
    fn a_visitor_that_overrides_nothing_does_not_block_a_config_load() {
        // Carries every section the trait exposes, so each default is walked:
        // plugins, global, global.defaults, groups, and a route.
        let yaml = r#"
engine_settings:
  dispatch: policy
global:
  defaults:
    tool:
      authorization:
        pre_invocation:
          - "require(authenticated)"
groups:
  all:
    authorization:
      pre_invocation:
        - "require(authenticated)"
routes:
  - tool: get_compensation
"#;
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_visitor(Arc::new(SilentVisitor));
        mgr.load_config_yaml(yaml)
            .expect("a visitor that overrides nothing must not fail the load");
    }

    #[test]
    fn the_visitor_name_is_what_diagnostics_report() {
        assert_eq!(SilentVisitor.name(), "silent");
    }

    /// A visitor that reads a route key praxis-policy-core does not model, the
    /// shape an out-of-tree Rego or Cedar orchestrator takes.
    #[derive(Debug)]
    struct RegoVisitor;

    impl ConfigVisitor for RegoVisitor {
        fn name(&self) -> &str {
            "rego"
        }

        fn extra_route_keys(&self) -> &[&str] {
            &["rego"]
        }
    }

    const ROUTE_WITH_A_VISITOR_KEY: &str = "
engine_settings:
  dispatch: policy
routes:
  - tool: get_compensation
    rego:
      package: hr.authz
";

    /// The route-key check exists to catch a typo, so it has to take the keys a
    /// visitor declares on faith. A closed list would turn every out-of-tree
    /// orchestrator's own block into a load failure.
    #[test]
    fn a_route_key_a_visitor_declares_is_accepted() {
        let mgr = Arc::new(PolicyEngine::default());
        mgr.register_visitor(Arc::new(RegoVisitor));
        mgr.load_config_yaml(ROUTE_WITH_A_VISITOR_KEY)
            .expect("a key the registered visitor consumes must load");
    }

    /// The other half of the same behavior: with nobody consuming the key it is
    /// a typo again, named in the failure.
    #[test]
    fn the_same_route_key_is_rejected_when_no_visitor_claims_it() {
        let mgr = Arc::new(PolicyEngine::default());
        let err = mgr
            .load_config_yaml(ROUTE_WITH_A_VISITOR_KEY)
            .expect_err("an unclaimed route key must fail the load")
            .to_string();
        assert!(err.contains("rego"), "the key as written: {err}");
        assert!(err.contains("route 0"), "the route index: {err}");
    }
}
