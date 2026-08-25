// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Hook routing metadata — answers "what dispatch context does this
// hook name belong to?"
//
// # What this solves
//
// praxis-policy-core's `invoke_named::<H>(hook_name, ...)` already routes to
// the right handlers based on the hook name. But APL's dispatcher
// (`praxis-policy-apl-runtime/src/dispatch_plan.rs`) needs a finer-grained question:
// when a plugin is registered for MULTIPLE hooks (e.g.
// `[cmf.tool_pre_invoke, cmf.tool_post_invoke]`), which entry should
// fire for the current dispatch context?
//
// Pre-2026-05-25 dispatch_plan used a naming heuristic — any hook
// name containing "field", "redact", "scan", or "validate" was
// classified as field-context, everything else as step-context. Two
// problems:
//
//   1. **Multi-hook bug.** Two step-context hooks on the same plugin
//      (pre + post) collapsed to "first non-field wins" — silent
//      wrong dispatch when pre_invocation and post_invocation needed
//      different entries.
//   2. **The "field-hook" classification didn't match any real hook.**
//      No CMF hook actually carries `field` / `redact` / `scan` /
//      `validate` in its name — the heuristic was anticipating a
//      convention no plugin uses. APL's field-stage dispatch (from
//      `args:` / `result:` pipelines) routes to the same hook a
//      plugin registers under for step dispatch.
//
// This module replaces the heuristic with an explicit hook-name →
// metadata table.
//
// # The table
//
// Each entry maps a hook name to `HookMetadata`:
//
//   * `entity_type` — `Some("tool")`, `Some("llm")`, etc. for hooks
//     tied to an entity type; `None` for hook families that apply
//     regardless of entity (`identity.resolve`, `token.delegate`).
//   * `phase` — `Pre` / `Post` / `Unphased`. APL's evaluator uses
//     this to pick the right entry for the current phase context.
//
// Lookup is the foundation for `praxis-policy-apl-runtime::dispatch_plan`'s entry
// selection.
//
// # Phase semantics
//
// APL phases map to hook phases:
//
//   * `args:` field stage     → looks for `Pre` hooks
//   * `pre_invocation:` step       → looks for `Pre` hooks
//   * `result:` field stage   → looks for `Post` hooks
//   * `post_invocation:` step      → looks for `Post` hooks
//
// A plugin that wants to discriminate "args field stage" from
// "pre_invocation step" — both Pre context — inspects `PluginContext::hook_name()`
// itself. The hook-routing layer doesn't slice phase finer than
// Pre/Post.
//
// # Custom hook metadata
//
// Hosts and plugin authors can register metadata for custom hook
// names via [`register_hook_metadata`]. `lookup` returns `None` for a
// name the registry does not hold, leaving the fallback to the caller:
// [`HookMetadata::permissive`] is the wildcard that matches any
// dispatch context, so a caller opting into it lets unregistered hooks
// dispatch on the first registered entry. Authors who want phase-aware
// behavior register metadata explicitly.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::cmf::constants::CMF_HOOK_METADATA;
use crate::delegation::hook::DELEGATION_HOOK_METADATA;
use crate::elicitation::hook::ELICITATION_HOOK_METADATA;
use crate::identity::hook::IDENTITY_HOOK_METADATA;

/// Lifecycle position a hook occupies for dispatcher purposes.
///
/// APL's `args/pre_invocation` phases dispatch to `Pre` hooks; APL's
/// `result/post_invocation` phases dispatch to `Post` hooks. Hook families
/// outside the request-lifecycle model (identity at request entry,
/// token-delegate inside authorization) use `Unphased` and match any
/// requested phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPhase {
    /// Pre-invocation hook — e.g. `cmf.tool_pre_invoke`,
    /// `cmf.llm_input`. Dispatched from APL's `args:` field stages
    /// and `pre_invocation:` steps.
    Pre,
    /// Post-invocation hook — e.g. `cmf.tool_post_invoke`,
    /// `cmf.llm_output`. Dispatched from APL's `result:` field stages
    /// and `post_invocation:` steps.
    Post,
    /// Not phase-bound. Covers hook families that fire once per
    /// request without an APL phase concept (`identity.resolve`,
    /// `token.delegate`) AND custom hooks the framework doesn't know
    /// about. APL's dispatcher matches `Unphased` against any
    /// requested phase — conservative default that lets unknown
    /// hooks still dispatch.
    Unphased,
}

/// Metadata describing what dispatch context a hook name belongs to.
/// See module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookMetadata {
    /// Entity type the hook applies to (`"tool"`, `"llm"`, `"prompt"`,
    /// `"resource"`). `None` means "applies regardless of `entity_type`"
    /// — used for hooks that don't tie to MCP's entity-type taxonomy.
    pub entity_type: Option<&'static str>,
    /// Lifecycle phase the hook occupies.
    pub phase: HookPhase,
}

impl HookMetadata {
    /// The wildcard default, `entity_type: None` and `phase: Unphased`.
    /// [`matches`][Self::matches] treats `Unphased` as "matches any
    /// phase", so a caller substituting this for an absent registry
    /// entry lets the hook dispatch on the first registered entry.
    /// Deliberate, not the result of a failed lookup: `lookup` returns
    /// `None` and the caller chooses this.
    pub const fn permissive() -> Self {
        Self {
            entity_type: None,
            phase: HookPhase::Unphased,
        }
    }

    /// Whether this hook's metadata matches a dispatch context.
    ///
    /// Matching rules:
    ///
    /// - `entity_type`: a hook tied to a specific `entity_type`
    ///   (`Some("tool")`) matches only contexts with that entity
    ///   type. A hook with `entity_type: None` matches any context.
    ///   A request without an `entity_type` (`None`) matches any hook
    ///   — the dispatcher hasn't specified what entity is in play,
    ///   so we can't filter on it.
    /// - `phase`: exact match between hook's phase and the requested
    ///   phase, EXCEPT `Unphased` is a wildcard from either side
    ///   (lets custom / unregistered hooks dispatch without phase
    ///   rules).
    pub fn matches(&self, request_entity_type: Option<&str>, requested_phase: HookPhase) -> bool {
        let entity_ok = match (self.entity_type, request_entity_type) {
            (Some(hook_et), Some(req_et)) => hook_et == req_et,
            (Some(_), None) => true, // request didn't specify; don't filter
            (None, _) => true,       // hook applies to any entity_type
        };
        if !entity_ok {
            return false;
        }
        match (self.phase, requested_phase) {
            (HookPhase::Unphased, _) | (_, HookPhase::Unphased) => true,
            (a, b) => a == b,
        }
    }
}

/// The per-module hook tables, in declaration order. Each is emitted by
/// that module's `define_hooks!` invocation, so a hook cannot have a
/// constant without a row. What a new module *can* still get wrong is
/// being left out of this list, which makes every hook it owns
/// unregistered at once rather than one of them quietly.
const HOOK_TABLES: &[&[(&str, HookMetadata)]] = &[
    CMF_HOOK_METADATA,
    IDENTITY_HOOK_METADATA,
    DELEGATION_HOOK_METADATA,
    ELICITATION_HOOK_METADATA,
];

/// How many rows the per-module tables hold between them, so the flat
/// table's size comes from the tables rather than being restated.
#[allow(
    clippy::indexing_slicing,
    reason = "const context; bounds are the loop conditions"
)]
const HOOK_COUNT: usize = {
    let mut total = 0;
    let mut i = 0;
    while i < HOOK_TABLES.len() {
        total += HOOK_TABLES[i].len();
        i += 1;
    }
    total
};

/// Flatten [`HOOK_TABLES`] at compile time. Neither `Iterator` nor
/// `slice::get` is available in const context, hence the index arithmetic.
#[allow(
    clippy::indexing_slicing,
    reason = "const context; bounds are the loop conditions"
)]
const fn concat_hook_tables<const N: usize>() -> [(&'static str, HookMetadata); N] {
    let mut out = [("", HookMetadata::permissive()); N];
    let mut table = 0;
    let mut written = 0;
    while table < HOOK_TABLES.len() {
        let rows = HOOK_TABLES[table];
        let mut row = 0;
        while row < rows.len() {
            out[written] = rows[row];
            written += 1;
            row += 1;
        }
        table += 1;
    }
    out
}

const BUILTIN_HOOK_METADATA_ROWS: [(&str, HookMetadata); HOOK_COUNT] = concat_hook_tables();

/// Built-in hook metadata, the authority for which hooks
/// `praxis-policy-core` dispatches. Every enumeration of hook names is a
/// projection of this table, and the config loader validates declared
/// `hooks:` entries against the registry it seeds. Hosts register
/// additional entries via [`register_hook_metadata`].
pub(crate) const BUILTIN_HOOK_METADATA: &[(&str, HookMetadata)] = &BUILTIN_HOOK_METADATA_ROWS;

/// Runtime-registered additions to the metadata table. Hosts /
/// plugin authors call [`register_hook_metadata`] to populate.
/// Initialized from `BUILTIN_HOOK_METADATA` on first access.
fn registry() -> &'static RwLock<HashMap<String, HookMetadata>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, HookMetadata>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut map: HashMap<String, HookMetadata> = HashMap::new();
        for (name, meta) in BUILTIN_HOOK_METADATA {
            map.insert((*name).to_owned(), *meta);
        }
        RwLock::new(map)
    })
}

/// Look up metadata for a hook name. `None` means the registry holds
/// no entry, which is distinct from an entry whose phase is
/// [`HookPhase::Unphased`], a hook deliberately outside the request
/// lifecycle. A caller that wants the old permissive behavior asks for
/// it: `.unwrap_or_else(HookMetadata::permissive)`.
pub fn lookup(hook_name: &str) -> Option<HookMetadata> {
    let r = registry()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    r.get(hook_name).copied()
}

/// Register or override metadata for a hook name. Idempotent — a
/// host re-registering the same hook with the same metadata is fine.
/// Re-registering with different metadata overwrites the previous
/// entry; intentional for hosts that need to customize defaults.
///
/// # Ordering
///
/// Call this **before** loading config that names the hook. The config
/// loader validates every declared `hooks:` entry against this registry,
/// so a hook registered afterwards is unknown at the moment it is
/// checked and the load refuses. A host declaring several hooks can emit
/// them with [`define_hooks!`][crate::define_hooks] and register the
/// resulting slice in a loop; `praxis-policy-core`'s own tables are
/// seeded on first access and need no call.
///
/// Thread-safe; intended to be called at startup. Concurrent calls
/// are serialized via the registry's `RwLock`.
pub fn register_hook_metadata(hook_name: impl Into<String>, meta: HookMetadata) {
    let mut w = registry()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    w.insert(hook_name.into(), meta);
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::cmf::constants::{
        ENTITY_LLM, ENTITY_TOOL, HOOK_CMF_HTTP_REQUEST, HOOK_CMF_HTTP_RESPONSE,
        HOOK_CMF_LLM_OUTPUT, HOOK_CMF_TOOL_PRE_INVOKE,
    };
    use crate::delegation::HOOK_TOKEN_DELEGATE;
    use crate::elicitation::HOOK_ELICIT;
    use crate::identity::HOOK_IDENTITY_RESOLVE;

    #[test]
    fn cmf_tool_pre_invoke_is_pre_phase_for_tool_entity() {
        let meta = lookup(HOOK_CMF_TOOL_PRE_INVOKE).expect("registered");
        assert_eq!(meta.entity_type, Some(ENTITY_TOOL));
        assert_eq!(meta.phase, HookPhase::Pre);
    }

    #[test]
    fn cmf_llm_output_is_post_phase_for_llm_entity() {
        let meta = lookup(HOOK_CMF_LLM_OUTPUT).expect("registered");
        assert_eq!(meta.entity_type, Some(ENTITY_LLM));
        assert_eq!(meta.phase, HookPhase::Post);
    }

    #[test]
    fn identity_resolve_is_unphased_no_entity() {
        let meta = lookup(HOOK_IDENTITY_RESOLVE).expect("registered");
        assert_eq!(meta.entity_type, None);
        assert_eq!(meta.phase, HookPhase::Unphased);
    }

    #[test]
    fn token_delegate_is_unphased_no_entity() {
        let meta = lookup(HOOK_TOKEN_DELEGATE).expect("registered");
        assert_eq!(meta.entity_type, None);
        assert_eq!(meta.phase, HookPhase::Unphased);
    }

    #[test]
    fn an_unregistered_hook_has_no_entry() {
        assert_eq!(lookup("custom.unrecognized_hook"), None);
    }

    #[test]
    fn an_unphased_hook_is_distinguishable_from_an_absent_one() {
        // The three unphased hooks used to be indistinguishable from a
        // name nobody registered, which is how a missing row read as a
        // deliberate choice.
        for name in [HOOK_IDENTITY_RESOLVE, HOOK_TOKEN_DELEGATE, HOOK_ELICIT] {
            let meta = lookup(name).expect("registered");
            assert_eq!(meta.phase, HookPhase::Unphased, "{name}");
        }
        assert_eq!(lookup("identity.resolve_typo"), None);
    }

    #[test]
    fn every_builtin_hook_is_registered() {
        for (name, meta) in BUILTIN_HOOK_METADATA {
            assert_eq!(lookup(name).as_ref(), Some(meta), "{name}");
        }
    }

    #[test]
    fn a_host_registered_hook_becomes_present() {
        let name = "test_custom.registered_at_runtime";
        assert_eq!(lookup(name), None);
        register_hook_metadata(name, HookMetadata::permissive());
        assert_eq!(lookup(name), Some(HookMetadata::permissive()));
    }

    #[test]
    fn matches_filters_by_entity_type_when_set() {
        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        assert!(tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(!tool_pre.matches(Some(ENTITY_LLM), HookPhase::Pre));
    }

    #[test]
    fn matches_allows_any_entity_when_hook_entity_is_none() {
        let universal = HookMetadata {
            entity_type: None,
            phase: HookPhase::Pre,
        };
        assert!(universal.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(universal.matches(Some(ENTITY_LLM), HookPhase::Pre));
        assert!(universal.matches(None, HookPhase::Pre));
    }

    #[test]
    fn matches_phase_exactly_unless_unphased() {
        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        assert!(tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(!tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Post));
    }

    #[test]
    fn matches_unphased_is_wildcard_in_either_direction() {
        let unphased = HookMetadata {
            entity_type: None,
            phase: HookPhase::Unphased,
        };
        assert!(unphased.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(unphased.matches(Some(ENTITY_LLM), HookPhase::Post));

        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        // Request with Unphased phase matches any registered hook
        // of the right entity_type.
        assert!(tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Unphased));
    }

    #[test]
    fn matches_request_without_entity_type_doesnt_filter_on_it() {
        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        // Request didn't specify entity_type — hook still matches.
        assert!(tool_pre.matches(None, HookPhase::Pre));
    }

    #[test]
    fn cmf_http_request_is_pre_phase_for_http_entity() {
        let meta = lookup(HOOK_CMF_HTTP_REQUEST).expect("registered");
        assert_eq!(meta.entity_type, Some(crate::cmf::constants::ENTITY_HTTP));
        assert_eq!(meta.phase, HookPhase::Pre);
    }

    #[test]
    fn cmf_http_response_is_post_phase_for_http_entity() {
        let meta = lookup(HOOK_CMF_HTTP_RESPONSE).expect("registered");
        assert_eq!(meta.entity_type, Some(crate::cmf::constants::ENTITY_HTTP));
        assert_eq!(meta.phase, HookPhase::Post);
    }

    #[test]
    fn elicit_is_unphased_no_entity() {
        let meta = lookup(HOOK_ELICIT).expect("registered");
        assert_eq!(meta.entity_type, None);
        assert_eq!(meta.phase, HookPhase::Unphased);
    }

    #[test]
    fn http_hooks_match_entity_typed_dispatch_as_before() {
        let request = lookup(HOOK_CMF_HTTP_REQUEST).expect("registered");
        let response = lookup(HOOK_CMF_HTTP_RESPONSE).expect("registered");
        // The visitor installs both under ENTITY_HTTP, so entity-typed
        // dispatch has to keep matching and the other entities must not.
        assert!(request.matches(Some(crate::cmf::constants::ENTITY_HTTP), HookPhase::Pre));
        assert!(!request.matches(Some(crate::cmf::constants::ENTITY_HTTP), HookPhase::Post));
        assert!(!request.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(response.matches(Some(crate::cmf::constants::ENTITY_HTTP), HookPhase::Post));
        assert!(!response.matches(Some(crate::cmf::constants::ENTITY_HTTP), HookPhase::Pre));
    }

    #[test]
    fn authority_holds_every_declared_hook() {
        // The per-module tables come from the same `define_hooks!`
        // invocations as the constants, so completeness is structural.
        // What this guards is the one gap that leaves: a module table
        // dropped from HOOK_TABLES, which unregisters every hook it owns.
        assert_eq!(CMF_HOOK_METADATA.len(), 10);
        assert_eq!(IDENTITY_HOOK_METADATA.len(), 1);
        assert_eq!(DELEGATION_HOOK_METADATA.len(), 1);
        assert_eq!(ELICITATION_HOOK_METADATA.len(), 1);
        assert_eq!(BUILTIN_HOOK_METADATA.len(), 13);
        for table in HOOK_TABLES {
            for (name, _) in *table {
                assert!(
                    BUILTIN_HOOK_METADATA.iter().any(|(n, _)| n == name),
                    "{name} is declared but missing from the concatenated table",
                );
            }
        }
    }

    #[test]
    fn no_two_modules_declare_the_same_hook_name() {
        // Each module owns its names, so a collision would be a bug that
        // silently gives one hook two rows and lets the later table's
        // metadata win in the registry.
        let mut seen = std::collections::HashSet::new();
        for (name, _) in BUILTIN_HOOK_METADATA {
            assert!(seen.insert(*name), "{name} is declared by two modules");
        }
    }

    #[test]
    fn every_hook_constant_keeps_its_import_path() {
        // Names the constants rather than iterating the authority on
        // purpose: what is under test is the *path* each one resolves at,
        // which the table cannot express. Rewriting the declarations as a
        // macro must not move any of them.
        use crate::cmf::constants::{
            HOOK_CMF_HTTP_REQUEST, HOOK_CMF_HTTP_RESPONSE, HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT,
            HOOK_CMF_PROMPT_POST_INVOKE, HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_RESOURCE_POST_FETCH,
            HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
        };
        use crate::delegation::HOOK_TOKEN_DELEGATE;
        use crate::elicitation::HOOK_ELICIT;
        use crate::identity::HOOK_IDENTITY_RESOLVE;

        for name in [
            HOOK_CMF_TOOL_PRE_INVOKE,
            HOOK_CMF_TOOL_POST_INVOKE,
            HOOK_CMF_LLM_INPUT,
            HOOK_CMF_LLM_OUTPUT,
            HOOK_CMF_PROMPT_PRE_INVOKE,
            HOOK_CMF_PROMPT_POST_INVOKE,
            HOOK_CMF_RESOURCE_PRE_FETCH,
            HOOK_CMF_RESOURCE_POST_FETCH,
            HOOK_CMF_HTTP_REQUEST,
            HOOK_CMF_HTTP_RESPONSE,
            HOOK_IDENTITY_RESOLVE,
            HOOK_TOKEN_DELEGATE,
            HOOK_ELICIT,
        ] {
            assert!(
                BUILTIN_HOOK_METADATA.iter().any(|(n, _)| *n == name),
                "{name} resolved but is not in the authority",
            );
        }
    }

    #[test]
    fn register_hook_metadata_overrides_default() {
        let name = "test_custom.overridden_meta";
        register_hook_metadata(
            name,
            HookMetadata {
                entity_type: Some("custom"),
                phase: HookPhase::Pre,
            },
        );
        let meta = lookup(name).expect("registered");
        assert_eq!(meta.entity_type, Some("custom"));
        assert_eq!(meta.phase, HookPhase::Pre);
    }
}
