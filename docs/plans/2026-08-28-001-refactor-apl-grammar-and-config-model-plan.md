---
title: "refactor(apl): write the grammar down and make the config model match it"
type: refactor
status: completed
date: 2026-08-28
origin: docs/brainstorms/2026-08-27-apl-grammar-requirements.md
---

# refactor(apl): write the grammar down and make the config model match it

## Summary

Sixteen units in six phases, ordered so every commit boundary builds and every
removal lands atomically with the in-repo migration it forces. The foundation
phase renames `plugin_settings` to `engine_settings` and coalesces three key
tables into one per scope without changing a single accept decision; each later
unit then adds one rejection and rewrites the files that rejection would break,
in the same commit. The grammar work comes last, when the accept set it documents
has stopped moving.

---

## Problem Frame

The grammar exists only as comments inside a 5,588-line parser, and those
comments are wrong on four counts. Ten config keys are accepted that should not
be: five that never had a place in the language and five the runtime parses and
honors nowhere. See origin for the full frame.

The planning problem is different from the requirements problem. The origin
document's Key Decisions propose a sequence ending in "then the migrations of
fixtures and tests," and that order does not survive the file inventory: 23 files
write the flat phase form exclusively, 15 write `apl:`, and 62 `compile_config`
calls span three crates. Closing the key sets before those files change breaks
the suite at that commit. Migration is not a trailing phase; it is part of each
removal.

---

## Requirements

This plan implements the origin document in full. R-IDs below are origin's.

- R1-R8, R39, R41-R43: the grammar document and conformance corpus (U15)
- R9-R22: lexical and predicate reconciliation (U12)
- R23-R27, R24b, R26b: `require` as a predicate (U13)
- R28-R38, R67, R67b, R67d, R67g-R67k: positional rules, map forms, key-table
  coalescing (U2, U14). R63b is U6, and R67c / R67e / R67f are enforcement U8 owns
- R44-R48, R47b: migration artifacts (U16, and per-unit CHANGELOG entries)
- R49-R50b: canonical conformance, discharged by U15's document
- R51-R58b: legacy keys, closures, `compile_config` (U3, U5, U11)
- R59-R62b, R63: `authorization:`, IR vocabulary (U4, U10)
- R68-R69b: `run(name)` as the only invoke form (U14)
- R70-R76: parsed-and-ignored key removal (U6)
- R79-R81b: `replace_inherited:` at bundle scope (U7)
- R82-R89e: the two dispatch modes (U1, U8, U9)

**Origin actors:** A1 policy author, A2 deployment operator, A3 PPE maintainer,
A4 policy-change reviewer, A5 coverage-work author (#14), A6 downstream config
author (praxis-demos).

**Origin acceptance examples:** AE1-AE20 are carried onto the units that own
them; each is cited in that unit's test scenarios.

---

## Scope Boundaries

- Splitting `parser.rs` into modules. Carried from origin: no acceptance
  criterion asks for it, and it has no dependency in either direction.
- Evaluator semantics, except the two exceptions origin names (`require(P)`
  desugaring, `replace_inherited:` at bundle scope).
- New language features. No new operators, stages, or step forms.
- Raising the coverage floor. That is #14; this work produces material for it.
- Making the shipped PDP resolvers read the paren form. Origin tracks it
  elsewhere; U14 documents what each form delivers and stops there.

### Deferred to Follow-Up Work

- **Runtime request tags composing for `authentication:`**: identity resolution
  walks static tags only while the plugins resolver merges both. Threading the
  request's tags into `resolve_identity_plugins_for_route` is a signature change
  past this work's edge. U7 documents static-only as intended and records the
  asymmetry; the extension gets its own issue.
- **`parser.rs` module split**: the EBNF from U15 names the seams.

---

## Context & Research

### Relevant Code and Patterns

- `crates/ppe-core/src/config.rs` — `KNOWN_ROUTE_KEYS` (the closed-key-set
  pattern every new table copies), `reject_unknown_route_keys`,
  `RENAMED_APL_KEYS`, `reject_renamed_identity_key`, `resolve_plugins_for_entity`,
  `resolve_identity_plugins_for_route`, `route_static_tags`, `score_route_match`
- `crates/ppe-apl-runtime/src/visitor.rs` — `apl_subblock`, `FLAT_APL_KEYS`,
  `GLOBAL_ONLY_NON_DSL_KEYS`, `response_yaml_block`, `strip_non_dsl_keys`,
  `warn_unreferenced_plugin_overrides` (the shape U9's reachability check
  follows), `warn_if_delegating_without_identity` (the shape U7's report follows)
- `crates/ppe-apl-core/src/parser.rs` — `PredParser`, `Lexer`, `parse_rule`,
  `is_require_call`, `parse_require_rule`, `split_predicate_action`,
  `unwrap_quotes`, `split_top_level_commas`, `parse_stage`, `parse_step_map`
- `crates/ppe-core/src/engine.rs:405-431` — the three "Setting ignored" warnings
  U6 deletes; `:1774` `filter_entries_by_route` for U9's dispatch work
- `crates/ppe-core/Cargo.toml` `[features]` — the `test-util` precedent U11
  mirrors, including its stated rationale about keeping test seams out of the
  semver-bound published surface
- `crates/ppe-core/tests/wire_compatibility.rs` — the guarantee U4 retires

### Institutional Learnings

`docs/solutions/` does not exist in this repo, so there are none to carry.
`AGENTS.md` (symlinked as `.claude/CLAUDE.md`) supplies the constraints that
shape every unit: SPDX headers on new files, `max_width = 100` stable rustfmt,
no new lint violations, suppressions at the narrowest scope with a `reason`, and
two test passes (default features, then `--all-features`).

### Measured Migration Inventory

Counts are occurrences, not files, gathered for this plan:

| Migration | Sites | Files | Concentration |
|---|---|---|---|
| `plugin_settings` / `routing_enabled` / `PluginSettings` | 398 | 21 | `config.rs` 164, `engine.rs` 75, `http_route_e2e.rs` 66 |
| policy-text `plugin(` | ~94 | 14 | `parser.rs` 29 (own tests), `visitor_e2e.rs` 17 |
| flat phase form | — | 30 | 23 flat-only, 7 mixed |
| `apl:` in YAML | — | 16 | 3 in PDP builtins; one found only by a non-anchored grep |
| `compile_config` calls | 67 | 9 | spans `ppe-apl-core`, `ppe-apl-cmf`, `ppe-apl-runtime` |

---

## Key Technical Decisions

- **Each removal is atomic with its migration.** The origin sequence ends in a
  trailing migration phase; the inventory shows why that fails. A unit that adds
  a rejection also rewrites every in-repo file that rejection would break.
- **A unit rewrites only its own dimension of a shared file.** Thirteen files carry
  both an `apl:` wrapper and the flat phase form, so both U3 and U4 list them. U3
  unwraps; U4 nests. Neither reformats the file beyond its own concern, which is what
  keeps both commit orders green and stops the two units conflicting.
- **Closed key sets are enumerated tables, not `deny_unknown_fields`.**
  `config.rs:1041-1047` records why `KNOWN_ROUTE_KEYS` exists in that form: a
  route shares its mapping with orchestrator blocks the typed struct deliberately
  ignores, so `deny_unknown_fields` "would reject every APL-annotated route in
  the tree." `GlobalConfig` and `PolicyGroup` carry the same APL blocks, so the
  same shape applies. (Resolves origin's deferred question on R54.)
- **The key tables coalesce before any rejection changes.** U2 is behavior-
  preserving on purpose: it replaces three overlapping tables with one per scope
  while keeping today's accept decisions exactly. Every later unit then edits one
  table entry instead of reconciling three.
- **The `compile_config` replacement ships behind a `test-util` feature on
  `praxis-policy-apl-core`.** Callers span three crates' integration tests, which
  see only the public API, and `ppe-apl-core` has no `[features]` block today.
  `ppe-core`'s existing `test-util` feature is the precedent, and its rationale
  applies verbatim: a feature keeps the helper out of the semver-bound published
  surface. (Resolves R58b.)
- **The rename lands with the default unchanged.** U1 renames the key and the
  Rust surface while `dispatch` still defaults to `hooks`, today's effective
  default. The flip is U9, beside the checks that make it survivable. A 398-site
  mechanical commit must not also change which plugins run.
- **Custom PDP dialects get a `pdp(name):` wrapper key.** Closest to the existing
  call syntax, and load-time verification of the name is impossible anyway since
  resolvers register at runtime. (Resolves R34.)
- **The escape set is `\\`, `\'`, `\"` and nothing else.** The minimum that
  closes the rule. `\n` and `\t` are excluded: a deny reason rides in a violation
  field a host renders, and a multi-line reason there is a display problem rather
  than a capability. (Resolves R9/R11.)
- **An empty pipe chain has two answers, matching the two positions.** A leading,
  trailing, or doubled `|` is an error everywhere. `parse_pipeline("")` keeps
  returning an empty pipeline, because R45 protects it as a public entry point; an
  `args:` / `result:` map value that is empty or whitespace is a load error,
  because a field declared with no stages is a mistake. (Resolves R31.)
- **A reversed comparison is rejected, not rewritten**, with a message naming the
  accepted order. Rewriting would silently accept text whose meaning the author
  guessed at. (Resolves R20.) **`007` stays an integer** — changing it would alter
  a value silently, which is the failure mode this work exists to remove.
  (Resolves R15.)
- **Phase spellings:** `Phase::PreInvocation` / `Phase::PostInvocation`,
  `CompiledRoute.pre_invocation` / `.post_invocation`. `CompiledRoute.args` and
  `.result` keep their names, already matching their config keys. (Resolves R61.)
- **The upgrade guide is its own document** at
  `docs/content/guides/upgrade-apl.md`, with the CHANGELOG pointing at it. A
  per-form list inside a changelog entry is unreadable at this size.
  (Resolves R47b.)

---

## Open Questions

### Resolved During Planning

- Closed key sets as tables vs `deny_unknown_fields`: tables, per `config.rs`'s
  own recorded reason.
- Where the `compile_config` helper lives: a `test-util` feature on
  `praxis-policy-apl-core`.
- Escape set, empty-chain behavior, reversed comparisons, `007`, phase spellings,
  custom-dialect spelling, upgrade-guide location: see Key Technical Decisions.
- Whether the flat-form migration is separable from the grammar work (origin's
  R60 question): no. It is atomic with the enforcement in U4.
- `global.policies:` merge retirement (R51): the merge collapses to a direct
  assignment once top-level `groups:` is the only input. Part of U5.
- Route-key ownership split (R36): statable from `KNOWN_ROUTE_KEYS` plus
  `RouteYaml`; U2's scope tables record which side owns each key.
- Elicitation verbs in the EBNF (R2/R32): one shared kwarg production plus a verb
  table. Six verbs share one argument parser.

### Deferred to Implementation

- Where exactly R85's reachability check hooks into `AplConfigVisitor` — after
  layer stacking, but the precise call site depends on what the visitor's state
  looks like once U8 removes the activation lists.
- Whether `strip_non_dsl_keys` survives U3 at all. Origin's R56c expects it may
  have no job left once the engine blocks are `global:` siblings; that is visible
  only with the code in front of you.
- The exact `PolicyConfig` top-level table contents if U1's rename reveals a key
  the inventory missed.
- Whether the metadata-less denial in U9 needs a new `PluginViolation` constant
  or can reuse the unreadable-path shape with a different code.

---

## High-Level Technical Design

> *This illustrates the intended dependency structure and is directional guidance
> for review, not implementation specification.*

```mermaid
graph TD
    U1[U1 rename to engine_settings/dispatch<br/>default stays hooks] --> U2[U2 coalesce key tables<br/>behavior-preserving]
    U2 --> U3[U3 remove apl:<br/>relocate attribute_files:]
    U2 --> U4[U4 nested authorization: only<br/>retire wire-compat guarantee]
    U2 --> U5[U5 remove 5 legacy keys<br/>hint in unknown-key error]
    U2 --> U6[U6 remove 5 inert keys]
    U3 --> U7[U7 honor replace_inherited:<br/>at bundle scope]
    U5 --> U7
    U3 --> U8[U8 remove activation lists<br/>enforce mode exclusion]
    U4 --> U8
    U6 --> U8
    U8 --> U9[U9 flip default to policy<br/>reachability + fail-closed]
    U5 --> U10[U10 IR renames]
    U4 --> U11[U11 delete compile_config<br/>test-util helper]
    U11 --> U12[U12 lexical reconciliation]
    U12 --> U13[U13 require as a predicate]
    U12 --> U14[U14 positional + map-form rules<br/>run\(\) only]
    U13 --> U15[U15 grammar document<br/>+ conformance corpus]
    U14 --> U15
    U9 --> U16[U16 upgrade guide<br/>+ CHANGELOG assembly]
    U10 --> U16
    U15 --> U16
```

Phase A is U1-U2, B is U3-U7, C is U8-U9, D is U10-U11, E is U12-U15, F is U16.

---

## Implementation Units

- U1. **Rename to `engine_settings` and `dispatch`, default unchanged**

**Goal:** `plugin_settings:` becomes `engine_settings:` and the boolean
`routing_enabled` becomes `dispatch: policy | hooks`, with `hooks` as the default
so no dispatch behavior changes. An unrecognized value is a load error.

**Requirements:** R82, R82b, R82c, R89

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (150 sites, `PluginSettings` →
  `EngineSettings`, `PolicyConfig.plugin_settings` → `engine_settings`,
  `routing_enabled()` → a mode accessor)
- Modify: `crates/ppe-core/src/engine.rs` (75), `crates/ppe-apl-runtime/src/visitor.rs` (16),
  `crates/ppe-core/src/visitor.rs` (4), `crates/ppe-core/src/plugin.rs`,
  `crates/ppe-core/src/http_hook.rs`, `crates/ppe-apl-core/src/parser.rs`
- Modify: `crates/ppe-apl-runtime/tests/http_route_e2e.rs` (66),
  `crates/ppe-core/tests/identity_route_e2e.rs` (24),
  `crates/ppe-apl-runtime/tests/global_http_authz.rs` (24),
  `crates/ppe-apl-runtime/tests/visitor_e2e.rs`,
  `crates/ppe-apl-runtime/tests/canonical_authn_authz_e2e.rs`,
  `crates/ppe-apl-runtime/tests/visitor_config_errors.rs`,
  `crates/ppe-core/tests/wire_compatibility.rs` (it calls `routing_enabled()`, so
  the test target does not compile without it)
- Modify: `crates/ppe-core/tests/fixtures/legacy-policy-document.yaml`,
  `crates/ppe-core/examples/plugin_demo.yaml`,
  `crates/ppe-core/examples/cmf_capabilities_demo.yaml`,
  `crates/ppe-apl-runtime/tests/fixtures/authpolicy_transpiler_global_http.yaml`
- Modify: `CHANGELOG.md` (edit the unreleased `http:` selector entry in place per
  R89c — it names `plugin_settings.routing_enabled: true` and "defaults to false")

**Approach:**
- One mechanical commit. Nothing else hides in it, which is why the default stays
  `hooks`: a config with no `engine_settings` block behaves exactly as today.
- A stale `plugin_settings:` at top level is rejected in this same commit, naming
  `engine_settings` as the replacement. Without it a config that asked for routing
  loads in hook mode with no error, because the key is `#[serde(default)]` and the
  typed parse drops the renamed one, and it stays that way until the top-level
  table closes four units later. Rejecting here is the smallest fix and it belongs
  with the rename that causes it.
- `dispatch` deserializes to a two-variant enum with a `deny_unknown_variants`
  style error naming both modes, not a lenient string.
- `route_cache_max_entries` gains a doc line saying it is policy-mode only.

**Execution note:** Land the type rename and the YAML key rename together; a
half-renamed tree does not compile, so there is no intermediate to test.

**Patterns to follow:** the existing `#[serde(rename = ...)]` usage in
`RouteEntry.identity` shows the shape, though U10 removes that particular one.

**Test scenarios:**
- Happy path: a config with `engine_settings: {dispatch: hooks}` loads and every
  declared plugin fires, as today.
- Happy path: a config with no `engine_settings` block at all loads in hook mode.
- Covers AE18c (partly). Error path: `dispatch: plicy` fails at load naming both
  `policy` and `hooks`.
- Error path: `dispatch: true` (a stale boolean) fails at load rather than
  coercing.
- Error path: a top-level `plugin_settings:` block fails at load naming
  `engine_settings`, rather than loading in hook mode with its contents dropped.
- Integration: the wire-compatibility fixture still parses after its
  `plugin_settings` block is renamed.

**Verification:** `make ci` passes. No occurrence of `plugin_settings`,
`routing_enabled`, or `PluginSettings` remains outside CHANGELOG history and the
two brainstorm documents. Dispatch behavior is unchanged for every existing test.

---

- U2. **Coalesce the key tables into one per scope, behavior-preserving**

**Goal:** Replace `KNOWN_ROUTE_KEYS`, `FLAT_APL_KEYS`, and
`GLOBAL_ONLY_NON_DSL_KEYS` with one table per scope, keeping today's accept
decisions byte for byte. This is the seam every later unit edits.

**Requirements:** R36, R64, R65, R66, R67b, R67g

**Dependencies:** U1

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (the route table, plus new tables for
  `global:`, `global.defaults.<entity>:`, `groups.<name>:`, and `PolicyConfig`)
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` (`FLAT_APL_KEYS` and
  `GLOBAL_ONLY_NON_DSL_KEYS` retire; the APL key set is named once and referenced)
- Test: `crates/ppe-core/tests/config_key_sets.rs` (new)

**Approach:**
- Tables, not `deny_unknown_fields`, for the reason `config.rs:1041-1047` already
  records. Name them for what they hold: no `FLAT_`, no `NON_DSL`.
- Each entry carries a role alongside its scope and owning crate: structural,
  APL term, engine wiring, or shape-conditional. Scope alone is not enough, because
  the three tables being merged are indexed by role rather than by scope:
  `KNOWN_ROUTE_KEYS` is the route's accept set, `FLAT_APL_KEYS` is
  `apl_subblock`'s *constructive* set (what it copies into a synthetic block,
  deliberately excluding `response` and treating `plugins` as shape-conditional),
  and the global-only set is the warn-at-non-global set. Without the role marker
  `apl_subblock` has no way to pick its subset, and iterating a scope table would
  start copying `response`, `tool`, `meta`, and `groups` into the block handed to
  the compiler.
- `apl_subblock` iterates only the APL-term entries, plus `plugins` in its mapping
  shape alone.
- The engine-block set (`pdp`, `session_store`, `attribute_files`) is referenced
  by the `global:` table only. It is not yet *enforced* as global-only — that is
  U3, since `attribute_files:` has no section-level path until then.
- `pdp:` and `session_store:` stay in the route table for now with their existing
  warning, so this unit changes nothing. U3 removes them from it.
- Record per key which crate owns it, satisfying R36.

**Test scenarios:**
- Happy path: every config in the test suite and both examples load with
  identical results before and after. This is the unit's whole point.
- Edge case: a route carrying `pdp:` still warns rather than failing, as today.
- Test expectation for behavior change: none — this unit is a refactor, and a
  test asserting a new rejection here would mean it did too much.

**Verification:** `make ci` passes with no test modifications. The three old
tables are gone; every key appears in exactly one scope table.

---

- U3. **Remove `apl:`, relocate `attribute_files:`, collapse both precedence rules**

**Goal:** The `apl:` wrapper leaves the accept set at every scope. APL terms sit
on the section. `attribute_files:` becomes `global.attribute_files:`. The two
opposed precedence rules the wrapper created go with it.

**Requirements:** R51 (the `apl:` half), R56, R56b, R56c, R57, R66

**Dependencies:** U2

**Files:**
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` (`apl_subblock` loses the
  wrapper branch; `response_yaml_block` loses the `apl.response:` fallback and its
  comment; `attribute_files` joins the section-level APL key set;
  `strip_non_dsl_keys` re-examined per R56c)
- Modify: `crates/ppe-core/src/config.rs` (`apl` leaves the route table; `pdp` and
  `session_store` leave it too, becoming global-only errors per R66)
- Modify: `crates/ppe-core/src/visitor.rs` (the trait doc line claiming a
  visitor's name matches its YAML key, per R56b)
- Modify, migrating `apl:` out of inline YAML: the 16 files, including
  `crates/ppe-apl-runtime/tests/visitor_config_errors.rs` (12 sites as escaped
  inline YAML, plus assertions on `global.apl.attribute_files` error text, which a
  line-anchored grep misses) —
  `crates/ppe-apl-runtime/tests/{attribute_source_e2e,http_route_e2e,payload_mutation_propagation,delegation_identity_warning,visitor_e2e,global_http_authz,config_override,capability_gating,restrict_e2e,end_to_end_route}.rs`,
  `crates/ppe-apl-runtime/src/visitor.rs`, `crates/ppe-core/src/config.rs`,
  `builtins/pdps/{cedar-direct,opa,cel}/tests/visitor_*_config.rs`
- Modify: `CHANGELOG.md`

**Approach:**
- Migration and enforcement in one commit. The 16 files must lose `apl:` before or
  as the accept set closes, or every one of them fails to load.
- This is also the unit that switches unknown-key rejection **on** for the
  `global:`, `global.defaults.<entity>:`, and `groups.<name>:` tables U2 created,
  because it is the first removal that needs enforcement at those scopes. U5 then
  edits table contents and adds the replacement hint rather than introducing
  enforcement.
- `attribute_files:` is the dependency that makes this unit non-trivial: it is
  read only as `global.apl.attribute_files`, so the relocation is not optional
  cleanup, it is what keeps the `data.*` namespace loadable.

**Patterns to follow:** `warn_if_global_only_key_at_nonglobal_scope` shows how
scope violations are currently reported; U3 converts the two warned keys to
errors via the U2 tables.

**Test scenarios:**
- Covers AE15. Happy path: `global: { attribute_files: [...] }` written flat
  loads the static tree and `data.*` predicates resolve.
- Covers AE13 (partly). Error path: `apl:` on a route, at `global:`, under
  `global.defaults.tool:`, and on a `groups.<name>:` bundle each fail at load
  naming the key.
- Covers AE15. Edge case: a `response:` block resolves by one precedence rule,
  the same rule every other APL key uses; an `apl:`-nested `response:` is now
  simply an unknown key.
- Error path: `pdp:` or `session_store:` on a route fails at load rather than
  warning.
- Integration: the three PDP builtin visitor tests load their configs with the
  wrapper removed and register their resolvers as before.

**Verification:** `make ci` passes. No `apl:` in any YAML or inline YAML.
`response_yaml_block`'s fallback and comment are gone.

---

- U4. **`authorization:` is the only phase wrapper, and the wire guarantee is retired**

**Goal:** The flat `pre_invocation:` / `post_invocation:` spelling is removed. An
`authorization:` block must declare at least one phase. The published
compatibility guarantee this breaks is retired deliberately.

**Requirements:** R59, R60, R60b, R60c, R60d, R60e

**Dependencies:** U3. Not U2: `compile_policy_block_value` deserializes an `apl:`
block body into the same `RouteYaml`, so deleting its two flat fields also breaks
every `apl: { pre_invocation: ... }` site U3 owns, and `RouteYaml`'s `flatten other`
would swallow them into empty policy rather than erroring. U3 rewrites those blocks
straight into the nested form so they migrate once.

**Files:**
- Modify: `crates/ppe-apl-core/src/parser.rs` (`RouteYaml` loses the two flat
  fields; `AuthorizationYaml` gains the at-least-one check;
  `ParseError::ConflictingAuthorizationForms` is deleted with the merge that
  produced it)
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` (the APL key set loses the two
  flat entries)
- Modify: `crates/ppe-core/src/config.rs` (the two flat phase keys leave the route
  key table, without which flat `pre_invocation:` stays accepted and silently
  dropped; plus 4 inline test YAML sites and the flat-orchestrator-form test),
  `crates/ppe-core/src/engine.rs` (5 sites), `crates/ppe-core/src/visitor.rs` (2)
- Modify, nesting the flat form: all 30 files the inventory counts, the 23
  flat-only plus the 7 mixed. Including `crates/ppe-core/src/config.rs`, whose
  test `a_route_written_in_the_flat_orchestrator_form_loads` asserts the flat form
  keeps loading and must move with the parser change. Notably
  `crates/ppe-apl-core/tests/yaml_end_to_end.rs`,
  `crates/ppe-apl-cmf/tests/end_to_end.rs`,
  `crates/ppe-apl-runtime/tests/*.rs` (14 files),
  `builtins/pdps/{cedar-direct,opa,cel}/tests/visitor_*_config.rs`,
  `crates/ppe-apl-core/src/step.rs`, `crates/ppe-apl-runtime/src/{delegation_invoker,dispatch_plan}.rs`,
  `crates/ppe-core/src/hooks/metadata.rs` (rustdoc examples)
- Modify: `crates/ppe-core/tests/fixtures/legacy-policy-document.yaml`
- Modify: `crates/ppe-core/tests/wire_compatibility.rs` (its doc comment now
  states what the guarantee covers after this change)
- Modify: `CHANGELOG.md` (retire the 0.1.0 "policy document format unchanged"
  claim explicitly; name the removed global field-pipeline capability as a loss)
- Modify: `crates/ppe-core/src/config.rs` and the U2 `global:` scope table
  (`args:` and `result:` become load errors under `global:`, per R60d)

**Approach:**
- The largest migration in the work. Mechanical, but it touches the one fixture
  whose entire purpose is proving the format did not move, so the CHANGELOG entry
  is part of the unit rather than a follow-up.
- `wire_compatibility.rs` keeps its other assertions (plugin `kind:` strings,
  hook names, violation codes); only the phase-spelling guarantee lapses.

**Execution note:** Rewrite the fixture and the CHANGELOG entry in the same
commit as the parser change, so the retirement is never implicit in a green test
run.

**Test scenarios:**
- Covers AE16. Happy path: `authorization: { pre_invocation: [...] }` loads and
  compiles as the flat form did.
- Covers AE16. Error path: `authorization: {}` fails at load naming the missing
  phase.
- Covers AE16. Error path: flat `pre_invocation:` on a section fails as an
  unknown key.
- Edge case: `authorization: { post_invocation: [...] }` alone loads — one phase
  is enough.
- Error path: `global: { args: {...} }` and `global: { result: {...} }` each fail at
  load. The capability is removed deliberately, so the CHANGELOG names it as a loss
  rather than a tightening, and `reject_field_stages_without_fields` loses its
  global-scope carve-out to the wider rule.
- Integration: `wire_compatibility.rs` still passes on every guarantee it asserts
  other than the retired one, proving the retirement is scoped.

**Verification:** `make ci` passes. No flat phase key in any file.
`ConflictingAuthorizationForms` is gone. The CHANGELOG names the retirement.

---

- U5. **Remove the five legacy keys; the unknown-key error carries the replacement**

**Goal:** `policy:`, `post_policy:`, `identity:`, and `global.policies:` leave the
accept set at every scope (`apl:` went in U3). Their rename guards are deleted,
and the name-to-replacement mapping survives as the hint the unknown-key error
carries.

**Requirements:** R51, R52, R53, R54, R54b, R55

**Dependencies:** U2

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (delete `RENAMED_APL_KEYS`,
  `renamed_apl_key_message`, `reject_renamed_identity_key`; the unknown-key
  reporter gains a hint table; `PolicyConfig` and the three scope tables from U2
  now enforce; `GlobalConfig.policies` is rewired so top-level `groups:` is the
  only input and the merge collapses to an assignment)
- Modify: `crates/ppe-apl-core/src/parser.rs` (delete `RENAMED_FIELDS`,
  `ParseError::RenamedField`, `reject_legacy_keys`; `RouteYaml` closes its key set,
  dropping the `flatten other` catch-all)
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` (delete `reject_legacy_apl_keys`)
- Modify: `crates/ppe-core/src/engine.rs` (a second, independent `global.policies` /
  top-level `groups:` merge on the raw-YAML path builds the bundle list the visitor
  walks; it collapses to reading `groups:` and its deprecated-alias comment goes,
  or it survives as dead code still claiming the removed spelling works)
- Test: `crates/ppe-core/tests/config_key_sets.rs` (extend U2's file)
- Modify: `CHANGELOG.md`

**Approach:**
- The closed key sets from U2 become enforcing here. That is why U2 was
  behavior-preserving: this unit is a table edit plus guard deletion, not a
  redesign.
- `PolicyConfig`'s own table matters most: without it a stale `plugin_settings:`
  from U1 loses every engine setting silently, `dispatch:` included.

**Test scenarios:**
- Covers AE13. Error path: each of the four keys at each of route, `global:`,
  `global.defaults.tool:`, and `groups.<name>:` fails at load naming both the key
  and its replacement spelling.
- Covers AE14. Error path: a misspelled key at each of those scopes, plus on a
  route's APL block, fails at load naming it.
- Error path: a stale `plugin_settings:` at top level fails rather than silently
  taking the default dispatch mode.
- Happy path: a bundle written under top-level `groups:` resolves exactly as one
  written under `global.policies:` did.
- Covers AE13. Integration: a grep of the tree finds no rename table and no rename
  error variant.

**Verification:** `make ci` passes. Every removed key fails at every scope with a
message naming its replacement.

---

- U6. **Remove the five keys the runtime parses and never honors**

**Goal:** A route's `when:`, `plugin_dirs`, `parallel_execution_within_band`,
`fail_on_plugin_error`, and an `authentication:` step's `on_error:` leave the
accept set. Their warnings and dead carriers go with them.

**Requirements:** R63b, R70, R71, R72, R73, R74, R75, R76

**Dependencies:** U2

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (`when` leaves the route table;
  `RouteEntry.when` is deleted; the `when_bonus` at the scoring site goes;
  `ResolvedPlugin.when` and its assignment go; `plugin_dirs`,
  `parallel_execution_within_band`, `fail_on_plugin_error` leave `EngineSettings`
  and `PolicyConfig`)
- Modify: `crates/ppe-core/src/engine.rs` (delete the three "Setting ignored"
  warnings at `:405-431`)
- Modify: `crates/ppe-core/src/identity/route_config.rs` (`RouteIdentityStep`
  loses `on_error` and the `flatten extra` catch-all; its module docs stop calling
  the block `identity:`)
- Modify: `crates/ppe-core/src/engine.rs` (the only in-repo `plugin_dirs` YAML is a
  unit-test config there, not in the examples)
- Modify: `CHANGELOG.md`

**Approach:**
- `when:` is the one removal that takes a capability rather than a no-op, so its
  CHANGELOG entry points at the `when:` / `do:` step that expresses the intent.
- Removing the specificity bonus changes which route wins for a config that
  declared `when:` on one of two otherwise equally specific routes. Since `when:`
  becomes an unknown route key in the same commit, no config can reach that state
  afterward — the CHANGELOG names it for configs being upgraded, not for a
  reachable runtime path.

**Test scenarios:**
- Covers AE19. Error path: each of the five keys, at its own scope, fails at load
  naming the key and its replacement.
- Covers AE19. Integration: a grep finds no "Setting ignored" warning.
- Edge case: two routes with identical selectors and scopes rank identically —
  there is no `when:` to break the tie.
- Happy path: an `authentication:` step with `name:` and `config:` loads; the same
  step with `on_error:` fails.
- Covers AE18a. Error path: a misspelled key inside an `authentication:` step
  fails at load naming it, which the removed `flatten extra` used to swallow.

**Verification:** `make ci` passes. No key in the accept set is inert.

---

- U7. **Honor `replace_inherited:` at bundle scope, and report what it drops**

**Goal:** A bundle's `replace_inherited:` drops everything accumulated before it
rather than being parsed and ignored. Every route whose inherited global
`authentication:` layer a bundle drops is named at load.

**Requirements:** R79, R80, R80b, R80c, R81, R81b, R62b

**Dependencies:** U3, U5

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (`resolve_identity_plugins_for_route`
  honors the flag per layer; its doc comment stops saying a bundle's is not
  honored)
- Modify: `crates/ppe-core/src/identity/route_config.rs` (the type doc claiming
  the flag is stored but not exercised is corrected — the resolver is the fact)
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` or `crates/ppe-core/src/config.rs`
  (the load-time report, following `warn_if_delegating_without_identity`'s shape)
- Modify: `CHANGELOG.md`
- Test: `crates/ppe-core/tests/identity_route_e2e.rs`

**Approach:**
- Bundle order is `meta.tags` in declaration order then `groups:` in declaration
  order, which `route_static_tags` already guarantees, so which bundle replaces is
  reproducible from the file. Nothing new is needed for determinism.
- Static-only tag composition is documented as intended; the asymmetry with
  `resolve_plugins_for_entity` is recorded and deferred.
- The report matters because this moves an authentication-removing control from
  route-local to tag-inherited: the route's author never sees the bundle.

**Test scenarios:**
- Covers AE20. Happy path: a route joining two bundles where the second sets the
  flag keeps the second bundle's steps plus its own, and drops the global layer
  and the first bundle's.
- Covers AE20. Edge case: the same two bundles named in the other order produce a
  different result, and it matches declaration order.
- Covers AE20. Happy path: a route setting the flag itself drops every inherited
  layer, as today.
- Edge case: `replace_inherited: true` with `steps: []` on a bundle drops
  everything and contributes nothing.
- Integration: load emits one report per route whose global layer a bundle drops,
  naming the route and the bundle.

**Verification:** `make ci` passes. A bundle's flag changes the resolved identity
list, and the load report names every affected route.

---

- U8. **Remove activation lists and enforce the mode boundary**

**Goal:** `plugins:` as an activation list leaves every scope in policy mode. The
two modes reject each other's keys.

**Requirements:** R67c, R67e, R67f, R83, R86, R86b, R87

**Dependencies:** U3, U4, U6

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (`RouteEntry.plugins` and
  `PolicyGroup.plugins` in list form become policy-mode load errors;
  `resolve_plugins_for_entity`'s policy-mode branch loses its four list sources;
  per-plugin `conditions:` and `priority` become policy-mode load errors;
  `routes:`, `groups:`, `global:`, `global.defaults:` become hook-mode load errors)
- Modify: `crates/ppe-core/examples/plugin_demo.yaml`,
  `crates/ppe-core/examples/cmf_capabilities_demo.yaml`,
  `crates/ppe-core/examples/README.md`. Both declare `routes:` **and** `global:`,
  which this unit makes hook-mode load errors, so adding `dispatch: hooks` alone
  makes them fail to load. Each is a real hook-mode rewrite: `routes:` and `global:`
  are dropped, activation moves into each plugin's own `hooks:` plus per-plugin
  `conditions:`, and the README stops advertising tag-based group activation, which
  hook mode cannot express. Route- and tag-scoped activation is not preserved, and
  the README says so rather than implying equivalence.
- Modify: `crates/ppe-core/src/config.rs` (delete the `http:` inertness report in
  `http_routing_gaps`, its `!routing_enabled()` branch at `:1412-1422`, which has no
  reachable input once `routes:` is a hook-mode error. Do not touch the
  unknown-plugin validation at `:1349-1359`, which is a different check and stays)
- Modify: `CHANGELOG.md`

**Approach:**
- The two examples are the concrete case R86b names: they have no `run(name)` path
  because they register no visitor, so `dispatch: hooks` is their migration. That
  is the honest demonstration that hook mode is a supported peer rather than a
  deprecation target.
- The chain-wide replacement in policy mode is a `run(name)` step under
  `global.authorization`, which stacks onto every entity route.

**Test scenarios:**
- Covers AE18b, AE18e. Error path: a `plugins:` list on a route, a bundle, a
  `defaults:` entry, or the `all` group fails at load naming `run(name)`, whether
  or not the section also declares `authorization:`.
- Covers AE18b. Happy path: the same route with a `plugins:` override map loads.
- Covers AE18c. Error path: `dispatch: hooks` with a `routes:` block fails naming
  the key and the mode; `dispatch: policy` with a plugin declaring `conditions:`
  fails the same way.
- Happy path: `global.authorization.pre_invocation: ["run(audit-log)"]` reaches
  every entity route, which is the chain-wide replacement.
- Integration: both examples run to completion under `dispatch: hooks`. Their
  plugin behavior is *not* identical to before: route- and tag-scoped activation is
  gone, and each example's README states what it now demonstrates.

**Verification:** `make ci` passes. Both examples run. No activation list is
accepted in policy mode, and neither mode accepts the other's keys.

---

- U9. **Flip the default to `policy`, with the checks that make it survivable**

**Goal:** `dispatch:` defaults to `policy`. A policy-mode config that reaches no
plugin is reported at load. A request the engine cannot identify is denied rather
than dispatched against absent context.

**Requirements:** R84, R85, R85b, R85c, R85d, R85e, R85f, R85g, R89b

**Dependencies:** U8

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (the default)
- Create the seam the check needs: `crates/ppe-core/src/visitor.rs` gains a
  defaulted post-walk method on `ConfigVisitor`, called once per visitor after its
  own route walk in `load_config_yaml`. Without it there is nowhere to run the
  check: the trait exposes only `visit_plugins`, `visit_global`, `visit_default`,
  `visit_policy_bundle`, and `visit_route`; `visit_global` runs before any route is
  seen, and a config with no routes, groups, or `global:` fires nothing after it, so
  the union of references can never be computed. This is a public-trait addition,
  not a call-site detail.
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` (the per-plugin reachability and
  per-hook narrowing checks, accumulating declared and referenced names in the
  existing visitor state and reporting from the post-walk method)
- Modify: `crates/ppe-core/src/engine.rs` (call the post-walk method; and a
  `dispatch: policy` load with no registered visitor is a load error naming
  `dispatch: hooks`, since the visitor walk is a documented no-op with no visitors
  and that path is exactly what both examples use)
- Modify: `crates/ppe-core/src/config.rs` (the narrow visitor-less backstop, and
  the denial guard's predicate)
- Modify: `crates/ppe-core/src/engine.rs` (`filter_entries_by_route`: the
  metadata-less early return becomes a guarded denial)
- Modify: `crates/ppe-core/src/error.rs` (the violation constant, if a new one is
  needed rather than reusing the unreadable-path shape)
- Modify: `CHANGELOG.md`
- Test: `crates/ppe-apl-runtime/tests/dispatch_mode_e2e.rs` (new)

**Approach:**
- The reachability check is **per plugin, not per config**. Every declared plugin
  no reference reaches is named at load, matching
  `warn_unreferenced_plugin_overrides`'s per-name shape. A config-wide "reaches
  nothing" test would pass a config that declares three plugins and names one,
  which is the common partial case rather than an edge.
- It runs in the visitor because only the visitor sees the full reference set: a
  `run(name)` step, a `run(name)` pipeline stage, a `delegate(...)` call, an
  elicitation verb's handler, and an `authentication:` step at any scope. Not
  `taint(...)`: that stage carries a label and scopes, never a plugin name.
  It reads the **compiled IR**, not surface text, so it is unaffected by U14 not
  having renamed `plugin(` to `run(` yet.
- A second, narrower check lives in `ppe-core`, because the visitor cannot protect
  a host that registers no visitor at all, and that host gets the flipped default
  with no check whatever. `ppe-core` can decide the narrow case without seeing any
  APL step: policy mode, a non-empty `plugins:` list, and no `routes:`, `groups:`,
  or `global:` block. That is exactly the shape of the two examples U8 rewrites, so
  it is known to exist downstream.
- **The denial's guard needs its own predicate, and it is not "policy mode".** By
  the point the metadata-less path is reached, `filter_entries_by_route` has already
  returned through `let Some(policy_config) = routing_config else { ... }`, so
  policy mode is guaranteed true there and a guard keyed on it would deny for every
  default-mode config, including one declaring nothing. The predicate is instead:
  the config declares at least one of `global.authorization`, a route, or a group.
  That is what makes the plan's own exception true, that a config declaring no
  policy does not start denying traffic it used to pass.
- Per-hook narrowing is reported, not just documented. A plugin declaring three
  hooks and reached by a step on one loses coverage on two, and the check compares
  the hooks a plugin declares against the hooks any reference actually reaches it
  under, naming every hook left uncovered. A warning rather than an error, because
  narrowing can be exactly what an operator intended; the CHANGELOG still names it,
  and `dispatch: hooks` is the escape for wanting today's behavior wholesale.

**Execution note:** Land the default, the reachability check, and the denial in
one commit. The default alone is the fail-open the other two close.

**Patterns to follow:** `warn_unreferenced_plugin_overrides` for the check's
shape; `RouteResolutionError::UnreadablePath` and its guard for the denial's.

**Test scenarios:**
- Covers AE18d. Error path: a config declaring plugins with no `routes:`,
  `groups:`, or `global:`, and no `engine_settings`, fails at load naming the
  plugins nothing reaches.
- Happy path: a plugin reached only by an `authentication:` step passes the check
  — the reference set is wider than `run(name)`.
- Happy path: a plugin reached only by `delegate(...)` or an elicitation verb
  passes.
- Error path: a config declaring three plugins and naming one reports the other
  two by name, rather than passing because something was reached.
- Edge case: a plugin declaring two hooks but reached on one is reported as
  narrowed, naming the uncovered hook.
- Edge case: a config that declares no plugins, no routes, and no `global:` block
  does not deny metadata-less requests — the guard's predicate is unmet.
- Integration: a host that registers no APL visitor and writes `dispatch: policy`
  with declared plugins and no routes fails at load from the `ppe-core` side check.
- Error path: a request with no `meta` reaching an installed policy is denied with
  the 400-class code, distinct from a policy deny.
- Edge case: the same request against a config with no policy installed is not
  denied — the guard holds.
- Integration: an HTTP request carrying `meta.entity_type = "http"` resolves to
  its installed annotation, never to the denial, since `resolved_name` is always
  `Some` for that entity type.

**Verification:** `make ci` passes. A config that reaches nothing fails at load;
a metadata-less request against installed policy is denied; a config with no
policy is unaffected.

---

- U10. **IR renames**

**Goal:** The IR stops speaking a vocabulary no config may use.

**Requirements:** R61, R62, R63

**Dependencies:** U5

**Files:**
- Modify: `crates/ppe-apl-core/src/rules.rs` (`Phase::Policy` →
  `Phase::PreInvocation`, `Phase::PostPolicy` → `Phase::PostInvocation`,
  `CompiledRoute.policy` → `.pre_invocation`, `.post_policy` → `.post_invocation`)
- Modify: `crates/ppe-core/src/config.rs` (the three `identity` fields whose serde
  key is `authentication` are renamed, dropping the `rename` attribute)
- Modify: `crates/ppe-apl-core/src/{route,evaluator}.rs`,
  `crates/ppe-apl-runtime/src/{visitor,dispatch_plan,route_handler}.rs` and every
  reader of the renamed fields
- Modify: `crates/ppe-core/src/identity/route_config.rs` (rustdoc)
- Modify: `CHANGELOG.md` (the serialized shape changes, not only the Rust API)

**Approach:** `CompiledRoute` derives `Serialize`, so this changes the serialized
phase keys. `args` and `result` keep their names, already matching their config
keys.

**Test scenarios:**
- Covers AE17. Happy path: a serialized `CompiledRoute` carries
  `pre_invocation` / `post_invocation` keys.
- Covers AE17. Integration: a grep finds no `Phase::Policy`, no
  `CompiledRoute.policy`, and no struct field named `identity` whose serde key is
  `authentication`.
- Happy path: every existing evaluator and route test passes with renamed fields,
  proving the rename is not a behavior change.

**Verification:** `make ci` passes. `make semver` reports the breaking API change
rather than hiding it.

---

- U11. **Delete `compile_config`; give the tests a `test-util` helper**

**Goal:** One `routes:` shape survives in the project. The 62 test calls get what
they actually needed.

**Requirements:** R58, R58b, R45

**Dependencies:** U4

**Files:**
- Modify: `crates/ppe-apl-core/src/parser.rs` (delete `compile_config`,
  `ConfigYaml`, `CompiledConfig`, `compile_route`; `RouteYaml` and
  `compile_apl_blocks` stay; 32 in-module test calls migrate)
- Modify: `crates/ppe-apl-core/src/lib.rs` (the re-exports)
- Create: `crates/ppe-apl-core/src/test_util.rs` (a helper returning one compiled
  route plus a plugin registry, behind a new feature)
- Modify: `crates/ppe-apl-core/Cargo.toml` (add `[features] test-util = []`)
- Modify: `crates/ppe-apl-core/tests/yaml_end_to_end.rs` (9),
  `crates/ppe-apl-runtime/tests/{end_to_end_route,elicit_then_delegate_e2e,elicit_step_e2e,delegate_step_e2e,config_override}.rs` (14),
  `crates/ppe-apl-cmf/tests/end_to_end.rs` (6)
- Modify: the three crates' `Cargo.toml` dev-dependencies to enable the feature,
  including a self dev-dependency on `praxis-policy-apl-core` for its own tests
- Modify: `Makefile` (`make coverage` gains `--all-features`)
- Modify: `CHANGELOG.md` (a breaking public API deletion)

**Approach:** Callers span three crates' integration tests, which see only the
public API, so the helper must be public and feature-gated. `ppe-core`'s existing
`test-util` feature supplies the rationale — a feature keeps a test seam out of the
semver-bound published surface — but not the mechanism, because it is enabled only
by *downstream* crates and never by its own tests. Nine of the 62 calls are in
`ppe-apl-core`'s own `tests/`, and cargo does not enable a crate's own optional
feature for `cargo test`. So `ppe-apl-core` gets a self dev-dependency with
`features = ["test-util"]` rather than a `required-features` test target: a
`required-features` target is silently skipped by the first test pass and excluded
from `make coverage`, which runs `--workspace` with no `--all-features` against a
95% floor. `make coverage` gains `--all-features` in this unit so the gated targets
stay inside that floor.

**Test scenarios:**
- Happy path: every migrated test asserts what it asserted before, on the same
  input, through `compile_policy_block_value` plus the helper.
- Covers AE18. Integration: a grep for `routes:` across the workspace finds one
  shape defined.
- Test expectation for new behavior: none — this unit moves test scaffolding and
  must not change a single assertion's outcome.

**Verification:** `make ci` passes both feature passes, and `make coverage` still
meets its floor with the gated targets counted. No `compile_config` in the tree. A
default-features build of `ppe-apl-core` does not contain the helper. No test target
is silently skipped: the count of executed tests does not fall.

---

- U12. **Lexical reconciliation: quoting, escapes, paths, numbers, identifiers**

**Goal:** One quoting rule at every site, escapes that unescape, an attribute path
that is a production, and rejections that name the construct.

**Requirements:** R9-R22, R29

**Dependencies:** U11

**Files:**
- Modify: `crates/ppe-apl-core/src/parser.rs` (`Lexer::lex_string` gains escape
  handling; `unwrap_quotes`, `split_top_level_commas`, `split_top_level`, and the
  PDP paren-arg path route through one shared string reader; `lex_ident_or_keyword`
  becomes a path production; `lex_number` states its forms;
  `split_predicate_action` becomes bracket-aware; `not` becomes reserved; `&&` and
  `||` get their own error)
- Test: `crates/ppe-apl-core/tests/lexical_conformance.rs` (new; folds into U15's
  corpus)
- Modify: `CHANGELOG.md`

**Approach:**
- Escape set is exactly `\\`, `\'`, `\"`. An unrecognized escape is an error.
- That breaks every downstream `regex("\d+")`, `regex("\w+")`, or any pattern
  carrying a backslash class, because a backslash passes through literally today.
  No in-repo policy text uses one, so both test passes stay green and the break
  would surface only in an operator's config. So this unit carries its own
  CHANGELOG entry and upgrade-guide item stating that a backslash inside a quoted
  literal must be doubled, with a `regex(...)` before and after.
- The path production rejects `a..b`, `a.`, `.a`, `data.t[]`, and makes
  `data.t[a:b]` and `data.t["a]"]` errors by construction rather than by accident.
- Positions are reported in characters, not bytes, so a non-ASCII identifier names
  the character.

**Execution note:** Characterization-first. The parser has ~90 error sites and no
document; write the accept/reject cases for today's behavior before changing it,
so a tightening that also breaks something valid is visible immediately.

**Test scenarios:**
- Covers AE2. Happy path: `a == 'it\'s'` parses with value `it's`;
  `deny('it\'s bad')` yields `it's bad` with no backslash.
- Covers AE2. Error path: `regex(")` and `enum(")` fail naming the unterminated
  literal; `a == "x\qy"` fails naming the unrecognized escape.
- Covers AE3. Error path: `a..b`, `a.`, `.a`, `data.t[]`, `data.t[a:b]`, and `1.`
  each fail naming the production violated.
- Covers AE3. Error path: a non-ASCII identifier names the character, not a byte
  offset.
- Covers AE4. Error path: `not authenticated` fails naming `!`; a path beginning
  `not.` fails naming `not` as reserved; `a not in b` still parses.
- Covers AE7. Happy path: `data.t[subject.tenant] == "y"` with a `:` inside the
  group parses as one predicate.
- Error path: `a && b` and `a || b` fail naming `&` and `|`.
- Happy path: `007` is still the integer 7; `a&b`, `a & b`, `a  &  b` are one
  expression.
- Integration: `opa("p/q")` reaches a resolver as `p/q`, not `"p/q"`.
- Error path: `regex("\d+")` fails naming the unrecognized escape, and
  `regex("\\d+")` parses to the pattern the author meant. This is the case the
  CHANGELOG and the upgrade guide must carry.

**Verification:** `make ci` passes. One string reader serves every site. Every
rejection names a construct and a character position.

---

- U13. **`require` becomes a predicate**

**Goal:** `require(P)` means `!P`, its special case in `parse_rule` is gone, and
every form in use compiles to the IR it compiles to today.

**Requirements:** R23, R24, R24b, R25, R26, R26b, R27, R5 (the comma)

**Dependencies:** U12

**Files:**
- Modify: `crates/ppe-apl-core/src/parser.rs` (`is_require_call` and
  `parse_require_rule` are deleted; `require` becomes a keyword the predicate
  parser handles; the normalization folds `Not(IsTrue)` to `IsFalse` and
  distributes `Not` over `And`/`Or`; a top-level `require(...)` rule accepts only
  `deny`; the comma binds lower than `&` and `|`)
- Test: `crates/ppe-apl-core/tests/require_conformance.rs` (new; folds into U15's
  corpus)
- Modify: `CHANGELOG.md`

**Approach:** The normalization is what makes the equivalence structural rather
than merely semantic, which is what keeps the three existing tests that assert the
current shapes by name passing unchanged.

**Test scenarios:**
- Covers AE5. Happy path: `require(role.hr)` compiles to the same IR as today;
  `require(team.engineering | team.security)` and `require(a, b)` likewise, all
  asserted against the compiled tree.
- Covers AE6. Happy path: `require(delegation.depth < 3)` parses and denies at
  depth 3.
- Covers AE6. Happy path: `require(a) & b` compiles to `!a & b`;
  `require(a, b | c)` compiles to `!(a & (b | c))`.
- Covers AE6. Happy path: `require(a): deny` and `require (a)` both parse with no
  lexer error about `:`.
- Covers AE6. Error path: `require(a): allow` fails at load naming the inversion.
- Edge case: `require(!delegated)` parses, which it cannot today.
- Integration: the two in-repo fixtures using `require(...)` compile unchanged.

**Verification:** `make ci` passes. The three named desugaring tests pass without
modification. No `require` special case remains in `parse_rule`.

---

- U14. **Positional and map-form reconciliation; `run(name)` is the only invoke form**

**Goal:** A field operation is not a rule. A step map's key set is closed. `plugin(`
is gone from both step and stage position.

**Requirements:** R28, R30, R31, R32, R33, R34, R35, R37, R38, R68, R69, R69b

**Dependencies:** U12

**Files:**
- Modify: `crates/ppe-apl-core/src/parser.rs` (`try_parse_field_op`'s shape test
  becomes a rejection in rule position; `parse_pipeline` rejects an empty stage;
  `parse_stage`'s `validate` message names the alternatives; `parse_step_map`
  closes its key set with `pdp(name):` for custom dialects, retiring the
  shorthand-detection exclusion list; `plugin(` leaves `detect_step_kind`,
  `parse_step_string`, and `parse_stage`)
- Modify, rewriting `plugin(` as `run(`: the 14 files, notably
  `crates/ppe-apl-runtime/tests/{visitor_e2e,payload_mutation_propagation,http_route_e2e,end_to_end_route,config_override,capability_gating,canonical_authn_authz_e2e}.rs`,
  `crates/ppe-apl-core/src/{parser,evaluator,step,rules}.rs` (rustdoc and tests),
  `crates/ppe-core/src/config.rs`, `crates/ppe-apl-runtime/src/visitor.rs`,
  `reference/plugins/pii-scanner/src/lib.rs`
- Modify: `CHANGELOG.md`

**Approach:** An `args:` / `result:` map value that is empty is a load error while
`parse_pipeline("")` keeps returning an empty pipeline, because R45 protects the
public entry point and the two positions want different answers.

**Test scenarios:**
- Covers AE7. Error path: `result.x | redact` in rule position fails naming effect
  position, rather than compiling a disjunction.
- Covers AE8. Error path: `mask(4) |` fails naming the empty stage; so do a
  leading and a doubled `|`.
- Covers AE8. Error path: `validate(x)` anywhere, field rule included, names
  `regex("...")` and `run(name)`.
- Covers AE9. Error path: a step map keyed `whens:` fails naming the key.
- Covers AE9. Happy path: `pdp(workload):` compiles and routes to a resolver
  registered under that custom dialect.
- Error path: `plugin(x)` in step position and in stage position both fail naming
  `run(x)`.
- Happy path: `plugin:` as a kwarg inside `delegate(...)` and the `delegate:` map
  form still parses — the word survives as a noun.
- Edge case: an empty `args:` map value fails at load while `parse_pipeline("")`
  still returns an empty pipeline.

**Verification:** `make ci` passes. No `plugin(` in policy text. Every step-map
key is either a keyword or an explicit dialect.

---

- U15. **The grammar document and the conformance corpus**

**Goal:** APL's grammar exists as one normative document, and every claim it makes
is asserted by a corpus case.

**Requirements:** R1-R8, R39, R41, R42, R43, R49, R50, R50b, R67, R67d, R67h,
R67k

**Dependencies:** U13, U14

**Files:**
- Create: `docs/apl-grammar.md` (the EBNF, the lexical rules, the one precedence
  table including the comma, the per-position table, the stage table, the YAML
  shape, the surviving warts with reasons, hook mode's key set alongside policy
  mode's)
- Create: `crates/ppe-apl-core/tests/conformance/main.rs` plus its case modules
  (the corpus: one accepted and one rejected case per production, per documented
  wart, and per breaking change; each rejected case asserts a message class and
  names the error site it exercises). The `main.rs` entry point is load-bearing:
  cargo auto-discovers `tests/*.rs` and `tests/<dir>/main.rs` but ignores loose
  files under `tests/<dir>/`, so a corpus without it compiles and runs never while
  `make ci` stays green. U12's `lexical_conformance.rs` and U13's
  `require_conformance.rs` move into it, so the corpus is the single authority the
  grammar document points at.
- Modify: `crates/ppe-apl-core/src/parser.rs` (the header comment stops describing
  the grammar and points at the document)
- Modify: `crates/ppe-apl-core/Cargo.toml` (its `docs/specs/apl-design.md` pointer
  dangles; repoint it at the new document)

**Approach:** The document is written last, when the accept set has stopped
moving. Writing it first would guarantee it describes a state no commit reaches.
It carries no dependency on any external document; where a decision departs from
how APL was first defined, the departure is named at that decision.

**Test scenarios:**
- Covers AE1. Happy path: a reader finds a comparison's spelling, `!` against `&`,
  the escape set, and the YAML key a step list goes under, without opening
  `parser.rs`.
- Covers AE10. Integration: every production has an accepted and a rejected case;
  every documented wart has a rejected case.
- Covers R43. Edge case: changing any corpus case's input invalidates its
  assertion — no case passes whichever way the parser behaves.
- Covers AE12. Happy path: `parser.rs`'s header describes the file and points at
  the document; every surviving wart in the document has a corpus case.
- Covers AE18. Happy path: the document states hook mode's key set as well as
  policy mode's, so both legal `dispatch:` values have a readable surface.

**Verification:** `make ci` passes and `make doc` passes with `-D warnings`. The
corpus executes: its test count is non-zero and rises with each case added. Every
production and every documented wart in the grammar document has a case, checked by
walking the document's tables against the corpus module list.

---

- U16. **The upgrade guide and the assembled CHANGELOG**

**Goal:** An operator has one place to read what their 0.1.0 config must become.

**Requirements:** R44, R46, R47, R47b, R48, R89c, R89d, R89e

**Dependencies:** U9, U10, U15

**Files:**
- Create: `docs/content/guides/upgrade-apl.md` (every key and form an existing
  config must rewrite, with before and after)
- Modify: `CHANGELOG.md` (assemble the per-unit entries; point at the guide; give
  `response:` the entry it never got, since it shipped in 0.1.0 undocumented)
- Verify: all three praxis-demos policies (`policy.yaml`, `policy-cel.yaml`,
  `policy-opa.yaml`) against the finished grammar

**Approach:** Each unit wrote its own CHANGELOG entry as it landed; this unit
assembles them into a coherent release note and cross-checks the guide against the
full removal list so nothing is missing. The external check is against every
breaking change, not a named subset.

**Test scenarios:**
- Covers AE11. Happy path: every tightened form appears in the guide with a
  before, an after, and a rewrite.
- Covers AE11. Integration: all three praxis-demos configs are read against the
  finished grammar and the result is stated. Measured expectation from planning:
  `policy.yaml`, `policy-cel.yaml`, and `policy-opa.yaml` each need the
  `engine_settings` / `dispatch` rename and four flat `pre_invocation:` blocks
  nested — three renames and twelve blocks — plus correction of the notes in
  `policy-cel.yaml` and `policy-opa.yaml` asserting the engine accepts both phase
  spellings, which U4 makes false.
- Test expectation: none for the documents themselves — they are prose. The
  verification is the external config check.

**Verification:** `make ci` passes. `make lint-extra` passes (typos, taplo).
Every removal in the plan appears in the guide. The praxis-demos result is
recorded.

---

## System-Wide Impact

- **Interaction graph:** `filter_entries_by_route` (U9) sits on every hook
  dispatch, so its denial path affects all traffic. `resolve_identity_plugins_for_route`
  (U7) affects `identity.resolve` only. The visitor's layer stacking (U3, U8, U9)
  affects every route's compiled policy.
- **Error propagation:** New load errors surface as `PluginError::Config` through
  `load_config_yaml`, the existing path. The metadata-less denial surfaces as a
  `PluginViolation` with a 400-class proto code, following the unreadable-path
  precedent.
- **State lifecycle risks:** U9's default flip changes which plugins run for
  configs that never opted into routing. No partial-write or cache concern: the
  route cache is keyed on configuration-derived names, and U8 removes the only
  non-deterministic tag iteration.
- **API surface parity:** U10 and U11 are breaking Rust API changes on
  `ppe-apl-core`. `make semver` should report both rather than have them slip.
- **Integration coverage:** the two `ppe-core/examples` are the only in-repo
  consumers that register no APL visitor, which makes them the integration test
  for hook mode being genuinely supported (U8).
- **Unchanged invariants:** plugin `kind:` strings, hook names, and violation
  codes stay exactly as they are — `wire_compatibility.rs` keeps asserting them.
  Only the phase-spelling guarantee lapses, and U4 says so.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Closing key sets before migrating files breaks the suite mid-series | Every removal unit contains its own migration; U2 is behavior-preserving so later units are one-line table edits |
| The 398-site rename hides a behavior change | U1 keeps `dispatch` defaulting to `hooks`; the flip is U9, with its own tests |
| U9's default flip silently narrows enforcement for upgraded configs | The reachability check catches reach-nothing configs; the CHANGELOG names the per-hook narrowing no check can catch, and `dispatch: hooks` is the documented escape |
| U4 retires a published guarantee without anyone noticing | The fixture rewrite, the test's doc comment, and the CHANGELOG entry land in one commit |
| `require` normalization misses a case and inverts a decision | U13 asserts against the compiled IR for all four forms, and the three existing named tests must pass unmodified |
| The grammar document describes a state no commit reaches | U15 is last, after the accept set stops moving |
| Two-pass test runs hide a feature-gated break | U11's helper is feature-gated; both passes are part of every unit's verification |

---

## Documentation / Operational Notes

- `docs/apl-grammar.md` (U15) and `docs/content/guides/upgrade-apl.md` (U16) are
  new deliverables.
- `crates/ppe-apl-core/Cargo.toml` points at `docs/specs/apl-design.md`, which does
  not exist; U15 repoints it.
- Repo convention from `CONTRIBUTING.md`: requirement and unit identifiers from
  these documents must not appear in commit messages, code comments, rustdoc,
  changelog entries, or test names. Describe the behavior instead.
- `make semver` should be run after U10 and U11 so the breaking API changes are
  reported deliberately.

---

## Sources & References

- **Origin document:** `docs/brainstorms/2026-08-27-apl-grammar-requirements.md`
- **Origin companion:** `docs/brainstorms/2026-08-27-apl-canonical-form.md`
- Issue: [praxis-proxy/policy#17](https://github.com/praxis-proxy/policy/issues/17)
- Pairs with: [#14](https://github.com/praxis-proxy/policy/issues/14) (coverage)
- Prior plan convention: `docs/plans/2026-08-25-001-feat-http-route-selector-plan.md`
