---
title: "fix: one authority for which hooks exist"
type: fix
status: completed
date: 2026-08-24
origin: docs/brainstorms/2026-08-24-cmf-hook-registry-requirements.md
---

# fix: one authority for which hooks exist

## Summary

Make `BUILTIN_METADATA` the single authority for the hooks the engine dispatches, complete it
(it is missing three of the thirteen), derive the name enumeration from it instead of
hand-maintaining a parallel list, and point the plugin-config validator at that enumeration so a
wrong entry fails a test instead of sitting unread. Drop the six legacy constants that shadow
CMF hooks, reconcile identity and delegation onto their dotted names, and add `cmf.http_response`
so the L7 path has a return half.

The unglamorous part carries the risk. `validate_config` runs on two of four config-load paths,
so a validator added to it is unreachable for a host that builds a `PolicyConfig`
programmatically. U5 fixes that, and the assertions work needs the same fix for a different
reason.

---

## Implementation Guidelines

**1. No requirement or plan identifiers in durable text.** Nothing that ships may cite `R7`,
`U3`, `AE5`, or any identifier from this plan or its origin. That covers rustdoc, comments,
commit messages, the CHANGELOG entry, test names, and the PR description. Describe the
behavior:

```
no    // Per R7, distinguishes unregistered from unphased.
yes   // An absent hook and a deliberately unphased one both used to read
      // as Unphased, so a caller reading phase to decide could not tell
      // a missing entry from a real one.
```

**2. Keep comments and rustdoc short.** One or two sentences per item. No em dashes. No
restating the signature in prose. Rationale earns its place where the code looks wrong without
it: in this work that is why an unphased hook still needs a table row (U1), and why the
enumeration is derived rather than written (U3).

**3. Commits.** `git commit -s` on every commit. No AI attribution trailers. Conventional
style; this work carries a breaking change, so the subject takes `!`.

**4. One authority means one.** No unit may introduce a second hand-maintained list of hook
names, including in a test. A test that needs the set iterates the authority.

---

## Problem Frame

Twelve hook constants exist; `BUILTIN_METADATA` holds ten, missing `cmf.http_request` and
`elicit`. `builtin_hook_types()` restates the set by hand and gets six of sixteen entries right.
`hook_names` adds eight more constants: six shadowing CMF hooks under names nothing dispatches,
two duplicating identity and delegation under the wrong spelling.

Nothing consumes either enumeration, in this repository or in praxis, which is why the drift was
never caught: a list nothing reads cannot fail. Meanwhile the thing that should be validated is
not. Plugin declarations carry hook names as free strings (`plugin.rs:188`), nothing checks them,
and a typo loads clean and never fires. The canonical example at `plugin.rs:150-153` teaches one
of the dead spellings.

The cost is now concrete. The assertions work derives request-versus-response direction from a
hook's registered phase, and `cmf.http_request` has no entry, so `lookup` reports `Unphased` and
the L7 path silently gets neither direction. See origin for the full framing.

---

## Requirements

Restated from origin. Cited by unit below.

- R1. `BUILTIN_METADATA` is the single authority. Every enumeration of hook names derives from it.
- R2. Every dispatched hook has an entry: `cmf.http_request` gains `Pre` / `ENTITY_HTTP`, `elicit` gains `Unphased`, `cmf.http_response` is added.
- R3. A hook name is defined by exactly one constant.
- R4. Hook names declared in plugin config are validated at load, naming the name, the plugin, and the nearest known match.
- R5. A host's runtime-registered hook satisfies R4 once registered.
- R6. `builtin_hook_types()` and `hook_type_from_str()` are kept, re-expressed as projections over the authority, and consumed by R4's validator.
- R7. A consumer can distinguish a deliberately unphased hook from an unregistered one.
- R8. An entry's phase matches the phase the dispatcher installs it under, asserted by a test.
- R9. The six `hook_names` constants shadowing CMF hooks are removed.
- R10. Identity and delegation keep the dotted names `identity.resolve` and `token.delegate`; the underscored duplicates go.
- R11. The `plugin.rs` example stops teaching a removed spelling.
- R12. Removing public items is a breaking change, recorded. The `cmf/constants.rs` names stay public and stably valued.
- R13. `cmf.http_response` exists, carries `Post` / `ENTITY_HTTP`, and APL installs a handler for it.
- R14. The reason both L7 halves exist is recorded at the constants.
- R15. PPE defining and routing a hook does not oblige a host to fire it.

---

## Context & Research

### Verified against the tree

| Concern | Location | Note |
|---|---|---|
| The authority | `hooks/metadata.rs:167-242` `BUILTIN_METADATA` | `&[(&str, HookMetadata)]`, ten entries |
| Metadata shape | `hooks/metadata.rs:118` `HookMetadata`, `:91` `HookPhase` | `HookPhase` is **not** `#[non_exhaustive]`, so adding a variant is breaking |
| Permissive fallback | `hooks/metadata.rs:126` `unknown()`, `:268` inside `lookup` | `{entity_type: None, phase: Unphased}`, substituted for an absent name. Two references in the whole tree: its definition and that one use |
| Runtime registration | `hooks/metadata.rs:271` `register_hook_metadata` | seeds from `BUILTIN_METADATA` on first access, then accepts additions |
| Only production reader | `ppe-apl-runtime/src/dispatch_plan.rs:100` | `lookup_hook_metadata(name).matches(entity, phase)` |
| Permissive wildcard | `hooks/metadata.rs:147` `matches`, `:157` | `(Unphased, _) | (_, Unphased) => true`, which is why the gap never surfaced |
| Hand-maintained list | `hooks/types.rs:132` `builtin_hook_types()`, `:157` `hook_type_from_str` | no caller in this tree or praxis |
| Count test | `hooks/types.rs:194` | asserts `len() == 16`, a magic number to be replaced |
| Legacy constants | `hooks/types.rs:72-98` `hook_names` | underscored identity/delegation at `:94,96` |
| CMF names | `cmf/constants.rs:125-145` | nine; `HOOK_CMF_HTTP_REQUEST` at `:145` with the pre-only rationale at `:141-144` |
| L7 install site | `ppe-apl-runtime/src/visitor.rs:551` | `ENTITY_HTTP`, `ENTITY_NAME_GLOBAL`, `Phase::Pre` |
| Declared hooks | `plugin.rs:188` `pub hooks: Vec<String>`; example at `:150-153` | free strings, unvalidated; example uses a dead spelling |
| Existing validator | `config.rs:718` `validate_config` | `pub(crate)`; duplicate plugin names and route shape |

### Validation does not run on every load path

`validate_config` is called from `config::load_config` (`config.rs:644`) and
`PolicyEngine::load_config_yaml` (`engine.rs:600-601`). It is **not** called from
`PolicyEngine::load_config` (`engine.rs:506`), which takes a pre-built `PolicyConfig`, nor from
`from_config` (`engine.rs:748`). `merge_groups_into_policies` has the identical coverage.

So a host constructing a `PolicyConfig` in Rust gets no duplicate-plugin-name check, no route
shape check, and would get no hook-name check. R4 would be satisfied on paper and unreachable
for that host. This is pre-existing and out of the origin's stated scope, but R4 cannot be met
without it, so U5 fixes it. The assertions work needs the same fix for group resolution, so
doing it once here serves both.

### Declared names that must keep working

`elicit` is declared in shipped plugin code (`builtins/plugins/elicitation-ciba/src/factory.rs:68`)
and in operator YAML (`crates/ppe-core/tests/fixtures/legacy-policy-document.yaml:199`,
`ppe-apl-runtime/tests/elicit_then_delegate_e2e.rs:213`). Praxis declares `identity.resolve` in
its own policy-filter YAML. Both must pass R4's validator on day one, which is why R2 adds
`elicit` even though its phase carries no routing information.

---

## Key Technical Decisions

**D1. `lookup` returns `Option<HookMetadata>`.** An `Unregistered` variant on `HookPhase` is out,
because the enum is not `#[non_exhaustive]` and every external match would break. That leaves
either a signature change or a second function alongside, and the signature change is right:
`lookup` has exactly one caller anywhere (`dispatch_plan.rs:100`), and praxis references neither
`lookup`, `HookMetadata`, nor `HookPhase`. A companion function would leave a lookup that still
cannot say "absent" sitting next to one that can.

Its caller becomes explicit about the fallback it wants:

```rust
lookup_hook_metadata(hook_name)
    .unwrap_or_else(HookMetadata::permissive)
    .matches(requested_entity_type, requested_phase)
```

That is an improvement independent of this work. Today the substitution is invisible at the call
site, so a reader has to know `lookup` swaps in a wildcard to understand why an unregistered hook
still dispatches. `unknown()` is renamed `permissive()` in the same change: with `lookup`
returning `Option`, "unknown" no longer describes a lookup result, only a deliberate default. Both
are breaking changes to public items and ride the same minor bump as U4's removals.

**D2. Derive the enumeration; do not delete it.** An earlier draft removed
`builtin_hook_types()` and `hook_type_from_str()` because nothing calls them. That mistook the
symptom for the disease: unused is *why* the list rotted, and deleting it leaves the drift class
open for the next parallel list. Both become projections over the authority, and U6 gives them a
consumer that fails when they are wrong. U7's agreement test needs an enumeration anyway.

**D3. An unphased hook still needs a row.** The table reads as if it were built for phase-based
route matching, where an unphased hook gains nothing from an entry, which is plausibly why
`elicit` was never added. Giving the table a second consumer changes what completeness means:
any hook a plugin can declare must be present, phase or not. This gets a comment at the table,
because it is the invariant a future maintainer will otherwise break.

**D4. Validate against the runtime registry, not the constant.** R5 requires a host's
registered hook to pass. `registry()` seeds from `BUILTIN_METADATA` and accepts additions, so
the validator reads the registry. Ordering matters: a host registering a custom hook must do so
before loading config that declares it, which U9 documents.

**D5. `cmf.http_response` ships even though no host fires it.** PPE defining and routing a hook
is independent of a host choosing to fire it (R15). A host that never fires it sees no change.
Shipping it now means the praxis-side work is a host change alone, with no coordinated release.

**D6. Co-declare the constant and its metadata row with a macro.** A test cannot enumerate
constants: Rust has no reflection, and any list a test iterates is a second hand-maintained list,
which is the defect this work exists to remove. The alternative backstop, U6's validator, only
fires for a hook someone *declares in config*, so a hook registered in Rust and never named in
YAML slips through, reads as unregistered to every phase consumer, and reproduces the
`cmf.http_request` bug exactly.

So a `define_hooks!` macro emits both the `pub const` and the metadata row from one declaration.
It is invoked once per module that owns hooks, and `BUILTIN_METADATA` concatenates the per-module
slices, so import paths are unchanged and R12 holds. A constant without a row stops being a bug
to test for and becomes unrepresentable.

The residual gap moves up one level: a new module's slice could be left out of the concatenation.
That is rarer than forgetting a row, more visible in review, and unlike a missing row it makes
every hook in that module unregistered at once rather than one quietly.

---

## Scope Boundaries

- Praxis firing the LLM hooks or `cmf.http_response`. Two host-side issues, tracked separately.
- Adding, renaming, or removing any dispatched hook beyond `cmf.http_response`.
- The assertions feature. This work unblocks it and is otherwise independent.
- Validating anything else in `PluginConfig` beyond hook names, beyond making the existing checks reachable (U5).
- A typed-payload hook family. The payload types the legacy constants named do not exist.

---

## Implementation Units

- U1. **Co-declare hooks and their metadata, and complete the authority**

**Goal:** One declaration per hook emits both its constant and its metadata row, and the table
holds all thirteen including the L7 return half.

**Requirements:** R1, R2, R3, R13, R14

**Dependencies:** None

**Files:**
- Create: `crates/ppe-core/src/hooks/declare.rs` (the `define_hooks!` macro)
- Modify: `crates/ppe-core/src/hooks/metadata.rs`, `crates/ppe-core/src/cmf/constants.rs`,
  `crates/ppe-core/src/identity/hook.rs`, `crates/ppe-core/src/delegation/hook.rs`,
  `crates/ppe-core/src/elicitation/hook.rs`

**Approach:**
- `define_hooks!` takes, per hook, a constant name, its wire name, an optional entity type, and a
  phase. It emits the `pub const` with its doc comment and a `HookMetadata` row, and exposes the
  module's rows as one `&[(&str, HookMetadata)]` slice (D6).
- Invoke it once per owning module. Constants keep their current paths, so `praxis_policy_core::cmf::constants::HOOK_CMF_TOOL_PRE_INVOKE` and the identity, delegation and
  elicitation constants resolve exactly as they do today (R12).
- `BUILTIN_METADATA` becomes the concatenation of the per-module slices rather than a literal
  table. Keep the name: `registry()` and every reader are unchanged.
- Declare `HOOK_CMF_HTTP_RESPONSE = "cmf.http_response"` with `ENTITY_HTTP` / `Post`, alongside a
  corrected `ENTITY_HTTP` / `Pre` for the request hook and `Unphased` for `elicit` — the three
  rows the table is missing (R2).
- Rewrite the request constant's doc comment. Its pre-only rationale is correct for
  authorization and does not cover response filtering, which is why the post half now exists;
  state each half's purpose at each constant (R14).
- Put the D3 note at the macro rather than the table: a hook a plugin can declare needs a row
  whether or not it has a phase, which is why `Unphased` is a value the macro requires rather
  than a default it supplies.

**Patterns to follow:** `hooks/macros.rs` `define_hook!`, which already generates a hook type and
its handler trait from one declaration. This is the same idea one level down.

**Test scenarios:**
- Happy: `lookup` gives `Pre` / `ENTITY_HTTP` for `cmf.http_request`, `Post` / `ENTITY_HTTP` for `cmf.http_response`, and `Unphased` for `elicit`.
- Happy: every constant the macro declares appears in the concatenated table, by construction rather than by assertion. A test that names hooks by hand is a defect (Guideline 4).
- Happy: the concatenated table has thirteen rows, and each per-module slice has the count that module declares.
- Happy: every constant resolves at its pre-existing path, asserted by importing each one at its documented path.
- Edge: `matches` behavior for the two HTTP hooks is unchanged for existing entity-typed dispatch, since `ENTITY_HTTP` is already what `visitor.rs` installs under.

---

- U2. **Registered versus unphased**

**Goal:** A caller can tell an absent hook from a deliberately unphased one.

**Requirements:** R7

**Dependencies:** U1

**Files:**
- Modify: `crates/ppe-core/src/hooks/metadata.rs`

**Approach:**
- Change `lookup` to `pub fn lookup(hook_name: &str) -> Option<HookMetadata>`, returning `None`
  for a name the registry does not hold (D1).
- Rename `HookMetadata::unknown()` to `permissive()` and update its doc line: it is the
  deliberate wildcard default a caller opts into, not the result of a failed lookup.
- Update the one caller, `dispatch_plan.rs:100`, to `.unwrap_or_else(HookMetadata::permissive)`
  before `.matches(...)`, so its dispatch behavior is unchanged and now visible at the call site.
- Do not add a `HookPhase` variant. The enum is not `#[non_exhaustive]`.

**Test scenarios:**
- Happy: `lookup` is `Some` for all thirteen and `None` for an unregistered name.
- Happy: the three deliberately unphased hooks return `Some` carrying `Unphased`, distinguishable from `None`.
- Happy: a host-registered hook becomes `Some` after `register_hook_metadata`.
- Happy: `dispatch_plan`'s routing decisions are unchanged for every hook, registered or not. This is the regression guard on the signature change; assert it against the existing dispatch tests rather than a new fixture.

---

- U3. **Derive the enumeration**

**Goal:** No hand-maintained list of hook names anywhere.

**Requirements:** R1, R6

**Dependencies:** U1

**Files:**
- Modify: `crates/ppe-core/src/hooks/types.rs`

**Approach:**
- `builtin_hook_types()` becomes a projection over `BUILTIN_METADATA`.
- `hook_type_from_str` keeps canonical-or-custom behavior, sourcing the canonical set from the
  authority rather than its own list.
- Replace `test_builtin_hook_types_count`'s `len() == 16` with an assertion against the
  authority's length, so the number is not restated (Guideline 4).

**Test scenarios:**
- Happy: the derived enumeration equals the authority's key set, including `cmf.http_response` and `elicit`.
- Happy: adding a row to the authority changes the enumeration with no second edit; a test demonstrates this rather than asserting a count.
- Happy: `hook_type_from_str` returns the canonical instance for a known name and a custom `HookType` for an unknown one, as today.

---

- U4. **Drop the legacy CMF constants**

**Goal:** One constant per hook, and no documentation teaching a name that does not dispatch.

**Requirements:** R9, R10, R11, R12

**Dependencies:** U3

**Files:**
- Modify: `crates/ppe-core/src/hooks/types.rs`
- Modify: `crates/ppe-core/src/plugin.rs`
- Modify: `CHANGELOG.md`

**Approach:**
- Delete the `hook_names` module outright (`types.rs:72-98`), not just its six shadowing
  constants. Nothing imports it: the only `hook_names::` reference in the tree is the doctest at
  `types.rs:31`, and it names `TOOL_PRE_INVOKE`, one of the constants being removed, so that
  doctest changes either way. A re-export shim would exist for no caller and would leave a second
  place a spelling could reappear, which is what R3 forbids.
- Point the `types.rs:31` doctest at a dispatched constant from `cmf::constants`.
- Fix the `plugin.rs:150-153` example to a dispatched name.
- CHANGELOG entry under breaking changes, noting that the `cmf/constants.rs` names are unchanged
  and remain the supported import, and that their string values are operator-facing because
  hosts name hooks in YAML (R12).

**Test scenarios:**
- Happy: the workspace builds and every test passes with no replacement enumeration.
- Happy: a grep for each removed spelling finds nothing outside the CHANGELOG.
- Happy: every dispatched hook name resolves to exactly one constant.

---

- U5. **Make config validation reachable on every load path**

**Goal:** A host that builds a `PolicyConfig` in Rust gets the same validation as one that loads YAML.

**Requirements:** R4 (precondition)

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/engine.rs`

**Approach:**
- Call `merge_groups_into_policies` and `validate_config` from `PolicyEngine::load_config`
  (`:506`) and `from_config` (`:748`), matching what `load_config_yaml` (`:579`) already does.
- `from_config` is infallible today; check its signature before changing it. If it cannot return
  an error, either it gains a fallible sibling or it validates and logs at `error` without
  refusing, and the plan records which. Decide in review, not silently.
- This is a behavior change: a programmatic config with a duplicate plugin name now fails where
  it previously loaded. That is the intent, and it belongs in the CHANGELOG.

**Test scenarios:**
- Happy: a valid `PolicyConfig` loads through all four paths.
- Error: a duplicate plugin name is rejected through `load_config` and `from_config`, not only through the YAML paths.
- Happy: group blocks resolve through `load_config` and `from_config`, which they did not before.

---

- U6. **Validate declared hook names**

**Goal:** A typo in `hooks:` fails at load with a usable message.

**Requirements:** R4, R5

**Dependencies:** U3, U5

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Extend `validate_config` to check every `PluginConfig.hooks` entry against the runtime registry
  (D4), not against `BUILTIN_METADATA` directly, so a host-registered hook passes.
- The error names the plugin, the offending hook name, and the nearest known name by edit
  distance. `tool_pre_invoke` should suggest `cmf.tool_pre_invoke`, which is the exact mistake
  the old documentation taught.
- A plugin declaring no hooks is unaffected.

**Test scenarios:**
- Error: Covers R4. A plugin declaring `tool_pre_invoke` fails, names the plugin, and suggests `cmf.tool_pre_invoke`.
- Error: a plugin declaring `cmf.prompt_pre_fetch` fails and suggests `cmf.prompt_pre_invoke`.
- Happy: Covers R5. A host registering a custom hook, then loading config declaring it, succeeds.
- Happy: the shipped CIBA plugin's `elicit` declaration passes, and the fixture YAML declaring `hooks: [elicit]` still loads.
- Happy: praxis's `identity.resolve` spelling passes.
- Edge: an empty `hooks:` list loads.

---

- U7. **The authority and the dispatch sites agree on phase**

**Goal:** A hook's recorded phase matches the phase the dispatcher installs it under.

**Requirements:** R8

**Dependencies:** U1

**Files:**
- Create: `crates/ppe-apl-runtime/tests/hook_phase_agreement.rs`

**Approach:**
- Completeness is not tested here. U1's macro makes a constant without a row unrepresentable
  (D6), so the only thing left to check is whether the phase recorded is the phase used.
- The test lives in `ppe-apl-runtime` because that is where the install sites are: `visitor.rs`
  installs each hook with an explicit `Phase`, and `ppe-core` cannot see them.
- Assert that for every hook the visitor installs, the `Phase` it passes matches
  `lookup(name)`'s phase. Iterate the authority, not a hand-written list.

**Test scenarios:**
- Error: a table row whose phase contradicts the install site fails, naming the hook and both phases.
- Happy: the current install sites agree with the authority, including both L7 halves after U8.
- Edge: a hook in the authority that the visitor never installs is not a failure. Identity, delegation and elicit are dispatched by other paths.

---

- U8. **APL installs the response handler**

**Goal:** The L7 return half is routable.

**Requirements:** R13, R15

**Dependencies:** U1

**Files:**
- Modify: `crates/ppe-apl-runtime/src/visitor.rs`

**Approach:**
- Install a handler for `HOOK_CMF_HTTP_RESPONSE` alongside the request hook at `:551`, with
  `Phase::Post`, same `ENTITY_HTTP` / `ENTITY_NAME_GLOBAL` annotation.
- A host that never fires it sees no change (R15); the handler simply never runs.

**Test scenarios:**
- Happy: a global policy with a post phase is annotated under the response hook, mirroring the existing request-hook test in `global_http_authz.rs`.
- Happy: firing the request hook alone behaves exactly as before.

---

- U9. **Documentation and CHANGELOG**

**Requirements:** R11, R12, R15

**Dependencies:** U1-U8

**Files:**
- Modify: `CHANGELOG.md`, plugin-authoring docs wherever `hooks:` is documented

**Approach:** Document the validated `hooks:` field and the registration-before-load ordering
D4 requires. Record the breaking removals, and state that a host is free never to fire
`cmf.http_response`.

---

## Unit Dependency Graph

```
U1 (complete the authority) ──┬── U2 (registered vs unphased)
                              ├── U3 (derive enumeration) ── U4 (drop legacy) ──┐
                              ├── U7 (agreement test)                          │
                              └── U8 (APL response handler)                     │
U5 (validation reachable) ────────────────────────────────── U6 (validate names) ── U9 (docs)
```

U1 and U5 have no dependency and can start in parallel. U6 needs both the derived enumeration
and a reachable validator, so it is the integration point.

---

## System-Wide Impact

- **Breaking:** six legacy constants and two underscored duplicates removed from `ppe-core`'s public surface; `lookup` now returns `Option`; `HookMetadata::unknown()` renamed `permissive()`. Nothing in this tree or praxis uses the constants, and `lookup` has one caller in this tree and none in praxis, but all of it is a minor bump under the 0.1.x policy.
- **Behavior change:** config load now fails on an unknown declared hook name, and on the checks U5 makes reachable. A config that previously loaded with a silently-inert plugin now refuses to start. That is the intent and needs a CHANGELOG note.
- **Additive:** `cmf.http_response`, three authority rows.
- **No plugin API change.** Handler traits, registration, and capabilities are untouched.
- **Unblocks** the assertions work's direction gate, and fixes its group-resolution finding as a side effect of U5.
- **Coverage gate:** `make coverage` is at 95%.

---

## Risks & Dependencies

| Risk | Mitigation |
|---|---|
| U6 rejects a config that works today, breaking a deployment on upgrade. | The validator runs against the runtime registry including host additions (D4), and U6 tests the shipped CIBA declaration, the fixture YAML, and praxis's spelling. Residual: a host declaring a hook it registers *after* loading config now fails. D4 documents the ordering; U9 states it. |
| U5 turns a previously-silent programmatic misconfiguration into a startup failure. | Intended, and the same class of change as U6. Both land in one CHANGELOG entry so an upgrader reads one note. |
| `from_config` cannot return an error, so U5 cannot fail closed there. | Called out in U5 as a decision for review rather than resolved silently. |
| A new module owning hooks is added and its slice is left out of the concatenation, making every hook in it unregistered at once. | The residual gap D6 accepts, in exchange for closing the per-hook one. Rarer than forgetting a row, and it fails loudly: every hook in that module reads as unregistered rather than one quietly. There are four such modules today and adding a fifth is a reviewable event. |
| The macro obscures the constants, so a reader cannot find a hook's declaration by grepping its name. | The wire name still appears as a literal in the macro invocation, so grepping `"cmf.tool_pre_invoke"` lands on the declaration. Assert this in review; if the macro takes the name any other way, that is a reason to reject the shape. |
| The dotted names are operator-facing, so a future rename breaks deployed YAML silently. | R12 fixes their values as public API; the CHANGELOG says so. Praxis has `identity.resolve` in its own config files today. |

---

## Open Questions

### Resolved during planning

- **Delete or derive the enumeration?** Derive (D2). Unused was the defect, not the reason to remove.
- **How to distinguish unregistered from unphased?** `lookup` returns `Option` (D1). An enum variant is out because `HookPhase` is not `#[non_exhaustive]`; a companion function was drafted and cut, since `lookup` has one caller in this tree and none in praxis, so there is no compatibility burden to route around.
- **Does an unphased hook need a row?** Yes (D3). `elicit` is declared in shipped plugin config, so R4's validator would reject the elicitation plugin without it.
- **Which identity and delegation spelling survives?** The dotted ones, per origin R10.
- **How is completeness enforced?** By construction, via U1's `define_hooks!` macro (D6), not by a test. A test cannot enumerate constants, and U6's validator only catches hooks that appear in config, so a Rust-registered hook would have slipped through exactly as `cmf.http_request` did.
- **Is `hook_names` re-exported or deleted?** Deleted. Its only reference is a doctest naming a constant being removed, so a re-export shim would serve no caller and would leave a second place a spelling could reappear.

### Needing an answer before U5

- **Can `from_config` fail?** If not, decide whether it gains a fallible sibling or validates-and-logs. Do not leave it validating nothing.

### Deferred to implementation

- The edit-distance threshold for U6's suggestion, and whether to suggest at all when nothing is close.
- Whether `define_hooks!` should also emit the `define_hook!` type declaration where a family has one, or stay narrowly about names and metadata. Narrow is the assumption; widening it is a follow-on.

---

## Sources & References

- Origin requirements: `docs/brainstorms/2026-08-24-cmf-hook-registry-requirements.md`
- Unblocks: `docs/plans/2026-08-24-001-feat-upstream-assertions-plan.md`, whose direction gate reads hook phase
- Host-side follow-ups: praxis does not fire `cmf.llm_input` / `cmf.llm_output`, and will need to fire `cmf.http_response`
