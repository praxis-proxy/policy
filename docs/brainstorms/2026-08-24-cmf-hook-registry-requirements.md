---
date: 2026-08-24
topic: cmf-hook-registry
---

# One authority for which hooks exist

## Summary

Four places in the tree claim to know what hooks the engine dispatches, and they disagree.
The disagreement survived because hook metadata was only ever read for dispatch *matching*,
where an unregistered hook falls back to a permissive wildcard and nothing fails. It stops
surviving the moment a consumer reads a hook's phase in order to *decide* something.

This work makes the metadata table the single authority, derives the name enumeration from it
instead of hand-maintaining a parallel list, and gives that enumeration a consumer so a wrong
entry breaks a test rather than sitting unread. It fills the three metadata gaps, adds a
response counterpart on the L7 path, and drops the six legacy constants that shadow CMF hooks.

---

## Problem Frame

Twelve hook constants exist. The metadata table holds ten.

| Where | What it holds | State |
|---|---|---|
| `cmf/constants.rs:125-145` | the nine `cmf.*` names | correct; what the dispatcher and the host use |
| `identity/hook.rs:35`, `delegation/hook.rs:21`, `elicitation/hook.rs:20` | `identity.resolve`, `token.delegate`, `elicit` | correct |
| `hooks/metadata.rs` `BUILTIN_METADATA` | phase and entity per hook | missing `cmf.http_request` and `elicit` |
| `hooks/types.rs` `hook_names` | eight constants | six shadow CMF hooks under names nothing dispatches; two duplicate identity and delegation under the wrong spelling |
| `hooks/types.rs` `builtin_hook_types()` | a 16-entry list | ten entries wrong, one dispatched hook missing |

`builtin_hook_types()` is wrong four ways at once. Its six legacy CMF entries name hooks
nothing dispatches. Its prompt entries say `cmf.prompt_pre_fetch` / `cmf.prompt_post_fetch`
where the constants and the host use `_pre_invoke` / `_post_invoke`. Its identity and delegation
entries say `identity_resolve` / `token_delegate` where the registered names carry dots. And it
omits `cmf.http_request`. Six of sixteen entries are correct.

**Why the drift was never caught: nothing consumes it.** `builtin_hook_types()` and
`hook_type_from_str()` have no caller in this repository or in praxis, verified against both
trees. A list that nothing reads cannot fail, so it was free to rot. Correcting it in place
would leave that property intact.

**Meanwhile the thing that should be validated is not.** Plugin declarations carry hook names
as free strings (`plugin.rs:188`, `pub hooks: Vec<String>`), populated from YAML, and nothing
checks them against the set of hooks that exist. A typo loads clean and the plugin silently
never fires. The evidence that this already bites: the canonical plugin example at
`plugin.rs:150-153` teaches `hooks: [tool_pre_invoke, tool_post_invoke]`, which is one of the
spellings nothing dispatches.

**The cost is now concrete.** `cmf.http_request` is the L7 authorization hook. The host gates
on it (`filter.rs:206`) and APL installs it with `Phase::Pre` (`visitor.rs:551`), but with no
metadata entry `lookup` returns `HookMetadata::unknown()`, whose phase is `Unphased`. That is
survivable for matching and wrong for deciding, and it makes `Unphased` carry two incompatible
meanings: "genuinely has no phase" (identity, delegation, elicit) and "never registered." The
assertions work ([#28](https://github.com/praxis-proxy/policy/issues/28)) derives
request-versus-response direction from phase, so on the current table the L7 path silently gets
neither, in a control whose failure mode is to pass client-supplied headers through.

**And the L7 path has no return half.** `cmf.http_request`'s comment explains the absence:
"authorization is an admission check, so there is no post counterpart." Correct for
authorization, and it does not cover response-header filtering, which is not an admission check
and which the L7 path needs more than any entity path, having no entity-specific hook to fall
back on.

---

## Actors

- A1. PPE maintainer: adds or renames a hook and should change one place, not four.
- A2. Plugin author: writes `hooks:` in YAML and today gets no signal when the name is wrong.
- A3. Host integrator: reads the public surface to learn which names are real. Currently misinformed.
- A4. Metadata consumer: any engine feature reading phase or entity to make a decision rather than to match a route. The assertions direction gate is the first.

---

## Requirements

**One authority**

- R1. `BUILTIN_METADATA` is the single authority for which hooks the engine dispatches. Every enumeration of hook names derives from it rather than restating it.
- R2. Every dispatched hook has an entry. `cmf.http_request` gains `Pre` / `ENTITY_HTTP`, `elicit` gains `Unphased`, and `cmf.http_response` is added per R11.
- R3. A hook name is defined by exactly one constant. A second spelling of the same hook is a defect, not an alias.

**The enumeration earns its place**

- R4. Hook names declared in plugin config are validated at load against the authority. An unknown name fails, naming the name, the plugin, and the nearest known match.
- R5. A host's runtime-registered hook satisfies R4 once registered, so `register_hook_metadata` remains the supported path for a custom hook and validation does not close it.
- R6. `builtin_hook_types()` and `hook_type_from_str()` are kept, re-expressed as projections over the authority, and consumed by R4's validator. Neither is hand-maintained after this work.

**Phase semantics**

- R7. A consumer can distinguish a hook that is deliberately unphased from one that is not registered. Identity, delegation, and elicit are the deliberately unphased set.
- R8. An entry's phase matches the phase the dispatcher installs that hook under, and a test asserts the table and the dispatch sites agree so a hook cannot land in one without the other.

**Dropping the legacy CMF counterparts**

- R9. The six `hook_names` constants shadowing CMF hooks are removed: tool pre and post, prompt pre and post, resource pre and post. They have no `define_hook!`, no payload type in the tree, and no dispatch site, and the prompt pair never matched the CMF spelling.
- R10. Identity and delegation are not legacy and keep their hooks. The preserved names are the **dotted** forms, `identity.resolve` and `token.delegate`, as declared by `define_hook!` (`identity/hook.rs:93`, `delegation/hook.rs:80`) and already used by `BUILTIN_METADATA`, by `engine.rs:1451`, and by the host in both Rust and operator-facing YAML. The underscored duplicates `identity_resolve` and `token_delegate` (`hooks/types.rs:94,96`) are removed along with their `builtin_hook_types()` entries (`:141,142`), which are the only four places the underscored spelling exists and which nothing dispatches. `hook_names` re-exports the authoritative constants instead, so there is one import path and one value; removing the module outright is also acceptable if the re-export earns nothing. `elicit` needs no reconciliation, having no separator and no duplicate.
- R11. The `plugin.rs` documentation example stops teaching a removed spelling.
- R12. Removing public items is a breaking change to `ppe-core` and is recorded in the CHANGELOG. Praxis depends on the published crate and imports the `cmf/constants.rs` names directly, so those stay public and stably named.

**The L7 return half**

- R13. `cmf.http_response` exists, carries `Post` / `ENTITY_HTTP`, and APL installs a handler for it from the same place it installs the request hook.
- R14. The reason both halves exist is recorded at the constants, replacing the comment that argues the post half away on authorization grounds alone.
- R15. PPE defining and routing a hook does not oblige a host to fire it. The host contract for firing `cmf.http_response` is documented, and a host that never fires it behaves exactly as it does today.

---

## Acceptance Examples

- AE1. **Covers R2, R8.** Given `lookup("cmf.http_request")`, the result is `Pre` / `ENTITY_HTTP`, matching what `visitor.rs` installs it under; `lookup("elicit")` is deliberately unphased.
- AE2. **Covers R1, R6.** Given a hook added to the authority, the derived enumeration contains it with no second edit; given a hook removed, it disappears from the enumeration.
- AE3. **Covers R4.** Given a plugin declaring `hooks: [tool_pre_invoke]`, config load fails, names the plugin, and suggests `cmf.tool_pre_invoke`.
- AE4. **Covers R5.** Given a host that registers its own hook and a plugin declaring it, config load succeeds.
- AE5. **Covers R7.** Given a name absent from the table, a consumer can tell it is unregistered rather than deliberately unphased, and the three deliberately unphased hooks still report as such.
- AE6. **Covers R8.** Given a new hook added to the constants and installed by the dispatcher but not added to the authority, a test fails and names it.
- AE7. **Covers R9, R11.** Given the removals, the workspace builds, no replacement enumeration is hand-maintained, and no documentation example references a removed name.
- AE8. **Covers R13, R15.** Given an L7 request through a host that fires both halves, a post-phase handler runs; given a host that fires only the request half, behavior is unchanged from today.

---

## Success Criteria

- A maintainer adding a hook edits one table and a test catches anything they missed.
- A plugin author with a typo in `hooks:` learns at config load, not by wondering why the plugin never fired.
- Nothing in the tree or its documentation reports a hook that does not exist.
- The assertions direction gate resolves every dispatched hook without special-casing any of them.

---

## Scope Boundaries

- Praxis firing the LLM hooks or `cmf.http_response`. PPE defines and routes; the host decides. Tracked separately, see below.
- Adding, renaming, or removing any dispatched hook beyond `cmf.http_response`.
- The assertions feature itself. This work removes an obstacle in its path and is otherwise independent.
- Migrating the legacy typed-payload family. There is nothing to migrate: the payload types the constants were named for do not exist in the tree.

### Tracked elsewhere

- **Praxis is incomplete on the LLM path.** It imports seven CMF constants; PPE defines nine. `cmf.llm_input` and `cmf.llm_output` are referenced nowhere in praxis, so an APL `llm:` route compiles, installs a handler, and never evaluates. That is a host gap, not a reason to drop the hooks, and it needs a praxis-side issue.
- **Praxis will need to fire `cmf.http_response`** for the L7 return half to do anything, which is the same praxis-side conversation.

---

## Key Decisions

- **Derive and consume, rather than delete.** An earlier draft removed `builtin_hook_types()` and `hook_type_from_str()` on the grounds that nothing calls them. That mistook the symptom for the disease: unused is *why* the list rotted, and deleting it leaves the drift class open for the next parallel list. Deriving it from the authority makes divergence unrepresentable, and pointing the plugin-config validator at it means a wrong entry fails a test. The enumeration is needed anyway, since R8's agreement test has to iterate something.

- **`Unphased` must stop meaning two things.** Conflating "no phase" with "not registered" is what let `cmf.http_request` look deliberate for as long as it did. Separating them is the smallest change that stops the next phase-reading consumer repeating the assertions gate's mistake, and it is worth more than the single entry it would have caught.

- **Drop the six legacy CMF counterparts; keep identity and delegation.** The six shadow hooks that exist under `cmf.*` names, and nothing dispatches them, so they can only mislead — as the `plugin.rs` example proves. Identity, delegation and elicit are live hooks and stay. What goes for those is the *duplicate spelling*, not the hook.

- **Add `cmf.http_response`.** The existing comment's reasoning is right and incomplete: authorization has nothing to decide after the fact, but response filtering does, and the L7 path is the one with no entity hook to fall back on. Every other CMF family has both halves; this exception was argued from a single use case that is no longer the only one. The cost is one constant, one entry, one `install_handler` call, and a host free to ignore it.
