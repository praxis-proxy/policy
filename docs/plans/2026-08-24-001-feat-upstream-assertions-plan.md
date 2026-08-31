---
title: "feat: Assertions config for what reaches upstream as request headers"
type: feat
status: draft
date: 2026-08-24
origin: docs/brainstorms/2026-08-23-upstream-header-projection-requirements.md
---

# feat: Assertions config for what reaches upstream as request headers

## Summary

Add an `assertions:` block to the unified config, beside `authentication:`, holding a
`request:` and a `response:` contract. The request contract renders engine-derived state
onto the upstream request as headers and removes the client-supplied headers that would
collide with it. The response contract removes what an upstream should not be telling the
client and adds what it should. Sources are slot paths resolved against `Extensions`; a set
fixed in code makes credentials and wire headers unusable as sources in either direction.
The engine applies each result by replacing the corresponding `HttpExtension` header map
wholesale, which is what makes strip-and-inject atomic and what lets this ship without a
coordinated praxis change.

The two directions do not share semantics. Request is an allowlist; response is a denylist
over a protocol floor fixed in code (D7).

Two things carry most of the risk. `PolicyEngine::invoke` has early returns that bypass the
executor entirely, and an always-on security control must fire on those paths too. And the
call sites cannot currently name the hook they are dispatching, so nothing there can resolve
a direction at all. U7 exists mostly to close both.

---

## Implementation Guidelines

These govern what ships in the repository, not what this document says about it.

**1. No requirement or plan identifiers in durable text.** Nothing that ships may cite
`R7`, `U3`, `AE5`, or any identifier from this plan or its origin. That covers rustdoc,
comments, commit messages, the CHANGELOG entry, test names, and the PR description.
Describe the behavior instead:

```
no    // Enforces R7: credential slots are never projectable.
yes   // Credential slots are unusable as sources: a config naming one
      // fails to load, so there is no request-time path to check.
```

This is `CONTRIBUTING.md`'s rule.

**2. Keep comments and rustdoc short.** One or two sentences per item. No em dashes; use
a comma, a colon, or a second sentence. No restating the signature in prose. Rationale
earns its place where the code looks wrong without it — in this work that is the
unconditional strip (U6) and the early-return call sites (U7), and little else.
`missing_docs` and `missing_errors_doc` are denied workspace-wide, so every public item
needs a doc line; meeting the lint is not a reason to pad it.

**3. Commits.** `git commit -s` on every commit. No AI attribution trailers. Conventional
commit style, imperative subject, body only when the reason is not obvious from the diff.

**4. Reject unknown keys.** Every config struct added here carries
`#[serde(deny_unknown_fields)]`. PR #31 shipped this as a breaking change after a
misspelled `audiences` silently disabled audience checking. A misspelled header name here
silently disables a projection, which is the same class of failure.

---

## Problem Frame

PPE validates tokens, maps claims into typed identity, mints delegated credentials, and
accumulates labels. None of it reaches the upstream request, because nothing renders
engine state onto the wire. Praxis PR #954 closed the gap by encoding the safe shape in a
Rust type plus a filter to read it, which puts the policy somewhere an operator cannot
audit and needs a new type per consumer.

Capability gating answers a different question. `Capability` and the `build_filtered_*`
functions govern what a plugin may read from the extensions tree; nothing governs what is
emitted. See origin for the full framing.

---

## Requirements

Restated from origin. Cited by unit below.

- R1. The block is `assertions:`, beside `authentication:` at global, group, and route level, holding `request:` and `response:`, each a contract with `headers:` and `strip:`.
- R2. An entry under `headers:` names its target header and takes either one source or a set of named members, never both.
- R3. Sources are slot paths; the engine maps each to the capability gating that slot.
- R4. A claim source names one claim; a bare claim root is not a valid source.
- R5. A source naming no addressable slot fails at config load, naming the path and its direction.
- R6. A closed set fixed in code is never usable as a source in either direction: raw inbound tokens, delegated tokens, inbound request headers, upstream response headers. No config surface; naming one fails at load with a message distinct from an unaddressable path.
- R7. Only what a request entry names reaches upstream.
- R8. A response header no `strip:` entry names passes through to the client unchanged. The response direction is a denylist.
- R9. A protocol floor fixed in code cannot be removed by a response `strip:` entry; naming one fails at config load.
- R10. A members entry renders one JSON object; values keep the JSON shape of their sources.
- R11. A structured source renders as its JSON value, not a JSON string holding serialized text.
- R12. Collection-valued sources render in a stable order.
- R13. A collection-valued source targeted at a single-value header fails at config load unless the entry declares how it encodes.
- R14. A rendered value containing CR or LF is not emitted.
- R15. A source resolving to nothing omits its header. Default.
- R16. An entry may instead deny the request, under the claim map's spelling and denial code family.
- R17. Omission never leaves a header from the wire in place.
- R18. Every header an entry targets is removed from the corresponding wire map before injection, unconditionally: the client's request in the request direction, the upstream's response in the response direction.
- R19. `strip:` accepts further header names and glob prefixes.
- R20. Removal and injection are one replacement of the corresponding header map.
- R21. Removal matches header names case-insensitively.
- R22. Direction derives from the hook's registered phase: pre applies `request:`, post applies `response:`, unphased applies neither.
- R23. Removal and injection happen after that phase's policy evaluation; policy reads wire headers unchanged.
- R24. On an already-denied pipeline, request removal happens and injection does not; R16 is not evaluated. The response direction does not run at all.
- R25. A direction's contract is whole; contracts never merge. Global, group, and route may each declare one, resolved per direction, most specific present in force. A route joining two groups declaring the same direction fails at config load.
- R26. R6, R9, and R18 hold at every level.
- R27. The engine renders the effective policy as one artifact covering both directions, the source exclusions, the response floor, the removal sets, and the phase each direction fires on.
- R28. With no `assertions:` block, nothing is asserted and nothing is removed in either direction.

---

## Context & Research

### The integration points, verified against the tree

| Concern | Location | Note |
|---|---|---|
| Route matching by entity | `crates/ppe-core/src/config.rs:1051` `find_matching_route` | Specificity + scope. Private; U4 reuses it in-module. |
| Per-hook route config resolution | `crates/ppe-core/src/config.rs:952` `resolve_identity_plugins_for_route` | Structural template for U4, but it stacks its layers where U4 selects one. |
| Pipeline entry points | `engine.rs:1070` `invoke`, `:1143` `invoke_named`, `:1231` `invoke_entries` | All return `(PipelineResult, BackgroundTasks)`. |
| Executor | `executor.rs:298` `execute` | Returns `PipelineResult::allowed_with(...)`. |
| Result shape | `executor.rs:77` `PipelineResult`, `:134` `allowed_with`, `:160` `denied` | `denied` takes violation + extensions + ctx table. |
| Wholesale header replace | `extensions/container.rs:313-329` `merge_http` | Assigns `request_headers` and `response_headers` outright. This is why R20 is achievable. |
| Header helpers | `extensions/http.rs:125,133` | `remove_header_ci`, `get_header_ci` exist but are bare `fn` under `// -- Internal helpers --`; reusing them from `assertions/apply.rs` requires promoting to `pub(crate)`. Note `remove_header_ci` removes exactly one matching key. |
| Sorted collection rendering | `cmf/view.rs:429-439` | `roles.sort()` / `perms.sort()` / `teams.sort()`. Precedent for R12. |
| Subject sub-field gating | `extensions/filter.rs:480-508` `build_filtered_subject` | Why capability names cannot be the source vocabulary. |
| Credential slots | `extensions/raw_credentials.rs:431,438` | `inbound_tokens`, `delegated_tokens`. |
| Denial code family | `builtins/plugins/identity-jwt/src/resolver.rs:43` | `auth.mapping_failed`. |
| Hook phase authority | `hooks/metadata.rs:221` `BUILTIN_HOOK_METADATA`, read via `:241` `lookup` | Landed in #38. `lookup` returns `Option<HookMetadata>`; `:125` `permissive()` is the opt-in wildcard. |
| How the authority is assembled | `hooks/metadata.rs:167` `HOOK_TABLES` → `concat_hook_tables` | Four per-module slices, each emitted by that module's `define_hooks!`, flattened in const context. A module left out of `HOOK_TABLES` makes every hook it owns unregistered at once. |
| L7 hook pair | `cmf/constants.rs:158` `HOOK_CMF_HTTP_RESPONSE` | Landed in #38 as `ENTITY_HTTP` / `Post`, alongside the request half as `Pre`. |
| Config-load normalization | `engine.rs:294` `normalize_and_validate`, called at `:530`, `:627`, `:782` | Landed in #38. Every load path now merges groups and validates, which U3 hooks into rather than re-plumbing. |
| Violation shape | `error.rs:215` `PluginViolation` | `code`, `reason`, `details`, `proto_error_code`. |
| Fold precedent | `ppe-apl-runtime/src/candidate_constraint.rs` | Emitted state folded into a typed extension; called at `route_handler.rs:428`. |

### The early-return hazard

`PolicyEngine::invoke` returns before the executor runs in two cases: no entries
registered for the hook and no route annotations (`engine.rs:1082-1090`), and an empty
entry list after route filtering (`engine.rs:1096-1101`). `invoke_named` and
`invoke_entries` have their own equivalents.

Every one of those paths currently returns the caller's `Extensions` untouched. A
deployment whose route has no plugins on the request hook would therefore skip stripping
entirely, and a client-supplied `x-auth-user-id` would reach the upstream. This is the
single most likely way to ship this feature broken, because every one of those paths is
an *absence* of code rather than a wrong line.

### Groups participate, by selection rather than stacking

`PolicyGroup` already carries `authentication:` (`config.rs:193-203`), stacked between
global and route by `resolve_identity_plugins_for_route`. Stacking is what R25 forbids;
levels are not. So `assertions:` resolves global, group, route with the most specific
present winning whole, and nothing concatenates.

Groups matter here because several routes fronting one upstream is the ordinary case, and
without a group each of them carries a copy of the same contract.

The one new failure this introduces: a route joining two groups that both declare a block
has two whole contracts and no principled winner. `authentication:` resolves that by
concatenating; a contract cannot survive concatenation, so it is a config-load error.
It is detectable at load because `route_static_tags` (`config.rs:835-842`) reads only
`meta.tags` and the `groups:` sugar, both static — runtime tags do not participate, so
there is no request-time ambiguity.

One consequence: there is no inheritance flag. `authentication:` needs
`replace_inherited` because its layers accumulate. Nothing accumulates here, so there is
nothing to opt out of.

### Idempotence

Strip-then-inject over the same `Extensions` is idempotent: a second application strips
the headers the first injected (they are entry targets) and re-injects identical values.
That makes double-application harmless for correctness. It is not a licence to leave the
firing rule loose, because `on_missing: deny` would evaluate twice and the work is wasted,
but it does mean an ordering mistake degrades to wasted cycles rather than a leak.

---

## Key Technical Decisions

**D1. Apply in `ppe-core`, not in the APL runtime.** The constraint fold lives in
`ppe-apl-runtime` because `restrict` is an APL effect. `assertions:` is engine config and
must hold for hosts that never load APL, so it applies in `PolicyEngine` after the
executor returns. Cost: `ppe-core` grows a rendering module it did not have.

**D2. One shared applier, called at every return point.** Rather than wrapping the three
`invoke*` methods, add a private `fn apply_assertions(&self, snapshot: &RuntimeSnapshot,
hook_name: &str, result: PipelineResult) -> PipelineResult` and call it at every point each
method can return from. The snapshot carries the `PolicyConfig` the block resolves from; the
hook name is what D3's phase lookup turns into a direction.
U7 enumerates them and adds a test per site. A wrapper that only covers the happy path is
the failure mode this decision exists to prevent.

**D3. Direction comes from the hook's registered phase, not from a list of hook names.**
Implemented by [#38](https://github.com/praxis-proxy/policy/pull/38), which this work now depends
on. `hooks/metadata.rs` holds the authority as `HOOK_TABLES`, flattened at compile time from
per-module slices that `define_hooks!` emits alongside each hook's constant, so a hook without a
phase row cannot be declared. `lookup` returns `Option<HookMetadata>`, so an unregistered hook is
distinguishable from a deliberately unphased one.

Read it: a `Pre` hook applies `request:`, a `Post` hook applies `response:`, `Unphased` applies
neither, and `None` applies neither. Identity, delegation and elicit are the `Unphased` set;
mapping them to no contract is correct, since none of them is a wire boundary.

Two earlier drafts of this decision were wrong. The first hardcoded `cmf.tool_pre_invoke` and
`tool_pre_invoke`, missing the CMF prompt, resource and llm hooks. The second claimed the phase
registry already covered everything, when the table was missing `cmf.http_request` and `elicit`
and the legacy names it appeared to cover were never dispatched at all. Both are closed by #38
rather than by anything here.

The residual gap is now small: a host declaring its own hook must register phase metadata for it
(`register_hook_metadata`), and #38 validates declared hook names at config load, so a hook a
plugin names without metadata fails loudly rather than silently getting no contract.

**D4. Sources are slot paths; capabilities are the enforcement mapping.** `subject.roles`,
not `read_roles`. `build_filtered_subject` gates sub-fields individually while
`has_read_access` makes a sub-capability imply the parent, so capability names are not a
tree and cannot express nesting. See origin's Key Decisions.

**D5. Render to strings inside PPE.** `HttpExtension.request_headers` is
`HashMap<String, String>`, so R11's guarantee is about not flattening on the *read* side:
a claim holding `["a"]` renders as the JSON array `["a"]`, distinguishable from a claim
holding the string `"[\"a\"]"`, which renders as `"[\"a\"]"`.

**D6. A missing `http` slot is a no-op, not an error.** Non-HTTP transports have no header
map. The projection skips; `on_missing: deny` does not fire, because the entry was never
going to render anywhere.

**D7. The response direction is a denylist over a protocol floor; the request direction is
an allowlist.** The request direction can default-deny because the engine originates every
value it asserts, so the legitimate set is finite. A response is a passthrough of an
upstream's own output: the engine originates none of it and cannot enumerate what is
legitimate. Default-deny there removes `content-type`, `content-length`, `etag`,
`cache-control`, `retry-after`, rate-limit and tracing headers, and the CORS set, and the
client breaks. So `response.strip:` removes what it names and everything else passes, with a
floor fixed in code that a greedy glob cannot reach (U11). Cost: two mental models in one
block, which U10 has to make legible.

---

## Scope Boundaries

- Response bodies and trailers. The response direction covers headers only.
- Non-HTTP transports.
- Reading identity *from* inbound headers.
- Listener-level prefix reservation (praxis-side).
- A first-class tenant field on `SubjectExtension`.
- Conditional assertion gated on an evaluated predicate.
- An operator-authored exclusion list. Rejected in origin's Key Decisions.

### Deferred to follow-up

- Sources beyond identity (`agent.*`, `labels`, `delegation.*`). The grammar admits them once U1 maps their paths; no entry ships in this work.
- A non-header transport under `assertions:`.

---

## Implementation Units

- U1. **Source path grammar and slot resolution**

**Goal:** A `SourcePath` that parses an authored string into an addressable slot and
resolves it against `&Extensions` to an `Option<serde_json::Value>`.

**Requirements:** R3, R4, R5, R6

**Dependencies:** None

**Files:**
- Create: `crates/ppe-core/src/assertions/source.rs`
- Modify: `crates/ppe-core/src/lib.rs` (declare `assertions` module)

**Approach:**
- Enum over the addressable set rather than free-form traversal: `SubjectId`,
  `SubjectRoles`, `SubjectTeams`, `SubjectPermissions`, `SubjectType`, `Claim(String)`,
  `ClientId`, `ClientRoles`, … Parsing is a match on the authored string, so an
  unaddressable path is rejected by construction rather than by a runtime lookup miss.
- `claim.<name>` captures the remainder as one claim name. Bare `claim` is a distinct
  error from an unknown path (R4 vs R5), with its own message.
- The excluded set is a separate match arm returning a distinct error kind:
  `raw_credentials.*`, `http.request_headers.*`, `http.response_headers.*` and any prefix of
  them. Response headers are excluded for the mirror reason inbound ones are: an upstream
  that controls a response header must not be able to aim it at what the client trusts. The message says the source is never
  usable, not that it is unknown (R6's "distinguishing it from an unaddressable path").
- `fn capability(&self) -> Capability` so the capability model stays the authority (R3).
  Not used for gating in this work — the engine writes canonical state — but it is the
  mapping D4 promises and the artifact in U8 prints it.
- Resolution returns `Value` so structure survives (R11). Collections resolve to
  `Value::Array` with elements sorted (R12) at resolution, not at render, so every caller
  gets the stable order.

**Patterns to follow:** `extensions/filter.rs:480-508` for which sub-fields exist under
each slot; `builtins/plugins/identity-jwt/src/config.rs` `build()` for
`Result<_, String>` errors a caller wraps.

**Test scenarios:**
- Happy: `subject.id` resolves a scalar; `subject.roles` resolves a sorted array; `claim.tenant` resolves a scalar; `claim.realm_access` resolves a nested object with shape intact.
- Happy: Covers R12. `subject.roles` from a `HashSet` populated in two different insertion orders resolves to the same `Value`.
- Happy: Covers R11. A claim holding `["a"]` and a claim holding the string `"[\"a\"]"` resolve to different `Value`s.
- Edge: a source whose slot is absent resolves to `None`, distinct from an empty collection which resolves to `Some(Value::Array([]))`.
- Edge: `claim.` with a trailing dot, and a claim name containing dots, both parse to the claim name verbatim. The claim map's escaping is not re-implemented here; a claim name is taken whole.
- Error: Covers R5. `subject.nonexistent`, `nonsense`, `` all rejected naming the path.
- Error: Covers R4. bare `claim` rejected with the claim-root message, not the unknown-path message.
- Error: Covers R6. `raw_credentials.inbound`, `raw_credentials.delegated`, `raw_credentials`, `http.request_headers.x-user`, `http.request_headers`, `http.response_headers.x-backend`, `http.response_headers` each rejected with the never-usable message; a test asserts the two error kinds are distinguishable.

**Verification:** Every arm of the grammar has a test. The floor test enumerates the
excluded set explicitly so adding a slot without considering it fails.

---

- U2. **Config types**

**Goal:** `AssertionsConfig` deserializing the `assertions:` block, wired into
`GlobalConfig` and `RouteEntry`.

**Requirements:** R1, R2, R13, R15, R16, R19, R25

**Dependencies:** U1

**Files:**
- Create: `crates/ppe-core/src/assertions/config.rs`
- Modify: `crates/ppe-core/src/config.rs` (fields on `GlobalConfig`, `RouteEntry`)

**Approach:**
- `AssertionsConfig { request: Option<DirectionBlock>, response: Option<DirectionBlock> }`,
  with `DirectionBlock { headers: Vec<HeaderEntry>, strip: Vec<String> }` shared by both.
  Direction is the first level so nothing moves when the response half grows.
- `HeaderEntry { name: String, source: EntrySource, on_missing: OnMissing, encode: Option<Encoding> }`
  where `EntrySource` is an untagged enum over `From(SourcePath)` and
  `Members(BTreeMap<String, SourcePath>)`. `BTreeMap` so the rendered JSON object has
  stable key order (R12 extends to object keys, not just arrays).
- R2's "never both" is enforced by the enum: `from:` and `members:` on one entry fail to
  deserialize. A hand-written `Deserialize` is not needed; untagged plus
  `deny_unknown_fields` covers it, but the error message untagged produces is poor, so a
  custom `expecting` is worth the few lines.
- `OnMissing { Omit, Deny }`, default `Omit` (R15). Spelling matches the claim map.
- `#[serde(deny_unknown_fields)]` on every struct here.
- Fields land as `Option<AssertionsConfig>` on `GlobalConfig`, `PolicyGroup`, and
  `RouteEntry`, named `assertions` in Rust and in YAML, so no `rename` is needed.
- No `replace_inherited` flag: nothing accumulates, so there is nothing to opt out of.

**Test scenarios:**
- Happy: the worked config round-trips. Vendor it into the repository first as
  `crates/ppe-core/tests/fixtures/assertions_worked_example.yaml` and point this scenario and
  U9's worked-example scenario at that path. `.sketchpad/` is gitignored (`.gitignore:24`), so a
  fixture read from there fails on any clean checkout and in CI.
- Happy: `on_missing` absent defaults to omit; present as `deny` parses.
- Edge: `assertions:` absent leaves `None` at all three levels (R28); `assertions:` present with only `request:` leaves `response:` as `None`, and the reverse.
- Edge: `headers: []` and `strip: []` parse as empty, distinct from absent.
- Error: an entry with both `from:` and `members:` fails, and the message names the entry's header.
- Error: a misspelled key (`header:`, `form:`, `stip:`) fails rather than being ignored.

---

- U3. **Config-load validation**

**Goal:** Every configuration error surfaces at load, naming what is wrong.

**Requirements:** R5, R6, R9, R13, R25

**Dependencies:** U1, U2

**Files:**
- Modify: `crates/ppe-core/src/assertions/config.rs`
- Modify: `crates/ppe-core/src/engine.rs` (`load_config` / `from_config` call site)

**Approach:**
- `AssertionsConfig::validate(&self) -> Result<(), String>` run over every declared block
  during config load, at all three levels, before any request is served.
- Hook into `validate_config` (`config.rs`), which #38 already reaches from every load path via
  `normalize_and_validate` and which now carries `validate_declared_hooks` as the precedent for
  a name-checking pass. No new plumbing.
- Checks: each source parses (U1 surfaces R5 and R6); a collection-valued source with no
  `encode:` on a single-value entry is rejected (R13); duplicate header names within one
  block are rejected; a header name that is not a valid HTTP field name is rejected.
- Cross-block check: a route whose static tags name two groups that both declare the *same
  direction* is rejected, naming the route, the direction, and both groups (R25). Two groups
  declaring different directions is legal. This runs over the whole `PolicyConfig`, so it is
  a separate function from `validate`.
- Response-only check: a `response.strip:` entry whose literal name or glob would match any
  member of the protocol floor is rejected, naming the floor header it would have removed
  (R9). Checked against the floor constant from U11, so the two cannot drift.
- Errors name the block (global, or the route's matcher) and the header entry, since a
  bare path is not locatable in a large config.
- Members entries do not need `encode:` — a JSON object holds arrays natively (R10).

**Test scenarios:**
- Error: Covers R6. A global block naming `raw_credentials.inbound` fails `load_config`, and the error names both the block and the header.
- Error: Covers R13. `from: subject.roles` on an entry with no `encode:` fails; the same source under `members:` succeeds.
- Error: two entries targeting `x-auth-user-id` in one block fail.
- Error: a route block naming an unaddressable source fails, and the message identifies the route.
- Error: Covers R25. A route joining two groups that each declare a block fails, naming both groups. A route joining two groups where only one declares a block succeeds.
- Happy: a config declaring a valid block at each of the three levels loads, in both directions.
- Error: Covers R9. `response: {strip: ["content-*"]}` fails and names `content-type`; `response: {strip: ["x-backend-*"]}` succeeds.

---

- U4. **Route resolution**

**Goal:** `resolve_assertions_for_route` returning the block in force for a request.

**Requirements:** R25, R26

**Dependencies:** U2

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Signature mirrors `resolve_identity_plugins_for_route(config, entity_type, entity_name,
  request_scope)` plus a `direction` argument, returning `Option<&DirectionBlock>`.
  Resolution runs per direction (R25), so a route stating only `response:` still inherits
  the global `request:`.
- Selection, not stacking (R25). First match wins, most specific first: the matching
  route's own block; else a block on a group the route joins, via `route_static_tags`;
  else the global block; else `None`.
- The two-groups case cannot arise here because U3 rejects it at load. This function may
  therefore take the first group it finds without ordering anxiety, but it asserts the
  invariant in debug rather than relying on a comment.
- Reuses `find_matching_route` and `route_static_tags`, both private to the module — this
  function lives in the same file for that reason.
- **L7 traffic resolves only the global block, in both directions.** `RouteEntry` has four
  selectors, `tool` / `resource` / `prompt` / `llm` (`config.rs:296-308`), and no `http:`, so no
  route can match an L7 request. `find_matching_route` (`:1145-1149`) hits `_ => continue` for
  `ENTITY_HTTP` and returns `None`; `route_static_tags` needs a `&RouteEntry`, so there is no group
  layer either. #38 did not change this. Nothing is silently skipped, because the expression is
  impossible: an operator cannot write a per-HTTP-path contract at all.

  **The consequence runs the other way too, and matters more.** Since L7 falls to global and global
  also covers any entity whose route declares no contract, one `global:` block serves both. A
  contract written for MCP tools also applies to non-MCP HTTP traffic transiting the filter, so
  identity headers are injected and client headers stripped on requests the author was not
  thinking about. The host's `require_protocol_metadata` gate defaults to fail-closed, which bounds
  this to deployments that turned it off or run no entity routes, but it does not remove it.

  Mitigation follows the precedent the host already set for the mirror-image problem: praxis warns
  at startup when a global HTTP policy coexists with entity routes and the gate is off
  (`filter/src/builtins/http/security/policy/filter.rs:206-230`, "make that specific
  misconfiguration loud at startup"). So U3 emits a load-time warning when a global block is
  declared alongside entity routes, naming that L7 traffic will receive the global contract, and
  R27's artifact states per scope which traffic it reaches. Giving routes an `http:` selector would
  close it properly and is a larger change reaching beyond assertions.

**Test scenarios:**
- Happy: no route or group block returns the global block, per direction.
- Happy: a route declaring only `response:` resolves its own response block and the global request block.
- Happy: a route block returns the route's, and neither the group's nor the global block's headers appear.
- Happy: Covers R25. Two routes joining one group both resolve that group's block; a third route joining the group but declaring its own resolves its own.
- Edge: Covers R28. No global and no route block returns `None`.
- Edge: a route matching no entry falls back to global.
- Edge: a generic-HTTP request (`ENTITY_HTTP`) resolves the global block even when a route declares its own, and the test says so explicitly so the limitation is pinned rather than discovered.
- Edge: scope-specific routes resolve the same way `resolve_identity_plugins_for_route` does; one shared test shape.

---

- U5. **Rendering**

**Goal:** A resolved block plus `&Extensions` becomes a set of header name/value pairs, or
a denial.

**Requirements:** R10, R11, R12, R13, R14, R15, R16

**Dependencies:** U1, U2

**Files:**
- Create: `crates/ppe-core/src/assertions/render.rs`

**Approach:**
- `fn render(cfg: &AssertionsConfig, ext: &Extensions) -> Result<Vec<(String, String)>, MissingSource>`.
- Single-source entry: resolve, then render by `encode:` — scalar renders bare, `json`
  renders `serde_json::to_string`, `csv` joins a resolved array. A `Value::String` renders
  as its contents, never as a quoted JSON string, which is the difference R11 turns on.
- Members entry: resolve each member, drop members that resolve to `None`, build a
  `serde_json::Map` in `BTreeMap` order, render as one JSON string. An entry whose members
  all resolve to `None` is itself missing and takes the entry's `on_missing`.
- `MissingSource` carries the header name and the source path so U7 can build a violation
  with useful `details`.
- Header values are validated (R14): a rendered value containing CR or LF is dropped and
  logged rather than emitted. A claim is attacker-influenced data and header splitting is
  the obvious injection.

**Test scenarios:**
- Happy: Covers R10. A members entry renders one JSON object whose keys are in sorted order, matching U2's `BTreeMap`, and whose array values are arrays. Sorted, not authoring, order is the stability guarantee: `serde_json::Map` is `BTreeMap`-backed without `preserve_order`, so authoring order is not recoverable at render time.
- Happy: Covers R11. A structured claim renders as JSON; a string claim whose text looks like JSON renders as that text, and the two are distinguishable.
- Happy: Covers R12. Two renders of the same identity produce byte-identical output, including object key order.
- Edge: Covers R15. A missing source omits its entry and renders nothing for it.
- Edge: A members entry with one missing member renders the object without that key; with all members missing it is treated as missing.
- Edge: An empty collection renders as `[]` under `json`, and as an empty string under `csv`; both are distinct from missing.
- Error: Covers R16. `on_missing: deny` with a missing source returns `MissingSource` naming the header and path.
- Security: Covers R14. A claim value containing `\r\n` produces no header for that entry rather than two headers.

---

- U6. **Strip and inject**

**Goal:** Apply a rendered set to `Extensions`, as one replacement.

**Requirements:** R8, R17, R18, R19, R20, R21, D6

**Dependencies:** U5

**Files:**
- Create: `crates/ppe-core/src/assertions/apply.rs`

**Approach:**
- `fn apply(block: &DirectionBlock, rendered: &[(String, String)], ext: &mut Extensions,
  direction: Direction)`, writing `request_headers` or `response_headers` accordingly.
- Build the new map from the existing one: remove every entry-target name and every `strip:`
  match, then insert the rendered pairs, then assign the target map once. One assignment, so
  there is no intermediate state (R20).
- Response direction inverts the default: entry targets and `strip:` matches are removed and
  *everything else is retained* (R8). The floor is never removable, but U3 already rejected a
  config that would try, so `apply` does not re-check it at request time.
- Removal is case-insensitive (R21), which means iterating and comparing lowercased rather
  than a `HashMap::remove`. `remove_header_ci` in `extensions/http.rs` is the existing
  helper; use it or match its behavior.
- Removal of entry targets is unconditional and does not consult `rendered` (R17, R18).
  This is the line most likely to be "optimized" into `if let Some(value)` later, so it
  gets a comment saying why it must not be.
- `strip:` entries support a trailing `*` glob. Match the globbing used for route entity
  matchers rather than inventing a second dialect.
- `ext.http` is `Option<Arc<HttpExtension>>`: clone the inner, mutate, re-wrap. `None` is
  a no-op (D6).

**Test scenarios:**
- Happy: rendered headers appear; unrelated inbound headers survive untouched.
- Security: Covers R18, R17. A client-supplied value under an entry target is removed when the engine derived no identity at all, so nothing is left behind.
- Security: Covers R19. A client-supplied `x-auth-projects` is removed by the `x-auth-*` glob though no entry targets it.
- Security: Covers R21. `X-Auth-User-Id` inbound is removed by a config written `x-auth-user-id`, and by the `x-auth-*` glob.
- Edge: `Authorization` is untouched by a config that does not name it.
- Edge: Covers D6. `ext.http` of `None` applies nothing and does not panic.
- Edge: applying twice produces the same header map as applying once.
- Response: Covers R8. A response header no entry and no `strip:` names survives untouched.
- Response: Covers R18. An upstream echoing an entry-target name has it replaced by the engine's value, or removed when nothing rendered.

---

- U7. **Engine integration**

**Goal:** The block is applied on every path that returns a `PipelineResult` for the
request-side hook, including the ones that never reach the executor.

**Requirements:** R7, R8, R16, R22, R23, R24, R26, R28

**Dependencies:** U3, U4, U5, U6

**Files:**
- Modify: `crates/ppe-core/src/engine.rs`

**Approach:**
- `fn apply_assertions(&self, snapshot: &RuntimeSnapshot, hook_name: &str, result:
  PipelineResult) -> PipelineResult`, private. Same signature as D2 states. Resolves the block (U4), renders (U5), applies (U6), and converts a
  `MissingSource` into `PipelineResult::denied` with a violation coded in the
  `auth.*` family alongside `auth.mapping_failed`. Proposed code:
  `auth.assertion_missing`. Build it as
  `PipelineResult::denied(violation, extensions, result.context_table).with_errors(result.errors)`
  and carry `result.metadata` across: `denied` constructs with `errors: Vec::new()` and
  `metadata: None` (`executor.rs:160-172`), so a bare call discards every `on_error: ignore`
  plugin error the pipeline just recorded, which is what an operator needs to debug the deny.
- Call it at **every** return point of `invoke` (`engine.rs:1070`), `invoke_named`
  (`:1143`), and `invoke_entries` (`:1231`) — the early return when no entries and no
  annotations exist, the early return after route filtering yields nothing, and the
  executor's own return. Enumerate the sites in the PR description.
- Resolve the hook's phase via `hooks::metadata::lookup`, which returns `Option<HookMetadata>`
  since #38, and map it to a direction (R22, D3): `Pre` applies `request:`, `Post` applies
  `response:`, `Unphased` and `None` apply neither. Skip when the resolved direction block is
  `None` (R28).
- On a pipeline a plugin already denied (R24): in the request direction strip, do not render,
  do not inject, and do not evaluate `on_missing`. Removal costs nothing and is never wrong,
  so it happens even though the request is not forwarded, which keeps client-supplied values
  out of the extensions the audit path sees. Injecting onto a refused request would be
  pointless and could replace one violation with another. The response direction does not run
  at all on a denied pipeline: there is no upstream response to filter.

**Test scenarios:**
- Covers R26, and the early-return hazard. One test per return site, each asserting that a client-supplied entry-target header does not survive:
  - a hook with no registered entries and no route annotations;
  - a hook whose entries all filter out by route;
  - a normal pipeline through the executor;
  - the same three through `invoke_named` and `invoke_entries`.
- Covers R16. A route whose tenant entry is `on_missing: deny` and whose token carries no tenant claim produces a denied result with the expected code, and the header does not appear.
- Covers R28. A config with no block leaves the header map byte-identical to the input.
- Covers R7. A readable slot that no entry names does not appear in the outgoing headers.
- Covers R22. A pre-phase hook applies `request:` and not `response:`; a post-phase hook applies `response:` and not `request:`; an unphased hook applies neither. A host-registered hook with pre-phase metadata applies `request:` with no config change.
- Covers R23. A policy rule reading a target header name observes the client's value, and the upstream still receives only the engine's.
- Covers R24. A pipeline denied by a plugin returns extensions with no client value under any target name, and with no asserted header added.

**Verification:** A reviewer can point at each return site in `engine.rs` and name the
test covering it. If that mapping cannot be stated, the unit is not done.

---

- U8. **Effective-policy artifact**

**Goal:** The engine can render what reaches upstream, without reading Rust.

**Requirements:** R27

**Dependencies:** U1, U2, U4

**Files:**
- Modify: `crates/ppe-core/src/assertions/mod.rs`

**Approach:**
- `fn effective_policy(config: &PolicyConfig) -> String` rendering, per scope (global, each
  group, and each route with its own block): every header that can be emitted with its
  source and capability, the `strip:` set including the implicit entry-target names, the
  code-fixed excluded set with its rationale, the response protocol floor, and the phase each
  direction fires on (R27). Both directions render, labelled, so an operator reads one
  document for the whole boundary.
- Emitted at startup at `info` when a block is configured, and available as a public
  function so a host can expose it.
- The excluded set is printed from the same constant U1 matches on, so the artifact cannot
  drift from what the code enforces. A test asserts every excluded variant appears.

**Test scenarios:**
- The artifact names every configured header and its source.
- The artifact lists entry-target names as stripped even though they are not in `strip:`.
- Covers the anti-drift property: adding a variant to the excluded set without updating the renderer fails a test.
- A config with no block renders a statement that nothing is asserted, not an empty string.

---

- U9. **End-to-end tests**

**Goal:** The properties an operator is promised hold through the real engine.

**Requirements:** R7, R8, R9, R11, R17, R18, R20, R24, R25, R28

**Dependencies:** U7

**Files:**
- Create: `crates/ppe-core/tests/assertions_e2e.rs`

**Approach:** Drive `PolicyEngine` with a loaded config and a populated `Extensions`,
asserting on the header map in the returned `PipelineResult`.

**Test scenarios:**
- Covers the worked example. A request carrying spoofed `x-auth-user-id`, `x-auth-attributes` and `x-auth-projects` reaches the upstream with the engine's values and none of the client's.
- Covers R28 and R7. Under a default config, no JWT, no raw credential, and no delegated token appears in any outgoing header. Assert on the whole header map, not on named absences, so a future source cannot leak past the test.
- Covers R11. A Keycloak-shaped token's nested claim reaches the header as JSON with structure intact.
- Covers R25. Two routes with different blocks each receive exactly their own headers.
- Covers R20. No ordering of plugins in the pipeline exposes a client value; a plugin holding `write_headers` that writes an entry-target name is overwritten, not merged.
- Covers R8, R9. A response carrying a backend banner, `set-cookie`, and `content-type` reaches the client without the first two and with the third intact.
- Covers R18 in the response direction. An upstream echoing `x-auth-attributes` back does not reach the client with the upstream's value.
- Covers R24. A denied pipeline produces no response-direction filtering, because no upstream response exists.

---

- U10. **Documentation and CHANGELOG**

**Requirements:** R27

**Dependencies:** U1–U9

**Files:**
- Modify: `CHANGELOG.md`, `README.md` if the feature list needs a line
- Create: a config reference section wherever `authentication:` is documented

**Approach:** Document the block, the excluded set, and the strip semantics. State plainly
that what crosses the boundary is unsigned and believed on the strength of the network
path, because an operator configuring this needs to know the trust model they are opting
into.

---

- U11. **The response protocol floor**

**Goal:** A code-fixed set of response header names a `strip:` entry can never remove, with
its rationale on the page rather than in someone's head.

**Requirements:** R9

**Dependencies:** None

**Files:**
- Create: `crates/ppe-core/src/assertions/floor.rs`

**Approach:**
- One constant listing the names, each with a one-line reason. The set covers what a client
  needs in order to interpret the response at all: content negotiation and framing
  (`content-type`, `content-length`, `content-encoding`, `transfer-encoding`), caching and
  conditional requests (`cache-control`, `etag`, `last-modified`, `expires`, `vary`),
  retry/flow signalling (`retry-after`), and the CORS response set, without which a browser
  client silently fails.
- `fn is_floor(name: &str) -> bool`, case-insensitive, plus `fn floor_names() -> &[FloorEntry]`
  so U3 can check globs against it and U8 can print it.
- Glob checking is the floor's job, not U3's: `fn glob_would_match_floor(pattern: &str) ->
  Option<&'static str>` returns the first floor name a pattern would hit, so U3's error can
  name it.
- Deliberately *not* included: `set-cookie` (removing it on the gateway domain is a stated
  use case), `server` and `x-powered-by` (banners an operator should be able to strip), and
  anything vendor-specific.

**Patterns to follow:** the excluded-source set in U1 — same shape, same anti-drift
requirement, opposite polarity.

**Test scenarios:**
- Happy: every name in the floor is matched case-insensitively.
- Happy: a glob matching a floor name returns that name; a glob matching nothing in the floor returns `None`.
- Edge: `set-cookie`, `server`, `x-powered-by` are NOT in the floor, so an operator can strip them.
- Covers the anti-drift property: a test asserts every floor entry carries a non-empty reason, so an addition cannot land undocumented.

**Verification:** The floor's contents are reviewable as a list with reasons. Adding a name is
a visible change with a stated justification, not a silent widening.

---

## Unit Dependency Graph

```
U1  (source paths) ──┬── U2 (config types) ──┬── U3 (validation) ──┐
                     │                       ├── U4 (resolution) ──┤
                     ├── U5 (rendering) ──────┴── U6 (apply) ──────┴── U7 (engine) ── U9 (e2e)
                     └── U8 (artifact)                                              └── U10 (docs)

U11 (response floor) ──> U3 (glob rejection), U8 (artifact renders it)
```

U1 and U11 have no dependency and can start in parallel. U2 depends on U1. U7 is the
integration point and cannot start until U3–U6 land.

---

## System-Wide Impact

- **`ppe-core` public API grows**: a new `assertions` module, new fields on `GlobalConfig`, `PolicyGroup`, and `RouteEntry`. All are `Option`, so existing configs are unaffected, but the struct change is a semver event under the project's 0.1.x policy.
- **Config load can now fail** for reasons it could not before. A deployment with a malformed block that previously would have been ignored now refuses to start. That is the intent (R5, R6) and belongs in the CHANGELOG as a behavior change.
- **No plugin API change.** Capabilities, write tokens, and `merge_http` are untouched.
- **No praxis change.** Header mutations already flow back through `PipelineResult`, and `merge_http` assigns `response_headers` alongside `request_headers`.
- **The engine now writes `response_headers`.** A deployment that adds a `response:` block changes what its clients receive, which is a client-visible behavior change and belongs in the CHANGELOG with the floor's contents.
- **Coverage gate**: `make coverage` is at 95%. New modules need tests to match or the gate fails.

---

## Risks & Dependencies

| Risk | Mitigation |
|---|---|
| A return site in `engine.rs` is missed and stripping silently does not happen. | U7's per-site tests, and the reviewer check that each site maps to a named test. This is the highest-severity risk in the work: it fails open. |
| A host declares its own hook without registering phase metadata, so neither contract fires for it. | Largely closed by #38: the host registers metadata via `register_hook_metadata`, and a hook a plugin declares without metadata now fails at config load. Residual: a hook installed in Rust and never named in config still reads as `None`, which maps to no contract. U8's artifact prints the phase per hook so the gap is visible. |
| A claim value injects CRLF and splits a header. | U5 validates rendered values, under R14. |
| `HashSet` iteration order leaks into headers. | Sorting happens at resolution in U1, not at each render site, so a new caller cannot forget it. |
| Route resolution semantics drift from `authentication:`. | U4 mirrors `resolve_identity_plugins_for_route` structurally and shares its test shapes. The one deliberate divergence, selection instead of stacking, is documented in Context so it does not read as an oversight. |
| A route joins two groups that both declare the same direction, and one silently wins. | U3 rejects it at load; U4 asserts the invariant rather than trusting it. Detectable only because group membership is static. |
| A greedy `response.strip:` glob removes a header the client needs. | U11's floor plus U3's load-time rejection, which names the floor header the glob would have hit. Fails at load, not in production. |
| The floor is incomplete and a client-critical header stays strippable. | The floor is an enumerated list with a reason per entry and a test that every entry has one. Residual: a header nobody thought of is strippable until someone adds it. This is the response direction's analogue of the excluded-source set, and carries the same standing review obligation. |
| Two mental models in one config block confuse operators into expecting response default-deny. | D7 states the asymmetry, U8's artifact renders both directions labelled, and U10 documents it. Residual: this is a real cognitive cost, accepted because the alternative breaks clients. |

---

## Open Questions

### Resolved during planning

- **Where the projection is applied.** `ppe-core` after the executor, not the APL runtime (D1), because the block is engine config and must hold for hosts without APL.
- **Whether groups contribute.** Yes, by selection. R25 forbids merging, not levels, so global, group, and route each declare a whole contract and the most specific present wins. A route joining two groups that both declare one is a config-load error, since concatenation is what a contract cannot survive.
- **Whether double application is harmful.** No. Strip-then-inject is idempotent over the same extensions.

### Settled 2026-08-24

- **Does policy see inbound headers before removal?** Yes. Removal happens after the policy phase, so existing rules keep working and an author can deny a request that arrived carrying a target header name at all. The accepted cost is that a value under `http.request_headers.x-auth-user-id` looks authoritative and is not. Stripping earlier would close that but make spoof-detection impossible and silently change what existing policies see. R23.
- **Which hooks are request-side?** `cmf.tool_pre_invoke` and `tool_pre_invoke`. See D3, including the open-hook-types gap it does not close.
- **An already-denied pipeline** — strip, do not inject, do not evaluate `on_missing`. R24.
- **A route block without `replace_inherited: true`** — moot. The flag does not exist, because selection replaced stacking.

### Raised by review 2026-08-24, still open

- **Layering default.** Review argues additive-with-opt-out is right, matching `authentication:`'s default, on the grounds that a union of allowlists can only weaken the global floor and so cannot be used to widen it. R25 currently says contracts never merge. The counter-argument is that a merged header set is one nobody designed. Unresolved; it interacts with the finding that `strip:` is silently dropped when a lower level declares a block.
- **Delegated-token collision.** Undefined today, and more pressing now that a contract entry and the delegated-token writer share a fold point. Who wins when both target the same header name.
- **Response-direction sources.** Whether a response entry may read response-phase state at all, beyond the identity state a request entry reads. Excluded for now by R6, which forbids `http.response_headers.*`; nothing yet needs more.
- **Duplicate inbound headers.** `HttpExtension` is `HashMap<String, String>`, so duplicate wire headers collapse and repeated names cannot be emitted. Probably acceptable; needs stating rather than deciding.
- **Failure modes beyond absence.** `on_missing` covers a source that resolved to nothing. It does not cover a source that errored, or a value rejected by R14. Both currently fall to "omit", which may want to be configurable.

### Deferred to implementation

- Whether `csv` is worth shipping, or whether `json` plus members covers every real case. R13 requires *an* encoding declaration, not specifically this set.
- Whether `effective_policy` should render structured output rather than text.

---

## Sources & References

- Origin requirements: `docs/brainstorms/2026-08-23-upstream-header-projection-requirements.md`
- **Depends on** [#38](https://github.com/praxis-proxy/policy/pull/38) (issue [#37](https://github.com/praxis-proxy/policy/issues/37)), which lands the hook phase authority D3 reads, the `cmf.http_response` hook the response direction fires on, and validation on every config-load path. Not yet merged to `main`.
- Tracking issue: praxis-proxy/policy#28
- Dependencies already landed: policy#9 (claim JSON shape), policy#31 (configurable claim map)
- Upstream framing: praxis-proxy/praxis#954 and its review thread
- Worked config: `.sketchpad/headers_config.yaml` (gitignored; U2 vendors it to `crates/ppe-core/tests/fixtures/assertions_worked_example.yaml` for use as a fixture)
