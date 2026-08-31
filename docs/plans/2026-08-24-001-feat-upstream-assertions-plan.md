---
title: "feat: Assertions config for what reaches upstream as request and response headers"
type: feat
status: draft
date: 2026-08-24
revised: 2026-08-31
origin: docs/brainstorms/2026-08-23-upstream-header-projection-requirements.md
---

# feat: Assertions config for what reaches upstream as request and response headers

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
over a protocol floor fixed in code (D7). Both accumulate across four config levels the way
`authentication:` does, with `replace_inherited` to opt out (D10).

Three things carry most of the risk.

`PolicyEngine` has **four** pipeline entry points with **fourteen** return points between
them, and an always-on security control must fire on all of them (U7). Three of the four are
boundaries and carry a hook name; `invoke_entries` is a nested dispatch primitive and
deliberately applies nothing (D8).

A contract on an `http:` route is reachable only when the host supplies the request line at
that invocation, and a response invocation is where a host is most likely not to. Silent
degradation to the global contract is the failure mode, and U12 exists to make it loud.

And the config model now has four inheritance levels and a closed key table per scope, so
adding a block is a change to the key model rather than one struct (D9, U2), and a route's
contract is a merge of up to four of them (D10, U4).

**Revised 2026-08-30.** This plan was written against a tree that has since moved three
times. Every line reference below is re-verified against the current checkout.

| Landed | What it changed here |
|---|---|
| [#38](https://github.com/praxis-proxy/policy/pull/38) | The hook phase authority D3 reads. Merged; no longer a pending dependency. |
| [#42](https://github.com/praxis-proxy/policy/pull/42) | `http:` route selector and an `http.*` hook family. U4's "L7 resolves only global" limitation is gone; the reachability hazard U12 covers replaces it. `cmf.http_request` / `cmf.http_response` no longer exist. |
| [#55](https://github.com/praxis-proxy/policy/pull/55) | Four inheritance levels, `ConfigKey` tables per scope, `resolve_route` replacing `find_matching_route`, `invoke_by_name` as a fourth entry point, `dispatch: policy` as the default. |

Separately, and not driven by a merge: **layering is now additive** (D10), reversing this plan's
original position after the first worked config demonstrated that selection loses inherited
`strip:` entries in practice. R25, R26 and R33 to R35 carry it; U2 to U4, U8 and U9 change with
it.

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
earns its place where the code looks wrong without it: in this work that is the
unconditional strip (U6), the fourteen return sites (U7), and the two entry points that
apply nothing (D8). `missing_docs` and `missing_errors_doc` are denied workspace-wide, so
every public item needs a doc line; meeting the lint is not a reason to pad it.

**3. Commits.** `git commit -s` on every commit. No AI attribution trailers. Conventional
commit style, imperative subject, body only when the reason is not obvious from the diff.

**4. Register every new key in the key model, not only on the struct.** #55 replaced
per-struct field rejection with a closed table per config scope (`ConfigScope`,
`config.rs:1279`). A key absent from its scope's table is a load error naming what the scope
accepts, which is stronger than `deny_unknown_fields` and is where an operator's typo is
actually caught. So `assertions` needs a `structural_key("assertions", KeyOwner::Core)` row
in `GLOBAL_STRUCTURAL_KEYS`, `BUNDLE_STRUCTURAL_KEYS` and `ROUTE_STRUCTURAL_KEYS`, and the
blocks nested under it need `ConfigScope` variants of their own with tables to match.
`#[serde(deny_unknown_fields)]` still goes on every struct as the second line of defence;
it is no longer the first. `crates/ppe-core/tests/config_key_sets.rs` is the test that walks
the whole model and must grow with it.

The reason this matters is the one PR #31 shipped: a misspelled `audiences` silently
disabled audience checking. A misspelled header name here silently disables a projection.

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

- R1. The block is `assertions:`, beside `authentication:` at all four levels (`global:`, `global.defaults.<entity>:`, `groups.<name>:`, a `routes[]` entry), holding `request:` and `response:`, each a contract with `headers:` and `strip:`.
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
- R18. Every header an entry targets is removed from the corresponding wire map before injection, unconditionally.
- R19. `strip:` accepts further header names and glob prefixes.
- R20. Removal and injection are one replacement of the corresponding header map.
- R21. Removal matches header names case-insensitively.
- R22. Direction derives from the hook's registered phase: pre applies `request:`, post applies `response:`, unphased applies neither. Covers the MCP entity hooks and the generic-HTTP pair without naming either.
- R23. Removal and injection happen after that phase's policy evaluation; policy reads wire headers unchanged.
- R24. On an already-denied pipeline, request removal happens and injection does not; R16 is not evaluated. The response direction does not run at all.
- R25. A direction's contract accumulates across four levels: global, entity default, each bundle, then route. `headers:` unions by target header name, most specific wins for a repeated name; `strip:` unions. `replace_inherited: true` drops what accumulated before that level. Per direction.
- R26. R6, R9, R18 and R32 hold at every level, and `replace_inherited` cannot reach any of them.
- R33. Accumulation is per header entry, never inside one. A repeated header name replaces that entry whole, members and `on_missing` included.
- R34. Two bundles naming the same target header in the same direction fail at config load, naming route, direction, header and both bundles. Different headers union.
- R35. A level above the route that drops inherited content is reported once per affected route at load. A route's own flag is not reported.
- R27. The engine renders the effective policy as one artifact covering both directions, the source exclusions, the response floor, the removal sets, the phase each direction fires on, the dispatch paths R31 leaves uncovered, and per level which traffic that level reaches.
- R28. With no `assertions:` block, nothing is asserted and nothing is removed in either direction.
- R29. A contract on an `http:` route is in force only when the host supplies the request line on the HTTP extension at that invocation. Absent it, the global contract governs, and the engine reports once, naming the routes.
- R30. Both halves of one HTTP exchange resolve their contract from the request line. A response invocation with no request line falls to the global `response:`, reported under R29.
- R31. A nested dispatch primitive is not a boundary and applies neither contract; the artifact names which entry points are boundaries.
- R32. The request line and response status are not addressable as sources. An entry naming one fails under R5, not R6.

---

## Context & Research

### The integration points, verified against the tree at `75e33fd`

| Concern | Location | Note |
|---|---|---|
| Route matching | `config.rs:3064` `resolve_route`, `:3097` `score_route_match` | Replaces the private `find_matching_route`. **Public**, and takes a `RouteQuery`. Matches `ENTITY_HTTP` in its own arm. |
| Route query / result | `config.rs:2721` `RouteQuery`, `:2733` `named`, `:2745` `http`, `:2757` `with_scope`; `:2763` `MatchedRoute` | `MatchedRoute` carries the route and the selector name it resolved under. |
| Per-hook route config resolution | `config.rs:2942` `resolve_identity_plugins_for_route` | Now takes `Option<&MatchedRoute>` rather than matching internally. This is U4's signature template, and better than the old one: the caller matches once. It stacks its layers where U4 selects one. |
| The four inheritance levels | `config.rs:2863` `authentication_layers`, `:2819` `AuthenticationSource` | `Global`, `EntityDefault(entity)`, `Bundle(tag)`, `Route`, in stacking order. `label()` at `:2834` is how a diagnostic names each. |
| Bundle membership | `config.rs:2546` `route_static_tags` (private), `:2568` `route_bundle_names` (public, deduped) | `meta.tags` then `groups:`, declaration order. Order is load-bearing. |
| Route identity | `config.rs:2584` `route_entity_identity` | The one mapping from a route to the names it is known by. Precedence tool, resource, prompt, llm, http. |
| Config scopes and key tables | `config.rs:1279` `ConfigScope`, `:1306` `ALL`, `:1194`-`:1245` the tables | Where guideline 4's rows go. `ConfigScope::keys()` at `:1339` composes structural + APL terms + field stages + wiring. |
| Config-load validation | `config.rs:2170` `validate_config`, `:2109` `validate_declared_hooks`, `:2137` `reject_reserved_route_names` | U3 hooks in here. `validate_declared_hooks` is the precedent for a name-checking pass. |
| Load-time findings, reported not fatal | `config.rs:2335` `http_routing_gaps` | Returns `Vec<String>`; the engine emits them once per load. Exactly U12's shape, and its test shape: assert on the finding, not on a log line. |
| Runtime warn-once precedent | `engine.rs:2148` `warn_once_if_route_authentication_is_unreachable` | Fires when an `http:` route declares `authentication:` and the request carries no readable path. R29 is the same problem for a contract; U12 follows this. |
| Snapshot-derived route facts | `engine.rs:142` `http_routes_declaring_authentication`, held at `:310` | Computed once at snapshot build so the hot path reads an answer. U12's equivalent list is derived the same way. |
| Pipeline entry points | `engine.rs:1432` `invoke_by_name`, `:1528` `invoke`, `:1616` `invoke_named`, `:1723` `invoke_entries` | Four, not three. All return `(PipelineResult, BackgroundTasks)`. |
| Route filtering | `engine.rs:1853` `filter_entries_by_route` | Where the HTTP request line is read and `resolve_route` is called. Runs *after* the first early return in each entry point. |
| Executor | `executor.rs:298` `execute` | Returns `PipelineResult::allowed_with(...)`. |
| Result shape | `executor.rs:77` `PipelineResult`, `:134` `allowed_with`, `:160` `denied` | `denied` takes violation + extensions + ctx table, and constructs with `errors: Vec::new()` / `metadata: None`. |
| Wholesale header replace | `extensions/container.rs:346` `merge_http` | Assigns `request_headers` and `response_headers` outright, which is why R20 is achievable. Now takes `Guarded<HttpExtension>` + `Option<&WriteToken>`, and preserves the request line and `status` from canonical. |
| HTTP slot shape | `extensions/http.rs:22` `HttpExtension` | Gained `status`, `method`, `path`, `host`, `scheme`. R32 is about these. |
| Header helpers | `extensions/http.rs:133` `get_header_ci`, `:141` `remove_header_ci` | Still bare `fn` under `// -- Internal helpers --`; reuse from `assertions/apply.rs` requires promoting to `pub(crate)`. `remove_header_ci` removes exactly one matching key. |
| Glob dialect | `config.rs:604` `Pattern` (wildmatch) | What route entity matchers use. `http:` deliberately does *not*, matching by equality or segment prefix instead. U6 uses `Pattern`, since `strip:` matches header names and not paths. |
| Sorted collection rendering | `cmf/view.rs:441,446,451` | `roles.sort()` / `perms.sort()` / `teams.sort()`. Precedent for R12. |
| Subject shape | `extensions/security.rs:31` `SubjectExtension`, `:74` `claim_str` | Unchanged. `claim_str` returns `None` for objects and arrays, which is the scalar/structured split U5 needs. |
| Subject sub-field gating | `extensions/filter.rs:500` `build_filtered_subject` | Why capability names cannot be the source vocabulary. |
| Capabilities | `extensions/tiers.rs` `Capability` | `ReadSubject`, `ReadRoles`, `ReadTeams`, `ReadClaims`, `ReadPermissions`, `ReadHeaders`, `WriteHeaders`, `ReadInboundCredentials`, `ReadDelegatedTokens`. |
| Credential slots | `extensions/raw_credentials.rs:431` `inbound_tokens`, `:438` `delegated_tokens` | R6's first two exclusions. |
| Denial code family | `builtins/plugins/identity-jwt/src/resolver.rs:825` | `auth.mapping_failed`. |
| Hook phase authority | `hooks/metadata.rs:187` `HOOK_TABLES`, `:241` `BUILTIN_HOOK_METADATA`, read via `:262` `lookup` | Landed in #38. `lookup` returns `Option<HookMetadata>`; `:144` `permissive()` is the opt-in wildcard. Thirteen rows. |
| How the authority is assembled | `hooks/metadata.rs:187` `HOOK_TABLES` → `:217` `concat_hook_tables` | Five per-module slices now (`CMF`, `HTTP`, `IDENTITY`, `DELEGATION`, `ELICITATION`), flattened in const context. A module left out unregisters every hook it owns at once. |
| Generic-HTTP hook pair | `http_hook.rs` `HOOK_HTTP_REQUEST` = `"http.request"` (`Pre`), `HOOK_HTTP_RESPONSE` = `"http.response"` (`Post`) | Landed in #42, in a family of their own with `HttpHook` / `HttpPayload`. The `cmf.http_*` names this plan used to cite are gone. |
| HTTP route selector | `config.rs:373` `RouteEntry.http`, `:710` `HttpSelector`, `:721` `HttpMatch` | Three shapes: exact path, list of exact paths, `{path_prefix|path, method}`. Equality or segment-boundary prefix, never glob. |
| Config-load normalization | `engine.rs:439` `normalize_and_validate`, called at `:816`, `:974`, `:1109` | Landed in #38. Every load path merges, folds bundles, and validates. U3 and U12 hook in rather than re-plumbing. |
| Violation shape | `error.rs:215` `PluginViolation` | `code`, `reason`, `details`, `proto_error_code`. |
| Fold precedent | `ppe-apl-runtime/src/candidate_constraint.rs`, called at `route_handler.rs:551` and folded at `:681` | Emitted state folded into a typed extension. |
| Key-model test | `crates/ppe-core/tests/config_key_sets.rs` | Walks `ConfigScope::ALL`. Guideline 4's gate. |

### The early-return hazard, restated for four entry points

Every entry point returns before the executor on at least one path, and every one of those
paths currently returns the caller's `Extensions` untouched.

| Entry point | Return sites |
|---|---|
| `invoke_by_name` (`:1432`) | `:1451` no entries and no annotations; `:1467` route resolution failed, denied; `:1479` entry list empty after filtering; tail `executor.execute` |
| `invoke` (`:1528`) | `:1543`, `:1555`, `:1568`, tail |
| `invoke_named` (`:1616`) | `:1639`, `:1651`, `:1664`, tail |
| `invoke_entries` (`:1723`) | `:1732` empty entry list; tail |

Fourteen sites. The plan previously named nine across three methods, so three of the new
five are `invoke_by_name`'s and two are the denied-on-route-resolution-failure sites, which
are new in kind: #42 made an unreadable HTTP path a denial rather than a fall-through
(`engine.rs:1894-1901`), and a denial is a return.

A deployment whose route has no plugins on the request hook still skips stripping entirely
on the first site, and a client-supplied `x-auth-user-id` reaches the upstream. This remains
the single most likely way to ship this feature broken, because every one of those paths is
an *absence* of code rather than a wrong line.

### Three entry points are boundaries; one is a nested primitive

`invoke_named` and `invoke_by_name` take `hook_name: &str` outright.

`invoke::<H>` passes `H::NAME`, and for the hook types it is meant to be used with that *is*
a hook name: a single-name type sets `NAME` to the hook constant (`plugin_demo.rs:75`,
`ToolPreInvoke::NAME = "demo.tool_pre_invoke"`, a `Pre` row in the table). A multi-name family
type sets it to the family (`CmfHook` is `"cmf"`), and using `invoke::<CmfHook>` is already a
no-op dispatch, because the registry is keyed by hook name and nothing is registered under
`"cmf"`. So `invoke::<H>` needs no special case: pass `Some(H::NAME)` and let `lookup` be the
discriminator. A family name resolving to no phase is the same failure that makes the
dispatch find no entries.

`invoke_entries::<H>` is the different one, and the difference is not that it lacks a name.
It is that it is not a boundary. Its three non-test callers are all inside the APL runtime:
`cmf_invoker.rs:407` for `run(name)` policy steps, `delegation_invoker.rs:224`
(`token.delegate`, `Unphased`), `elicitation_invoker.rs:111` (`elicit`, `Unphased`). All three
run inside `AplRouteHandler`, which is itself an `AnyHookHandler` (`route_handler.rs:268`) and
therefore executes *inside* the executor, inside an outer `invoke_named`. The contract is
applied once at that outer boundary, after the handler returns.

That ordering is R23, not a convenience. The APL route handler *is* the policy evaluation, so
applying the contract around each nested `run(name)` step would inject asserted headers
mid-evaluation and let a later step read the engine's value where R23 promises it reads the
client's. Applying nothing at a nested dispatch is the correct behavior, not a gap.

The name is available if it were ever wanted: `pick_entry` (`dispatch_plan.rs:96-109`) walks
`entries_by_hook: HashMap<String, HookEntry>` and discards the key at `:108`. `HookEntry`
itself carries no hook name (`registry.rs:200`), so the engine cannot recover one from the
slice; only the caller can. Recorded because the cheap-looking fix is the wrong one.

### Four levels, stacking the way `authentication:` does

`PolicyGroup` (`config.rs:234`) carries `authentication:` and deserializes for two scopes,
`groups.<name>:` and `global.defaults.<entity>:`. `authentication_layers` (`config.rs:2863`)
stacks global, entity default, each bundle, then route, honoring `replace_inherited` at each.
`assertions:` now does the same, so U4 mirrors that function rather than inverting it, and the
two chains share a layer order that cannot drift apart.

Bundles matter because several routes fronting one upstream is the ordinary case. Entity
defaults matter because "every tool route" is the next scope up, and `global.defaults` now
accepts `http` as a key too (`config.rs:2188-2199`), so "every generic-HTTP request" is
expressible without being global.

Top-level `groups:` is folded into `GlobalConfig.bundles` by `fold_groups_into_bundles`
(`config.rs:1023`) at load, so every resolver reads one map. U4 reads `bundles`, not the
document field: after load the document's `groups:` is empty.

Bundles are the one layer with no inherent order, so two bundles naming the same target header
in the same direction is a load error (R34). Different headers union, which makes the check
per-header rather than per-direction. It is detectable at load because `route_static_tags`
reads only `meta.tags` and the `groups:` sugar, both static; runtime tags contribute no
bundle, so there is no request-time ambiguity.

`replace_inherited` is the escape hatch, and R26 bounds what it can reach: operator-authored
`headers:` and `strip:` content, and nothing else. It cannot touch the unconditional removal
of an entry target, the fixed source exclusions, or the response floor. That bound is what
makes the flag safe to offer, since the laundering hole the feature exists to close is not
reachable by any spelling of it.

`dropped_inherited_authentication` (`config.rs:2996`) is the model for R35's report, down to
which drops are worth reporting: a level above the route, because the route's author cannot
see it, and not the route's own flag, because that author wrote it.

### The reachability hazard #42 introduced

This replaces the "L7 resolves only the global block" section, which is obsolete: `RouteEntry`
has an `http:` selector and `resolve_route` matches it.

An HTTP request resolves a route from `extensions.http.path` and `.method`
(`engine.rs:1876-1918`). When the host supplies neither, `routing_config.zip(path)` yields
`None`, `resolved_name` falls to `ENTITY_NAME_GLOBAL`, and the global contract governs.
Nothing errors.

Two properties make that worse than it sounds. The request and the response are separate
invocations, so a host can supply the request line on one and not the other, and a route's
`request:` then pairs with the global `response:` (R30). And `dispatch: policy` is now the
default (`config.rs:91`), so `http:` routes resolve out of the box rather than behind an
opt-in, which widens who can hit this.

The tree already treats exactly this as worth reporting rather than accepting: `http_routing_gaps`
reports at load that declared `http:` routes leave a gap, and
`warn_once_if_route_authentication_is_unreachable` warns at runtime when an `http:` route's
`authentication:` list could not apply for want of a path. U12 follows both.

That the default flipped is worth holding onto, because it is what makes this reachable
rather than opt-in. Five comments in the tree still claimed `dispatch: policy` was not the
default; `871a71f` corrected them, and the `RouteEntry::http` rustdoc among them had read the
worst way round, telling a reader an `http:` route "stays inert until it is set" when such a
route is live as written. Anyone sizing this hazard from the rustdoc before that commit would
have sized it as narrow.

### Idempotence, now load-bearing

Strip-then-inject over the same `Extensions` is idempotent: a second application strips the
headers the first injected (they are entry targets) and re-injects identical values.

This used to be a nice-to-have. It is now doing real work, because an HTTP-transported MCP
tool call fires two `Pre` hooks: `http.request` and `cmf.tool_pre_invoke`. Both apply the
request contract, and the second application is a no-op by construction. It is still not a
licence to leave the firing rule loose, because `on_missing: deny` would evaluate twice and
the work is wasted, but an ordering mistake degrades to wasted cycles rather than a leak.

---

## Key Technical Decisions

**D1. Apply in `ppe-core`, not in the APL runtime.** The constraint fold lives in
`ppe-apl-runtime` because `restrict` is an APL effect. `assertions:` is engine config and
must hold for hosts that never load APL, so it applies in `PolicyEngine` after the
executor returns. Cost: `ppe-core` grows a rendering module it did not have.

**D2. One shared applier, called at every return point.** Rather than wrapping the entry
points, add a private
`fn apply_assertions(&self, snapshot: &RuntimeSnapshot, hook_name: Option<&str>,
matched: Option<&MatchedRoute<'_>>, result: PipelineResult) -> PipelineResult`
and call it at every one of the fourteen sites. The snapshot carries the `PolicyConfig` the
block resolves from; `hook_name` is what D3's phase lookup turns into a direction, and
`None` means D8 applies nothing; `matched` is the route the caller already resolved, or
`None` where it has not resolved one yet.

U7 enumerates the sites and adds a test per site. A wrapper that only covers the happy path
is the failure mode this decision exists to prevent.

`matched` is threaded rather than re-derived because `filter_entries_by_route` already
computes it and the route cache (`engine.rs:343`) caches entry lists, not `MatchedRoute`.
Re-resolving would be a second table walk per request for an answer already in hand. The
first return site in each entry point runs before matching, so it passes `None` and U4
resolves the global contract, which is correct: no route matched there either.

**D3. Direction comes from the hook's registered phase, not from a list of hook names.**
`hooks/metadata.rs` holds the authority as `HOOK_TABLES` (`:187`), flattened at compile time
from five per-module slices that `define_hooks!` emits alongside each hook's constant, so a
hook without a phase row cannot be declared. `lookup` (`:262`) returns
`Option<HookMetadata>`, so an unregistered hook is distinguishable from a deliberately
unphased one.

Read it: a `Pre` hook applies `request:`, a `Post` hook applies `response:`, `Unphased`
applies neither, and `None` applies neither. Identity, delegation and elicit are the
`Unphased` set; mapping them to no contract is correct, since none of them is a wire
boundary.

Three earlier drafts of this decision were wrong, and the third is the argument for the
current one. The first hardcoded `cmf.tool_pre_invoke` and `tool_pre_invoke`, missing the
CMF prompt, resource and llm hooks. The second claimed the phase registry already covered
everything, when the table was missing `cmf.http_request` and `elicit`. The third named
`cmf.http_request` / `cmf.http_response` as the L7 pair; #42 deleted both names and
introduced `http.request` / `http.response` in a family of their own. Reading the phase meant
that landed as a table row and cost this plan nothing, which is precisely the property the
decision was chosen for.

The residual gap is small and is now two gaps. A host declaring its own hook must register
phase metadata for it (`register_hook_metadata`, `:286`), and #38 validates declared hook
names at config load, so a hook a plugin names without metadata fails loudly. The second
gap is D8's, and is not closable by registration.

**D4. Sources are slot paths; capabilities are the enforcement mapping.** `subject.roles`,
not `read_roles`. `build_filtered_subject` gates sub-fields individually while
`has_read_access` makes a sub-capability imply the parent, so capability names are not a
tree and cannot express nesting. See origin's Key Decisions.

**D5. Render to strings inside PPE.** `HttpExtension.request_headers` is
`HashMap<String, String>`, so R11's guarantee is about not flattening on the *read* side:
a claim holding `["a"]` renders as the JSON array `["a"]`, distinguishable from a claim
holding the string `"[\"a\"]"`, which renders as `"[\"a\"]"`. `SubjectExtension::claim_str`
(`extensions/security.rs:74`) already draws the scalar/structured line the renderer needs:
it returns `None` for objects and arrays rather than handing back JSON text.

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

**D8. The contract applies at boundaries, and `invoke_entries` is not one.** An earlier draft
of this decision claimed two entry points could not name their hook and accepted a coverage
hole for both. That was wrong twice over.

`invoke::<H>` needs nothing special. `H::NAME` is a hook name for the single-name hook types
that are the only sound users of it, so it passes `Some(H::NAME)` like the other two named
entry points. A family type resolves no phase and applies nothing, which is correct, because
that call dispatches nothing either.

`invoke_entries` applies nothing because it is a nested dispatch primitive rather than a wire
boundary, and R23 puts the contract after policy evaluation. Every current caller sits inside
`AplRouteHandler`, which the executor runs inside an outer `invoke_named` that does apply the
contract. Applying it again around each nested `run(name)` would contradict R23 by letting a
later step read an asserted header where the client's value is promised, and would evaluate
`on_missing: deny` once per step. So this is a design boundary, not an accepted hole.

Plumbing a hook name through `invoke_entries` was considered and rejected on those grounds
rather than on cost: `pick_entry` already has the name and discards it, so the change is
small, and it would buy a correctness regression.

What remains is narrower and is Decision 1 in the open questions: a host *could* call
`invoke_entries` as its outermost dispatch, and would then have no boundary and no contract.
No current caller does. U8's artifact names which entry points are boundaries so a host
integrating that way can see it, and U7 adds a debug assertion rather than trusting it.

**D9. Adding a key is a change to the key model.** #55 made every config scope carry a closed
table (`ConfigScope::keys()`, `config.rs:1339`), and the tables are the accept set. So U2's
work is three table rows plus new `ConfigScope` variants for the nested blocks, and
`config_key_sets.rs` grows to walk them. The alternative, relying on `deny_unknown_fields`
alone, gives a worse message and skips the model the rest of the config is validated by.
Cost: a new key touches four places instead of one. That is the trade #55 made deliberately.

**D10. Contracts accumulate; a level opts out with a flag it cannot abuse.** Reversed from an
earlier draft that made a contract whole and let the most specific level win. Two fail-open
holes killed it, and the first worked config written against this design walked into one of
them four times out of four: every subordinate contract re-declared the `x-auth-*` glob and
dropped the two enumerated legacy names beside it, so a client-supplied `x-tenant-id` reached
those upstreams. The second hole is that declaring any `request:` block silently escaped a
global `on_missing: deny`, which is how a deliberate tenant floor stops applying to the one
route whose author was thinking about something else.

Additive cannot fail either way, structurally: the excluded set is fixed in code so no level
unions in a credential, only named entries propagate so no unnamed slot joins, and the engine
originates every asserted value so no wire input is in the union. The residual is a header an
upstream does not read.

Three implementation consequences. Merge granularity is the entry, not its contents (R33): a
repeated header name replaces that entry whole, so a members object always has one author and
a four-level composite JSON object cannot arise. Bundles are unordered, so a repeated header
name across two of them is a load error (R34) while different names union. And
`replace_inherited` is bounded by R26 to operator-authored content, which is what makes
offering it safe.

Cost: answering "what does this route assert" spans four levels, so U8 renders provenance per
header rather than only the effective set, and U3 emits R35's drop report. Both have a
precedent to copy in `authentication:`.

---

## Scope Boundaries

- Response bodies and trailers. The response direction covers headers only.
- Non-HTTP transports.
- Reading identity *from* inbound headers.
- Listener-level prefix reservation (praxis-side).
- A first-class tenant field on `SubjectExtension`.
- Conditional assertion gated on an evaluated predicate.
- An operator-authored exclusion list. Rejected in origin's Key Decisions.
- Making the request line addressable as a source (R32).
- Giving `invoke` and `invoke_entries` a hook name (D8).

### Deferred to follow-up

- Sources beyond identity (`agent.*`, `labels`, `delegation.*`). The grammar admits them once U1 maps their paths; no entry ships in this work.
- A non-header transport under `assertions:`.
- Nothing further on the `all` reserved bundle. Under D10 it contributes a layer like any other bundle, so it needs no special rule.

---

## Implementation Units

- U1. **Source path grammar and slot resolution**

**Goal:** A `SourcePath` that parses an authored string into an addressable slot and
resolves it against `&Extensions` to an `Option<serde_json::Value>`.

**Requirements:** R3, R4, R5, R6, R32

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
  that controls a response header must not be able to aim it at what the client trusts. The
  message says the source is never usable, not that it is unknown (R6's "distinguishing it
  from an unaddressable path").
- The request line and status (`http.method`, `http.path`, `http.host`, `http.scheme`,
  `http.status`) fall through to the *unaddressable* arm, not the never-usable one (R32).
  They are host-populated rather than credential-bearing, and admitting them later should be
  a grammar addition rather than a reversal of a security refusal. A test pins which arm each
  lands in, because the `http.` prefix makes it easy to lump them together by accident.
- `fn capability(&self) -> Capability` so the capability model stays the authority (R3),
  mapping to the variants in `extensions/tiers.rs`. Not used for gating in this work, since
  the engine writes canonical state, but it is the mapping D4 promises and U8 prints it.
- Resolution returns `Value` so structure survives (R11). Collections resolve to
  `Value::Array` with elements sorted (R12) at resolution, not at render, so every caller
  gets the stable order.

**Patterns to follow:** `extensions/filter.rs:500` `build_filtered_subject` for which
sub-fields exist under each slot; `extensions/security.rs:74` `claim_str` for the
scalar/structured split; `builtins/plugins/identity-jwt/src/config.rs` `build()` for
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
- Error: Covers R32. `http.path`, `http.method`, `http.host`, `http.scheme`, `http.status` and bare `http` each rejected with the *unaddressable* message, and a test asserts they do not share the never-usable kind.

**Verification:** Every arm of the grammar has a test. The excluded-set test enumerates the
set explicitly so adding a slot without considering it fails.

---

- U2. **Config types and key-model rows**

**Goal:** `AssertionsConfig` deserializing the `assertions:` block, wired into the four
levels and registered in the config key model.

**Requirements:** R1, R2, R13, R15, R16, R19, R25

**Dependencies:** U1

**Files:**
- Create: `crates/ppe-core/src/assertions/config.rs`
- Modify: `crates/ppe-core/src/config.rs` (fields on `GlobalConfig`, `PolicyGroup`, `RouteEntry`; key tables; `ConfigScope`)
- Modify: `crates/ppe-core/tests/config_key_sets.rs`

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
- `DirectionBlock` carries `replace_inherited: bool`, default `false`, spelled and defaulted
  the way `authentication:`'s is (`AUTHENTICATION_KEYS`, `config.rs:1274`). Per direction, so a
  route can replace its `response:` while still stacking the inherited `request:`.
- Fields land as `Option<AssertionsConfig>` named `assertions` on `GlobalConfig`
  (`config.rs:200`), `PolicyGroup` (`:234`, which covers both `groups.<name>:` and
  `global.defaults.<entity>:`), and `RouteEntry` (`:351`). One field on `PolicyGroup` gives
  two of the four levels, which is why the level count costs less than it reads.
- **Key model (D9, guideline 4).** Add `structural_key("assertions", KeyOwner::Core)` to
  `GLOBAL_STRUCTURAL_KEYS` (`:1204`), `BUNDLE_STRUCTURAL_KEYS` (`:1217`) and
  `ROUTE_STRUCTURAL_KEYS` (`:1233`). Add `ConfigScope` variants for the nested blocks with
  their own tables: the `assertions:` object (`request`, `response`), a direction block
  (`headers`, `strip`, `replace_inherited`), and a header entry (`name`, `from`, `members`,
  `on_missing`, `encode`). Extend `ConfigScope::ALL` and each match in `label()` and `keys()`; the array's
  length is written out, so a missing variant fails to compile rather than silently dropping
  a scope.
- `#[serde(deny_unknown_fields)]` on every struct here as the second line of defence.

**Test scenarios:**
- Happy: the worked config round-trips. Copy it from
  `docs/plans/2026-08-24-001-assertions-worked-config.yaml` to
  `crates/ppe-core/tests/fixtures/assertions_worked_example.yaml`, beside the existing
  `legacy-policy-document.yaml`, and point this scenario and U9's worked-example scenario at
  that path. It lives next to the plan rather than in `tests/fixtures/` until this unit lands,
  because a fixture there is read by a test that loads it and `assertions:` is not a known key
  yet.

  It was rewritten on 2026-08-30 for the current surface and its skeleton is verified: with the
  `assertions:` blocks stripped, `config::parse_config` accepts it and reports
  `dispatch=Policy`, one entity default under `http`, six routes, one of them an `http:` route.
  So the only thing standing between it and a passing load is this unit. The earlier draft did
  not load at all: it opened with `plugin_settings: routing_enabled: true`, which #55 made a
  load error naming `engine_settings.dispatch: policy` as the replacement (`config.rs:1048`),
  and it named `kind: identity-jwt` where the factory registers `identity/jwt`
  (`identity-jwt/src/factory.rs:64`).

  One thing that probe pinned, worth knowing before U4: after load, `config.groups` is empty,
  because `fold_groups_into_bundles` has drained it into `global.bundles`. A resolver reading
  the document field finds nothing.
- Happy: `on_missing` absent defaults to omit; present as `deny` parses.
- Happy: `replace_inherited` absent defaults to false; present as true parses, per direction independently.
- Error: `replace_inherted: true`, the misspelling `authentication:` was bitten by, fails rather than loading with the flag false. Add it to `typos.toml`, which already carries `inherted` for that reason.
- Edge: `assertions:` absent leaves `None` at all four levels (R28); present with only `request:` leaves `response:` as `None`, and the reverse.
- Edge: `headers: []` and `strip: []` parse as empty, distinct from absent.
- Edge: a block under `global.defaults.http:` parses, since `http` is an accepted entity-default key.
- Error: an entry with both `from:` and `members:` fails, and the message names the entry's header.
- Error: a misspelled key (`header:`, `form:`, `strp:`, `assertion:`) fails naming what the scope accepts, via the key table rather than via serde. Each deliberate misspelling a test uses as input needs a row in `typos.toml`, which already carries a block of them for exactly this reason.
- Error: `assertions:` under `engine_settings:` fails, since that scope's table does not carry it.
- Key model: `config_key_sets.rs` covers the new scopes, so a variant added without a table fails.

---

- U3. **Config-load validation**

**Goal:** Every configuration error surfaces at load, naming what is wrong.

**Requirements:** R5, R6, R9, R13, R25, R32, R34, R35

**Dependencies:** U1, U2, U11

**Files:**
- Modify: `crates/ppe-core/src/assertions/config.rs`
- Modify: `crates/ppe-core/src/config.rs` (`validate_config`)

**Approach:**
- `AssertionsConfig::validate(&self) -> Result<(), String>` run over every declared block
  during config load, at all four levels, before any request is served.
- Hook into `validate_config` (`config.rs:2170`), which `normalize_and_validate`
  (`engine.rs:439`) reaches from every load path, and which carries `validate_declared_hooks`
  (`:2109`) as the precedent for a name-checking pass. No new plumbing.
- Checks: each source parses (U1 surfaces R5, R6 and R32); a collection-valued source with
  no `encode:` on a single-value entry is rejected (R13); duplicate header names within one
  block are rejected; a header name that is not a valid HTTP field name is rejected.
- Cross-block check: a route whose static tags name two bundles that declare the *same target
  header in the same direction* is rejected, naming the route, the direction, the header, and
  both bundles (R34). Read membership through `route_bundle_names` (`:2568`), which is deduped
  and public, so a name written in both `meta.tags` and `groups:` is one membership rather than
  a false conflict. Bundles naming different headers union and are legal. This runs over the
  whole `PolicyConfig`, so it is a separate function from `validate`.
- Only bundles are unordered. Every other pair of levels is ordered by R25, so an entity
  default and a bundle declaring the same header is a per-name override, not an error.
- Drop report (R35): one finding per route that loses inherited content to a
  `replace_inherited: true` written above it, naming the level and the headers and `strip:`
  entries the route no longer carries. A route's own flag is silent. Follow
  `dropped_inherited_authentication` (`:2996`) exactly, including returning findings rather
  than logging them, so a test reads the finding.
- Response-only check: a `response.strip:` entry whose literal name or glob would match any
  member of the protocol floor is rejected, naming the floor header it would have removed
  (R9). Checked against the floor constant from U11, so the two cannot drift.
- Errors name the level (`global`, `global.defaults.<entity>`, `groups.<name>`, or the
  route's display name) and the header entry, since a bare path is not locatable in a large
  config. `AuthenticationSource::label()` (`:2834`) is the existing spelling for the first
  three; `route_display_name` (`:3042`) for the fourth. Reuse both rather than inventing a
  second vocabulary for the same four levels.
- Members entries do not need `encode:` — a JSON object holds arrays natively (R10).

**Test scenarios:**
- Error: Covers R6. A global block naming `raw_credentials.inbound` fails `load_config`, and the error names both the level and the header.
- Error: Covers R13. `from: subject.roles` on an entry with no `encode:` fails; the same source under `members:` succeeds.
- Error: two entries targeting `x-auth-user-id` in one block fail.
- Error: a route block naming an unaddressable source fails, and the message identifies the route by its display name.
- Error: Covers R34. A route joining two bundles that name the same header in the same direction fails, naming the header and both bundles. Two bundles naming *different* headers succeeds. Two bundles naming the same header in *different* directions succeeds.
- Edge: Covers R34. A bundle named in both `meta.tags` and `groups:` is one membership, so a route joining it and one other bundle is not reported as a conflict.
- Happy: Covers R25. An entity default and a bundle naming the same header succeeds; it is a per-name override, not a conflict.
- Happy: a config declaring a valid block at each of the four levels loads, in both directions.
- Report: Covers R35. A bundle with `replace_inherited: true` produces one finding per route joining it, naming the bundle and the global content dropped. A route with its own flag produces none. A global flag produces none, since nothing has accumulated before it.
- Error: Covers R9. `response: {strip: ["content-*"]}` fails and names `content-type`; `response: {strip: ["x-backend-*"]}` succeeds.

---

- U4. **Contract resolution**

**Goal:** `resolve_assertions_for_route` returning the accumulated contract in force for a
request, per direction.

**Requirements:** R25, R26, R33

**Dependencies:** U2

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- `pub fn resolve_assertions_for_route(config: &PolicyConfig,
  matched: Option<&MatchedRoute<'_>>, direction: Direction) -> Option<ResolvedContract>`.
  Signature mirrors `resolve_identity_plugins_for_route` (`config.rs:2942`), which since #55
  takes the already-matched route rather than matching internally. The caller matches once
  with `resolve_route`, which is what D2 threads.
- Returns an owned `ResolvedContract` rather than a borrowed `&DirectionBlock`, because the
  result is a merge of up to four levels and no single level owns it. Hold entries in an
  index-map keyed by lowercased header name so a per-name override is a replace and iteration
  order stays the declaration order the levels contributed in. `strip:` accumulates into a
  `Vec`, deduped case-insensitively.
- Accumulate in `authentication_layers`' order: global, entity default, each bundle, route
  (R25). Write the walk over that function's output shape, or over a sibling that yields the
  same four layers for `assertions:`, so the two chains cannot disagree about layer order. A
  layer whose `replace_inherited` is true clears what accumulated before it, then contributes,
  exactly as `resolve_identity_plugins_for_route` does with its steps.
- Per header name, the later layer wins and replaces the entry whole, members and `on_missing`
  included (R33). Never merge inside an entry: a members object composed from two levels has no
  author, and R10 says it renders as one object.
- Read bundles from `config.global.bundles`, which `fold_groups_into_bundles`
  (`config.rs:1023`) has already filled from the document's `groups:`. After load the document
  field is empty, so reading it finds nothing.
- Bundle order among themselves is `route_bundle_names` (`:2568`) order, which is `meta.tags`
  then `groups:`, deduped. U3 has already rejected two bundles repeating a header name, so this
  function never resolves an ambiguous override; it asserts that invariant in debug rather than
  relying on a comment.
- `matched: None` accumulates the global layer alone, which is correct for the entry points'
  pre-matching return sites: no route matched there either, so no entity default and no bundle
  applies.
- Returns `None` only when no layer contributed anything (R28), distinct from a contract that
  accumulated to empty because a `replace_inherited` cleared it and added nothing.
- `route_bundle_names` and `route_entity_identity` are public since #55, and `resolve_route`
  is too, so this function no longer has to live in `config.rs` for visibility. It lives
  there anyway, beside the resolver it mirrors, so the two are read and changed together.

**Test scenarios:**
- Happy: no route, bundle or entity-default block resolves the global content, per direction.
- Happy: a route declaring only `response:` resolves the accumulated response and the accumulated global request.
- Happy: Covers R25. A route adding one header to a global contract resolves both levels' headers, and both levels' `strip:` entries.
- Happy: Covers R25 at four levels. All four contribute; a header two levels declare resolves to the more specific level's entry, with that level's `on_missing`.
- Happy: Covers R25. `strip:` from all four levels is present, deduped, and a subordinate level that omits an inherited glob does not remove it.
- Happy: Covers R33. A global members entry and a route entry on the same header resolve to the route's members alone, not a union of keys.
- Happy: Covers R25. `replace_inherited` on the route drops all three inherited levels for that direction and not for the other.
- Happy: Covers R25. `replace_inherited` on a bundle drops global and the entity default, and the route still stacks on top of the bundle.
- Happy: two routes joining one bundle both resolve that bundle's content; a third joining it and adding its own resolves all three levels.
- Happy: an `http:` route resolves its own content on top of the inherited levels, which #42 made expressible and which an earlier revision of this plan recorded as impossible.
- Happy: a block under `global.defaults.http:` applies to a generic-HTTP request that matched no route, and not to a tool request.
- Edge: Covers R28. No block at any level returns `None`.
- Edge: a `replace_inherited` that clears everything and contributes nothing resolves an empty contract, distinct from `None`.
- Edge: `matched: None` accumulates global alone, and the test says so explicitly, since that is what the pre-matching return sites pass.
- Edge: bundle order follows `route_bundle_names`, so a header two bundles could have contributed is the one U3 rejected, and the debug assertion fires if it ever reaches here.
- Edge: case-insensitive keying, so a global `X-Auth-User-Id` and a route `x-auth-user-id` are one entry and not two headers.
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
- `fn render(contract: &ResolvedContract, ext: &Extensions) -> Result<Vec<(String, String)>, MissingSource>`. Takes U4's merged result, not a single level's block, so rendering never sees the layering.
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
- `fn apply(contract: &ResolvedContract, rendered: &[(String, String)], ext: &mut Extensions,
  direction: Direction)`, writing `request_headers` or `response_headers` accordingly. The
  contract is already merged, so removal reads one accumulated `strip:` list and one accumulated
  set of entry targets.
- Build the new map from the existing one: remove every entry-target name and every `strip:`
  match, then insert the rendered pairs, then assign the target map once. One assignment, so
  there is no intermediate state (R20).
- Response direction inverts the default: entry targets and `strip:` matches are removed and
  *everything else is retained* (R8). The floor is never removable, but U3 already rejected a
  config that would try, so `apply` does not re-check it at request time.
- Removal is case-insensitive (R21), which means iterating and comparing lowercased rather
  than a `HashMap::remove`. `remove_header_ci` (`extensions/http.rs:141`) is the existing
  helper; use it or match its behavior. Note it removes exactly one matching key, so a map
  holding two casings of one name needs a loop.
- Removal of entry targets is unconditional and does not consult `rendered` (R17, R18).
  This is the line most likely to be "optimized" into `if let Some(value)` later, so it
  gets a comment saying why it must not be.
- `strip:` entries support a trailing `*` glob, via `Pattern` (`config.rs:604`, wildmatch),
  the dialect route entity matchers use. Deliberately *not* `HttpSelector`'s dialect: that
  one matches paths by equality or segment-boundary prefix because it has to agree with the
  host router, and a header name is neither.
- This writes canonical state directly, so `merge_http`'s `WriteToken` gate
  (`extensions/container.rs:346`) is not in the path. The engine is not a plugin returning an
  edit. What `merge_http` still gives us is the wholesale assignment of both header maps,
  which is what makes R20 hold for a plugin's edit as well as ours.
- `ext.http` is `Option<Arc<HttpExtension>>`: clone the inner, mutate, re-wrap. `None` is
  a no-op (D6). The request line and `status` on the cloned slot are carried through
  untouched, since nothing here reads or writes them (R32).

**Test scenarios:**
- Happy: rendered headers appear; unrelated inbound headers survive untouched.
- Security: Covers R18, R17. A client-supplied value under an entry target is removed when the engine derived no identity at all, so nothing is left behind.
- Security: Covers R19. A client-supplied `x-auth-projects` is removed by the `x-auth-*` glob though no entry targets it.
- Security: Covers R21. `X-Auth-User-Id` inbound is removed by a config written `x-auth-user-id`, and by the `x-auth-*` glob. A map carrying both `X-Auth-User-Id` and `x-auth-user-id` loses both.
- Edge: `Authorization` is untouched by a config that does not name it.
- Edge: Covers D6. `ext.http` of `None` applies nothing and does not panic.
- Edge: Covers R32. The request line and `status` are unchanged by an application in either direction.
- Edge: applying twice produces the same header map as applying once.
- Response: Covers R8. A response header no entry and no `strip:` names survives untouched.
- Response: Covers R18. An upstream echoing an entry-target name has it replaced by the engine's value, or removed when nothing rendered.

---

- U7. **Engine integration**

**Goal:** The contract is applied on every path that returns a `PipelineResult`, on every
entry point that can name its hook.

**Requirements:** R7, R8, R16, R22, R23, R24, R26, R28, R31

**Dependencies:** U3, U4, U5, U6

**Files:**
- Modify: `crates/ppe-core/src/engine.rs`

**Approach:**
- `fn apply_assertions(&self, snapshot: &RuntimeSnapshot, hook_name: Option<&str>,
  matched: Option<&MatchedRoute<'_>>, result: PipelineResult) -> PipelineResult`, private.
  Same signature as D2 states. Resolves the contract (U4), renders (U5), applies (U6), and
  converts a `MissingSource` into `PipelineResult::denied` with a violation coded in the
  `auth.*` family alongside `auth.mapping_failed`. Proposed code: `auth.assertion_missing`.
  Build it as
  `PipelineResult::denied(violation, extensions, result.context_table).with_errors(result.errors)`
  and carry `result.metadata` across: `denied` (`executor.rs:160`) constructs with
  `errors: Vec::new()` and `metadata: None`, so a bare call discards every
  `on_error: ignore` plugin error the pipeline just recorded, which is what an operator needs
  to debug the deny.
- Resolve the hook's phase via `hooks::metadata::lookup` (`hooks/metadata.rs:262`) and map it
  to a direction (R22, D3): `Pre` applies `request:`, `Post` applies `response:`, `Unphased`
  and `None` apply neither. `hook_name: None` applies neither (R31, D8). Skip when the
  resolved direction block is `None` (R28).
- Call it at **all fourteen** return points, per the table in Context:
  - `invoke_by_name` (`:1432`): `:1451`, `:1467`, `:1479`, tail. Passes `Some(hook_name)`.
  - `invoke_named` (`:1616`): `:1639`, `:1651`, `:1664`, tail. Passes `Some(hook_name)`.
  - `invoke` (`:1528`): `:1543`, `:1555`, `:1568`, tail. Passes `Some(H::NAME)`, which is a
    hook name for the single-name types that are its sound users, and a family name otherwise;
    `lookup` is the discriminator (D8).
  - `invoke_entries` (`:1723`): `:1732`, tail. Passes `None`, because it is a nested dispatch
    primitive and not a boundary (D8). Add a `debug_assert` that it is reached from within an
    executor invocation, so a host adopting it as an outermost dispatch trips it in debug
    rather than silently losing the contract.
  Enumerate the sites in the PR description. `invoke_entries` still gets the call, so the site
  list is uniform and the boundary rule is expressed in one place.
- The pre-matching sites (`:1451`, `:1543`, `:1639`, `:1732`) pass `matched: None`, so U4
  resolves the global contract. The post-filtering sites and the executor tail pass the
  `MatchedRoute` `filter_entries_by_route` (`:1853`) resolved. That requires threading it out
  of the filter, which today returns only the entry list: extend its return to
  `(Arc<Vec<HookEntry>>, Option<MatchedRoute>)`, or stash it, but do not re-resolve. The
  route table walk is not free and the answer is already computed.
- The denied-on-route-resolution-failure sites (`:1467`, `:1555`, `:1664`) are the ones #42
  added: an unreadable HTTP path denies (`:1894-1901`). Treat them as R24's case, strip and
  do not inject, and pass `matched: None`, because by construction no route resolved.
- On a pipeline a plugin already denied (R24): in the request direction strip, do not render,
  do not inject, and do not evaluate `on_missing`. Removal costs nothing and is never wrong,
  so it happens even though the request is not forwarded, which keeps client-supplied values
  out of the extensions the audit path sees. Injecting onto a refused request would be
  pointless and could replace one violation with another. The response direction does not run
  at all on a denied pipeline: there is no upstream response to filter.

**Test scenarios:**
- Covers R26, and the early-return hazard. **One test per return site, fourteen in all**, each asserting that a client-supplied entry-target header does not survive where a contract applies, and that nothing changes where D8 says it does not:
  - per boundary entry point (`invoke_by_name`, `invoke_named`, `invoke::<H>` with a single-name hook type): a hook with no registered entries and no route annotations; a hook whose entries all filter out by route; a route resolution failure that denies; a normal pipeline through the executor;
  - `invoke::<H>` with a multi-name family type: the header map comes back byte-identical, since no phase resolves and nothing dispatches;
  - `invoke_entries`: both sites return a byte-identical header map, so D8's boundary rule is pinned as behavior rather than left as an omission;
  - nesting: an APL route whose policy names a `run(name)` step receives the contract exactly once, applied at the outer `invoke_named` after the handler returns, and the nested step observes the client's header value and not the engine's (R23).
- Covers R16. A route whose tenant entry is `on_missing: deny` and whose token carries no tenant claim produces a denied result with the expected code, and the header does not appear.
- Covers R28. A config with no block leaves the header map byte-identical to the input.
- Covers R7. A readable slot that no entry names does not appear in the outgoing headers.
- Covers R22. A pre-phase hook applies `request:` and not `response:`; a post-phase hook applies `response:` and not `request:`; an unphased hook applies neither. `http.request` applies `request:` and `http.response` applies `response:`, with no name written anywhere in this feature. A host-registered hook with pre-phase metadata applies `request:` with no config change.
- Covers R22 and idempotence. An exchange firing both `http.request` and `cmf.tool_pre_invoke` produces one set of asserted headers, identical to either hook alone.
- Covers R23. A policy rule reading a target header name observes the client's value, and the upstream still receives only the engine's.
- Covers R24. A pipeline denied by a plugin returns extensions with no client value under any target name, and with no asserted header added.

**Verification:** A reviewer can point at each of the fourteen return sites in `engine.rs`
and name the test covering it. If that mapping cannot be stated, the unit is not done.

---

- U8. **Effective-policy artifact**

**Goal:** The engine can render what crosses the boundary, without reading Rust.

**Requirements:** R27, R31, R35

**Dependencies:** U1, U2, U4, U11

**Files:**
- Modify: `crates/ppe-core/src/assertions/mod.rs`

**Approach:**
- `fn effective_policy(config: &PolicyConfig) -> String` rendering, per scope: every header
  that can be emitted with its source and capability, the `strip:` set including the implicit
  entry-target names, the code-fixed excluded set with its rationale, the response protocol
  floor, and the phase each direction fires on (R27). Both directions render, labelled, so an
  operator reads one document for the whole boundary.
- **Render the accumulated contract, with provenance per header.** Under D10 a route's contract
  spans four levels, so a per-level dump does not answer "what does this route assert". Render
  the merged result for each route and for each scope that can stand alone, and name the level
  each header came from, marking one that overrode a less specific level's entry. Provenance is
  the cost additive imposes on auditability, and this is where it is paid.
- Render `replace_inherited` where it is set, and what it dropped (R35), so the artifact and
  U3's load-time findings tell the same story.
- Name the levels with `AuthenticationSource::label()`'s spellings and `route_display_name`,
  so the artifact and a validation error name the same level the same way.
- State per level which traffic it reaches: an entity default reaches every route of that
  type including generic HTTP, a bundle reaches the routes joining it, global reaches
  whatever matched no route. This is R27's "which traffic" clause and it is what makes the
  four-level ladder legible.
- Name which entry points are boundaries and therefore apply a contract, and that a nested
  dispatch primitive does not (R31), so a host integrating through a pre-resolved entry list
  learns it here rather than from an absent header.
- Emitted at startup at `info` when a block is configured, and available as a public
  function so a host can expose it.
- The excluded set and the floor are printed from the same constants U1 and U11 match on, so
  the artifact cannot drift from what the code enforces. A test asserts every excluded
  variant and every floor entry appears.

**Test scenarios:**
- The artifact names every configured header and its source.
- The artifact lists entry-target names as stripped even though they are not in `strip:`.
- The artifact names all four levels present in a config, with the spellings U3's errors use.
- Covers R25, R27. For a route inheriting from all four levels, the artifact names every accumulated header and the level each came from, and marks an overridden entry as overridden.
- Covers R35. A `replace_inherited` above a route appears in the artifact with what it dropped, matching U3's finding for the same config.
- Covers R31. The artifact names which entry points are boundaries, and names nested dispatch as applying nothing.
- Covers the anti-drift property: adding a variant to the excluded set, or a name to the floor, without updating the renderer fails a test.
- A config with no block renders a statement that nothing is asserted, not an empty string.

---

- U9. **End-to-end tests**

**Goal:** The properties an operator is promised hold through the real engine.

**Requirements:** R7, R8, R9, R11, R17, R18, R20, R24, R25, R28, R29, R30, R33

**Dependencies:** U7, U12

**Files:**
- Create: `crates/ppe-core/tests/assertions_e2e.rs`

**Approach:** Drive `PolicyEngine` with a loaded config and a populated `Extensions`,
asserting on the header map in the returned `PipelineResult`. Dispatch through
`invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, ...)` and its response half for the HTTP cases,
and `invoke_named::<CmfHook>("cmf.tool_pre_invoke", ...)` for the MCP ones.
`crates/ppe-apl-runtime/tests/http_route_e2e.rs` is the existing harness shape for driving
both halves of an HTTP exchange with a request line on the extensions.

**Test scenarios:**
- Covers the worked example. A request carrying spoofed `x-auth-user-id`, `x-auth-attributes` and `x-auth-projects` reaches the upstream with the engine's values and none of the client's.
- Covers R28 and R7. Under a default config, no JWT, no raw credential, and no delegated token appears in any outgoing header. Assert on the whole header map, not on named absences, so a future source cannot leak past the test.
- Covers R11. A Keycloak-shaped token's nested claim reaches the header as JSON with structure intact.
- Covers R25. A route adding one header to a global contract reaches its upstream with both, and with both levels' `strip:` applied.
- Covers R25 at four levels. A generic-HTTP request matching no route receives global plus `global.defaults.http`; one matching a route receives those plus the route's.
- Covers R25. A global `on_missing: deny` entry denies a request through a route that declares its own headers and no flag, so a route cannot escape an inherited floor by declaring a contract.
- Covers R25, R26. The same route with `replace_inherited: true` is allowed, and a client-supplied value under a target name still does not reach the upstream.
- Covers R33. A route entry on a header a global members entry also names reaches the upstream with the route's members alone.
- Covers R20. No ordering of plugins in the pipeline exposes a client value; a plugin holding `write_headers` that writes an entry-target name is overwritten, not merged.
- Covers R8, R9. A response carrying a backend banner, `set-cookie`, and `content-type` reaches the client without the first two and with the third intact.
- Covers R18 in the response direction. An upstream echoing `x-auth-attributes` back does not reach the client with the upstream's value.
- Covers R24. A denied pipeline produces no response-direction filtering, because no upstream response exists.
- Covers R29. An `http:` route declaring a contract, driven with no `path` on the HTTP extension, applies the global contract instead, and the engine has reported the route.
- Covers R30. The same route driven with a request line on the request invocation and none on the response invocation applies the route's `request:` and the global `response:`, and the asymmetry is reported.

---

- U10. **Documentation and CHANGELOG**

**Requirements:** R27, R29

**Dependencies:** U1-U9, U11, U12

**Files:**
- Modify: `CHANGELOG.md`, `README.md` if the feature list needs a line
- Create: a config reference section for the block

**Approach:** Document the block, the four levels and how they resolve, the excluded set, the
strip semantics, and the response floor's contents. State plainly that what crosses the
boundary is unsigned and believed on the strength of the network path, because an operator
configuring this needs to know the trust model they are opting into.

Document the host's obligation from R29 explicitly, next to the block rather than in a
release note: a contract on an `http:` route needs the request line on the HTTP extension at
both invocations, and without it the global contract governs. `docs/upgrade-apl.md` is the
precedent for a per-key operator-facing reference in this tree; there is no general config
reference document yet, so this either starts one or extends that one. Decide which in U10
rather than assuming a file that does not exist.

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
  name it. Use the same `Pattern` dialect U6 matches with, or the two disagree about what a
  glob covers and a config passes load then strips a floor header.
- Deliberately *not* included: `set-cookie` (removing it on the gateway domain is a stated
  use case), `server` and `x-powered-by` (banners an operator should be able to strip), and
  anything vendor-specific.

**Patterns to follow:** the excluded-source set in U1 — same shape, same anti-drift
requirement, opposite polarity.

**Test scenarios:**
- Happy: every name in the floor is matched case-insensitively.
- Happy: a glob matching a floor name returns that name; a glob matching nothing in the floor returns `None`.
- Happy: the glob check and U6's removal agree on a shared table of patterns, so the load-time check cannot be looser than the runtime match.
- Edge: `set-cookie`, `server`, `x-powered-by` are NOT in the floor, so an operator can strip them.
- Covers the anti-drift property: a test asserts every floor entry carries a non-empty reason, so an addition cannot land undocumented.

**Verification:** The floor's contents are reviewable as a list with reasons. Adding a name is
a visible change with a stated justification, not a silent widening.

---

- U12. **Reachability reporting**

**Goal:** An operator learns that a contract on an `http:` route is unreachable, rather than
inferring it from a header that did not appear.

**Requirements:** R29, R30

**Dependencies:** U2, U4

**Files:**
- Modify: `crates/ppe-core/src/config.rs` (load-time findings)
- Modify: `crates/ppe-core/src/engine.rs` (snapshot-derived list, runtime warn-once)

**Approach:**
- Load-time: a function beside `http_routing_gaps` (`config.rs:2335`) returning
  `Vec<String>`, one finding per `http:` route that declares a contract, stating that the
  contract applies only when the host supplies the request line. Emitted once per config load
  by the engine, the way `http_routing_gaps`' findings are. Kept separate from emission so a
  test reads the finding rather than a log line, which is the shape that function established.
- Runtime: derive the list of `http:` routes declaring a contract at snapshot build, beside
  `http_routes_declaring_authentication` (`engine.rs:142`, held at `:310`), so the hot path
  reads an answer rather than walking the route table. Then warn once, per direction, when a
  generic-HTTP invocation carries no readable path and that list is non-empty. Model on
  `warn_once_if_route_authentication_is_unreachable` (`:2148`), including its `AtomicBool`
  gate: this is the same failure for a different block, and two warnings that read differently
  for one root cause is worse than one that reads well.
- Per direction matters because of R30. A host that supplies the request line on the request
  invocation and not the response one gets a warning naming the response direction, which is
  the actionable half. One combined warning would fire on the request invocation and be
  suppressed by the time the informative case arrived.
- The load-time finding names the routes; the runtime warning names the direction and repeats
  the host's obligation. Neither denies: the global contract is a defensible fallback and
  failing a load because a *host* might not populate a field is not this layer's call.

**Test scenarios:**
- Happy: a config with `http:` routes declaring contracts produces one finding per route, naming each.
- Happy: a config whose `http:` routes declare no contract produces no findings; nor does one with no `http:` routes.
- Runtime: a generic-HTTP invocation with no path, against a config with such a route, warns once and not twice.
- Runtime: the same invocation with a readable path does not warn.
- Runtime: Covers R30. A request invocation with a path and a response invocation without one warns for the response direction only.
- Edge: the snapshot-derived list is empty when no route declares a contract, so the runtime check short-circuits.

---

## Unit Dependency Graph

```
U1  (source paths) ──┬── U2 (config types + keys) ──┬── U3 (validation) ──┐
                     │                              ├── U4 (resolution) ─┤
                     └── U5 (rendering) ────────────┴── U6 (apply) ──────┴── U7 (engine) ──┬── U9 (e2e)
                                                                                           └── U10 (docs)

U11 (response floor) ──> U3 (glob rejection), U8 (renders the floor)
U1, U2, U4, U11 ──────> U8 (artifact)
U2, U4 ───────────────> U12 (reachability reporting) ──> U9
```

U1 and U11 have no dependency and can start in parallel. U2 depends on U1, and its key-model
rows are the part most likely to be underestimated. U7 is the integration point and cannot
start until U3-U6 land. U12 needs only U2 and U4, so it can land before U7 and its warning is
useful on its own.

---

## System-Wide Impact

- **`ppe-core` public API grows**: a new `assertions` module, new fields on `GlobalConfig`, `PolicyGroup` and `RouteEntry`, new `ConfigScope` variants, and `resolve_assertions_for_route` returning an owned `ResolvedContract`. All config fields are `Option`, so existing configs are unaffected, but the struct and enum changes are a semver event under the project's 0.1.x policy. `ConfigScope::ALL` has a written length, so adding variants is a compile-time-checked change for any external matcher.
- **Config load can now fail** for reasons it could not before. A deployment with a malformed block that previously would have been ignored now refuses to start. That is the intent (R5, R6) and belongs in the CHANGELOG as a behavior change.
- **Config load now reports three more findings**: U12's two reachability findings, plus R35's drop report when a level above a route replaces what the route inherits. A deployment with `http:` routes or a `replace_inherited` above a route sees new startup output.
- **No plugin API change.** Capabilities, write tokens, and `merge_http` are untouched. The engine writes canonical state directly, so it does not pass through the `WriteToken` gate `merge_http` added.
- **No praxis change.** Header mutations already flow back through `PipelineResult`, and `merge_http` assigns `response_headers` alongside `request_headers`.
- **The engine now writes `response_headers`.** A deployment that adds a `response:` block changes what its clients receive, which is a client-visible behavior change and belongs in the CHANGELOG with the floor's contents.
- **`filter_entries_by_route` gains a return value** if the `MatchedRoute` is threaded rather than re-resolved (U7). Private, so no external impact, but it touches the hottest function in the engine.
- **Coverage gate**: `make coverage` is at 95%. New modules need tests to match or the gate fails.

---

## Risks & Dependencies

| Risk | Mitigation |
|---|---|
| One of fourteen return sites in `engine.rs` is missed and stripping silently does not happen. | U7's per-site tests, and the reviewer check that each site maps to a named test. Highest-severity risk in the work: it fails open. Worse than the previous revision assumed, since the site count grew from nine to fourteen across four entry points rather than three. |
| A host adopts `invoke_entries` as its outermost dispatch, so there is no boundary and no contract. | Not a risk for any current caller: all three sit inside `AplRouteHandler`, which runs inside `invoke_named`. U7 adds a `debug_assert` that the call is nested, U8's artifact names which entry points are boundaries, and U10 documents it. Residual: a release build integrated that way loses the contract silently. |
| A host does not supply the request line on the response invocation, so a route's `response:` silently becomes the global one. | U12's load-time finding and per-direction runtime warning, modelled on the two precedents the tree already set for this exact failure. Residual: a warning is not enforcement, and the global contract still governs. |
| A claim value injects CRLF and splits a header. | U5 validates rendered values, under R14. |
| `HashSet` iteration order leaks into headers. | Sorting happens at resolution in U1, not at each render site, so a new caller cannot forget it. |
| Contract resolution drifts from `authentication:`'s layer order. | Both now accumulate over the same four layers in the same order, so U4 walks that order rather than inverting it, and U3 and U8 name levels with the same `label()` spellings. Additive removed the divergence this risk was about. |
| A route joins two bundles that repeat a header name, and one silently wins. | U3 rejects it at load per header, reading deduped `route_bundle_names`; U4 asserts the invariant rather than trusting it. Detectable only because bundle membership is static. |
| A route inherits a header or an `on_missing: deny` its author cannot see, and the surprise lands in production. | This is additive's residual, accepted in D10 because the alternative loses inherited `strip:` and lets a route escape a deliberate deny floor. Mitigated by U8's per-header provenance and U3's R35 findings, both modelled on `authentication:`'s. Residual: a four-level contract is harder to read than a one-level one, and no artifact fully removes that. |
| A members entry gets merged across levels, producing a JSON object with no author. | R33 makes granularity the entry; U4 replaces a repeated header name whole and U9 asserts it end to end. Called out because per-key merging is the intuitive thing to reach for once headers union. |
| `replace_inherited` is read as reaching more than it does, and someone expects it to disable a strip. | R26 bounds it to operator-authored content, so unconditional entry-target removal, the source exclusions and the response floor are unreachable by construction. U6's test asserts a flagged route still strips its targets. |
| Accumulated headers outgrow an upstream's header budget. | New with additive: four levels of members entries can add up. Not mitigated in this work beyond the artifact showing the full set. Worth a size warning if it shows up in practice. |
| The `assertions:` key is added to the structs but not to a scope's key table, so it is rejected at that scope. | Guideline 4, D9, and `config_key_sets.rs`'s walk over `ConfigScope::ALL`. Fails at load with a message naming the scope, which is loud rather than silent. |
| A greedy `response.strip:` glob removes a header the client needs. | U11's floor plus U3's load-time rejection, which names the floor header the glob would have hit. U11's shared-pattern test keeps the load-time check from being looser than the runtime match. |
| The floor is incomplete and a client-critical header stays strippable. | The floor is an enumerated list with a reason per entry and a test that every entry has one. Residual: a header nobody thought of is strippable until someone adds it. This is the response direction's analogue of the excluded-source set, and carries the same standing review obligation. |
| Two mental models in one config block confuse operators into expecting response default-deny. | D7 states the asymmetry, U8's artifact renders both directions labelled, and U10 documents it. Residual: a real cognitive cost, accepted because the alternative breaks clients. |
| The worked config drifts out of date again between now and U2, the way it did between August and now. | It is tracked beside the plan rather than left in gitignored scratch, so a breaking config change shows up as a file a reviewer can see. Residual: nothing loads it in CI until U2 copies it to `tests/fixtures/`, so drift is caught by review rather than by a gate. |
| Re-resolving the route per application costs a second table walk per request. | U7 threads the `MatchedRoute` out of `filter_entries_by_route` rather than calling `resolve_route` again. The route cache caches entry lists, not matches, so there is nothing to lean on. |

---

## Open Questions

### Resolved during planning

- **Where the projection is applied.** `ppe-core` after the executor, not the APL runtime (D1), because the block is engine config and must hold for hosts without APL.
- **Whether groups contribute.** Yes, and so do entity defaults. All four levels stack.
- **Whether double application is harmful.** No. Strip-then-inject is idempotent over the same extensions, which #42 turned from a nicety into load-bearing: two `Pre` hooks fire on one HTTP-transported tool call.

### Settled 2026-08-24

- **Does policy see inbound headers before removal?** Yes. Removal happens after the policy phase, so existing rules keep working and an author can deny a request that arrived carrying a target header name at all. The accepted cost is that a value under `http.request_headers.x-auth-user-id` looks authoritative and is not. R23.
- **An already-denied pipeline** — strip, do not inject, do not evaluate `on_missing`. R24.
- **A route block without `replace_inherited: true`** — stacks on what it inherits. The flag exists and is what a route uses to speak only for itself.

### Settled 2026-08-30

- **Which hooks are request-side?** None are named. The phase registry answers it, and #42 is the proof that was the right call: the L7 pair this plan used to name by hand was deleted and replaced, and D3 needed no amendment. D3.
- **What happens on a dispatch path with no hook name?** The question was malformed. `invoke::<H>` has one for the hook types that can soundly use it, so it needs no special case. `invoke_entries` applies nothing because it is a nested primitive and R23 puts the contract after policy evaluation, not because a name is missing. D8, R31.
- **Can a contract be written per HTTP path?** Yes, since #42. The previous revision recorded this as impossible and proposed a startup warning for the resulting over-broad global block. That mitigation is withdrawn; U12 addresses the opposite hazard #42 introduced instead.
- **How does a new config key get accepted?** Through its scope's key table, not only `deny_unknown_fields`. D9, guideline 4.
- **Layering default: additive, with `replace_inherited` to opt out.** Review's position, adopted. Selection was fail-open twice: a subordinate level dropped the inherited `strip:` list with the direction, which the first worked config got wrong four times out of four, and declaring any `request:` block escaped a global `on_missing: deny`. Additive cannot leak by construction, because the exclusions are code-fixed, only named entries propagate, and the engine originates every value. Granularity is the entry, not its contents (R33); bundles repeating a header name are a load error (R34); the flag reaches operator-authored content only (R26). D10.
- **The reserved `all` bundle.** Moot as a precedence question now that levels accumulate: it contributes its layer alongside any other bundle, in `route_bundle_names` order, and R34 catches a header two bundles both name.

### Still open

- **Is "the outermost dispatch is a named boundary" an invariant or an observation?** Today it is an observation: all three `invoke_entries` callers nest inside `AplRouteHandler`. If it is an invariant PPE guarantees, the `debug_assert` in U7 plus a line in U10 closes it and D8 is finished. If a host may legitimately drive `invoke_entries` as its outermost call, that host needs a boundary of its own, and the options are a public "apply the contract to this result" entry point or a documented requirement that it call a named entry point instead. This is the one live decision `invoke_entries` still carries.
- **Delegated-token collision.** Narrower than earlier revisions of this plan claimed. They do not share a fold point: this surface writes `http.request_headers`, while delegation writes `raw_credentials.delegated_tokens`, whose `outbound_header` (`extensions/raw_credentials.rs:378`) is a *declaration* of the name a forwarding component should attach the token under. Nothing in this tree attaches it, so no ordering exists here to get wrong. The collision lives at whichever component reads `outbound_header`, and only when an operator has both pointed `default_outbound_header` away from its `Authorization` default and written an assertions entry targeting that same name. R18 would then strip what the forwarder attached, or the forwarder would overwrite the assertion, depending on an order PPE cannot see. Both inputs are visible at config load, so this is a candidate load-time check rather than a runtime rule; not in scope here, and no unit is blocked on it.
- **Response-direction sources.** Whether a response entry may read response-phase state at all, beyond the identity state a request entry reads. `http.status` is the obvious candidate and R32 currently excludes it from the grammar; nothing yet needs it.
- **Duplicate inbound headers.** `HttpExtension` is `HashMap<String, String>`, so duplicate wire headers collapse and repeated names cannot be emitted. Probably acceptable; needs stating rather than deciding.
- **Failure modes beyond absence.** `on_missing` covers a source that resolved to nothing. It does not cover a source that errored, or a value rejected by R14. Both currently fall to "omit", which may want to be configurable.
- **Whether U12's warning should be a load error under some condition.** It cannot be in general, since whether the host populates the request line is not visible at load. Whether a host could declare its capability, and then a contract on an `http:` route without that declaration could fail loudly, is worth asking of the praxis side.

### Deferred to implementation

- Whether `csv` is worth shipping, or whether `json` plus members covers every real case. R13 requires *an* encoding declaration, not specifically this set.
- Whether `effective_policy` should render structured output rather than text.
- Whether U10 starts a general config reference document or extends `docs/upgrade-apl.md`.

---

## Sources & References

- Origin requirements: `docs/brainstorms/2026-08-23-upstream-header-projection-requirements.md`
- Tracking issue: praxis-proxy/policy#28
- **Landed dependencies**: policy#9 (claim JSON shape), policy#31 (configurable claim map), [policy#38](https://github.com/praxis-proxy/policy/pull/38) (hook phase authority, validation on every load path), [policy#41](https://github.com/praxis-proxy/policy/pull/41) (writers serialized on the runtime snapshot), [policy#42](https://github.com/praxis-proxy/policy/pull/42) (`http:` route selector and the `http.*` hook family)
- **Base branch**: `feat/apl_cleanup`, carrying [policy#55](https://github.com/praxis-proxy/policy/pull/55) (APL grammar and config-model cleanup: four inheritance levels, `ConfigKey` tables, `resolve_route`, `invoke_by_name`, `dispatch: policy` as default, and `871a71f` correcting the five comments that still said otherwise)
- Upstream framing: praxis-proxy/praxis#954 and its review thread
- Existing harness for driving both halves of an HTTP exchange: `crates/ppe-apl-runtime/tests/http_route_e2e.rs`
- Worked config: `docs/plans/2026-08-24-001-assertions-worked-config.yaml`, tracked beside this plan. Covers all four levels, both directions, an `http:` route, and the configs that fail to load. U2 copies it to `crates/ppe-core/tests/fixtures/assertions_worked_example.yaml`.
