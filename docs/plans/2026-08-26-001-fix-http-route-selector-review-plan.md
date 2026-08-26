---
title: "fix: HTTP route matching, install symmetry, and hot-path cost"
type: fix
status: planned
date: 2026-08-26
origin: https://github.com/praxis-proxy/policy/pull/42
---

# fix: HTTP route matching, install symmetry, and hot-path cost

## Summary

Nine defects in the `http:` route selector, found after it landed on the branch
and all reproduced at runtime. Three change which policy runs for a request and
all three fail in the permissive direction: a method-narrowed route loses to the
broader route declared above it, two routes whose methods differ only in case
both match while one silently wins, and an exact-path route misses the ordinary
`/admin/` spelling and falls through to the global policy.

One changes which handlers install. The global HTTP catch-all decides each half
independently, on the reasoning that authorization has nothing to say on the way
out and response filtering nothing on the way in. The route path installs both
halves whenever any phase is declared, so adding a catch-all route silences the
whole response-side chain. The engine now holds one rule for this in two places
that disagree, and the entity-less path's tests are what say which is intended.

Two are diagnostics: a stale `policy:` key gets a typo error instead of the
rename message it has a check for, and a route with three bad keys takes three
loads to fix.

Three are cost on the request path: a latch that never latches, so a scan runs
per identity hook rather than once; a name lookup that clones every path a
selector declares, per matching route, per request; and a normalizer that
allocates on every request carrying a query string.

Nothing here changes the selector's design. Three of the units can move an
existing config's behavior, and all three move it toward the narrower route: the
method scoring, the case-folded duplicate check, and the exact-path trailing
slash.

---

## Implementation Guidelines

**1. No plan or finding identifiers in durable text.** Nothing that ships may
cite `U3`, `F5`, a finding number, or a review URL. That covers rustdoc,
comments, commit messages, the CHANGELOG entry, test names, and the PR
description. Describe the defect and the behavior:

```
no    // Fixes finding 2: method now scores.
yes   // A method-narrowed route outranks the same path without one, so the
      // narrower policy wins rather than whichever was declared first.
```

**2. Reproduce before fixing.** A probe patch holding eleven probe tests and
three instrumentation counters, covering every unit below, is attached to the
review discussion; a local copy sits in the untracked `.sketchpad/`. It applies
cleanly to the merge and changes no behavior. Apply it first, watch each probe
fail, then fix. Probes that assert behavior become permanent tests and land in
the tree; the three counters are instrumentation and come back out.

**3. One commit per unit.** Each unit is independently revertable. U1 and U2 in
particular should not share a commit: one changes route selection, the other
changes handler installation.

**4. Fail-closed stays fail-closed.** U1, U3, and U4 move requests from a
broader policy to a narrower one. None may turn a request that resolved into one
that resolves nothing, since an empty resolution is an allow.

**5. Cost claims need a counter, not a guess.** U6 through U8 are allocation
findings measured with counters. Re-run the counters after each fix rather than
reasoning about whether an allocation went away.

---

## Problem Frame

The selector shipped with the scoring, normalization, and install rules stated in
its own plan, and the implementation diverges from those statements in three
places rather than from anything a reader would have to infer.

The PR body says "among prefixes, the longest wins regardless of declaration
order." Method narrowing is order-dependent, so that sentence is false for any
config that narrows by method.

The selector's own test names the trailing-slash asymmetry and justifies it for
prefixes, where both sides get stripped. Exact paths arrived in the same change
and compare by byte equality, where the justification does not hold.

The global catch-all's comment states the per-half rule explicitly. The route
path predates neither and simply does not implement it.

The remaining five are cost and diagnostics, where the code does what it says
and what it says is more expensive or less helpful than intended.

---

## Requirements

- R1. A route narrowed by `method:` outranks an otherwise identical route with no
  `method:`, for the methods it names. Ordering stays total and independent of
  declaration order.
- R2. Two routes on the same path whose method sets differ only by case are the
  same route, and load fails naming both, as it already does for other duplicate
  selector identities.
- R3. An exact-path route matches the spellings of its path that normalization
  treats as equivalent, including one trailing slash.
- R4. A route installs a phase's handler only when its effective layers declare
  steps for that phase, on the route path as on the global catch-all.
- R5. A route carrying a renamed APL key reports the rename, not an unknown key.
- R6. A load reports every unrecognized route key it found, not the first.
- R7. The unreachable-authentication scan runs at most once per fill cycle
  regardless of whether it finds anything, and preferably not on the request path
  at all.
- R8. Resolving a matched route's name allocates nothing proportional to the
  number of paths the selector declares.
- R9. Normalizing a path that needs no rewriting allocates nothing, query strings
  included.
- R10. A plugin that cannot read what a hook carries cannot silently register on
  it and report clean.
- R11. A response-phase policy can express a decision about the response status.
- R12. No existing configuration changes which handlers install or which route it
  resolves to, except where R1, R2, and R3 deliberately move it toward the
  narrower route.

---

## Context & Research

### Verified against the merge

Each finding below was reproduced on `dc4f0b7` (the merge of `origin/main` into
this branch) or on the PR head immediately before it, with the probe patch
applied. File and line references are post-merge.

- `SPECIFICITY_EXACT_PATH` is `usize::MAX / 2` (`config.rs:1341`), and
  `resolve_route` already combines scores with `saturating_add`
  (`config.rs:1819`). Any method bonus must saturate too, or an
  exact-path-plus-method route wraps.
- `rendered_methods` (`config.rs:1492`) sorts and dedups but does not case-fold,
  while `http_method_matches` compares with `eq_ignore_ascii_case`.
- `path_prefix_matches` (`config.rs:1373`) strips a trailing slash on both sides.
  The exact-path comparison is `declared == path`.
- The global catch-all computes `installs_pre_handler` and
  `installs_post_handler` separately (`visitor.rs:561`). `visit_routes` checks
  `effective.declared_phases().is_empty()` once and then installs both.
- Both predicates the catch-all uses take `&CompiledRoute`, which the route
  path's `effective` already is, so reuse needs no new plumbing.
- `warn_if_delegating_without_identity` and the displaced-plugin-chain warning
  both run in `visit_routes` after the merge, the first per entity name and the
  second guarded on `idx == 0`.

### The severity of the install asymmetry is capped today, and will not stay capped

`HttpExtension` carries `request_headers`, `response_headers`, `method`, `path`,
`host`, and `scheme`. There is no body field, and no `request_body` or
`response_body` anywhere in the workspace. So a response-phase plugin today can
strip a header, enforce a content type, or attach a label, and cannot redact a
body. That is what the dropped chain currently costs.

It grows the moment body plumbing lands, because that is when the dropped chain
starts carrying the plugins the response hook exists for. The fix is cheap now
and the exposure is not static, which is the argument for doing U2 in this pass
rather than deferring it behind the body work.

### The route path's fix reaches entity routes

`visit_routes` is shared. Guarding each half changes entity routes as well as
HTTP ones: an entity route whose effective layers declare only pre-phase steps
stops installing a post handler. The suite covers entity routes and stays green
under the fix, which says the coverage does not depend on the unconditional
install, not that no host does. U2 treats this as a deliberate widening with its
own test, not as a side effect.

### The hook payload is the wrong shape for HTTP, and this is the cheap moment

Both HTTP hooks are typed on `CmfHook`, whose payload is an LLM chat message.
The HTTP path fills nothing into it: the e2e harness constructs
`Message::text(Role::User, "hi")` for an HTTP request, and header mutation goes
through `modified_extensions`. A content-inspecting plugin written for MCP is
`HookHandler<CmfHook>`, so it registers on `cmf.http_response`, scans the
fabricated message, finds nothing, and reports clean. An always-passing scanner
is worse than no scanner.

There is also no HTTP status code anywhere, on the extension or in the payload,
so a response-phase policy cannot express "deny on 5xx" or "label 4xx". That is
close to the first thing anyone writes at that point.

A body is not a payload field. A response is status, then headers, then chunks,
then trailers, so an owned-body payload forces the proxy to buffer before policy
runs: unbounded memory on attacker-controlled response sizes, and a deadlock
rather than a slowdown on SSE, which is how MCP streams. Body inspection needs a
per-chunk phase a plugin opts into through a capability, with a size cap and
deny-on-overflow. That is a separate piece of work; U9 only decides the hook type
and the status field, while the whole CHANGELOG is `[Unreleased]` at 0.1.0 and the
cost is a search and replace rather than a migration.

---

## Key Technical Decisions

**D1. A method bonus, not a validation rejection.** Rejecting overlapping
selectors would refuse configs that load today and whose intent is legible: a
broad rule plus a narrower one for one method is a reasonable thing to write. The
bonus makes it mean what it looks like. It sits below the path-prefix step so it
breaks ties within a path without reordering across paths, and it saturates.

**D2. Strip the trailing slash in the exact comparison rather than normalizing it
away.** Normalizing `/a/` to `/a` would diverge from the gateway normalizer this
code deliberately mirrors, and that agreement is what keeps PPE's view of a
request the same as the router's that chose its upstream. Stripping inside the
comparison, the way `path_prefix_matches` already does, fixes the miss without
touching what normalization returns or what policy reads.

**D3. Compute the unreachable-authentication answer at load.** It depends only on
the config. Setting the latch unconditionally would fix the repeated scan, but
computing it during the config walk removes the scan from the request path
entirely and puts the answer next to the other load-time route diagnostics.

**D4. Return the matched name by borrow or index.** `matched_http_name` clones
every path a selector declares and discards all but one. The ordering that puts
resolution ahead of the cache lookup is correct and stays; only the allocation
goes.

**D5. Test `needs_rewrite` on the stripped path, not the raw one.** The `?` and
`#` arms currently force the owned branch, which is what drops the query string,
so the fix has to keep the non-absolute early return handing back `raw` byte for
byte, which is documented behavior.

---

## Scope Boundaries

In scope: route scoring for `method:`, duplicate detection for case-variant
methods, exact-path trailing slash, per-half handler install on the route path,
the rename diagnostic, multi-key reporting, the authentication latch, the two
name allocations, and the normalizer allocation.

Out of scope: body plumbing and a per-chunk inspection phase; the pre-existing
glob-route policy-body gap the selector's plan already excluded; Cedar and Rego
annotation paths, which register no annotations today; whether the host supplies
the request line on the response half and at `identity.resolve`, which is the
Praxis side of the contract and gates the observable effect of U2 and U7.

U9 is a decision and a CHANGELOG note in this plan. If it resolves toward a
dedicated hook type, that lands as its own change against the hook authority, not
inside this one.

---

## Implementation Units

- U1. **A method-narrowed route outranks the same path without one**

**Goal:** Two routes on one path, one narrowed by `method:`, resolve the narrower
for the methods it names, in either declaration order.

**Requirements:** R1, R12

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Add a specificity constant for a present `method:`, applied below the
  path-prefix step so it orders within a path rather than across paths.
- Combine it with `saturating_add`. `SPECIFICITY_EXACT_PATH` is `usize::MAX / 2`,
  so an exact path plus a method bonus must not wrap.
- Update the doc comment that currently states method gates without scoring, and
  the PR body sentence claiming order independence.

**Patterns to follow:** the existing specificity constants and the
`saturating_add` already used to total a score.

**Test scenarios:**
- Happy: broad and narrow declared in each order both resolve the narrow route
  for a named method.
- Happy: a request whose method the narrow route does not name resolves the broad
  route.
- Edge: exact path plus `method:` does not overflow and still outranks a prefix.
- Edge: two prefixes of equal length, one narrowed, order deterministically.

---

- U2. **A route installs only the halves it declares**

**Goal:** A body-less `http:` route stops silencing the response-side chain, and
each half installs on the route path the way it does on the global catch-all.

**Requirements:** R4, R12

**Dependencies:** None. Independent of U1; do not share a commit.

**Files:**
- Modify: `crates/ppe-apl-runtime/src/visitor.rs`

**Approach:**
- Reuse `http_catchall_should_install` and `http_catchall_response_should_install`
  on `effective` in `visit_routes`, and guard each `install_handler` with its
  flag. The review attaches this exact change as a patch, which applies cleanly
  to the merge.
- Leave the layer-seeding order alone, so a route with no `apl:` block still
  receives the global policy.
- Treat the entity-route widening as intended and cover it: an entity route
  declaring only pre-phase steps installs no post handler.

**Patterns to follow:** the global catch-all's own two-predicate decision and the
comment above it.

**Test scenarios:**
- Happy: two configs identical but for a catch-all route resolve the same
  response-side chain.
- Happy: a route declaring both halves still installs both.
- Edge: an entity route declaring only pre-phase steps installs no post handler.
- Edge: a body-less route with a global body still receives the global policy on
  the half that declares steps.

---

- U3. **An exact-path route matches its path's equivalent spellings**

**Goal:** `http: /admin` matches `/admin/`, as it already matches `/admin//` and
`/admin/.`.

**Requirements:** R3, R12

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Strip one trailing slash on both sides of the exact-path comparison, the way
  `path_prefix_matches` does (D2). Normalization keeps returning `/a/` verbatim.
- Extend the comment on the trailing-slash normalization test, which currently
  reasons only about prefixes, to say what the exact-path case relies on.

**Test scenarios:**
- Happy: all five spellings of `/admin` resolve the exact route.
- Edge: `/adminx` does not.
- Edge: a declared path written with a trailing slash matches the same set.
- Edge: `/` as an exact path stays distinct from `path_prefix: /`.

---

- U4. **Case-variant method sets are one route**

**Goal:** `method: GET` and `method: get` on the same path fail the load naming
both, rather than both matching with the first silently winning.

**Requirements:** R2

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Uppercase in `rendered_methods` before sorting and deduping, so the rendered
  identity agrees with the case-insensitive matching the runtime does.
- The existing duplicate-selector-identity check then catches the collision with
  no change of its own.

**Test scenarios:**
- Edge: `GET` and `get` on one path fail the load naming both.
- Edge: `GET,POST` and `post,get` are the same identity.
- Happy: a single lowercase `method:` still matches, and renders uppercase.

---

- U5. **A renamed APL key reports its rename**

**Goal:** A route carrying `policy:` gets the rename message, not an unknown-key
error, and a route with three bad keys names all three.

**Requirements:** R5, R6

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Check the renamed-key table before the unknown-key scan, so the more specific
  diagnostic wins.
- Collect unrecognized keys and report them together, matching the validators in
  this file that already do.

**Test scenarios:**
- Edge: `policy:` on a route reports the rename to
  `authorization.pre_invocation`.
- Edge: three unknown keys are all named in one error.
- Edge: a visitor-declared extra key is still accepted.
- Happy: the fail-closed behavior is unchanged; a stale key never loads.

---

- U6. **The authentication-reachability answer is computed at load**

**Goal:** The route-table scan leaves the request path.

**Requirements:** R7

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/engine.rs`

**Approach:**
- Compute the unreachable-authentication set during the config walk, where the
  other load-time route diagnostics live, and have the request path read the
  answer (D3).
- If that proves awkward against the snapshot's shape, the minimal version is
  setting the latch unconditionally once the scan has run, which fixes the
  repetition without moving the work.

**Test scenarios:**
- Edge: a config where no `http:` route declares `authentication:` performs no
  per-request scan, measured with the probe counter.
- Happy: the warning still fires once, naming the same routes.
- Edge: a reload recomputes the answer.

---

- U7. **Resolving a matched name allocates nothing per declared path**

**Goal:** A cached HTTP request stops cloning the selector's path list.

**Requirements:** R8

**Dependencies:** None. Touches the same function as U3; sequence U3 first.

**Files:**
- Modify: `crates/ppe-core/src/config.rs`

**Approach:**
- Return the matched name by borrow, or have the match hand back an index into
  the selector's list, so nothing proportional to the declared paths is built and
  discarded (D4). The resolution-before-cache ordering stays.
- Cover the prefix shape too, where the answer is a single `format!` and the
  current code still builds a vector.

**Test scenarios:**
- Edge: ten identical cached requests against a twenty-path selector allocate no
  per-path names, measured with the probe counter.
- Happy: resolved names are byte-identical to today's for every selector shape,
  which is what keeps annotation keys and cache keys stable.

---

- U8. **A path needing no rewrite is borrowed**

**Goal:** A request carrying a query string stops allocating in normalization.

**Requirements:** R9

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/http_path.rs`

**Approach:**
- Test `needs_rewrite` on the stripped path rather than the raw one and borrow
  that slice (D5). Keep the non-absolute early return handing back `raw`.

**Test scenarios:**
- Edge: `/v1/files/q3.pdf?page=2` borrows rather than allocates, measured with
  the probe counter.
- Happy: every existing normalization case returns the same string, the encoded
  traversal spellings included.
- Edge: a non-absolute path is still returned byte for byte.

---

- U9. **Decide the HTTP hook's payload and status** (decision, then a separate
  change)

**Goal:** A plugin that cannot read what an HTTP hook carries cannot register on
it and report clean, and a response policy can decide on status.

**Requirements:** R10, R11

**Dependencies:** Blocks nothing here. Resolve before hosts write plugins against
the current type.

**Files:**
- Decide only, in this plan. Implementation lands against the hook authority.

**Approach:**
- Option A: give HTTP its own hook type, so an `HookHandler<CmfHook>` scanner
  fails to compile rather than silently passing. One type serves both halves. An
  empty struct rather than `()` leaves room for a body chunk later without
  changing the type twice; `PluginPayload` needs only
  `Clone + Send + Sync + 'static`. Not prototyped.
- Option B: keep `CmfHook`, add a status field, and document on both constants
  that the payload is unused. Closes the expressiveness gap and not the hazard,
  since a doc comment cannot fail a build.
- Either option adds the status field.

**Test scenarios:**
- Under A: a `CmfHook` handler registered on an HTTP hook fails to compile.
- Under either: a response policy denies on a 5xx status.

---

## Unit Dependency Graph

```
U1  U2  U4  U5  U6  U8      independent
U3 ──► U7                   same function; ordering only, not a data dependency
U9                          decision, independent of all of the above
```

Nothing blocks anything else. Suggested order by risk: U2 and U1 first, since
they change behavior and want the most review attention; then U3 and U4; then U5;
then U6, U7, U8, which are cost. U9 is a conversation to have in parallel.

---

## System-Wide Impact

`config.rs` carries five of the nine units, so sequencing them as separate commits
matters more than usual for reviewability.

U1, U3, and U4 move requests from a broader policy to a narrower one. A
deployment relying on the current order-dependence, or on `/admin/` reaching the
global policy, changes behavior. That is the point of the fix and belongs in the
CHANGELOG as a behavior change rather than a bug fix.

U2 reaches entity routes through shared code, which is the widest blast radius
here and the reason it gets its own unit and its own test rather than riding
along.

U6, U7, and U8 are internal. No configuration or public signature changes.

U9, under option A, changes a public hook type while the CHANGELOG is
`[Unreleased]` at 0.1.0.

---

## Risks & Dependencies

- The specificity bonus interacts with a constant already at `usize::MAX / 2`.
  Saturating arithmetic is not optional, and the overflow case needs a test
  rather than an argument.
- U2's observable effect on the response half depends on the host supplying the
  request line there. The probe drives the hook with it present, which is what
  the selector asks hosts to do, so it demonstrates the behavior once Praxis
  complies rather than what Praxis does today. The install-side assertion does
  not depend on the host.
- U6's load-time computation has to survive a reload. Getting it wrong turns a
  once-per-fill-cycle warning into a stale answer, which is worse than the
  repeated scan it replaces.
- U7 must not change any resolved name. Those names key the annotation table and
  the route cache, so a change there is a behavior change wearing a refactor's
  clothes.
- The three instrumentation counters in the probe patch are not tests and must
  come back out before the branch merges.

---

## Open Questions

### Resolved during planning

- Whether to reject overlapping selectors or score the narrower one higher.
  Scoring (D1): rejection refuses configs that load today and whose intent is
  legible.
- Whether to normalize the single trailing slash. No (D2): the gateway agreement
  is load-bearing, and the exact-path comparison can strip it locally.
- Whether the authentication latch fix is a latch fix or a relocation.
  Relocation (D3), with the latch as the fallback if the snapshot shape resists.
- Whether U2 belongs in this pass or behind the body work. This pass: the fix is
  cheap now, and the exposure grows exactly when the body lands.

### Needs a decision before the affected unit starts

- U9, option A or B. A closes the hazard at compile time and changes a public
  type; B closes only the expressiveness gap. Both add status. Cheapest at
  0.1.0.
- U2's entity-route widening. The plan treats it as intended and tests it. If it
  should stay HTTP-only, the guard needs to be conditional on the entity type,
  which is a worse shape and worth avoiding if the widening is acceptable.

### Deferred to implementation

- Whether U7 returns a borrow or an index. Both satisfy R8; the choice falls out
  of what the borrow checker allows against `MatchedRoute`'s lifetimes.
- Whether U6's answer lives on the snapshot or is recomputed by the visitor.

---

## Sources & References

- The selector's own plan: `docs/plans/2026-08-25-001-feat-http-route-selector-plan.md`
- Review discussion, which attaches both patches referenced above:
  https://github.com/praxis-proxy/policy/pull/42
- Local copies of those patches, untracked and not part of the repository:
  `.sketchpad/pr-42-review-probes.patch`, `.sketchpad/pr-42-finding-1-fix.patch`
