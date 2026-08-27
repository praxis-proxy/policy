---
title: "fix: HTTP route matching, install symmetry, and hot-path cost"
type: fix
status: completed
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

A second track gives the HTTP hooks a payload of their own. Both are typed on the
chat-message payload that MCP uses, which the HTTP path never fills, so a
content-scanning plugin written for MCP registers on the response hook, scans a
message the host had to fabricate, finds nothing, and reports clean. An
always-passing scanner is worse than no scanner. The four units there give the
family its own type and names, make plugin dispatch carry that payload rather than
a fabricated message, check the pairing where handlers register, and add the
response status a post-phase policy needs and cannot currently read. A dedicated
type does not fail the bad registration at compile time, which is why the registry
check is a unit of its own rather than a footnote.

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
- R13. The HTTP hooks carry a payload of their own, and it is a struct rather than
  a unit so a body chunk can land in it later without changing the hook type
  twice.
- R14. The HTTP hook names name the family they belong to, and the authority holds
  their rows outside the CMF family's table.
- R15. A policy block an HTTP route's payload cannot serve is refused at load
  rather than silently reading nothing.
- R16. Registering a handler for a hook whose payload it does not accept is
  refused, on the config-driven path as well as the typed one.
- R17. A handler reports the hook family it was built for, rather than a literal
  that happens to be right today.
- R18. A hook registered with permissive metadata accepts a handler of any family,
  so the open hook registry stays open.

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
`HookHandler<CmfHook>`, so it registers on the HTTP response hook, scans the
fabricated message, finds nothing, and reports clean. An always-passing scanner
is worse than no scanner.

There is also no HTTP status code anywhere, on the extension or in the payload,
so a response-phase policy cannot express "deny on 5xx" or "label 4xx". That is
close to the first thing anyone writes at that point.

### A dedicated hook type does not fail that registration at compile time

Worth stating plainly, because it is the reason the work below is four units
rather than one. `register_for_names::<H: HookTypeDef>` takes the hook type and
never consults it:

```rust
pub fn register_for_names<H: HookTypeDef>(..., names: &[&str]) -> Result<(), String> {
    self.register_for_names_inner(plugin, config, handler, names)   // H unused
}
```

`register_for_names_with_handler` drops the type parameter entirely, and its own
doc says why: it is "the config-driven factory path where the hook type is not
known at compile time". That is the path the hazard travels. The PII scanner
wraps `TypedHandlerAdapter::<CmfHook, _>` for every name in `cfg.hooks`, so a
plugin declaring the HTTP response hook in YAML never names a hook type anywhere
a compiler could check it.

So a new type alone closes nothing. What closes it is the type plus a name-to-type
check in the registry, which is why U12 exists. After the hook-authority work the
metadata table is the single place that knows which hooks exist, so it is the
natural place to record which payload each one carries.

### The dispatcher is payload-agnostic above the invoker

`PluginInvoker`, the boundary the evaluator sees, takes a name, an attribute bag,
and an invocation discriminator. No payload crosses it, and it is used as
`Arc<dyn PluginInvoker>` in twenty-five places, so a payload change stays below
the trait object and never reaches `praxis-policy-apl-core`.

Below it the message-specific surface is small and concentrated: one construction
site (`route_handler.rs:253`), one typed dispatch (`cmf_invoker.rs:374`), and
three touchpoints in one method, which read the field before the call, write the
returned payload back, and re-read the field after.

Per-family invokers are already the pattern. `CmfPluginInvoker` dispatches
`invoke_entries::<CmfHook>`, `delegation_invoker` dispatches
`::<TokenDelegateHook>`, and `elicitation_invoker` dispatches
`::<ElicitationHook>`. Making the CMF invoker's dispatch follow the route's hook
type is a smaller change than adding a fourth sibling, and it is what lets a
plugin on an HTTP route receive a payload that does not pretend to hold content.

### Why the payload has to reach the plugin, not just the host

Branching in `AplRouteHandler` to build an empty message would fix the host's
entry call and nothing else. `invoke_entries::<CmfHook>` would still hand every
APL-dispatched plugin a `MessagePayload`, so the scanner referenced by an HTTP
route's policy step would still scan a fabricated message and still report clean.
That relocates the fabrication from the host into PPE rather than removing it.

Making the dispatch follow the route's hook type also makes "this payload has no
fields" expressible, which is what allows an `args:` or `result:` block on an
HTTP route to be refused at load instead of silently reading nothing.

### A body is not a payload field

A response is status, then headers, then chunks, then trailers, so an owned-body
payload forces the proxy to buffer before policy runs: unbounded memory on
attacker-controlled response sizes, and a deadlock rather than a slowdown on SSE,
which is how MCP streams. Body inspection needs a per-chunk phase a plugin opts
into through a capability, with a size cap and deny-on-overflow. That stays out
of scope. The units below only give the family its own type, payload, names, and
status field, while the whole CHANGELOG is `[Unreleased]` at 0.1.0 and the cost is
a search and replace rather than a migration.

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

**D6. The payload reaches the plugin, not just the host.** Branching in
`AplRouteHandler` to synthesize an empty message would fix the host's entry call
and leave `invoke_entries::<CmfHook>` handing every APL-dispatched plugin a
`MessagePayload`, so the scanner referenced by an HTTP route's policy step would
still scan a fabricated message and still report clean. That relocates the
fabrication instead of removing it. Making the typed dispatch follow the route's
hook family is confined below `Arc<dyn PluginInvoker>`, which carries no payload,
so it costs less than the trait-level generalization it looks like.

**D7. Rename the hook names with the type.** A `cmf.` prefix on a hook whose
payload is not CMF is a name that lies, and the loader's nearest-name suggestion
already turns a stale name into a legible error. Config-visible and cheapest while
the CHANGELOG is `[Unreleased]` at 0.1.0.

**D8. Claim a load-time refusal, not a compile-time one.** `register_for_names`
takes a `HookTypeDef` and never consults it, and the config-driven factory path
takes no type at all, which is the path a YAML-declared plugin travels. Nothing
about a new hook type can be enforced by the compiler for that path, so U12
validates the pairing in the registry and the CHANGELOG says load-time.

**D9. The field trait is local to `praxis-policy-apl-runtime`.** Field addressing
needs `DispatchPhase`, which lives in `praxis-policy-apl-core`, and
`praxis-policy-core` is a leaf crate depending on no APL crate. So the method
cannot go on `PluginPayload` without moving an APL concept into the leaf or
duplicating it, and it would also oblige the identity, delegation, and elicitation
payloads to carry a method about args/result projection that means nothing to them.
A local trait is coherent because the trait itself is local, so implementing it for
those payloads is allowed.

**D10. The field trait reads; the write-back stays message-specific.** An HTTP
route cannot declare `args:` or `result:` once U11 refuses it at load, so a
write-back on a fieldless payload is unreachable by construction. Gating the
existing message write-back on "this payload has fields" keeps the trait to one
method and does not add an implementation whose only honest body is unreachable.

**D11. Reuse `hook_type_name()` rather than adding a payload discriminator.**
`AnyHookHandler` already reports the family, and `TypedHandlerAdapter` already
answers `H::NAME`. A `&'static str` also prints in the refusal message, which a
`TypeId` cannot.

**D12. The row records `<Type>::NAME`, not a literal.** The hook name and the hook
type are declared by different macros in different files, so a hand-written family
string is two places that must agree. Writing the const expression ties them, which
is the same reason the name and its metadata row are emitted together.


**D13. The trait carries a default body returning no fields.** A blanket
`impl<T: PluginPayload>` is not available: it conflicts with `MessagePayload`'s real
implementation under E0119, and specialization is unstable. A default method body
gives the same ergonomics, so `HttpPayload`'s implementation is empty and
`MessagePayload` overrides. The bound on the invoker means a new payload still has
to name the trait to be carried at all, so the default is a low-friction choice
rather than a silent one, and the direction it defaults to is the safe one: a
payload wrongly claiming no fields loses a pipeline stage it never had, where the
reverse would hand a plugin a field that does not exist.

**D14. U2's guard fixes entity routes too, in this pass.** Measured rather than
assumed: a `tool:` route listing `plugins: [deny-gate]` alongside a policy body
declaring only pre-phase steps installs a post handler that runs no steps, and that
handler suppresses the route's own plugin chain. Firing the post hook returns
`continue = true` with no violation before the guard and `continue = false` with the
plugin's denial after it. So the operator wrote a plugin onto the route and it never
ran on the post half. That is the same defect as the HTTP case rather than a scope
widening, and leaving it would require conditioning the guard on the entity type,
which puts a special case in the one place the rule should be general and is then
deleted by the follow-up.

The change is one indivisible edit: two predicate bindings and an `if` around each
`install_handler`, inside a loop over every entity type. It cannot be split into an
HTTP commit and an entity commit, so traceability comes from the commit message
naming both effects, a CHANGELOG entry for each, and a test for each. The direction
is fail-closed, since a previously suppressed deny begins denying, and no test in
the suite catches the difference today.

---

## Scope Boundaries

In scope: route scoring for `method:`, duplicate detection for case-variant
methods, exact-path trailing slash, per-half handler install on the route path,
the rename diagnostic, multi-key reporting, the authentication latch, the two
name allocations, the normalizer allocation, and the HTTP hook family's own type,
payload, names, status field, and registration check.

Out of scope: body plumbing and a per-chunk inspection phase; the pre-existing
glob-route policy-body gap the selector's plan already excluded; Cedar and Rego
annotation paths, which register no annotations today; whether the host supplies
the request line on the response half and at `identity.resolve`, which is the
Praxis side of the contract and gates the observable effect of U2 and U7.

The hook-family work is deliberately not a trait-level generalization. Making
`PluginInvoker` generic over the payload is unnecessary, because the trait already
carries no payload, and the MCP dispatch path stays untouched (D6).

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
- Treat the entity-route effect as intended and in scope (D14). It is the same
  defect: an entity route listing plugins alongside a pre-only policy body installs
  an empty post handler that suppresses those plugins, so they never run on the post
  half. The guard un-suppresses them.
- The edit is indivisible, so give the commit message both effects, and write two
  CHANGELOG entries: one for the HTTP response chain, one for entity routes whose
  post-half plugins begin running. Say in the second that a deny there begins
  denying.
- Say it in the PR description too. A reviewer reading a diff titled for an HTTP
  route selector should know before the guard that it reaches MCP dispatch.

**Patterns to follow:** the global catch-all's own two-predicate decision and the
comment above it.

**Test scenarios:**
- Happy: two configs identical but for a catch-all route resolve the same
  response-side chain.
- Happy: a route declaring both halves still installs both.
- Edge: an entity route declaring only pre-phase steps installs no post handler.
- Edge: an entity route listing plugins alongside a pre-only policy body runs those
  plugins on the post half. Assert the denial, not just the install: before the
  guard the post half allows with no violation, and the install flag alone does not
  show that a plugin was being suppressed.
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

- U9. **A response carries its status**

**Goal:** A response-phase policy can decide on the HTTP status the upstream
returned.

**Requirements:** R11

**Dependencies:** None. Independent of U10 through U12 and worth landing first,
since it is the smallest and the only one visible to policy authors.

**Files:**
- Modify: `crates/ppe-core/src/extensions/http.rs`, the attribute-bag walk, and
  the HTTP attribute documentation.

**Approach:**
- Add `status: Option<u16>` to `HttpExtension` beside `response_headers`, with the
  same `skip_serializing_if` treatment the other optional fields get.
- Surface it in the attribute bag as `http.status` so a predicate can read it.
  `None` on the request half, since there is no status yet.
- Document that the host populates it on the response invocation only, the way
  `response_headers` is already documented.

**Patterns to follow:** `response_headers` for the request/response split, and
`method` / `path` for an optional scalar reaching the bag.

**Test scenarios:**
- Happy: a post-phase rule denying on `http.status >= 500` fires for a 502 and
  not for a 200.
- Edge: the request half sees no `http.status` key, and a rule reading it denies
  rather than erroring open.
- Edge: a host that never sets it behaves exactly as today.

---

- U10. **The HTTP family gets its own hook type, payload, and names**

**Goal:** The HTTP hooks stop borrowing a chat-message payload they never fill.

**Requirements:** R10, R13, R14

**Dependencies:** None. U11 and U12 both build on it.

**Files:**
- Modify: `crates/ppe-core/src/extensions/http.rs` or a new sibling for the
  payload, `crates/ppe-core/src/cmf/constants.rs`, `crates/ppe-core/src/hooks/metadata.rs`
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` and the two HTTP test files

**Approach:**
- Add `HttpPayload`, an empty struct rather than `()`, through
  `impl_plugin_payload!`. `PluginPayload` needs only
  `Clone + Send + Sync + 'static`, so the shape is mechanically fine, and a struct
  leaves somewhere for a body chunk to land later without changing the hook type
  twice.
- Declare `HttpHook` with `define_hook!`, payload `HttpPayload`, result
  `PluginResult<HttpPayload>`, one type serving both halves the way `CmfHook`
  serves a dozen names.
- Rename the two hook names to `http.request` and `http.response` and move their
  rows out of the CMF family table into an HTTP one (D7). The constants move with
  them.
- Update the two HTTP test files, which name the hooks about fifty times between
  them, and the visitor's hook-pair mapping.

**Patterns to follow:** `identity/hook.rs`, which pairs a `define_hooks!` row with
a `define_hook!` type for a family of its own, and is the closest existing shape
to what HTTP needs.

**Test scenarios:**
- Happy: both HTTP hooks resolve from the authority with their new names and the
  entity type and phases they had.
- Happy: a host invoking by name with `HttpHook` and an `HttpPayload` reaches an
  HTTP route's policy.
- Edge: the old names are absent from the authority, so a config naming one is
  refused with the nearest-name suggestion the loader already produces.
- Edge: the CMF family table no longer contains an HTTP row, and the count test
  over the authority reflects that.

---

- U11. **Plugin dispatch follows the route's hook type**

**Goal:** A plugin invoked on an HTTP route receives `HttpPayload`, not a
fabricated message, and an `args:` or `result:` block on an HTTP route is refused
at load.

**Requirements:** R10, R15, R17

**Dependencies:** U10

**Files:**
- Modify: `crates/ppe-apl-runtime/src/cmf_invoker.rs`,
  `crates/ppe-apl-runtime/src/route_handler.rs`
- Modify: `crates/ppe-apl-runtime/src/visitor.rs` for the load-time refusal
- Modify: `crates/ppe-apl-runtime/src/lib.rs`, whose crate doc states that "the
  payload type is locked at the impl level" and that `CmfPluginInvoker` "can only
  dispatch to CMF hooks because every internal call goes through
  `invoke_named::<CmfHook>`". This unit makes both sentences false, and it is the
  first thing a reader of the public API sees.

**Approach:**
- Add a trait local to `praxis-policy-apl-runtime` answering one question: what is
  this field's value on this payload, for this phase. `MessagePayload` answers
  through the existing projection; `HttpPayload` answers `None` (D9). The trait
  carries a default body returning no fields, so `HttpPayload`'s implementation is
  empty and `MessagePayload` overrides (D13). The trait
  cannot live on `PluginPayload`: its signature needs `DispatchPhase`, which is in
  `praxis-policy-apl-core`, and `praxis-policy-core` is a leaf crate that depends
  on no APL crate.
- Parameterize the invoker over `H: HookTypeDef` where `H::Payload` implements that
  trait, which supplies both the typed dispatch and the field behavior from one
  parameter. The generic is erased at `Arc<dyn PluginInvoker>`, which carries no
  payload, so `praxis-policy-apl-core` is untouched and MCP's dispatch semantics do
  not move.
- The construction site (`route_handler.rs:253`) picks the concrete hook type from
  the route's entity type. One branch, two monomorphizations, one trait object out.
- Keep the write-back message-specific and gate it on the payload having fields at
  all (D10). Preserve the `field_before` baseline comparison exactly: it exists so
  an earlier pipeline stage's redaction is not undone by a readback, and getting it
  wrong hands pre-redaction plaintext to the next stage.
- `AplRouteHandler::invoke` stops downcasting unconditionally to `MessagePayload`.
  Its current comment asserts the handler "only registers for cmf.* hook names",
  which U10 makes false.
- `AplRouteHandler::hook_type_name` returns the literal `"cmf"`
  (`route_handler.rs:679`). U10 makes that wrong for every HTTP route. Nothing
  validates it today, so this is latent rather than broken, but it is the same
  stale-literal shape the hook authority exists to prevent: have it report the
  family the handler was built for.
- Because the HTTP payload supports no field stages, refuse an `args:` or
  `result:` block on an HTTP route at load rather than letting it read nothing.
  This is a new load-time error and needs its own CHANGELOG line.

**Patterns to follow:** `delegation_invoker` and `elicitation_invoker`, which each
own a typed dispatch for their family. The difference here is that one invoker
serves two families rather than a fourth sibling being added.

**Test scenarios:**
- Happy: a plugin referenced by an HTTP route's policy step receives
  `HttpPayload`, asserted by a fixture plugin that fails if handed anything else.
- Happy: MCP routes keep receiving `MessagePayload`, and the field stages behave
  exactly as they do today. This is the regression surface that matters most.
- Edge: an `args:` block on an HTTP route fails the load naming the route and the
  block.
- Edge: a transform plugin on an HTTP route mutating extensions still has its
  mutation persisted, since header rewriting goes through `modified_extensions`
  rather than the payload.
- Edge: a plugin returning a modified payload of the wrong type is reported
  rather than silently dropped, which is what the current downcast-failure warning
  does.
- Edge: an MCP field pipeline whose earlier stage redacted a value still sees the
  redacted value on readback, not the payload's untouched original. This is the
  `field_before` invariant and the subtlest thing the unit can break.
- Edge: the handler installed for an HTTP route reports the HTTP family rather than
  `"cmf"`.

---

- U12. **Registration checks the payload a hook name expects**

**Goal:** A plugin registering for an HTTP hook with a CMF handler is reported,
rather than passing and reporting clean at runtime.

**Requirements:** R10, R16, R18

**Dependencies:** U10. Independent of U11, though the two together are what make
the guarantee complete.

**Files:**
- Modify: `crates/ppe-core/src/hooks/metadata.rs`, `crates/ppe-core/src/registry.rs`

**Approach:**
- The discriminator already exists. `AnyHookHandler::hook_type_name()` returns the
  family a handler was built for, and `TypedHandlerAdapter<H, P>` returns `H::NAME`
  for it. No `TypeId` and no new handler method are needed (D11).
- Add `family: Option<&'static str>` to `HookMetadata`, written in the
  `define_hooks!` row as `<Type>::NAME` rather than a literal, so the row and the
  hook type cannot drift apart (D12).
- `Option` is load-bearing: `HookMetadata::permissive()` is the const wildcard a
  host opts into, so `None` means "any family accepted". Without that, restoring
  permissive behavior would start failing registrations and the open hook registry
  would close.
- Validate in `register_for_names_inner`, which both the typed and the
  config-driven paths funnel through. The factory path
  (`register_for_names_with_handler`) is the one the hazard actually travels and
  takes no hook type at all today.
- Refuse naming the plugin, the hook, the family the row expects, and the family
  the handler reports. This is a load-time refusal, not a compile-time one: the
  type parameter on `register_for_names` is never consulted and the factory path
  has no type to check, so nothing here can be enforced by the compiler (D8).
- Bound the claim honestly. `annotate_route` is generic over the handler type, not
  a `HookTypeDef`, and inserts into `route_annotations` rather than the hook
  registry, so it does not pass through this check. That is acceptable, because the
  hazard is a plugin registering for an HTTP hook name and plugins arrive through
  the factory path, but the CHANGELOG should not imply the check covers every way a
  handler can reach a hook.

**Patterns to follow:** the hook-name validation the loader already performs
against the authority, and its error phrasing.

**Test scenarios:**
- Edge: a `TypedHandlerAdapter::<CmfHook, _>` registered for an HTTP hook name is
  refused naming the plugin and the hook.
- Edge: the same handler registered for its own CMF names still registers.
- Edge: a host hook registered with its own metadata and its own handler
  registers, so the check does not close the open registry.
- Happy: every reference plugin still loads, since none of them declares an HTTP
  hook today.
- Edge: a hook registered with `permissive()` metadata accepts a handler of any
  family, so the open registry stays open.
- Edge: a route annotation still installs, since it does not travel this path.

---

## Unit Dependency Graph

```
U1  U2  U4  U5  U6  U8  U9    independent
U3 ──► U7                     same function; ordering only, not a data dependency
U10 ──► U11                   dispatch needs the type to dispatch on
    └─► U12                   the registry check needs the payload recorded
```

Within the selector fixes nothing blocks anything else. Suggested order by risk:
U2 and U1 first, since they change behavior and want the most review attention;
then U3 and U4; then U5; then U6, U7, U8, which are cost.

The hook-family units are a separate track. U9 is independent and smallest, so it
can land any time. U10 is a rename plus a type and touches roughly fifty test call
sites, so it wants to land early in its track and alone. U11 and U12 both depend on
it and are independent of each other; U11 carries the MCP regression risk and U12
is what actually closes the registration hazard.

---

## System-Wide Impact

`config.rs` carries five of the nine selector units, so sequencing them as
separate commits matters more than usual for reviewability.

U1, U3, and U4 move requests from a broader policy to a narrower one. A
deployment relying on the current order-dependence, or on `/admin/` reaching the
global policy, changes behavior. That is the point of the fix and belongs in the
CHANGELOG as a behavior change rather than a bug fix.

U2 reaches entity routes through shared code, which is the widest blast radius in
the selector track. An entity route that lists plugins alongside a pre-only policy
body currently suppresses those plugins on the post half; after the guard they run,
and a deny among them begins denying. Fail-closed, and a behavior change to all four
MCP selectors that the CHANGELOG has to name in its own entry rather than fold into
the HTTP one.

U6, U7, and U8 are internal. No configuration or public signature changes.

U9 adds a field to a public extension. Additive, and a host that never sets it is
unaffected.

U10 is the widest change in the plan. It renames two hook names, so a config
naming the old ones is refused, and it changes the hook type a host names when it
invokes them. Both are config- and API-visible, and both are cheapest now: the
CHANGELOG is `[Unreleased]` at 0.1.0, and after hosts have written plugins against
`CmfHook` this becomes a migration rather than a search and replace.

U11 touches the dispatch path every APL route uses, MCP included. Nothing about
the MCP payload changes, but the code that carries it does, which makes the MCP
field-stage tests the regression surface that matters most in this plan.

U12 refuses a registration that succeeds today. No shipped plugin declares an HTTP
hook, so nothing in the tree changes, but a host that registered a CMF handler
for an HTTP hook name now fails at load instead of passing and reporting clean.

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
- U11 is the one unit that can break MCP. The payload it carries is unchanged, but
  every APL route's dispatch runs through the code it edits, and the field-stage
  read-write-reread sequence is subtle: the field baseline exists specifically so
  an earlier stage's redaction is not undone by a readback. Preserve that
  comparison exactly.
- U12 has to leave the open hook registry open. A host declaring its own hook and
  its own handler must still register, so the check can only refuse a pairing the
  authority actually knows to be wrong, never an unrecognized one. `permissive()`
  carrying no family is what makes that hold.
- U12 does not cover `annotate_route`, which inserts into `route_annotations`
  rather than the hook registry and is generic over the handler type rather than a
  `HookTypeDef`. The hazard travels the factory path, so this is a bound on the
  claim rather than a gap in it, and the CHANGELOG should say so.
- The rename in U10 lands in the same release as the hook-name validation from the
  authority work, so an operator upgrading past both gets a refusal naming the new
  name rather than a hook that silently never fires. That is the good outcome and
  worth stating in the CHANGELOG entry.

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
- Whether U2's guard should reach entity routes or stay HTTP-only. It reaches them
  (D14): the measured behavior is a route's own plugins never running on the post
  half, which is the same defect rather than a widening, and scoping it out means a
  special case in shared code that a follow-up deletes.
- Whether the HTTP hooks get their own type or keep `CmfHook` with a documented
  unused payload. Their own type, and the payload reaches the plugin rather than
  only the host (D6). A doc comment cannot fail a load.
- Whether generalizing the dispatch means generalizing `PluginInvoker`. No: the
  trait already carries no payload, so the change stays below the trait object and
  MCP's dispatch semantics are untouched.
- Whether the hook names move with the type. Yes (D7): a `cmf.` prefix on a
  non-CMF payload is a name that lies, and renaming is a search and replace now
  and a migration later.
- Whether a dedicated type closes the registration hazard by itself. No (D8): the
  type parameter on `register_for_names` is unused and the factory path has none,
  so U12 validates the pairing in the registry and the claim is load-time.
- Where U11's field trait lives. In `praxis-policy-apl-runtime`, not on
  `PluginPayload` (D9): the signature needs `DispatchPhase` from
  `praxis-policy-apl-core`, and `praxis-policy-core` depends on no APL crate.
- Whether that trait also owns the write-back. No (D10): an HTTP route cannot
  declare a field stage, so the write-back is unreachable for a fieldless payload
  and stays message-specific behind a gate.
- Whether U12 needs a payload `TypeId` on the row. No (D11): `AnyHookHandler`
  already reports the family and `TypedHandlerAdapter` already answers `H::NAME`,
  and a string prints in the refusal where a `TypeId` cannot.
- Whether the row's family is a literal. No (D12): it is written as `<Type>::NAME`
  so the row and the type cannot disagree.
- Whether `HttpPayload` gets a hand-written no-fields implementation or inherits
  one. It inherits a default body (D13). A blanket impl over every payload is not
  an option: E0119 rejects it against `MessagePayload`'s real implementation, and
  specialization is unstable.

### Needs a decision before the affected unit starts

None. Every choice that changes what gets built is recorded above.

### Deferred to implementation

- Whether U7 returns a borrow or an index. Both satisfy R8; the choice falls out
  of what the borrow checker allows against `MatchedRoute`'s lifetimes.
- Whether U6's answer lives on the snapshot or is recomputed by the visitor.
- What the field trait is called.

---

## Sources & References

- The selector's own plan: `docs/plans/2026-08-25-001-feat-http-route-selector-plan.md`
- Review discussion, which attaches both patches referenced above:
  https://github.com/praxis-proxy/policy/pull/42
- Local copies of those patches, untracked and not part of the repository:
  `.sketchpad/pr-42-review-probes.patch`, `.sketchpad/pr-42-finding-1-fix.patch`
