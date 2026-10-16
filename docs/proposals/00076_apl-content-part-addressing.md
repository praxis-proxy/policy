---
issue: https://github.com/praxis-proxy/policy/issues/76
discussion: >-
  Originally opened as praxis-proxy/policy#76. Design questions were
  discussed in issue comments. Maintainer feedback consolidated into
  this proposal.
status: proposed
authors:
  - aviavissar
graduation_criteria:
  - A route with `match:` entries dispatches field pipelines per
    content part, not per message.
  - Write-back targets the specific content part the view was built
    from, never appending a new text part.
  - A route without `match:` behaves identically to today (backward
    compatible).
  - `iter_views()` has at least one production caller.
  - View attributes (`view.kind`, `view.name`, `view.action`,
    `view.role`, `view.index`) are present in the bag during match
    evaluation.
stakeholders:
  - araujof
  - terylt
---

# APL content-part addressing

## What?

Enable APL routes to target individual content parts within a
multi-part message, instead of treating the whole message as one
flat unit.

A model like Claude returns a response that can contain thinking,
text, and two tool calls — all in one response. Praxis converts
that response into a CMF message — a list of typed content parts.
Today, APL cannot address any of those parts individually.

### Goals

- A `match:` block in a route selects content parts by kind, name,
  or index.
- Field pipelines inside `match:` run per matched content part.
- Write-back targets the specific part, not the first one found.
- View attributes are available in the bag for predicates.
- No breaking changes to existing configs.

### Non-Goals

- Rewriting the CMF message format itself.
- Adding new content-part types.
- Changing how routes select entities (LLM, tool, resource, prompt).

## Why?

### Motivation

`message_projection.rs` extracts one `args` value and one `result`
value per message by taking the **first** tool call, prompt request,
or tool result it finds, and falling back to concatenated text for
everything else. Anything past the first match is invisible to the
policy.

That means:

- No way to say "redact the text part, leave thinking alone."
- No way to say "this rule applies to the second tool call."
- No way to scan each message inside a rendered `PromptResult`.
- Write-back lands on the first text part or appends a new one,
  even when the message held a structured part somewhere else.

The read side of the fix is already written: `MessageView` in
`crates/ppe-core/src/cmf/view.rs` provides a zero-copy, uniform
interface over every content-part variant. `iter_views()` decomposes
a message into individually addressable views. Neither has a
production caller.

### User Stories

- As a policy author, I want to redact PII from the text part of
  an LLM response without touching the thinking part, so that
  debugging information is preserved.
- As a policy author, I want to validate tool call arguments per
  tool call, so that a message with two tool calls can have
  different rules for each.
- As a policy author, I want to scan only the thinking part for
  injection attacks, so that scanning is targeted and efficient.

## How?

### Design principles

This proposal applies five ideas from Ousterhout's
*A Philosophy of Software Design*:

- **Deep module**: `match:` is a shallow config surface (a few
  optional fields). The runtime hides view iteration, projection,
  and write-back internally.
- **Define errors out of existence**: no `match:` = current
  behavior. No match = no-op. Overlapping matches = all run in
  order.
- **Pull complexity downward**: config author writes `kind: text`,
  runtime does the rest.
- **Different layer, different abstraction**: three layers — Route
  (entity), Match (content part), Pipeline (field).
- **Information hiding**: config author never sees `MessageView`,
  `ContentPart`, or projection internals.

### The two-level model

Route-level operations run **once** per message with **shared
state**. Match-level operations run **per matched content part** in
isolation.

<!-- validate: fragment -->
```yaml
routes:
  - llm: "claude-*"

    # --- Route level (once per message, shared state) ---
    authorization:
      pre_invocation:
        - require(authenticated)
        - when: delegation.depth > 3
          deny("delegation chain too deep")

    # --- Match level (per content part, isolated) ---
    match:
      - kind: thinking
        result:
          "": "scan(injection)"

      - kind: text
        result:
          "": "str | redact(pii)"

      - kind: tool_call
        name: "get_compensation"
        args:
          employee_id: "str | type(uuid)"
          salary: "redact"
```

What lives at each level:

| Concern | Level | Why |
|---------|-------|-----|
| `authorization:` / `deny` / `allow` | Route | Needs shared state (bag, taints). A deny must stop everything. |
| `taint(label, scope)` | Route | Accumulates across the message, not per-part. |
| `require_approval()` / elicitation | Route | Protocol uses one shared elicitation ID. |
| `delegate()` | Route | Mints one credential per request, not per-part. |
| `restrict()` | Route | Backend constraint applies to the whole request. |
| `redact` / `mask` / `omit` / `hash` | Match | Per-field, per-part — no cross-part dependency. |
| `scan(injection)` | Match | Scans one part at a time. |
| `type(uuid)` / `length(...)` | Match | Validates one field in one part. |

### Execution order

The existing code already splits evaluation into two phases:
`evaluate_pre` (args + pre_invocation) and `evaluate_post`
(result + post_invocation). Match entries follow the same split.

**Pre-invocation (inside `evaluate_pre`):**

```
1. Route-level authorization (once, shared bag)
   └─ deny or pending elicitation? → halt, skip everything below
2. Route-level args pipeline (once, first-match projection — v0 compat)
3. For each match entry, in declaration order:
   a. Filter message views by matcher
   b. For each matching view:
      i.   Inject view attributes into bag (view.kind, view.name, ...)
      ii.  Project args from this view
      iii. Run the entry's args field pipeline
      iv.  Write back args to the same content part
      v.   deny or pending? → halt the message
4. Route-level pre_invocation effects (once, shared bag)
```

**← invocation happens here (tool runs, LLM responds, etc.) →**

**Post-invocation (inside `evaluate_post`):**

```
5. Route-level result pipeline (once, first-match projection — v0 compat)
6. For each match entry, in declaration order:
   a. Filter message views by matcher
   b. For each matching view:
      i.   Inject view attributes into bag (view.kind, view.name, ...)
      ii.  Project result from this view
      iii. Run the entry's result field pipeline
      iv.  Write back result to the same content part
      v.   deny? → halt the message
7. Route-level post_invocation effects (once, shared bag)
```

### Match semantics

Matcher fields:

| Field | Type | Matches against | Example |
|-------|------|-----------------|---------|
| `kind` | string | `ViewKind` | `text`, `thinking`, `tool_call`, `tool_result`, `resource`, `image` |
| `name` | string or glob | `MessageView::name()` | `"get_compensation"`, `"get_*"` |
| `index` | integer | Position in `message.content` | `0`, `1` |

All fields are optional. Unspecified fields match everything.
Multiple specified fields combine as AND.

How matching works:

1. **All matching entries run**, in YAML declaration order. No
   scoring, no specificity ladder.
2. **Deny halts**: a deny in entry N stops entries N+1, N+2, ...
   from running, and denies the whole message.
3. **No match = no-op**: an entry whose matcher selects zero views
   in a given message is silently skipped.

Addressing "the second tool call": two calls to the same tool in
one turn have the same `name`. `name: "get_weather"` matches both.
`index: 3` matches a specific position. `name` + `index` combine
as AND. For v1, `name` is the primary mechanism and `index` is the
escape hatch.

### Interaction with entity routes

A route selects an **entity** (`llm`, `tool`, `resource`, `prompt`,
`http`). A `match:` block selects **content parts within that
entity's message**. These are different scoping levels.

Example: Claude decides to call `get_compensation`.

<!-- validate: fragment -->
```yaml
routes:
  # Tool route — fires first, at tool invocation time
  - tool: "get_compensation"
    authorization:
      pre_invocation:
        - jwt-token

  # LLM route — fires later, when the LLM response arrives
  - llm: "claude-*"
    match:
      - kind: tool_call
        name: "get_compensation"
        args:
          salary: "redact"
```

The **tool route** fires first — it decides whether the tool is
allowed to run at all. If denied, everything stops here.

The **LLM route** fires later — after the tool runs and Claude
produces a response. It inspects what Claude *said* and modifies
it before it reaches the user. For example, redacting a salary
field.

Note: the order in the YAML file does not determine execution
order. Each route fires at a different time based on its hook type.

### View attributes in the bag

Each match iteration injects the current view's properties into
the attribute bag:

| Bag key | Source | Example value |
|---------|--------|---------------|
| `view.kind` | `ViewKind` | `"text"`, `"tool_call"` |
| `view.name` | `MessageView::name()` | `"get_compensation"` |
| `view.action` | `ViewAction` | `"execute"`, `"generate"` |
| `view.role` | `Role` | `"assistant"`, `"user"` |
| `view.index` | Position in content list | `0`, `1`, `2` |

The bag mechanism already supports arbitrary keys and the predicate
evaluator already handles dotted paths. Injecting view attributes
requires no new config syntax — only a `with_view()` call on
`BagBuilder`. The `match:` config block becomes syntactic sugar
over bag-based predicates.

### Write-back

Write-back is the step where modified data is written back into
the message after a pipeline has processed it.

Today, `write_args_back_to_message` and
`write_result_back_to_message` target the **first** matching
content part. With per-view dispatch, write-back must target the
**specific** part the view was built from.

`MessageView` already borrows the underlying `ContentPart` by
reference. The view's position in `message.content` (its index)
is the write-back address. The new per-view projection functions:

```
extract_args_from_view(view)  → Value
extract_result_from_view(view) → Value
write_args_to_view(message, view_index, value)
write_result_to_view(message, view_index, value)
```

These complement — not replace — the existing per-message
functions. Routes without `match:` continue to call the v0
projections.

The current code appends a new `ContentPart::Text` when no text
part exists. The per-view path never does this — it writes to the
part the view was built from, or nowhere. An appended text part
on a message that originally held a structured part is the exact
bug this feature exists to fix.

### Requirements

- `CompiledRoute` gains a `matches: Vec<MatchEntry>` field.
- New `MatchEntry` struct with optional `kind`, `name`, `index`
  filters plus `args` / `result` field rules and `effects`.
- `AplRouteHandler::evaluate` gains a match loop after route-level
  evaluation.
- `BagBuilder` gains a `with_view()` method for injecting view
  attributes.
- `visitor.rs` parses `match:` from YAML config. The `match:` key
  must be extracted from the route block before calling
  `compile_policy_block_value`, which does not recognize it.
- Per-view projection functions in `message_projection.rs`.

### Design

`CompiledRoute` (ppe-apl-core/src/rules.rs):

```rust
pub struct CompiledRoute {
    // ... existing fields ...

    /// Content-part match entries. Empty = v0 behavior.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<MatchEntry>,
}
```

`MatchEntry`:

```rust
pub struct MatchEntry {
    pub kind: Option<ViewKind>,
    pub name: Option<StringOrGlob>,
    pub index: Option<usize>,
    pub args: Vec<FieldRule>,
    pub result: Vec<FieldRule>,
    pub effects: Vec<Effect>,
    pub source: String,
}
```

`BagBuilder::with_view()`:

```rust
impl BagBuilder {
    pub fn with_view(mut self, view: &MessageView, index: usize) -> Self {
        self.bag.set("view.kind", view.kind().to_string());
        if let Some(name) = view.name() {
            self.bag.set("view.name", name);
        }
        self.bag.set("view.action", view.action().to_string());
        self.bag.set("view.role", view.role().to_string());
        self.bag.set("view.index", index.to_string());
        self
    }
}
```

Match loop pseudocode (runs in both `evaluate_pre` and
`evaluate_post`, processing args or result respectively):

```
for entry in route.matches:
    views = iter_views(message, hook, extensions)
    matched = filter(views, entry.matcher)
    for (index, view) in matched:
        bag_with_view = bag.clone().with_view(view, index)
        value = extract_from_view(view, phase)  // args in pre, result in post
        eval = run_field_pipeline(entry, value, bag_with_view, phase)
        taints.extend(eval.taints)              // merge into message-level accumulator
        write_back_to_view(message, index, value, phase)
        if eval.deny or eval.pending: halt      // taints survive even on halt
```

### Migration and backward compatibility

| Scenario | Behavior |
|----------|----------|
| Existing route, no `match:` | Exactly the same as today. v0 projection, first-match. |
| New route with `match:` only | Per-view dispatch for content operations. |
| New route with both `authorization:` and `match:` | Authorization runs first (route level), then match entries. |
| `args:` / `result:` at route level alongside `match:` | Route-level pipelines use v0 projection. Match entries use per-view projection. Both can coexist. |

No existing config breaks. No new flags or migration steps.

### Testing strategy

Unit tests:

- `MatchEntry` filtering: kind-only, name-only, index-only, AND
  combinations, no-match.
- Per-view projection: extract/write-back round-trips for each
  content-part variant.
- Bag enrichment: verify `view.kind`, `view.name`, etc. are
  present during match evaluation.

Integration tests:

- Deny inside a match halts the whole message.
- Field-level rewrite lands on the correct content part (not the
  first one, not an appended one).
- Multi-part message: assistant turn with thinking + text + two
  tool calls.
- `PromptResult` with several messages.
- Overlapping match entries both run in order.

Backward compatibility tests:

- Every existing e2e test passes without modification.
- A route with `match: []` (empty) behaves identically to no
  `match:`.

### Open questions

| # | Question | Proposed answer | Status |
|---|----------|-----------------|--------|
| 1 | Should `match:` support `authorization:` / `deny` inside entries? | Yes, but a deny in a match entry denies the whole message. | Proposed |
| 2 | Should taint inside a match entry scope to the part or the message? | Message — taints are message-level by design. | Proposed |
| 3 | Should `match:` support `parallel:` blocks? | No for v1 — complexity without clear benefit. | Proposed |
| 4 | Glob syntax for `name` — same as route selectors? | Yes, reuse `StringOrGlob` from the config parser. | Proposed |
| 5 | Should `index` be 0-based or 1-based? | 0-based, matching Rust/JSON convention. | Proposed |

### Suggested PR breakdown

1. **PR 1 — Data structures**: `MatchEntry`, `CompiledRoute.matches`,
   `ViewMatcher` logic, unit tests.
2. **PR 2 — Runtime**: per-view projection, match loop in
   `AplRouteHandler`, bag enrichment, `iter_views` gains production
   callers. Note: the proxy host adapter (praxis repo) must also
   preserve content-part identity instead of folding tool-response
   text into one block, and support `PromptResult` projections for
   per-part write-back. That is a companion PR in the praxis repo.
3. **PR 3 — Config parsing**: `visitor.rs` reads `match:` from YAML,
   validation, config-level tests.
4. **PR 4 — E2E tests + docs**: integration tests, backward-compat
   tests, DSL spec update.
