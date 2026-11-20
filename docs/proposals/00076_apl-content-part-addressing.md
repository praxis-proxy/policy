---
issue: https://github.com/praxis-proxy/policy/issues/76
discussion: >-
  Originally opened as praxis-proxy/policy#76. Design questions were
  discussed in issue comments. Maintainer findings on the proposal
  are decided in this revision.
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
    evaluation, and `args.*` / `result.*` in that bag come from the
    matched part.
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
- A match entry can also make a policy decision about that part.
- Write-back targets the specific part, not the first one found.
- View attributes, and that part's own `args` or `result`, are
  available in the bag for predicates.
- No breaking changes to existing configs.

### Non-Goals

- Rewriting the CMF message format itself.
- Adding new content-part types.
- Changing how routes select entities (LLM, tool, resource, prompt).
- Addressing messages nested inside `PromptResult`. That needs a
  nested address and an evaluation model this proposal does not
  define. Issue #76 stays open for that case until a follow-up
  specifies both. This proposal does not resolve it.

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
  That case stays on #76; it is not delivered here.
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
- As a policy author, I want to deny a tool call the model proposed
  unless the caller has `role.hr`, so that per-part addressing can
  govern a part and not only rewrite it.

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
state**. Match-level operations run **per matched content part**.
A match entry sees only that part. Decisions from every entry
combine with the route decision under deny-overrides: a deny in
any entry denies the whole message, and a per-part allow does not
override a route-level deny.

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

    # --- Match level (per content part) ---
    match:
      - kind: thinking
        result:
          text: "injection.scan"

      - kind: text
        result:
          text: "str | pii.redact"

      - kind: tool_call
        name: "get_compensation"
        # The model proposes this call in its response, so the
        # decision runs on the post side. The args rules still run
        # because the part is a tool_call.
        authorization:
          post_invocation:
            - when: not role.hr
              deny("hr role required")
        args:
          employee_id: "str | uuid"
          salary: "redact"
```

`authorization:` is the YAML name of the `pre_invocation` /
`post_invocation` effect list. It is not a separate phase. The same
shape is legal on a route and on a match entry.

What lives at each level:

| Concern | Level | Why |
|---------|-------|-----|
| `authorization:` (`require` / `deny` / `when`, and PDP steps `cedar` / `cel` / `opa`) | Route and match | The route decision sees the message bag. A match entry's block sees the per-view bag, so `view.name`, `view.kind`, and that part's own `args.*` or `result.*` are in scope. Deny-overrides across both levels. |
| `taint(label, scope)` | Route and match | Legal inside a match entry. Taints accumulate on the message, not on the part. |
| `require_approval()` / elicitation | Route and match | The protocol carries one elicitation id per request. Every part that asks is covered by that one elicitation. v1 does not mint a separate id per part. |
| `delegate()` | Route only | Mints one credential per request. A match entry that contains it is a load error. |
| `restrict()` | Route only | The backend constraint applies to the whole request. A match entry that contains it is a load error. |
| `redact` / `mask` / `omit` / `hash` | Match | Per-field, per-part. |
| `injection.scan` | Match | Scans one part at a time. |
| `uuid` / `len(...)` | Match | Validates one field in one part. |

A field pipeline still denies only when a value fails validation
(type, length, range, enum, regex, `validate`, or a plugin's own
denial). Governing the caller or the part as a whole is the match
entry's `authorization:` block, not the field pipeline.

### Who runs the loop

`evaluate_pre` and `evaluate_post` stay in `ppe-apl-core`
(`crates/ppe-apl-core/src/route.rs`). They take a flat
`RoutePayload` — one `args` value and one `result` value — and
never a `Message`. `ppe-apl-core` stays free of `ppe-core`, so it
has no views to iterate. The match loop cannot live inside those
functions.

The loop lives in the runtime, in `AplRouteHandler`
(`ppe-apl-runtime`). That handler already holds the `Message`. For
each matched view it builds a `RoutePayload` from that view and
calls one core function that runs a single set of field rules.

That function is `evaluate_field_rules` in
`ppe-apl-core::route`. It is the field-rule loop factored out of
`evaluate_pre` / `evaluate_post`. Both paths call it.
`evaluate_pre` / `evaluate_post` stay the no-match composition:
field rules, then route authorization, with no view loop. A handler
that has a message does not call them as one shot. It calls the
same pieces itself, with the match loop between the field rules and
the route authorization.

The runtime owns merging the per-view results into one phase
decision: any deny denies the message, a pending elicitation
suspends it when nothing denied, taints accumulate, and
`args_modified` / `result_modified` are set if any view's field
rules changed a value.

### Execution order

Field rules run before the policy phase, which is the order in
`evaluate_pre` today: the `args` loop finishes, then
`evaluate_effects` runs `route.pre_invocation` (`route.rs`, the
`evaluate_effects` call after the args loop). Match entries sit in
the same place a second field-rule pass would: after the
route-level field rules, and before route-level
`pre_invocation` / `post_invocation`.

Stated once. The post side uses `result` and `post_invocation`
where the pre side uses `args` and `pre_invocation`.

```
1. Route-level field rules (once, v0 first-match projection)
   └─ evaluate_field_rules on route.args (pre) or route.result (post)
2. Match entries, in layer order then declaration order
   └─ for each entry, enumerate message.content, then filter
      for each matching view:
        a. Build the per-view bag and the per-view RoutePayload
        b. evaluate_field_rules on this part
           (args rules or result rules; see below)
        c. This entry's authorization
           (pre_invocation on the pre side, post_invocation on the post side)
           against the per-view bag
        d. deny? → halt the message
           approval requested? → record the part; do not dispatch yet
   After the entries, nothing has been minted or dispatched.
3. Route-level authorization, decision only (once, shared bag)
   └─ this is route.pre_invocation (pre) or route.post_invocation (post)
   └─ no credential is minted and no elicitation is dispatched
   └─ deny? → halt the message immediately
4. If the route asked for approval, add that to the parts recorded
   in step 2. One elicitation covers the route and every recorded
   part. Pending suspends the phase. delegate() mints only when
   the phase allows and nothing is pending.
```

Step 3 is the only route-level authorization pass. It is not also
step 1. It is a decision, not the side effect: a match denial or a
route denial both happen before `delegate()` mints a credential and
before any elicitation is sent.

Which rule block a matched part uses follows the part's content
type, not the hook phase:

- A `tool_call` (and a `prompt_request`) runs the entry's `args:`
  rules. A tool call that appears in an LLM response is still a
  `tool_call`, so it runs `args:` even though the message is a
  response.
- A `tool_result` runs the entry's `result:` rules.
- Text and thinking are not tool parts. On the pre side they run
  the entry's `args:` rules. On the post side they run `result:`.

Match entries read the original part. They do not see route-level
rewrites. `route_payload` stays the v0 projection. The per-view
baseline is taken from the message before either pass changes it.
The route-level fold runs first, then the per-index merge. Both are
path diffs from that original baseline, so a change is applied once.
When a route rule and a match entry change the same field, the
match entry's value wins. A route edit to a field the match entry
left alone is kept.

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

1. **Enumerate, then filter.** `view.index` and the write-back
   address are the position in `message.content`. The loop counts
   that position before the matcher drops non-matching parts. A
   message whose first part does not match must not number the
   first match as `0`.
2. **All matching entries run**, in layer order and then YAML
   declaration order. No scoring, no specificity ladder.
3. **Deny halts**: a deny in entry N stops entries N+1, N+2, ...
   from running, and denies the whole message.
4. **No match = no-op**: an entry whose matcher selects zero views
   in a given message is silently skipped.

Addressing "the second tool call": two calls to the same tool in
one turn have the same `name`. `name: "get_weather"` matches both.
`index: 3` matches a specific position in `message.content`.
`name` + `index` combine as AND. For v1, `name` is the primary
mechanism and `index` is the escape hatch.

### Layering

`match:` is allowed on a `global`, `default`, tag, or route block.
"Scan every thinking part" is a global rule.

`CompiledRoute::apply_layer` (`crates/ppe-apl-core/src/rules.rs`)
already appends `pre_invocation` / `post_invocation` and replaces
`args` / `result` per field. Match entries append, like effects.
There is nothing to replace: every matching entry runs. Each layer
is applied least-specific first, so the effective list is global,
then default, then tag, then route.

### Interaction with entity routes

A route selects an **entity** (`llm`, `tool`, `resource`, `prompt`,
`http`). A `match:` block selects **content parts within that
entity's message**. These are different scoping levels.

Example: Claude decides to call `get_compensation`.

<!-- validate: fragment -->
```yaml
routes:
  # Tool route — fires when the generated call is invoked
  - tool: "get_compensation"
    authorization:
      pre_invocation:
        - jwt-token

  # LLM route — sees the generated call in the LLM output
  - llm: "claude-*"
    match:
      - kind: tool_call
        name: "get_compensation"
        args:
          salary: "redact"
```

The **LLM route** sees the generated tool call before the tool is
invoked. Its `args:` rules run because the part is a `tool_call`,
including when that part arrives on the LLM response. The **tool
route** then decides whether that invocation is allowed.

Note: the order in the YAML file does not determine execution
order. Each route fires at a different time based on its hook type.

### View attributes in the bag

The handler flattens the v0 first-match projection into the bag
before evaluation (`extract_args` / `extract_result` in
`route_handler.rs`). A match entry must not inherit that
projection. `bag_with_view` clones the message bag, removes every
`args` / `args.*` key or every `result` / `result.*` key for the
side this part uses, writes the view's own projection in their
place, and then adds `view.*`.

A predicate such as `redact when args.amount > 1000` on the second
tool call then reads that call's amount. A field present only on
the first call is absent. Two calls with different amounts are the
regression case, including a field that exists only on the first.

| Bag key | Source | Example value |
|---------|--------|---------------|
| `view.kind` | `ViewKind` | `"text"`, `"tool_call"` |
| `view.name` | `MessageView::name()` | `"get_compensation"` |
| `view.action` | `ViewAction` | `"execute"`, `"generate"` |
| `view.role` | `Role` | `"assistant"`, `"user"` |
| `view.index` | Position in `message.content` (integer) | `0`, `1`, `2` |
| `args.*` or `result.*` | This view's projection, replacing the message-level keys | the second call's `amount` |

The bag mechanism already supports arbitrary keys and the predicate
evaluator already handles dotted paths. `view.index` must be an
integer so numeric predicates work. The `match:` config block
becomes syntactic sugar over bag-based predicates.

### Scalar parts

A text or thinking part projects to a JSON object, `{"text":
"..."}`, not to a bare string. The field path is `text`. The same
shape is what Praxis already uses for a non-JSON tool result, and
it matches the object projection planned for resources and prompt
results (#305). Every projection the field expander sees is then
an object, so `text` resolves on every text-like kind.

An empty field path (`""`) does not run. `segment_get`
(`route.rs`) returns nothing for any segment of a non-object, so
today the expander emits no path and the pipeline is skipped. The
loader rejects `""` in any field pipeline, match or route. It is a
load error, not a no-op.

<!-- validate: fragment -->
```yaml
match:
  - kind: text
    result:
      text: "str | pii.redact"
  - kind: thinking
    result:
      text: "injection.scan"
```

### Plugins

A field stage today hands the plugin the whole payload.
`PayloadFields::field_value` (`payload_fields.rs`) then reads the
field back through the v0 first-match projection. On a match entry,
`pii.redact` with `kind: text` would see the thinking part and the
sibling tool calls, and the readback would compare against the
first tool call or the concatenated text. On the write side,
`CmfPluginInvoker::invoke` replaces the request's shared payload
with the plugin's returned payload (`*self.payload.lock().await =
modified.clone()` in `cmf_invoker.rs`).

Match-entry field stages use a per-part dispatch mode. The plugin
itself does not change: same hook, same `MessagePayload`.

1. Take the part at the view's content index out of the shared
   message.
2. Wrap it as a one-part message with the same role.
3. Invoke the plugin with that message. The plugin does not see
   sibling parts. That isolation is what the redaction stories
   want. A plugin that needs the whole turn is a route-level stage
   and keeps today's whole-payload dispatch.
4. Splice the returned part back at the same index. If its kind
   differs, or its name differs when the view has a name, fail
   closed and do not write.
5. Read the field back through the per-view projection, not
   through the first-match projection.

`PluginInvocation::Field` (`ppe-apl-core/src/step.rs`) carries the
content index so the invoker knows which part it took out. Route-level
field stages leave the index unset and keep the current behavior.

The proposal's runtime work and the host work are the same change
#305 depends on. The Praxis adapter folds a tool response's text
blocks into one, and builds response parts only for `tools/call`.
Per-part write-back needs that adapter to preserve content-part
identity. Plan that Praxis change once for both proposals.

### Write-back

Write-back is not an assignment inside the match loop. The handler
takes a baseline projection of each matched view before that view's
field rules run. Plugins may then mutate the message, including the
spliced part above. After evaluation, the handler folds only the
paths the pipeline changed into the plugin-mutated part with
`apply_changed_paths` (`route_handler.rs`), the same merge the
route-level path uses so a plugin edit to a different key is not
clobbered. The merge is per content index, at the end of the phase.

Before writing, the part at that index must still have the view's
kind, and its name when the view has one. A plugin that inserted or
removed a part shifts every later index. A mismatch fails closed
rather than writing into a neighbour.

The per-view projection functions:

```
extract_args_from_view(view)    → Value   // object, {"text": ...} for text-like parts
extract_result_from_view(view)  → Value
```

The write lands through the per-index merge, not through
`write_args_back_to_message` / `write_result_back_to_message`. Those
still target the first matching part and remain the v0 path.
Routes without `match:` keep calling them.

The current v0 code appends a new `ContentPart::Text` when no text
part exists. The per-view path never does this. It writes to the
part the view was built from, or it fails closed. An appended text
part on a message that originally held a structured part is the
exact bug this feature exists to fix.

### Requirements

- `CompiledRoute` gains a `matches: Vec<MatchEntry>` field.
  `apply_layer` appends it in layer order.
- New `MatchEntry` struct with optional `kind`, `name`, `index`
  filters, `args` / `result` field rules, and `pre_invocation` /
  `post_invocation` effect lists compiled from the entry's
  `authorization:` block.
- The loader rejects `delegate()` and `restrict()` inside a match
  entry, and rejects an empty field path in any pipeline.
- Match `args` and `result` rules contribute to
  `CompiledRoute::declared_phases()`; `visitor.rs` installs the
  corresponding handlers even when a route has no route-level rules.
- `evaluate_field_rules` is public in `ppe-apl-core`.
  `evaluate_pre` / `evaluate_post` call it for the route-level
  field rules. They do not grow a view loop.
- `AplRouteHandler` owns the match loop, in the order in
  "Execution order". It builds one `RoutePayload` per view, calls
  `evaluate_field_rules`, runs the entry's authorization against
  the per-view bag, and merges the decisions.
- `bag_with_view` replaces `args.*` or `result.*` with the view's
  projection and adds `view.*`.
- `CmfPluginInvoker` grows the per-part dispatch mode.
  `PluginInvocation::Field` carries the content index.
- `visitor.rs` parses `match:` from YAML config. The `match:` key
  must be extracted from the route block before calling
  `compile_policy_block_value`, which does not recognize it. The
  same key is legal on `global`, `default`, and tag blocks.
- Per-view projection functions in `message_projection.rs`.

### Design

`CompiledRoute` (ppe-apl-core/src/rules.rs):

```rust
pub struct CompiledRoute {
    // ... existing fields ...

    /// Content-part match entries. Empty = v0 behavior.
    /// Appended by apply_layer, global first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<MatchEntry>,
}
```

`MatchEntry`:

```rust
pub struct MatchEntry {
    pub kind: Option<ContentKind>,
    pub name: Option<String>,
    pub index: Option<usize>,
    pub args: Vec<FieldRule>,
    pub result: Vec<FieldRule>,
    /// Compiled from the entry's `authorization:` block.
    /// `delegate` and `restrict` are rejected at load.
    pub pre_invocation: Vec<Effect>,
    pub post_invocation: Vec<Effect>,
    pub source: String,
}
```

`ContentKind` is an APL-owned enum with the same snake-case values
as `ViewKind`. The runtime maps `MessageView::kind()` to it, keeping
`ppe-apl-core` independent of `ppe-core`. The visitor validates
`name` as an exact name or glob when loading config.

The CMF bridge builds the per-view bag. `clear_prefix` removes the
message-level `args` / `args.*` or `result` / `result.*` keys before
the view's own projection is written, so a field that exists only on
another part does not survive:

```rust
fn bag_with_view(
    base: &AttributeBag,
    view: &MessageView<'_>,
    index: i64,
    projection: &Value,
    side: Side,
) -> AttributeBag {
    let mut bag = base.clone();
    bag.clear_prefix(side.prefix());          // "args" or "result"
    project_into_bag(side, projection, &mut bag);
    bag.set("view.kind", kind_name(view.kind()));
    if let Some(name) = view.name() {
        bag.set("view.name", name);
    }
    bag.set("view.action", action_name(view.action()));
    bag.set("view.role", role_name(view.role()));
    bag.set("view.index", index);
    bag
}
```

The name helpers emit the enums' snake-case config values. Convert
the content position to `i64` with a checked conversion before
building the bag; an out-of-range index fails closed.

Match loop pseudocode. This runs in `AplRouteHandler`, not in
`evaluate_pre` / `evaluate_post`. `phase` selects the route-level
side. The part's content type selects the entry's rule block.

```
// 1. Route-level field rules.
route_payload = project_message_v0(message, phase)
route_baseline = clone(route_payload)
route_fields = evaluate_field_rules(route.field_rules(phase), route_payload, bag)
merge(route_fields)                          // taints, modified flags
if route_fields.deny: halt

// 2. Match entries. Enumerate content index before filtering.
for entry in route.matches:                  // global, default, tag, route
    for (index, view) in enumerate(iter_views(message, hook, extensions)):
        if not entry.matcher.accepts(view): continue
        if message.content[index] is not still view.kind/name: fail closed
        // First entry to touch this index keeps the pre-evaluation baseline.
        // A later entry starts from the previous entry's projection, so it
        // sees that entry's field edits.
        // Original content only. route_payload is not copied onto the view.
        // The first baseline stays the pre-evaluation part, so the final
        // per-index merge does not apply a route edit and a match edit twice.
        if index not in baseline:
            baseline[index] = project_view(view)   // text-like → {"text": ...}
        projection = evaluated[index] if index in evaluated else baseline[index]
        view_bag = bag_with_view(bag, view, checked_i64(index), projection, side_for(view))
        part_payload = RoutePayload::from(projection, side_for(view))
        fields = evaluate_field_rules(entry.field_rules(side_for(view)), part_payload, view_bag)
        merge(fields)
        if fields.deny: halt                 // taints survive
        auth = evaluate_effects(entry.authorization(phase), view_bag, part_payload)
        merge(auth)
        if auth.deny: halt
        if auth.pending: record(index)      // dispatch once, after the entries
        evaluated[index] = part_payload

// 3. Route authorization, decision only. No mint, no dispatch.
auth = evaluate_effects(route.authorization(phase), bag, route_payload, decision_only=true)
merge(auth)
if auth.deny: halt                       // nothing has been minted or sent
if auth.pending: record_route()

// One elicitation for the route and every part that asked. Then suspend.
// delegate() mints only when nothing denied and nothing is pending.
if recorded:
    dispatch one elicitation covering the route request and every recorded part
    suspend the phase
else:
    commit route side effects              // delegate() may mint now

// Route-level field edits still fold through the existing
// apply_changed_paths(route_baseline → route_payload) path.
// That fold uses the original route baseline. The per-index merge
// below uses baseline[index], also taken from the original part.
// Same field changed by both: the match value wins. Route-only
// fields are kept. Each path is applied once.

// After the phase: per-index merge. Not inside the loop.
for index in evaluated:
    if message.content[index] is not still that view's kind/name: fail closed
    current = project_part(message.content[index])
    merged = apply_changed_paths(current, baseline[index], evaluated[index])
    write merged onto message.content[index]
```

A field plugin invoked from `evaluate_field_rules` for a match entry
uses the per-part dispatch mode. It splices that one part back during
the call. The end merge then folds only the pipeline's changed paths
onto whatever the plugin left at that index.

### Migration and backward compatibility

| Scenario | Behavior |
|----------|----------|
| Existing route, no `match:` | Exactly the same as today. v0 projection, first-match. `evaluate_pre` / `evaluate_post` call `evaluate_field_rules` and then the route authorization. |
| New route with `match:` only | The handler runs match entries after the empty route-level field rules and before route authorization. |
| New route with both `authorization:` and `match:` | Route-level field rules, then match entries. Route authorization is then decision-only. A deny halts before any mint or dispatch. Route and match approvals become one elicitation. |
| `args:` / `result:` at route level alongside `match:` | Route-level pipelines use the v0 projection. Match entries read the original part, not `route_payload`. The route fold runs first; the per-index merge runs second. The match value wins on a field both changed. |
| `match:` on `global` / `default` / tag | Entries append ahead of the route's own entries. |

No existing config breaks. An empty field path, or `delegate()` /
`restrict()` inside a match entry, is a new config and fails at
load. No new flags or migration steps.

### Testing strategy

Unit tests:

- `MatchEntry` filtering: kind-only, name-only, index-only, AND
  combinations, no-match.
- `view.index` is the content position when a non-matching part
  comes first. Enumerate, then filter.
- Match-only routes install Pre and/or Post handlers for their
  declared field pipelines.
- Per-view projection: extract round-trips for each content-part
  variant. Text and thinking project as `{"text": ...}`, and a
  `text` pipeline runs on both.
- An empty field path is a load error.
- `delegate()` and `restrict()` inside a match entry are load
  errors.
- Bag: two tool calls with different amounts, and a field present
  only on the first. The second view's predicate reads the second
  amount and does not see the first call's extra field.
- `apply_layer` appends match entries, global first.

Integration tests:

- Deny inside a match halts the whole message. A per-part allow
  does not override a route-level deny.
- A match denial happens before route authorization, so
  `delegate()` has not minted a credential and `require_approval()`
  has not dispatched.
- Field-level rewrite lands on the correct content part (not the
  first one, not an appended one). The second part changes and the
  first is untouched.
- The rewrite is an `apply_changed_paths` merge after evaluation.
  A plugin edit to a different key on that part survives.
- A plugin stage on `kind: text` does not read or rewrite the
  thinking part or a sibling tool call. The returned part is
  spliced at the same index. A returned part whose kind or name
  differs fails closed.
- Multi-part message: assistant turn with thinking + text + two
  tool calls.
- A `tool_call` inside an LLM response runs the entry's `args:`
  rules.
- Overlapping match entries both run in order. A global entry runs
  before a route entry.
- Several parts asking for approval, and a route-level approval,
  produce one elicitation. A route deny sends nothing and mints
  nothing.

Backward compatibility tests:

- Every existing e2e test passes without modification.
- A route with `match: []` (empty) behaves identically to no
  `match:`.

### Open questions

| # | Question | Answer | Status |
|---|----------|--------|--------|
| 1 | Should `match:` support `authorization:` / `deny` inside entries? | Yes. Same `pre_invocation` / `post_invocation` shape as a route. A deny in any entry denies the message. Decisions combine deny-overrides. | Decided |
| 2 | Should taint inside a match entry scope to the part or the message? | Message. Taint is allowed in a match entry and accumulates on the message. | Decided |
| 3 | Should `match:` support `parallel:` blocks? | No for v1 — complexity without clear benefit. | Proposed |
| 4 | Glob syntax for `name` — same as route selectors? | Yes, validate the pattern at load and use the same glob syntax. | Proposed |
| 5 | Should `index` be 0-based or 1-based? | 0-based, matching Rust/JSON convention. It is the position in `message.content`. | Decided |
| 6 | How does `args:` target a tool call produced in an LLM output? | By content type. A `tool_call` runs `args:` wherever it appears, including in an LLM response. A `tool_result` runs `result:`. | Decided |
| 7 | Does v1 address messages inside `PromptResult.messages`? | No. This proposal does not resolve it. #76 stays open until a follow-up specifies the nested address and the evaluation model. | Deferred |
| 8 | May a match entry drop one disallowed, not-yet-executed tool call instead of denying the whole message? | Half a message cannot be forwarded for most parts. An unexecuted tool call is the case where removing the part is meaningful. v1 denies the message. | Open |

### Suggested PR breakdown

1. **PR 1 — Data structures**: `MatchEntry`, `CompiledRoute.matches`,
   `apply_layer` append, `declared_phases()`, `ViewMatcher` logic,
   `evaluate_field_rules`, load errors for `""` / `delegate` /
   `restrict`, unit tests.
2. **PR 2 — Runtime**: per-view projection, the match loop in
   `AplRouteHandler`, per-view bag, per-part plugin dispatch,
   per-index `apply_changed_paths` merge. `iter_views` gains
   production callers. The Praxis host adapter must preserve
   content-part identity instead of folding tool-response text into
   one block. That host change also serves #305; plan it once.
3. **PR 3 — Config parsing**: `visitor.rs` reads `match:` from YAML
   on route, global, default, and tag blocks, validation,
   config-level tests.
4. **PR 4 — E2E tests + docs**: integration tests, backward-compat
   tests, DSL spec update.
