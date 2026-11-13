# Design Proposal: Resource and Prompt Projection Support (Issue 75)

**Status:** Proposed — for engineering review  
**Related:** Issue 76 (per-view/content-part addressing)  
**Scope:** CMF message projection, APL field evaluation, structured write-back, configuration validation, MCP host integration

## 1. Overview

Resource and prompt routes currently match and dispatch, but their structured payloads are not projected into APL-readable values. Consequently, a policy that appears properly configured may evaluate against an empty string, allow the operation, and leave sensitive content untouched. Fixing routing alone does not fix this: redactions must also be written back to the original structured content part.

**Proposal:** Introduce stable JSON envelopes for three missing entity/phase combinations (`ResourceRef` pre-fetch, `Resource` post-fetch, and `PromptResult` post-invoke), apply APL changes back to the original structured parts, reject unsupported field configurations at load time, and document the message contract hosts must satisfy.

This is deliberately a **per-message** solution, not general per-part inspection. Issue 76 will address multi-content and `PromptResult.messages` coverage. Those limitations remain meaningful security gaps and are called out below.

## 2. Motivation and problem statement

### Why this matters

APL enforcement must inspect the same content the downstream consumer receives. Today, `message_projection.rs` handles `ToolCall`, `ToolResult`, and `PromptRequest`, but not resource references, resource responses, or prompt results. Those parts fall back to concatenated text; structured resource/prompt messages usually have no text parts, so APL sees an empty string.

For example, a resource post-fetch policy intended to mask an SSN may load and report an allowed operation while the original `Resource.content` remains unredacted. A temporary end-to-end probe confirmed that `result == 'topsecret': deny` allowed a resource containing `topsecret`, while a comparison to the empty string denied.

### Current behavior vs. desired behavior

| Entity / phase | Today | Desired after Issue 75 |
|---|---|---|
| Resource pre-fetch | `args` projects as empty text | `args` exposes `ResourceRef` fields |
| Resource post-fetch | `result` projects as empty text | `result` exposes `Resource` fields; content rewrites modify original part |
| Prompt post-invoke | `result` projects as empty text | `result` exposes `PromptResult` fields; content rewrites modify original part |

**Consequence:** Both policy decisions (deny/match) and policy transformations (redact/rewrite) can be ineffective without signaling failure.

## 3. Goals and non-goals

### Goals

- Make `args.*` and `result.*` meaningful on the three missing entity/phase combinations.
- Preserve structured message shape and unrelated fields during any write-back.
- Maintain numeric/type fidelity, including unsigned 64-bit fields.
- Reject statically invalid or read-only field paths at configuration load rather than silently accepting them.
- Align MCP data structures and attributes with the targeted MCP 2026-07-28 specification.
- Define a clear host integration contract and prove behavior with *deny* and *redaction* end-to-end assertions.

### Non-goals

- Projecting LLM message bodies into structured APL field paths.
- Inspecting `Resource.blob` or non-text content blocks.
- Projecting `PromptResult.messages` or scanning every content part in a multi-resource response (Issue 76).
- Per-view addressing or new `match:` syntax (Issue 76).
- Automatically parsing JSON inside `result.content` or adding an APL `parse` operator.

## 4. Challenges and constraints

1. **Projection gaps:** Existing extractors select only tool and prompt-request variants. We need a deterministic shape for three additional structured variants.
2. **Write-back correctness:** A transformed string must replace the relevant field in the *same* `ContentPart`, never be appended as a separate `Text` part that consumers may ignore.
3. **Type fidelity:** `u64`, optional strings, closed enums, boolean flags, annotations maps, and read-only identity fields need explicit conversion and invalid-value behavior.
4. **Silent misconfiguration:** Some entity/phase combinations have no field paths; unknown or read-only field writes should be caught at load time.
5. **Three-layer host contract:** `MetaExtension` controls routing, `MCPExtension` feeds PDP attributes, and `ContentPart` feeds APL. Populating one does not substitute for the others.
6. **Partial inspection:** First-match-only extraction and flat prompt `content` leave potential bypasses until Issue 76 or an explicit host normalization step.

## 5. Proposed architecture

### Data flow

```text
Host event / MCP response
    |
    v
CMF Message
  ├─ MetaExtension      → entity/route matching
  ├─ MCPExtension       → PDP mcp.* attributes
  └─ ContentPart        → APL data-plane payload
    |
    v
Projection: structured ContentPart → stable JSON envelope
    |
    v
APL evaluation: inspect / deny / transform args.* or result.*
    |
    +---- deny → block operation
    |
    v
Write-back: apply changed paths to original structured ContentPart
    |
    v
CMF Message with original structure preserved
```

### 5.1 Stable JSON envelopes

Use a fixed object shape (not a bare string or opportunistically parsed JSON). Each exposed field has a one-to-one source mapping:

| Hook | Source part | APL fields |
|---|---|---|
| Resource pre-fetch | `ResourceRef` | `args.{uri,name,resource_type,range_start,range_end,selector}` |
| Resource post-fetch | `Resource` | `result.{uri,name,title,description,resource_type,content,mime_type,size_bytes,version,annotations,icons}` |
| Prompt post-invoke | `PromptResult` | `result.{prompt_name,description,content,is_error,error_message}` |

`result.content` remains an **opaque string**: match, deny, or replace it as a whole; do not automatically parse nested JSON. `Resource.blob` and `PromptResult.messages` are not projected. The complete types and writeability table are in Appendix A.

### 5.2 Structured write-back

Changes are applied to the original matching `ResourceRef`, `Resource`, or `PromptResult` part. Do not append `Text` and do not alter other content parts. Preserve fields omitted from projection (`resource_request_id`, `prompt_request_id`, `blob`).

- Preserve original values when an APL-produced `u64` is negative, fractional, or out of range, an enum value is unknown, or `is_error` has the wrong type.
- Preserve read-only `PromptResult.prompt_name` and `Resource.icons` even if a change somehow reaches write-back; reject those writes earlier at config load.
- Merge `annotations` at addressed-key level so editing one annotation does not erase unrelated keys.
- Handle optional strings consistently; the exact JSON-to-field conversion policy is in Appendix B.

### 5.3 Configuration-time validation

Extend the existing no-field-path guard from `http:` routes to `llm:` routes, for both route-level blocks and `global.defaults.llm`. For resource/prompt fixed envelopes, validate the top-level field name, reject nested access under scalar fields (e.g. `result.content.ssn`), allow nested map access under `annotations`, and reject writes to read-only fields. Tool/prompt argument maps remain dynamic and are not subject to a static field catalog.

Coupling validation to a fixed field catalog creates schema drift risk. Add a test asserting that each catalog matches the keys emitted by its projection function.

### 5.4 Data model and host contract

Bring MCP extension metadata up to the targeted 2026-07-28 schema: shared `Icon`, metadata titles/icons/sizes as applicable, `Resource.title/icons`, and `PromptResult.description`. Map the new extension attributes into the PDP bag.

A host must populate the distinct layers correctly:

| Layer | Purpose | Failure if omitted |
|---|---|---|
| `MetaExtension` | Route matching | Wrong/missing route selection |
| `MCPExtension` | PDP metadata predicates | Missing `mcp.*` attributes |
| `ContentPart` | APL field projection/write-back | Route can match while APL has no effective payload |

Until Issue 76, a host that emits `PromptResult` **MUST** fill its flat `content` with rendered text (ordered text parts of `messages`), or prompt content inspection will not run effectively. Hosts should emit one fetched resource content per message, or treat multi-content reads as only partially covered. The guide must explicitly explain both failure modes.

## 6. Design decisions and alternatives

| Decision | Alternatives | Rationale |
|---|---|---|
| **Fixed JSON envelope** | Raw string; auto-parse JSON | `apply_changed_paths` needs an object; fixed fields make write-back deterministic and preserve metadata. Auto-parsing makes behavior content-dependent. |
| **Opaque `content` string** | Parse arbitrary nested JSON | Predictable policy shape and no parse-failure ambiguity; nested parsing can be an explicit later feature. |
| **In-place write-back** | Append transformed `Text` | Downstream hosts consume the original structured part; appending text leaves unmodified data visible. |
| **Read-only identity/display fields** | Write every projected field | `prompt_name` identity must remain correlated; `icons` are exposed for inspection but not rewritten. |
| **Fail fast on static field errors** | Allow runtime no-ops | Prevents the failure mode that motivated this issue. |
| **Use `ContentPart` as APL source** | Fall back to `MCPExtension` | Avoid ambiguous duplicate sources; matches existing tool behavior. |
| **Defer per-part coverage** | Solve all message-view addressing in Issue 75 | Keeps implementation bounded and reusable for Issue 76, but retains documented security gaps. |

Detailed comparison of the three envelope strategies is in Appendix C.

## 7. Limitations, risks, and mitigations

| Risk / limitation | Impact | Mitigation or follow-up |
|---|---|---|
| Only first matching resource part is inspected | Sensitive text in second/later part can bypass policy | Document host one-content-per-message guidance; pin with expected-failure test; address in Issue 76. |
| Prompt result uses only flat `content` | `messages`-only hosts can bypass injection rules | Host **MUST** populate `content`; pin with expected-failure test; address native `messages` inspection in Issue 76. |
| Invalid runtime types are preserved | Rewrite may silently no-op for bad data | Static type/path validation where feasible; tests for invalid conversion; consider diagnostics separately. |
| Fixed field catalogs may drift | False rejection or unvalidated paths | Projection/catalog parity test. |
| Mixed `ToolResult` and `Resource` parts | First-match extraction may choose wrong entity | No known builder currently produces mixed parts; consider entity-aware extraction as hardening. |
| Host contract misconfiguration | Policy may not see expected data | Six host recipes with concrete examples and missing-layer behavior. |

**Security caveat:** Issue 75 does not establish complete inspection of all content in arbitrary MCP messages. Deployments requiring that guarantee must enforce the stated host normalization constraints or await Issue 76.

## 8. Open questions for review

1. **Icons in the PDP attribute bag:** Publish `mcp.*.icons` as a `StringSet` of source URLs (recommended for consistency and future `contains` rules), or keep icons only on structs because they are presentation metadata?
2. **Prompt result missing flat `content`:** Require host normalization only (recommended for Issue 75), or also derive a read-only inspection fallback from `messages`? The fallback improves *deny* coverage but cannot safely write redactions into `messages` without a broader design.

## 9. Implementation strategy

One PR, four independently compiling/testable commits:

| Phase | Deliverable | Verification focus |
|---|---|---|
| **1. Schema alignment** | MCP metadata fields, `Icon`, CMF fields, PDP attributes | Attribute-bag/unit/catalog tests and compile checks |
| **2. Projection and write-back** | Three envelope projections, extraction, in-place mutation | Round-trip invariants; deny and redact visitor E2E; known-gap tests |
| **3. Config validation** | Reject no-field shapes, unknown paths, read-only writes | Load rejection diagnostics; valid-field acceptance; catalog parity |
| **4. Host guide** | Six entity/phase recipes covering three message layers | Human review of contract, examples, and failure modes |

Full file changes, test names, expected results, and commands are in Appendix D.

## 10. Test strategy and acceptance criteria

**Behavioral proof is essential:** an `allow` assertion is insufficient because the existing failure mode also allows. The E2E suite must assert *denied* decisions for matching resource/prompt content and *actual modifications* for redaction.

Acceptance requires:

- Every new envelope exposes correct fields on the intended entity/phase.
- Extraction followed by write-back without changes yields an identical message.
- Rewriting one field changes **that field only**; content-part count stays constant and no `Text` part is appended.
- Above-2^53 unsigned integers round-trip exactly; malformed numeric, enum, or boolean writes preserve the original.
- E2E coverage includes resource pre-fetch URI deny; resource post-fetch content deny/redact; prompt post-invoke content deny/redact and `is_error` deny.
- Invalid field configurations are rejected with actionable entity, block, and field diagnostics; dynamic-map cases remain valid.
- Two known holes (multi-resource; prompt `messages`-only) are pinned by explicitly named expected-failure tests pending Issue 76.
- `make check`, `make test`, and `make lint` pass; host guide describes all six entity/phase contracts.

## 11. Dependencies and rollout

Issue 75 is intended to land before Issue 76. Standalone projection helpers can be reused by per-view addressing. Until that work lands, hosts must honor the flat prompt-content contract and avoid assuming complete coverage of multi-content resource responses. This proposal does not introduce an APL syntax change.

---

# Detailed appendices

The sections below preserve the implementation-level specifications and checklists from the source planning document, separated from the architectural review narrative.


## Appendix A — Detailed envelope and write-back specification

#### Solution: JSON envelope projection

Each missing entity/phase gets a fixed JSON envelope mapping struct fields
to APL paths. The body (`result.content`) is always an opaque string — not
auto-parsed. Two alternative approaches (raw string, auto-parse JSON) were
evaluated and ruled out; see [Appendix C](#appendix-c-approach-comparison).

#### Resource pre-fetch → `args`

From `ContentPart::ResourceRef`:

| Struct field | APL path | Type |
|---|---|---|
| `uri` | `args.uri` | String |
| `name` | `args.name` | String or null |
| `resource_type` | `args.resource_type` | String (snake_case enum) |
| `range_start` | `args.range_start` | Number or null |
| `range_end` | `args.range_end` | Number or null |
| `selector` | `args.selector` | String or null |

#### Resource post-fetch → `result`

From `ContentPart::Resource`:

| Struct field | APL path | Type | Writable |
|---|---|---|---|
| `uri` | `result.uri` | String | Yes |
| `name` | `result.name` | String or null | Yes |
| `title` | `result.title` | String or null | Yes |
| `description` | `result.description` | String or null | Yes |
| `resource_type` | `result.resource_type` | String (snake_case enum) | Yes |
| `content` | `result.content` | String or null | Yes |
| `mime_type` | `result.mime_type` | String or null | Yes |
| `size_bytes` | `result.size_bytes` | Number or null | Yes |
| `version` | `result.version` | String or null | Yes |
| `annotations` | `result.annotations` | Object (may be empty) | Yes |
| `icons` | `result.icons` | Array or null | No (read-only) |

`result.content` is the body as an opaque string. APL can match, deny, or
rewrite the whole string but cannot address fields inside it. Body-field
access is a planned follow-up (APL `json` operator or `content_parsed`
sibling field).

#### Prompt post-invoke → `result`

From `ContentPart::PromptResult`:

| Struct field | APL path | Type | Writable |
|---|---|---|---|
| `prompt_name` | `result.prompt_name` | String | No (read-only) |
| `description` | `result.description` | String or null | Yes |
| `content` | `result.content` | String or null | Yes |
| `is_error` | `result.is_error` | Boolean | Yes |
| `error_message` | `result.error_message` | String or null | Yes |

`messages` (`Vec<Message>`) is not projected — deferred to Issue 76.

#### Complete projection reference

For all six entity/phase envelopes (including the three that already work),
see [Appendix A](#appendix-a-complete-projection-reference).

#### Write-back rules

- Modify the original `ContentPart` in place. Never append a `Text` part.
- Preserve fields excluded from projection (`resource_request_id`,
  `prompt_request_id`, `blob`).
- `prompt_name` and `icons` are read-only. A config that writes them is
  refused at load ([Commit 3b](#3b-unknown-and-read-only-field-paths-beyond-ac3)).
  Write-back also preserves the original, as defence in depth.
- `u64` fields (`range_start`, `range_end`, `size_bytes`): convert via
  `serde_json::Number::from()` on projection; reject negative, fractional,
  or out-of-range values on write-back (preserve original).
- `resource_type` is a closed enum (`File`, `Blob`, `Uri`, `Database`, `Api`,
  `Memory`, `Artifact`). If APL produces a string that doesn't match a valid
  variant, preserve the original value (same pattern as invalid `u64`). This
  applies on both the pre-fetch `args` envelope (`ResourceRef.resource_type`)
  and the post-fetch `result` envelope (`Resource.resource_type`).
- `is_error` is a `bool`. If APL produces a non-boolean value (string,
  number, null), preserve the original (shape mismatch — silent no-op,
  consistent with the general wrong-type pattern).
- `annotations` is a `HashMap<String, Value>`. Write-back uses **key-level
  merge** — only keys the pipeline addressed are updated; unmentioned keys
  are preserved. This is consistent with how `apply_changed_paths` already
  handles the tool result object, where a pipeline that redacts one field
  does not erase the others.
- `Option<String>` fields: see [Appendix B](#appendix-b-write-back-value-type-mapping).

---


## Appendix B — Write-back value conversion

#### Appendix B: Write-back value-type mapping

For `Option<String>` target fields (`Resource.content`, `Resource.name`,
`PromptResult.content`, `PromptResult.error_message`, etc.):

| JSON value type | Write-back behavior |
|---|---|
| `Value::String(s)` | `Some(s)` |
| `Value::Null` | `None` (clears the field — needed for `drop`) |
| `Value::Object` / `Value::Array` | Serialize to JSON string → `Some(serialized)` |
| `Value::Bool` / `Value::Number` | Preserve original (shape mismatch — silent no-op) |

---


## Appendix C — Projection alternatives

#### Appendix C: Approach comparison

Three projection approaches were evaluated:

| | Raw string | Auto-parse JSON | **JSON envelope (chosen)** |
|---|---|---|---|
| Metadata access | No | No (unless wrapped) | **Yes** |
| Body field access | No | Yes (JSON only) | No (future `parse`) |
| Consistent shape | Yes (always scalar) | No (depends on mime) | **Yes (always object)** |
| Runtime compatible | **No** (`apply_changed_paths` needs object) | Partially | **Yes** |
| Write-back safety | Whole-value only | Ambiguous edge cases | **1:1 field mapping** |
| Parse failure risk | None | Yes (silent or aggressive) | **None** |

**Raw string** is ruled out by a hard blocker: `apply_changed_paths` requires
`Value::Object`.

**Auto-parse JSON** produces inconsistent shapes — the same route yields an
object for JSON bodies and a scalar for everything else. Policy authors cannot
predict the shape at write time. Parse failures are runtime surprises with no
error channel.

**JSON envelope** gives a stable, predictable shape. Every field maps 1:1 to
a struct field. No parsing, no ambiguity. Body-field access is deferred to a
future `parse` operator that policy authors opt into explicitly.


## Appendix D — Detailed implementation and test plan

#### Commit 1: MCP spec field gaps

**Goal:** Update data model to match MCP 2026-07-28 before building
projection on top of it.

#### Changes

**`crates/ppe-core/src/extensions/mcp.rs`:**

Add `Icon` struct:

```rust
pub struct Icon {
    pub src: String,
    pub mime_type: Option<String>,
    pub sizes: Option<Vec<String>>,
}
```

Add to `ToolMetadata`:
- `icons: Option<Vec<Icon>>`

Add to `ResourceMetadata`:
- `title: Option<String>`
- `icons: Option<Vec<Icon>>`
- `size: Option<u64>`

Add to `PromptMetadata`:
- `title: Option<String>`
- `icons: Option<Vec<Icon>>`

**`crates/ppe-core/src/cmf/content.rs`:**

Add to `Resource`:
- `title: Option<String>`
- `icons: Option<Vec<Icon>>`

Add to `PromptResult`:
- `description: Option<String>`

**`crates/ppe-core/src/extensions/mod.rs`:**

Re-export `Icon`.

**`crates/ppe-apl-cmf/src/mcp.rs`:**

Wire into attribute bag:
- `mcp.tool.icons` → StringSet of src URLs
- `mcp.resource.title` → String
- `mcp.resource.size` → Int (u64 cast to i64)
- `mcp.resource.icons` → StringSet of src URLs
- `mcp.prompt.title` → String
- `mcp.prompt.icons` → StringSet of src URLs

Add tests: `tool_icons_flatten_as_src_set`,
`resource_title_flattens`, `resource_size_flattens`,
`resource_icons_flatten_as_src_set`, `prompt_title_flattens`,
`prompt_icons_flatten_as_src_set`,
`prompt_result_description_projects` (after commit 2 wires it).

**`crates/ppe-apl-cmf/tests/key_catalog/`:**

Add 6 catalog entries. Update test fixtures.

**`docs/content/cmf-extensions.md`:**

Document all new bag keys.

**Fix compile errors:** grep for `ResourceMetadata {` and `PromptResult {`
without `..Default::default()`.

#### Verify

```bash
make check
cargo nextest run -p praxis-policy-apl-cmf --lib
cargo nextest run -p praxis-policy-apl-cmf --test key_catalog
make test
```

---

#### Commit 2: Core projection and write-back

**Goal:** Make `args.*` and `result.*` work for resources and prompts.

#### Changes

**`crates/ppe-apl-runtime/src/message_projection.rs`:**

Add three standalone projection functions:

```rust
project_resource_ref_args(&ResourceReference) -> Value
project_resource_result(&Resource) -> Value
project_prompt_result(&PromptResult) -> Value
```

**Note:** `MessageView` in `crates/ppe-core/src/cmf/view.rs` already reads
`Resource.content`, `PromptResult.content`, resource URIs, and names via
`iter_views()` (currently has no callers outside its own tests). The
projection functions may reuse `MessageView` accessors internally or read
struct fields directly — implementer's choice. Either way, be aware the
read side is largely written; some of this may be wiring rather than new code.

Update extraction:
- `extract_args_from_message`: add `ContentPart::ResourceRef` arm
- `extract_result_from_message`: add `ContentPart::Resource` and
  `ContentPart::PromptResult` arms

Update write-back:
- `write_args_back_to_message`: add `ContentPart::ResourceRef` arm
- `write_result_back_to_message`: add `ContentPart::Resource` and
  `ContentPart::PromptResult` arms — modify in place, never append Text

Add doc comment with the six-envelope projection table.

#### Unit tests

In `message_projection.rs`:

| Test | Assertion |
|---|---|
| `args_round_trip_leaves_a_resource_ref_unchanged` | Extract → write back → message identical |
| `a_resource_ref_projects_its_fields_not_its_text` | `args.uri` is the URI, not empty string |
| `a_rewritten_resource_ref_field_differs_in_that_field_only` | Rewrite `args.uri` → write back → message equals the original with only `uri` replaced |
| `resource_ref_range_u64_fidelity_above_2_53` | Value above 2^53 round-trips exactly |
| `resource_ref_range_rejects_negative_and_fractional` | Original preserved on invalid input |
| `result_round_trip_leaves_a_resource_unchanged` | Extract → write back → identical |
| `a_resource_projects_its_envelope_not_its_text` | `result.content` is the body, `result.uri` is the URI |
| `a_redacted_resource_content_differs_in_that_field_only` | Rewrite `result.content` → message equals the original with only `content` replaced |
| `result_round_trip_leaves_a_prompt_result_unchanged` | Extract → write back → identical |
| `a_prompt_result_projects_its_fields_not_its_text` | `result.content` is rendered text, not empty string |
| `a_redacted_prompt_result_content_differs_in_that_field_only` | Rewrite `result.content` → message equals the original with only `content` replaced |
| `prompt_name_is_not_overwritten_on_write_back` | Mutate `result.prompt_name` → original preserved |
| `prompt_result_description_differs_in_that_field_only` | Rewrite `result.description` → message equals the original with only `description` replaced |

**"In that field and nowhere else."** The issue's round-trip criterion is
that the message differs in the mutated field *and nowhere else*. Checking
that the new value is present is not enough. Each rewrite test builds the
expected message by cloning the original and setting the one field by hand,
then asserts:

- `assert_eq!(written_back, expected)`: the whole message, not just the field
- `written_back.content.len() == original.content.len()`: no part appended
- no `ContentPart::Text` in `written_back.content` when the original had none

Put these in a shared helper (`assert_differs_only_in(original, written_back,
|expected| ...)`) so every rewrite test, including the `PromptRequest`
regression guard, uses the same check.

#### PromptRequest regression guard

`PromptRequest` pre-invoke projection is claimed as already working (it
matches `ContentPart::PromptRequest` in `extract_args_from_message` today).
Add one regression test to verify this claim and guard against future breakage:

| Test | Assertion |
|---|---|
| `prompt_request_args_round_trip` | Extract args from a `PromptRequest` with `{tone: "terse", length: 200}`, write back with a modified field, verify the message changed in that field only |

#### Integration tests (e2e through the visitor)

The issue requires: *"e2e tests that redact a field of a fetched resource and
of a rendered prompt, and that deny on their contents. Assertions on a deny,
not on an allow."*

Unit tests verify `message_projection.rs` in isolation. Integration tests
dispatch a message through the full visitor pipeline (route matching → hook
dispatch → APL evaluation → write-back) and assert on the **outcome** —
deny or redacted content. These go in `crates/ppe-apl-runtime/tests/visitor_e2e.rs`.

| Test | Setup | Assertion |
|---|---|---|
| `resource_post_fetch_deny_on_content` | Route: `resource: hr://employees/*`, policy: `result.content matches 'topsecret': deny`. Message: `ContentPart::Resource` with `content: Some("topsecret")` | **Denied** (not allowed) |
| `resource_post_fetch_redact_content` | Route: `resource: hr://employees/*`, policy: `result: { content: "str \| mask_pattern('\\d{3}-\\d{2}-\\d{4}', '[REDACTED]')" }`. Message: resource with SSN in content | Content modified, no appended Text part, SSN replaced |
| `resource_pre_fetch_deny_on_uri` | Route: `resource: hr://employees/*`, policy: `args.uri matches 'restricted': deny`. Message: `ContentPart::ResourceRef` with restricted URI | **Denied** |
| `prompt_post_invoke_deny_on_content` | Route: `prompt: summarize-*`, policy: `result.content matches 'ignore.*instructions': deny`. Message: `ContentPart::PromptResult` with injection text | **Denied** |
| `prompt_post_invoke_redact_content` | Route: `prompt: summarize-*`, policy: `result: { content: "str \| mask_pattern('\\d{3}-\\d{2}-\\d{4}', '[REDACTED]')" }`. Message: prompt result with SSN | Content modified, no appended Text part, SSN replaced |
| `prompt_post_invoke_deny_on_is_error` | Route: `prompt: *`, policy: `result.is_error == true: deny 'render failed'`. Message: `ContentPart::PromptResult` with `is_error: true` | **Denied** with reason |

These tests must assert on **deny decisions or modified message content**,
never on allow — an allow is indistinguishable from the broken behavior this
issue fixes.

#### Known gap: multi-resource messages

`extract_args_from_message`, `extract_result_from_message` and their
write-back counterparts walk `msg.content` and stop at the **first** matching
part. The new `ResourceRef` / `Resource` / `PromptResult` arms inherit this.

A single MCP `resources/read` can return several contents, for example a
directory or templated URI. If the host maps each one to its own
`ContentPart::Resource`, only the first is projected and written back:

```
content: [ Resource { uri: ".../a.txt", content: "harmless" },     ← projected, redacted
           Resource { uri: ".../b.txt", content: "123-45-6789" } ] ← not seen, passes through
```

This is the same class of silent bypass this issue fixes, limited to the
second and later parts. Tools behave the same today (only the first
`ToolResult` is projected), but multi-content resource reads are a normal
case, so the exposure is higher here.

**Decision:** this issue projects the first matching part only. Projecting
every part needs per-part addressing, which is Issue 76's scope. The gap is
pinned by a test and documented in the host guide rather than left silent.

| Test | Setup | Assertion |
|---|---|---|
| `known_gap_only_the_first_resource_part_is_projected` | Route: `resource: hr://employees/*`, policy: `result.content matches '\d{3}-\d{2}-\d{4}': deny`. Message: two `ContentPart::Resource` parts, SSN only in the **second** | Asserts **Denied**; fails today. `#[should_panic(expected = "known gap #76")]`, with the assertion message containing `known gap #76` |

When Issue 76 lands, this test starts passing and its `should_panic` must be
removed, which flags the fix.

**Related, lower likelihood:** a single message holding both a `ToolResult` and
a `Resource` part would project whichever comes first, so a tool route could see
a resource envelope. Nothing in this repo builds such a message. It depends on
whether a host splits an MCP tool result's embedded resources into separate
`ContentPart`s. Optional hardening: pass the route's entity type into the
extract and write-back functions so a tool route only matches `ToolCall` /
`ToolResult`, or match `ToolResult` ahead of `Resource`.

#### Known gap: prompt results carried only in `messages`

`PromptResult` has two places for the rendered prompt: a flat
`content: Option<String>` and `messages: Vec<Message>`. This issue projects
`content` only. `messages` is deferred to Issue 76.

That leaves a hole in the main prompt-side use case. The issue says scanning
a rendered prompt for injected instructions is "precisely the use case". MCP
`prompts/get` returns `messages`, so a host that maps the response faithfully
may fill `messages` and leave `content` as `None`. Then `result.content` is
null, an injection rule like `result.content matches 'ignore.*instructions':
deny` never matches, and the prompt passes with no signal. This is the same
silent bypass this issue fixes, limited to hosts that don't fill `content`.

**Decision:** for this issue:

1. The host guide makes it a **MUST** that a host set `PromptResult.content` to
   the rendered text whenever it sends a `PromptResult` (the text parts of
   `messages`, joined in order). It also names the failure mode if the host
   leaves it out (see Commit 4).
2. The gap is pinned by a test, so it is not silent in the codebase either:

| Test | Setup | Assertion |
|---|---|---|
| `known_gap_prompt_result_messages_are_not_projected` | Route: `prompt: summarize-*`, policy: `result.content matches 'ignore.*instructions': deny`. Message: `ContentPart::PromptResult` with `content: None` and the injection text only inside `messages` | Asserts **Denied**; fails today. `#[should_panic(expected = "known gap #76")]` |

A read-only fallback, where `content` is derived from `messages` when it is
`None`, would close the hole without waiting for Issue 76. But a redaction of
the derived value has nowhere to be written back, which is the
"write-back appends or drops" problem this issue exists to avoid. It is
listed under [Open decisions](#open-needs-team-input) rather than adopted.

#### Verify

```bash
cargo nextest run -p praxis-policy-apl-runtime --lib   # unit tests
cargo nextest run -p praxis-policy-apl-runtime --test visitor_e2e  # integration tests
make test
```

---

#### Commit 3: Config validation

**Goal:** Refuse field blocks that can address nothing, at load time instead
of at runtime.

Two pieces of work. Only the first is required by the issue.

#### 3a. Shapes with no field path (issue AC3)

AC3: *"An `args:` or `result:` block that addresses a shape with no field path
is refused at load with a message naming the block and the entity type, the
way an `http:` route's is today."*

`reject_field_stages_without_fields` (`crates/ppe-apl-runtime/src/visitor.rs`)
checks `ENTITY_HTTP` only. Once commit 2 lands, resource and prompt routes have
field paths, so they correctly pass. The entity left with no field path is
**`llm:`**. Both LLM hooks still project the concatenated `Text` parts as a
scalar string (see [Appendix A](#appendix-a-complete-projection-reference),
Fallback), so `args: { foo: ... }` on an `llm:` route loads today and does
nothing. That is the same silence this issue is about.

Change: extend the guard from `entity_type != ENTITY_HTTP` to cover
`ENTITY_LLM`. The refusal message names the block and `llm:`, and points to
the `llm.*` attributes under `pre_invocation:` / `post_invocation:`, matching
the existing `http:` wording. The check already runs for a route's own block
and for `global.defaults.<entity>`. Both scopes pick up the new arm.

Before landing, confirm that no config, test fixture or demo in the workspace
declares `args:` / `result:` on an `llm:` route. A search of `crates/`,
`tests/` and `docs/content/` found none, but the demos under `../demos` should
be checked too.

#### 3b. Unknown and read-only field paths (beyond AC3)

The issue does not require this. It is the same principle (a block that can
never take effect should not load) applied to field names, now that resource
and prompt envelopes have a fixed set of fields.

Define static valid-field sets:

```
resource args:   {uri, name, resource_type, range_start, range_end, selector}
resource result: {uri, name, title, description, resource_type, content,
                  mime_type, size_bytes, version, annotations, icons}
prompt result:   {prompt_name, description, content, is_error, error_message}
```

Rules:

- **Match on the first path segment.** `annotations` is an open map, so
  `result.annotations.audience` must be accepted. The check is "the first
  segment is in the set". Deeper segments are checked only for scalar fields
  (`result.content.ssn` is refused: `content` is an opaque string, see
  [body parsing](#resource-post-fetch--result)).
- **Writes to read-only fields are refused.** A `result:` block that writes
  `prompt_name` or `icons` is refused at load, rather than silently preserved
  at write-back. This keeps the "silent no-op" behaviour for cases only
  runtime can detect (invalid enum, out-of-range `u64`, wrong JSON type).
  Write-back still preserves `prompt_name` and `icons` as defence in depth.
- **Dynamic-key envelopes are not checked.** Tool `args` / `result` and prompt
  `args` take their keys from the host's arguments map, so they have no static
  set.
- **Same scopes as 3a.** The route's own block and `global.defaults.<entity>`.

The error message names the block (`args` or `result`), the entity type, the
offending path, and either the valid set or "read-only".

Cost: validation is coupled to the envelope shape, so adding an envelope field
means updating its set. A unit test asserts each static set equals the keys
the matching `project_*` function emits, so the two cannot drift.

#### Tests

| Test | Expected |
|---|---|
| `result:` on HTTP route | Rejected (existing, regression guard) |
| `args:` on LLM route | Rejected, message names `args` and `llm` |
| `result:` on LLM route | Rejected, message names `result` and `llm` |
| `args:` on LLM route under `global.defaults.llm` | Rejected |
| `args:` with valid fields on resource route | Accepted |
| `result:` with valid fields on resource route | Accepted |
| `result:` with `annotations.audience` on resource route | Accepted (nested path under an open map) |
| `args:` with unknown field on resource route | Rejected with diagnostic |
| `result:` with unknown field on prompt route | Rejected with diagnostic |
| `result:` with `content.ssn` on resource route | Rejected (`content` is opaque) |
| `result:` writing `prompt_name` on prompt route | Rejected as read-only |
| `result:` writing `icons` on resource route | Rejected as read-only |
| Static field sets match `project_*` output keys | Pass (drift guard) |

#### Verify

```bash
cargo nextest run -p praxis-policy-apl-runtime --lib
make test
```

---

#### Commit 4: Host integration guide

**Goal:** Document what a host must put on a message for policy to work.

The issue requires a contract covering what goes on the message **and in
MCPExtension**. Three layers feed policy, and the guide must cover all of them:

| Layer | What it feeds | Source struct |
|---|---|---|
| `MetaExtension` (`entity_type`, `entity_name`) | Route matching | Set by host |
| `MCPExtension` (`ResourceMetadata`, `PromptMetadata`, `ToolMetadata`) | PDP attribute bag (`mcp.resource.*`, `mcp.prompt.*`, `mcp.tool.*`) | Set by host |
| `ContentPart` (`ResourceRef`, `Resource`, `PromptResult`, etc.) | APL `args.*` / `result.*` projection | Set by host |

A host that sets only MCPExtension but no ContentPart gets route matching and
PDP predicates but empty APL envelopes. This is the most likely
misconfiguration and must be called out explicitly.

#### File

`docs/content/host-integration-guide.md` — new, ~1000 lines.

#### Structure

Six recipes (one per entity/phase), each following:

```
Step 1 — Host builds a CmfMessage     (JSON example, MUST/SHOULD/MAY)
         Covers all three layers: MetaExtension, MCPExtension, ContentPart
Step 2 — What APL sees                 (envelope field → value)
Step 3 — What PDP sees                 (attribute bag keys from MCPExtension)
Step 4 — Example policy                (YAML)
Step 5 — What goes wrong if skipped    (per-field, per-layer consequences)
```

Plus a common-mistakes section covering:
- Overlapping fields across layers (MetaExtension, MCPExtension, ContentPart)
- Missing ContentPart with MCPExtension-only (route matches but APL sees null)
- Missing MCPExtension with ContentPart-only (APL works but PDP predicates are empty)
- The `prompt_name` read-only contract
- `PromptResult` with `messages` but no `content`: hosts **MUST** set
  `content` to the rendered text (text parts of `messages`, joined in order).
  Otherwise `result.content` is null and content rules on the prompt route,
  injection scanning included, never match. Pinned by
  `known_gap_prompt_result_messages_are_not_projected` until Issue 76
- Multi-content resource reads: only the first `Resource` part is projected
  until Issue 76. Hosts should map one fetched content per message, or treat
  multi-content reads as only partly covered by policy

#### Verify

Prose review only.

---


## Appendix E — Issue 76 comparison and complete checklist

#### Relationship with Issue 76

| | This issue (75) | Issue 76 |
|---|---|---|
| Scope | Per-message projection | Per-view content-part addressing |
| `PromptResult.messages` | Not projected | Projected |
| Several `Resource` parts in one message | First part only (known gap, pinned by test) | Every part |
| New syntax | None | `match:` blocks |
| `iter_views()` | Not used | Integrated |

Issue 75 lands first. The projection helpers are standalone functions so
Issue 76 can reuse them.

---

#### Definition of done

#### Commit 1: spec field gaps

- [ ] `Icon` struct defined, re-exported through `extensions/mod.rs`
- [ ] `ToolMetadata` has `icons`
- [ ] `ResourceMetadata` has `title`, `icons`, `size`
- [ ] `PromptMetadata` has `title`, `icons`
- [ ] CMF `Resource` has `title`, `icons`
- [ ] CMF `PromptResult` has `description`
- [ ] Attribute bag keys wired: `mcp.tool.icons`, `mcp.resource.{title,size,icons}`, `mcp.prompt.{title,icons}`
- [ ] Key catalog and `cmf-extensions.md` updated
- [ ] Tests pass

#### Commit 2: projection and write-back

- [ ] `ResourceRef` fields available through `args`
- [ ] `Resource` fields available through `result`
- [ ] `PromptResult` fields available through `result`
- [ ] Write-back modifies original structured part (no appended Text)
- [ ] `u64` fields round-trip above 2^53; invalid values preserve original
- [ ] `prompt_name` and `icons` are read-only on write-back
- [ ] Doc comment on `message_projection.rs` with six-envelope table
- [ ] Unit tests: round-trip, rewrite, wrong-shape, u64 fidelity
- [ ] Every rewrite test asserts the whole message equals the original with only the mutated field changed, part count unchanged, no `Text` part added (shared `assert_differs_only_in` helper)
- [ ] PromptRequest regression guard: args round-trip verified for prompt pre-invoke
- [ ] Integration tests: resource deny, resource redact, resource pre-fetch deny, prompt deny, prompt redact, prompt is_error deny — all asserting on deny/modified content, not on allow
- [ ] Multi-resource gap pinned: `known_gap_only_the_first_resource_part_is_projected` with `#[should_panic(expected = "known gap #76")]`
- [ ] Prompt `messages`-only gap pinned: `known_gap_prompt_result_messages_are_not_projected` with `#[should_panic(expected = "known gap #76")]`

#### Commit 3: config validation

- [ ] (3a, AC3) `args:` / `result:` on an `llm:` route refused at load, naming the block and entity type, in both route and `global.defaults.llm` scope
- [ ] (3a) Existing HTTP route rejection preserved
- [ ] (3a) No existing config or demo declares field blocks on `llm:` routes (checked before landing)
- [ ] (3b) Unknown field paths rejected at load time with diagnostic; nested paths under `annotations` accepted
- [ ] (3b) Writes to read-only fields (`prompt_name`, `icons`) rejected at load
- [ ] (3b) Valid field paths accepted for resource and prompt routes
- [ ] (3b) Static field sets match `project_*` output keys (drift test)

#### Commit 4: host integration guide

- [ ] `docs/content/host-integration-guide.md` covers all six entity/phase combinations
- [ ] Each recipe covers all three layers: MetaExtension, MCPExtension, ContentPart
- [ ] MUST/SHOULD/MAY field requirements per entity/phase
- [ ] JSON examples and "what goes wrong" sections (per-field, per-layer)
- [ ] Common mistakes: MCPExtension-only, ContentPart-only, overlapping field consistency, multi-content resource reads, `PromptResult` without `content`

#### Overall

- [ ] `make check` passes
- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] Issue 76 functionality remains outside this change

---


## Appendix F — Existing design-decision register

#### Design decisions

#### Settled

| Decision | Rationale |
|---|---|
| **JSON envelope** over raw string or auto-parse | Raw string blocked by `apply_changed_paths` requiring Object. Auto-parse has non-deterministic shape. See [Appendix C](#appendix-c-approach-comparison). |
| **`Resource.blob` excluded** | Byte-level inspection is not a policy engine concern |
| **`prompt_name` read-only** | Mutating identity breaks correlation. Writes refused at load (3b) and preserved at write-back |
| **Refuse field blocks on `llm:` routes** | AC3: a shape with no field path is refused at load, as `http:` is today |
| **Reject unknown and read-only fields at load** | Goes beyond AC3, same principle: silence caused this bug. Drift test keeps the sets in step with the envelopes |
| **`PromptResult.content` is a host MUST** | `messages` is Issue 76; until then a host that fills only `messages` defeats content rules. Documented and pinned by a known-gap test |
| **ContentPart only, no MCPExtension fallback** | Two-source ambiguity; consistent with how tools work |
| **Document field consistency, don't enforce** | Tools don't enforce it either; adding it for resources only would be inconsistent |
| **Body parsing deferred** | Two compatible future paths exist (APL `json` operator, `content_parsed` field). Neither blocks this issue. |

#### Open (needs team input)

| Decision | Options | Recommendation |
|---|---|---|
| **Icons in attribute bag** | (a) StringSet of src URLs — lets rules do `contains` (b) Skip the bag — icons are display metadata, struct-only like `inputSchema` | (a) StringSet — consistent with scalar-array walker pattern, useful if ever needed, cheap |
| **`PromptResult` with `content: None`** | (a) Host MUST set `content`; pin the gap with a test (b) Also derive a read-only `result.content` from the text parts of `messages` when `content` is `None`, so deny rules work and redaction is refused at write-back | (a) for this issue. (b) closes the deny case early but adds a derived, non-writable value; better designed alongside Issue 76's `messages` projection |

---


## Appendix G — Full six-envelope reference

#### Appendix A: Complete projection reference

All six entity/phase combinations:

| Entity | Phase | Content type | APL binding |
|---|---|---|---|
| Tool | Pre-invoke | `ToolCall` | `args.<key>` (dynamic keys from arguments map) |
| Tool | Post-invoke | `ToolResult` | `result` or `result.<key>` (any JSON value) |
| Prompt | Pre-invoke | `PromptRequest` | `args.<key>` (dynamic keys from arguments map) |
| **Prompt** | **Post-invoke** | **`PromptResult`** | **`result.{prompt_name, description, content, is_error, error_message}`** |
| **Resource** | **Pre-fetch** | **`ResourceRef`** | **`args.{uri, name, resource_type, range_start, range_end, selector}`** |
| **Resource** | **Post-fetch** | **`Resource`** | **`result.{uri, name, title, description, resource_type, content, mime_type, size_bytes, version, annotations, icons}`** |

Bold rows are added by this issue. The first three already work.

#### Fallback

Any content part not matched above falls through to
`Value::String(msg.get_text_content())` — the concatenated text parts.

---
