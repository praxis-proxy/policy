# Resource and prompt projection implementation plan

**Status:** PPE implementation under review; Praxis adapter pending **Related:**
Issue 76 (per-view/content-part addressing) **Scope:** CMF message projection,
APL field evaluation, structured write-back, configuration validation, MCP host
integration

## 1. Overview

Before this implementation, resource and prompt routes matched and dispatched,
but their structured payloads were not projected into APL-readable values.
Consequently, a policy that appears properly configured may evaluate against an
empty string, allow the operation, and leave sensitive content untouched. Fixing
routing alone does not fix this: redactions must also be written back to the
original structured content part.

**Implementation:** Introduce stable JSON envelopes for three missing
entity/phase combinations (`ResourceRef` pre-fetch, `Resource` post-fetch, and
`PromptResult` post-invoke), apply APL changes back to the original structured
parts, reject unsupported field configurations at load time, and document the
message contract hosts must satisfy.

This is deliberately a **per-message** solution, not general per-part
inspection. Issue 76 will address multi-content and `PromptResult.messages`
coverage. Those limitations remain meaningful security gaps and are called out
below.

## 2. Motivation and problem statement

### Why this matters

APL enforcement must inspect the same content the downstream consumer receives.
Before this change, the projection supported tool calls, tool results and prompt
requests. Resource references, resource responses and prompt results fell back
to concatenated text, which was usually empty for those structured messages.

For example, a resource post-fetch policy intended to mask an SSN may load and
report an allowed operation while the original `Resource.content` remains
unredacted. A temporary end-to-end probe confirmed that `result == 'topsecret':
deny` allowed a resource containing `topsecret`, while a comparison to the empty
string denied.

The gap is on both sides of the host boundary. Praxis, the reference host,
builds response content parts and re-serializes response bodies for `tools/call`
only. For `resources/read` and `prompts/get` it builds no `Resource` or
`PromptResult` part, so APL sees an empty message (part of why the probe saw an
empty string). A part that PPE rewrites is also never written back into the
response body. Fixing PPE projection alone therefore does not stop the leak
through the proxy; see [§11](#11-dependencies-and-rollout).

### Previous behavior and implemented behavior

| Entity / phase | Before this implementation | PPE implementation |
|---|---|---|
| Resource pre-fetch | `args` projects as empty text | `args` exposes `ResourceRef` fields |
| Resource post-fetch | `result` projects as empty text | `result` exposes `Resource` fields; content rewrites modify original part |
| Prompt post-invoke | `result` projects as empty text | `result` exposes `PromptResult` fields; content rewrites modify original part |

**Consequence:** Both policy decisions (deny/match) and policy transformations
(redact/rewrite) can be ineffective without signaling failure.

## 3. Goals and non-goals

### Goals

- Make `args.*` and `result.*` meaningful on the three missing entity/phase
  combinations.
- Preserve structured message shape and unrelated fields during any write-back.
- Maintain numeric/type fidelity, including unsigned 64-bit fields.
- Reject statically invalid or read-only field paths at configuration load
  rather than silently accepting them.
- Add only the CMF metadata fields used by the fixed resource and prompt
  envelopes.
- Define a clear host integration contract and prove behavior with *deny* and
  *redaction* end-to-end assertions.

### Non-goals

- Projecting LLM message bodies into structured APL field paths.
- Inspecting `Resource.blob` or non-text content blocks.
- Projecting `PromptResult.messages` or scanning every content part in a
  multi-resource response (Issue 76).
- Per-view addressing or new `match:` syntax (Issue 76).
- Automatically parsing JSON inside `result.content` or adding an APL `parse`
  operator.

## 4. Challenges and constraints

1. **Projection gaps:** Existing extractors select only tool and prompt-request
   variants. We need a deterministic shape for three additional structured
   variants.
2. **Write-back correctness:** A transformed string must replace the relevant
   field in the *same* `ContentPart`, never be appended as a separate `Text`
   part that consumers may ignore.
3. **Type fidelity:** `u64`, optional strings, and annotations maps need
   explicit conversion and invalid-value behavior; read-only fields (`uri`,
   `resource_type`, `prompt_name`, `is_error`, `icons`) must be preserved.
4. **Silent misconfiguration:** Some entity/phase combinations have no field
   paths; unknown or read-only field writes should be caught at load time.
5. **Three-layer host contract:** `MetaExtension` controls routing,
   `MCPExtension` feeds PDP attributes, and `ContentPart` feeds APL. Populating
   one does not substitute for the others.
6. **Partial inspection:** First-match-only extraction and flat prompt `content`
   leave potential bypasses until Issue 76 or an explicit host normalization
   step.
7. **Host-side dependency:** PPE only sees what the host builds and only affects
   what the host serializes. Enforcement for resources and prompts needs
   matching Praxis changes, verified on the bytes sent to the client, not just
   on the PPE `Message`.

## 5. Architecture

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

Use a fixed object shape (not a bare string or opportunistically parsed JSON).
Each exposed field has a one-to-one source mapping:

| Hook | Source part | APL fields |
|---|---|---|
| Resource pre-fetch | `ResourceRef` | `args.{uri,name,resource_type,range_start,range_end,selector}` |
| Resource post-fetch | `Resource` | `result.{uri,name,title,description,resource_type,content,mime_type,size_bytes,version,annotations,icons}` |
| Prompt post-invoke | `PromptResult` | `result.{prompt_name,description,content,is_error,error_message}` |

`result.content` remains an **opaque string**: match, deny, or replace it as a
whole; do not automatically parse nested JSON. `Resource.blob` and
`PromptResult.messages` are not projected. The complete types and writeability
table are in Appendix A.

### 5.2 Structured write-back

Changes are applied to the original matching `ResourceRef`, `Resource`, or
`PromptResult` part. Do not append `Text` and do not alter other content parts.
Preserve fields omitted from projection (`resource_request_id`,
`prompt_request_id`, `blob`).

- Clear optional `u64` fields when an APL-produced value is negative,
  fractional, or out of range. Missing keys and `null` also clear them.
- Identity and classification fields are **read-only**: `ResourceRef.uri`,
  `Resource.uri`, `ResourceRef.resource_type`, `Resource.resource_type`,
  `PromptResult.prompt_name`, `PromptResult.is_error`, and the display field
  `Resource.icons`. Writes to them are refused at config load and, as a
  backstop, the original is preserved if a change reaches write-back.
- `uri` is read-only because Praxis writes `ResourceRef.uri` back into
  `params.uri`. A writable `args.uri` would let a pipeline step change which
  resource is fetched after route matching and the PDP decided on the original
  URI, with nothing re-authorizing the new one. On the post-fetch side, a
  rewritten `result.uri` would tell the client the content came from somewhere
  it did not.
- Merge `annotations` at addressed-key level so editing one annotation does not
  erase unrelated keys.
- Handle optional strings consistently; the exact JSON-to-field conversion
  policy is in Appendix B.

Resource result edits and plugin field readback keep the resource selected at
the start of the route. Its URI must identify exactly one part in both the
original and current message. A removed target or duplicate URI fails closed;
removing one duplicate later cannot establish which original part remains.
Request correlation IDs do not provide per-part identity. Issue 76 still owns
per-part addressing; this issue rejects ambiguous edits instead of guessing.

The existing `PayloadFields::field_value(field, phase)` method stays intact. An
additive `field_value_with_projection` method defaults to that host method,
while CMF payloads use the route projection. Resource readback follows the
captured route target without cloning the whole envelope.

### 5.3 Configuration-time validation

The existing no-field-path guard stays on `http:` routes only. Field blocks on
`llm:` routes are out of scope for this issue (see Appendix D, 3a). For
resource/prompt fixed envelopes, validate the top-level field name, reject
nested access under scalar fields (e.g. `result.content.ssn`), allow nested map
access under `annotations`, and reject writes to read-only fields. Tool/prompt
argument maps remain dynamic and are not subject to a static field catalog.

Coupling validation to a fixed field catalog creates schema drift risk. Add a
test asserting that each catalog matches the keys emitted by its projection
function.

### 5.4 Data model and host contract

Add only fields read by the fixed CMF envelopes: `Resource.title`,
`Resource.icons`, and `PromptResult.description`, with the shared `Icon` type
required by `Resource.icons`. Resolved MCP metadata, new attribute-bag keys, and
dependency advisory policy changes are outside this PR.

A host must populate the distinct layers correctly:

| Layer | Purpose | Failure if omitted |
|---|---|---|
| `MetaExtension` | Route matching | Wrong/missing route selection |
| `MCPExtension` | PDP metadata predicates | Missing `mcp.*` attributes |
| `ContentPart` | APL field projection/write-back | Route can match while APL has no effective payload |

**The layers are views, not duplicates.** `ContentPart` and `MCPExtension` can
both carry a name, namespace or `uri` for the same entity, but they describe
different things:

- **`ContentPart` is the wire view:** the request as the agent sent it.
  `ToolCall.name` comes from `params.name`, `ResourceRef.uri` from `params.uri`,
  and write-back serializes them back into the body.
- **`MCPExtension` is the resolved identity:** the host's view of the entity
  from its own catalog. It carries data the agent never sends (`server_id`,
  schemas, annotations).

A gateway is exactly where the two differ. A federating gateway may expose a
tool to the agent as `hr__get_salary` (`ToolCall.name`) while the upstream tool
is `get_salary` on `hr-server` (`ToolMetadata.name`, `server_id`). Likewise,
`ResourceRef.uri` is what the agent asked for and `ResourceMetadata.uri` can be
what the host resolved it to. PPE therefore **does not require the layers to be
equal**, and no equality check is added: it would reject every federated setup.

**`ToolCall.namespace` is the agent-facing namespace.** The field is not part of
MCP: `tools/call` params are only `name` and `arguments` (2025-11-25, 2026-07-28
and draft). It came over from the CPEX CMF, where it forms the
`tool://{namespace}/{name}` view identity. PPE never reads it and Praxis always
leaves it `None`, so until now its meaning was undefined. Following the
wire-view definition above, it is defined as the namespace the agent sees, if
the agent sees one (for example `hr` in `hr__get_salary`), and `None` otherwise.
The upstream server's namespace belongs in `ToolMetadata.namespace` (PDP
attribute `mcp.tool.namespace`), not here.

**`MetaExtension.entity_name` is the exact value routes match.** Praxis uses the
agent-facing name from `params.name` / `params.uri`. A renaming host can supply
its resolved catalog name, but must document that choice and configure routes
against that naming scheme. PPE does not resolve aliases between the wire and
catalog views.

**`MCPExtension` MUST come from the host's own catalog**, never from values the
agent sent. A host that copies `params.name` or `params.uri` into it lets the
agent choose the name the PDP authorizes. A host without a catalog leaves
`MCPExtension` unset; `mcp.*` attributes are then absent and authorization
relies on route matching (`entity_name`) and identity. Praxis does this today:
it does not set `MCPExtension` for MCP calls.

**Which layer each kind of rule uses:** authorization keys on the resolved
identity in `MCPExtension` (`mcp.tool.name`, `mcp.resource.uri`, …); content
rules key on the content part (`args.*`, `result.*`).

Until Issue 76, a host that emits `PromptResult` **MUST** fill its flat
`content` with rendered text (ordered text parts of `messages`), or prompt
content inspection will not run effectively. This MUST lasts only until Issue 76
projects `messages`. Until then, **`content` is the authoritative copy on the
way out**: it is the copy policy inspected and rewrote, so a host serializes the
response from `content`, not from the original `messages`. Otherwise a redaction
applied to `content` would not reach the client. Hosts should emit one fetched
resource content per message, or treat multi-content reads as only partially
covered. The guide must explicitly explain both failure modes.

## 6. Design decisions and alternatives

| Decision | Alternatives | Rationale |
|---|---|---|
| **Fixed JSON envelope** | Raw string; auto-parse JSON | Only the envelope exposes metadata (`uri`, `mime_type`, `size_bytes`, …) to policy; fixed fields make write-back deterministic. A raw string works at runtime but hides all metadata. Auto-parsing makes behavior content-dependent. |
| **Opaque `content` string** | Parse arbitrary nested JSON | Predictable policy shape and no parse-failure ambiguity; nested parsing can be an explicit later feature, through an opt-in APL operator. |
| **In-place write-back** | Append transformed `Text` | Downstream hosts consume the original structured part; appending text leaves unmodified data visible. |
| **Read-only identity/classification fields** | Write every projected field | `prompt_name` and `uri` identify what was authorized and must stay correlated with the PDP decision; a writable `uri` would redirect a fetch without re-authorization. `resource_type` and `is_error` have no known write use case and are more likely to cause mistakes. `icons` are exposed for inspection but not rewritten. Loosening a field later is additive; locking one down after use is breaking. |
| **No fetch redirection in Issue 75** | Allow `args.uri` rewrites | Redirection (geo routing, tenant pinning, versioned mirrors) is a real use case but needs its own design: an explicit effect that re-enters route matching and authorization for the new URI, or a routing decision in the gateway. |
| **Fail fast on static field errors** | Allow runtime no-ops | Prevents the failure mode that motivated this issue. |
| **Use `ContentPart` as APL source** | Fall back to `MCPExtension` | The layers are different views (wire view vs resolved identity, see §5.4), so a fallback would quietly swap the agent's name for the resolved one. Matches existing tool behavior. |
| **Layers are views, not duplicates** | Treat overlapping fields as copies and require them to be equal | `ContentPart` is what the agent sent; `MCPExtension` is what the host resolved. A gateway may legitimately make them differ, so an equality check would reject every federated setup. Each layer's meaning is documented instead. |
| **Defer per-part coverage** | Solve all message-view addressing in Issue 75 | Keeps implementation bounded and reusable for Issue 76, but retains documented security gaps. |

Detailed comparison of the three envelope strategies is in Appendix C.

## 7. Limitations, risks, and mitigations

| Risk / limitation | Impact | Mitigation or follow-up |
|---|---|---|
| PPE tests pass while the proxy leaks | Redaction is applied to the PPE `Message` but never reaches the client; resource/prompt rules see an empty message | Praxis dependency with its own acceptance criteria, asserted on response bytes ([§11](#11-dependencies-and-rollout)). |
| Only first matching resource part is inspected | Sensitive text in second/later part can bypass policy | Proposed: Praxis folds all text entries of a `resources/read` into one `Resource` part, as it already does for tool text blocks. Other hosts get one-content-per-message guidance; pin with expected-failure test; address in Issue 76. |
| Prompt result uses only flat `content` | `messages`-only hosts can bypass injection rules | Host **MUST** populate `content`; pin with expected-failure test; address native `messages` inspection in Issue 76. |
| Invalid optional numeric values are cleared | A malformed or redacted `u64` becomes unset; hosts must handle the absent field | Test negative, fractional, string and out-of-range writes, and keep the conversion rules explicit. |
| Fixed field catalogs may drift | False rejection or unvalidated paths | Projection/catalog parity test. |
| Mixed `ToolResult` and `Resource` parts | First-match extraction may choose wrong entity | No known builder currently produces mixed parts; consider entity-aware extraction as hardening. |
| Host contract misconfiguration | Policy may not see expected data | Six host recipes with concrete examples and missing-layer behavior. |

**Security caveat:** Issue 75 does not establish complete inspection of all
content in arbitrary MCP messages. Deployments requiring that guarantee must
enforce the stated host normalization constraints or await Issue 76.

## 8. Open questions for review

1. **Icons in the PDP attribute bag:** *Resolved:* icons stay out of the PDP bag
   (see Appendix F).
2. **Prompt result missing flat `content`:** *Resolved:* option (a), host MUST
   set `content`, scoped to "until Issue 76" (see §5.4 and Appendix F).
3. **Routing names on hosts that rename entities:** *Resolved:* the host selects
   and documents the routing view. Current Praxis uses the agent-facing name; a
   catalog-backed host can use its resolved name. Routes must cover the exact
   names supplied by that host. PPE performs no alias resolution.

## 9. Implementation strategy

One PR, four independently compiling/testable commits:

| Phase | Deliverable | Verification focus |
|---|---|---|
| **1. Projection metadata** | `Icon` and the projected CMF metadata fields | Projection/key parity tests and compile checks |
| **2. Projection and write-back** | Three envelope projections, extraction, in-place mutation | Round-trip invariants; deny and redact visitor E2E; known-gap tests |
| **3. Config validation** | Reject no-field shapes, unknown paths, read-only writes | Load rejection diagnostics; valid-field acceptance; catalog parity |
| **4. Host contract** | New `host-integration-guide.md` holding the contract: MUSTs, layer definitions, two known gaps (the follow-up PR adds the six recipes to the same file) | Human review of the contract |

Full file changes, test names, expected results, and commands are in Appendix D.

## 10. Test strategy and acceptance criteria

**Behavioral proof is essential:** an `allow` assertion is insufficient because
the existing failure mode also allows. The E2E suite must assert *denied*
decisions for matching resource/prompt content and *actual modifications* for
redaction.

**Scope of the PPE tests:** the PPE suite proves that the PPE `Message` is
denied or modified. It cannot prove that the client receives the redacted bytes;
that is a host property. Delivery is proven by the Praxis acceptance criteria in
[§11](#11-dependencies-and-rollout), and #75 is not done until both pass.

Acceptance requires:

- Every new envelope exposes correct fields on the intended entity/phase.
- Extraction followed by write-back without changes yields an identical message.
- Rewriting one field changes **that field only**; content-part count stays
  constant and no `Text` part is appended.
- Above-2^53 unsigned integers round-trip exactly; malformed optional numeric
  writes clear the field.
- Writes to read-only fields (`uri` in both envelopes, `resource_type`,
  `prompt_name`, `is_error`, `icons`) are refused at load and preserved at
  write-back.
- E2E coverage includes resource pre-fetch URI deny; resource post-fetch content
  deny/redact; prompt post-invoke content deny/redact and `is_error` deny.
- Invalid field configurations are rejected with actionable entity, block, and
  field diagnostics; dynamic-map cases remain valid.
- Two known holes (multi-resource; prompt `messages`-only) are pinned by
  explicitly named expected-failure tests pending Issue 76.
- `make check`, `make test`, and `make lint` pass; the host contract section
  states the MUSTs, the layer definitions and the two known gaps.

## 11. Dependencies and rollout

Issue 75 is intended to land before Issue 76. Standalone per-part projection and
write-back helpers (`project_*` / `write_*`) can be reused by per-view
addressing. Until that work lands, hosts must honor the flat prompt-content
contract and avoid assuming complete coverage of multi-content resource
responses. This proposal does not introduce an APL syntax change.

### 11.1 Host dependency: Praxis response handling

PPE projection is necessary but not sufficient. Today Praxis builds response
content parts and re-serializes the response body for `tools/call` only. Issue
75 is not complete until Praxis also handles `resources/read` and `prompts/get`.
This is tracked as a separate Praxis change with its own acceptance criteria.

**Required Praxis behavior:**

- Build `ContentPart::Resource` from `result.contents[]` of a `resources/read`
  response.
- Build `ContentPart::PromptResult` from `result.messages[]` of a `prompts/get`
  response, with `content` set to the text parts of `messages` joined in order
  (the host MUST in §5.4).
- Re-serialize the fields policy changed into the response body sent to the
  client.
- Fail closed on a malformed response when post-phase `resource:` or `prompt:`
  rules are active, as is already done for `tools/call`.

**Multi-resource responses (to settle with Praxis):** how Praxis builds
`Resource` parts decides whether the first-part-only gap (Appendix D) is
reachable through Praxis.

| Option | Behavior | Trade-off |
|---|---|---|
| **(a) Fold (proposed)** | All text entries of one `resources/read` are folded into a single `Resource` part; a rewrite emits one entry | Nothing goes uninspected, consistent with how Praxis folds tool text blocks. Per-entry `uri`/`mimeType` are not preserved on a rewrite. |
| (b) One part per entry | Each entry becomes its own `Resource` part | Keeps structure, but PPE inspects only the first part until Issue 76, so later entries bypass policy. |

With (a), the first-part-only gap stays a documented limitation for hosts that
emit several `Resource` parts, but is closed for Praxis. Non-text blocks (for
example blobs, which PPE does not project) are dropped on a rewrite, matching
current `tools/call` behavior, so the emitted bytes are exactly what policy
vetted.

**Praxis acceptance criteria (asserted on the bytes sent to the client, not on
the PPE `Message`):**

| Test | Assertion |
|---|---|
| Resource post-fetch redact | An SSN in `result.contents[].text` is masked in the response body the client receives |
| Prompt post-invoke redact | An SSN in `result.messages[].content` text is masked in the response body the client receives |
| Resource / prompt deny | A matching deny rule replaces the response with a JSON-RPC error |
| Multi-entry resource deny | A secret only in the **second** `contents[]` entry is denied |
| Malformed response | A malformed `resources/read` / `prompts/get` response with active post-phase rules fails closed |

**Sequencing:** Praxis depends on a published `praxis-policy` release, so the
byte-level `result.*` tests can only pass once a PPE release includes this
issue.

1. PPE: land this issue (projection and write-back) and release.
2. Praxis: response builders, re-serialization and fail-closed handling.
   Attribute-only post rules (identity, subject/meta predicates) work before
   step 1; `result.*` rules need it.
3. Praxis: adopt the PPE release and add the byte-level acceptance tests above.

---

## Detailed appendices

The sections below preserve the implementation-level specifications and
checklists from the source planning document, separated from the architectural
review narrative.

## Appendix A — Detailed envelope and write-back specification

### Solution: JSON envelope projection

Each missing entity/phase gets a fixed JSON envelope mapping struct fields to
APL paths. The body (`result.content`) is an opaque string when present and
`null` when absent; it is not auto-parsed. Two alternative approaches (raw
string, auto-parse JSON) were evaluated and ruled out; see [Appendix
C](#appendix-c-approach-comparison).

### Resource pre-fetch → `args`

From `ContentPart::ResourceRef`:

| Struct field | APL path | Type | Writable |
|---|---|---|---|
| `uri` | `args.uri` | String | No (read-only) |
| `name` | `args.name` | String or null | Yes |
| `resource_type` | `args.resource_type` | String (snake_case enum) | No (read-only) |
| `range_start` | `args.range_start` | Number or null | Yes |
| `range_end` | `args.range_end` | Number or null | Yes |
| `selector` | `args.selector` | String or null | Yes |

### Resource post-fetch → `result`

From `ContentPart::Resource`:

| Struct field | APL path | Type | Writable |
|---|---|---|---|
| `uri` | `result.uri` | String | No (read-only) |
| `name` | `result.name` | String or null | Yes |
| `title` | `result.title` | String or null | Yes |
| `description` | `result.description` | String or null | Yes |
| `resource_type` | `result.resource_type` | String (snake_case enum) | No (read-only) |
| `content` | `result.content` | String or null | Yes |
| `mime_type` | `result.mime_type` | String or null | Yes |
| `size_bytes` | `result.size_bytes` | Number or null | Yes |
| `version` | `result.version` | String or null | Yes |
| `annotations` | `result.annotations` | Object (may be empty) | Yes |
| `icons` | `result.icons` | Array or null | No (read-only) |

`result.content` is the body as an opaque string. APL can match, deny, or
rewrite the whole string but cannot address fields inside it. Body-field access
is a planned follow-up through an opt-in APL operator (e.g. `json`). A
`content_parsed` sibling field is not planned: it would put the body in the
envelope twice, so a redaction applied to one copy and not the other would leak,
with no clear rule for which copy is written back.

### Prompt post-invoke → `result`

From `ContentPart::PromptResult`:

| Struct field | APL path | Type | Writable |
|---|---|---|---|
| `prompt_name` | `result.prompt_name` | String | No (read-only) |
| `description` | `result.description` | String or null | Yes |
| `content` | `result.content` | String or null | Yes |
| `is_error` | `result.is_error` | Boolean | No (read-only) |
| `error_message` | `result.error_message` | String or null | Yes |

`messages` (`Vec<Message>`) is not projected — deferred to Issue 76.

### Complete projection reference

For all six entity/phase envelopes (including the three that already work), see
[six-envelope reference](#appendix-g-full-six-envelope-reference).

### Write-back rules

- Modify the original `ContentPart` in place. Never append a `Text` part.
- Preserve fields excluded from projection (`resource_request_id`,
  `prompt_request_id`, `blob`).
- Read-only fields: `uri` (both `ResourceRef` and `Resource`), `resource_type`
  (both), `prompt_name`, `is_error`, and `icons`. A config that writes them is
  refused at load ([Commit 3b](#3b-fixed-envelope-field-paths)). Write-back also
  preserves the original, as defence in depth. They remain readable, so rules
  such as `args.uri == 'hr://employees/restricted': deny` and `result.is_error
  == true: deny` still work.
- `u64` fields (`range_start`, `range_end`, `size_bytes`): convert via
  `serde_json::Number::from()` on projection; reject negative, fractional, or
  out-of-range values on write-back by clearing the optional field.
- `resource_type` is a closed enum (`File`, `Blob`, `Uri`, `Database`, `Api`,
  `Memory`, `Artifact`) projected as a snake_case string, and `is_error` is a
  `bool`. Both are read-only, so write-back never converts a value into them; it
  always keeps the original.
- `annotations` is a `HashMap<String, Value>`. Write-back uses **key-level
  merge** — only keys the pipeline addressed are updated; unmentioned keys are
  preserved. This is consistent with how `apply_changed_paths` already handles
  the tool result object, where a pipeline that redacts one field does not erase
  the others.
- `Option<String>` fields: see [Appendix B](#optional-string-fields).

---

## Appendix B — Write-back value conversion

### Optional string fields

For `Option<String>` target fields (`Resource.content`, `Resource.name`,
`PromptResult.content`, `PromptResult.error_message`, etc.):

| JSON value type | Write-back behavior |
|---|---|
| `Value::String(s)` | `Some(s)` |
| `Value::Null` | `None` (clears the optional field) |
| `Value::Object` / `Value::Array` / `Value::Bool` / `Value::Number` | Serialize to JSON string → `Some(serialized)` (e.g. `true` → `"true"`, `42` → `"42"`) |

Every non-null, non-string value is converted the same way. A write is never
dropped: preserving the original on a type mismatch would let a redaction that
produced an unexpected type silently send the unredacted original, which is the
failure this issue exists to remove. Rejecting the write is not possible at load
(the value's type is only known at runtime), and failing the request would turn
a slightly wrong rule into an outage.

`null` on a non-optional field (`uri`, `prompt_name`) does not arise: both are
read-only, so writes to them are refused at load and preserved at write-back.

### Removed fields, nested maps and numbers

Write-back receives the whole envelope after `apply_changed_paths` has merged in
the pipeline's changes . A field is missing from it only when the pipeline
removed it.

| Case | Example | Write-back behavior |
|---|---|---|
| Pipeline removes a field (`omit`) | `content: "SSN 123-45-6789"` → `result: { content: omit }` | Field cleared (`None`). Keeping the old value would leak exactly what the pipeline removed |
| Pipeline changes one `annotations` key | `{tier: "gold", owner: "hr"}` → `annotations: { tier: "silver" }` | `{tier: "silver", owner: "hr"}`. `apply_changed_paths` already merges nested objects key by key, so write-back replaces the map with the merged object. `null` or removal clears the map, like any other removed field; any other non-object value also clears the map |
| `u64` field gets an invalid value | `size_bytes: 2048` → `"-5"`, `-5`, `1.5`, or above `u64::MAX` | Invalid values, `null` and removal clear it |

**Same as tools.** A tool call's `arguments` and a tool result's `content` are
replaced whole with the merged value , so a key the pipeline removed is gone and
nested objects merge key by key. The only difference is the `u64` row: tool
values accept any JSON, while these envelope fields have fixed types.

### A whole envelope replaced by a non-object

The rows above apply per field. A pipeline can also replace the **whole**
envelope. A bare `**` path matches the root (`**` can match zero levels,
`crates/ppe-apl-core/src/route.rs`, `expand_for_pipeline`), so `result: { "**":
redact }` turns `{ uri, content, ... }` into the string `"[REDACTED]"`. A plugin
stage can do the same.

The first implementation followed the older tool-call convention, "silently
no-op when the shape does not match", and kept the original part. That rule came
from the existing code, not from this plan, and it breaks the principle above: a
redaction that produced an unexpected type silently sent the unredacted
original. A probe confirmed it: the config loaded, the request was allowed, and
`Resource.content` reached the client unredacted.

It cannot be refused at load. The same route sees an envelope when the host
sends a `Resource` / `PromptResult` / `ResourceRef` part and plain text when it
sends a text part, and `**` works on the text.

**Interim rule:** when write-back receives a non-object for a `ResourceRef`,
`Resource` or `PromptResult` part, the request is **denied** with code
`policy.envelope_replaced` and a reason pointing to `content: redact` or
`"**.<field>": redact`. This keeps the "never send the original" principle while
leaving the meaning of a bare `**` undecided. Denying rather than guessing (for
example, applying the string to `content`) avoids deciding what the pipeline
meant.

| Case | Result |
|---|---|
| `"**": redact`, or a plugin returning a non-object, on a message with an envelope part | Denied (`policy.envelope_replaced`) |
| `"**": redact` on a text-only resource or prompt message | Text redacted (unchanged) |
| `"**.<field>"`, `content: redact`, other named paths | Work (unchanged) |
| `llm:`, tool result | Unchanged |
| Tool call args, prompt request args | Non-object replacement is denied with `policy.envelope_replaced` |

The precise meaning of a bare `**` on structured payloads is tracked as a
follow-up (`policy-bare-double-star-semantics`). Current fixed-envelope
replacement is denied for resources, prompts and tool-call arguments.

---

## Appendix C — Projection alternatives

### Appendix C: Approach comparison

Three projection approaches were evaluated:

| | Raw string | Auto-parse JSON | **JSON envelope (chosen)** |
|---|---|---|---|
| Metadata access | No | No (unless wrapped) | **Yes** |
| Body field access | No | Yes (JSON only) | No (future `parse`) |
| Consistent shape | Yes (always scalar) | No (depends on mime) | **Yes (always object)** |
| Runtime compatible | Yes (whole-value replace) | Partially | **Yes** |
| Write-back safety | Whole-value only | Ambiguous edge cases | **1:1 field mapping** |
| Parse failure risk | None | Yes (silent or aggressive) | **None** |

**Raw string** works at runtime: for a non-object value, `apply_changed_paths`
replaces the whole value when it changed. It is ruled out because it exposes
only the content: `uri`, `mime_type`, `size_bytes` and the other metadata would
be invisible to policy.

**Auto-parse JSON** produces inconsistent shapes — the same route yields an
object for JSON bodies and a scalar for everything else. Policy authors cannot
predict the shape at write time. Parse failures are runtime surprises with no
error channel.

**JSON envelope** gives a stable, predictable shape. Every field maps 1:1 to a
struct field. No parsing, no ambiguity. Body-field access is deferred to a
future `parse` operator that policy authors opt into explicitly.

## Appendix D — Detailed implementation and test plan

### Commit 1: projected metadata fields

**Goal:** Add the CMF fields used by the resource and prompt envelopes.

- Define the shared `Icon` type and re-export it for hosts constructing
  `Resource.icons`.
- Add `Resource.title`, `Resource.icons`, and `PromptResult.description`.
- Update affected CMF fixtures and prove the projected key catalogs match the
  envelopes.
- Keep resolved MCP metadata fields, new `mcp.*` bag keys and their catalog
  entries, and dependency advisory changes outside this PR.

#### Verify

```console
make check
cargo nextest run -p praxis-policy-core --lib
cargo nextest run -p praxis-policy-apl-runtime --lib
```

### Commit 2: Core projection and write-back

**Goal:** Make `args.*` and `result.*` work for resources and prompts.

#### Changes

**`crates/ppe-apl-runtime/src/message_projection.rs`:**

Add three standalone projection functions:

| Function | Input | Result |
|---|---|---|
| `project_resource_ref_args` | `&ResourceReference` | `Value` |
| `project_resource_result` | `&Resource` | `Value` |
| `project_prompt_result` | `&PromptResult` | `Value` |

**Note:** `MessageView` in `crates/ppe-core/src/cmf/view.rs` already reads
`Resource.content`, `PromptResult.content`, resource URIs, and names via
`iter_views()` (currently has no callers outside its own tests). The projection
functions may reuse `MessageView` accessors internally or read struct fields
directly — implementer's choice. Either way, be aware the read side is largely
written; some of this may be wiring rather than new code.

Update extraction:

- `extract_args_from_message`: add `ContentPart::ResourceRef` arm
- `extract_result_from_message`: add `ContentPart::Resource` and
  `ContentPart::PromptResult` arms

Update write-back:

Add three standalone per-part write-back functions, the inverses of the
projection functions above:

| Function | Target | Input | Result |
|---|---|---|---|
| `write_resource_ref` | `&mut ResourceReference` | `&Value` | `Result<(), EnvelopeReplaced>` |
| `write_resource` | `&mut Resource` | `&Value` | `Result<(), EnvelopeReplaced>` |
| `write_prompt_result` | `&mut PromptResult` | `&Value` | `Result<(), EnvelopeReplaced>` |

Each applies the write-back rules (read-only fields preserved, `u64` and
`Option<String>` conversion, annotations key-level merge) to one part.

- `write_args_back_to_message`: add `ContentPart::ResourceRef` arm that calls
  `write_resource_ref`
- `write_result_back_to_message`: add `ContentPart::Resource` and
  `ContentPart::PromptResult` arms that call `write_resource` /
  `write_prompt_result` — modify in place, never append Text

Extraction selects the first matching part. Resource write-back follows the
originally selected URI and refuses missing or ambiguous targets. Issue 76 can
reuse the per-part functions for every part it inspects.

Document the current projection and write-back contract. The six-envelope table
belongs in the host documentation. For future per-part addressing, **new
structured text projections are objects**: a text-like part (for example `text`
or `thinking`) gaining structured projection uses `{"text": ...}`. Existing tool
results accept any JSON value and the legacy text-only fallback remains a bare
string. A field path never resolves on a bare string, so this keeps a `text`
field path working the same way on every kind of part. Praxis already wraps a
non-JSON tool result as `{"text": ...}`, and every envelope in this issue is an
object. Stating it here lets Issue 76 (proposal #201, which asks how a `match:`
entry addresses a scalar part) inherit the convention instead of choosing again.

#### Unit tests

In `message_projection.rs`:

| Test | Assertion |
|---|---|
| `args_round_trip_leaves_a_resource_ref_unchanged` | Extract → write back → message identical |
| `a_resource_ref_projects_its_fields_not_its_text` | `args.uri` is the URI, not empty string |
| `a_rewritten_resource_ref_field_differs_in_that_field_only` | Rewrite `args.selector` → write back → message equals the original with only `selector` replaced |
| `resource_ref_uri_is_not_overwritten_on_write_back` | Mutate `args.uri` → original preserved (fetch target cannot change after authorization) |
| `resource_ref_resource_type_is_not_overwritten_on_write_back` | Mutate `args.resource_type` → original preserved |
| `resource_ref_range_u64_fidelity_above_2_53` | Value above 2^53 round-trips exactly |
| `resource_ref_range_clears_on_a_non_u64_write` | Optional field cleared on invalid input |
| `result_round_trip_leaves_a_resource_unchanged` | Extract → write back → identical |
| `a_resource_projects_its_envelope_not_its_text` | `result.content` is the body, `result.uri` is the URI |
| `a_redacted_resource_content_differs_in_that_field_only` | Rewrite `result.content` → message equals the original with only `content` replaced |
| `resource_uri_and_type_are_not_overwritten_on_write_back` | Mutate `result.uri` and `result.resource_type` → originals preserved |
| `result_round_trip_leaves_a_prompt_result_unchanged` | Extract → write back → identical |
| `a_prompt_result_projects_its_fields_not_its_text` | `result.content` is rendered text, not empty string |
| `a_redacted_prompt_result_content_differs_in_that_field_only` | Rewrite `result.content` → message equals the original with only `content` replaced |
| `prompt_name_is_not_overwritten_on_write_back` | Mutate `result.prompt_name` → original preserved |
| `prompt_is_error_is_not_overwritten_on_write_back` | Mutate `result.is_error` → original preserved |
| `prompt_result_description_differs_in_that_field_only` | Rewrite `result.description` → message equals the original with only `description` replaced |
| `string_field_write_back_converts_every_value_type` | Write `true`, `42`, an object and an array into `result.content` → stored as `"true"`, `"42"` and their JSON strings; never preserved |

**"In that field and nowhere else."** The issue's round-trip criterion is that
the message differs in the mutated field *and nowhere else*. Checking that the
new value is present is not enough. Each rewrite test builds the expected
message by cloning the original and setting the one field by hand, then asserts:

- `assert_eq!(written_back, expected)`: the whole message, not just the field
- `written_back.content.len() == original.content.len()`: no part appended
- no `ContentPart::Text` in `written_back.content` when the original had none

Put these in a shared helper (`assert_differs_only_in(original, written_back,
|expected| ...)`) so every rewrite test, including the `PromptRequest`
regression guard, uses the same check.

#### PromptRequest regression guard

`PromptRequest` pre-invoke projection is claimed as already working (it matches
`ContentPart::PromptRequest` in `extract_args_from_message` today). Add one
regression test to verify this claim and guard against future breakage:

| Test | Assertion |
|---|---|
| `prompt_request_args_round_trip` | Extract args from a `PromptRequest` with `{tone: "terse", length: 200}`, write back with a modified field, verify the message changed in that field only |

#### Integration tests (e2e through the visitor)

The issue requires: *"e2e tests that redact a field of a fetched resource and of
a rendered prompt, and that deny on their contents. Assertions on a deny, not on
an allow."*

Unit tests verify `message_projection.rs` in isolation. Integration tests
dispatch a message through the full visitor pipeline (route matching → hook
dispatch → APL evaluation → write-back) and assert on the **outcome** — deny or
redacted content. These go in `crates/ppe-apl-runtime/tests/visitor_e2e.rs`.

| Test | Setup | Assertion |
|---|---|---|
| `resource_post_fetch_deny_on_content` | Route: `resource: hr://employees/*`, policy: `result.content == 'topsecret': deny('secret resource content')`. Message: `ContentPart::Resource` with `content: Some("topsecret")` | **Denied** with reason; clean content allowed |
| `resource_post_fetch_redact_content` | Route: `resource: hr://employees/*`, policy: `result: { content: "str \| redact" }`. Message: resource with SSN in content | `Resource.content` is `[REDACTED]`, no appended Text part, `uri` unchanged |
| `resource_pre_fetch_deny_on_uri` | Route: `resource: hr://employees/*`, policy: `args.uri == 'hr://employees/restricted-42': deny('restricted resource')`. Message: `ContentPart::ResourceRef` with that URI | **Denied** with reason; other URI allowed |
| `prompt_post_invoke_deny_on_content` | Route: `prompt: summarize-*`, policy: `result.content == 'ignore previous instructions': deny('prompt injection')`. Message: `ContentPart::PromptResult` with that text | **Denied** with reason; clean prompt allowed |
| `prompt_post_invoke_redact_content` | Route: `prompt: summarize-*`, policy: `result: { content: "str \| redact" }`. Message: prompt result with SSN | `PromptResult.content` is `[REDACTED]`, no appended Text part, `prompt_name` unchanged |
| `prompt_post_invoke_deny_on_is_error` | Route: `prompt: "*"`, policy: `result.is_error == true: deny('render failed')`. Message: `ContentPart::PromptResult` with `is_error: true` | **Denied** with reason; successful render allowed |

These tests must assert on **deny decisions or modified message content**, never
on allow alone — an allow is indistinguishable from the broken behavior this
issue fixes. Each deny test also sends a clean input to the same route and
expects an allow, so a route that denies everything cannot pass.

**APL matching in these examples.** APL rules have no regex operator, and
`contains` tests membership in a set, so on a string it is always false
(`crates/ppe-apl-core/src/evaluator.rs:206-209`). Rules therefore use exact `==`
matches, and redaction uses the `redact` transform, which replaces the whole
value. That still proves the content reaches policy: before this issue, policy
saw `""`, so an exact match never succeeded. Matching a pattern inside the text
(an SSN anywhere in a body) needs a `regex(...)` validator or a `pii.redact` /
`injection.scan` stage in a `result:` pipeline, or a plugin. These were not
exercised here.

These tests prove the PPE side only: the `Message` handed back to the host is
denied or modified. They pass even if the host never serializes the change into
the response. Delivery to the client is covered by the Praxis acceptance
criteria in [§11.1](#111-host-dependency-praxis-response-handling).

#### Known gap: multi-resource messages

`extract_args_from_message`, `extract_result_from_message` and their write-back
counterparts walk `msg.content` and stop at the **first** matching part. The new
`ResourceRef` / `Resource` / `PromptResult` arms inherit this.

A single MCP `resources/read` can return several contents, for example a
directory or templated URI. If the host maps each one to its own
`ContentPart::Resource`, only the first is projected and written back:

```text
content: [ Resource { uri: ".../a.txt", content: "harmless" },     ← projected, redacted
           Resource { uri: ".../b.txt", content: "123-45-6789" } ] ← not seen, passes through
```

This is the same class of silent bypass this issue fixes, limited to the second
and later parts. Tools behave the same today (only the first `ToolResult` is
projected), but multi-content resource reads are a normal case, so the exposure
is higher here.

**Decision:** this issue projects the first matching part only. Projecting every
part needs per-part addressing, which is Issue 76's scope. The gap is pinned by
a test and documented in the host guide rather than left silent.

Whether the gap is reachable depends on the host. If Praxis folds every text
entry of a `resources/read` into one `Resource` part (option (a) in
[§11.1](#111-host-dependency-praxis-response-handling)), it is closed for
Praxis and remains only for hosts that emit several `Resource` parts.

| Test | Setup | Assertion |
|---|---|---|
| `known_gap_only_the_first_resource_part_is_projected` | Route: `resource: hr://employees/*`, policy: `result.content == '123-45-6789': deny('ssn in resource')`. Message: two `ContentPart::Resource` parts, SSN only in the **second** | Asserts **Denied**; fails today. `#[should_panic(expected = "known gap #76")]`, with the assertion message containing `known gap #76` |

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

`PromptResult` has two places for the rendered prompt: a flat `content:
Option<String>` and `messages: Vec<Message>`. This issue projects `content`
only. `messages` is deferred to Issue 76.

That leaves a hole in the main prompt-side use case. The issue says scanning a
rendered prompt for injected instructions is "precisely the use case". MCP
`prompts/get` returns `messages`, so a host that maps the response faithfully
may fill `messages` and leave `content` as `None`. Then `result.content` is
null, an injection rule like `result.content == 'ignore previous instructions':
deny` never matches, and the prompt passes with no signal. This is the same
silent bypass this issue fixes, limited to hosts that don't fill `content`.

**Decision:** for this issue:

1. The host guide makes it a **MUST** that a host set `PromptResult.content` to
   the rendered text whenever it sends a `PromptResult` (the text parts of
   `messages`, joined in order). It also names the failure mode if the host
   leaves it out (see Commit 4). The MUST lasts until Issue 76, and until then
   `content` is the authoritative copy: the host serializes the response from
   `content`, not from the original `messages`. Once Issue 76 projects
   `messages`, carrying the text in both places would let a redaction of one
   copy leak through the other, so Issue 76 must say which copy wins.
2. The gap is pinned by a test, so it is not silent in the codebase either:

| Test | Setup | Assertion |
|---|---|---|
| `known_gap_prompt_result_messages_are_not_projected` | Route: `prompt: summarize-*`, policy: `result.content == 'ignore previous instructions': deny('prompt injection')`. Message: `ContentPart::PromptResult` with `content: None` and the injection text only inside `messages` | Asserts **Denied**; fails today. `#[should_panic(expected = "known gap #76")]` |

A read-only fallback, where `content` is derived from `messages` when it is
`None`, would close the hole without waiting for Issue 76. But a redaction of
the derived value has nowhere to be written back, which is the "write-back
appends or drops" problem this issue exists to avoid. It is not adopted: a deny
on the derived value would pass the tests while a redaction of the same text
silently does nothing (see Appendix F).

#### Verify

```console
cargo nextest run -p praxis-policy-apl-runtime --lib   # unit tests
cargo nextest run -p praxis-policy-apl-runtime --test visitor_e2e  # integration tests
make test
```

---

### Commit 3: Config validation

**Goal:** Refuse field blocks that can address nothing, at load time instead of
at runtime.

Two pieces of work were planned. 3a is deferred; 3b ships, and it is what meets
AC3 for the resource and prompt routes the issue is about.

#### 3a. Shapes with no field path on `llm:` routes (deferred)

Planned: extend `reject_field_stages_without_fields` from `http:` to `llm:`,
refusing named field paths (`args: { prompt: ... }`) on a payload that projects
as plain text, and keeping `**`-only paths.

Deferred out of this issue, to the separate LLM issue, because:

- **The issue scopes LLM out.** Its projection table reads "llm, both: the
  concatenated Text parts. See the separate LLM issue".
- **AC3's own case is met by 3b.** The issue's example is `result: { ssn: ... }`
  on a *resource* route, which 3b now refuses at load
  (`reject_unknown_field_paths`).
- **It is a breaking change** for `llm:` configs that load today, and it fails
  two Praxis tests that declare named fields on an `llm:` route on purpose
  (`a_field_mutator_leaves_an_inference_request_untouched` /
  `..._response_untouched`). The workspace search planned here ("found none")
  did not cover Praxis's tests.
- **The `**` exception does not hold through Praxis.** The probe that returned
  `[REDACTED]` ran against PPE alone; Praxis does not rewrite inference bodies
  and sends the original (`praxis/.../policy/filter.rs`, "Policy field mutators
  do not rewrite inference bodies"). So the design question is broader than
  named fields, and belongs with `policy-bare-double-star-semantics`.

In this issue: `reject_field_stages_without_fields` is unchanged from `main`
(`http:` only). `llm:` field blocks keep loading and keep having no effect, as
before; this is not a regression.

#### 3b. Fixed envelope field paths

AC3's principle (a block that can never take effect should not load) applied to
field names, now that resource and prompt envelopes have a fixed set of fields.
This is what refuses the issue's own example, `result: { ssn: ... }` on a
resource route.

Define static valid-field sets, keyed by **content kind** rather than by entity
and phase, so Issue 76 `match:` entries (which select parts by kind on any
route) can reuse them:

```text
ResourceRef:  {uri, name, resource_type, range_start, range_end, selector}
Resource:     {uri, name, title, description, resource_type, content,
               mime_type, size_bytes, version, annotations, icons}
PromptResult: {prompt_name, description, content, is_error, error_message}
```

For Issue 75 the config check maps each route and phase to its content kind
(resource `args` → `ResourceRef`, resource `result` → `Resource`, prompt
`result` → `PromptResult`) and uses that set.

Rules:

- **Match on the first path segment.** `annotations` is an open map, so
  `result.annotations.audience` must be accepted. The check is "the first
  segment is in the set". Deeper segments are checked only for scalar fields
  (`result.content.ssn` is refused: `content` is an opaque string, see [body
  parsing](#resource-post-fetch--result)).
- **Writes to read-only fields are refused.** An `args:` or `result:` block that
  writes `uri`, `resource_type`, `prompt_name`, `is_error` or `icons` is refused
  at load. Write-back also preserves these identity and classification fields as
  defence in depth. Invalid writable optional `u64` values are detected at
  runtime and clear the field instead of retaining its old value.

  ```text
  ResourceRef read-only:  {uri, resource_type}
  Resource read-only:     {uri, resource_type, icons}
  PromptResult read-only: {prompt_name, is_error}
  ```

The read-only check needs only these small sets, not the full field catalog. If
the unknown-field part of 3b moves to a follow-up, the read-only refusal stays
in this issue.

- **Dynamic-key envelopes are not checked.** Tool `args` / `result` and prompt
  `args` take their keys from the host's arguments map, so they have no static
  set.
- **Same scopes as the `http:` guard.** The route's own block and
  `global.defaults.<entity>`.

The error message names the block (`args` or `result`), the entity type, the
offending path, and either the valid set or "read-only".

Cost: validation is coupled to the envelope shape, so adding an envelope field
means updating its set. A unit test asserts each static set equals the keys the
matching `project_*` function emits, so the two cannot drift.

#### Tests

| Test | Expected |
|---|---|
| `result:` on HTTP route | Rejected (existing, regression guard) |
| `args:` with a named field on LLM route | Deferred — loads without error, fields have no effect (Praxis does not rewrite inference bodies) |
| `result:` with a named field on LLM route | Deferred — loads without error, fields have no effect |
| `args:` with a named field under `global.defaults.llm` | Deferred — loads without error, fields have no effect |
| `"**"` on LLM route, route and `global.defaults.llm` | Deferred — loads without error; Praxis does not rewrite inference bodies, so the redaction does not reach the client |
| `"**"` with a named field on LLM route | Deferred — loads without error, fields have no effect |
| `args:` with valid fields on resource route | Accepted |
| `result:` with valid fields on resource route | Accepted |
| `result:` with `annotations.audience` on resource route | Accepted (nested path under an open map) |
| `args:` with unknown field on resource route | Rejected with diagnostic |
| `result:` with unknown field on prompt route | Rejected with diagnostic |
| `result:` with `content.ssn` on resource route | Rejected (`content` is opaque) |
| `result:` writing `prompt_name` on prompt route | Rejected as read-only |
| `result:` writing `icons` on resource route | Rejected as read-only |
| `args:` writing `uri` on resource route | Rejected as read-only |
| `result:` writing `uri` on resource route | Rejected as read-only |
| `args:` / `result:` writing `resource_type` on resource route | Rejected as read-only |
| `result:` writing `is_error` on prompt route | Rejected as read-only |
| Predicate reading `args.uri` / `result.is_error` | Accepted (read-only fields stay readable) |
| Static field sets match `project_*` output keys | Pass (drift guard) |

#### Verify

```console
cargo nextest run -p praxis-policy-apl-runtime --lib
make test
```

---

### Commit 4: Host contract section

**Goal:** Document what a host must put on a message for policy to work. The
**contract** ships with the code in this PR; the full guide with worked recipes
follows in a separate PR.

The issue requires a contract covering what goes on the message **and in
MCPExtension**. Three layers feed policy, and the guide must cover all of them:

| Layer | What it feeds | Source struct |
|---|---|---|
| `MetaExtension` (`entity_type`, `entity_name`) | Route matching | Set by host |
| `MCPExtension` (`ResourceMetadata`, `PromptMetadata`, `ToolMetadata`) | PDP attribute bag (`mcp.resource.*`, `mcp.prompt.*`, `mcp.tool.*`) | Set by host |
| `ContentPart` (`ResourceRef`, `Resource`, `PromptResult`, etc.) | APL `args.*` / `result.*` projection | Set by host |

A host that sets only MCPExtension but no ContentPart gets route matching and
PDP predicates but empty APL envelopes. This is the most likely misconfiguration
and must be called out explicitly.

#### In this PR: the contract, in a new guide

A new doc, `docs/content/host-integration-guide.md`, holding only the contract
for now. It is linked from `docs/content/index.md`, from `cmf.md`, and from the
`mcp` slot section of `cmf-extensions.md`. It covers:

- **The MUSTs:**
- `PromptResult.content` set to the rendered text (until Issue 76), and
    `content` is authoritative on the way out;
- `MCPExtension` comes from the host's own catalog, never from values the agent
    sent;
- read-only fields (`uri`, `resource_type`, `prompt_name`, `is_error`, `icons`).
- **The layer definitions:**
- `ContentPart` = wire view, `MCPExtension` = resolved identity, no equality
    required;
- `entity_name` (today: the name the agent sent);
- `ToolCall.namespace` (agent-facing namespace);
- which layer authorization rules and content rules key on.
- **The two known gaps:** multi-resource messages (first part only) and prompt
  results carried only in `messages`.

A separate doc was chosen over a section of `cmf-extensions.md`: that doc is the
attribute-bag contract, while this one is about the message a host builds, and
the follow-up guide already had this file name. Starting the file now means the
contract does not move when the recipes arrive.

#### Follow-up PR: full host integration guide

The worked recipes below follow in a separate PR. They are added to
`docs/content/host-integration-guide.md`, build on the contract already there,
and do not change it.

##### Structure

Six recipes (one per entity/phase), each following:

```text
Step 1 — Host builds a CmfMessage     (JSON example, MUST/SHOULD/MAY)
         Covers all three layers: MetaExtension, MCPExtension, ContentPart
Step 2 — What APL sees                 (envelope field → value)
Step 3 — What PDP sees                 (attribute bag keys from MCPExtension)
Step 4 — Example policy                (YAML)
Step 5 — What goes wrong if skipped    (per-field, per-layer consequences)
```

Plus a common-mistakes section covering:

- Layer meanings: `ContentPart` is the wire view (what the agent sent),
  `MCPExtension` is the resolved identity (from the host's catalog). They may
  differ, for example behind a federating gateway, and PPE does not require them
  to be equal
- `ToolCall.namespace` vs `ToolMetadata.namespace`: the first is the namespace
  the agent sees (if any, otherwise `None`); the second is the upstream server's
  namespace from the host's catalog. Do not copy one into the other
- `entity_name` is the name the agent sent today: write routes against the names
  agents actually call, including any gateway prefix
- Filling `MCPExtension` from the agent's request lets the agent choose what is
  authorized. Fill it from the host's catalog, or leave it unset
- On a host that does not set `MCPExtension` (Praxis today), `mcp.*` rules have
  nothing to read; use route matching and identity instead
- Missing ContentPart with MCPExtension-only (route matches but APL sees null)
- Missing MCPExtension with ContentPart-only (APL works but PDP predicates are
  empty)
- The read-only contract (`uri`, `resource_type`, `prompt_name`, `is_error`,
  `icons`), and that fetch redirection is not a policy-pipeline write
- `PromptResult` with `messages` but no `content`: hosts **MUST** set `content`
  to the rendered text (text parts of `messages`, joined in order). Otherwise
  `result.content` is null and content rules on the prompt route, injection
  scanning included, never match. Pinned by
  `known_gap_prompt_result_messages_are_not_projected` until Issue 76. Until
  then `content` is authoritative on the way out: serialize the response from
  `content`, not from the original `messages`
- Multi-content resource reads: only the first `Resource` part is projected
  until Issue 76. Hosts should map one fetched content per message, or treat
  multi-content reads as only partly covered by policy

##### Verify

Prose review only.

---

## Appendix E — Issue 76 comparison and complete checklist

### Relationship with Issue 76

| | This issue (75) | Issue 76 |
|---|---|---|
| Scope | Per-message projection | Per-view content-part addressing |
| `PromptResult.messages` | Not projected | Projected |
| Several `Resource` parts in one message | First part only (known gap, pinned by test) | Every part |
| New syntax | None | `match:` blocks |
| `iter_views()` | Not used | Integrated |

Issue 75 lands first. The projection helpers are standalone functions so Issue
76 can reuse them.

---

### Definition of done

#### Commit 1: projected metadata fields

- [ ] `Icon` is defined and re-exported for `Resource.icons`
- [ ] CMF `Resource` has `title` and `icons`
- [ ] CMF `PromptResult` has `description`
- [ ] Fixed envelope keys match the remaining CMF fields
- [ ] Resolved MCP metadata, new bag keys and advisory changes stay out
- [ ] Tests pass

#### Commit 2: projection and write-back

- [ ] `ResourceRef` fields available through `args`
- [ ] `Resource` fields available through `result`
- [ ] `PromptResult` fields available through `result`
- [ ] Write-back modifies original structured part (no appended Text)
- [ ] Per-part write-back functions (`write_resource_ref`, `write_resource`,
  `write_prompt_result`) exist and are called by the message-level arms
- [ ] `u64` fields round-trip above 2^53; invalid values clear the field
- [ ] `uri` (both envelopes), `resource_type` (both), `prompt_name`, `is_error`
  and `icons` are read-only on write-back
- [ ] Doc comment on `message_projection.rs` with the six-envelope table, fixed
  object envelopes, and the object convention for new structured text
- [ ] Unit tests: round-trip, rewrite, wrong-shape, u64 fidelity
- [ ] A whole envelope replaced by a non-object is refused at write-back and the
  request denied (`policy.envelope_replaced`), never sending the original;
  text-only messages and `"**.<field>"` unchanged
- [ ] Every rewrite test asserts the whole message equals the original with only
  the mutated field changed, part count unchanged, no `Text` part added (shared
  `assert_differs_only_in` helper)
- [ ] PromptRequest regression guard: args round-trip verified for prompt
  pre-invoke
- [ ] Integration tests: resource deny, resource redact, resource pre-fetch
  deny, prompt deny, prompt redact, prompt is_error deny — all asserting on
  deny/modified content, not on allow
- [ ] Multi-resource gap pinned:
  `known_gap_only_the_first_resource_part_is_projected` with
  `#[should_panic(expected = "known gap #76")]`
- [ ] Prompt `messages`-only gap pinned:
  `known_gap_prompt_result_messages_are_not_projected` with
  `#[should_panic(expected = "known gap #76")]`

#### Commit 3: config validation

- [ ] (3a) Deferred to the LLM issue; `reject_field_stages_without_fields`
  unchanged from `main`
- [ ] (3a) Existing HTTP route rejection preserved
- [ ] (3b) Unknown field paths rejected at load time with diagnostic; nested
  paths under `annotations` accepted
- [ ] (3b) Writes to read-only fields (`uri`, `resource_type`, `prompt_name`,
  `is_error`, `icons`) rejected at load
- [ ] (3b) Valid field paths accepted for resource and prompt routes
- [ ] (3b) Static field sets match `project_*` output keys (drift test)

#### Commit 4: host contract section

- [ ] `docs/content/host-integration-guide.md` holds the contract (MUSTs, layer
  definitions, two known gaps) and is linked from `index.md`, `cmf.md` and
  `cmf-extensions.md`
- [ ] The guide's resource and prompt policy fences are loaded by the docs
  example suite and exercised by visitor E2E deny and redaction tests
- [ ] The guide distinguishes PPE support from the pending Praxis adapter

#### Follow-up PR: full host integration guide

- [ ] `docs/content/host-integration-guide.md` covers all six entity/phase
  combinations
- [ ] Each recipe covers all three layers: MetaExtension, MCPExtension,
  ContentPart
- [ ] MUST/SHOULD/MAY field requirements per entity/phase
- [ ] JSON examples and "what goes wrong" sections (per-field, per-layer)
- [ ] Policy examples and host fixtures have regression coverage through the
  real parser and policy engine, with allow, deny and write-back assertions
- [ ] Common mistakes: MCPExtension-only, ContentPart-only, layer meanings (wire
  view vs resolved identity), multi-content resource reads, `PromptResult`
  without `content`

#### Host dependency (Praxis, tracked separately)

- [ ] Praxis change opened and linked from Issue 75
- [ ] Multi-resource option agreed with Praxis maintainers (fold proposed)
- [ ] `resources/read` and `prompts/get` responses build `Resource` /
  `PromptResult` parts
- [ ] Changed fields re-serialized into the response body
- [ ] Malformed resource/prompt responses fail closed when post-phase rules are
  active
- [ ] Byte-level acceptance tests from §11.1 pass against a PPE release that
  includes this issue

#### Overall

- [ ] `make check` passes
- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] Issue 76 functionality remains outside this change

---

## Appendix F — Existing design-decision register

### Design decisions

#### Settled

| Decision | Rationale |
|---|---|
| **JSON envelope** over raw string or auto-parse | Raw string hides all metadata from policy (it would work at runtime via whole-value replace). Auto-parse has non-deterministic shape. See [Appendix C](#appendix-c-approach-comparison). |
| **`Resource.blob` excluded** | Byte-level inspection is not a policy engine concern |
| **`prompt_name` read-only** | Mutating identity breaks correlation. Writes refused at load (3b) and preserved at write-back |
| **`uri` read-only (both envelopes)** | Same kind of identity field as `prompt_name`. A writable `args.uri` redirects the fetch after authorization; a writable `result.uri` misreports the source. Fetch redirection needs its own design (re-authorizing effect or gateway routing) |
| **`resource_type`, `is_error` read-only** | No known write use case; more likely to cause a mistake than to serve one. Can be loosened later without breaking configs |
| **Deny a whole-envelope replacement** | A bare `**` (or a plugin) can replace a resource / prompt envelope with a string, which write-back cannot apply. Keeping the original leaked; refusing at load is impossible because the shape is known only at runtime. Deny until the meaning of `**` is defined (follow-up `policy-bare-double-star-semantics`) |
| **Defer field paths on `llm:` routes** | The issue scopes LLM out ("see the separate LLM issue"); AC3's resource example is met by 3b. Refusing `llm:` named fields would break configs and two Praxis tests, and the `**` exception does not take effect through Praxis, which does not rewrite inference bodies. Tracked with the LLM issue and `policy-bare-double-star-semantics` |
| **Reject unknown and read-only fields at load** | Goes beyond AC3, same principle: silence caused this bug. Drift test keeps the sets in step with the envelopes |
| **`PromptResult.content` is a host MUST, until Issue 76** | `messages` is Issue 76; until then a host that fills only `messages` defeats content rules. `content` is the authoritative copy on the way out. Documented and pinned by a known-gap test. A read-only `content` derived from `messages` was rejected: a deny on it would pass the tests while a redaction of the same text silently does nothing |
| **ContentPart only, no MCPExtension fallback** | `ContentPart` and `MCPExtension` are different views (wire view vs resolved identity), so falling back would quietly swap the agent's name for the resolved one. Consistent with how tools work |
| **Layers are views; no consistency check** | `ContentPart` is the wire view (what the agent sent) and `MCPExtension` is the resolved identity (from the host's catalog). A gateway may legitimately make them differ, so equality is neither enforced nor expected. The guide documents what each layer means |
| **`ToolCall.namespace` = agent-facing namespace** | Not in MCP and never read by PPE, so its meaning was undefined. Kept rather than removed (it is a public CMF field shared with CPEX) and defined to match the wire view: the namespace the agent sees, if any. The upstream namespace stays in `ToolMetadata.namespace` |
| **Host contract ships with the code; full guide follows** | The code depends on hosts honoring the MUSTs, so the contract (MUSTs, layer definitions, two known gaps) lands in this PR as a new `host-integration-guide.md`, kept separate from the attribute-bag doc. The six worked recipes follow in a separate PR, added to the same file |
| **Icons not in the PDP attribute bag** | Display metadata; no known rule keys on an icon URL. Kept on structs (struct-only, like `inputSchema`). A `StringSet` of `src` values can be added later if a use case turns up; adding is non-breaking, removing would be |
| **`MCPExtension` from host catalog only** | Authorization keys on it, so agent-supplied values would let the agent choose what is authorized. Hosts without a catalog leave it unset |
| **Body parsing deferred; operator preferred** | The future path is an opt-in APL operator (e.g. `json`), used per rule, which leaves the envelope unchanged. A `content_parsed` sibling field is not planned: two copies of the body let a redaction of one copy leak through the other. Neither blocks this issue. |

#### Open (needs team input)

Routing names are a documented host-owned choice, as recorded in
[§8 question 3](#8-open-questions-for-review). No unresolved routing-name
requirement changes PPE's projection behavior.

---

## Appendix G: Full six-envelope reference

### Complete projection reference

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

### Fallback

Any content part not matched above falls through to
`Value::String(msg.get_text_content())` — the concatenated text parts.

---
