---
date: 2026-09-28
topic: llm-request-authorization
issue: https://github.com/praxis-proxy/policy/issues/142
---

# Authorize LLM request JSON and lists of complex objects

## Summary

Praxis hands PPE the inference request it already parsed, as a read-gated structured document.
PPE gives OPA, CEL, and Cedar native access to it as `llm.request`, and to structured MCP tool
arguments as `args`, without changing APL or the scalar attributes existing policies rely on.
Diagnostics never print payload values. The work ships as a coordinated PPE and Praxis PR pair.

---

## Problem Frame

A colleague building an SSRF guard wants to reject any inference request whose `tools[]`
contains an element whose `type` does not match a regex allowlist:

```json
{"model":"m","messages":[],
 "tools":[{"type":"web_search_20250305"},{"type":"function","function":{}}],
 "mcp_servers":[...]}
```

No PDP can see `tools[]` today. The data is dropped at three points:

- **Praxis projection.** Praxis parses the whole body once and keeps the parsed value until
  `cmf.llm_input`, but it only passes the model, configured top-level scalar parameters
  (`custom.llm.*`), and prompt text
  (`../praxis/crates/filter/src/builtins/http/security/policy/{filter.rs,llm.rs}`).
  Responses-API `input` is not projected at all, so text scanners see an empty prompt for
  those requests.
- **PPE flattener.** The attribute bag holds only bool, int, float, string, and string set.
  The JSON flattener drops any array that contains an object or a nested array
  (`crates/ppe-apl-cmf/src/payload.rs`). A structured MCP argument such as
  `args.items[].classification` is therefore lost before it reaches OPA or CEL, even though
  both engines can iterate lists.
- **Data model.** The LLM extension carries model id, provider, and capabilities only
  (`crates/ppe-core/src/extensions/llm.rs`). It does not carry tools, MCP servers, or
  response format.

Adding the data safely has two complications:

- **Plugin access.** The existing `llm` and `custom` extension slots are readable and
  writable by every plugin. The `read_llm` and `read_custom` capability names exist but
  nothing enforces them.
- **Diagnostic leaks.** On deny, CEL diagnostics print every bag value under any namespace
  the expression references (`crates/builtins/src/pdps/cel/resolver.rs`). Adding a full
  request document naively would put prompts and the request JSON into diagnostics.

Switching engines does not help. The input is missing before OPA or CEL run.

---

## Actors

- A1. Policy author: writes OPA, CEL, or Cedar rules against inference and tool-call requests.
- A2. Praxis policy filter (host): parses the request, attaches PPE inputs, and forwards or
  rejects.
- A3. PPE route handler: builds PDP input from host-supplied extensions and CMF content.
- A4. Third-party plugin: reads request data only if it declares the read capability.

---

## Key Flows

- F1. Inference request authorization
  - **Trigger:** a client POSTs a JSON body with a valid top-level `model` to an `llm:` route.
  - **Actors:** A2, A3, A1
  - **Steps:**
    1. Praxis applies its existing size and model gates.
    2. Praxis attaches the parsed document to the gated slot, alongside the current model,
       scalar, and prompt projection. The prompt projection now includes Responses `input`
       text.
    3. PPE builds PDP input: flat attributes as today, plus the structured side channel.
    4. OPA, CEL, and Cedar evaluate against `llm.request`.
  - **Outcome:** on allow, the original bytes go upstream unchanged. On deny, nothing reaches
    upstream and the client gets a deny reason that contains no payload values.
  - **Covered by:** R1-R5, R9-R12, R14-R17
- F2. MCP `tools/call` authorization
  - **Trigger:** a JSON-RPC `tools/call` request reaches a `tool:` route.
  - **Actors:** A2, A3, A1
  - **Steps:** Praxis builds the CMF ToolCall as today. PPE exposes its arguments to PDPs as
    structured `args`, and APL predicates keep reading the flattened `args.*` scalars.
  - **Outcome:** a PDP can iterate `args.items`, and APL scalar predicates behave as before.
  - **Covered by:** R6-R8, R13

---

## Requirements

**Host input (Praxis)**
- R1. At `cmf.llm_input`, Praxis passes the full parsed request body to PPE as a structured
  document. It reuses the value it already parsed and does not parse or deep-copy the body a
  second time.
- R2. The existing model, route, ambiguity (`jsonrpc`/`method`), and `llm.max_request_bytes`
  gates are unchanged. Oversized bodies still fail closed before PPE is invoked.
- R3. The prompt projection also covers Responses-API `input`: a string `input`, and the text
  parts of `input[].content`. Chat Completions, Anthropic `system`/`messages`, and legacy
  `prompt` projection behave as before.
- R4. On allow, the upstream body is byte-for-byte the original. On deny, the request never
  reaches upstream.

**Carrier and access (PPE)**
- R5. PPE provides a new extension slot for the structured request document. The host sets
  it, and plugins cannot mutate it. It is separate from the unrestricted `llm` and `custom`
  slots, neither of which carries the document.
- R6. Built-in PDPs can always read structured inputs. Any other plugin receives the slot only
  if it declares a new read capability; otherwise the slot is absent from its view.
  Enforcement is real, not an advisory label.
- R7. Structured MCP arguments come from the CMF ToolCall arguments already in the message,
  with the existing first-ToolCall selection. They are gated the same way as R6 when handed to
  PDPs as structured input.

**PDP input**
- R8. PDPs receive a structured side channel next to the flat attribute bag. Under the name
  `args` the side channel replaces the flattened `args.*` view in PDP input. APL continues to
  evaluate the flattened scalars unchanged.
- R9. OPA sees `input.llm.request` and `input.args` as native JSON. CEL sees `llm.request` and
  `args` as native lists and maps, so `exists`, `all`, and `matches` work over them. Existing
  `llm.model_id`, `llm.provider`, `llm.capabilities`, `custom.llm.*`, and other flat names keep
  their current meaning.
- R10. Cedar sees `llm.request` and `args` in context as records and sets. Array order and
  duplicates cannot be preserved in Cedar sets, and the docs say so.
- R11. Types survive intact for OPA and CEL: objects, array order, repeated elements,
  booleans, integers, floats, nulls, empty arrays, and empty objects.
- R12. The flat attribute bag, APL grammar, and APL evaluator are unchanged. Every existing
  APL, CEL, OPA, and Cedar scalar or set policy stays valid. The one exception is OPA/CEL
  policies that read `args` on `tool:` routes: `args` becomes native JSON, which is a
  documented breaking change in 0.4.0 (see Key Decisions).

**Fail-closed**
- R13. When the host does not supply a structured input, it is absent. It is never an empty
  object or list. A policy that depends on it cannot allow by default:
  - A CEL reference to a missing field is an evaluation error and denies under the default
    `on_error`.
  - An undefined OPA query result denies.
  - A Cedar access to a missing attribute errors and denies.

**Diagnostics and audit**
- R14. For structured inputs, CEL deny and error diagnostics report key names and value types,
  never values. OPA decision diagnostics and violation reasons carry no request-document
  content unless a policy author explicitly writes it into a reason.
- R15. Audit events, error messages, and `tracing` output never contain prompt text or the
  request JSON. Normal deny reasons and codes stay useful.

**Docs and delivery**
- R16. Docs cover the input names, missing and null field behavior, which JSON requests
  qualify for inference routing, size limits, filter ordering, the read capability, and the
  Cedar ordering limitation. They include the SSRF regex-allowlist example over `tools[].type`
  in both OPA and CEL.
- R17. Delivery is a coordinated PR pair. The PPE PR lands and is released first, as a minor
  version because the PDP input contract changes. The Praxis PR stays in draft on a git
  dependency to the PPE branch until the release exists, then switches to the registry
  version.

---

## Acceptance Examples

- AE1. **Covers R1, R9, R11.** Given an `llm:` route with an OPA rule that denies when any
  `tools[i].function.name == "transfer_funds"`, when that tool is the second element of
  `tools`, the request is denied before upstream. A request with only permitted tools is
  allowed. The same holds for the equivalent CEL rule.
- AE2. **Covers R9, R16.** Given the colleague's CEL allowlist
  `llm.request.tools.all(t, allowed.exists(p, t.type.matches(p)))`, a request with
  `{"type":"web_search_20250305"}` is denied when that pattern is not in the allowlist, and
  allowed when it is.
- AE3. **Covers R3, R9.** Given a Responses-style body with `input` as an array of message
  items, `llm.request.input` is iterable in OPA and CEL, and a text-scanning plugin sees the
  `input` text in the CMF prompt.
- AE4. **Covers R7, R8, R12.** Given a `tools/call` whose `args.items[1].classification` is
  `"secret"`, a CEL rule using `args.items.exists(...)` denies. On the same route, an APL
  predicate on a scalar argument such as `args.region == "eu"` still evaluates as before.
- AE5. **Covers R13.** Given a CEL rule that references `llm.request.tools` and a host that
  supplies no document, the request is denied, not allowed. When `tools` is absent from a
  supplied document, a rule that guards with `has()` behaves as written.
- AE6. **Covers R14, R15.** Given a denied request whose `messages` contain a known marker
  string, neither the violation, CEL diagnostics, audit output, nor logs contain that marker
  or any fragment of the request JSON.
- AE7. **Covers R6.** Given a plugin without the read capability, its extension view contains
  no request document. Given a plugin with the capability, the document is present.
- AE8. **Covers R11.** Round-trip tests show `[]`, `{}`, `null`, `[1,1]`, mixed-type arrays,
  and nested arrays of objects arriving at OPA and CEL with types and order intact.

---

## Success Criteria

- The colleague's SSRF guard runs in stock Praxis with OPA or CEL, with no custom plugin or
  recompilation.
- Every #142 acceptance criterion is met by a named test: PPE conversion tests, and a Praxis
  integration test covering one Chat Completions shape and one Responses shape.
- No existing PPE or Praxis test changes behavior, except the intended `args` shape change,
  redacted deny-reason text, and the embeddings projection test. Scalar policies that do not
  read `args` pass unmodified.
- A planner can sequence the PPE work, the Praxis work, and the release without inventing
  input names, access rules, or redaction behavior.

---

## Scope Boundaries

- APL quantifiers (`any`/`forall`), list indexing, and item-path access. These move to a
  follow-up issue. Until then, authors use CEL or OPA.
- Rewriting or redacting the inference body on allow.
- Enforcing capabilities on the existing unrestricted `llm` and `custom` slots. Only the new
  slot is gated.
- A dedicated CMF model for `tools` or `mcp_servers`. They are reachable through
  `llm.request`.
- Structured arguments for more than the first ToolCall part in a message.
- Structured `result` (tool output) for post-invocation policy.

---

## Key Decisions

- **Carrier is a gated extension slot plus a PDP side channel (approach C).** It reuses the
  existing tier and access-policy machinery for the read capability, and it leaves APL and
  the flat bag untouched. The rejected alternative, a JSON variant in the attribute bag, would
  have forced every exhaustive match and the APL evaluator to handle trees.
- **Whole body, not a subset.** Authors cannot predict which fields matter (`tools`,
  `mcp_servers`, `response_format`, provider-specific keys), and a subset would be a second
  projection to maintain.
- **Structured `args` fully replaces flattened `args.*` in PDP input only, flagged as
  breaking.** This gives one representation that matches the JSON. Overlaying only the paths
  the flattener drops was rejected, because a client could flip a field's type by adding an
  object and so get past deny-lists. Scalar arrays become ordered native arrays with
  duplicates and numbers, and explicit `null` is present. APL keeps the flattened view.
- **Cedar is included, with sets.** Cedar has `contains`, `containsAll`, and `containsAny` but
  no general quantifiers, and its sets are unordered. The limitation is documented rather than
  worked around.
- **Fail-closed through engine semantics, with no new route config.** The engines already
  deny on missing data when the input is absent rather than empty. Tests lock this in.
- **Redaction by type, not by value.** Diagnostics keep key names and types so authors can
  still debug missing or mis-typed fields.
- **Responses `input` projection is included.** It is small, and it closes the gap where text
  scanners see an empty prompt.

---

## Dependencies / Assumptions

- Praxis depends on `praxis-policy` from the registry (`../praxis/Cargo.toml`, currently
  `0.3.1`). A git dependency is used only while the Praxis PR is in draft.
- Workspace `serde_json` has `preserve_order` enabled (pulled in by cedar), so object key
  order is stable in every workspace build.
- The PDP invocation contract is internal to the workspace. The host-facing API change is the
  new slot, which is additive.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R5, R6][Technical] Exact slot shape, capability name, and how enforcement plugs
  into extension filtering and `merge_owned`.
- [Affects R8][Technical] Whether the side channel reaches PDPs through the existing PDP input
  path or through a new parameter. Also the merge order when a flat key and a structured name
  share a top-level segment.
- [Affects R10][Needs research] How Cedar maps JSON nulls, floats, and mixed-type arrays. It
  has no null or float type. Pick a documented, lossy-but-safe mapping or omit those values.
- [Affects R13][Technical] Confirm the default CEL `on_error` and the OPA undefined-result
  path both deny today. Confirm the Cedar missing-attribute behavior.
- [Affects R14][Technical] How OPA decision diagnostics are bounded today, and whether they
  can echo input. Also whether any audit consumer of `PdpDecision.diagnostics` exists
  downstream in Praxis.
- [Affects R1][Technical] Whether the parsed value can be shared by reference counting without
  a clone, given how Praxis owns `ParsedLlmRequest`.
