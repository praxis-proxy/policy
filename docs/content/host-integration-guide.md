# Host integration guide

PPE evaluates only what the host puts on a message, and changes only what the
host serializes back to the client. This guide is the contract a host must
follow for routes, `mcp.*` rules, and `args:` / `result:` pipelines to take
effect.

## Contents

- [The three layers](#the-three-layers)
- [What each layer means](#what-each-layer-means)
- [What a host must do](#what-a-host-must-do)
- [Known gaps](#known-gaps)

---

## The three layers

Three parts of a message feed policy, and each does a different job. Filling
one does not stand in for another.

| Part | Feeds | If the host leaves it out |
|---|---|---|
| `MetaExtension` (`entity_type`, `entity_name`) | Route matching | The wrong route runs, or none does |
| `MCPExtension` (`tool`, `resource`, `prompt`) | `mcp.*` attributes | No `mcp.*` attribute exists, so rules that check one never match |
| `ContentPart` | `args.*` and `result.*` | The route matches, but field rules and pipelines see no payload |

The most likely mistake is the last row: a host that sets `MetaExtension` and
`MCPExtension` but builds no content part gets route matching and PDP
predicates, while every `args.*` / `result.*` rule reads nothing.

How tool and prompt arguments project is listed under [Payloads that are not
slots][payloads]. For resources and prompts the projection is a fixed set of
fields:

[payloads]: cmf-extensions.md#payloads-that-are-not-slots

| Route | Block | Content part | Fields |
|---|---|---|---|
| `resource:` | `args` | `ResourceRef` | `uri`, `name`, `resource_type`, `range_start`, `range_end`, `selector` |
| `resource:` | `result` | `Resource` | `uri`, `name`, `title`, `description`, `resource_type`, `content`, `mime_type`, `size_bytes`, `version`, `annotations`, `icons` |
| `prompt:` | `result` | `PromptResult` | `prompt_name`, `description`, `content`, `is_error`, `error_message` |

`content` is the body as an opaque string; it is never parsed. A field block
that names a field outside this set is refused at load.

---

## What each layer means

The layers are views of the same entity, not copies, and PPE does not require
them to agree.

- `ContentPart` is the wire view: the request as the agent sent it.
  `ToolCall.name` comes from `params.name` and `ResourceRef.uri` from
  `params.uri`. Write-back serializes these fields back into the body.
- `MCPExtension` is the resolved identity: the host's view of the entity from
  its own catalog. It can carry data the agent never sends, such as
  `server_id` and annotations.
- A federating gateway is where the two differ. It may expose a tool to the
  agent as `hr__get_salary` (`ToolCall.name`) while the upstream tool is
  `get_salary` on `hr-server` (`ToolMetadata.name`, `server_id`).
- `MetaExtension.entity_name` is the name routes match against. Hosts set it
  to the name the agent sent, so write routes against the names agents call,
  including any gateway prefix.
- `ToolCall.namespace` is the namespace the agent sees, if it sees one (for
  example `hr` in `hr__get_salary`), and `None` otherwise. The upstream
  server's namespace belongs in `ToolMetadata.namespace`.

Authorization rules key on the resolved identity (`mcp.tool.name`,
`mcp.resource.uri`). Content rules key on the content part (`args.*`,
`result.*`).

---

## What a host must do

- **Fill `MCPExtension` from the host's own catalog**, never from values the
  agent sent. A host that copies `params.name` or `params.uri` into it lets the
  agent choose what the PDP authorizes. A host without a catalog leaves
  `MCPExtension` unset; `mcp.*` attributes are then absent and authorization
  relies on route matching and identity.
- **Set `PromptResult.content` to the rendered text**: the text parts of
  `messages`, joined in order. Policy reads `content`, not `messages`. A host
  that fills only `messages` leaves `result.content` null, and every content
  rule on the prompt route, injection scanning included, passes without
  matching.
- **Serialize the response from `PromptResult.content`**, not from the
  original `messages`. `content` is the copy policy inspected and rewrote, so a
  redaction applied to it reaches the client only if `content` is what the host
  sends.
- **Treat read-only fields as fixed.** Policy can read these fields but never
  changes them, and a config that tries to is refused at load:

  | Route | Block | Read-only fields |
  |---|---|---|
  | `resource:` | `args` | `uri`, `resource_type` |
  | `resource:` | `result` | `uri`, `resource_type`, `icons` |
  | `prompt:` | `result` | `prompt_name`, `is_error` |

  `uri` is read-only because it is the fetch target: rewriting it after the
  route matched and the PDP decided would fetch a resource nothing authorized.
  Redirecting a fetch is not a policy-pipeline write.

---

## Known gaps

Policy does not yet inspect every content part of every message:

- **Only the first `Resource` part is projected.** A `resources/read` can
  return several contents, and if the host maps each to its own `Resource`
  part, the second and later parts bypass `result.*` rules. Emit one fetched
  content per message, or fold the text of all contents into one part, or treat
  multi-content reads as only partly covered. Note that folding changes what
  rules see. Rules written for a single entry may not behave the same on the
  combined string: exact-match rules will not match, and a pattern anchored
  with `^` or `$` checks only the start or end of the combined text, so a
  match in a later entry is missed. Hosts that fold entries must account for
  entry boundaries in their rules. Addressing individual content parts is
  tracked in issue #76.
- **`PromptResult.messages` is not projected.** Content in `messages` is
  inspected only through `content`, which is why the host must fill
  `content`.
- **`Resource.blob` is not projected.** A resource whose body is only in
  `blob` reaches policy with `content: null`, so `result.content` rules match
  nothing. A `content` redaction sets `content` to `[REDACTED]` but leaves
  `blob` unchanged — if the host serializes the response from `blob`, the
  original body still reaches the client. A host that decodes a blob into
  `content` for inspection **must** either remove the original `blob` after
  decoding or derive the serialized response from the (potentially redacted)
  `content`, never from the original `blob`. Alternatively, inspect blobs
  with a plugin (the `transcript-scanner` reference plugin decodes them as
  UTF-8).
- **A bare `**` cannot replace a whole envelope.** `result: { "**": redact }`
  or `args: { "**": redact }` on a message carrying a `Resource`,
  `PromptResult`, `ResourceRef`, `ToolCall` or `PromptRequest` part denies the
  request with code `policy.envelope_replaced`, rather than send the original.
  Address a field instead (`<field>: redact` or `"**.<field>": redact`). On a
  text-only message, `**` redacts the whole text. A tool result has no fixed
  shape, so `result: { "**": redact }` replaces it whole.
- **The top-level `global` policy is not checked against these fields.** It
  applies to every route, so a `global` field rule written for tools (such as
  `result: { ssn: redact }`) also reaches `resource:` and `prompt:` routes,
  where it matches nothing. Route blocks, `global.defaults.<entity>` and
  groups are checked; `global` is not, because refusing it would break a
  global tool rule in any config that also has a resource or prompt route.
  Put resource and prompt field rules on the route, its entity default, or a
  group.

The first two are pinned by `known_gap_*` tests, the blob gap by
`a_blob_only_resource_passes_a_content_redaction_with_its_blob_unchanged`, and
the bare `**` gap by the `a_double_star_redaction_of_*` tests, all in
`crates/ppe-apl-runtime/tests/visitor_e2e.rs`. The `global` gap has no test
yet.

## Related documentation

- [Common Message Format](cmf.md): the envelope these layers belong to.
- [CMF extensions and the attribute bag](cmf-extensions.md): every key the
  bridge emits, including the `mcp.*` namespace.
