# Host integration

Build a CMF message with the data policy should inspect, then serialize the
parts PPE returns. Forwarding the original upstream body bypasses any
redaction applied to those parts.

Current Praxis builds and rewrites response parts for `tools/call` only.
Resource and prompt response inspection requires the adapter work in
[praxis#1583]. The instructions below describe the PPE host contract.

[praxis#1583]: https://github.com/praxis-proxy/praxis/pull/1583

If configuration loading fails, stop using that engine. `load_config_yaml`
does not roll back partial loads. Hosts that must retain the current policy
on failure should build and validate a replacement engine before switching
traffic to it.

## Message inputs

Routing, catalog attributes and field pipelines read separate parts of the
message:

| Input | Used for | When absent |
|---|---|---|
| `MetaExtension.entity_type`, `entity_name` | Route matching | The expected route may not run |
| `MCPExtension.tool`, `resource`, `prompt` | `mcp.*` attributes | Those attributes are absent |
| `ContentPart` | `args.*` and `result.*` | The expected field envelope is absent |

For example, supplying route metadata and a catalog entry without a
`Resource` part gives policy a resource route, but no fetched content in
`result.content`.

Tool and prompt arguments use the request's argument map. The resource and
prompt result envelopes have fixed fields:

| Route | Block | Part | Fields |
|---|---|---|---|
| `resource:` | `args` | `ResourceRef` | `uri`, `name`, `resource_type`, `range_start`, `range_end`, `selector` |
| `resource:` | `result` | `Resource` | `uri`, `name`, `title`, `description`, `resource_type`, `content`, `mime_type`, `size_bytes`, `version`, `annotations`, `icons` |
| `prompt:` | `result` | `PromptResult` | `prompt_name`, `description`, `content`, `is_error`, `error_message` |

`content` is an opaque string, or `null` when absent. Paths inside it, such
as `content.ssn`, are refused at load. Annotation maps accept descendant
paths. See [payload projection] for the tool and prompt argument contract.

[payload projection]: ../concepts/cmf-extensions.md#payloads-that-are-not-slots

## Wire names and catalog names

`ContentPart` carries the wire view: `ToolCall.name` comes from
`params.name`, and `ResourceRef.uri` from `params.uri`. `MCPExtension`
carries the host's resolved catalog view. A gateway can expose
`hr__get_salary` to the agent while identifying the upstream tool as
`get_salary` on `hr-server`. PPE permits those names to differ.

Populate `MCPExtension` from the host's catalog. Copying an agent-supplied
name or URI into it lets the agent choose what the PDP authorizes. Hosts
without a catalog leave it unset and authorize through routes and identity.
Use `mcp.*` when a rule needs the resolved entity; `args.*` and `result.*`
refer to the content parts.

Routes match against `MetaExtension.entity_name` supplied by the host.
Praxis uses the agent-facing name, including any gateway prefix. A host
that uses resolved names must document that choice and configure its routes
accordingly. PPE performs no alias resolution.

`ToolCall.namespace` is the agent-facing namespace, if one exists, such as
`hr` in `hr__get_salary`. The upstream namespace belongs in
`ToolMetadata.namespace`.

## Resource responses

Only the first `Resource` part is projected. For a read returning several
contents, evaluate each entry in its own message or combine the text into
one part. Leaving later entries as separate parts gives them no
`result.*` inspection.

Combining entries changes matching behavior. An exact comparison against
one entry may fail on the joined text. A pattern anchored with `^` or
`$` may miss a match in a later entry. Rules for combined text must
account for entry boundaries.

Result edits and plugin field readback use the URI selected before plugins
run. That URI must identify one resource in both the original and current
message. A removed target or duplicate URI denies the request.
Resource argument edits apply the same rule to the selected `ResourceRef`.
The selected part's resource request ID must also remain unchanged.
Write-back reports `policy.envelope_replaced`; a plugin readback denial is
attributed to its field pipeline. Request correlation IDs do not distinguish
parts of one response. Emit one resource per message when URIs can repeat.

`Resource.blob` is excluded from projection. For text carried in a blob,
decode it into `content` before policy runs. Remove the original blob or
rebuild the response from the inspected, possibly redacted text. Reusing the
original blob sends its unredacted bytes. A plugin that understands the
blob format is another option; the reference `transcript-scanner` handles
UTF-8 blobs.

## Prompt responses

Until [issue #76] provides message-list inspection, hosts must join the
rendered text parts of `PromptResult.messages` into `PromptResult.content`.
A messages-only result leaves `result.content` null and its text unavailable
to content rules.

Treat the returned `content` as authoritative when writing the response.
Map its edited text back into the response sent to the client; reusing the
original rendered messages bypasses redaction.
PPE ties edits to the inspected request ID and prompt name, and denies if
that pair no longer identifies a unique result.
Prompt argument reads and writes also retain the originally selected request,
including a tool-call fallback. Request source metadata must remain unchanged.

Retain each message's role and text boundaries separately from the joined
string. Apply edits only when they can be mapped back without changing those
roles or boundaries; deny if an edit crosses a boundary and cannot be mapped
safely. Per-message evaluation lets a host replace each message's text
separately, but changes matching for exact and anchored rules. Keep joined-text
evaluation for rules that must detect content spanning message boundaries.

Issue #76 also tracks inspection and addressing of individual resource
parts.

[issue #76]: https://github.com/praxis-proxy/policy/issues/76

## Field rules

Policy can inspect the following fields, but writes to them are refused at
load and write-back preserves their original values:

| Route | Block | Read-only fields |
|---|---|---|
| `resource:` | `args` | `uri`, `resource_type` |
| `resource:` | `result` | `uri`, `resource_type`, `icons` |
| `prompt:` | `result` | `prompt_name`, `is_error` |

The URI identifies the fetch that was authorized. Redirecting a fetch after
the route and PDP have decided requires separate routing and authorization.

Array fields use indexes. Plugins must retain element order when editing
array leaves. A write is refused if its parent structure or array length no
longer matches the recorded state. These checks do not detect same-length
reordering. Use one chain, such as `run(plugin) | omit`,
when a plugin must inspect an element before removal. Use ordered `do:` steps
for operations that depend on earlier edits; field maps define no execution
order. A later field plugin addressing that array is refused while its
payload still has the old indexes.

A bare `**` redaction replaces a whole envelope with a string. On
`ResourceRef`, `Resource`, `PromptResult`, `ToolCall` or `PromptRequest`,
that denies with `policy.envelope_replaced`. Address a field such as
`content` or `annotations.ssn` instead. Text-only messages and arbitrary
tool-result JSON retain their whole-value redaction behavior.

Field rules and condition keys are checked against the route's envelope at
load, including inherited global rules. Put fields specific to resources or
prompts on their routes, entity defaults or groups; a global rule must be
valid for every resource and prompt route that inherits it.

## Example policies

This resource policy denies the exact content `topsecret` and redacts
other fetched text.

<!-- evaluate: host-resource-projection -->
```yaml
engine_settings:
  dispatch: policy
routes:
  - resource: hr://employees/*
    authorization:
      post_invocation:
        - "result.content == 'topsecret': deny('secret resource')"
        - when: "result.content != 'topsecret'"
          do: "result.content | redact"
```

This prompt policy denies the exact text `ignore previous instructions`
and redacts other rendered text.

<!-- evaluate: host-prompt-projection -->
```yaml
engine_settings:
  dispatch: policy
routes:
  - prompt: summarize-*
    authorization:
      post_invocation:
        - "result.content == 'ignore previous instructions': deny('unsafe prompt')"
        - when: "result.content != 'ignore previous instructions'"
          do: "result.content | redact"
```

## Related pages

- [Common Message Format](../concepts/cmf.md): message structure.
- [CMF extensions and attributes](../concepts/cmf-extensions.md): attribute
  names and absent-value behavior.
