# Common Message Format

APL evaluates policy against a request in the Common Message Format (CMF). This
protocol-agnostic envelope represents every mediated operation in one structure.
One policy therefore applies across tool calls, inference, prompts,
and resources without depending on the transport protocol.

## Why a common format

Without CMF, tool-result redaction and LLM-output redaction require separate code
for separate payload types. CMF gives every interception point the same
representation. The same APL field pipeline can redact a field from either a
tool result or a model completion.

## Message structure

A CMF `Message` carries:

- role: `system`, `developer`, `user`, `assistant`, or `tool`.
- content: a list of typed parts: text, thinking, tool call, tool result,
  resource, prompt request, image, video, audio, document.
- channel: optional routing such as `analysis`, `commentary`, or `final`.

Typed content parts let policy target only `tool_call` arguments, redact a
field inside a `tool_result`, or check a `text` part for injection without
disturbing the rest.

## Views

A `MessageView` is a flattened projection of a message for uniform evaluation:
each view has a kind (`text`, `tool_call`, `tool_result`, and so on), an
optional name, and the text or structured payload. Plugins and APL field
pipelines operate over views, which is why one policy expression works across
content types.

## CMF hooks

CMF operations run at CMF hooks, which parallel the typed hooks but carry a
`Message`:

| Hook | Fires |
|------|-------|
| `cmf.tool_pre_invoke` / `cmf.tool_post_invoke` | around a tool call |
| `cmf.llm_input` / `cmf.llm_output` | around an inference call |
| `cmf.prompt_pre_invoke` / `cmf.prompt_post_invoke` | around a prompt fetch |
| `cmf.resource_pre_fetch` / `cmf.resource_post_fetch` | around a resource fetch |

At the relevant pre-operation hook, a route evaluates `args` and
`authorization.pre_invocation`. At the post-operation hook, it evaluates
`result` and `authorization.post_invocation`. A guardrail attached to a CMF hook
covers every operation type mapped to that hook.

## APL integration

CMF is the "what you evaluate" layer (see [Vision](vision.md)). Identity,
security labels, and delegation context ride alongside the message as typed
extensions ([Extensions & Capability-Gating](extensions.md)), and APL reads all
of it through one attribute bag
([CMF extensions and the attribute bag](cmf-extensions.md)). The message
gives policy the content; the extensions give it the context; APL decides.

## Next

- [Extensions and Capability Gating](extensions.md): inspect the typed context
  carried alongside each message.
- [CMF extensions and the attribute bag](cmf-extensions.md): the keys APL
  reads and what a missing key means in each engine.
- [Crates](crates.md): locate the CMF and runtime implementations in the
  workspace.
