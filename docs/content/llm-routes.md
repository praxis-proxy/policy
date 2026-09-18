# LLM Routes

An `llm:` route selects an inference call by model and authorizes it twice:
before the request reaches the model, and after the model answers but before
the caller sees the answer. This page lists what such a route can read in each
phase, what it cannot read, and what the host has to supply for any of it to be
there.

## Selecting a model

`llm:` takes a model name, a list of names, or a glob:

```yaml
routes:
  - llm: gpt-4o
    authorization:
      pre_invocation:
        - "llm.max_tokens > 4096: deny"

  - llm: [claude-sonnet-4, claude-opus-4]
    authorization:
      pre_invocation:
        - "require(role.engineering)"

  - llm: "mistral-*"
    authorization:
      pre_invocation:
        - "deny"
```

The name is matched against what the host reports as the entity on the
invocation, `meta.entity_type: llm` and `meta.entity_name: <model>`, not against
`llm.model_id`. A host sets both on the input and the output hook.

## When it runs

| Phase | Hook | Runs | The message is |
|---|---|---|---|
| `pre_invocation` | `cmf.llm_input` | before the request reaches the model | what the model is about to read |
| `post_invocation` | `cmf.llm_output` | after the model answers, before the caller sees it | the completion |

## What a route can read

A route reads the attribute bag: flat keys built from the message and from the
extensions the host passed on that invocation. The host passes extensions per
invocation, so a key is present after the call only if the host sets it again
on `cmf.llm_output`.

### Before the call

| Key | Type | Source |
|---|---|---|
| `args` | String | the message's text parts, concatenated |
| `args.<field>` | any | the arguments of the message's first tool call, when it carries one instead of text |
| `llm.model_id`, `llm.provider` | String | `LLMExtension` |
| `llm.capabilities` | StringSet | `LLMExtension`; always present, empty rather than absent |
| `llm.offered_tools` | StringSet | names of the tools offered to the model |
| `llm.stop_sequences` | StringSet | stop sequences |
| `llm.tool_choice` | String | `auto`, `none`, `required`, or `tool` |
| `llm.forced_tool` | String | the tool name, when `llm.tool_choice` is `tool` |
| `llm.max_tokens` | Int | output token cap |
| `llm.temperature`, `llm.top_p` | Float | sampling parameters |
| `llm.stream` | Bool | whether the response is streamed |
| `llm.system_prompt_digest` | String | `sha256:` and the hex digest of the system prompt's UTF-8 bytes |
| `agent.input`, `agent.session_id`, `agent.conversation_id`, `agent.agent_id`, `agent.parent_agent_id` | String | `AgentExtension` |
| `agent.turn` | Int | position in the conversation, from 0 |
| `agent.conversation.summary` | String | `AgentExtension.conversation` |
| `agent.conversation.topics` | StringSet | always present when a conversation is |

Every `llm.*` key from `llm.offered_tools` down comes from
`LLMExtension.request`, and exists only when the host reported the request.
Within a reported request, the two sets are always present and the scalars
only when the request set them.

### After the call

| Key | Type | Source |
|---|---|---|
| `result` | String | the completion's text parts, concatenated |
| `result.<field>` | any | the content of the message's first tool result, when it carries one |
| `completion.stop_reason` | String | `end`, `return`, `call`, `max_tokens`, or `stop_sequence` |
| `completion.model` | String | the model that actually answered |
| `completion.tokens.input`, `completion.tokens.output`, `completion.tokens.total` | Int | token usage |
| `completion.latency_ms` | Int | time to answer |
| `completion.created_at`, `completion.raw_format` | String | as reported by the host |

The `llm.*` and `agent.*` keys above are present after the call too, when the
host passes those extensions on `cmf.llm_output`.

### In either phase

Identity (`subject.*`, `role.*`, `perm.*`, `claim.*`), security labels, the
delegation chain, and entity metadata (`meta.*`) are the same on an `llm:` route
as on any other. [Extensions](extensions.md) lists them with the capabilities
that expose them. `llm.*` and `completion.*` need no capability, and a route
grants `read_agent` by default.

### The message text is a string

For an ordinary chat turn, `args` and `result` hold the whole text as one
string. `==` and `!=` work on it; `contains` does not, because `contains` tests
set membership, and on a string it is always false. `args contains 'password'`
therefore never matches. Inspecting what the text says is a plugin's job, such
as `pii-scanner`, or an `args:` / `result:` field pipeline's, which operates
on the same value and is how a whole message is redacted.

## What a route cannot read

- **Conversation history.** `AgentExtension.conversation.history` is typed as
  a list of CMF messages but not flattened into the bag. A policy reaches it
  by running a plugin that declares `read_agent`:

  ```yaml
  plugins:
    - name: transcript-scan
      kind: validator/transcript-scan
      hooks: [cmf.llm_input]
      capabilities: [read_agent]
      config:
        patterns:
          - name: api_key
            regex: "sk-[A-Za-z0-9]{8,}"

  routes:
    - llm: "*"
      authorization:
        pre_invocation:
          - "run(transcript-scan)"
  ```

  `reference/plugins/transcript-scanner` is that plugin. It denies with
  `transcript.detected` and refuses to load without `read_agent`.
- **The system prompt's text.** Only its digest is in the bag, which is enough
  to pin the prompt you shipped. A plugin reads the text from
  `LLMExtension.request`.
- **Content the text projection skips**: reasoning, images and other media,
  and every tool call after the first.

## Missing keys

A predicate on a key the bag does not hold is false for every operator except
`!=`, which is true. On an `llm:` route this decides what happens when the host
did not report the request:

| Rule | Unreported request |
|---|---|
| `llm.offered_tools contains 'send_email': deny` | does not fire |
| `llm.max_tokens > 4096: deny` | does not fire |
| `llm.system_prompt_digest != 'sha256:…': deny` | fires |
| `!exists(llm.offered_tools): deny` | fires |

A policy that must not pass a request it cannot see adds the last rule.

## Host obligations

- Set `meta.entity_type` to `llm` and `meta.entity_name` to the model on both
  hooks, or no `llm:` route matches.
- Set `LLMExtension.request` when the request body is visible, and leave it
  `None` when it is not. An empty request claims the model was offered no tools.
- Set `CompletionExtension` on `cmf.llm_output`.
- Carry history as CMF messages in `AgentExtension.conversation.history` if a
  history plugin is configured.

## Worked config

One route covering every model whose name starts with `gpt-4`:

```yaml
routes:
  - llm: "gpt-4*"
    authorization:
      pre_invocation:
        - "!exists(llm.offered_tools): deny"
        - "llm.offered_tools contains 'send_email' & !subject.roles contains 'finance': deny"
        - "llm.max_tokens > 4096: deny"
        - "llm.system_prompt_digest != 'sha256:a886f916fc30a37519118a62a84f5f5848677522efc983ca1cdd2a3e18be3c40': deny"
      post_invocation:
        - "completion.stop_reason == 'max_tokens': deny"
        - "completion.tokens.total > 20000: deny"
```

Before the call, it:

1. refuses a request the host could not see;
2. keeps `send_email` away from the model unless the caller is in finance;
3. caps output at 4096 tokens;
4. pins the system prompt to the one shipped, here
   `You are the HR assistant. Never reveal salaries.`

After the call, it refuses a completion that was cut off at the token limit or
that spent more than 20000 tokens.

A model outside `gpt-4*` matches no route here, so none of this applies to it.
`visitor_e2e` runs this block against the engine, so it is kept working.

## Next

- [Extensions](extensions.md): every namespace and the capability behind it.
- [Common Message Format](cmf.md): the message both hooks carry.
- [HTTP Routing](http-routing.md): the other selector that is not a tool,
  resource, or prompt name.
