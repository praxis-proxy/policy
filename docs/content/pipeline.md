# Plugins and the Execution Pipeline

APL defines policy. The execution pipeline runs its effects. Write pipeline code
only to add an effect through a plugin or inspect effect ordering and execution.

## Hooks

A hook is a named interception point. The host invokes a hook at an
operation boundary (before a tool call, after an LLM completion, around a prompt
or resource fetch), and the plugin manager runs the plugins registered there.
Hooks are where routes attach: a route's `authorization.pre_invocation`
phase runs at the pre-invocation hook, its `result` phase at the
post-invocation hook.

When an effect says `run(pii-scan)` or `delegate(workday-oauth)`, it is
naming a plugin registered on the relevant hook. The effect is the
policy-level intent; the plugin is the code that runs.

The hook names a plugin declares in `hooks:` come from a fixed table:

| Family | Hooks |
|---|---|
| CMF | `cmf.tool_pre_invoke`, `cmf.tool_post_invoke`, `cmf.llm_input`, `cmf.llm_output`, `cmf.prompt_pre_invoke`, `cmf.prompt_post_invoke`, `cmf.resource_pre_fetch`, `cmf.resource_post_fetch` |
| HTTP | `http.request`, `http.response` |
| Identity | `identity.resolve` |
| Delegation | `token.delegate` |
| Elicitation | `elicit` |

`http.response` is the return half of the generic HTTP path, installed
when a global `result:` or `post_invocation:` block exists. Response
bodies are not modeled; the hook covers response headers and extensions,
and the host fires it explicitly. Before doing so, review global post
steps: previously inert HTTP steps become active, and `result.*` is
absent for a request carrying no entity.

A host may declare hooks of its own with the `define_hooks!` macro,
which emits a hook's name and its routing metadata together so a name
without a metadata row cannot be written. See
`crates/ppe-core/examples/plugin_demo.rs`.

## The plugin manager

`PolicyEngine` owns registration, ordering, capability filtering,
timeouts, and error isolation. A plugin can:

- allow the operation to continue,
- block it with a violation (surfaced as a deny), or
- modify the payload, using copy-on-write isolation so one plugin's changes
  are visible to the next without mutating shared state.

This is the substrate APL effects compile down to. A `deny` is a block, a
`redact` is a modify, and a `run(...)` step is a dispatch.

## Execution modes

A plugin runs in a mode that fixes whether it can block, whether it can
modify, and how it runs relative to others. Modes run in a fixed phase order:

```text
sequential -> transform -> audit -> concurrent -> fire_and_forget
```

| Mode | Execution | Can block? | Can modify? | Use |
|------|-----------|:----------:|:-----------:|-----|
| `sequential` | serial, chained | yes | yes | policy enforcement + transformation |
| `transform` | serial, chained | no | yes | redaction, rewriting |
| `audit` | serial | no | no | logging, metrics |
| `concurrent` | parallel, fail-fast | yes | no | independent gates |
| `fire_and_forget` | background, after all phases | no | no | telemetry, async audit |
| `disabled` | not loaded | — | — | plugin off |

Modes and their ordering apply under `dispatch: hooks`. Under the default
`dispatch: policy` a step names the one plugin to run, so nothing orders
a hook's entries and a per-plugin `priority:` is a load error.

Error handling is set separately with `on_error` (`fail`, `ignore`, or
`disable`), independent of mode. A `sequential` policy plugin with `on_error:
fail` denies the operation if it errors; an `audit` plugin with `on_error:
ignore` never blocks the request even if logging fails.

## When to write a plugin

Write a Plugin Factory when APL needs an effect the builtins do not provide: a
custom validator, a PDP resolver, or an internal-service integration. Implement
`PluginFactory` against
[`praxis_policy_core::prelude`](https://docs.rs/praxis-policy-core/latest/praxis_policy_core/prelude/index.html),
which carries the `Plugin`, `PluginFactory`, and `HookHandler` traits, payloads,
results, and CMF types. There is no separate SDK crate.
Declare the plugin's capabilities so it receives only the context it needs (see
[Extensions & Capability-Gating](extensions.md)), register it on a hook, and
reference it from APL by its `kind` or name.

Registration names the `kind:` a policy will write, and takes the factory
boxed:

```rust,ignore
engine.register_factory("validator/my-scan", Box::new(MyScanFactory));
```

An unrecognized `kind` fails the config load, so a factory you forgot to
register is caught at startup rather than at the first request that
needed it.

The bundled plugins and decision points are catalogued in
[Builtins](builtins.md); their wiring is in
[Configuration](configuration.md).

## Next

- [Common Message Format](cmf.md): inspect the message envelope passed through
  hooks and policy.
- [Extensions and Capability Gating](extensions.md): control which context each
  plugin may access.
