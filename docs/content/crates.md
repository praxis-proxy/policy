# Crate Reference

PPE is a Cargo workspace. Most hosts depend on `praxis-policy`, the
facade, and nothing else: it re-exports the runtime and, behind
features, the bundled extensions.

## Core Engine

| Crate | Role |
|---|---|
| [`praxis-policy`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe) | Host facade. Re-exports the runtime and registers the builtins. Start here. |
| [`praxis-policy-core`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-core) | The runtime: engine, phased executor, hook registry, config, extensions, the HTTP seam. |
| [`praxis-policy-apl-core`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-apl-core) | APL compiler and evaluator: rules, effects, field pipelines, routes. |
| [`praxis-policy-apl-cmf`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-apl-cmf) | Bridges typed extensions into the flat attribute bag a policy reads. |
| [`praxis-policy-apl-runtime`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-apl-runtime) | Host runtime: wires APL routes to hooks, dispatches plugins and decision points. |
| [`praxis-policy-orchestration`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-orchestration) | Async branch-concurrency primitives shared by the runtime. |

They depend on each other in one direction:

```text
praxis-policy (facade)
 -> praxis-policy-apl-runtime -> praxis-policy-apl-cmf -> praxis-policy-apl-core
 -> praxis-policy-orchestration
 -> praxis-policy-core
```

## Bundled extensions

Each is its own published crate, reached through a feature on the
facade rather than named directly. See [Builtins](builtins.md).

| Crate | Kind |
|---|---|
| `praxis-policy-plugin-identity-jwt` | `identity/jwt` |
| `praxis-policy-plugin-delegator-oauth` | `delegator/oauth` |
| `praxis-policy-plugin-elicitation-ciba` | `elicitation/ciba` |
| `praxis-policy-pdp-cedar-direct` | `cedar-direct` |
| `praxis-policy-pdp-cel` | `cel` |
| `praxis-policy-pdp-opa` | `opa` |
| `praxis-policy-session-valkey` | `valkey` |

## Not published

| Crate | Why |
|---|---|
| `praxis-policy-pdp-diff` | Differential tests across the three decision points. A test harness, not an API. |
| `reference/plugins/pii-scanner` | A worked example of a host plugin. |
| `reference/plugins/audit-logger` | The same, for an audit sink. |

## Writing a Plugin Factory

There is no separate SDK crate. The Plugin Factory surface is
`praxis_policy_core::prelude`, which carries the `Plugin` and
`HookHandler` traits, payloads, results, and the CMF types. Implement
`PluginFactory` against it and register it with
`PolicyEngine::register_factory` under the `kind:` your policy names.

An unrecognized `kind` fails policy loading, so a missing registration
is caught at startup rather than at the first request that needed it.

## Generated API docs

[docs.rs/praxis-policy](https://docs.rs/praxis-policy), built with all
features so the feature-gated re-exports are visible.

The crates are versioned and released together, so one `0.2`
requirement covers the set.

## Next

- [Builtins](builtins.md): review the extensions available through facade
  features.
- [Testing](testing.md): test APL and plugins through the runtime.
