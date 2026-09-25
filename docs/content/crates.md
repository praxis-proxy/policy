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

All nine ship in one published crate, `praxis-policy-builtins`, each behind
its own feature and reached through the matching feature on the facade rather
than named directly. See [Builtins](builtins.md).

| Feature | Module | Kind |
|---|---|---|
| `jwt` | `plugins::identity_jwt` | `identity/jwt` |
| `api-key` | `plugins::identity_api_key` | `identity/api-key` |
| `oauth` | `plugins::delegator_oauth` | `delegator/oauth` |
| `elicitation-ciba` | `plugins::elicitation_ciba` | `elicitation/ciba` |
| `cedar` | `pdps::cedar_direct` | `cedar-direct` |
| `cel` | `pdps::cel` | `cel` |
| `opa` | `pdps::opa` | `opa` |
| `valkey` | `session::valkey` | `valkey` |
| `secrets-vault` | `secrets::vault` | `vault` |

### Migrating from a per-extension crate

Releases up to 0.3.1 published each extension separately. Those versions stay
on crates.io; later releases publish only `praxis-policy-builtins`. Most hosts
reach these through the facade and need no change.

If a dependency names one of the old crates directly, **remove it** and add the
consolidated crate with the matching feature. Removing it matters: keeping both
links two copies of the same implementation, each registering the same `kind`,
and the registry is last-write-wins, so the stale copy can win silently rather
than failing loudly.

| Retired crate | Replacement |
|---|---|
| `praxis-policy-plugin-identity-jwt` | `praxis-policy-builtins`, feature `jwt` |
| `praxis-policy-plugin-delegator-oauth` | `praxis-policy-builtins`, feature `oauth` |
| `praxis-policy-plugin-elicitation-ciba` | `praxis-policy-builtins`, feature `elicitation-ciba` |
| `praxis-policy-pdp-cedar-direct` | `praxis-policy-builtins`, feature `cedar` |
| `praxis-policy-pdp-cel` | `praxis-policy-builtins`, feature `cel` |
| `praxis-policy-pdp-opa` | `praxis-policy-builtins`, feature `opa` |
| `praxis-policy-session-valkey` | `praxis-policy-builtins`, feature `valkey` |

`praxis-policy-plugin-identity-api-key` and `praxis-policy-secrets-vault` were
never published, so nothing depends on them by name.

A new extension belongs in `praxis-policy-builtins` as a feature when it is a
bundled integration the facade exposes and the maintainers commit to publishing
and supporting. Anything else is a reference plugin under `reference/plugins/`.

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

The crates are versioned and released together, so one `0.3`
requirement covers the set.

## Next

- [Builtins](builtins.md): review the extensions available through facade
  features.
- [Testing](testing.md): test APL and plugins through the runtime.
