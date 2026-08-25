# PPE Core Examples

## plugin_demo

A complete end-to-end example showing how to build plugins, load config, and invoke hooks with the PPE runtime.

### What it demonstrates

- **Defining hook types and payloads** — `ToolPreInvoke` and `ToolPostInvoke` hooks with a shared `ToolInvokePayload`
- **Building plugins** — three plugins (`IdentityResolver`, `PiiGuard`, `AuditLogger`) implementing `Plugin` + `HookHandler<H>` for different hook types
- **Multi-hook registration** — a single plugin instance (e.g., `IdentityResolver`) registered for multiple hooks (`demo.tool_pre_invoke` and `demo.tool_post_invoke`) via the factory pattern
- **Host-owned hooks** — the demo declares its own hook names with `define_hooks!` and registers their metadata before loading the config that names them, which is the ordering the loader requires
- **Plugin factories** — `PluginFactory` implementations that create plugin instances and wire up typed handler adapters
- **YAML config loading** — `plugin_demo.yaml` declares plugins, policy groups, and routing rules
- **Policy groups and tag-based routing** — the `pii` policy group activates `PiiGuard` only for tools tagged with `pii`
- **Route resolution** — exact tool matches, wildcard catch-all, tag-driven plugin selection
- **PluginContext** — `global_state` used to pass PII clearance between hooks, `local_state` for per-plugin scratch data
- **BackgroundTasks** — fire-and-forget plugins (`AuditLogger`) spawn background tasks; `wait_for_background_tasks()` awaits them
- **PluginContextTable** — context table threaded from pre-invoke to post-invoke to preserve plugin state

### Running

From the workspace root:

```
cargo run --example plugin_demo
```

### Scenarios

The demo runs five scenarios against three registered plugins:

| Scenario | Tool | User | Outcome |
|----------|------|------|---------|
| 1 | get_compensation | alice (no clearance) | DENIED by pii-guard |
| 2 | get_compensation | alice (with clearance) | ALLOWED, then post-invoke fires |
| 3 | list_departments | bob | ALLOWED (no PII tag, pii-guard skipped) |
| 4 | some_other_tool | charlie | ALLOWED (wildcard route) |
| 5 | list_departments | (empty) | DENIED by identity-resolver |

### Files

- `plugin_demo.rs` — Rust source with plugins, factories, and main
- `plugin_demo.yaml` — YAML config with plugins, policy groups, and routes

---

## cmf_capabilities_demo

Demonstrates CMF messages with capability-gated extension access. Shows how different plugins see different views of the same extensions based on their declared capabilities.

### What it demonstrates

- **CMF Message** — typed content parts (`Text`, `ToolCall`) with the standard CMF format
- **Capability gating** — plugins declare capabilities in YAML config; the executor filters extensions per plugin
- **Security labels** — `MonotonicSet` (add-only, no remove at compile time)
- **Guarded HTTP headers** — `.read()` is free, `.write(token)` requires a `WriteToken`
- **COW copy** — `extensions.cow_copy()` for plugins that need to modify; zero-cost for read-only plugins
- **Write tokens** — executor sets tokens based on capabilities; propagated through `cow_copy()`
- **Three capability levels** — identity-checker (security), header-injector (http + labels), audit-logger (http + labels read-only)

### Running

From the workspace root:

```
cargo run --example cmf_capabilities_demo
```

### What each plugin sees

| Plugin | Capabilities | Security Labels | Subject | HTTP Headers | Can Write |
|--------|-------------|-----------------|---------|--------------|-----------|
| identity-checker | read_labels, read_subject, read_roles | visible | visible (id + roles) | hidden | no |
| header-injector | read_headers, write_headers, append_labels | visible | hidden | visible | yes (headers + labels) |
| audit-logger | read_headers, read_labels | visible | hidden | visible | no (audit mode) |

### Files

- `cmf_capabilities_demo.rs` — Rust source with CMF plugins and capability-gated access
- `cmf_capabilities_demo.yaml` — YAML config with per-plugin capabilities
