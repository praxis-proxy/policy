---
title: "feat: Selectable CIBA correlation store, with Valkey"
type: feat
status: active
date: 2026-10-22
origin: docs/brainstorms/2026-10-21-ciba-correlation-store-selection-requirements.md
---

# feat: Selectable CIBA correlation store, with Valkey

## Summary

Make the CIBA correlation store async and fallible, add a typed `store` block
to `CibaConfig` (memory or valkey) with unknown-field rejection, and add a
Valkey-backed store that reuses the session store's connection validation and
pool code. A small optional factory context in ppe-core lets the CIBA factory
see `global.session_store` so a `connection: session_store` reference can be
resolved at plugin construction. Both Valkey stores gain env and file password
sources.

---

## Problem Frame

`CibaApprover::new` always builds an in-process store, `CibaConfig` silently
ignores unknown keys, and `global.session_store` does not reach CIBA. Approvals
fail across replicas and restarts (see origin).

---

## Requirements

R1-R26 from the origin document, unchanged. Grouped:

- Store selection: R1-R4
- Validation: R5-R8
- Valkey configuration: R9-R16
- Valkey store behavior: R17-R20
- Tests: R21-R22
- Documentation: R23-R26

**Origin acceptance examples:** AE1 (R3), AE2 (R5), AE3 (R8), AE4 (R17, R22),
AE5 (R20), AE6 (R3, R10), AE7 (R10, R11, R14), AE8 (R12), AE9 (R11)

---

## Scope Boundaries

Carried from origin: no implicit inheritance, no named-connection registry, no
retry or circuit breaker, no unknown-field rejection for other plugin configs,
no change to approval semantics, no Valkey for other plugin state, no ACL
management by PPE.

### Deferred to Follow-Up Work

- Consolidating the three `ClientSecretSource`-shaped enums into one shared
  secret-source type.
- `deny_unknown_fields` on the session store's `ValkeyConfig` (it ignores
  `kind` by design today).
- Sharing one connection pool between the session store and a CIBA reference.

---

## Context & Research

### Relevant Code and Patterns

- `crates/builtins/src/plugins/elicitation_ciba/{approver,config,store,factory}.rs`
- `crates/builtins/src/session/valkey/{config,connection,store,error}.rs`:
  validation, `connection_url`, lazy `build_pool`, timed `conn()`, fail-closed
  error mapping, sha256 key derivation.
- `crates/ppe-core/src/factory.rs` (`PluginFactory`) and
  `crates/ppe-core/src/engine.rs` (`load_config_yaml` builds plugins via
  `load_config` before the visitor walk reads `global.session_store`).
- `crates/builtins/src/plugins/identity_api_key/credential.rs`: tagged enum
  with `deny_unknown_fields`.
- `crates/builtins/src/secrets/vault/config.rs` `SecretIdSource`: untagged
  `{env} | {file} | {literal}` source.
- `crates/builtins/tests/valkey/valkey_store_integration.rs`: live gating via
  `VALKEY_TEST_URL`, testcontainers fallback, `VALKEY_TESTS_OPTIONAL`.
- `tests/utils/src/capture.rs`: the only safe tracing capture.
- `crates/ppe/tests/docs_examples/main.rs`: every fenced `yaml` block in
  `docs/` is parsed as a document unless marked.

### Institutional Learnings

- No `docs/solutions/`. Prior plans: prefer internally tagged enums with
  `deny_unknown_fields`; `flatten` and `deny_unknown_fields` do not compose;
  every backend error denies, never reads as missing.
- Hand-rolled `with_default` tracing capture flakes; use the shared capture in
  `tests/utils`.
- Each new test binary costs ~87s on the dev machine; add modules to existing
  harnesses.

---

## Key Technical Decisions

- **Factory context, defaulted.** Add `PluginFactory::create_with(&PluginConfig,
  &FactoryContext)` with a default that calls `create`, mirroring
  `initialize`/`initialize_with`. `FactoryContext` carries the raw
  `global.session_store` block (`Option<serde_yaml::Value>`). `load_config_yaml`
  fills it; `load_config` and `from_config` pass an empty one, which matches
  today, since `session_store` is only honored on the YAML path.
- **Async, fallible store trait.** `CorrelationStore` becomes `async_trait`
  returning `Result<_, StoreError>`. The approver maps any `Err` to a new
  violation `elicitation.store_unavailable`, distinct from `unknown_id`. The
  dispatch-time `put` and check-time `set_resolved_approver` stop being
  infallible.
- **Store config shape.** `store: { kind: memory }` or
  `store: { kind: valkey, ... }`. The valkey variant is compiled in every build
  as a raw mapping and parsed only under `cfg(feature = "valkey")`; without the
  feature, construction fails naming the feature (R8). A
  `connection: session_store` key selects the reference form; overridable keys
  are `username`, `password`, `key_prefix`, `connect_timeout_ms`,
  `command_timeout_ms`. `endpoint` or `tls` in a reference is rejected (R11).
- **Reuse session-store validation in place.** Widen
  `ValkeyConfig::validate`, `build_pool`, and the redaction helpers to
  `pub(crate)`. The CIBA store builds a `ValkeyConfig` (merged for a reference)
  and calls the same validation, so R9 and R13 hold by construction. No module
  move; the shared code stays where it is.
- **Password source.** `ValkeyConfig.password` becomes `Option<PasswordSource>`,
  an untagged enum of a plain string, `{env: NAME}`, or `{file: PATH}`, resolved
  during `from_value`. Inline strings keep loading. This is a public type change
  in `ValkeyConfig`, which the facade re-exports.
- **Storage layout.** One hash per correlation at `<prefix>:<sha256(id)>`, with
  `PEXPIREAT` set to `expires_at`. Default prefix `ciba:v1`. `take_if_ready` and
  `set_resolved_approver` are small Lua scripts sent with `EVAL` via
  `redis::cmd`, so the `redis` `script` feature stays off. `+@scripting` goes in
  the documented ACL line.
- **Warning test location.** The R3 warning assertion lives in the integration
  suite, which already depends on the shared capture.

---

## Open Questions

### Resolved During Planning

- How the factory sees `global.session_store`: factory context (above).
- Shared layer extract vs duplicate: reuse in place by widening visibility.
- Atomic redeem: server-side Lua via `EVAL`.
- Encoding: hash fields; the `v1` prefix segment versions the layout.
- Sliding TTL: not needed; per-entry absolute expiry from `expires_at`.
- Pool sharing: each CIBA store opens its own lazy pool.

### Deferred to Implementation

- Exact Lua bodies and hash field names.
- Whether the warning is emitted from `new` or the factory.

---

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for
> review, not implementation specification.*

```text
load_config_yaml(raw)
  -> FactoryContext { session_store: raw.global.session_store }
  -> load_config_with(cfg, ctx)
       -> factory.create_with(plugin_cfg, ctx)
            CibaApprover::with_context(cfg, ctx)
              store: None              -> memory + warn
              store: memory            -> memory
              store: valkey standalone -> ValkeyConfig::from_value(block)
              store: valkey reference  -> merge(ctx.session_store, overrides)
                                          -> ValkeyConfig validate
              valkey without feature   -> Config error naming feature
```

---

## Implementation Units

- U1. **Password sources for the Valkey session store**

**Goal:** `ValkeyConfig.password` accepts a plain string, `{env}`, or `{file}`;
validation and pool helpers become crate-visible for reuse.

**Requirements:** R15, R26 (partial)

**Dependencies:** None

**Files:**
- Modify: `crates/builtins/src/session/valkey/config.rs`
- Modify: `crates/builtins/src/session/valkey/connection.rs`
- Modify: `crates/builtins/src/session/valkey/error.rs`

**Approach:**
- Untagged `PasswordSource` with `deny_unknown_fields` on the object arms.
  Resolve to a `Zeroizing`-free `String` held privately after `from_value`, so
  `connection_url` keeps using a resolved value.
- File contents trimmed; errors name the env var or path, never the secret.
- Widen `validate`, `build_pool` to `pub(crate)` for U4.

**Test scenarios:**
- Happy path: inline `password: s3cret` builds the same URL as before.
- Happy path: `{env: NAME}` with the var set resolves into the URL.
- Happy path: `{file: path}` resolves with trailing newline trimmed.
- Error path: unset env var fails with the var name and no secret.
- Error path: unreadable file fails naming the path.
- Error path: `{env: X, file: Y}` or an unknown key is rejected.

**Verification:** existing Valkey config tests still pass; new ones pass.

---

- U2. **Async, fallible correlation store**

**Goal:** `CorrelationStore` becomes async and returns errors; the approver
maps errors to `elicitation.store_unavailable`.

**Requirements:** R2, R19, R20

**Dependencies:** None

**Files:**
- Modify: `crates/builtins/src/plugins/elicitation_ciba/store.rs`
- Modify: `crates/builtins/src/plugins/elicitation_ciba/approver.rs`
- Modify: `crates/builtins/tests/ciba/ciba_e2e.rs`

**Approach:**
- `StoreError` (thiserror) with a message; memory store never errors.
- Each call site maps `Err` to `deny("elicitation.store_unavailable", ...)`
  whose reason says the outcome is indeterminate and fail-closed.

**Test scenarios:**
- Covers AE5. Error path: a failing store at check-time `get` denies with
  `store_unavailable`, not `unknown_id`.
- Error path: failing `put` after a successful backchannel POST denies with
  `store_unavailable`.
- Error path: failing `set_resolved_approver` after a 2xx poll denies with
  `store_unavailable` rather than reporting approved.
- Error path: failing `take_if_ready` and peek `get` deny with
  `store_unavailable`.
- Happy path: existing memory-store tests unchanged in outcome.

**Verification:** CIBA unit and e2e tests pass with the async trait.

---

- U3. **Typed `store` config and unknown-field rejection**

**Goal:** `CibaConfig` gains `store`, rejects unknown fields, warns when the
store is omitted, and rejects valkey without the feature.

**Requirements:** R1, R3-R8

**Dependencies:** U2

**Files:**
- Modify: `crates/builtins/src/plugins/elicitation_ciba/config.rs`
- Modify: `crates/builtins/src/plugins/elicitation_ciba/approver.rs`
- Modify: `crates/builtins/src/plugins/elicitation_ciba/factory.rs`

**Approach:**
- `#[serde(deny_unknown_fields)]` on `CibaConfig`.
- `StoreConfig` tagged on `kind`: `Memory {}` (deny unknown) and
  `Valkey(serde_json::Map)` parsed later.
- Omitted store: memory, one `tracing::warn!` with plugin name and an
  `alarm = "ciba_store_process_local"` field.
- Without `valkey` feature, `Valkey(_)` fails with a message naming the
  `valkey` feature.
- Fix the stale `kind: env` comment in `factory.rs`.

**Test scenarios:**
- Covers AE2. Unknown top-level `stroe` fails naming `stroe` and the plugin.
- Explicit `store: {kind: memory}` builds.
- `store: {kind: memory, endpoint: x}` fails.
- `store: {kind: dynamo}` fails listing supported kinds.
- Covers AE3. `store: {kind: valkey, ...}` without the feature fails naming
  the feature (cfg-gated test).

**Verification:** factory and config tests pass in both feature sets.

---

- U4. **Factory context in ppe-core**

**Goal:** Factories can read `global.session_store` at construction.

**Requirements:** R10, R12

**Dependencies:** None

**Files:**
- Modify: `crates/ppe-core/src/factory.rs`
- Modify: `crates/ppe-core/src/engine.rs`
- Modify: `crates/ppe/src/lib.rs`

**Approach:**
- `FactoryContext` with a `session_store()` accessor; `create_with` default
  calls `create`. `create_plugin_instances` calls `create_with`.
- `load_config_yaml` builds the context from `raw.global.session_store` and
  passes it through a private `load_config_with`; public `load_config` passes
  `FactoryContext::default()`.

**Test scenarios:**
- Happy path: a test factory overriding `create_with` sees the global block
  through `load_config_yaml`.
- Edge case: through `load_config` it sees none.
- Happy path: a factory implementing only `create` still works.

**Verification:** ppe-core tests pass; facade exports `FactoryContext`.

---

- U5. **Valkey correlation store and reference resolution**

**Goal:** `ValkeyCorrelationStore` implements the async trait atomically;
CIBA resolves standalone and reference configs.

**Requirements:** R9-R14, R16-R20, R22

**Dependencies:** U1, U2, U3, U4

**Files:**
- Create: `crates/builtins/src/plugins/elicitation_ciba/valkey_store.rs`
- Modify: `crates/builtins/src/plugins/elicitation_ciba/{mod,config,approver,factory}.rs`
- Modify: `crates/builtins/src/session/valkey/config.rs` (ciba default prefix)
- Test: `crates/builtins/tests/valkey/ciba_store_integration.rs`,
  `crates/builtins/tests/valkey/main.rs`, `crates/builtins/Cargo.toml`

**Approach:**
- Reference merge: copy the global block, drop `kind`, reject `endpoint`/`tls`
  overrides, apply overrides, default `key_prefix` to `ciba:v1`, then
  `ValkeyConfig::from_value` validates.
- Reference with no global valkey block, or global kind not `valkey`, fails
  naming the plugin.
- `put`: `HSET` + `PEXPIREAT` in a MULTI. `get`: `HGETALL`, missing fields or
  undecodable data are `StoreError`. `set_resolved_approver` and
  `take_if_ready`: `EVAL` scripts; take compares route/tool/requester and
  resolved state, deleting only when ready.
- The valkey test harness needs `elicitation-ciba` too, so its `[[test]]`
  `required-features` becomes `["valkey", "elicitation-ciba"]`, or the CIBA
  module is cfg-gated within it.

**Test scenarios:**
- Covers AE7. Reference with credential override connects as the override
  user under `ciba:v1` (config-level: merged config fields).
- Covers AE8. Reference with global `kind: memory` fails.
- Covers AE9. Reference with `endpoint` fails pointing to standalone.
- Error path: reference merged username without password fails (R13).
- Error path: standalone non-localhost without TLS fails (R9).
- Edge case: reference without credential override keeps the global user.
- Integration (live, gated): put/get/set/take round trip.
- Covers AE4. Integration: two approvers sharing a store, concurrent take,
  exactly one `Ready`.
- Integration: binding mismatch does not consume; later correct take succeeds.
- Integration: entry expires server-side after `expires_at`.
- Integration: unreachable endpoint yields `StoreError`.
- Integration: stored hash contains no token field (R19).

**Verification:** unit tests pass; live tests pass against a Valkey container.

---

- U6. **Integration warning test, docs, changelog**

**Goal:** Prove the R3 warning through the engine; document every pattern.

**Requirements:** R3, R18, R23-R26, AE1, AE6

**Dependencies:** U3, U5

**Files:**
- Modify: `tests/integration/tests/suite/host_contract.rs`
- Modify: `docs/content/builtins.md`, `docs/content/apl/elicitation.md`,
  `docs/content/apl/tainting.md`
- Modify: `CHANGELOG.md`

**Approach:**
- Docs examples are full documents so `docs_examples` checks them.
- Elicitation docs gain a "Correlation store" section with the three patterns
  and ACL lines.

**Test scenarios:**
- Covers AE1, AE6. Loading a config with `global.session_store: valkey` and a
  CIBA plugin without `store` emits exactly one warning naming the plugin.
- Explicit memory store emits none.
- Docs examples parse (existing harness).

**Verification:** integration suite and docs examples pass.

---

## System-Wide Impact

- **API surface:** `PluginFactory` gains a defaulted method (non-breaking);
  `ValkeyConfig.password` type changes (breaking for Rust constructors);
  `CorrelationStore` becomes async (breaking for builtins-crate implementors).
- **Error propagation:** new violation code `elicitation.store_unavailable`
  flows through the step's `on_error` like other CIBA failures.
- **Unchanged invariants:** approval binding, expiry, single use; memory
  behavior; `global.session_store` semantics for taint.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Production line budget (500) | Reuse in place; keep comments short |
| Lua via raw `EVAL` | Live tests cover each script path |
| Docker absent in CI pass | Tests are `#[ignore]`d and skip with `VALKEY_TESTS_OPTIONAL` |

---

## Sources & References

- **Origin document:** [docs/brainstorms/2026-10-21-ciba-correlation-store-selection-requirements.md](../brainstorms/2026-10-21-ciba-correlation-store-selection-requirements.md)
- Issue: https://github.com/praxis-proxy/policy/issues/236
