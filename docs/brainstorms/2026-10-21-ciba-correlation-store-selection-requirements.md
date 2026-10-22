---
date: 2026-10-21
topic: ciba-correlation-store-selection
issue: https://github.com/praxis-proxy/policy/issues/236
---

# Selectable CIBA correlation store, with Valkey

## Summary

The `elicitation/ciba` plugin config gains an explicit `store` choice with two
supported kinds, `memory` and `valkey`. With Valkey, pending approvals survive a
restart and reach any replica, while keeping today's guarantees: bound to route,
tool and requester, expiring, and applied at most once. A Valkey store is either
standalone or an explicit reference to the `global.session_store` connection,
with its own credentials and key prefix. Omitting `store` keeps memory with a
startup warning, and any setting the plugin does not recognize fails config
load.

---

## Problem Frame

A CIBA approval spans several requests. Dispatch records who must approve, a
later poll records who did, and a later retry redeems the approval. That state
lives in a correlation store, and `CibaApprover::new` always builds an
in-process one. Nothing in config can change it.

Operators running more than one replica, or restarting a gateway mid-approval,
see valid flows fail: the retry lands on a process that never saw the dispatch.
It fails closed (no approval is granted), but an approval that a human already
gave is lost. The only workaround today is sticky routing of approval retries to
one process, which the elicitation docs recommend.

Two things make this easy to misconfigure:

- **The session store looks like it should apply.** `global.session_store:
  {kind: valkey}` persists Session Taint labels, and an operator who sets it can
  reasonably assume approvals are now shared too. They are not.
- **A plausible fix is silently ignored.** `CibaConfig` accepts unknown fields,
  so adding `store: {kind: valkey, ...}` under the plugin's `config:` parses
  cleanly and changes nothing.

---

## Requirements

**Store selection**

- R1. The CIBA plugin config accepts a `store` block whose `kind` selects the
  correlation store. Supported kinds are `memory` and `valkey`.
- R2. The approver's constructor builds the store the config selects. No code
  path silently substitutes a different store.
- R3. When `store` is omitted, the plugin uses memory and emits one startup
  warning per plugin instance. The warning names the plugin, says pending
  approvals are local to this process, and says how to select a store.
- R4. When `store: {kind: memory}` is given explicitly, no warning is emitted.

**Validation**

- R5. Unknown top-level fields in the CIBA plugin config fail config load,
  naming the plugin and the field.
- R6. An unrecognized store `kind` fails config load, naming the plugin and the
  supported kinds.
- R7. Settings inside the `store` block that the selected kind does not accept
  fail config load. A `memory` store accepts no settings beyond `kind`.
- R8. Selecting `kind: valkey` in a build without the `valkey` feature fails
  config load with a message naming the missing feature, rather than reading as
  an unknown kind.

**Valkey configuration**

- R9. The Valkey store takes the same connection settings and the same
  validation as the session-taint Valkey store: endpoint, TLS required off
  localhost, ACL username paired with password, connect and command timeouts.
- R10. The Valkey store is configured in the plugin's own `store` block, in one
  of two forms. Standalone: the block carries its own endpoint and connection
  settings. Reference: the block names `connection: session_store` and reuses
  the Valkey connection settings from `global.session_store`. CIBA never uses
  the global store implicitly; with no `store` block it uses memory (R3).
- R11. A reference may override the ACL username and password, the key prefix,
  and the connect and command timeouts. Endpoint and TLS come from the global
  block and cannot be overridden; a different server uses the standalone form.
- R12. A reference fails config load, naming the plugin, when
  `global.session_store` is absent or is not `kind: valkey`.
- R13. Validation applies to the merged settings: a reference whose result
  breaks a Valkey rule (for example a username override with no password)
  fails the same way a standalone block would.
- R14. The CIBA Valkey store defaults to its own key prefix, distinct from the
  session store's, in both forms, so the keyspaces cannot collide under
  defaults.
- R15. Both Valkey stores, CIBA and session taint, accept the password from an
  environment variable or a file, the way `client_secret_source` does, as well
  as inline. A compartmentalized ACL user should not require a plaintext secret
  in YAML on either side. Existing inline `password:` strings keep loading
  unchanged. An unreadable source fails config load without echoing the
  secret, and a CIBA reference may override the password with any source form.
- R16. A reference with no credential override is accepted and connects as the
  session store's user. It is documented as not compartmentalized (R23).
**Valkey store behavior**

- R17. Redeeming an approval is atomic across replicas: when two replicas redeem
  the same id concurrently, at most one succeeds, and a route, tool or requester
  mismatch never consumes the entry.
- R18. Correlations expire server-side at their recorded expiry, so abandoned
  approvals do not accumulate.
- R19. Only the extracted approver claim is stored, never the OP token, matching
  the memory store's at-rest guarantee.
- R20. Every backend failure (unreachable, timeout, undecodable entry) fails
  closed and reads as indeterminate. It is never treated as approved, and a
  backend error is never reported as a missing correlation. A failed write after
  the OP request has gone out is also reported as indeterminate, since a human
  may already have been prompted.

**Tests**

- R21. Config-level tests cover: store omitted (memory, warning emitted),
  explicit memory (no warning), standalone Valkey parsed and validated, a
  reference merged with its overrides, a reference with no Valkey global store
  rejected, an endpoint or TLS override in a reference rejected, a merged
  config that breaks a Valkey rule rejected, env and file password sources on
  both stores (including an inline password still loading and an unreadable
  source failing without the secret in the message),
  unknown store kind rejected, unknown top-level field rejected, unexpected
  settings in a store block rejected, and Valkey selected without the feature
  rejected.
- R22. Behavioral tests run the dispatch, check and validate sequence against
  the Valkey store, including a cross-instance case (dispatch on one approver,
  redeem on another sharing the store), concurrent redemption, and expiry. These
  tests follow the existing Valkey gating on `VALKEY_TEST_URL` and
  `VALKEY_TESTS_OPTIONAL`.

**Documentation**

- R23. The builtins and elicitation docs state that `global.session_store` does
  not configure CIBA correlations unless a CIBA `store` block references it, and
  include complete, copyable examples of each pattern below. Each example states
  what it isolates and what it does not.
  - **Shared server, separate ACL user (recommended baseline).** A reference to
    `session_store` that overrides username, password source and key prefix,
    plus the Valkey `ACL SETUSER` lines that confine each user to its own key
    pattern. The docs explain that the prefix only prevents collisions, and the
    ACL users are the boundary: stolen taint credentials cannot forge an
    approver, and stolen CIBA credentials cannot clear taint labels.
  - **Separate server or instance.** A standalone block
    with its own endpoint, TLS and credentials, with guidance on when to choose
    it: a separate failure domain, `noeviction`, retention, or backups.
  - **Reference without credential override (not compartmentalized).** Shown as
    the convenience form, with a callout that both stores share one trust
    boundary.
- R24. The ACL guidance is presented as operator runbook: PPE does not create or
  verify ACL users. Any command category the atomic redeem needs (for example
  scripting) appears in the CIBA ACL line.
- R25. The elicitation docs replace the "route retries to the same process"
  guidance with: memory is single-process, Valkey is shared and durable.
- R26. The CHANGELOG records the new store option, the password sources on both
  Valkey stores, and the stricter unknown-field validation as a breaking config
  change. The session-taint docs show the new password source forms.

---

## Acceptance Examples

- AE1. **Covers R3.** Given a CIBA plugin with no `store`, when config loads,
  the plugin starts on memory and one warning names the plugin.
- AE2. **Covers R5.** Given a CIBA config with `stroe: {kind: valkey}`, config
  load fails and names `stroe`.
- AE3. **Covers R8.** Given `store: {kind: valkey, endpoint: ...}` in a build
  without the `valkey` feature, config load fails and says the `valkey` feature
  is required.
- AE4. **Covers R17, R22.** Given two approvers sharing one Valkey store, when a
  correlation dispatched on the first is resolved, both redeem it at once, then
  exactly one succeeds and the other sees it as missing.
- AE5. **Covers R20.** Given a Valkey store that times out on read, when the
  agent retries with an elicitation id, the request is denied as indeterminate,
  not as unknown id and not as approved.
- AE6. **Covers R3, R10.** Given `global.session_store: {kind: valkey}` and a
  CIBA plugin with no `store`, CIBA uses memory and the R3 warning fires.
- AE7. **Covers R10, R11, R14.** Given `global.session_store: {kind: valkey,
  endpoint: valkey.internal:6380, tls: true, username: ppe-taint, ...}` and a
  CIBA `store: {kind: valkey, connection: session_store, username: ppe-ciba,
  password from env}`, CIBA connects to `valkey.internal:6380` over TLS as
  `ppe-ciba`, under the CIBA default prefix.
- AE8. **Covers R12.** Given `global.session_store: {kind: memory}` and a CIBA
  store referencing `session_store`, config load fails and says the global
  store is not Valkey.
- AE9. **Covers R11.** Given a reference that also sets `endpoint`, config load
  fails and points to the standalone form.

---

## Success Criteria

- An operator running two replicas behind a round-robin load balancer completes
  a CIBA approval with no sticky routing.
- A gateway restart between dispatch and redeem does not lose a pending
  approval on the Valkey store.
- No CIBA config that previously loaded with an ignored field loads silently
  now. It loads as intended or fails with a message naming the problem.
- An operator can copy the shared-server example from the docs, apply the ACL
  lines, and end up with CIBA and session-taint data that neither credential
  can cross.
- The store semantics, failure behavior, and config shape are specified well
  enough to plan the implementation.

---

## Scope Boundaries

- Implicit inheritance: CIBA picking up `global.session_store` with no `store`
  block. Considered and rejected (see Key Decisions).
- Named connections beyond `session_store`, or a general connection registry.
- PPE creating, checking, or warning about Valkey ACL users.
- Retry or circuit-breaker behavior for the CIBA Valkey store. The session store
  has neither yet.
- Unknown-field rejection for other plugin configs.
- Changes to CIBA approval meaning, binding or single-use semantics.
- Using Valkey for other plugin state, such as the OAuth token cache.

---

## Key Decisions

- **Omitted store defaults to memory, with a warning.** Keeps existing configs
  loading while making the single-process limit visible. Requiring an explicit
  choice was rejected as a breaking change for no safety gain, since memory
  fails closed.
- **Explicit reference, not inheritance.** Operators who already run Valkey for
  Session Taint should not repeat the connection, so a CIBA store may reference
  it. The reference must be written in the plugin config, so every CIBA plugin
  shows where its approvals live, and changing the global store never moves
  approvals silently.
- **Credentials and prefix overridable; endpoint and TLS fixed.** Follows the
  isolation note already in the CIBA store module: approval state should be
  scoped apart from the session-taint keyspace, ideally by ACL user. Write
  access to CIBA keys can forge an approver, so a separate ACL user is the
  real boundary, and a prefix is only collision avoidance. Fixing endpoint and
  TLS keeps one block from describing two servers.
- **Document Valkey ACLs.** PPE cannot enforce them, so the docs provide
  copyable commands for separate Session Taint and CIBA users.
- **Parity with the session-taint Valkey store.** Same connection settings and
  validation, so operators learn one shape and the TLS and ACL guardrails carry
  over.
- **Fail closed, indeterminate on uncertainty.** Matches the approver's existing
  treatment of OP timeouts: an outcome that may have happened must not read as
  one that did not.

---

## Dependencies / Assumptions

- The correlation store interface is synchronous today. A Valkey store needs it
  to become async. All approver call sites are already in async methods
  (verified), so the change stays inside the plugin.
- The Valkey connection layer in `crates/builtins/src/session/valkey` is
  internal. Its module header names a second consumer as the trigger for
  extracting a shared layer; this is that consumer.
- `elicitation-ciba` and `valkey` are independent Cargo features in
  `crates/builtins/Cargo.toml` (verified).
- No shipped fixture or docs example puts extra keys in a CIBA `config:` block
  (verified by search), so R5 breaks no in-repo YAML.
- The session store's Valkey `password` is a plain string today, with no env or
  file source (verified in its config). R15 adds one to both stores.
- The session store's default key prefix is `taint:v1` (verified). The docs
  examples use `ciba:v1` for CIBA; the final default is a planning choice.
- The Valkey config is parsed when the global session store is built. A CIBA
  reference needs those settings at plugin construction, so plugin
  construction must be able to see them. Unverified; see Outstanding Questions.

---

## Outstanding Questions

### Deferred to Planning

- [Needs research] Extract a shared Valkey connection layer now, or duplicate
  the setup inside the CIBA plugin? The session store's header favors
  extraction once a second consumer exists.
- [Needs research] How a plugin factory sees `global.session_store` settings at
  construction time, given that plugins are built from their own
  `PluginConfig`. This decides where the R10 reference is resolved.
- Whether a reference shares the session store's connection pool or opens its
  own. With a credential override it must open its own.
- How the atomic redeem (R17) is expressed server-side: a script, a
  transaction, or a key layout that makes a single command sufficient.
- Encoding of a stored correlation, and whether it carries a version marker so
  a future field change does not misread old entries.
- Whether the Valkey store also needs a sliding TTL, or whether per-entry
  expiry from the correlation alone is enough.
