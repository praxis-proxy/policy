# Extensions and Capability-Gating

Alongside the message, every operation carries typed extensions: the
contextual state policy reasons about. Identity, security labels, the delegation
chain, request headers, and agent session context are extensions.
Each extension is bridged into the flat attribute bag APL reads, under a
well-known namespace. Capability-gating controls which plugins may read or
write each one.

Hosts rarely configure extensions directly. Capability gating restricts the
state available to plugins that execute APL effects. The namespaces below are
the exact keys an APL predicate or plugin may read.

## The extensions

Each extension flattens into bag attributes under its namespace, gated by a read
capability. A prefix ending in `.` matches any key beneath it (`role.` matches
`role.hr`); a bare name is an exact key.

| Extension | Carries | Bag namespace | Read capability |
|-----------|---------|---------------|-----------------|
| Security (subject) | subject id and type, roles, permissions, teams, claims, authentication status | `subject.id`, `subject.type`, `authenticated`, `role.*`, `perm.*`, `subject.teams`, `team.*`, `claim.*` | `read_subject`, `read_roles`, `read_permissions`, `read_teams`, `read_claims` |
| Security (client) | OAuth application identity: client id, trust level, roles, permissions, scopes, audiences, teams, claims | `client.*` | `read_client` |
| Security (workload) | attested workload identity (SPIFFE / mTLS) for the inbound caller and for this instance | `caller_workload.*`, `this_workload.*` | `read_workload` |
| Security (labels) | taint / classification labels for information-flow control | `security.labels`, `security.classification` | `read_labels`, `append_labels` |
| Delegation | delegation depth, delegated flag, origin and actor subjects, chain age | `delegation.*`, `delegated` | `read_delegation`, `append_delegation` |
| Agent | session, conversation, turn, and lineage context | `agent.*` | `read_agent` |
| Meta | entity metadata: type, name, tags, scope, properties | `meta.*` | `read_meta` |
| Request | environment, request id, timestamp, trace and span ids | `request.*` | `read_request` |
| HTTP | request line (method, path, host, scheme) and request/response headers (lowercased) | `http.method`, `http.path`, `http.host`, `http.scheme`, `http.request_headers.*`, `http.response_headers.*` | `read_headers`, `write_headers` |
| LLM | model id, provider, capabilities | `llm.*` | `read_llm` |
| MCP | tool, resource, or prompt metadata | `mcp.*` (`mcp.tool.*`, `mcp.resource.*`, `mcp.prompt.*`) | `read_mcp` |
| Completion | stop reason, token counts, model, latency | `completion.*` | `read_completion` |
| Provenance | source, message id, parent id | `provenance.*` | `read_provenance` |
| Framework | agentic framework name and version, node and graph ids, metadata | `framework.*` | `read_framework` |
| Custom | free-form host-defined namespace | `custom.*` | `read_custom` |
| Raw credentials | inbound tokens and minted delegated tokens | flow through plugin payloads, not the bag | `read_inbound_credentials`, `read_delegated_tokens` |
| Candidate constraint | folded backend routing constraint from `restrict` effects | not a bag namespace — read by the host router | written by the policy engine |

The request arguments and response body are also flattened, under `args.*` and
`result.*`, and the route name is available as `route.key`. APL field pipelines
(`args:` / `result:`) operate on those. Operator-maintained static attributes
are flattened under `data.*` — these come from config files, not the request,
and need no capability (see [Static Attributes](apl/attributes.md)).

Most extensions are inputs — resolved before policy runs and flattened into
the bag for predicates to read. The candidate constraint is the exception:
it is an output. APL `restrict` effects fold into it (see [Backend
Restriction](apl/restrict.md)), it rides the returned extensions the same way
minted delegation tokens do, and the host router reads it typed to prune its
candidate set. Because PPE links the router in-process, this is a typed value,
not a serialized blob. Capability-gating the write is not yet applied — the
policy engine is its only writer today.

## Capabilities

A plugin declares the capabilities it needs. PPE filters the extensions before
handing them to the plugin, so a plugin sees only what it declared. The default
is no access; capabilities are additive grants.

```yaml
plugins:
  - name: audit-log
    kind: audit/logger
    hooks: [cmf.tool_pre_invoke]
    capabilities:
      - read_subject
      - read_client
      - read_delegation
```

### Read capabilities and the bag keys they unlock

| Capability | Unlocks |
|-----------|---------|
| `read_subject` | `subject.id`, `subject.type`, `authenticated` |
| `read_roles` | `role.*` (plus the `read_subject` baseline) |
| `read_permissions` | `perm.*` (plus baseline) |
| `read_teams` | `subject.teams` (plus baseline; `team.*` mirrors teams) |
| `read_claims` | `claim.*` (plus baseline) |
| `read_client` | `client.*` |
| `read_workload` | `caller_workload.*`, `this_workload.*` |
| `read_delegation` | `delegation.*`, `delegated` |
| `read_agent` | `agent.*` |
| `read_meta` | `meta.*` |
| `read_request` | `request.*` |
| `read_headers` | `http.method`, `http.path`, `http.host`, `http.scheme`, `http.request_headers.*`, `http.response_headers.*` |
| `read_llm` | `llm.*` |
| `read_mcp` | `mcp.*` |
| `read_completion` | `completion.*` |
| `read_provenance` | `provenance.*` |
| `read_framework` | `framework.*` |
| `read_custom` | `custom.*` |
| `read_labels` | the labels on the security extension. A plugin reads them from the extension; `security.labels` in the bag is what an APL predicate reads |
| `read_inbound_credentials` | no bag keys; gates raw inbound tokens in the plugin payload |
| `read_delegated_tokens` | no bag keys; gates minted tokens in the plugin payload |

`read_roles`, `read_permissions`, `read_teams`, and `read_claims` each imply the
`read_subject` baseline (`subject.id`, `subject.type`, `authenticated`). The
last three capabilities widen no plugin's bag view: labels are read from the
typed extension, and credential material flows through plugin payloads rather
than the bag. APL predicates read `security.labels` from the bag directly, which
is how `security.labels contains "secret"` works (see [Session
Taint](apl/tainting.md)).

### Write capabilities

Four capabilities grant write tokens rather than read access:

| Capability | Grants |
|---|---|
| `append_labels` | add a taint or classification label (monotonic; cannot remove) |
| `append_delegation` | extend the delegation chain (monotonic) |
| `write_headers` | rewrite request and response headers (implies `read_headers`) |
| `write_candidate_constraint` | narrow the backends the router may select |

Reading a candidate constraint is ungated: the host consumes it after
the pipeline rather than through a filtered plugin view. If a second
writer is ever introduced, composition should be monotonic, allow-sets
intersecting and deny-sets unioning, so no writer can weaken another's
constraint.

### Gating an action rather than a slot

`perform_http` is the odd one out. Every capability above gates a *slot*
of contextual state, widening or narrowing what a plugin can see and
set. `perform_http` gates an action: reaching outside the process at
all.

It is the one capability where withholding it stops the call rather than
degrading it. A plugin denied `read_claims` sees fewer attributes and
carries on; a plugin denied its IdP call but carrying on regardless
would decide without the answer it needed, which fails open. The
engine therefore refuses to start and names the plugin and the
capability to add.

Any plugin that fetches JWKS, exchanges a token, or dispatches a CIBA
prompt must declare it. See [Builtins](builtins.md) for how the bundled
ones do.

## Mutability tiers

Extensions differ in how they may change during a request, and the runtime
enforces the tier:

- Immutable: fixed once resolved. The verified subject identity, client,
  workload, agent, meta, request, LLM, MCP, completion, provenance, and
  framework extensions.
- Monotonic: may only grow. Security labels (added via `append_labels`,
  never removed) and the delegation chain (extended via `append_delegation`).
- Mutable: may be rewritten. HTTP headers (via `write_headers`) and the
  custom namespace.

A plugin cannot clear a Session Taint label or rewrite a verified identity even
if it holds the corresponding read capability. This keeps the state that APL
depends on trustworthy: the model is untrusted, and so is any plugin beyond the
context and mutations it was explicitly granted.

## APL integration

Capability-gating runs at the boundary between the manager and each plugin
(`filter_extensions` in praxis-policy-core decides which extension slots a
plugin sees;
the CMF extractors then flatten those slots into the bag). The same filtered,
tier-enforced view feeds the attribute bag APL evaluates, so a policy and the
plugins it invokes operate on a consistent, least-privilege picture of the
request. See [Identity](apl/identity.md) for how the subject is populated and
[Session Taint](apl/tainting.md) for the monotonic label tier in action.

## Next

- [Crates](crates.md): map the runtime and extension APIs to workspace crates.
- [Builtins](builtins.md): review the bundled plugins, PDPs, and session store.
