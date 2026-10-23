# Extensions and Capability-Gating

Alongside the message, every operation carries typed extensions: the
contextual state policy reasons about. Identity, security labels, the delegation
chain, request headers, and agent session context are extensions.
Each extension is bridged into the flat attribute bag APL reads, under a
well-known namespace. Capability-gating controls which plugins may read or
write protected state; operational context remains unrestricted.

Hosts rarely configure extensions directly. Capability gating restricts the
sensitive state available to plugins that execute APL effects. The namespaces
below are the exact keys an APL predicate may read; the Access column describes
which of them a plugin may read. The per-type
absent-value contract, original vs flattened keys, and the catalog of every key
the bridge emits are in [CMF extensions and the attribute bag](cmf-extensions.md).

## The extensions

Each extension flattens into bag attributes under its namespace. The Access
column says whether a plugin needs a capability for the typed slot behind those
keys. A prefix ending in `.` matches any key beneath it (`role.` matches
`role.hr`); a bare name is an exact key.

| Extension | Carries | Bag namespace | Access |
|-----------|---------|---------------|-----------------|
| Security (subject) | subject id and type, roles, permissions, teams, claims, authentication status | `subject.id`, `subject.type`, `authenticated`, `subject.roles`, `subject.permissions`, `subject.teams`, `role.*`, `perm.*`, `team.*`, `claim.*` | `read_subject`, `read_roles`, `read_permissions`, `read_teams`, `read_claims` |
| Security (client) | OAuth application identity: client id, trust level, roles, permissions, scopes, audiences, teams, claims | `client.*` | `read_client` |
| Security (workload) | attested workload identity (SPIFFE / mTLS) for the inbound caller and for this instance | `caller_workload.*`, `this_workload.*` | `read_workload` |
| Security (labels) | taint labels for information-flow control | `security.labels` | `read_labels`, `append_labels` |
| Security (classification) | host classification | `security.classification` | unrestricted |
| Security (authentication method) | host-recorded authentication method | `auth_method` | unrestricted |
| Delegation | delegation depth, delegated flag, origin and actor subjects, chain age | `delegation.*`, `delegated` | `read_delegation`, `append_delegation` |
| Agent | session, conversation, turn, and lineage context | `agent.*` | `read_agent` |
| Metadata | immutable facts acquired from an external policy information source, with trusted provenance | `metadata.<instance>.*` | `read_metadata` |
| Meta | entity metadata: type, name, tags, scope, properties | `meta.*` | unrestricted |
| Request | environment, request id, timestamp, trace and span ids | `request.*` | unrestricted |
| HTTP | request line (method, path, query, host, scheme) and request/response headers (lowercased) | `http.method`, `http.path`, `http.query`, `http.host`, `http.scheme`, `http.request_headers.*`, `http.response_headers.*` | `read_headers` for headers and non-query request-line fields; `write_headers` for header writes; `read_query` for raw `http.query` |
| LLM | model id, provider, capabilities | `llm.model.id`, `llm.model.provider`, `llm.model.capabilities` | unrestricted |
| LLM request | the host-parsed inference request body, and its normalized parts: ordered instructions, offered tools, tool choice, sampling parameters | the body is not flattened; OPA, CEL, and Cedar read it as `llm.request`. The typed parts flatten to `llm.input.offered_tools`, `llm.input.stop_sequences`, `llm.input.tool_choice`, `llm.input.forced_tool`, `llm.input.max_tokens`, `llm.input.candidate_count`, `llm.input.temperature`, `llm.input.top_p`, `llm.input.stream`, `llm.input.instructions_digest` | `read_llm_request` |
| MCP | tool, resource, or prompt metadata | `mcp.*` (`mcp.tool.*`, `mcp.resource.*`, `mcp.prompt.*`) | unrestricted |
| Completion | stop reason, token counts, model, latency | `llm.output.*` | unrestricted |
| Provenance | source, message id, parent id | `provenance.*` | unrestricted |
| Framework | agentic framework name and version, node and graph ids, metadata | `framework.*` | unrestricted |
| Custom | free-form host-defined namespace | `custom.*` | unrestricted |
| Raw credentials | inbound tokens and minted delegated tokens | flow through plugin payloads, not the bag | `read_inbound_credentials`, `read_delegated_tokens` |
| Candidate constraint | folded backend routing constraint from `restrict` effects | not a bag namespace — read by the host router | written by the policy engine |

One field of the agent extension is carried but not flattened: the
conversation history. `AgentExtension.conversation.history` is a list of CMF
`Message`s, oldest first, the same type as the current turn's payload. No
`agent.*` key exposes it, so an APL predicate cannot read it directly. A policy
that needs to reason over earlier turns runs a plugin that declares
`read_agent` and walks the typed turns itself;
`reference/plugins/transcript-scanner` is a worked example.

The gated `Extensions.llm_request` carrier contains the parsed body and
normalized parts. Its body is structured PDP input at `llm.request`, never a
bag key. Reported parts emit `llm.input.offered_tools` and
`llm.input.stop_sequences` as sets, the applicable scalar keys, and
`llm.input.instructions_digest`. The digest preserves instruction roles,
order, and message boundaries without exposing their text. A plugin needs
`read_llm_request` to see either reading. With no normalized parts,
`llm.input.*` keys are absent; use `!exists(llm.input.offered_tools): deny`
to refuse an unreported request. The model and output facts use
`llm.model.*` and `llm.output.*`. Legacy `llm.model_id`, `llm.provider`,
`llm.capabilities`, and `completion.*` aliases remain value-identical for
existing policies.
[LLM Routes](llm-routes.md) lists the per-phase keys and a worked config.

The request arguments and response body are also flattened. An object
writes `args.<dotted>` / `result.<dotted>`; a top-level scalar or scalar
array writes the bare key `args` / `result`. The route name is
`route.key`. APL field pipelines (`args:` / `result:`) operate on those. Operator-maintained static attributes
are flattened under `data.*` — these come from config files, not the request,
and need no capability (see [Static Attributes](apl/attributes.md)).

PDPs read the raw `http.query` from the canonical attribute bag. Plugin views
include it only with `read_query`; `read_headers` alone exposes the request and
response headers but not the query. `read_query` alone does not expose headers
or other request-line fields. Hosts must keep the query out of `http.path`.
When an identity resolver also reads a query, both inputs must come from the
same request target.

Most extensions are inputs — resolved before policy runs and flattened into
the bag for predicates to read. The candidate constraint is the exception:
it is an output. APL `restrict` effects fold into it (see [Backend
Restriction](apl/restrict.md)), it rides the returned extensions the same way
minted delegation tokens do, and the host router reads it typed to prune its
candidate set. Because PPE links the router in-process, this is a typed value,
not a serialized blob. Capability-gating the write is not yet applied — the
policy engine is its only writer today.

Acquired metadata belongs to one policy invocation. The metadata PIP fetch
step ([#184](https://github.com/praxis-proxy/policy/issues/184)), or a host
that resolves facts before dispatch, installs one record per source instance
with `Extensions::install_metadata`; ordinary plugin merge-back cannot add,
replace, or remove it. Route predicates always read `metadata.*`, because the
synthetic APL handler holds `read_metadata` intrinsically. Plugins dispatched within
the same invocation (`run`, delegation, elicitation) see the records read-only
when they declare `read_metadata`. A host starting a child policy invocation
uses `Extensions::for_child_request`, which retains the ordinary request
context but clears acquired metadata. The child may install its own records,
and those records are not merged into the parent.

## Capabilities

A plugin declares the capabilities it needs. PPE filters the extensions before
handing them to the plugin. The default for a capability-gated slot is no
access, and capabilities are additive grants. Unrestricted slots reach every
plugin regardless of what it declares.

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
| `read_roles` | `subject.roles` and `role.*` aliases for undotted members (plus the `read_subject` baseline) |
| `read_permissions` | `subject.permissions` and `perm.*` aliases for undotted members (plus baseline) |
| `read_teams` | `subject.teams` and `team.*` aliases for undotted members (plus baseline) |
| `read_claims` | `claim.*` (plus baseline) |
| `read_client` | `client.*` |
| `read_workload` | `caller_workload.*`, `this_workload.*` |
| `read_delegation` | `delegation.*`, `delegated` |
| `read_agent` | `agent.*` |
| `read_headers` | `http.method`, `http.path`, `http.host`, `http.scheme`, `http.request_headers.*`, `http.response_headers.*`; excludes raw `http.query` |
| `read_query` | raw `http.query` only; may include credentials |
| `read_llm_request` | `llm.input.offered_tools`, `llm.input.stop_sequences`, `llm.input.tool_choice`, `llm.input.forced_tool`, `llm.input.max_tokens`, `llm.input.candidate_count`, `llm.input.temperature`, `llm.input.top_p`, `llm.input.stream`, `llm.input.instructions_digest`; also gates the parsed request body on `Extensions.llm_request` |
| `read_metadata` | `metadata.<instance>.*` |
| `read_labels` | the labels on the security extension. A plugin reads them from the extension; `security.labels` in the bag is what an APL predicate reads |
| `read_inbound_credentials` | no bag keys; gates raw inbound tokens in the plugin payload |
| `read_delegated_tokens` | no bag keys; gates minted tokens in the plugin payload |

There is no read capability for `request`, `provenance`, `completion`, `llm`,
`framework`, `mcp`, `meta`, or `custom`: those slots are unrestricted. The
`auth_method` and `security.classification` sub-fields are unrestricted too.
Inventing a read-capability name for one of these slots does not make it gated.

`read_roles`, `read_permissions`, `read_teams`, and `read_claims` each imply the
`read_subject` baseline (`subject.id`, `subject.type`, `authenticated`). The
label and credential capabilities widen no plugin's bag view: labels are read
from the typed extension, and credential material flows through plugin payloads
rather than the bag. APL predicates read `security.labels` from the bag, which
is how `security.labels contains "secret"` works (see [Session
Taint](apl/tainting.md)).

`read_llm_request` gates the one request carrier. The body contains
client-supplied JSON and reaches PDPs through structured input, while the
normalized parts supply only the exact `llm.input.*` keys listed above.
Neither the body nor the parts are serialized with extensions. The route
handler receives both intrinsically; plugins need the capability. Host PDP
resolvers opt in by overriding `PdpResolver::evaluate_structured`.

Membership names containing `.` remain atomic values in the canonical sets and
do not receive flattened aliases. For example, test a dotted role with
`subject.roles contains "admin.readonly"`; there is no
`role.admin.readonly` key. The same rule applies to subject permissions and
teams, and to client roles and permissions.

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
  workload, agent, meta, request, LLM, LLM request, MCP, completion,
  provenance, framework, and externally acquired metadata extensions. Metadata
  is installed once per source instance by the framework and has no plugin
  write capability. The LLM request's body and normalized parts, and acquired
  metadata, are never serialized with `Extensions`, so they stay out of
  extension dumps and session stores; serde cannot carry provenance the
  framework did not stamp.
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
