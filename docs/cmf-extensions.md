# CMF extensions and the attribute bag

A policy is written against a flat `AttributeBag`. The bag is filled by
`praxis-policy-apl-cmf`: each present slot on `Extensions` is walked into dotted
keys. Plugins that received the typed slot still see the original struct. This
document is the contract for what the bridge emits, how original collections
relate to flattened booleans, and which keys exist.

The twelve slots dispatched by `extract_extensions` are listed below.
`raw_credentials` and `candidate_constraint` are not among them: credentials
never enter the bag, and a routing constraint is not a policy attribute.

## Contents

- [Absent values](#absent-values)
- [Original collections and flattened booleans](#original-collections-and-flattened-booleans)
- [`subject.claims`](#subjectclaims)
- [What each decision point does with a missing key](#what-each-decision-point-does-with-a-missing-key)
- [The twelve slots](#the-twelve-slots)
- [Payloads that are not slots](#payloads-that-are-not-slots)

---

## Absent values

The rule is per **attribute type**, and it only applies inside a **present
slot**. An absent slot writes nothing for its namespace. CEL then reports an
undeclared reference for that namespace; synthesizing empty namespaces for
missing slots is out of scope.

| Type | When the field is empty or `None` | Why |
|---|---|---|
| `StringSet` | **Present and empty.** Membership is false. | CEL treats a missing key as an evaluation error. `!("banned" in subject.roles)` would deny every subject with no roles — a routine state, including a plugin that lacks `read_roles` and is handed an empty set. |
| `Bool` as a real field (`delegation.delegated`) | **Present**, including `false`. | The field is not optional on the struct. |
| `Bool` as a flattened member (`role.hr`) | **Omitted.** Presence means true. | Emitting `false` for every name that is not a member is impossible. APL reads a missing flattened bool as false; CEL needs `has(role.hr) && role.hr`. |
| `Bool` derived (`authenticated`) | **Omitted** unless `subject.id` is set. | Absence is "not authenticated". Emitting `false` would collapse that with an explicit unauthenticated marker the model does not have. |
| `String` | **Omitted** when `Option::None`. A non-option string (`client.client_id`) is always written, even if empty. | Empty string and missing are different questions (`exists(subject.id)` vs `subject.id == ""`). |
| `Int` | **Omitted** when `Option::None` (`http.status`, `agent.turn`, `completion.latency_ms`). A non-option int (`delegation.depth`) is always written, including `0`. | Emitting `0` for an unset HTTP status would make `http.status >= 500` and `http.status == 0` both lie. |
| `Float` | Same as `Int`. `delegation.age_seconds` is non-option and always written, including `0.0`. | Same reason: a missing telemetry field is not zero. |
| JSON object / claims map | **No parent key.** Each scalar (or scalar-array) child is written under a dotted path. `{}`, `null`, and an array holding a nested container set nothing. | The bag has no map type. See [`subject.claims`](#subjectclaims). |

`ppe-pdp-diff` is the executable form of this table for the keys Cedar can
see. Empty `subject.teams` and a subject with no roles (no `role.*` keys,
empty `subject.roles`) must Deny on APL, CEL, cedar-direct, and OPA when the
policy is a membership or flattened-bool gate. Unguarded CEL against an
**omitted scalar** remains an evaluation error and lives on the allowlist.

---

## Original collections and flattened booleans

[Pull request #7](https://github.com/praxis-proxy/policy/pull/7) added the
original CMF collections as bag keys alongside the flattened booleans that
were already there.

| Original (the set) | Flattened (presence-only) | Write |
|---|---|---|
| `subject.roles` | `role.<name> = true` | Both, from the same `HashSet`. |
| `subject.permissions` | `perm.<name> = true` | Same. |
| `subject.teams` | `team.<name> = true` | Same. |
| `client.roles` | `client.role.<name> = true` | Same. |
| `client.permissions` | `client.perm.<name> = true` | Same. |

**Authors should use the original set** for membership (`subject.roles contains
"hr"` in APL, `"hr" in subject.roles` in CEL, `"hr" in input.subject.roles` in
OPA). That key is present whenever the subject (or client) sub-record is, so
the four decision points agree on empty.

Flattened booleans are an APL convenience: `require(role.hr)` is false when the
key is missing. They are not a second source of truth. The bridge always
derives them from the set, so as emitted they cannot disagree. A later
`AttributeBag::set` that writes one and not the other **last write wins** on
that key; the other key is left as it was. Do not mix a hand-built bag with
the bridge if you need them to stay paired.

Cedar does not read the bag the way CEL and OPA do. `principal.roles` and
`principal.permissions` are rebuilt from flattened `role.*` / `perm.*` trues.
`principal.teams` is read from the original `subject.teams` set. Cedar does
not surface `client.*`, `http.*`, or the other slots as principal attributes.
A Cedar policy that needs those values does not get them from this mapping.

---

## `subject.claims`

There is no `subject.claims` bag key, and there will not be one until the bag
gains a map type.

`AttributeValue` is `Bool`, `Int`, `Float`, `String`, or `StringSet`. A JWT
claim object is none of those. The bridge walks each claim through the same
JSON flattener as `custom.*` and `args.*`:

- a scalar lands at `claim.<name>` with its type kept
- a scalar array, empty included, lands as a `StringSet` (numbers and bools
  rendered as strings)
- `{}`, `null`, and an array holding a nested container set no key
- a nested object sets only the children (`claim.realm_access.roles`), never
  the parent (`claim.realm_access`)

Client claims are the same shape under `client.claim.<name>`.

That is enough for every predicate the language can ask: `claim.tenant ==
"acme"`, `claim.realm_access.roles contains "admin"`. What it cannot do is
treat the whole map as one value (`exists(subject.claims)` meaning "any
claim"). Cedar still injects an empty `principal.claims` record so a probe of
the record itself is not a missing-attribute error; individual missing claim
names inside it follow Cedar's own rules.

To put a dict in the bag would take a sixth `AttributeValue` variant, APL
lookup into it, CEL map construction (already nested from dotted keys, so
partly redundant), a Cedar record that is not string-keyed leftovers, and an
OPA object. The flattened keys would still be required for the predicates that
exist today. Until that type exists, `claim.*` / `client.claim.*` are the
policy surface, and `SubjectExtension.claims` remains the typed form plugins
read.

---

## What each decision point does with a missing key

| Engine | Missing key | Empty `StringSet` |
|---|---|---|
| APL | false for presence, equality, membership, and order; `!=` is true (an absent key is not equal to a value) | `contains` / `in` is false |
| CEL | evaluation error; default `OnError::Deny` turns it into a denial that reports a key error, not a policy false | `in` is false |
| cedar-direct | empty `roles` / `permissions` / `teams` / `claims` on the principal so those names exist; no `subject.id` is a dispatch error | `contains` is false |
| OPA | undefined; without `default allow := false` the query is a default deny | `in` is false |

A policy written against a **present-empty set** therefore agrees — including
when Cedar reads flattened `role.*` and CEL reads `subject.roles`, because the
bridge filled both from the same set. A policy written against an **omitted
scalar**, or against a flattened bool whose namespace was never written
(`has(role.hr)` with no `role.*` keys), agrees only if CEL is rewritten onto
the original set. Unguarded CEL is the `missing-collection` /
`missing-subject-id` class of split.

---

## The twelve slots

Keys listed **always** are written whenever the slot (and, where noted, the
sub-record) is present. The rest are omitted when the field is `None` or the
map has no entry.

### 1. `security` — `SecurityExtension`

**Subject** (`sec.subject` present):

| Key | Type | When |
|---|---|---|
| `subject.id` | String | `id` is `Some` |
| `subject.type` | String (`user` / `agent` / `service` / `system`) | `subject_type` is `Some` |
| `subject.roles` | StringSet | always |
| `role.<name>` | Bool (`true`) | each member of `roles` |
| `subject.permissions` | StringSet | always |
| `perm.<name>` | Bool (`true`) | each member of `permissions` |
| `subject.teams` | StringSet | always |
| `team.<name>` | Bool (`true`) | each member of `teams` |
| `claim.<dotted>` | flattened JSON | each claim; see [`subject.claims`](#subjectclaims) |
| `authenticated` | Bool (`true`) | `id` is `Some` |

**Client** (`sec.client` present):

| Key | Type | When |
|---|---|---|
| `client.client_id` | String | always |
| `client.client_name` | String | `Some` |
| `client.trust_level` | String | always (`first_party` / `third_party` / `internal` / custom / `unknown`) |
| `client.roles` | StringSet | always |
| `client.role.<name>` | Bool (`true`) | each member |
| `client.permissions` | StringSet | always |
| `client.perm.<name>` | Bool (`true`) | each member |
| `client.authorized_scopes` | StringSet | always |
| `client.authorized_audiences` | StringSet | always |
| `client.teams` | StringSet | always |
| `client.claim.<dotted>` | flattened JSON | each claim |

**Workload** (`caller_workload` / `this_workload`; same shape, two namespaces).
These are not `agent.*`. `agent.*` is session context.

| Key | Type | When |
|---|---|---|
| `<ns>.spiffe_id` | String | `Some` |
| `<ns>.trust_domain` | String | `Some` |
| `<ns>.attestor` | String | `Some` |
| `<ns>.selectors` | StringSet | always |
| `<ns>.client_id` | String | `Some` |

`attested_at` is not in the bag: APL has no datetime type.

**Other**, written whenever the security slot itself is present:

| Key | Type | When |
|---|---|---|
| `auth_method` | String | `Some` |
| `security.labels` | StringSet | always |
| `security.classification` | String | `Some` |

### 2. `delegation` — `DelegationExtension`

| Key | Type | When |
|---|---|---|
| `delegation.depth` | Int | always (0 if none) |
| `delegation.delegated` | Bool | always |
| `delegated` | Bool | always (alias of the previous) |
| `delegation.origin_subject_id` | String | `Some` |
| `delegation.actor_subject_id` | String | `Some` |
| `delegation.age_seconds` | Float | always |

Per-hop scopes, audience, and strategy stay on the typed chain.

### 3. `agent` — `AgentExtension`

| Key | Type | When |
|---|---|---|
| `agent.input` | String | `Some` |
| `agent.session_id` | String | `Some` |
| `agent.conversation_id` | String | `Some` |
| `agent.turn` | Int | `Some` |
| `agent.agent_id` | String | `Some` |
| `agent.parent_agent_id` | String | `Some` |
| `agent.conversation.summary` | String | conversation present and summary `Some` |
| `agent.conversation.topics` | StringSet | conversation present (always then) |

`conversation.history` is not flattened.

### 4. `meta` — `MetaExtension`

| Key | Type | When |
|---|---|---|
| `meta.entity_type` | String | `Some` |
| `meta.entity_name` | String | `Some` |
| `meta.tags` | StringSet | always |
| `meta.scope` | String | `Some` |
| `meta.properties.<k>` | String | each map entry |

### 5. `request` — `RequestExtension`

| Key | Type | When |
|---|---|---|
| `request.environment` | String | `Some` |
| `request.request_id` | String | `Some` |
| `request.timestamp` | String | `Some` (ISO 8601 text) |
| `request.trace_id` | String | `Some` |
| `request.span_id` | String | `Some` |

A default request slot adds nothing.

### 6. `http` — `HttpExtension`

| Key | Type | When |
|---|---|---|
| `http.method` | String | `Some` |
| `http.path` | String | `Some` |
| `http.host` | String | `Some` |
| `http.scheme` | String | `Some` |
| `http.status` | Int | `Some` (response half) |
| `http.request_headers.<name>` | String | each header; name lowercased |
| `http.response_headers.<name>` | String | each header; name lowercased |

### 7. `llm` — `LLMExtension`

| Key | Type | When |
|---|---|---|
| `llm.model_id` | String | `Some` |
| `llm.provider` | String | `Some` |
| `llm.capabilities` | StringSet | always |

### 8. `mcp` — `MCPExtension`

**Tool** present:

| Key | Type | When |
|---|---|---|
| `mcp.tool.name` | String | always |
| `mcp.tool.title` | String | `Some` |
| `mcp.tool.description` | String | `Some` |
| `mcp.tool.server_id` | String | `Some` |
| `mcp.tool.namespace` | String | `Some` |

**Resource** present:

| Key | Type | When |
|---|---|---|
| `mcp.resource.uri` | String | always |
| `mcp.resource.name` | String | `Some` |
| `mcp.resource.description` | String | `Some` |
| `mcp.resource.mime_type` | String | `Some` |
| `mcp.resource.server_id` | String | `Some` |

**Prompt** present:

| Key | Type | When |
|---|---|---|
| `mcp.prompt.name` | String | always |
| `mcp.prompt.description` | String | `Some` |
| `mcp.prompt.server_id` | String | `Some` |

Schemas and annotations are not flattened.

### 9. `completion` — `CompletionExtension`

| Key | Type | When |
|---|---|---|
| `completion.stop_reason` | String | `Some` (`end` / `return` / `call` / `max_tokens` / `stop_sequence`) |
| `completion.tokens.input` | Int | tokens present |
| `completion.tokens.output` | Int | tokens present |
| `completion.tokens.total` | Int | tokens present |
| `completion.model` | String | `Some` |
| `completion.raw_format` | String | `Some` |
| `completion.created_at` | String | `Some` |
| `completion.latency_ms` | Int | `Some` |

### 10. `provenance` — `ProvenanceExtension`

| Key | Type | When |
|---|---|---|
| `provenance.source` | String | `Some` |
| `provenance.message_id` | String | `Some` |
| `provenance.parent_id` | String | `Some` |

### 11. `framework` — `FrameworkExtension`

| Key | Type | When |
|---|---|---|
| `framework.framework` | String | `Some` |
| `framework.framework_version` | String | `Some` |
| `framework.node_id` | String | `Some` |
| `framework.graph_id` | String | `Some` |
| `framework.metadata.<dotted>` | flattened JSON | each metadata entry |

### 12. `custom` — `HashMap<String, Value>`

| Key | Type | When |
|---|---|---|
| `custom.<dotted>` | flattened JSON | each map entry |

An empty map adds nothing.

---

## Payloads that are not slots

These use the same walker and the same absent-value rules, but they are not
`extract_extensions` slots:

| Source | Prefix |
|---|---|
| Request arguments | `args.*` |
| Upstream result | `result.*` |
| Static `data:` tree | `data.*` |
| Route identifier | `route.key` |
