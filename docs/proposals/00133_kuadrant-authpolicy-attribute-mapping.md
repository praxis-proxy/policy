---
issue: https://github.com/praxis-proxy/policy/issues/133
discussion: >-
  Consolidated proposal and mapping for Kuadrant Well Known Attributes used with AuthPolicy
status: proposed
authors:
  - maleck13
graduation_criteria:
  - This document contains a field-by-field mapping of every Kuadrant
    RFC 0002 well-known attribute to its PPE equivalent, each with a
    status (Mapped / Mapped-path / Mapped-shape / Different-model /
    Gap / N/A).
  - A single consolidated table lists every unsupported (Gap) and
    lossy (Mapped-path / Mapped-shape / Different-model) mapping with
    the reason.
  - PPE-side citations are verified against this repo; cross-repo
    (praxis-proxy) citations are explicitly marked unverified.
  - A recommended compatibility approach and a tiered testing strategy
    (reference fixtures, in-process PDP differential, dual-gateway) are
    defined.
stakeholders:
  - araujof
  - terylt
---

# Kuadrant AuthPolicy → PPE attribute mapping

## What?

A field-by-field mapping of Kuadrant/Authorino
[RFC 0002 well-known attributes](https://docs.kuadrant.io/1.0.x/architecture/rfcs/0002-well-known-attributes/)
to their Praxis Policy Engine (PPE) equivalents, plus a clear list of
the mappings that are **unsupported** or **lossy**.

Authorino evaluates authorization against an attribute bag built from
Envoy's `CheckRequest` plus synthesized auth phases. PPE evaluates
against its own bag populated by the Praxis host. For an existing
Kuadrant CEL/OPA policy to behave identically on PPE, each attribute
path must resolve to the same value. This document records where that
holds, where it holds with a caveat (lossy), and where it cannot hold
today (gap) with references for each well known attribute and PPE attribute.
It also recommends an overall approach to providing PPE with parity and
compatibility, outlines existing problems and possible mitigations, and defines
a tiered testing strategy to avoid regression and validate the solution.

### Overview

Of RFC 0002's **49 attributes** (verified against the 1.0.x RFC — see
[References](#references)), **3 map cleanly** to PPE and **14 need adapter
aliasing to run unchanged** — of those, **6 differ only in path** (value
preserved) and **8 differ in shape or model** (lossy). **31 have no PPE value
today**, and **1 is N/A** (Envoy-specific). The policy text is never rewritten;
the adapter aliases the Kuadrant vocabulary at runtime. Counts are
over the 49 canonical attributes. The matrix also lists illustrative
`auth.identity.*` JWT sub-claims (`sub`, `iss`, `roles`, …) to show the
recursive walk — these are examples of the single `auth.identity` attribute,
**not counted separately**. Even "maps cleanly" covers only the *value*;
identity claims carry an additional flattening caveat
([Auth — identity](#auth--identity-authidentity)).
Full counts: [Summary counts](#summary-counts).

The runtime-observable subset — request line, headers, identity claims —
maps well enough to run real policies, and is the part backed by
dual-gateway test evidence ([Tier 3 evidence](#tier-3-evidence-dual-gateway-spike)).
The largest functional gap is `auth.metadata.*` (external metadata fetch):
no PPE pipeline phase reaches it.

The rest of this document is reference: the exhaustive
[mapping matrix](#field-by-field-mapping-matrix) row by row, then the
single actionable
[unsupported / lossy list](#consolidated-unsupported--lossy-list) the
graduation criteria require.

### Goals

- One checked-in spec that maps every RFC 0002 attribute to PPE.
- A single, unambiguous list of unsupported and lossy mappings.
- Citations verified against PPE source; external citations flagged.
- A recommended compatibility approach and a tiered testing strategy.
- Ground the runtime-observable rows in dual-gateway test evidence.

### Non-goals

- Building the final compatibility layer or the metadata phase. Those
  are separate work items; this document scopes and justifies them.
- Praxis-proxy host changes. Those are noted as host-required but
  owned by the proxy repo.
- OPA v0 and GJSON pattern-matching compatibility. The layer targets CEL and
  OPA v1 only; work depending on the other two dialects is held back — see
  [Supported evaluator dialects](#supported-evaluator-dialects-scope).

## Status key

- **Mapped** — direct equivalent exists in PPE at an equivalent path.
- **Mapped (path)** — same **value**, different attribute path. *Not a
  verbatim drop-in, but no value is lost:* the adapter aliases the Kuadrant
  path to the PPE one so the policy runs **unchanged**.
- **Mapped (shape)** — same concept, different representation (e.g.
  array membership → per-name booleans). *Lossy:* predicate form differs;
  adapter aliased at runtime so the policy runs unchanged.
- **Different model** — PPE handles the concept architecturally
  differently (e.g. SPIFFE identity vs raw certificate). *Lossy;* adapter aliased
  at runtime.
- **Gap** — no PPE equivalent. `custom.*` / `data.*` can bridge only
  if the host populates them.
- **N/A** — Envoy/Kubernetes-specific, not applicable to Praxis.

## Attribute consumption in Authorino

All evaluators consume the same authorization JSON built by
`GetAuthorizationJSON()`. Only the access form differs:

| Evaluator | Input form | Attribute prefix |
|---|---|---|
| OPA (v0 + v1) | Full JSON as `rego.EvalInput` | `input.auth.identity.*`, `input.request.*`, `input.context.*` |
| CEL | 5 `protobuf.Struct` bindings via `AuthJsonToCel()` | `auth.identity.*`, `request.*`, `source.*`, `destination.*`, `metadata.*` |
| Pattern matching (GJSON) | Raw JSON string | `auth.identity.*`, `request.*`, `context.*` |
| Response / Conditions | Dispatches to GJSON or CEL | Same as whichever is configured |

CEL cannot access the deprecated `context.*` path; OPA and GJSON can
access both old and new paths. OPA v0 vs v1 is a Rego *syntax*
difference, not an input-shape difference — the input document is
identical.

### Supported evaluator dialects (scope)

**Recommendation: the compatibility layer targets CEL and OPA v1 (Rego) only.**
Of the four consumption forms above, those are Authorino's two general-purpose
expression languages and the path new policies are written for. The following are
**out of scope** for now:

- **OPA v0** — the legacy Rego syntax. v0 vs v1 is a syntax-only difference over
  the *same* input document, so supporting v0 adds parser/syntax surface for no
  extra attribute coverage. v0 policies should be upgraded to v1 ahead of time.
- **GJSON pattern-matching** — Authorino's raw-JSON pattern dialect, and the
  `Response` / `Conditions` forms that dispatch to it. A separate minimal dialect;
  excluded from the run-unmodified path.

Anything that depends on these two dialects — spike test arms, fixtures, and
tooling — is **held back** until the CEL + OPA v1 path is settled. The differential
spike's evaluator coverage therefore stays CEL and OPA v1; no v0 or GJSON arm is
added yet. This is a scope decision, not a statement that the dialects are
unmappable.

## Field-by-field mapping matrix

### Request attributes

**Concept.** The HTTP request as Envoy sees it (`CheckRequest` / `HttpRequest`):
request line, headers, and body. PPE splits this across two roots — the request
line and headers live under `http.*` (`http.method/path/host/scheme`,
`http.request_headers.*`), while PPE's own `request.*` is unrelated trace
metadata (`request.request_id`, `request.timestamp`).

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `request.id` | String | `request.request_id` | Mapped (path) | `x-request-id` header value |
| `request.time` | Timestamp | `request.timestamp` | Mapped (path) | Time of first byte; check type compat (string vs protobuf Timestamp) |
| `request.protocol` | String | — | Gap | HTTP version (1.0/1.1/2/3) |
| `request.scheme` | String | `http.scheme` | Mapped | |
| `request.host` | String | `http.host` | Mapped | |
| `request.method` | String | `http.method` | Mapped | |
| `request.path` | String | `http.path` | Mapped (path) | *Clean only if the proxy carries the query.* RFC `path` is the raw path **including** the query string. PPE's `http.path` is a single opaque string set by the proxy (`crates/ppe-apl-cmf/src/http.rs`) and read verbatim (`crates/ppe-core/src/http_path.rs`); whether it carries the query is proxy-dependent (external, unverified). If it does not, the query is lost — the same limitation as `url_path` |
| `request.url_path` | String | `http.path` | Mapped (path) | *Lossy:* RFC `url_path` is URL-**decoded** and **excludes** the query string, i.e. deliberately different from `path`. PPE has only one `http.path` value, so it cannot represent both forms; mapping `url_path` to it is approximate |
| `request.query` | String | (`http.path`) | Gap | Query string, not populated today. Derivable by splitting `http.path` on `?` **if** the proxy carries the query (proxy-dependent, unverified — see `request.path`); otherwise passed explicitly as `custom.request.query`. A transform, not a re-key — done only in the AuthPolicy input builder so it never alters `http.path` or native rules |
| `request.headers` | Map\<String,String\> | `http.request_headers.*` | Mapped (shape) | PPE has flat `http.request_headers.<name>`; Kuadrant uses map access `request.headers["name"]` |
| `request.referer` | String | `http.request_headers.referer` | Mapped (path) | Via headers |
| `request.useragent` | String | `http.request_headers.user-agent` | Mapped (path) | Via headers |
| `request.size` | Number | — | Gap | Request size in bytes |
| `request.body` | JSONString | — | Gap | Body; buffered by Praxis for entity routes (MCP/LLM) only, not pure L7 |
| `request.raw_body` | Bytes | — | Gap | Raw body bytes |
| `request.context_extensions` | Map\<String,String\> | `data.*` / `custom.*` | Gap | Operator-configured static key/values from the Envoy `ext_authz` filter config (not client or upstream data). PPE equivalent is operator-authored static data (`data.*`) or host-injected `custom.*`; alias `request.context_extensions.*` to it |

**Problems.**

- **Namespace split.** Kuadrant `request.*` is the HTTP request; PPE `request.*`
  is trace metadata and the HTTP data lives under `http.*`. A verbatim
  `request.method` is absent, not wrong — see
  [The `request.*` namespace](#the-request-namespace-hygiene-not-a-value-collision).
- **`path` vs `url_path`.** PPE has a single `http.path`; it cannot represent
  both the raw (query-bearing) `path` and the decoded, query-stripped `url_path`.
- **Headers shape.** PPE exposes flat `http.request_headers.<name>`, not the
  map access `request.headers["name"]`.
- **Body, size, protocol, raw_body are not surfaced** to the L7 filter context
  today (all Gap). **Query** is not surfaced as its own attribute either, but
  unlike the others it is derivable from `http.path` — see Mitigation.

**Mitigation / solutions.**

- **Request line and headers run today** — backed by dual-gateway evidence
  ([Tier 3 evidence](#tier-3-evidence-dual-gateway-spike)).
- **`id` / `time` / `referer` / `useragent` / `url_path`** are reachable by a
  shim/rewrite alias to their `http.*` / trace equivalents.
- **`query`** is derivable by splitting `http.path` on `?` when the proxy carries
  the query — an isolated transform in the AuthPolicy input builder that leaves
  `http.path` and native rules untouched — or passed explicitly as
  `custom.request.query`.
- **`size` / `protocol` / `body`** require Praxis to surface the data (and PPE to
  model some) — see the [Unsupported list](#unsupported-no-ppe-value-today).

### Source attributes (downstream client)

**Concept.** The downstream client's network identity (IP, port) and mesh/mTLS
identity. PPE does not model Envoy source fields; the one identity it carries is
the SPIFFE caller workload (`caller_workload.*`), not a raw principal string.

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `source.address` | String | — | Gap | Client IP; bridgeable via `custom.*` if host injects |
| `source.port` | Number | — | Gap | |
| `source.service` | String | — | Gap | Envoy service-mesh concept |
| `source.labels` | Map\<String,String\> | — | Gap | Pod/VM labels |
| `source.principal` | String | `caller_workload.spiffe_id` | Different model | PPE uses SPIFFE identity, not raw principal |
| `source.certificate` | String | — | Gap | Raw X.509 PEM |

**Problems.**

- **Network fields are not surfaced** — IP, port, service, labels, certificate
  are all Gap; they exist only at the proxy.
- **`source.principal` is a different model** — a SPIFFE id
  (`caller_workload.spiffe_id`), not Envoy's raw principal string, and today the
  `WorkloadIdentity` is not populated from mTLS peer identity.

**Mitigation / solutions.**

- **Client IP** is bridgeable without a PPE change via a `custom.*` injection in
  the proxy (`custom.source.address`).
- **`source.principal`** maps to `caller_workload.spiffe_id` once the host
  populates `WorkloadIdentity` from `peer_identity`. See the
  [Host-required detail](#host-required-detail-praxis--ppe-rows).
- **Service/labels/certificate** have no PPE equivalent (mesh concepts).

### Destination attributes (gateway local endpoint)

**Concept.** In Envoy's `CheckRequest`, `destination.*` is the **local** address
where the downstream connection terminates on the gateway — i.e. the gateway's
own listener endpoint — **not** the upstream service PPE proxies to. PPE has no
equivalent concept for the gateway's listener identity.

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `destination.address` | String | — | Gap | |
| `destination.port` | Number | — | Gap | |
| `destination.service` | String | — | Gap | |
| `destination.labels` | Map\<String,String\> | — | Gap | |
| `destination.principal` | String | `this_workload.spiffe_id` | Different model | |
| `destination.certificate` | String | — | Gap | |

**Problems.** No listener-endpoint concept exists in PPE, so address / port /
service / labels / certificate are all Gap. `destination.principal` is the same
SPIFFE model mismatch as `source.principal`.

**Mitigation / solutions.** `destination.principal` maps to
`this_workload.spiffe_id`; the remaining fields have no PPE equivalent and would
need the host to surface the gateway's listener identity.

### Connection attributes

**Concept.** The TLS/mTLS state of the downstream connection — whether mutual
TLS was used, the negotiated version, SNI, and the peer/local certificates. PPE
models only whether the caller was mutually attested (`caller_workload.attestor`);
it carries none of the raw TLS material.

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `connection.id` | Number | — | Gap | |
| `connection.mtls` | Boolean | `caller_workload.attestor` | Different model | PPE: check `attestor == "mtls"`. Note the semantics differ: Authorino's boolean means *a verified client certificate was presented* (mutual TLS). Plain TLS (server-auth only) is **not** mTLS — do not equate TLS presence with this attribute |
| `connection.requested_server_name` | String | — | Gap | SNI |
| `connection.tls_session.sni` | String | — | Gap | |
| `connection.tls_version` | String | — | Gap | |
| `connection.subject_local_certificate` | String | — | Gap | |
| `connection.subject_peer_certificate` | String | — | Gap | |
| `connection.dns_san_local_certificate` | String | — | Gap | |
| `connection.dns_san_peer_certificate` | String | — | Gap | |
| `connection.uri_san_local_certificate` | String | — | Gap | |
| `connection.uri_san_peer_certificate` | String | — | Gap | |
| `connection.sha256_peer_certificate_digest` | String | — | Gap | |

**Problems.**

- **`connection.mtls` is a model mismatch** — PPE exposes `attestor`, not a
  boolean, and mTLS (a *verified client certificate*) must not be conflated with
  plain server-auth TLS.
- **All raw TLS material is Gap** — SNI, version, certificates and digests are
  not surfaced to the filter context.

**Mitigation / solutions.** Map `connection.mtls` to
`caller_workload.attestor == "mtls"`. Raw TLS state is bridgeable only if the
host injects it (`custom.connection.tls`, plus `peer_identity` for the mTLS
distinction); certificates and digests have no PPE equivalent today.

### Auth — identity (`auth.identity`)

**Concept.** In Authorino, `auth.identity` is the authenticated principal
*verbatim*: for JWT auth the full decoded JWT payload, for API-key auth the
entire `k8s.Secret` object. PPE instead models identity as a **typed**
`IdentityPayload` — a subject, client, and workloads with normalized
roles/permissions/teams — and flattens the remaining claims into `claim.*` via
the shared JSON walker (`crates/ppe-apl-cmf/src/security.rs:136-141`). Membership and scalar
claims map directly; the structural differences are below.

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `auth.identity` (JWT) | Object | `claim.*` (recursive walk) | Mapped (shape) | All JWT claims via recursive walk, but flattened and lossy — see **Problems** below |
| `auth.identity.sub` | String | `subject.id` + `claim.sub` | Mapped | |
| `auth.identity.iss` | String | `claim.iss` | Mapped | |
| `auth.identity.aud` | String/Array | `claim.aud` + `client.authorized_audiences` | Mapped (shape) | A string `aud` maps cleanly. An **array**-valued `aud` flattens to a `StringSet` like `roles` (order/duplicates lost, index access broken); membership (`'x' in aud`) still holds |
| `auth.identity.exp` | Number | `claim.exp` | Mapped | |
| `auth.identity.roles` | Array | `subject.roles` (set) + `role.*` (booleans) + `claim.roles` | Mapped (shape) | Membership maps directly: `'x' in subject.roles` ≡ Authorino `'x' in roles`. `role.*` booleans are extra. Array order, duplicates, and index access are lossy (see **Problems**). #130 compat aliases `subject.roles` → `auth.identity.roles` |
| `auth.identity.permissions` | Array | `subject.permissions` (set) + `perm.*` (booleans) + `claim.permissions` | Mapped (shape) | Same as roles: membership via `subject.permissions`; order/duplicates/index lossy |
| `auth.identity.groups` | Array | `subject.teams` (set) + `team.*` (booleans) + `claim.groups` | Mapped (shape) | PPE folds groups + teams into `subject.teams` / `team.*`; membership maps directly |
| `auth.identity.teams` | Array | `subject.teams` (set) + `team.*` (booleans) + `claim.teams` | Mapped (shape) | Membership via `subject.teams`; order/duplicates/index lossy |
| `auth.identity.email` | String | `claim.email` | Mapped | |
| `auth.identity.email_verified` | Boolean | `claim.email_verified` | Mapped | |
| `auth.identity.realm_access.roles` | Array | `claim.realm_access.roles` | Mapped | Recursive walk handles nested |
| `auth.identity.<any_claim>` | Any | `claim.<any_claim>` | Mapped | Full recursive walk; subject to the flattening caveat (see **Problems** below) |
| `auth.identity` (API Key) | k8s.Secret | — | Gap | A plugin **does** exist (`identity_api_key`): it looks the key up in a directory and projects selected record fields onto PPE's typed identity slots via `record_map`. It does **not** expose the whole `k8s.Secret` object as `auth.identity`, so the Secret *shape* is still unavailable |
| `auth.identity.metadata.annotations.*` | String | — | Gap | No `metadata.annotations` namespace; an operator could route a specific annotation into a claim via `record_map`, but the convention is not reproduced |
| `auth.identity.data.*` | String | — | Gap | PPE does not expose raw Secret `data`; individual fields reachable only if explicitly projected via `record_map` |

**Problems.** `claim.*` is not the raw JWT — it is the payload **flattened**
into the attribute bag by the shared JSON walker (`crates/ppe-apl-cmf/src/payload.rs:50`). The
flattening is lossy in ways a verbatim imported policy can observe:

- **Nulls vanish.** `Value::Null` sets no key (`crates/ppe-apl-cmf/src/payload.rs:108`), so `claim.x`
  is absent whether the JWT omitted `x` or sent `"x": null`. Authorino
  distinguishes the two — and an absence that reaches a negated predicate can
  fail open (see
  [Caveat: absent data fails open under negation](#caveat-absent-data-fails-open-under-negation)).
- **Arrays become unordered string sets.** Scalar arrays promote to a
  `StringSet` (`crates/ppe-apl-cmf/src/payload.rs:62-93`): order is lost, duplicates collapse, and
  numbers/bools are coerced to strings (`[1,2]` → `{"1","2"}`). Index access
  (`auth.identity.roles[0]`) and numeric element comparison stop working.
- **Arrays of objects are dropped entirely.** A nested array/object element
  aborts the whole array (`crates/ppe-apl-cmf/src/payload.rs:83-86`), so a structured claim (e.g.
  `addresses`) produces **no** `claim.addresses` key at all.
- **Literal dotted claim names collide with nesting.** Object keys are joined
  with `.` (`crates/ppe-apl-cmf/src/payload.rs:52-61`), so a claim literally named `"a.b"` and a nested
  `{"a":{"b":…}}` both yield `claim.a.b`, indistinguishable. Namespaced JWT
  claims (`"https://…/roles"`) are affected.
- **Normalized roles may come from a different claim.** `subject.roles` /
  `role.*` are produced by the claim-mapper preset (keycloak reads
  `realm_access.roles`, see [presets](#ppe-claim-mapper-presets)) — not
  necessarily the claim an Authorino policy names as `auth.identity.roles`.
- **API-key identity is not the `k8s.Secret` shape.** The `identity_api_key`
  plugin projects selected record fields onto typed slots via `record_map`; it
  does not expose `auth.identity` as the whole Secret, so `auth.identity.data.*`
  and `.metadata.annotations.*` have no automatic equivalent.

**Mitigation / solutions.**

- **Membership predicates work unchanged.** `'x' in subject.roles`,
  `subject.permissions`, `subject.teams` and the `role.*` / `perm.*` / `team.*`
  booleans cover the common role/permission/group checks directly.
- **Full fidelity needs a structured input, not a re-key.** Because the loss
  happens when the typed identity is flattened **into** the bag, a bag-to-bag
  re-key (00130 Approach A) cannot recover it. Preserving fidelity requires
  keeping the original verified identity and its structured values and building
  the PDP input from them (a per-PDP input builder) — adapter-layer work under
  [issue #130](https://github.com/praxis-proxy/policy/issues/130).
- **API-key fields** can be surfaced individually by mapping them through
  `record_map`; the raw Secret *shape* and its `data` / `metadata.annotations`
  namespaces remain a hard gap.

### Auth — other phases

**Concept.** Authorino's later pipeline phases: external metadata it fetches
(`auth.metadata`), results of earlier authz evaluators (`auth.authorization`),
exported response objects (`auth.response`), and post-auth callbacks
(`auth.callbacks`). PPE has no equivalent incremental auth-JSON pipeline.

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `auth.metadata` | Map\<String,Any\> | — | Gap | External metadata (HTTP fetch, OIDC userinfo). No PPE pipeline phase. |
| `auth.authorization` | Map\<String,Any\> | — | Gap | Results from earlier authz evaluators |
| `auth.response` | Map\<String,Any\> | — | Gap | Exported response objects |
| `auth.callbacks` | Map\<String,Any\> | — | Gap | Post-auth callback results |

**Problems.** `auth.metadata` is the largest functional gap — no PPE phase
reaches external metadata — and the other three have no incremental auth-JSON
model. These are also the attributes most exposed to the
[fail-open-under-negation](#caveat-absent-data-fails-open-under-negation) hazard:
a policy that denies on absent metadata will **allow** on PPE.

**Mitigation / solutions.** `auth.metadata` could be filled by a future callout
plugin or by Praxis fetching and injecting it; `authorization` / `response` /
`callbacks` would need pipeline-phase plugins. Until then, any imported policy
depending on these must be rejected at config time rather than silently allowed
(adapter-layer work, [#130](https://github.com/praxis-proxy/policy/issues/130)).

### Metadata and filter state

**Concept.** Authorino's `metadata` is Envoy **dynamic metadata** (filter-chain
state). PPE's `meta.*` is **entity metadata** (type/name/tags) — the same
keyword naming a different thing. `filter_state` is Envoy filter-chain internal
runtime state produced by other Envoy filters.

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `metadata` | Metadata | `meta.*` | Different model | PPE: entity metadata (type/name/tags). Authorino: Envoy dynamic metadata |
| `filter_state` | Map\<String,String\> | — | N/A | Envoy filter-chain internal runtime state, written by other Envoy filters during request processing. Not operator config and not request/identity data; no portable concept off Envoy, so no PPE producer |

**Problems.** The `metadata` keyword collides on name but not meaning; a verbatim
policy reading Envoy dynamic metadata will read PPE entity metadata instead.
`filter_state` is Envoy filter-chain internal state written by other filters at
runtime — it has no meaning or producer off Envoy.

**Mitigation / solutions.** Where a policy's use of `metadata` happens to align
with entity metadata, a shim/rewrite to `meta.*` works; general Envoy dynamic
metadata has no PPE equivalent. `filter_state` is N/A — there is no portable
concept to bridge to.

### Rate-limit attributes

**Concept.** RFC 0002 defines two rate-limit inputs consumed by Limitador, not by
Authorino's authorization evaluators. PPE addresses rate limiting through a
separate external Limitador integration
([#152](https://github.com/praxis-proxy/policy/issues/152)), not through these
attributes — a model difference, not a missing authorization value.

| Kuadrant Attribute | Type | PPE Equivalent | Status | Notes |
|---|---|---|---|---|
| `ratelimit.domain` | String | — | Different model | Limitador rate-limit domain; PPE rate limiting is external (#152), not a policy attribute |
| `ratelimit.hits_addend` | Number | — | Different model | Per-request hit cost; same external-Limitador model |

**Problems.** These are not authorization attributes — no Authorino authz
evaluator and no PPE authorization policy reads them. Mapping them into the
attribute bag would be meaningless.

**Mitigation / solutions.** Rate limiting is tracked separately under the
Limitador integration ([#152](https://github.com/praxis-proxy/policy/issues/152));
these attributes need no attribute-bag mapping at this point.

### PPE claim-mapper presets

`identity/jwt` supports four presets determining how claims map to
`role.*` / `perm.*` / `team.*`:

| Field | standard | keycloak | auth0 | cognito |
|---|---|---|---|---|
| `subject.id` | `sub` | `sub` | `sub` | `sub` |
| `role.*` | `roles[]` | `realm_access.roles[]` | — | — |
| `perm.*` | `permissions[]` → `scope` | `scope` | `permissions[]` → `scope` | `scope` |
| `team.*` | `teams[]` → `groups[]` | — | — | `cognito:groups[]` |
| `client.client_id` | `client_id` → `azp` | `client_id` → `azp` → `clientId` | `client_id` → `azp` | `client_id` |

`→` = fallback chain.

### PPE-only attributes (no Kuadrant equivalent)

`delegation.*`, `agent.*`, `llm.*`, `mcp.*`, `completion.*`,
`provenance.*`, `framework.*`, `data.*`, `args.*`, `result.*`,
`custom.*`, `session.*`.

### Summary counts

Counts are over RFC 0002's 49 canonical attributes (illustrative
`auth.identity.*` JWT sub-claims in the matrix are not counted). Need adapter
aliasing to run unchanged = path + shape + model = 14; of those, shape + model =
8 are **lossy** and path = 6 preserve the value. Total = 49.

| Status | Count | Meaning |
|---|---|---|
| Mapped | 3 | Direct path match, verbatim drop-in (`request.scheme/host/method`) |
| Mapped (path) | 6 | Same value, different path — **aliased** (no value lost) |
| Mapped (shape) | 2 | Same concept, different representation (`request.headers`, `auth.identity` JWT) — **lossy**, aliased |
| Different model | 6 | Architecturally different (SPIFFE ×2, mTLS, metadata, ratelimit ×2) — **lossy**, aliased |
| Gap | 31 | No PPE equivalent |
| N/A | 1 | Envoy-specific (`filter_state`) |

## Consolidated unsupported / lossy list

The single list the graduation criteria require. "Lossy / re-pathed" = the value
exists and the policy runs **unchanged** once the adapter aliases it, but the path
differs (value preserved) or the shape/model differs (lossy); "Unsupported" = the
value does not exist in PPE today. The policy text is never rewritten at runtime.

The **Solution** column says where each value should come from. Its
vocabulary: `Praxis → PPE` (proxy has it, host injects, no PPE change);
`Praxis + PPE` (proxy surfaces it *and* PPE models a new field);
`PPE: plugin` (new plugin); `PPE: hook` (new enrichment capability);
`Alias` (adapter-input alias at runtime — the goal; includes an isolated
transform that derives the value, e.g. splitting `http.path`, provided it does
not alter other attributes; or transpiler rewrite ahead-of-time); `N/A`.

### Lossy / re-pathed (runs unchanged via adapter aliasing)

| Attribute | Kind | Why it differs | Solution |
|---|---|---|---|
| `request.id` | path | → `request.request_id` | Alias |
| `request.time` | path | → `request.timestamp`; string vs protobuf Timestamp type | Alias |
| `request.path` | path | RFC `path` includes the query string; PPE `http.path` preserves the full value only if the proxy carries the query (unverified), else the query is lost | Alias |
| `request.url_path` | path | PPE has only `http.path`; cannot represent `url_path`'s decoded, query-stripped form distinctly from raw `path` | Alias |
| `request.referer` / `request.useragent` | path | only via `http.request_headers.*` | Alias |
| `request.headers` | shape | flat `http.request_headers.<name>` vs map access `["name"]` | Alias (present map) |
| `auth.identity.roles` / `permissions` / `groups` / `teams` | shape | membership maps directly via `subject.{roles,permissions,teams}` (StringSet); array order, duplicates, and index access are lossy | Alias `subject.*` set → `auth.identity.*` (the #130 compat does this) |
| `source.principal` / `destination.principal` | model | SPIFFE identity, not raw principal | Alias (map `caller_workload.spiffe_id`) |
| `connection.mtls` | model | `caller_workload.attestor == "mtls"`, not a boolean; and mTLS (verified client cert) must not be conflated with plain TLS | Alias (map `attestor`) |
| `metadata` | model | entity metadata, not Envoy dynamic metadata | Alias (map `meta.*`) |
| `ratelimit.domain` / `ratelimit.hits_addend` | model | Limitador inputs, not authz attributes; PPE rate-limits externally | Different mechanism ([#152](https://github.com/praxis-proxy/policy/issues/152)) |

### Unsupported (no PPE value today)

| Attribute | Why unsupported | Solution |
|---|---|---|
| `request.query` | Not populated today; the proxy has it (`req.uri.query()`) but doesn't pass it as an attribute | Alias (transform: split `http.path` on `?`) when the proxy carries the query; else Praxis → PPE (`custom.request.query`) |
| `request.context_extensions` | Operator-configured static key/values from the Envoy `ext_authz` filter config; no automatic equivalent, but the operator can author the same static values as `data.*` (or inject `custom.*`) | Alias (operator authors `data.*`, alias `request.context_extensions.*`) |
| `source.address` | Client IP known only to proxy | Praxis → PPE |
| `connection.mtls` state (raw) | mTLS state at listener (`downstream_tls` + verified peer cert) not passed; plain TLS alone does not satisfy it | Praxis → PPE |
| `source.principal` (mTLS) | `peer_identity` available but `WorkloadIdentity` not populated | Praxis → PPE |
| `request.protocol` | HTTP version not surfaced to filter context | Praxis + PPE |
| `request.size` | Not surfaced | Praxis + PPE |
| `source.port` / `destination.*` | Not surfaced to filter context | Praxis + PPE |
| `source.service` / `source.labels` | Mesh data; may not exist off-Envoy | Praxis + PPE |
| `source.certificate` / `connection.*` certs, SNI, tls_version, id | Not surfaced | Praxis + PPE |
| `request.body` / `request.raw_body` | Buffered for entity routes (MCP/LLM) only, not pure L7 | Praxis (enable buffering) + PPE (surface for L7) |
| `auth.metadata` | No metadata pipeline phase — biggest functional gap | PPE: plugin (callout) *or* Praxis fetch+inject |
| `auth.authorization` / `auth.response` / `auth.callbacks` | No incremental auth-JSON model | PPE: plugin (pipeline phases) |
| `auth.identity` (API key) Secret shape, `.metadata.annotations.*`, `.data.*` | Plugin exists (`identity_api_key`) but projects fields onto typed slots; raw `k8s.Secret` shape not exposed | Alias (`record_map` projection) |
| Identity extended properties (`defaults`/`overrides`) | PPE presets are static | PPE: hook (post-auth enrichment) |
| Multi-auth priority (JWT → API-key fallback) | Multiple JWT issuers only, no cross-method priority | PPE: plugin (multi-method resolver) |

### Host-required detail (`Praxis → PPE` rows)

The `Praxis → PPE` rows above are data Praxis *has* but does not pass.
A `custom.*` injection in the proxy's `attach_http_attributes` closes
them without PPE changes:

| Data | Praxis source (external repo, unverified) | Bridge as |
|---|---|---|
| Client IP | `ctx.client_addr` | `custom.source.address` |
| TLS state | `ctx.downstream_tls` | `custom.connection.tls` (TLS presence only; mTLS additionally needs a verified peer cert — see `peer_identity`) |
| mTLS peer identity | `ctx.peer_identity.spiffe_id` | populate `WorkloadIdentity` |
| Query string | `req.uri.query()` | `custom.request.query` |

## Compatibility approach

Implementation is tracked by
[issue #130](https://github.com/praxis-proxy/policy/issues/130) (Epic:
AuthPolicy/PPE attribute dictionary compatibility). This document is the attribute
analysis that feeds it; the engine seams and candidate design live in a companion
spike (`00130`), kept as experimental reference under #130, not merged here.

Two strategies run unmodified Kuadrant policies, matching #130's Option 1 and 2:

- **Adapter input (Option 1, recommended).** Behind a compatibility flag, present
  the Kuadrant vocabulary (`request.method`, `auth.identity.*`) to the evaluator
  alongside PPE's native attributes, so both resolve to the same value without
  editing the policy.
- **AST rewriting (Option 2).** Parse each rule into an AST and rewrite its paths.
  Ruled out as a runtime path
  ([why](#ruled-out-ast-rewriting-as-a-runtime-path)); the ahead-of-time case is
  covered by the external transpiler.

Adapter input wins because it survives variable aliasing in both CEL
(`let req = request`) and Rego (`req := input.request`), which a lexical rewrite
cannot handle without a full parser.

**Realising adapter input.** The 00130 spike tried a shared-bag re-key (Approach A,
a default-off spike) and sibling adapter PDPs (Approach B). The recommended form is
a **per-PDP input builder**: build each dialect's input from typed sources and feed
the existing CEL/OPA resolvers. Unlike a re-key it preserves identity fidelity and
per-dialect object identity (see
[Auth — identity](#auth--identity-authidentity) and
[The `request.*` namespace](#the-request-namespace-hygiene-not-a-value-collision)),
and it can **derive** a value with an isolated transform (e.g. splitting
`http.path` into `request.query`) as long as it leaves shared attributes and native
rules untouched.

### Ruled out: AST rewriting as a runtime path

A runtime runner must cover both evaluators, and Rego cannot round-trip.
CEL AST rewriting is likely feasible as it has an accessible AST. Rego (regorus 0.12.0) is the
blocker: its AST is behind a `#[doc(hidden)]` "likely to change" module, there is no
unparser, and the engine only ingests Rego source (`add_policy`).

### The `request.*` namespace (hygiene, not a value collision)

PPE's *own* `request.*` bag is environment/trace metadata
(`request.request_id`, `request.timestamp`, `request.trace_id`), **not**
the HTTP request. Kuadrant's `request.*` is the HTTP request
(`request.method`, `request.path`, …). So the Kuadrant `request.*`
namespace splits across two PPE roots — `request.method` → `http.method`,
`request.id` → `request.request_id`.

The 00130 spike checked whether this is a hard collision and found it is
not: a verbatim `request.method` never overwrites or reads a trace value — it is simply
absent until aliased, and a *positive* naive predicate on it fails **closed**
(see the naive-arm evidence below), not to a wrong value. This fail-closed
guarantee holds only for positive references; a *negated* reference to absent
data fails **open** — see
[Caveat: absent data fails open under negation](#caveat-absent-data-fails-open-under-negation).

The residual concern is **object identity**, not just namespace hygiene. A shared
bag re-key (Approach A) merges HTTP and trace leaves into one `request` map, so
although leaf reads still work, the object *as a whole* diverges and native PPE rules are
contaminated with the injected keys in the other direction.

The fix is the same **per-PDP input builder** the identity-fidelity mitigation
calls for ([Auth — identity](#auth--identity-authidentity)): select the input
construction by policy dialect, so AuthPolicy rules get a `request` /
`auth.identity` object built from typed sources carrying **only** the Authorino
keys, while native rules keep today's objects — reusing the existing CEL/OPA
resolvers unchanged. One builder closes both the object-identity and the fidelity
gap; a shared bag re-key closes neither. Adapter-layer work under
[issue #130](https://github.com/praxis-proxy/policy/issues/130).

## Testing strategy

Three tiers, cheapest and most isolated first; only the top tier needs a
cluster. Each tier is a regression gate, and a mapping change that flips a
decision should fail the cheapest tier that can observe it.

1. **Reference fixtures (no runtime).** Capture the reference authorization JSON
   and the expected decision from a pinned-Authorino harness, checked into the
   repo. These are the ground truth every other tier asserts against. Cover every
   attribute family, including the Gap and ratelimit rows (recorded as expected
   divergence, not compatibility).

2. **In-process PDP differential.** This tier carries the bulk of coverage. Each
   case is a table-driven in-process test — no proxy, no cluster — that runs the
   *unchanged* Kuadrant predicate through the real CEL/OPA resolver. A case:

   1. builds a PPE attribute bag / typed identity for the scenario;
   2. constructs the PDP input from it (`bag_to_input` for OPA, `bag_to_context`
      for CEL, or the per-PDP builder);
   3. feeds the verbatim predicate to the real engine (regorus / the `cel` crate);
   4. asserts both the projected attribute value and the allow/deny decision
      against the tier-1 Authorino fixture.

   Extend `ppe-pdp-diff` with these Authorino reference cases. The tier must
   exercise the fidelity hazards the mapping calls out: missing/null claims, scalar
   arrays (order/duplicates/coercion), literal dotted keys, indirect or aliased
   references, and the missing-data
   [fail-open case](#caveat-absent-data-fails-open-under-negation).

3. **Dual-gateway end-to-end (interim).** The smallest tier: fire identical HTTP
   requests at a real Authorino gateway and a real PPE gateway and compare status
   codes. Scoped to what only a live gateway exercises — real HTTP/TLS/body capture
   and AuthPolicy translation. This is the current spike
   ([Tier 3 evidence](#tier-3-evidence-dual-gateway-spike)); most cases do not need
   it. Treat it as **temporary**: the bespoke dual-gateway harness proves the
   concept now, but the end state is running **Kuadrant's own e2e suite** against a
   PPE-backed gateway, so compatibility is measured by upstream's tests rather than
   a parallel one we maintain.

Tier 1 pins ground truth, tier 2 catches mapping and fidelity regressions without
infrastructure, tier 3 catches host and transport regressions. Only the
runtime-observable subset has tier-3 evidence today; tiers 1 and 2 are the work
proposed here, and tier 3 migrates from the bespoke spike to Kuadrant upstream
e2e.

## Tier 3 evidence: dual-gateway spike

This section is the tier-3 evidence from the [Testing strategy](#testing-strategy)
above — the runtime-observable rows checked end-to-end against a real Authorino
gateway. Tiers 1 and 2 are proposed work; the results below are from an
exploratory spike.

The evidence comes from a dual-gateway spike kept as an **experimental,
out-of-tree reference** under [issue #133](https://github.com/praxis-proxy/policy/issues/133)
— it is **not** merged by this PR, whose only artifact is this document. In it the
same predicate is expressed as an Authorino AuthPolicy and an equivalent PPE
policy, the same requests are fired at both, and the status codes are compared.
Test IDs follow `<evaluator>-<group>-<attr>` (e.g. `cel-req-method`,
`opa-dep-method`), aligned with the CEL/OPA matrix below.

Coverage families: request line (`req`), headers (`hdr`), identity
claims (`id`), mixed namespaces (`mix`), source/connection gaps
(`gap`), deprecated `context.*` (`dep`), metadata gap (`meta`),
variable aliasing (`alias`), cross-evaluator consistency (`cross`).

Gap and metadata rows are expected to **fail** on PPE today — those
tests document the gap rather than assert compatibility.

Per the [dialect scope decision](#supported-evaluator-dialects-scope), the spike
covers CEL and OPA v1 only. No OPA v0 or GJSON pattern-matching arm is added;
cases for those dialects are held back.

### Naive straight-translate arm (evidence for #130)

In the spike, each attribute has two PPE-side policies, not one:

- **mapped** — the correct PPE path (`http.method`).
- **naive** — the Kuadrant predicate copied *verbatim* (`request.method`),
  the lift-and-shift #130 warns against.

The naive arm is the evidence the epic actually needs: it proves the
mistranslation is a *runtime* failure, invisible to compile/validation.

Observed for `cel-req-method` (POST expected allow, GET expected deny):

| Gateway / policy | POST | GET |
|---|---|---|
| Authorino (ground truth) | 200 | 403 |
| PPE mapped (`http.method`) | 200 | 403 |
| PPE naive (`request.method` verbatim) | **403** | 403 |

Both PPE configs pass `praxis -t` validation (exit 0); the divergence
only appears at request time. Notably the naive CEL case failed
**silently** — a plain 403 deny with no evaluation error or panic in the
proxy log. This *corrects* #130's expectation that CEL mistranslation
"tends to panic": here it failed closed. Fail-closed is safer than
fail-open, but it is still wrong behaviour and would silently break a
migrated allow rule.

### Caveat: absent data fails open under negation

The fail-closed result above is only the *positive* case
(`allow if request.method == "POST"` — absent `request.method` makes the
condition false, so the request is denied). **Negated** references to absent
data fail the other way, and this is a security hole, not a safe default:

```rego
# Deny suspended accounts. Relies on auth.metadata (a mapping Gap).
allow if {
    not input.auth.metadata.account.suspended
}
```

When PPE has no `auth.metadata`, the inner reference is *undefined*; in Rego
`not <undefined>` evaluates to **true**, so `allow` fires. Authorino, which
fetches the metadata, denies a suspended account; PPE **allows** it. The same
pattern applies to any `not <absent>` / absence-as-permission idiom, in both
Rego and CEL. `on_error: deny` does **not** catch this — there is no error, the
predicate simply evaluates to allow.

So a missing mapping can turn an Authorino *deny* into a PPE *allow*. This makes
mapping completeness security-critical for any imported policy that reasons over
negated or optional attributes. Closing it is adapter-layer work tracked under
[issue #130](https://github.com/praxis-proxy/policy/issues/130): imported
policies must declare their data dependencies, the config loader must reject
policies requiring attributes PPE cannot supply, and host data that *can* be
captured must be present (or the request denied before evaluation) rather than
silently absent. Fixtures must prove a missing mapping cannot flip an Authorino
deny into a PPE allow.

## Open questions

1. **Deprecated `context.*` in OPA** — Authorino OPA supports it, CEL
   does not. Should adapter input support it (broader compat, perpetuates
   a deprecated path)? The 00130 spike currently emits it
   (`context.request.http.*`), so this is a keep/drop decision, not new
   work. Note the
   [dialect scope decision](#supported-evaluator-dialects-scope) only removes
   one `context.*` consumer (GJSON); OPA **v1** — which stays in scope — can
   still read `context.*`, so this question remains open for OPA v1.
2. **`request.headers` shape** — presenting a map object for CEL/OPA
   given PPE's flat bag and its nested-tree activation.
3. **Identity extended properties** — how common in real AuthConfigs?
   If common, PPE needs a post-auth enrichment hook.
4. **Metadata phase** — in scope for the compatibility layer or
   explicitly out?
5. **`request.body` for pure L7** — enable body buffering for
   body-inspecting policies, or out of scope?
6. **Ownership** — the quick-win `custom.*` injections are Praxis-side
   (proxy repo). Who owns them?

## References

PPE-side citations verified against this repo at the time of writing.
Cross-repo (praxis-proxy) and Authorino citations are **unverified
here** — they point at external repositories.

### PPE (verified — this repo)

| Reference | Location |
|---|---|
| HTTP attributes (`http.method/path/host/scheme`, `request_headers.*`) | `crates/ppe-apl-cmf/src/http.rs` |
| Claim recursive walk | `crates/ppe-apl-cmf/src/security.rs:136-141` |
| JSON walker / claim flattening (null-skip, scalar-array → StringSet, nested-array drop, dotted-key join) | `crates/ppe-apl-cmf/src/payload.rs:50-110` |
| Client claim walk | `crates/ppe-apl-cmf/src/security.rs:209` |
| Custom namespace walk | `crates/ppe-apl-cmf/src/custom.rs:19-21` |
| Claim-mapper presets | `crates/builtins/src/plugins/identity_jwt/presets.rs:22-28` + `presets/{standard,keycloak,auth0,cognito}.json` |
| CEL activation (flat bag → nested tree) | `crates/builtins/src/pdps/cel/activation.rs` |
| `IdentityScheme::ApiKey` (variant) | `crates/ppe-core/src/identity/payload.rs:91` |
| API-key identity plugin (directory lookup + `record_map` projection) | `crates/builtins/src/plugins/identity_api_key/` |
| Global authz without authentication (`authentication: Option`) | `crates/ppe-core/src/config.rs:237` |

### Authorino / Kuadrant (unverified — external)

- RFC 0002 well-known attributes: https://docs.kuadrant.io/1.0.x/architecture/rfcs/0002-well-known-attributes/
  — attribute enumeration (49 total: request 16, source/destination/connection
  24, metadata/filter_state 2, auth 5, ratelimit 2) verified against this page.
- `GetAuthorizationJSON()` — `pkg/service/auth_pipeline.go`
- `AuthJsonToCel()` — `pkg/expressions/cel/expressions.go`
- OPA input passing — `pkg/evaluators/authorization/opa.go`
- Identity extended properties — `pkg/evaluators/identity.go` (`ResolveExtendedProperties`)
- Metadata evaluators — `pkg/evaluators/metadata/{generic_http,user_info,uma}.go`

### Praxis proxy (unverified — external repo)

- HTTP attribute population — `filter.rs` (`attach_http_attributes`)
- Filter context (`client_addr`, `downstream_tls`, `peer_identity`) — `context.rs` (`HttpFilterContext`)
- `custom.*` injection example — `filter.rs` (`attach_llm_attributes`)
