# Kuadrant → PPE Compatibility Layer

Design document for mapping Kuadrant/Authorino capabilities to the Praxis Policy Engine (PPE), covering attribute remapping, host requirements, identity/metadata compatibility issues, and the CEL/OPA test matrix.

**Context:** Authorino evaluates authorization policies against an attribute bag built from Envoy's CheckRequest + synthesized auth phases. PPE evaluates against its own attribute bag populated by the Praxis host. For existing Kuadrant CEL/OPA policies to work unmodified on PPE, the attribute paths must resolve to the same values.

**Sources:** Authorino source (`pkg/service/auth_pipeline.go`, `pkg/evaluators/`, `pkg/expressions/`), PPE source (`ppe-apl-cmf/src/`, `builtins/plugins/identity-jwt/`, `builtins/pdps/cel/`), Kuadrant RFC 0002.

---

## 1. Compatibility Plugin Remapping Table

A PPE compatibility plugin would inject Kuadrant-vocabulary aliases into the evaluation context alongside PPE-native attributes. Existing CEL/OPA policies reference the Kuadrant paths; new PPE-native policies use PPE paths. Both resolve to the same values.

### Request Attributes

| PPE Source | Kuadrant Alias (plugin injects) | Type | Complexity |
|---|---|---|---|
| `http.method` | `request.method` | String | Direct rename |
| `http.path` | `request.path` | String | Direct rename |
| `http.path` | `request.url_path` | String | Direct rename (Authorino separates path/url_path; PPE does not) |
| `http.host` | `request.host` | String | Direct rename |
| `http.scheme` | `request.scheme` | String | Direct rename |
| `http.request_headers.*` | `request.headers` | Map\<String, String\> | Shape change: PPE has flat `http.request_headers.x-foo`, Kuadrant has `request.headers["x-foo"]` as map access. Plugin must present a map object for OPA (`input.request.headers["x-foo"]`) and CEL (`request.headers["x-foo"]`). |
| `request.request_id` | `request.id` | String | Path rename |
| `request.timestamp` | `request.time` | Timestamp | Path rename; check type compatibility (PPE string vs Authorino protobuf Timestamp) |

### Identity Attributes

| PPE Source | Kuadrant Alias (plugin injects) | Type | Complexity |
|---|---|---|---|
| `claim.*` (recursive) | `auth.identity.*` | Any | Recursive walk: `claim.sub` → `auth.identity.sub`, `claim.realm_access.roles` → `auth.identity.realm_access.roles`. PPE's `claim.*` already surfaces all JWT claims via recursive walk — the plugin reverses the path. |
| `subject.id` | `auth.identity.sub` | String | Also available via `claim.sub` |
| `role.*` / `perm.*` / `team.*` | No alias needed | Boolean | PPE-native. Kuadrant policies don't reference these — they use array membership (`'x' in auth.identity.roles`) which the transpiler remaps to `has(role.x) && role.x`. With the compatibility plugin, the original Kuadrant form works directly because `auth.identity.roles` resolves to the claim array. |

### OPA Input Prefix

Authorino passes the full authorization JSON as `rego.EvalInput`, so Rego policies use `input.request.method`, `input.auth.identity.sub`, etc. The compatibility plugin must wrap the aliased attributes under an `input` root for OPA evaluation.

| PPE Source | OPA Input Path | Notes |
|---|---|---|
| `http.method` | `input.request.method` | |
| `http.path` | `input.request.path` | |
| `http.host` | `input.request.host` | |
| `http.request_headers.*` | `input.request.headers` (map) | |
| `claim.*` | `input.auth.identity.*` | Recursive |
| (see Host-Required) | `input.source.address` | Needs Praxis host |
| (see Host-Required) | `input.source.port` | Needs Praxis host |

### Deprecated Paths

Authorino's CEL evaluator does NOT support the deprecated `context.*` paths (only OPA/GJSON do). The plugin should inject these for OPA compatibility only.

| PPE Source | Deprecated Alias (OPA only) | Notes |
|---|---|---|
| `http.method` | `input.context.request.http.method` | OPA/GJSON legacy path |
| `http.path` | `input.context.request.http.path` | OPA/GJSON legacy path |
| `http.host` | `input.context.request.http.host` | OPA/GJSON legacy path |
| `http.request_headers.*` | `input.context.request.http.headers` | OPA/GJSON legacy path |

---

## 2. Host-Required Attributes (Praxis Must Provide)

These attributes cannot be faked by a PPE plugin — the data originates at the proxy/listener level. Praxis must populate them into PPE's extensions or the `custom.*` namespace.

| Kuadrant Attribute | Type | Why Host Must Provide | Praxis Has It? | PPE Models It? | Blocked By |
|---|---|---|---|---|---|
| `source.address` | String | Client IP — only the proxy/listener knows | Yes (`HttpFilterContext.client_addr: Option<IpAddr>`) | No field in `HttpExtension` | Praxis doesn't pass it; inject via `custom.*` or extend `HttpExtension` |
| `source.port` | Number | Client port | Not surfaced | No | Both |
| `request.query` | String | Query string — proxy parses the URL | Yes (`req.uri.query()` available) but `attach_http_attributes` only passes `uri.path()` which excludes query | No field in `HttpExtension` | Praxis doesn't pass it; add field or inject via `custom.*` |
| `request.body` | JSONString | Request body — proxy must buffer and forward | Yes (buffered for entity routes: MCP/LLM) | Yes for entity routes (`args.*`); No for pure L7 HTTP policy | Neither for entity routes; both for pure HTTP |
| `request.raw_body` | Bytes | Raw request body | Same as body | No | Both for pure HTTP |
| `request.protocol` | String | HTTP version (1.0, 1.1, 2, 3) | Available in Pingora session, not surfaced to `HttpFilterContext` | No field | Both |
| `request.size` | Number | Request size in bytes | Not surfaced | No | Both |
| `request.referer` | String | Accessible via request headers | Yes (`http.request_headers.referer`) | Yes (via headers) | Neither |
| `request.useragent` | String | Accessible via request headers | Yes (`http.request_headers.user-agent`) | Yes (via headers) | Neither |
| `connection.mtls` | Boolean | TLS state at the listener | Yes (`HttpFilterContext.downstream_tls: bool`) | No (PPE models mTLS as `caller_workload.attestor`) | Praxis doesn't pass it to PPE |
| `connection.tls_version` | String | TLS version | Not surfaced | No | Both |
| `connection.requested_server_name` | String | SNI | Not surfaced | No | Both |
| `source.principal` | String | mTLS client identity | Yes (`HttpFilterContext.peer_identity: Option<Arc<TlsPeerIdentity>>` — client cert subject, SPIFFE ID) | Yes (model: `caller_workload.spiffe_id`) | Praxis doesn't populate `WorkloadIdentity` from `peer_identity` |
| `source.certificate` | String | Raw client X.509 PEM | Partial (peer identity available, raw cert not surfaced) | No | Both |
| `destination.address` | String | Upstream address | Not surfaced to filter context | No | Both |
| `destination.port` | Number | Upstream port | Not surfaced to filter context | No | Both |

### Quick Wins (Praxis-only changes, no PPE modification)

The fastest path to Kuadrant compatibility is modifying `PolicyFilter::attach_http_attributes` (`filter.rs:1297-1320`) to inject additional data from the filter context into `custom.*`:

| Data | Source in Praxis | Inject as |
|---|---|---|
| Client IP | `ctx.client_addr` | `custom.source.address` |
| TLS state | `ctx.downstream_tls` | `custom.connection.tls` (bool) |
| mTLS peer identity | `ctx.peer_identity.spiffe_id` | Populate `WorkloadIdentity` on `SecurityExtension` |
| Query string | `req.uri.query()` | `custom.request.query` |

This requires no PPE changes — `custom.*` is already available to CEL/OPA evaluators. The compatibility plugin then aliases `custom.source.address` → `source.address` in the evaluation context.

### `custom.*` Injection Mechanism

Two ways to inject custom attributes:
1. **Policy filter code:** Modify `attach_http_attributes` in Praxis. Code-only, no YAML config. Example from existing code (`filter.rs:948-962` — LLM params injected as `custom.llm.*`).
2. **Host plugin:** Register a plugin that runs before authorization and populates `ext.custom` with arbitrary `serde_json::Value` entries.

**There is no YAML config for injecting custom attributes.** Both paths require code changes in Praxis.

---

## 3. Identity and Metadata Compatibility Issues

### 3.1 `auth.identity.*` — Extended Properties

**Problem:** Authorino supports `defaults` and `overrides` on identity evaluators (`ResolveExtendedProperties()` in `pkg/evaluators/identity.go:180-206`). These can:
- Inject new fields into the identity object (e.g. add `username` from `auth.identity.preferred_username`)
- Override existing claim values (e.g. force `roles` from a metadata response)
- Reference the full authorization JSON — including `request.*` and `auth.metadata.*`

PPE's claim mapper presets are static JSON mappings. They cannot:
- Inject fields computed from request context
- Override claims based on external data
- Reference anything outside the JWT payload

**Impact:** Any AuthConfig that uses identity `defaults`/`overrides` will produce a different `auth.identity` shape in PPE. OPA/CEL policies referencing the injected fields will fail at runtime.

**Possible solutions:**
- PPE could support a post-authentication hook that runs CEL expressions to enrich the identity
- The compatibility plugin could accept a static mapping config that injects additional claim paths
- Document as an unsupported capability and require users to refactor policies

### 3.2 `auth.identity.*` — Non-JWT Identity Shapes

**Problem:** `auth.identity` is not always a JWT payload:

| Auth Method | Identity Object | Authorino Source |
|---|---|---|
| JWT | Full decoded JWT payload (all claims) | `identity/jwt.go:41-65` |
| API Key | Full `k8s.Secret` object (metadata, data, labels, annotations) | `identity/api_key.go` |
| Plain | Whatever the GJSON/CEL selector resolves to (arbitrary) | `identity/plain.go:20-27` |
| Anonymous | Empty/nil | |
| Kubernetes TokenReview | TokenReview status (username, groups, extras) | |

PPE currently only has `identity/jwt`. The `IdentityScheme::ApiKey` variant exists but no plugin implements it. Policies referencing `auth.identity.metadata.annotations.username` (API key convention) or `auth.identity.data.tier` (secret data) have no PPE equivalent.

**Impact:** API key policies that inspect the k8s.Secret shape cannot work on PPE without an `identity/apikey` plugin that produces a compatible object shape.

### 3.3 `auth.identity.*` — Multi-Auth Priority

Authorino supports multiple authentication rules with priority ordering. First success wins, no merge. PPE's `identity/jwt` plugin supports multiple trusted issuers but does not have a general multi-auth-method priority system (e.g. "try JWT first, fall back to API key").

**Impact:** Low for JWT-only policies (PPE handles multiple issuers). High for mixed-method policies (JWT + API key fallback).

### 3.4 `auth.metadata.*` — Pipeline Phase Gap

**Problem:** Authorino has a metadata phase between authentication and authorization that fetches external data:

| Source | What It Does | Authorino Code |
|---|---|---|
| GenericHTTP | HTTP GET/POST to external endpoint; response stored as parsed JSON or raw string | `metadata/generic_http.go` |
| UserInfo | OIDC UserInfo endpoint, fetched with the request's access token | `metadata/user_info.go` |
| UMA | User-Managed Access resource lookup by request path | `metadata/uma.go` |

Results are stored as `auth.metadata.<evaluator_name>` and accessible by all subsequent authorization evaluators.

**Key behaviours:**
- URL templates can reference `auth.identity.*` (e.g. `https://api.example.com/users/{auth.identity.sub}`)
- Priority-ordered with concurrent execution within groups
- Failed metadata does not block the pipeline — results simply missing
- Later evaluators (authorization, response) can reference metadata results

PPE has **no equivalent pipeline phase**. There is no mechanism to:
- Fetch external data between authentication and authorization
- Inject fetched data into the evaluation context
- Template URLs with identity claims

**Impact:** Any AuthConfig/OPA/CEL policy referencing `auth.metadata.*` will fail at runtime. This is not a remapping problem — the data does not exist.

**Possible solutions:**
- PPE plugin that supports pre-authorization HTTP callouts (new plugin hook, e.g. `metadata.resolve`)
- Praxis host fetches metadata before invoking PPE and injects via `custom.*`
- Document as unsupported and require policy refactoring to remove metadata dependencies

### 3.5 `auth.metadata.*` — Cross-Phase References in OPA/CEL

**Problem:** Authorino's authorization JSON is built incrementally. By the time an authorization evaluator runs, it sees:
- `auth.identity` — populated
- `auth.metadata` — populated (if metadata phase ran)
- `auth.authorization` — partially populated (only results from earlier priority groups)

OPA policies commonly combine these:
```rego
allow {
    input.auth.identity.email_verified == true
    input.auth.metadata["user-profile"].department == "engineering"
    input.request.method == "GET"
}
```

Even if PPE adds metadata support, the ordering semantics (priority groups, concurrent within group, sequential across groups) must match for policies that depend on metadata-from-metadata chains.

### 3.6 `auth.identity.*` — Variable Aliasing in CEL and OPA

**Problem:** Lexical string replacement of attribute paths fails when evaluators use variable binding:

**CEL:**
```cel
let req = request
req.headers["x-custom-header"] == "foo"
```

**Rego:**
```rego
req := input.request
allow { object.get(req.headers, "x-custom-header", "") == "foo" }
```

The compatibility plugin's approach (injecting `request.method` alongside `http.method`) solves this for both languages — the original paths exist in the evaluation context, so aliases/variables resolve correctly regardless of how the policy is written.

**This is a key advantage of the compatibility-shim approach over AST rewriting.** No parsing needed, no edge cases around variable binding, destructuring, or comprehensions.

---

## 4. CEL and OPA Test Matrix

Test cases that prove compatibility between Authorino and PPE for the well-known attributes. Each test case defines:
- An AuthConfig (Authorino-native) and equivalent PPE policy
- A set of requests (method, path, headers, token) sent to both gateways
- Expected matching responses (status codes)

### 4.1 CEL Test Cases

#### Request Line Attributes

| ID | CEL Expression (Kuadrant) | Attributes Tested | Request | Expected |
|---|---|---|---|---|
| CEL-REQ-01 | `request.method == 'GET'` | `request.method` | `GET /api` | allow |
| CEL-REQ-02 | `request.method == 'GET'` | `request.method` | `POST /api` | deny |
| CEL-REQ-03 | `request.path.startsWith('/api')` | `request.path` | `GET /api/foo` | allow |
| CEL-REQ-04 | `request.path.startsWith('/api')` | `request.path` | `GET /public/foo` | deny |
| CEL-REQ-05 | `request.host == 'api.example.com'` | `request.host` | `Host: api.example.com` | allow |
| CEL-REQ-06 | `request.host == 'api.example.com'` | `request.host` | `Host: other.com` | deny |
| CEL-REQ-07 | `request.scheme == 'https'` | `request.scheme` | HTTPS request | allow (if host provides) |
| CEL-REQ-08 | `request.method == 'GET' && request.path.startsWith('/api') && request.host == 'api.example.com'` | Multiple request attrs | `GET /api/foo Host: api.example.com` | allow |

#### Header Attributes

| ID | CEL Expression (Kuadrant) | Attributes Tested | Request | Expected |
|---|---|---|---|---|
| CEL-HDR-01 | `request.headers['x-custom-header'] == 'foo'` | `request.headers` (bracket, single-quote) | `X-Custom-Header: foo` | allow |
| CEL-HDR-02 | `request.headers["x-custom-header"] == 'foo'` | `request.headers` (bracket, double-quote) | `X-Custom-Header: foo` | allow |
| CEL-HDR-03 | `request.headers.x_custom_header == 'foo'` | `request.headers` (dot access) | `X-Custom-Header: foo` | allow |
| CEL-HDR-04 | `request.headers['x-custom-header'] == 'foo'` | `request.headers` (missing header) | (no header) | deny |
| CEL-HDR-05 | `'x-custom-header' in request.headers` | `request.headers` (presence check) | `X-Custom-Header: any` | allow |
| CEL-HDR-06 | `request.headers['x-env'] == 'prod' && request.method == 'POST'` | Headers + request line | `X-Env: prod POST /api` | allow |

#### Identity Attributes (JWT Claims)

| ID | CEL Expression (Kuadrant) | Attributes Tested | Token Claims | Expected |
|---|---|---|---|---|
| CEL-ID-01 | `auth.identity.email_verified == true` | Top-level boolean claim | `{email_verified: true}` | allow |
| CEL-ID-02 | `auth.identity.email_verified == true` | Top-level boolean claim | `{email_verified: false}` | deny |
| CEL-ID-03 | `auth.identity.sub == 'user-123'` | Top-level string claim | `{sub: "user-123"}` | allow |
| CEL-ID-04 | `auth.identity.preferred_username == 'alice'` | Arbitrary top-level claim | `{preferred_username: "alice"}` | allow |
| CEL-ID-05 | `'admin' in auth.identity.roles` | Array membership (top-level) | `{roles: ["admin", "user"]}` | allow |
| CEL-ID-06 | `'admin' in auth.identity.roles` | Array membership (top-level) | `{roles: ["user"]}` | deny |
| CEL-ID-07 | `'admin' in auth.identity.realm_access.roles` | Nested claim array membership | `{realm_access: {roles: ["admin"]}}` | allow |
| CEL-ID-08 | `'admin' in auth.identity.realm_access.roles` | Nested claim array membership | `{realm_access: {roles: ["user"]}}` | deny |
| CEL-ID-09 | `auth.identity.resource_access.my_client.roles.exists(r, r == 'editor')` | Deep nested claim with CEL macro | `{resource_access: {my_client: {roles: ["editor"]}}}` | allow |
| CEL-ID-10 | `auth.identity.email_verified && auth.identity.sub != '' && 'user' in auth.identity.roles` | Multiple claims combined | `{email_verified: true, sub: "u1", roles: ["user"]}` | allow |

#### Mixed Namespace Expressions

| ID | CEL Expression (Kuadrant) | Attributes Tested | Request + Token | Expected |
|---|---|---|---|---|
| CEL-MIX-01 | `request.method == 'POST' && 'admin' in auth.identity.roles` | Request + identity | `POST` + `{roles: ["admin"]}` | allow |
| CEL-MIX-02 | `request.method == 'POST' && 'admin' in auth.identity.roles` | Request + identity | `GET` + `{roles: ["admin"]}` | deny |
| CEL-MIX-03 | `request.method == 'POST' && 'admin' in auth.identity.roles` | Request + identity | `POST` + `{roles: ["user"]}` | deny |
| CEL-MIX-04 | `request.headers['x-tenant'] == auth.identity.tenant_id` | Header matched against claim | `X-Tenant: t1` + `{tenant_id: "t1"}` | allow |
| CEL-MIX-05 | `request.headers['x-tenant'] == auth.identity.tenant_id` | Header matched against claim | `X-Tenant: t2` + `{tenant_id: "t1"}` | deny |
| CEL-MIX-06 | `request.path.startsWith('/api') && auth.identity.email_verified && request.headers['x-env'] == 'prod'` | All three namespaces | `GET /api/x X-Env: prod` + `{email_verified: true}` | allow |

#### Source/Connection Attributes (Gap Validation)

| ID | CEL Expression (Kuadrant) | Attributes Tested | Expected PPE Behaviour |
|---|---|---|---|
| CEL-GAP-01 | `source.address == '10.0.0.1'` | `source.address` | Fails unless host provides; confirms gap or shim |
| CEL-GAP-02 | `request.query.contains('debug=true')` | `request.query` | Fails unless host provides |

#### Deprecated Path (CEL should NOT support)

| ID | CEL Expression (Kuadrant) | Notes | Expected |
|---|---|---|---|
| CEL-DEP-01 | `context.request.http.method == 'GET'` | Authorino CEL does NOT support `context.*` | Should fail in both Authorino CEL and PPE |

### 4.2 OPA (Rego) Test Cases

#### Request Line Attributes

| ID | Rego Policy | Attributes Tested | Request | Expected |
|---|---|---|---|---|
| OPA-REQ-01 | `allow if { input.request.method == "GET" }` | `input.request.method` | `GET /api` | allow |
| OPA-REQ-02 | `allow if { input.request.method == "GET" }` | `input.request.method` | `POST /api` | deny |
| OPA-REQ-03 | `allow if { startswith(input.request.path, "/api") }` | `input.request.path` | `GET /api/foo` | allow |
| OPA-REQ-04 | `allow if { input.request.host == "api.example.com" }` | `input.request.host` | `Host: api.example.com` | allow |
| OPA-REQ-05 | `allow if { input.request.method == "GET"; startswith(input.request.path, "/api") }` | Multiple request attrs | `GET /api/foo` | allow |

#### Header Attributes

| ID | Rego Policy | Attributes Tested | Request | Expected |
|---|---|---|---|---|
| OPA-HDR-01 | `allow if { input.request.headers["x-custom-header"] == "foo" }` | Header map access | `X-Custom-Header: foo` | allow |
| OPA-HDR-02 | `allow if { object.get(input.request.headers, "x-custom-header", "") == "foo" }` | Header with default | `X-Custom-Header: foo` | allow |
| OPA-HDR-03 | `allow if { object.get(input.request.headers, "x-custom-header", "") == "foo" }` | Header with default (missing) | (no header) | deny |
| OPA-HDR-04 | `allow if { input.request.headers["x-env"] == "prod"; input.request.method == "POST" }` | Headers + request line | `X-Env: prod POST /api` | allow |

#### Identity Attributes

| ID | Rego Policy | Attributes Tested | Token Claims | Expected |
|---|---|---|---|---|
| OPA-ID-01 | `allow if { input.auth.identity.email_verified == true }` | Top-level boolean claim | `{email_verified: true}` | allow |
| OPA-ID-02 | `allow if { input.auth.identity.sub == "user-123" }` | Top-level string claim | `{sub: "user-123"}` | allow |
| OPA-ID-03 | `allow if { some role in input.auth.identity.roles; role == "admin" }` | Array iteration (v1 syntax) | `{roles: ["admin", "user"]}` | allow |
| OPA-ID-04 | `allow if { some role in input.auth.identity.realm_access.roles; role == "admin" }` | Nested claim array (v1) | `{realm_access: {roles: ["admin"]}}` | allow |
| OPA-ID-05 | `allow { input.auth.identity.roles[_] == "admin" }` | Array iteration (v0 syntax) | `{roles: ["admin", "user"]}` | allow |

#### Variable Aliasing (Critical Compatibility Test)

| ID | Rego Policy | What It Proves | Request | Expected |
|---|---|---|---|---|
| OPA-ALIAS-01 | `req := input.request; allow if { req.method == "GET" }` | Variable alias on request | `GET /api` | allow — proves shim works |
| OPA-ALIAS-02 | `req := input.request; allow if { req.headers["x-custom"] == "foo" }` | Variable alias on headers | `X-Custom: foo` | allow — proves shim works |
| OPA-ALIAS-03 | `id := input.auth.identity; allow if { id.email_verified == true }` | Variable alias on identity | `{email_verified: true}` | allow — proves shim works |
| OPA-ALIAS-04 | `auth := input.auth; allow if { auth.identity.roles[_] == "admin" }` | Variable alias on auth subtree | `{roles: ["admin"]}` | allow — proves shim works |
| OPA-ALIAS-05 | `req := input.request; hdrs := req.headers; allow if { hdrs["x-env"] == "prod" }` | Chained alias | `X-Env: prod` | allow — proves nested alias works |

#### Deprecated Path (OPA SHOULD support)

| ID | Rego Policy | Notes | Expected |
|---|---|---|---|
| OPA-DEP-01 | `allow if { input.context.request.http.method == "GET" }` | Authorino OPA supports `context.*` | allow in Authorino; PPE must decide whether to support |

#### Mixed Namespace Expressions

| ID | Rego Policy | Attributes Tested | Request + Token | Expected |
|---|---|---|---|---|
| OPA-MIX-01 | `allow if { input.request.method == "POST"; input.auth.identity.roles[_] == "admin" }` | Request + identity | `POST` + `{roles: ["admin"]}` | allow |
| OPA-MIX-02 | `allow if { input.request.headers["x-tenant"] == input.auth.identity.tenant_id }` | Header matched against claim | `X-Tenant: t1` + `{tenant_id: "t1"}` | allow |

#### Source/Connection (Gap Validation)

| ID | Rego Policy | Attributes Tested | Expected PPE Behaviour |
|---|---|---|---|
| OPA-GAP-01 | `allow if { input.source.address == "10.0.0.1" }` | `source.address` | Fails unless host provides |
| OPA-GAP-02 | `allow if { input.connection.mtls == true }` | `connection.mtls` | Fails unless host provides |

#### Metadata (Gap Validation)

| ID | Rego Policy | Attributes Tested | Expected PPE Behaviour |
|---|---|---|---|
| OPA-META-01 | `allow if { input.auth.metadata["user-profile"].active == true }` | `auth.metadata` | Fails — no metadata phase in PPE |

### 4.3 Cross-Evaluator Consistency

Same authorization logic expressed in CEL and OPA, run against both gateways. Proves that attribute resolution is consistent across evaluators.

| ID | CEL | Rego | Request + Token | Expected |
|---|---|---|---|---|
| CROSS-01 | `request.method == 'GET' && 'admin' in auth.identity.roles` | `allow if { input.request.method == "GET"; input.auth.identity.roles[_] == "admin" }` | `GET` + `{roles: ["admin"]}` | allow on both |
| CROSS-02 | `request.method == 'GET' && 'admin' in auth.identity.roles` | `allow if { input.request.method == "GET"; input.auth.identity.roles[_] == "admin" }` | `POST` + `{roles: ["admin"]}` | deny on both |
| CROSS-03 | `request.headers['x-tenant'] == auth.identity.tenant_id` | `allow if { input.request.headers["x-tenant"] == input.auth.identity.tenant_id }` | `X-Tenant: t1` + `{tenant_id: "t1"}` | allow on both |
| CROSS-04 | `request.headers['x-tenant'] == auth.identity.tenant_id` | `allow if { input.request.headers["x-tenant"] == input.auth.identity.tenant_id }` | `X-Tenant: t2` + `{tenant_id: "t1"}` | deny on both |

### 4.4 Dual-Gateway E2E Structure

```
test-compat/
  setup/
    kind-setup.sh              # make local-setup for Kuadrant
    praxis-setup.sh            # Build + start Praxis with PPE
    keycloak-setup.sh          # Shared IdP (in-cluster, port-forwarded)
  policies/
    cel-req-01.authconfig.yaml # Authorino AuthConfig
    cel-req-01.ppe-policy.yaml # Equivalent PPE policy
    ...
  requests.yaml                # [{id, method, path, headers, token_persona, expected}]
  run-compat.sh                # Deploy policies, mint tokens, fire requests at both gateways, diff
```

Each test: deploy the AuthConfig to the Kind cluster, deploy the PPE policy to Praxis, fire the same requests at both gateways, assert matching status codes.

---

## 5. Open Questions

1. **Deprecated `context.*` in OPA:** Should PPE's compatibility plugin support this? Authorino OPA does, Authorino CEL does not. Supporting it broadens compatibility but perpetuates a deprecated path.

2. **`request.headers` shape:** Authorino presents headers as a map (`request.headers["name"]`). PPE has flat keys (`http.request_headers.name`). The compatibility plugin needs to present a map-like object for OPA and CEL map access. Is this feasible in PPE's CEL activation / OPA input builder? PPE's CEL activation splits the flat bag into a nested tree on first `.` (`builtins/pdps/cel/src/activation.rs`), so a `request.headers` map may need special handling.

3. **Extended properties on identity:** How important is this for real-world AuthConfig usage? If it's rare, document as unsupported. If common, PPE needs a post-auth enrichment hook.

4. **Metadata phase:** Is building a metadata-fetch plugin in scope for the compatibility layer, or is it explicitly out of scope?

5. **`request.body` for pure HTTP policy:** Praxis buffers the body for entity routes (MCP/LLM) but not for pure L7 HTTP authorization. Kuadrant policies that inspect `request.body` in CEL/OPA need body buffering enabled. Is this in scope, or are body-inspecting policies out of scope for the compatibility layer?

6. **Praxis code changes vs PPE code changes:** The quickest Kuadrant compatibility wins are in `PolicyFilter::attach_http_attributes` (Praxis-side, inject `client_addr`, `query`, `downstream_tls` into `custom.*`). These don't require PPE changes. Who owns these changes — the Praxis team or the PPE team?

---

## 6. References

Sources used to build this document. Verify claims against these locations.

### Kuadrant / Authorino

| Reference | Location | What it covers |
|---|---|---|
| RFC 0002 — Well-Known Attributes | https://docs.kuadrant.io/1.0.x/architecture/rfcs/0002-well-known-attributes/ | Canonical list of Kuadrant well-known attributes, types, and which components use them |
| Authorization JSON construction | `pkg/service/auth_pipeline.go:588-625` (`GetAuthorizationJSON()`) | How Authorino assembles the attribute bag from Envoy CheckRequest + auth phases |
| Well-known attribute structs | `pkg/service/well_known_attributes.go:29-40` | `WellKnownAttributes` struct: `request`, `source`, `destination`, `auth`, `metadata` |
| CEL attribute binding | `pkg/expressions/cel/expressions.go:141-160` (`AuthJsonToCel()`) | 5 protobuf.Struct bindings; no `context.*` in CEL |
| OPA input passing | `pkg/evaluators/authorization/opa.go:87-108` (`Call()`) | Full JSON as `rego.EvalInput`; single code path for v0 and v1 |
| OPA policy compilation | `pkg/evaluators/authorization/opa.go:149-184` (`precompilePolicy()`) | No Rego version-specific parsing options; v0/v1 is syntax only |
| JWT identity resolution | `pkg/evaluators/identity/jwt.go:41-65` | `idToken.Claims(&claims)` — full decoded JWT payload, no subset |
| Identity extended properties | `pkg/evaluators/identity.go:180-206` (`ResolveExtendedProperties()`) | `defaults` (set if absent) and `overrides` (always set) on identity |
| Multi-auth priority | `pkg/service/auth_pipeline.go:207-262` (`evaluateIdentityConfigs()`) | First-success wins, no merge; priority groups; concurrent within group |
| API key resolution | `pkg/evaluators/identity/api_key.go` | Secrets by label selector; identity = full `k8s.Secret` object |
| Plain auth | `pkg/evaluators/identity/plain.go:20-27` | Identity = whatever selector/expression resolves to |
| Metadata — GenericHTTP | `pkg/evaluators/metadata/generic_http.go:69-103` | HTTP callout; JSON parsed or raw string |
| Metadata — UserInfo | `pkg/evaluators/metadata/user_info.go` | OIDC UserInfo endpoint with access token |
| Metadata — UMA | `pkg/evaluators/metadata/uma.go` | UMA resource lookup by request path |
| Metadata structure | `pkg/service/auth_pipeline.go:595-599` | `auth.metadata.<evaluator_name>` = full evaluator result |
| Metadata ordering | `pkg/service/auth_pipeline.go:264-289` | Priority-grouped, concurrent within group, sequential across groups |
| Pattern matching (GJSON) | `pkg/evaluators/authorization/json.go` | Raw JSON string queried via `gjson.Get()` |

### Praxis Policy Engine (PPE)

| Reference | Location | What it covers |
|---|---|---|
| Attribute bag constants | `ppe-apl-cmf/src/constants.rs` | Namespace definitions |
| HTTP attributes | `ppe-apl-cmf/src/http.rs:34-55` | `http.method`, `http.path`, `http.host`, `http.scheme`, `http.request_headers.*` |
| Security / identity attributes | `ppe-apl-cmf/src/security.rs` | `subject.*`, `role.*`, `perm.*`, `team.*`, `claim.*`, `client.*`, `caller_workload.*` |
| Claim recursive walk | `ppe-apl-cmf/src/security.rs:128-133` | All JWT claims exposed via `claim.*` with dot-separated nested paths |
| Client claims | `ppe-apl-cmf/src/security.rs:173-196` | `client.role.*`, `client.perm.*`, `client.claim.*` |
| Claim mapper presets | `builtins/plugins/identity-jwt/src/presets.rs:24-27` | `standard`, `keycloak`, `auth0`, `cognito` JSON presets |
| Preset definitions | `builtins/plugins/identity-jwt/src/presets/{standard,keycloak,auth0,cognito}.json` | Claim-to-namespace field mappings per preset |
| CEL activation | `builtins/pdps/cel/src/activation.rs` | Flat bag split into nested tree on first `.` for CEL variables |
| `IdentityScheme::ApiKey` | `ppe-core/src/extensions/payload.rs:92` | Variant exists, no plugin implements it |
| Custom namespace | `ppe-apl-cmf/src/custom.rs:19` | Host-supplied custom extensions, recursively walked |
| Delegation attributes | `ppe-apl-cmf/src/delegation.rs:23-34` | `delegation.*` namespace |
| Agent/MCP/LLM attributes | `ppe-apl-cmf/src/agent.rs`, `mcp.rs`, `llm.rs` | PPE-specific namespaces with no Kuadrant equivalent |

### Praxis Proxy (Host Integration)

| Reference | Location | What it covers |
|---|---|---|
| Policy filter — HTTP attribute population | `praxis-proxy-filter-0.6.0/filter.rs:1297-1320` (`attach_http_attributes`) | What Praxis passes to PPE: method, path, host, scheme, request_headers only |
| Filter context — available data | `praxis-proxy-filter-0.6.0/context.rs:250-287` (`HttpFilterContext`) | `client_addr`, `downstream_tls`, `peer_identity` — available but not passed to PPE |
| Custom attribute injection | `praxis-proxy-filter-0.6.0/filter.rs:948-962` (`attach_llm_attributes`) | How `custom.*` values are injected (code-only, no YAML config) |
| Query string availability | `filter.rs:1313` | `req.uri.path()` excludes query; `req.uri.query()` exists but unused |
| Body handling — MCP | `filter.rs:1695` (`on_request_body`) | JSON-RPC body parsed for entity routes |
| Body handling — LLM | `filter.rs:1583` (`ParsedLlmRequest::parse`) | LLM body parsed for inference routes |

### Kuadrant Operator

| Reference | Location | What it covers |
|---|---|---|
| Kind cluster setup | `make/kind.mk`, `make/development-environments.mk` | `make local-setup` / `make local-cleanup` |
| Kind cluster config | `utils/kind-cluster.yaml` | Kind cluster spec |
| Gateway provider | `Makefile:254` | Default Istio; `GATEWAYAPI_PROVIDER=envoygateway` supported |
| AuthPolicy → AuthConfig mapping test | `tests/common/authpolicy/authpolicy_controller_test.go:252` | "Maps to all fields of the AuthConfig" |
| Integration tests | `tests/common/authpolicy/authpolicy_controller_test.go` | Controller-level (K8s resource assertions, not traffic-level) |

### Transpiler (This Repo)

| Reference | Location | What it covers |
|---|---|---|
| CEL namespace remapping | `src/authpolicy/cel.rs` | Lexical rewrite of Kuadrant → PPE CEL paths |
| Translation logic | `src/authpolicy/translate.rs` | Core transpiler; fail-closed enforcement |
| AuthPolicy model | `src/authpolicy/model.rs` | Serde model for supported AuthPolicy subset |
| Golden test corpus | `tests/fixtures/authpolicy/*.yaml` + `*.golden` | `jwt-rbac`, `jwt-cel-http`, `apikey-opa`, `gateway-defaults` |
| E2E harness | `e2e/run-demo.sh` | Keycloak + Praxis + echo backend; alice/bob persona tokens |
| Well-known attributes mapping | `well-known-attributes-mapping.md` | Full attribute-by-attribute mapping table (companion to this doc) |
