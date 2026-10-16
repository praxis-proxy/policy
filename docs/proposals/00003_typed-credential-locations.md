# Plan: Typed Credential Locations for JWT Identity Plugin (Issue #64)

## Context

The JWT identity plugin (`builtins/plugins/identity-jwt/`) currently only extracts JWTs from HTTP headers. Issue #64 requests support for cookies and query parameters — one location per resolver instance. The old `header: "Authorization"` config field is removed; all configs must use the new `credential` block.

## Config Format Examples

### Header (default when `credential` is omitted)

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      credential:
        kind: header
        name: Authorization
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

### Cookie (e.g. browser app with HttpOnly cookie)

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      credential:
        kind: cookie
        name: __Host-jwt
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

### Query parameter (e.g. WebSocket/SSE that can't set headers)

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      credential:
        kind: query_param
        name: access_token
      trusted_issuers:
        - issuer: "https://idp.example.com"
          audiences: ["my-api"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/.well-known/jwks.json"
```

### Two resolvers: user JWT from header + workload SVID from header

```yaml
plugins:
  - name: user-jwt
    kind: identity/jwt
    config:
      role: user
      credential:
        kind: header
        name: Authorization
      trusted_issuers: [...]

  - name: workload-jwt
    kind: identity/jwt
    config:
      role: workload
      credential:
        kind: header
        name: X-Workload-Token
      trusted_issuers: [...]
```

---

## Phase 1: Core Types (`ppe-core`)

### 1a. `Credential` enum

Add to `crates/ppe-core/src/extensions/raw_credentials.rs`:

```rust
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credential {
    Header { name: String },
    Cookie { name: String },
    QueryParam { name: String },
}
```

Follows the `#[serde(tag = "kind")]` pattern used by `DecodingKeySource`. Add a `Display` impl for error messages (e.g. `header 'Authorization'`, `cookie 'session_token'`). Re-export from `extensions/mod.rs`.

**Why `ppe-core`, not the JWT plugin:** `Credential` describes *where* a credential was extracted from — a concern shared by every identity plugin, not just the JWT one. Placing it in `ppe-core` means the JWT plugin, a future X.509/mTLS plugin, a future WIMSE Proof Token plugin, or any custom identity resolver all record credential origin using the same type on `RawInboundToken.source`. Downstream consumers (audit logging, assertion propagation, policy predicates, the delegation layer) see a uniform `Credential` and can answer "where did this credential come from?" without plugin-specific logic. If the type lived inside the JWT plugin, each future plugin would need its own location type and every consumer would need to know about all of them.

### 1b. Replace `source_header` on `RawInboundToken`

Remove the `source_header: String` field and replace it with `source: Credential`. Update the constructor to `RawInboundToken::new(token, location, kind)`. All callers and test assertions that referenced `source_header` must migrate to `source`.

### 1c. Credential scrubbing on `RawInboundToken`

Replace the derived `Debug` impl on `RawInboundToken` with a hand-written one that redacts the token value. The `source` and `kind` fields are printed normally; the token is replaced with `<redacted>`:

```rust
impl fmt::Debug for RawInboundToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawInboundToken")
            .field("source", &self.source)
            .field("kind", &self.kind)
            .field("token", &"<redacted>")
            .finish()
    }
}
```

This ensures that `tracing::debug!(?raw_token)`, `format!("{:?}", raw_token)`, and error diagnostics never leak the bearer token. The `Display` impl (if any) must also omit the token value.

## Phase 2: Data Surface — PPE-Side Parsing

### Design decision: PPE parses, not the host

The issue requires cookie and query-string parsing to "handle encoding and duplicate names deterministically" and produce "consistent" results "across hosts." To satisfy this, PPE parses the raw `Cookie` header value and the raw query string internally. The host provides raw strings; PPE applies a single parser to every request regardless of which HTTP framework the host uses.

This avoids a class of bugs where different hosts (Envoy sidecar, Node gateway, Rust proxy) parse the same input differently — duplicate handling, whitespace tolerance, encoding — and the same JWT gets extracted or rejected depending on which host runs it.

### 2a. `raw_query_string` field on `IdentityPayload`

In `crates/ppe-core/src/identity/payload.rs`, add:

```rust
/// Raw query string from the request URL, without the leading `?`.
/// Set explicitly by the host; `None` otherwise. PPE parses this
/// deterministically — hosts must not pre-parse it.
///
/// Must not be derived from `HttpExtension.path`. The issue requires
/// "a request target supplied explicitly by the host" that does not
/// depend on whether `HttpExtension.path` includes a query string.
///
/// `#[serde(skip)]` — the query string may contain a bearer token
/// (e.g. `access_token=eyJ...`). Like `raw_token`, it must never
/// appear in serialized output, logs, or diagnostics.
#[serde(skip)]
raw_query_string: Option<String>,
```

Add a builder and getter following the existing pattern:

```rust
pub fn with_raw_query_string(mut self, qs: impl Into<String>) -> Self {
    self.raw_query_string = Some(qs.into());
    self
}

pub fn raw_query_string(&self) -> Option<&str> {
    self.raw_query_string.as_deref()
}
```

**Why `IdentityPayload`, not `HttpExtension`**: The issue explicitly states query extraction "must use a request target supplied explicitly by the host; it must not depend on whether `HttpExtension.path` happens to include a query string." Placing the query string on `IdentityPayload` keeps the identity resolver's input self-contained — it reads cookies from `payload.headers()` and the query string from `payload.raw_query_string()`, with no dependency on `Extensions` or `HttpExtension`.

### 2b. Cookie source: existing `Cookie` header in `payload.headers()`

Cookies arrive as a single `Cookie` HTTP header, which the host already provides in the `headers` map on `IdentityPayload`. The resolver reads `payload.headers()["cookie"]` (case-insensitive, matching the existing header lookup pattern) and parses the raw value. No new field is needed.

**Host contract for multiple `Cookie` headers**: HTTP/1.1 allows multiple `Cookie:` headers which MUST be combined with `; ` (RFC 6265 §5.4). The `IdentityPayload.headers` map stores one value per key. Hosts MUST combine multiple `Cookie` headers into one before populating the map. Most HTTP frameworks (hyper, Envoy, Express) do this automatically.

### 2c. Parsing module in `ppe-core`

**New file: `crates/ppe-core/src/http_credential.rs`**

Two pure functions and one error enum:

```rust
/// Reason a raw credential string was rejected during parsing.
pub enum CredentialParseError {
    /// The raw input exceeds the maximum allowed length.
    TooLong { location: &'static str, len: usize, max: usize },
    /// The raw input contains control characters (CR, LF, NUL).
    ControlCharacter { location: &'static str },
    /// A credential name appeared more than once.
    Duplicate { location: &'static str, name: String },
}

/// Parse a raw `Cookie` header value (RFC 6265 §4.2.1) into
/// name-value pairs. Rejects oversized input, control characters,
/// and duplicate names.
pub fn parse_cookie_header(
    raw: &str,
) -> Result<HashMap<String, String>, CredentialParseError>

/// Parse a raw query string (the part after `?`, without the `?`)
/// into name-value pairs. Rejects oversized input, control
/// characters, and duplicate names.
pub fn parse_query_string(
    raw: &str,
) -> Result<HashMap<String, String>, CredentialParseError>
```

Register the module in `crates/ppe-core/src/lib.rs` with `pub mod http_credential;`.

**Why `ppe-core`, not the JWT plugin**: Cookie and query-string parsing are generic HTTP operations. Future identity plugins (session-token, X.509 with query-transported fingerprints) will need the same parsers. Placing them in `ppe-core` avoids per-plugin duplication.

### 2d. Input validation (both parsers)

Both `parse_cookie_header()` and `parse_query_string()` apply two guards before parsing:

1. **Size limit.** Reject raw input longer than 8 KiB (`CredentialParseError::TooLong`). This prevents a malicious request with a multi-megabyte `Cookie` header or query string from allocating a large `HashMap` during parsing. 8 KiB aligns with common server defaults for cookie and query string limits (RFC 6265 §6.1 recommends at least 4096 bytes per cookie; most servers cap total header size at 8–16 KiB).

2. **Control character rejection.** Reject raw input containing `\r`, `\n`, or `\0` (`CredentialParseError::ControlCharacter`). This defends against header-smuggling attacks where an attacker injects a fake `Cookie` header via `\r\n` in a header value. Well-behaved HTTP parsers strip these, but PPE should not rely on every host's parser being correct — fail-closed is the safer default.

### 2e. Cookie parsing rules (RFC 6265 §4.2.1)

After input validation passes:

1. Split the raw `Cookie` header value on `; ` (semicolon + space). Also accept `;` without trailing space for tolerance.
2. For each pair, split on the first `=`. Left side = cookie name (trimmed of whitespace), right side = value.
3. No-value entries (a name with no `=` at all): included with an empty-string value. A JWT will never be a bare cookie name, so this is harmless tolerance.
4. Trim whitespace from names. Do not trim values — RFC 6265 does not define value trimming.
5. Duplicate name → `Err(CredentialParseError::Duplicate { location: "cookie", name })`.
6. **No percent-decoding.** RFC 6265 does not define percent-encoding for cookies, and JWT base64url never needs it.

### 2f. Query string parsing rules

After input validation passes:

1. Split the raw query string on `&`.
2. For each segment, split on the first `=`. Left = name, right = value.
3. No-value segments (no `=`) get empty-string value.
4. Duplicate name → `Err(CredentialParseError::Duplicate { location: "query_param", name })`.
5. **No percent-decoding.** JWT tokens are base64url and never percent-encoded. This avoids a new dependency on `percent-encoding` / `form_urlencoded` crates. If a future non-JWT plugin needs decoded values, the encoding contract can be revisited.

### 2g. No new crate dependencies

Both parsers are simple string splits (~20 lines each) plus the two validation guards. No `percent-encoding`, `form_urlencoded`, `cookie`, or `url` crate is needed.

## Phase 3: Plugin Config (breaking change)

### 3a. Config struct changes (breaking — no deprecation)

In `builtins/plugins/identity-jwt/src/config.rs`, remove the `header: String` field and `default_header()` entirely. Add:

```rust
#[serde(default)]
pub credential: Option<Credential>,
```

The old `header:` key is removed with no alias or deprecation period. All configs must migrate to the `credential` block before upgrading.

#### Migration error

Because the config struct uses `#[serde(deny_unknown_fields)]`, an old config containing `header:` will fail deserialization. To replace serde's generic "unknown field" message with an actionable one, add a custom `Deserialize` wrapper (or `deserialize_with`) that detects the `header` key and returns:

```text
"the 'header' field was removed; use 'credential: { kind: header, name: Authorization }' instead"
```

Implementation: a `#[serde(deserialize_with = "deserialize_config")]` function that first attempts normal deserialization, and on failure checks whether the raw map contains a `header` key. If so, it returns the migration error above instead of the generic serde message.

#### Migration guide (changelog entry)

```markdown
**Breaking:** The `header` field on `identity/jwt` config is removed.
Replace:
    header: "Authorization"
With:
    credential:
      kind: header
      name: Authorization
Omitting `credential` entirely still defaults to `Authorization` header.
```

### 3b. Constructor resolution

In `JwtIdentityResolver::new()`:
- `None` → default `Header { name: "Authorization" }`
- `Some(loc)` → use it

### 3c. Validation

- `Header { name }`: non-blank
- `Cookie { name }`: non-blank, no `=` or `;`
- `QueryParam { name }`: non-blank

## Phase 4: Extraction Logic

### 4a. Resolver field rename

In the `JwtIdentityResolver` struct, rename the stored field `header: String` to `credential: Credential`. The constructor populates this from the resolved config value (Phase 3b).

### 4b. Extract `extract_token()` helper

In `resolver.rs`, factor lines 670-697 (the header lookup, `Bearer` strip, `raw_token` fallback, and empty check inside `handle()`) into a method that branches on `self.credential`:

```rust
fn extract_token(
    &self,
    payload: &IdentityPayload,
) -> Result<String, PluginViolation>
```

The method takes only `payload` — all three credential sources (headers, `Cookie` header, raw query string) live on `IdentityPayload`. No dependency on `Extensions` or `HttpExtension`.

**`Credential::Header { name }`**: Existing logic — case-insensitive lookup in `payload.headers()`, `Bearer ` prefix strip, `raw_token()` fallback for single-resolver back-compat, empty check. Error code: `auth.malformed_header` (unchanged).

**`Credential::Cookie { name }`**:
1. Case-insensitive lookup for `"cookie"` in `payload.headers()`. If absent → deny `auth.missing_credential` with reason `"no Cookie header in request (resolver '<name>' expects cookie '<cookie_name>')"`.
2. Parse via `http_credential::parse_cookie_header()`. If `Err(DuplicateCredential)` → deny `auth.ambiguous_credential` with reason `"duplicate cookie name '<name>'"`.
3. Look up the configured cookie name in the parsed `HashMap`. If absent → deny `auth.missing_credential`. If empty → deny `auth.empty_credential`.
4. No fallback to `raw_token()`.

**`Credential::QueryParam { name }`**:
1. Read `payload.raw_query_string()`. If `None` → deny `auth.missing_credential` with reason `"no query string supplied by host (resolver '<name>' expects query_param '<param_name>')"`.
2. Parse via `http_credential::parse_query_string()`. If `Err(DuplicateCredential)` → deny `auth.ambiguous_credential` with reason `"duplicate query parameter name '<name>'"`.
3. Look up the configured param name in the parsed `HashMap`. If absent → deny `auth.missing_credential`. If empty → deny `auth.empty_credential`.
4. No fallback to `raw_token()` or `HttpExtension.path`.

### 4c. Credential scrubbing in error messages

All `PluginViolation` reason strings from `extract_token()` must include the credential location and configured name (e.g., `cookie '__Host-jwt'`, `query_param 'access_token'`) but never the credential *value*. This satisfies the issue's requirement: "without logging the credential."

### 4d. Update `RawInboundToken` construction

Change line 896 from `RawInboundToken::new(raw_token, self.header.clone(), kind)` to `RawInboundToken::new(raw_token, self.credential.clone(), kind)`.

### 4e. Security note: query parameter tokens in infrastructure logs

Query parameters routinely appear in HTTP access logs, CDN logs, and browser history. While PPE correctly redacts tokens in its own `Debug`/tracing output (Phase 1c), operators configuring `credential: { kind: query_param }` should be aware that `?access_token=...` may appear in infrastructure logs outside PPE's control. Consider adding a `tracing::info!` at resolver construction time when the credential kind is `query_param`:

```text
"resolver '<name>' configured for query_param credential — ensure infrastructure logs do not capture raw query strings"
```

## Phase 5: Tests

### Parsing unit tests (`http_credential.rs`)
- `parse_cookie_header`: single cookie, multiple cookies, trailing semicolon, no-value cookie (no `=`), whitespace tolerance, value containing `=` (base64), duplicate name → `DuplicateCredential` error, empty input → empty map
- `parse_query_string`: single param, multiple params, no-value param, value containing `=`, duplicate name → `DuplicateCredential` error, empty input → empty map

### Core type unit tests (`raw_credentials.rs`)
- `Credential` serde round-trips for all three variants
- `Credential` `Display` output: `header 'Authorization'`, `cookie '__Host-jwt'`, `query_param 'access_token'`
- `RawInboundToken` `Debug` output does not contain the token value

### Config unit tests (`config.rs`)
- `credential:` alone → deserializes, neither → default, blank name → error, misspelled key → rejected, old `header:` field → migration-specific error message

### Extraction tests (resolver.rs `#[cfg(test)]`)
- Header: existing tests, unchanged behavior
- Cookie: found, missing `Cookie` header, empty value, duplicate cookie name → deny `auth.ambiguous_credential`
- Query param: found, no `HttpExtension`, no `query_string`, empty value, duplicate param name → deny `auth.ambiguous_credential`
- Error messages never contain credential values (assert on `PluginViolation.reason`)

### E2E tests (tests/jwt_e2e.rs)
- `valid_jwt_from_cookie_resolves_subject`
- `valid_jwt_from_query_param_resolves_subject`
- `raw_inbound_token_records_cookie_origin`
- `raw_inbound_token_records_query_param_origin`

### Test helper changes (tests/common/mod.rs)

The existing `invoke()` helper (line 135) creates `IdentityPayload::new(token, source)` with no way to pass a `Cookie` header or query string. Add an `invoke_with_payload()` variant that takes a pre-built `IdentityPayload`, so cookie and query-param tests can populate the new fields via builders before driving through the pipeline.

```rust
pub(crate) async fn invoke_with_payload(
    cfg: PluginConfig,
    payload: IdentityPayload,
) -> PipelineResult {
    let resolver = JwtIdentityResolver::new(cfg.clone())
        .expect("the resolver must construct");

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::new(resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .expect("registration");
    mgr.initialize().await.expect("initialize");

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    result
}
```

Cookie e2e tests build a payload with the `Cookie` header:

```rust
let mut headers = HashMap::new();
headers.insert("cookie".to_owned(), format!("__Host-jwt={token}"));
let payload = IdentityPayload::new("", TokenSource::Bearer)
    .with_headers(headers);
let result = invoke_with_payload(cfg, payload).await;
```

Query-param e2e tests build a payload with the raw query string:

```rust
let payload = IdentityPayload::new("", TokenSource::Bearer)
    .with_raw_query_string(format!("access_token={token}"));
let result = invoke_with_payload(cfg, payload).await;
```

### Migration of existing tests

All existing tests that reference `header:` in config YAML or assert on `source_header` must be updated:
- Config YAML: replace `header: "Authorization"` with `credential: { kind: header, name: Authorization }` (or omit for the default)
- Assertions: replace `source_header` with `source` and compare against `Credential::Header { name }` instead of a string
- The existing `invoke()` helper is updated to use the new `RawInboundToken::new()` signature

## Dependencies

No new crate dependencies required. Cookie and query-string parsing are simple string splits (~20 lines each) implemented in `ppe-core::http_credential`. No `percent-encoding`, `form_urlencoded`, `cookie`, or `url` crate is needed. JWT tokens use base64url which never requires percent-decoding.

## Files to Modify

| File | Change |
|------|--------|
| `crates/ppe-core/src/extensions/raw_credentials.rs` | `Credential` enum, replace `source_header` with `source: Credential` on `RawInboundToken`, hand-written `Debug` |
| `crates/ppe-core/src/extensions/mod.rs` | Re-export `Credential` |
| `crates/ppe-core/src/identity/payload.rs` | Add `raw_query_string: Option<String>` field, builder, getter |
| `crates/ppe-core/src/http_credential.rs` | **New** — `parse_cookie_header()`, `parse_query_string()`, `DuplicateCredential` |
| `crates/ppe-core/src/lib.rs` | Register `pub mod http_credential` |
| `builtins/plugins/identity-jwt/src/config.rs` | Remove `header` field, add `credential: Option<Credential>`, migration error for old key |
| `builtins/plugins/identity-jwt/src/resolver.rs` | Rename `header` → `credential`, `extract_token()` with cookie/query branches, `RawInboundToken` construction, new tests |
| `builtins/plugins/identity-jwt/tests/jwt_e2e.rs` | E2E tests for cookie and query-param paths |
| `builtins/plugins/identity-jwt/tests/common/mod.rs` | `invoke_with_payload()` helper |

## Implementation Order

```text
Phase 1 (Credential enum + RawInboundToken)       ──┐
Phase 2a (IdentityPayload.raw_query_string)        ───┼── Config (Phase 3) → Resolver (Phase 4) → E2E tests
Phase 2c (http_credential parsing module)          ──┘
```

Phases 1, 2a, and 2c are independent and can proceed in parallel. Phase 3 depends on Phase 1 (needs the `Credential` type). Phase 4 depends on all prior phases.

## Verification

```console
make check          # type-check both feature sets
make test           # all workspace tests (two passes)
make lint           # fmt + clippy
cargo test -p praxis-policy-core --lib                  # core type + parsing tests
cargo test -p praxis-policy-plugin-identity-jwt --lib   # plugin unit tests
cargo test -p praxis-policy-plugin-identity-jwt         # plugin + e2e tests
```

## AIMS Gap Analysis: Token Delivery Mechanisms

The IETF AI Agent Authentication draft ([draft-klrc-aiagent-auth-00](https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-00.html)) Section 9 defines how agents present credentials on the wire. This section evaluates whether the three credential locations in this PR (header, cookie, query parameter) are sufficient, or whether AIMS suggests additional delivery mechanisms the `identity-jwt` plugin should support.

### Conclusion: No additional locations needed for `identity-jwt`

Header, cookie, and query parameter cover every HTTP transport where a bearer JWT arrives. AIMS does not suggest a fourth. The mapping by caller type:

| Caller type (per AIMS) | Authentication flow | Where the JWT arrives | Covered? |
|---|---|---|---|
| Human user via browser | OAuth authorization code → session cookie | Cookie (`__Host-jwt`) | Yes — this PR adds it |
| Human user via API client | OAuth authorization code → access token | `Authorization: Bearer` header | Yes — existing |
| Agent / service (autonomous) | Client credentials or JWT-SVID | `Authorization: Bearer` or custom header | Yes — existing |
| Agent via WebSocket/SSE | Can't set headers on upgrade handshake | Query parameter (`?access_token=`) | Yes — this PR adds it |
| Agent via mTLS | X.509 certificate in TLS handshake | `X-Forwarded-Client-Cert` header (not a JWT) | Out of scope — different credential format |
| Agent via WPT | WIMSE Proof Token bound to a WIT | `Workload-Proof-Token` header (not a standalone JWT) | Out of scope — different validation model |
| Agent via HTTP Message Signatures | RFC 9421 signature over the request | `Signature` / `Signature-Input` headers (not a token) | Out of scope — not a token at all |

### Why the last three don't belong in `identity-jwt`

The draft's Section 9 defines three authentication mechanisms beyond bearer JWTs. None are "JWTs arriving at a different location" — they are fundamentally different credential formats with different validation logic:

**mTLS / X.509-SVID (§9.1):** The credential is an X.509 certificate chain, not a JWT. Validation means ASN.1 parsing, CA trust bundle verification, and SPIFFE ID extraction from SAN URI extensions. None of the JWT plugin's code (JWKS fetching, `exp`/`nbf`/`aud` claim validation, claim mapping) applies.

**WIMSE Proof Tokens (§9.2.1):** A WPT *is* a JWT, but it cannot be validated with the JWT plugin's pipeline. A WPT proves possession of the private key matching a companion WIT's public key — not an IdP's JWKS endpoint. The plugin would need to verify the `wth` claim (hash binding to the WIT), enforce `jti` replay detection, and validate against the WIT's key rather than a configured issuer. Bolting this onto `identity-jwt` would mean special-casing every step of the validation pipeline.

**HTTP Message Signatures (§9.2.2):** Not a token at all. Verification means parsing RFC 9421 structured fields (`Signature`, `Signature-Input`), reconstructing the signature base from HTTP message components (method, request-target, content-digest), and verifying against a WIT's public key. There is no JWT decode step.

Each of these belongs in its own identity plugin (see Future Work below), not as additional `Credential` variants.

### What about RFC 6750 §2.2 (form-encoded body)?

RFC 6750 defines a third bearer token delivery method: `access_token` as a form-encoded POST body field. This is deprecated by OAuth 2.0 Security BCP (RFC 9700) and only works for `application/x-www-form-urlencoded` POST requests. Not worth supporting.

### How `Credential` in `ppe-core` helps close the AIMS gaps

By placing `Credential` in `ppe-core` rather than in the JWT plugin, future plugins for the three AIMS mechanisms above can record their credential origin using the same type:

- An `identity/x509` plugin records `Credential::Header { name: "X-Forwarded-Client-Cert" }`
- An `identity/wpt` plugin records `Credential::Header { name: "Workload-Proof-Token" }`
- An `identity/httpsig` plugin records `Credential::Header { name: "Signature" }`

Downstream consumers (audit, assertions, policy) see a uniform `Credential` regardless of which plugin produced it.

## Future Work: AIMS-Motivated Identity Plugins

The IETF AI Agent Authentication draft (draft-klrc-aiagent-auth-00) defines authentication mechanisms beyond bearer JWTs. The `Credential` enum introduced in this PR is designed to be reused by these future plugins — each would record its credential origin on `RawInboundToken.source` using the same type.

### `identity/x509` — mTLS / X.509-SVID (AIMS §9.1)

The draft's transport-layer authentication path. PPE already has `TokenSource::Mtls` and the `WorkloadIdentity` slot on `SecurityExtension`, but no builtin plugin processes X.509 certificate chains. A plugin would:

- Parse the `X-Forwarded-Client-Cert` header (Envoy/Istio XFCC format) or `X-Client-Cert` (RFC 9440)
- Decode the X.509 leaf certificate and chain
- Extract the SPIFFE ID from the SAN URI (`spiffe://<trust-domain>/<path>`)
- Validate the chain against a configured trust bundle (CA certs per trust domain)
- Check `notBefore` / `notAfter` expiry
- Populate `caller_workload` with `spiffe_id`, `trust_domain`, `attestor: "mtls"`, `attested_at`
- Record `Credential::Header { name: "X-Forwarded-Client-Cert" }` on the `RawInboundToken`

This is the most immediately relevant gap — it maps to deployed infrastructure (Istio, SPIRE, Envoy) that PPE's target audience already runs. Would compose naturally with the JWT plugin via the multi-resolver chain (`authentication: [user-jwt, x509-attestor]`): JWT resolves the user, X.509 resolves the workload, both land on the same `IdentityPayload`.

### `identity/wpt` — WIMSE Proof Tokens (AIMS §9.2.1)

The draft's primary application-layer proof-of-possession mechanism for workload authentication across proxies. A plugin would:

- Extract the `Workload-Proof-Token` header
- Verify the WPT JWT signature against the companion WIT's public key
- Validate the `wth` claim (hash of the WIT) binds the proof to the identity
- Check `aud`, `exp`, `jti` (with replay detection via `jti` uniqueness)
- Populate `caller_workload`
- Record `Credential::Header { name: "Workload-Proof-Token" }`

Lower priority — the WIMSE drafts are early (-00). The `jti` replay detection this would require is also a gap in the current JWT plugin (AIMS §9.2.3 MUST-level requirement).

### `identity/httpsig` — HTTP Message Signatures (AIMS §9.2.2)

The draft's strongest authentication mechanism, providing message integrity and identity via RFC 9421 signatures. A plugin would:

- Parse `Signature` and `Signature-Input` structured headers
- Verify the signature against the WIT's public key
- Validate mandatory signed components: method, request-target, content-digest, WIT
- Populate `caller_workload`

Lowest priority — most complex to implement and also depends on early WIMSE drafts. Would additionally require response signing support on the assertions layer for full coverage.
