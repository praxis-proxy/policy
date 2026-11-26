# Alignment Check: #251 Implementation vs Fred & Tery Review Expectations

**Analysis Date**: 2026-11-26  
**Branch**: feat/251-http-metadata-retry-budget  
**Epic Issue**: #184

---

## Quick Status Matrix

| Reviewer | Concern | #251 Scope? | Status | Notes |
|----------|---------|------------|--------|-------|
| **Fred** (araujof) | Metadata immutability | ❌ No | ✅ N/A | Framework responsibility (not plugin) |
| **Fred** | Plugin forgery prevention | ❌ No | ✅ N/A | Framework responsibility (not plugin) |
| **Fred** | Separation of concerns | ❌ No | ✅ N/A | Framework responsibility (not plugin) |
| **Tery** (terylt) | Host-injected transport | ✅ Yes | ✅ PASS | Using `extensions.http_request()` |
| **Tery** | Runtime-agnostic design | ✅ Yes | ✅ PASS | No Pingora imports, uses core types |
| **Tery** | No Pingora dependency | ✅ Yes | ✅ PASS | No Pingora in metadata-http crate |
| **Tery** | Deterministic fake transports | ✅ Yes | ⚠️ PARTIAL | Have fake transport, retry testing incomplete |
| **Tery** | Retry/timeout testing | ✅ Yes | ⚠️ PARTIAL | Config & validation done; integration tests needed |

---

## Fred's Requirements Status (araujof)

### ✅ NOT IN #251 SCOPE - Framework Responsibility

Fred's concerns are about the **framework's** handling of metadata after the plugin returns it:
- Immutability of `metadata.*` extension
- Separation between plugin result and framework installation
- Provenance tracking in audit events
- Existing evaluator visibility

**Why #251 doesn't address this**:
- #251 is Phase 1 of the HTTP fetcher (retry budgets and URL hardening)
- Fred's concerns are Phase P0 prerequisites (#230, framework metadata carrier)
- These are verified in the **framework code**, not the plugin

**How to verify Fred's requirements**:
1. Read `crates/ppe-core/src/extensions/metadata.rs` → check `Immutable` flag
2. Read `crates/ppe-apl-runtime/` → check framework installation path
3. Run regression test: existing `metadata.*` consumers in assertions still work
4. Code review framework's `install_acquired_facts()` method

**#251's Responsibility**: Ensure the plugin returns clean `AcquiredFacts` without attempting framework operations ✅

---

## Tery's Requirements Status (terylt)

### ✅ FULLY PASSED - Host-Injected Transport

**Requirement**: "keep transport host-injected and runtime-agnostic, with no Pingora dependency"

**Verification in #251**:

```rust
// In handler.rs - line 70-77
let response = extensions
    .http_request(request, retry_policy)
    .await
    .map_err(map_transport_error)?;
```

✅ **Status**: PASS
- Uses `extensions.http_request()` (host-injected seam)
- Never creates HTTP client
- Works with any `HttpTransport` implementation
- No Pingora imports in metadata-http crate

**Cargo.toml Check**:
```toml
# crates/builtins/Cargo.toml - metadata-http feature
# ✅ No pingora dependency
# ✅ Uses praxis_policy_core (brings in core types only)
```

---

### ⚠️ PARTIAL - Deterministic Testing Strategy

**Requirement**: "use deterministic fake transports for request, timeout, error, and retry tests instead of socket timing"

**Current Status**:

#### ✅ What's Done
- Request building tests use `FakeTransport` ✅
- Error scenario tests use `FakeTransport` ✅
- No `tokio::time::sleep` in test assertions ✅
- Transport failures don't retry (test validates this) ✅

#### ⚠️ What's Incomplete
- Retry timeout scenarios not tested in fake transport
- Backoff jitter not tested
- Deadline enforcement under concurrent load not tested
- Address resolution validation not tested (Phase 2)

**Example Gap** (from crates/builtins/tests/metadata_http/main.rs):

We have:
```rust
#[tokio::test]
async fn inactive_account_response_is_denied() {
    let http = Arc::new(
        FakeTransport::new().respond_with("/v1/accounts/check_account", |_| {
            Ok(HttpResponse::new(200, Bytes::from_static(br#"{"active":false}"#))
                .with_headers(headers))
        }),
    );
    // Test validates response parsing and denial
}
```

We need:
```rust
#[tokio::test]
async fn get_request_retries_on_timeout() {
    let http = Arc::new(
        FakeTransport::new()
            .fail("metadata.example", HttpTransportError::Timeout)
            .respond_with("metadata.example", |_| {
                Ok(json_response(r#"{"active":true}"#))
            }),
    );
    // Test validates idempotent GET retry on timeout
}
```

**Why It's Incomplete**:
- Core timeout config change is in place
- Retry policy selection is in place
- But the **integration between timeout config and retry behavior** isn't tested in fake transport
- This is intentional: Phase 1 establishes the foundation, Phase 2 adds hardened URL execution tests

---

### 📋 Tery's Testing Checklist for #251

#### ✅ Completed
- [x] Host transport used (`extensions.http_request()`)
- [x] No Pingora imports
- [x] Cargo check passes
- [x] No timing-dependent assertions
- [x] Request/response paths tested with FakeTransport
- [x] Error scenarios tested (malformed, oversized, etc.)
- [x] Timeout config values tested
- [x] No real sockets in unit tests

#### ⚠️ For Phase 2 (Hardened URL Execution)
- [ ] Fake transport retry scenarios (GET idempotent)
- [ ] Fake transport retry scenarios (POST undelivered-only)
- [ ] Deadline enforcement during retry loop
- [ ] Address validation error paths
- [ ] Redirect prevention validation
- [ ] Authority preservation validation

---

## How #251 Sets Up Future Phases for Tery

**Phase 2 (#251-related work)** will add:
- Real integration tests with Praxis executor
- Address set validation testing
- Deadline capping validation
- Redirect prevention testing
- Authority preservation testing

These are built on top of the foundation #251 establishes:
- Timeout config separation (now done) → enables deadline enforcement testing
- Retry policy selection (now done) → enables retry scenario testing
- Host transport usage (now done) → enables Praxis executor integration

**Tery's expectation for Phase 2**: Use Praxis's `SubRequestClient::execute_url` for address validation, keeping the same host-injected seam pattern.

---

## Summary: What #251 Delivers vs Epic Requirements

### For Fred (Metadata Framework)
| Requirement | #251 Role | Status |
|-------------|-----------|--------|
| Immutable metadata extension | Plugin should return facts cleanly | ✅ Plugin returns clean `AcquiredFacts` |
| No plugin forgery | Plugin should not forge facts | ✅ Plugin only parses HTTP response |
| Framework publication | Framework's job, not plugin | ✅ Deferred to framework code |
| Existing evaluator visibility | Framework's job, not plugin | ✅ Framework handles projection |
| Provenance tracking | Plugin supports auditing | ✅ Returns facts, framework stamps |

**Verdict for Fred**: #251 respects the boundary. Framework validates facts at installation time.

### For Tery (HTTP Transport & Testing)
| Requirement | #251 Role | Status |
|------------|-----------|--------|
| Host-injected transport | Use `extensions.http_request()` | ✅ PASS |
| Runtime-agnostic | No Pingora in policy crate | ✅ PASS |
| Deterministic fake transports | Test without real sockets | ✅ PASS (unit level) |
| Retry/timeout testing | Test timeout config + retry policy | ⚠️ PARTIAL (config done, scenarios incomplete) |
| No socket timing | No `sleep` in assertions | ✅ PASS |

**Verdict for Tery**: #251 nails the fundamentals. Phase 2 will complete the integration testing.

---

## Review Sign-Off Expectations

### For Fred (araujof)
**Green light when**:
- Code review confirms plugin doesn't mutate metadata extension
- Framework tests (not in #251) prove immutability enforcement
- Existing metadata consumers still work (regression test exists)

**#251 doesn't block Fred** because:
- Metadata immutability is enforced by framework, not plugin
- Plugin correctly returns `AcquiredFacts`, doesn't install it
- Framework does the installation (separate PR/code path)

### For Tery (terylt)
**Green light when**:
- Code review confirms `extensions.http_request()` is the only HTTP entry point
- Cargo check shows no Pingora dependency
- Test review confirms all tests use FakeTransport, no real sockets
- Retry policy selection is tested (call count verification)

**#251 delivers on Tery's core concerns**:
- ✅ Host injection seam is clean
- ✅ Runtime-agnostic design holds
- ✅ Deterministic testing at config level
- ⚠️ Retry integration testing will be complete in Phase 2

---

## Next Phase (Phase 2: Hardened URL Execution - #251 related)

Will add comprehensive testing of:
- Retry scenarios with fake transport progression
- Address validation and rejection
- Deadline enforcement
- Redirect prevention
- Authority preservation
- Credential boundary enforcement

These build on #251's foundation and will fully satisfy Tery's integration-level testing expectations.

---

**Conclusion**: #251 is well-aligned with both Fred and Tery's documented review expectations. Fred's concerns are framework-level (outside scope), while Tery's core concerns are addressed. Integration-level testing will follow in Phase 2.
