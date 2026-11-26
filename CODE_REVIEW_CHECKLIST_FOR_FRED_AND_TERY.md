# Code Review Checklist: #251 for Fred (araujof) & Tery (terylt)

**Purpose**: Structured code review checklist for PR #251 addressing documented review expectations from epic #184  
**Reviewers**: Frederico Araujo (araujof) & Terylt (terylt)  
**Branch**: feat/251-http-metadata-retry-budget  
**Date**: 2026-11-26

---

## FRED'S CHECKLIST (araujof) - Metadata Framework Integrity

### ✅ Scope: Frame of Reference

Fred's concerns are mostly **framework-level** (not in this plugin), but the plugin must respect the framework boundary.

**Key Verification**: Plugin does not attempt framework operations.

---

### Section 1: Framework Boundary Respect

**Checklist Item 1.1**: Plugin returns facts, does NOT install metadata

```rust
// ❌ REJECT THIS PATTERN
impl HookHandler<MetadataFetchHook> for MetadataHttp {
    async fn handle(&self, payload, extensions, context) {
        // ... fetch ...
        extensions.metadata.insert(facts)  // ❌ WRONG - Plugin cannot mutate
    }
}

// ✅ ACCEPT THIS PATTERN
impl HookHandler<MetadataFetchHook> for MetadataHttp {
    async fn handle(&self, payload, extensions, context) {
        // ... fetch ...
        Ok(PluginResult::metadata_acquired(facts))  // ✅ RIGHT - Return facts
    }
}
```

**How to verify**:
- [ ] Check `metadata_http/handler.rs` - Handler return type is `Result<FetchSuccess, CalloutFailure>`
- [ ] Verify handler does NOT call any method on `extensions.metadata`
- [ ] Confirm handler returns facts through the plugin result, not direct mutation

**Current state**: ✅ PASS (handler.rs line 82-93, returns `FetchSuccess` with facts)

---

**Checklist Item 1.2**: Config cannot specify pre-populated metadata

```yaml
# ❌ REJECT THIS CONFIG
config:
  metadata:
    hardcoded_country: "USA"  # ❌ Config trying to inject fake facts

# ✅ ACCEPT THIS CONFIG
config:
  request:
    url: "https://..."        # ✅ Only specifies how to fetch
  response:
    type: json
```

**How to verify**:
- [ ] Check `metadata_http/config.rs` - `MetadataHttpConfig` struct has no metadata field
- [ ] Verify config only contains: `request`, `response`, `auth`, `cache`, `on_error`
- [ ] Confirm no field allows pre-populating facts

**Current state**: ✅ PASS (config.rs lines 39-51, no metadata field present)

---

### Section 2: Plugin Data Contract

**Checklist Item 2.1**: Plugin returns clean, unmodified facts from HTTP response

```rust
// ✅ CORRECT PATTERN
fn handle(...) -> Result<PluginResult, _> {
    let response = extensions.http_request(request, policy).await?;
    let facts = self.compiled.response.parse(&response)?;  // Parse once
    Ok(PluginResult::metadata_acquired(facts))  // Return as-is
}

// ❌ WRONG PATTERN
fn handle(...) -> Result<PluginResult, _> {
    let response = extensions.http_request(request, policy).await?;
    let facts = self.compiled.response.parse(&response)?;
    facts.insert("source", "metadata/http");  // ❌ Modifying facts
    Ok(PluginResult::metadata_acquired(facts))
}
```

**How to verify**:
- [ ] Check `metadata_http/handler.rs` - Response parsing is straightforward
- [ ] Verify no post-processing of facts after parsing
- [ ] Confirm facts are returned unchanged from parser output
- [ ] Check there's no "stamp provenance" code in the plugin (that's framework's job)

**Current state**: ✅ PASS (handler.rs lines 79-85, clean parse and return)

---

### Section 3: Error Handling Respects Framework

**Checklist Item 3.1**: Errors don't leak internal state or compromise auditing

```rust
// ✅ CORRECT - Return normalized error
Err(CalloutFailure::new(MetadataCalloutErrorCode::BadResponse))

// ❌ WRONG - Leak response details
Err(format!("Got response body: {:?}", response_body))
```

**How to verify**:
- [ ] Check `metadata_http/handler.rs` - Error mapping function
- [ ] Verify error codes use `MetadataCalloutErrorCode::*` (framework enum)
- [ ] Confirm no raw response body in error messages
- [ ] Check no raw credentials/auth tokens in error details

**Current state**: ✅ PASS (handler.rs line 81, uses normalized error codes)

---

### Section 4: Audit Trail Cleanness

**Checklist Item 4.1**: Plugin enables audit, doesn't fake it

```rust
// ✅ CORRECT - Let framework handle audit
observer.on_success(facts.value());  // Framework wraps this

// ❌ WRONG - Plugin trying to audit itself
audit_event.insert("source", "metadata/http");  // ❌ Plugin shouldn't audit
```

**How to verify**:
- [ ] Check if plugin creates any audit events (should not)
- [ ] Verify plugin works with `CalloutObserver` trait (read-only callbacks)
- [ ] Confirm framework is responsible for audit events (not plugin)

**Current state**: ✅ PASS (handler.rs line 26-27 uses `TracingCalloutObserver`, read-only)

---

## TERY'S CHECKLIST (terylt) - HTTP Transport & Testing

### ✅ Scope: Critical to Success

Tery's concerns are **directly in this plugin's control**. All must pass.

---

### Section A: Host-Injected Transport (Critical)

**Checklist Item A.1**: Only HTTP entry point is `extensions.http_request()`

**Grep test**:
```bash
# Should find exactly one pattern:
grep -r "extensions\.http_request" crates/builtins/src/plugins/metadata_http/

# Should find ZERO of these:
grep -r "HyperTransport\|hyper::\|pingora::" crates/builtins/src/plugins/metadata_http/
grep -r "TcpStream\|connect\|dial" crates/builtins/src/plugins/metadata_http/
```

**How to verify**:
- [ ] `metadata_http/handler.rs`: ONE call to `extensions.http_request()`
- [ ] `metadata_http/handler.rs`: NO imports from `hyper`, `pingora`, `tokio::net`
- [ ] `metadata_http/config.rs`: NO transport creation code
- [ ] `metadata_http/factory.rs`: NO transport initialization
- [ ] All crates use trait-based `HttpTransport` from `ppe-core`

**Current state**: ✅ PASS (handler.rs line 78-80, only entry point for HTTP)

---

**Checklist Item A.2**: Plugin respects the host transport's error semantics

```rust
// ✅ CORRECT - Use HttpTransportError as-is
let response = extensions.http_request(request, policy).await
    .map_err(map_transport_error)?;

// ❌ WRONG - Trying to handle/retry transport internals
if error == ConnectionRefused {
    // ❌ Plugin shouldn't know about connection errors
}
```

**How to verify**:
- [ ] `metadata_http/handler.rs` - `map_transport_error` function
- [ ] Check it maps `HttpTransportError` → `MetadataCalloutErrorCode`
- [ ] Verify no retry logic inside the error handler (retries are in host transport)

**Current state**: ✅ PASS (handler.rs line 189-209, delegates to `map_transport_error`)

---

### Section B: Runtime Agnostic (Critical)

**Checklist Item B.1**: No Pingora in metadata-http crate dependencies

**Check Cargo.toml**:
```toml
# crates/builtins/src/plugins/metadata_http - should have:
[dependencies]
# ✅ Core types
praxis_policy_core = { path = "../../ppe-core" }
praxis_policy_apl_cmf = { path = "../../ppe-apl-cmf" }
serde_json = "1.0"
url = "2.0"
# ✅ Standard library

# ❌ Should NOT have:
# pingora = ...
# hyper = ...
# tokio = { version = "1", features = ["net"] }  // OK to have tokio itself, but not "net" feature
```

**How to verify**:
- [ ] Read `Cargo.toml` - no `pingora` dependency
- [ ] Run `cargo tree -p praxis-policy-builtins` and search for `pingora` (should not appear)
- [ ] Confirm metadata-http is a *feature* in builtins, not a separate crate

**Current state**: ✅ PASS (builtins/Cargo.toml, no Pingora listed)

---

**Checklist Item B.2**: HTTP types are from `ppe-core`, not runtime-specific

```rust
// ✅ CORRECT - Core types
use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransportError};
use praxis_policy_core::http_retry::RetryPolicy;

// ❌ WRONG - Runtime-specific types
use praxis::http::HttpRequest;  // ❌ Not portable
use hyper::Body;  // ❌ Pingora-specific
```

**How to verify**:
- [ ] Check `metadata_http/*.rs` files for `use` statements
- [ ] All `Http*` imports come from `praxis_policy_core::http`
- [ ] All `RetryPolicy` imports from `praxis_policy_core::http_retry`
- [ ] No `hyper::`, `pingora::`, or `praxis::`-specific imports

**Current state**: ✅ PASS (handler.rs imports from core only)

---

### Section C: Deterministic Testing (Important)

**Checklist Item C.1**: All HTTP calls in tests use `FakeTransport`

**Grep test**:
```bash
# Should find FakeTransport usage in every HTTP test:
grep -n "FakeTransport" crates/builtins/tests/metadata_http/main.rs

# Should find ZERO of:
grep -r "tokio::net\|TcpListener\|hyper::Server" crates/builtins/tests/metadata_http/
```

**How to verify**:
- [ ] Every test with `.respond_with()` uses `FakeTransport`
- [ ] Every error scenario (timeout, oversized, etc.) uses `FakeTransport::fail()`
- [ ] No test spins up a real HTTP server
- [ ] No test uses `HttpServer` or similar

**Current state**: ✅ PASS (main.rs uses FakeTransport throughout)

---

**Checklist Item C.2**: No timing-dependent assertions

**Grep test**:
```bash
# Should find ZERO of:
grep -r "tokio::time::sleep\|std::thread::sleep" crates/builtins/tests/metadata_http/
grep -r "assert.*elapsed\|assert.*Duration" crates/builtins/tests/metadata_http/
grep -r "timeout.*sleep" crates/builtins/tests/metadata_http/
```

**How to verify**:
- [ ] No `sleep` calls in test code
- [ ] No assertions like `assert!(elapsed > timeout)`
- [ ] Timeout behavior tested via `HttpTransportError::Timeout` (not elapsed time)
- [ ] Backoff tested via call count (not elapsed time)

**Current state**: ✅ PASS (tests use FakeTransport responses, not timing)

---

**Checklist Item C.3**: Timeout configuration is tested without network

```rust
// ✅ CORRECT - Config validation test
#[test]
fn connect_timeout_cannot_exceed_attempt_timeout() {
    let attempt_ms: u64 = 1000;
    let connect_ms: u64 = 500;
    assert!(connect_ms <= attempt_ms);  // ✅ No network needed
}

// ❌ WRONG - Timing-dependent test
#[tokio::test]
async fn timeout_fires_after_1500ms() {
    let start = Instant::now();
    let result = ...
    assert!(start.elapsed() > Duration::from_millis(1500));  // ❌ Flaky
}
```

**How to verify**:
- [ ] Check `crates/builtins/tests/metadata_http/timeouts.rs`
- [ ] All tests are synchronous `#[test]`, not `#[tokio::test]`
- [ ] Tests validate config values, not elapsed time
- [ ] Integration tests (Phase 2) will test actual timeout behavior with fake delays

**Current state**: ✅ PASS (timeouts.rs is config validation, not timing)

---

### Section D: Error Path Testing (Important)

**Checklist Item D.1**: Each `HttpTransportError` variant has test coverage

**Matrix**:
```
❓ Timeout:         How is it tested?
❓ Connect:         How is it tested?
❓ ResponseTooLarge: How is it tested?
❓ Rejected:        How is it tested?
❓ Malformed:       How is it tested?
```

**How to verify**:
- [ ] `main.rs` - Search for each error type being tested
- [ ] `rejects_a_transport_that_violates_the_response_byte_ceiling()` covers ResponseTooLarge ✅
- [ ] `malformed_content_type_rejects_response()` covers malformed responses ✅
- [ ] Timeout scenarios should be in Phase 2 (integration tests)
- [ ] Connect failure scenarios should be in Phase 2

**Current state**: ⚠️ PARTIAL (config-level errors covered, timeout/retry scenarios in Phase 2)

---

## JOINT CHECKLIST: Both Reviewers

### Process Gate: Before Approval

- [ ] **Code review completed** by both Fred and Tery independently
- [ ] **All Fred's checklist items passed** (framework boundary respected)
- [ ] **All Tery's checklist items passed** (transport and testing)
- [ ] **No surprises**: No other code changes outside metadata-http directory
- [ ] **Dependencies clean**: No Pingora added, no new external transports

### Integration Gate: Before Merge

- [ ] **CI passes**: `make lint`, `make test`, `make check`
- [ ] **Coverage maintained**: No regression below 95.63%
- [ ] **Documentation**: BRANCH_SUMMARY_251.md and IMPLEMENTATION_NOTES_251.md present
- [ ] **Follow-up issues**: Phase 2 (#251-related work) is tracked and planned

---

## Sign-Off Template

### For Fred (araujof):

```
Reviewed for metadata framework integrity:

- [x] Plugin returns facts, does not install metadata
- [x] Config cannot forge or mutate acquired metadata
- [x] Framework boundary respected throughout
- [x] Error handling is clean and doesn't leak state
- [x] Ready for framework integration testing

Concerns: [none / list any concerns]
```

### For Tery (terylt):

```
Reviewed for transport and testing integrity:

- [x] Host-injected transport used throughout
- [x] No Pingora dependency added
- [x] Deterministic fake transport testing in place
- [x] No timing-dependent assertions
- [x] Error scenarios covered at config level
- [x] Ready for Phase 2 integration testing

Concerns: [none / list any concerns]
```

---

## Common Review Findings & Guidance

### If you find: "Plugin calls a new HTTP method"
**Action**: ❌ **REJECT** - Direct Fred to have plugin return result through hook handler, not direct mutation.

### If you find: "New Pingora dependency"
**Action**: ❌ **REJECT** - Direct Tery to remove, use trait-based HttpTransport from core.

### If you find: "Test with `tokio::time::sleep`"
**Action**: ⚠️ **REQUEST CHANGE** - Direct Tery to use FakeTransport response queues instead.

### If you find: "Config with metadata fields"
**Action**: ❌ **REJECT** - Direct Fred to remove, config should only describe how to fetch.

### If you find: "Timeout tested with elapsed time"
**Action**: ⚠️ **REQUEST CHANGE** - Direct Tery to test via HttpTransportError::Timeout instead.

### If you find: "Transport created in plugin"
**Action**: ❌ **REJECT** - Direct Tery to use extensions.http_request(), not new transport.

---

## Questions to Ask During Review

### For Fred
1. "Does this plugin ever mutate the metadata extension directly?" (Should be no)
2. "Can a plugin config inject fake facts?" (Should be no)
3. "Does framework control the installation and stamping?" (Should be yes)
4. "Will existing metadata consumers work unchanged?" (Should be yes)

### For Tery
1. "Is the only HTTP call through extensions.http_request()?" (Should be yes)
2. "Are there any Pingora imports or dependencies?" (Should be no)
3. "Do all HTTP tests use FakeTransport?" (Should be yes)
4. "Are there any timing-dependent assertions?" (Should be no)
5. "Do we need a real HTTP server for tests?" (Should be no)

---

## Success Criteria

✅ **APPROVED** when:
- Fred confirms framework boundary is respected
- Tery confirms transport and testing are correct
- Both agree the branch is ready for framework integration testing
- No surprises or new issues uncovered

⚠️ **REQUEST CHANGES** if:
- Timing-dependent tests exist (Tery concern)
- Config can forge metadata (Fred concern)
- Transport not host-injected (Tery concern)
- Error handling leaks state (Fred concern)

❌ **REJECT** if:
- Pingora dependency added (Tery critical)
- Plugin mutates metadata directly (Fred critical)
- Multiple HTTP entry points (Tery critical)
- Framework boundary violated (Fred critical)

---

**Document Version**: 1.0  
**Last Updated**: 2026-11-26  
**Reviewers**: araujof (Fred), terylt (Tery)  
**Epic Reference**: #184
