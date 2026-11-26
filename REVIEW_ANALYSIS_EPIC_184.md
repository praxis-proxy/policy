# Review Analysis: Fred (araujof) & Tery (terylt) Feedback on Epic #184

**Epic**: HTTP External Metadata Policy Information Point  
**Issue**: #184  
**Date Analyzed**: 2026-11-26  
**Analysis Source**: Epic issue body review expectations section

---

## Executive Summary

Fred and Tery have **explicit, documented review expectations** for the HTTP metadata epic that form **hard constraints** on the implementation, not optional guidance. These are enforced as both architecture requirements and regression-test requirements.

| Reviewer | Focus Area | Key Constraint |
|----------|-----------|-----------------|
| **Fred (araujof)** | Metadata framework | Immutability + provenance |
| **Tery (terylt)** | HTTP transport seam | Host injection + runtime agnostic |

---

## Fred's Review Expectations (araujof)

### Statement
> "Frederico Araujo: preserve immutable framework-owned metadata and provenance; ordinary plugin configuration must not gain a path to forge, replace, or directly mutate acquired metadata; existing evaluator callers must retain their metadata visibility."

### Core Requirements

#### 1. **Immutable Framework-Owned Metadata** (Critical)
- **What**: The `AcquiredFacts` metadata extension must be **immutable once installed**
- **Why**: Prevents plugins from tampering with fetched enrichment data after the framework has validated and blessed it
- **How to verify**:
  - `metadata.*` namespace is `Immutable` in extension definition
  - No plugin code can mutate the acquired facts after framework installation
  - Runtime checks prevent write access via plugin configuration

#### 2. **Prevent Plugin Forgery** (Critical)
- **What**: Plugin configuration alone must **never** create a path to forge, replace, or mutate acquired metadata
- **Why**: A malicious/buggy plugin config must not be able to inject fake metadata facts
- **How to verify**:
  - Plugin config has NO direct write access to `metadata.*` namespace
  - Framework alone controls the installation of facts from plugin-returned data
  - Config cannot specify pre-populated metadata values
  - Config cannot override or shadow existing metadata

#### 3. **Separation of Concerns** (Critical)
- **What**: Clear boundary between:
  - **Plugin responsibility**: Build and return raw `AcquiredFacts` from HTTP response
  - **Framework responsibility**: Validate, stamp provenance, install immutably, project into bag
- **Why**: Makes attack surface clear and audit trail unambiguous
- **How to verify**:
  - Plugin returns `MetadataFetchResult` struct, not modified payload
  - Framework (not plugin) calls `.install_acquired_facts(facts, instance_name)`
  - Framework (not plugin) emits the audit event with provenance
  - Framework (not plugin) adds the `read_metadata` capability requirement

#### 4. **Existing Evaluator Visibility** (Critical)
- **What**: Existing APL/CEL/OPA/Cedar code that reads `metadata.*` must continue to work without modification
- **Why**: Backwards compatibility with existing policies that consume metadata
- **How to verify**:
  - `metadata.<name>.*` attributes project into every evaluator's AttributeBag
  - Existing predicates like `metadata.account.active` continue to work
  - Assertions reading `metadata.*` are not broken by the framework change
  - Regression tests verify end-to-end: fetch → install → consume in same invocation

#### 5. **Provenance Tracking** (Important)
- **What**: Metadata must carry provenance information (source, timestamp, TTL, cache status)
- **Why**: Audit trail and trust reasoning require knowing where the data came from
- **How to verify**:
  - `AcquiredFacts` struct includes source instance name
  - Audit events log the fetch outcome and cache status
  - Tracing spans identify whether the data came from cache or network
  - Framework stamps the metadata with framework-issued timestamp

### Implementation Impact

**On request.rs / response.rs**:
- Plugin builds request and parses response independently ✅
- Plugin **does not** write to metadata extension ✅

**On handler.rs**:
- Handler returns `PluginResult::modify_payload()` with acquired facts ✅
- Handler **does not** directly mutate metadata extension ✅

**On framework code** (beyond this plugin):
- Framework owns the immutability guarantee
- Framework owns the installation and provenance stamping
- Framework's `install_acquired_facts()` is the single entry point

### Test Checklist (Fred's Concerns)

- [ ] Immutability: Create a test that attempts to mutate `metadata.*` and verify it fails
- [ ] Forgery prevention: Config with fake metadata values is rejected at load time
- [ ] Separation of concerns: Plugin returns facts, framework installs them (not vice versa)
- [ ] Evaluator visibility: Multiple evaluators (APL, CEL, OPA, Cedar) all read the same `metadata.<name>.*`
- [ ] Provenance: Audit events include source, cache status, and timestamp
- [ ] Regression: Existing metadata consumers in assertions and predicates still work

---

## Tery's Review Expectations (terylt)

### Statement
> "Terylt: keep transport host-injected and runtime-agnostic, with no Pingora dependency in this policy crate; use deterministic fake transports for request, timeout, error, and retry tests instead of socket timing."

### Core Requirements

#### 1. **Host-Injected Transport** (Critical)
- **What**: The HTTP transport must be **provided by the host**, not created/owned by the plugin
- **Why**: Allows the host to implement transport pooling, TLS trust, certificate management, egress policy, and observability once for the whole process
- **How to verify**:
  - Plugin calls `extensions.http_request(req, retry_policy)` (host services)
  - Plugin does NOT create `HyperTransport`, TCP socket, or TLS config
  - Plugin does NOT own certificate validation logic
  - Plugin does NOT implement connection pooling

#### 2. **Runtime Agnostic** (Critical)
- **What**: The plugin must work with **any HTTP transport**, not just Pingora/Hyper
- **Why**: PPE might run in Envoy, bare-metal, or other runtimes with different transport stacks
- **How to verify**:
  - No imports from `pingora::*`, `hyper::*`, or runtime-specific crates in metadata HTTP plugin
  - Plugin code works with trait-based `HttpTransport` from `ppe-core`
  - Plugin makes no assumptions about the underlying implementation
  - Core HTTP types are used (`HttpRequest`, `HttpResponse`, `HttpTransportError`)

#### 3. **No Pingora Dependency** (Critical)
- **What**: The `policy` crate must **not depend on Pingora**
- **Why**: Keeps policy logic portable and runtime-independent; Pingora is a Praxis implementation detail
- **How to verify**:
  - `Cargo.toml` has no `pingora` dependency
  - `Cargo.lock` does not add Pingora transitively through policy crates
  - No `#[cfg(feature = "pingora")]` or Pingora feature flags
  - CI enforces this: `cargo deny` or `cargo tree` audit

#### 4. **Deterministic Fake Transports for Testing** (Important)
- **What**: Tests must use `FakeTransport` with **predetermined responses**, not real sockets
- **Why**: Avoids timing-dependent failures, flakiness, and test infrastructure dependencies
- **How to verify**:
  - All timeout tests use `FakeTransport::fail(...)` or response queues
  - No `.with_latency(Duration)` for latency simulation in critical tests
  - Backoff/retry logic tested with queue progression, not actual delays
  - No `tokio::time::sleep` in test assertions
  - No real DNS lookups or TCP connections in unit tests

#### 5. **Deterministic Retry/Timeout Testing** (Important)
- **What**: Retry and timeout behavior tested with **fake transport state**, not elapsed time
- **Why**: Prevents flaky tests that depend on scheduler behavior or system load
- **How to verify**:
  - `FakeTransport` queues multiple responses: fail once, then succeed
  - Retry policy verified by call count, not by timing assertions
  - Timeout validation through `FakeTransport::fail(HttpTransportError::Timeout)`
  - No assertions like `assert!(elapsed > timeout)` in tests

#### 6. **Request/Response/Error Test Coverage** (Important)
- **What**: Tests cover the **deterministic paths**:
  - Request building (URL, headers, body encoding)
  - Successful responses (various status codes, body sizes)
  - Error scenarios (timeout, connect failure, oversized response)
  - Retry scenarios (GET vs POST policy, backoff)
- **Why**: Builds confidence in plugin behavior without infrastructure dependency
- **How to verify**:
  - Each `FakeTransport` test has a clear scenario (success/fail/timeout/oversized)
  - No "real server" tests in unit suite (integration tests are separate)
  - Error paths tested with `HttpTransportError::*` variants
  - Retry tests verify policy selection by call count

### Implementation Impact

**On handler.rs**:
- Uses `extensions.http_request()` to call transport ✅
- Never creates HTTP client internally ✅
- Works with any `HttpTransport` implementation ✅

**On request.rs**:
- No transport creation ✅
- No TLS configuration ✅
- No certificate validation ✅

**On testing**:
- `crates/builtins/tests/metadata_http/main.rs` uses `FakeTransport` ✅
- No `tokio::time::sleep` in test assertions ✅
- Retry tests verify by call count ✅
- Timeout tests use `HttpTransportError::Timeout` ✅

**On dependencies**:
- `crates/builtins/Cargo.toml` must NOT add Pingora
- `crates/ppe/Cargo.toml` isolation is maintained
- No transitive Pingora through metadata-http feature

### Test Checklist (Tery's Concerns)

- [ ] Host injection: Plugin never creates or owns the transport
- [ ] Runtime agnostic: No Pingora imports in metadata HTTP plugin
- [ ] Pingora dependency: `cargo tree` shows no Pingora in policy crate
- [ ] Fake transports: All timeout/error tests use `FakeTransport`
- [ ] Deterministic: No `tokio::time::sleep` in test assertions
- [ ] Retry testing: Call count verifies retry behavior, not elapsed time
- [ ] Error scenarios: Each `HttpTransportError` variant has a test
- [ ] Request paths: Request building tested without real sockets

---

## Implementation Checklist: Both Reviewers

### Fred's Requirements
- [ ] Framework owns metadata immutability (not checked in this plugin PR)
- [ ] Plugin cannot forge/replace metadata via config
- [ ] Clear separation: plugin returns facts, framework installs
- [ ] Existing evaluator visibility maintained (regression test)
- [ ] Provenance tracking in audit events
- [ ] Immutability enforced at runtime

### Tery's Requirements
- [ ] Transport is host-injected via `extensions.http_request()`
- [ ] No Pingora imports in metadata HTTP crate
- [ ] No new Pingora dependency in `policy` crate
- [ ] All timeout tests use `FakeTransport`
- [ ] Retry tests verify by call count
- [ ] No timing-dependent assertions
- [ ] Request/response/error paths covered deterministically

### Shared Responsibility
- [ ] Both concerns are **hard constraints** (architecture + regression tests)
- [ ] Code review must verify both seams independently
- [ ] CI must enforce no-Pingora dependency
- [ ] Test suite exercises both perspectives

---

## Critical Junctions Where Their Concerns Intersect

### 1. **Metadata Extension Definition**
- **Fred**: Extension must be `Immutable` to prevent plugin tampering
- **Tery**: N/A (transport layer, not relevant here)
- **Action**: Verify `metadata.*` has correct `Immutable` flag in extension definition

### 2. **HTTP Transport Usage**
- **Fred**: N/A (framework concern, not plugin)
- **Tery**: Plugin uses `extensions.http_request()`, never owns transport
- **Action**: Code review: `handler.rs` must ONLY call `extensions.http_request()`

### 3. **Testing Strategy**
- **Fred**: Regression tests prove existing evaluator code still works
- **Tery**: All tests use `FakeTransport`, no real sockets or timing
- **Action**: Test suite must be both comprehensive (Fred) and deterministic (Tery)

### 4. **Audit Trail**
- **Fred**: Plugin fetch audited with source/status/cache info
- **Tery**: Audit events are deterministic, testable via `FakeTransport`
- **Action**: Audit observer in tests validates event shape and content

---

## Review Gate Criteria

This implementation is **ready for Fred and Tery's review** when:

### Fred's Gate
✅ Metadata extension is framework-owned (confirmed in design doc)  
✅ Plugin returns facts, framework installs immutably (code review)  
✅ Config cannot forge metadata (load-time validation test)  
✅ Existing metadata consumers work unchanged (regression test)  
✅ Audit events include provenance (tracing/audit test)  

### Tery's Gate
✅ All HTTP calls go through `extensions.http_request()` (code review)  
✅ No Pingora imports in metadata HTTP plugin crate (lint/audit)  
✅ No new Pingora dependency added (Cargo.toml audit + CI)  
✅ All timeout/error tests use `FakeTransport` (test review)  
✅ Retry logic verified by call count, not timing (test review)  

---

## References

- **Epic**: https://github.com/praxis-proxy/policy/issues/184
- **Design Proposal**: #215 / #216 (HTTP external-metadata design)
- **Metadata Extension**: #230 (immutable acquired-metadata extension)
- **Hook Dispatch**: #240 (typed `metadata.fetch` hook dispatch)
- **Framework Publication**: Framework code (not in this plugin's scope)
- **HTTP Transport**: `crates/ppe-core/src/http.rs` (host services)

---

**Analysis Type**: Explicit documented review expectations from epic issue  
**Enforcement Level**: Hard constraints (architecture + regression tests)  
**Review Owners**: Fred (araujof) & Tery (terylt)  
**Integration Date**: For PR review of metadata/http implementation
