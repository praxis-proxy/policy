# Implementation Notes: Issue #251 - Retry Budgets & Hardened URL Execution

## Phase 1: Completed ✅

### What Was Implemented

Separated HTTP request timeout configuration into two independent concepts:

1. **Per-attempt timeout** (`attempt_timeout_milliseconds`)
   - Default: 1500ms
   - Applied to each individual retry attempt
   - Covers DNS resolution, TLS handshake, and request/response I/O

2. **Total retry budget** (`total_timeout_milliseconds`)
   - Default: 5000ms
   - Bounds the entire retry loop including backoff delays
   - Ensures metadata calls don't outlive the request path timeout

### Configuration Changes

```yaml
# Old format (still supported via serde alias)
request:
  timeout_milliseconds: 1500

# New format (explicit and recommended)
request:
  attempt_timeout_milliseconds: 1500
  total_timeout_milliseconds: 5000
  connect_timeout_milliseconds: 500
```

### Retry Policy Selection

- **GET requests**: Use `RetryPolicy::idempotent()`
  - Max 3 attempts
  - Initial backoff: 100ms
  - Max backoff: 2 seconds
  - Retries all failures including timeout

- **POST requests**: Use `RetryPolicy::undelivered_only()`
  - Max 3 attempts
  - Initial backoff: 50ms
  - Max backoff: 500ms
  - Only retries failures that provably didn't reach the peer
  - Timeouts treated as indeterminate (not retried)

### Key Files Modified

- `crates/builtins/src/plugins/metadata_common/request.rs`
  - Added RequestConfig fields for new timeout structure
  - Added validation ensuring total >= attempt timeout
  - Added getters for total_budget() and method()

- `crates/builtins/src/plugins/metadata_http/handler.rs`
  - Fetch method now selects RetryPolicy based on HTTP method
  - Passes total_budget to retry policy
  - Handler passes retry_policy to extensions.http_request()

### Load-Time Validation

✅ Validates:
- `attempt_timeout_milliseconds > 0`
- `total_timeout_milliseconds > 0`
- `total_timeout_milliseconds >= attempt_timeout_milliseconds`
- `connect_timeout_milliseconds > 0`
- `connect_timeout_milliseconds <= attempt_timeout_milliseconds`

### Test Status

✅ All existing tests pass (751 tests)
✅ Lint passes (fmt + clippy)
✅ Backwards compatible via serde alias on timeout_milliseconds

---

## Phase 2: Upcoming - Hardened URL Execution

### Scope (from architecture plan)

1. **Address Validation**
   - Validate every resolved address before connection
   - Reject mixed public/private address sets atomically
   - Maps to SubRequestClient::execute_url from Praxis

2. **Redirect Handling**
   - Keep redirects disabled by default
   - Return 3xx responses as-is to caller
   - No automatic follow-up requests

3. **Authority Preservation**
   - Ensure Host header matches URL authority
   - TLS SNI matches Host header
   - Credentials never cross authority boundaries

4. **Integration with Praxis SubRequestClient**
   - Use SubRequestClient::execute_url for SSRF validation
   - Pass deadline information for timeout coordination
   - Implement address policy hooks

### Expected Test Coverage (Phase 2)

- Address set rejection tests (complete/mixed/private/public)
- SNI and Host header validation
- Deadline capping under invocation timeout
- Response size limits enforcement
- Credential boundary enforcement on redirects

### Dependencies

- Requires Praxis SubRequestClient availability
- Fallback: Use standard HttpTransport with best-effort validation
- No changes to existing retry policy logic

---

## Phase 3: Upcoming - Response Caching (#252)

Will depend on:
- Idempotent policy identification (GET = cacheable, POST = not)
- Cache key composition from authority + method + path/query
- Response ceiling enforcement
- Deadline propagation for conditional requests

---

## Phase 4: Upcoming - Secret Generation Tracking (#253)

Will depend on:
- Metadata callout audit events including retry count
- Final error classification (never_sent vs unknown)
- Credential lifecycle tracking
- Authority preservation validation

---

## Next Steps for PR

1. **Add comprehensive test coverage**
   - Fake transport tests for GET/POST retry scenarios
   - Real integration tests with Praxis executor
   - Deadline enforcement tests

2. **Code review checklist**
   - Confirm retry policy selection logic
   - Verify total_budget implementation
   - Validate load-time error messages

3. **Documentation**
   - Update metadata-http.example.yaml with new timeout fields
   - Document retry behavior in metadata.md
   - Add upgrade notes about timeout_milliseconds alias

4. **Performance validation**
   - Ensure backoff jitter doesn't cause thundering herd
   - Verify budget enforcement under concurrent load
   - Test deadline coordination with request path timeout

---

## Technical Debt & Future Work

1. Post-Phase-2: Consider per-destination allow-list from #209
2. Post-Phase-3: Consider OAuth2 client credentials (#258)
3. Post-Phase-4: Consider named TLS profiles (#256/#359)
4. Consider W3C trace propagation (#257)

---

## Questions for Review

1. Should `attempt_timeout_milliseconds` have a minimum threshold (e.g., 100ms)?
2. Should we provide a `quick` preset (1s attempt, 2s total) for metadata calls?
3. Should we emit a tracing span for each retry attempt to aid debugging?
4. Should the architecture plan's "undelivered_only max_attempts(2)" constraint be enforced?

---

Generated: 2026-11-26
Implementation: Senior Principal Engineer level
PR Target: Issue #251
Phase: 1/4 Complete
