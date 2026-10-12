---
date: 2026-10-07
topic: integration-test-suite
issue: https://github.com/praxis-proxy/policy/issues/99
---

# Integration test suite and hardening

## Summary

PPE gains top-level integration suites in the style of `../praxis`: a scenario suite that
ports the `praxis-demos` policy-engine flows across Cedar, CEL, and OPA, a hardening suite for
timeouts, load, and dependency failures, and a security suite for adversarial inputs. All run
hermetically on every PR, with an opt-in live mode against real services. Existing per-crate
e2e tests stay where they are; only cross-crate flow tests move.

---

## Problem Frame

The flows that matter most to adopters combine several features in one request: multi-token
identity, RFC 8693 delegation, APL gates, PDP decisions, on-the-wire redaction, PII scanning,
session taint, CIBA approval, and assertions. These are exercised today only by the twelve
scripted scenarios in `praxis-demos/demos/policy-engine`, which need praxis-ai, Keycloak, a
Python MCP server, docker-compose, and a manual `run-scenarios.sh --all-configs` run. A
regression in any of these flows can merge unnoticed and surface only when someone runs the
demo before a release.

The repo has about 83 integration-style test files, but they are organized by crate and each
exercises one crate's behavior. Cross-crate flows have no natural owner, so they are either
missing or scattered across `ppe-apl-runtime`, `ppe-core`, and the facade. There is no shared
test helper crate, so token minting, mock IdP endpoints, and fixture loading are duplicated.

Epic #99 also asks for hardening ahead of the next preview release. Nothing today
systematically checks how the engine behaves when an IdP, token endpoint, PDP, secret store, or
session store is slow, down, or misbehaving, or when inputs are hostile.

---

## Requirements

**Layout**

- R1. New integration suites live as top-level workspace members under `tests/`, following the
  `../praxis` pattern: one test binary per suite gathering its modules, plus a shared,
  unpublished test-utils crate.
- R2. Tests that exercise a single crate's behavior stay in that crate. Only tests that are
  really cross-crate flows are promoted into the new suites, and helpers duplicated across
  crates move into the shared test-utils crate.
- R3. Each suite has its own make target, named after the praxis equivalents, and the suites
  are included in what CI runs.

**Scenario suite**

- R4. Every scenario in `praxis-demos/demos/policy-engine/scenarios` (01 through 12) has an
  automated equivalent asserting the same observable outcome: allow, deny with the same
  violation, redacted field, minted token audience, taint propagation and isolation, approval
  pending then applied, and assertion results.
- R5. Each scenario runs against all three PDP configurations (Cedar, CEL, OPA), with the
  PDP-specific deny violation asserted per configuration.
- R6. Scenarios drive PPE at the boundary a host calls, using policy fixtures copied from the
  demo into this repo. No proxy process is involved.

**Fidelity**

- R7. By default the suites are hermetic: the IdP (JWKS, RFC 8693 token exchange, CIBA), the
  MCP upstream, and other external services are in-process mocks, so the suites need no
  network, containers, or credentials.
- R8. When the relevant environment variable is set, the same scenarios run against real
  services (Keycloak, Valkey, Vault, OPA), following the existing `VALKEY_TEST_URL` convention.
  Unset means the live variants skip, not fail.

**Hardening suite**

- R9. For each external dependency (IdP/JWKS, token endpoint, CIBA, PDP/OPA, Vault, Valkey),
  the suite covers: unavailable, slow beyond the configured timeout, returning errors, and
  returning malformed responses.
- R10. In every dependency-failure case the engine fails closed: it denies within a bounded
  time with an attributable reason, never hangs, and never allows.
- R11. Under many concurrent sessions and principals, decisions stay correct: no cross-session
  or cross-principal leakage of identity, taint, or delegated credentials, and latency stays
  bounded.

**Security suite**

- R12. Adversarial inputs are covered for at least: malformed, forged, expired, and
  algorithm-confused tokens; oversized and deeply nested payloads; header and encoding tricks
  that try to dodge a policy match (case, Unicode normalization, duplicate headers or keys);
  and delegation abuse such as confused-deputy and token-replay attempts.
- R13. Each adversarial case asserts a deny (or a rejection at parse time) and that the
  diagnostic does not leak secrets or payload values.

**Hardening follow-through**

- R14. A defect a suite exposes is filed as a sub-issue of #99 and fixed separately. Until it
  is fixed, its test is marked so the gap is visible without turning CI red.

---

## Acceptance Examples

- AE1. **Covers R4, R5.** With the CEL configuration, Eve's `get_compensation` call returns the
  record with the SSN removed, and Bob's identical call returns it intact with a token minted
  for the HR audience.
- AE2. **Covers R8.** With no live-service variable set, the live variants report as skipped
  and the suite passes. With `VALKEY_TEST_URL` set, the taint scenarios run against that
  server.
- AE3. **Covers R9, R10.** If the JWKS endpoint stops responding, a request carrying an
  otherwise valid JWT is denied within the configured timeout plus a small margin, with a
  reason naming identity resolution.
- AE4. **Covers R11.** If two principals run interleaved sessions concurrently and only one
  touches compensation data, only that session is blocked from external email.
- AE5. **Covers R12, R13.** If a JWT with `alg: none` or an HS/RS key-confusion signature is
  presented, it is rejected, and the diagnostic contains neither the token nor the key.

---

## Success Criteria

- Nobody needs to run the demo by hand to know the twelve flows still work. A PR that breaks
  one fails CI in this repo.
- The engine's fail-closed behavior under dependency failure is asserted for every bundled
  external integration, and any gap found is tracked under #99.
- Adding a new cross-crate scenario or adversarial case means adding one module to an existing
  suite, using shared helpers, with no new test binary.
- `ce-plan` can sequence the work into sub-issues without inventing scenario outcomes,
  failure modes, or the layout split.

---

## Scope Boundaries

- Running PPE embedded in a real praxis or praxis-ai proxy. Host wiring stays covered by
  `../praxis` (`tests/integration/tests/suite/examples/policy*.rs`).
- Moving existing per-crate e2e tests wholesale.
- Coverage-guided fuzzing (cargo-fuzz). A candidate later sub-issue.
- Throughput benchmarks and performance regression gates. Criterion benches already cover
  throughput.
- Changes to the `praxis-demos` repo or its scripts.
- Schema and conformance suites like praxis's. `ppe-apl-core/tests/conformance` already
  exists.

---

## Key Decisions

- **Hybrid layout over full migration.** Crate-owned tests stay put, so ownership stays clear
  and history is kept. Only flows with no owner move, which also fits the per-binary link cost.
- **Host boundary, not proxy.** Driving PPE at the host-call boundary keeps the suites in this
  repo and fast. The proxy's own wiring is already tested in praxis.
- **Copied fixtures.** Demo policies are copied, not referenced across repos. Drift from the
  demo is an accepted risk, and the copy becomes the source of truth for CI.
- **Fail closed is the contract.** The hardening suite asserts deny-with-reason within a bounded
  time. Any other behavior is a bug, not an accepted variant.
- **Load means correctness under concurrency.** Isolation and bounded latency, not throughput
  numbers.
- **Defects tracked, not blocking.** Exposed bugs become #99 sub-issues so the suite can land
  before every fix.
- **Live mode is non-blocking.** It runs as a separate CI job, so Keycloak and container
  flakiness cannot block PRs.

---

## Dependencies / Assumptions

- The twelve demo scenarios can all be expressed at the host-call boundary, including the
  CIBA pending-then-approved flow and the body rewrite. Unverified for scenario 11.
- The demo gateway registers the unpublished `reference/plugins` (pii-scanner, audit-logger),
  which the scenario suite needs too. Both are already workspace members.
- The demo targets praxis 0.6 and ppe 0.4.x. Fixtures may need adjusting to this repo's
  current APL and config shape.

---

## Outstanding Questions

### Deferred to Planning

- [Needs research] Which existing e2e tests are really cross-crate flows and should be
  promoted. Candidates: `canonical_authn_authz_e2e`, `elicit_then_delegate_e2e`,
  `delegation_e2e`, `end_to_end_route`.
- [Needs research] How the "known gap" marking in R14 should work given the two-pass test
  convention and the coverage gate.
- What timeout margins and concurrency levels the hardening suite should use so it stays
  deterministic on CI runners.
- Whether live OPA should run as a server or keep the in-process evaluator, and which live
  services get a CI job first.
- How the suites fit into the two test passes (default features vs `--all-features`) and the
  96% coverage gate.
