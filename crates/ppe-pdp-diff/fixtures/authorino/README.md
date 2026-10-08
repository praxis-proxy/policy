<!--
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Praxis Contributors
-->

# Authorino reference fixtures (Tier 1)

The current `request.id` fixture is a synthetic mapping contract test for
issue #156. Its `authorino.decision` is a source-derived expectation, not an
observed result. Passing the in-process tests does not establish live parity.
Captured Authorino values and decisions are still required for that claim.

Authorino copies ext_authz `HttpRequest.Id`; Envoy sets that field from its
stream ID. The fixture's `request.id` represents host-owned metadata and its
`headers.x-request-id` deliberately differs. PPE must use the metadata value.

## Schema

```json
{
  "attribute": "request.id",
  "status": "Mapped",                     // Mapped | Gap
  "request": { "method": "...", "path": "...", "id": "...", "headers": {} },
  "predicate_cel": "request.id == \"req-abc\"",
  "predicate_opa": "package t\nallow if { input.request.id == \"req-abc\" }\n",
  "authorino": { "decision": "allow", "reference": "..." },
  "expected": "allow"                     // the decision PPE must produce
}
```

Both `authorino.decision` and `expected` are `allow` or `deny`. Divergence is
**derived** (`expected != authorino.decision`), never a sentinel:

- **Mapped** rows: `expected == authorino.decision` — the mapping agrees with
  the fixture expectation; observed parity requires an actual reference capture.
- **Gap** rows: `expected != authorino.decision` — PPE diverges (for the
  fail-open direction: Authorino `deny`, PPE `allow`).

The current fixture is not captured from the dual-gateway spike. Its
`authorino.reference` records this limitation. A future capture must record the
Authorino and Envoy versions, input metadata, actual authorization attributes,
and observed decision. Tests continue to exercise the synthetic expectation
while capture is pending.

## Scope so far

Vertical slice: `request.id` only. Remaining request-line / header / derived
attributes land as further fixtures.
