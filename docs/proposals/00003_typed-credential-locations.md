---
issue: https://github.com/praxis-proxy/policy/issues/64
discussion: >-
  Issue #64 records the requirements and discussion for this proposal.
repos:
  - policy
status: proposed
authors:
  - monshri
graduation_criteria:
  - Existing header configurations retain a documented migration path.
  - Cookie and query credentials have deterministic extraction and deny codes.
  - Tests cover each location without exposing credential values.
stakeholders: []
---

# Typed credential locations for JWT identity

## Context

The JWT identity resolver originally read a configured HTTP header. Browser
and WebSocket clients may instead present a JWT in a cookie or query
parameter. Each resolver still reads exactly one location, so deployments
with separate user and workload tokens configure separate instances.

## Configuration

The `credential:` block selects a `header`, `cookie`, or `query_param` and
names the value to read. Omitting both `credential:` and the legacy `header:`
setting selects the `Authorization` header.

<!-- validate: fragment -->
```yaml
credential:
  kind: cookie
  name: __Host-jwt
```

The legacy `header: X-User-Token` setting remains accepted and logs a
migration warning when the resolver is built. Its typed equivalent is:

<!-- validate: fragment -->
```yaml
credential:
  kind: header
  name: X-User-Token
```

Setting both fields on one resolver fails configuration loading. An issuer
with DPoP enabled requires a header credential and the `read_headers`
capability. The [configuration guide] has complete examples.

[configuration guide]: ../content/configuration.md#credential-location

## Request inputs

The host supplies headers on `IdentityPayload` and the raw query string in
`HttpExtension.query`. A query credential needs the `read_query` capability;
`read_headers` alone does not expose the query. Query extraction does not
infer parameters from `HttpExtension.path`.

PPE parses cookie and query inputs rather than relying on host framework
parsers. Inputs over 16 KiB or containing ASCII controls other than HTAB
are rejected.
Duplicate occurrences of the configured credential name are ambiguous;
repeated unrelated names keep their first value. Cookie and query values
remain literal, without percent decoding. A percent-encoded query name
that would match the configured name is rejected when no literal match is
present.

A query token can appear in access logs, CDN logs, and browser history.
The resolver logs a notice when a query location is configured so operators
can keep raw query strings out of infrastructure logs.

## Outcomes and provenance

Extraction reports `auth.missing_credential`, `auth.empty_credential`,
`auth.ambiguous_credential`, or `auth.malformed_credential`. Malformed JWT
structure also reports `auth.malformed_credential`, regardless of location.
Denial reasons and `Debug` output do not include credential values.

A resolved `RawInboundToken` records its location in `source: Credential`.
Its token bytes are omitted from serialization; `IdentityPayload` likewise
omits request headers because they may contain credentials. The replacement
of `RawInboundToken.source_header: String` with `source: Credential` changes
the public and serialized shape for embedders.

A host-pre-extracted token is accepted for a header resolver only when
`IdentityPayload.source_header` names that header. An unattributed token
remains accepted for the default `Authorization` header. Cookie and query
resolvers do not use the pre-extracted token fallback.

Inbound cookie and query credentials are not automatically stripped from
the request a host forwards upstream. Hosts that forward the original
request must remove them when the route requires that boundary.

## Verification

Unit tests cover parsing, configured names, duplicate handling, and
location-specific outcomes. JWT integration tests exercise signed tokens
from all three locations. The host-contract suite checks that the raw
query survives identity resolution and remains available to policy.

Run `make check`, `make lint`, `make test`, and `make doc` before merging.
