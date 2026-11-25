# Guides

Configure routes, authenticate callers, and apply controls to requests and
responses. For a first policy, see [Getting Started](../getting-started/README.md).

- [Host integration](host-integration-guide.md):
  supply policy content parts and write inspected response edits back
- [HTTP Routing](http-routing.md):
  match requests by path and method
- [Rate Limiting](rate-limiting.md):
  limit requests before or after identity resolution
- [LLM Routes](llm-routes.md):
  select models and check inference requests and responses
- [Identity and Delegation](identity-delegation.md):
  resolve callers and obtain credentials for upstream calls
- [Add a claim mapper preset](identity-claim-mapping.md):
  add and test JWT claim mappings for an identity provider
- [Auditing](auditing.md):
  record decisions and effects, and configure or write an audit sink
- [FIPS](fips.md):
  select an OpenSSL FIPS build and validate the host at startup
- [Deployment](deployment.md):
  choose gateway, egress sidecar, or in-process enforcement
- [Patterns](patterns.md):
  compose controls and roll out policies with audit mode
- [Testing](testing.md):
  test policy compilation and runtime outcomes
- [Upgrading APL](upgrade-apl.md):
  migrate legacy configuration and Rust host APIs

See [APL](../apl/index.md) for policy syntax and
[Reference](../reference/README.md) for configuration keys and contracts.

[Documentation index](../index.md)
