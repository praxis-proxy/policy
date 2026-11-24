# Getting Started

The Praxis Policy Engine (PPE) decides which operations may run, what data
returns, and where that data may flow.

## Use cases

- **API and tool authorization:** control access to API endpoints, tools,
  prompts, and resources using verified identities and policy rules.
- **Model access and inference inputs:** restrict callers to approved models
  and inspect messages, tool definitions, and request parameters.
- **Upstream credentials:** exchange tokens for scoped backend access or
  retrieve credentials from Vault.
- **Permission-based redaction:** redact or mask tool arguments and results
  according to the caller's permissions.
- **Data flow across calls:** restrict later operations based on sensitive
  data accessed earlier in the session.
- **Input validation:** reject inputs that fail configured schema or content
  checks.
- **Human approval and auditing:** require approval for selected operations
  and record policy decisions and effects.
- **Rate limiting:** limit requests by client address, verified identity, or
  claims.
- **Trusted identity headers:** pass verified identity and claims to upstream
  services and control response headers.

See [Use Cases](../concepts/use-cases.md) for worked policies and demo scenarios,
and [Guides](../guides/README.md) for configuration and host requirements.

## Where to start

- [Quick Start](quickstart.md): for developers embedding PPE in a Rust host.
  Configure the runtime, register plugins, supply an HTTP transport, and load
  a policy.
- [Use with Praxis](use-with-the-gateway.md): run PPE through the Praxis
  `policy` filter. Start the gateway demo and compare allowed and denied calls.
