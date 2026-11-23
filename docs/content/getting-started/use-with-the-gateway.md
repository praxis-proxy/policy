# Use with the gateway

The Praxis Policy Engine (PPE) is a Rust library, not a standalone server.
A host embeds it and calls it at fixed points in each request. In a
[Praxis](https://github.com/praxis-proxy/praxis) gateway, that host is the
`policy` filter. This page summarises how the two fit together and where each
part is documented. It describes only what this repository documents and
tests; the Praxis documentation owns the filter's own configuration.

## How the engine runs in Praxis

Praxis is a proxy built around a filter chain. The policy engine ships as its
`policy` filter, behind the Praxis `policy-engine` feature. On an MCP tool
call the gateway parses the JSON-RPC request, runs the full policy pass, and
forwards a scoped request upstream only when policy allows it. A denied call
returns an error to the client and never reaches the backend.

The [policy-engine demo](https://github.com/praxis-proxy/demos/tree/main/demos/policy-engine)
wires this up with two files:

- [`praxis.yaml`](https://github.com/praxis-proxy/demos/blob/main/demos/policy-engine/praxis.yaml)
  declares the listener and the filter chain: `mcp`, then `policy`, then
  `router`. The `policy` filter's `config_path` names the policy document.
- [`policy-cedar.yaml`](https://github.com/praxis-proxy/demos/blob/main/demos/policy-engine/policy-cedar.yaml)
  holds the policy engine configuration: identity plugins, delegators,
  validators, routes, and the PDP policy.

The second file is an ordinary policy engine document, described in
[Configuration](../reference/configuration.md) and written in
[APL](../apl/index.md). [Use Cases](../concepts/use-cases.md) takes that
configuration apart one control at a time, with a script for each scenario.

## What happens on each call

The integration test suites drive a real engine through the same per-call
sequence as the Praxis `policy` filter, using a reference host described in
[Testing](../guides/testing.md#the-reference-host):

1. The identity gate resolves the caller from the request headers.
2. `cmf.tool_pre_invoke` runs the route's input and authorization phases.
3. On allow, the host attaches delegated tokens and applies request
   [header assertions](../reference/assertions.md).
4. The upstream answers.
5. The host applies response assertions.
6. `cmf.tool_post_invoke` runs the result phase, such as redaction, before
   the response reaches the agent.

Some behavior belongs to the host, not the policy engine: the outbound
transport and its SSRF checks, JSON-RPC parsing and request classification,
body size limits, and header validity on the wire. Praxis tests those itself.
[Plugins and Pipeline](../concepts/pipeline.md) describes the hooks, and
[Rate Limiting](../guides/rate-limiting.md#host-integration) and
[LLM Routes](../guides/llm-routes.md#host-obligations) list what a host must
supply for those features.

## Which Praxis revision is tested

The reference host records the Praxis commit it mirrors. On pull requests, a
CI job checks out that commit and verifies the mirrored files still exist;
scheduled runs report drift against Praxis `main`. A passing check is a review
signal, not proof that a given Praxis release and policy engine release behave
identically. See [Host drift](../guides/testing.md#host-drift).

## Other placements

Running inside the gateway is one placement. The same policy also applies at
an egress sidecar or inside an agent framework; see
[Deployment](../guides/deployment.md) and the
[Threat Model](../concepts/threat-model.md) for what each placement defends.

## Next

- [Quick Start](quickstart.md): embed the engine in your own host.
- [Use Cases](../concepts/use-cases.md): run the demo scenarios end to end.
- [Configuration](../reference/configuration.md): the structure of the
  policy document the filter loads.
