# Use PPE with Praxis

[Praxis](https://github.com/praxis-proxy/praxis) embeds the Praxis Policy Engine
(PPE) in its `policy` filter. The filter evaluates request policy before
forwarding an MCP tool call to the backend and response policy before returning
the result.

## Run the demo

You need Docker with Compose, Rust, `curl`, `jq`, and `lsof`. Start Docker
and keep ports `8081`, `8090`, `9100`, `6379`, and `5001` available on
localhost. See the
[demo prerequisites](https://github.com/praxis-proxy/demos/tree/main/demos/policy-engine#prerequisites)
for details.

Clone the demos repository and start the Cedar configuration:

```console
git clone https://github.com/praxis-proxy/demos.git
cd demos/demos/policy-engine
GATEWAY_CONFIG=praxis.yaml ./restart.sh
```

`restart.sh` builds the gateway, resets the demo containers and volumes, and
starts the gateway, Keycloak, Valkey, the mock MCP backend, and the approval UI.
The first build can take several minutes.

With the demo running, compare an allowed call and a denied call:

```console
./scenarios/01-bob-allow.sh
./scenarios/02-alice-deny.sh
```

- Bob calls `get_compensation` with the HR role and receives the record.
- Alice calls the same tool without the HR role and receives a JSON-RPC error
  with code `-32001`. The call never reaches the backend.

Both responses use HTTP 200; check the JSON-RPC result or error for the policy
outcome. Each script asserts its expected outcome and exits with a nonzero
status on failure. Run `./walkthrough.sh` for a narrated tour of the other
controls.

## Configuration

The demo gateway enables the `policy-engine` Cargo feature and uses two
configuration files:

- [`praxis.yaml`](https://github.com/praxis-proxy/demos/blob/main/demos/policy-engine/praxis.yaml)
  declares the listener and the filter chain: `mcp`, `policy`, `router`, then
  `load_balancer`. The `policy` filter's `config_path` names the policy
  document.
- [`policy-cedar.yaml`](https://github.com/praxis-proxy/demos/blob/main/demos/policy-engine/policy-cedar.yaml)
  holds the policy engine configuration: identity plugins, delegators,
  validators, routes, and the PDP policy.

Policy documents use [APL](../apl/index.md) to define routes and their controls.
See [Configuration](../reference/configuration.md) for the document's keys.

## Request flow

For each MCP tool call:

1. Praxis parses the JSON-RPC request and resolves the caller's identity.
2. PPE validates arguments and evaluates the route's request policy.
3. On allow, Praxis attaches delegated tokens, applies request
   [header assertions](../reference/assertions.md), and forwards the request.
4. The backend handles the call and returns a response.
5. Praxis applies response header assertions.
6. PPE applies result transformations, such as redaction, and evaluates response
   policy before the result reaches the agent.

A denial in the request phases stops the call before it reaches the backend.
Praxis handles JSON-RPC parsing, outbound HTTP transport, SSRF checks, body size
limits, and HTTP header validation. [Plugins and Pipeline](../concepts/pipeline.md)
describes the policy hooks and execution modes.

## Next

- [Quick Start](quickstart.md): embed the engine in your own host.
- [Use Cases](../concepts/use-cases.md): the policies behind each demo scenario.
- [Configuration](../reference/configuration.md): the structure of the
  policy document the filter loads.
- [Deployment](../guides/deployment.md) and
  [Threat Model](../concepts/threat-model.md): choose an enforcement point and
  understand its trust boundary.
- [Host drift](../guides/testing.md#host-drift): how integration tests track the
  Praxis revision they mirror.
