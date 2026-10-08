# request.id integration smoke test

This local test exercises the same CEL predicate in Authorino and PPE. It
requires `request.id` to be nonempty and differ from both supplied client
header values (`req-abc` and `other`). PPE runs twice from one policy file:
`kuadrant_compat: false` and `true`. The case files are in [`cases/`](cases/).
Before checking the allow policy, the suite installs a deny control using
`request.id == 'req-abc'`. It requires HTTP 403 plus the deny policy's
`x-kuadrant-compat-probe` response header for both client header values. The
allow policy injects a different probe header into the upstream request; the
Talker API echoes it in the response body. Requiring HTTP 200 plus that marker
proves the active AuthConfig handled the request and prevents an unprotected
route from satisfying the allow checks. The suite is not part of CI. It checks
presence and rejects the supplied header values; it does not establish value
parity.

## Prerequisites

- `docker` (or podman), `kind`, `kubectl`, `curl`, and Rust stable 1.92+.
- Sibling checkouts of `kuadrant-operator`, `praxis-proxy/ai`, and this policy
  worktree.
- A `praxis-ai` proxy that populates `RequestExtension.request_id` from
  host-owned proxy request metadata before invoking PPE.

The current `praxis-proxy-filter` 0.7.3 adapter only attaches HTTP attributes;
it does not populate this request extension. Rebuilding against the policy
worktree alone is insufficient: the host adapter must supply the request ID
before the suite's flag-on run can allow. Copying an inbound `x-request-id`
header into that field does not establish equivalent metadata semantics.

## Authorino gateway

From the Kuadrant operator checkout, start its local environment:

```console
make local-setup
```

Then apply this testbed from the policy worktree:

```console
kubectl apply -f kuadrant-compat/testbed/10-kuadrant-cr.yaml
kubectl -n kuadrant-system wait kuadrant/kuadrant --for=condition=Ready --timeout=300s
kubectl apply -f kuadrant-compat/testbed/00-namespaces.yaml
kubectl apply -f kuadrant-compat/testbed/20-gateway.yaml
kubectl apply -f kuadrant-compat/testbed/30-httproute.yaml
kubectl apply -n toystore -f https://raw.githubusercontent.com/Kuadrant/kuadrant-operator/refs/heads/main/examples/toystore/toystore.yaml
kubectl -n toystore rollout status deploy/toystore --timeout=120s
```

The testbed uses an Istio gateway. Authorino reads ext_authz `HttpRequest.Id`,
which Envoy sets from its stream ID ([Authorino source](https://github.com/Kuadrant/authorino/blob/main/pkg/service/well_known_attributes.go),
[Envoy source](https://github.com/envoyproxy/envoy/blob/main/source/extensions/filters/common/ext_authz/check_request_utils.cc)).
PPE reads the host-supplied `request.request_id`; its mapping ignores HTTP
headers. The suite sends two client header values and rejects either as an
authorization ID. A passing run still requires a capture of actual Authorino
attributes and pinned gateway versions before it can support a value-parity
claim. No such capture is committed yet.

## PPE proxy

The suite expects `praxis-ai` at
`$PRAXIS_AI_DIR/target/release/praxis-ai` (default: the sibling
`~/projects/src/github.com/praxis-proxy/ai` checkout) and httpbin on
`127.0.0.1:9200`:

```console
docker run -d --name httpbin -p 9200:80 kennethreitz/httpbin
```

Build `praxis-ai` against this policy worktree, since the published
`praxis-policy` crate does not contain this change. In the ai workspace
`Cargo.toml`, point the patch at the absolute path to this worktree's facade
crate:

```toml
[patch.crates-io]
praxis-policy = { path = "/absolute/path/to/policy-worktree/crates/ppe" }
```

Then run `make release` in the ai checkout. The patch is local development
configuration and should not be committed in the ai repository.

## Run

```console
cd kuadrant-compat
./suite.sh
```

The suite applies the deny control, waits for both requests to be denied, then
updates the same AuthPolicy to the allow predicate and waits for both requests
to be allowed. Each phase requires its distinct AuthConfig response marker in
addition to the expected status, and either propagation wait exits nonzero on
timeout. It then checks Authorino, deletes the policy, and runs PPE with the flag
off and on. It prints all decisions and exits nonzero if Authorino differs from
the smoke-test expectations in `cases/cel-req-id.expected`, if the flag-off
policy does not deny both requests, or if the flag-on policy differs from the
expected decisions. It also removes the AuthPolicy on exit after an error.
Success reports only that the smoke test passed; reference value capture remains
pending.

PPE uses its local `policy` filter for this comparison; it does not use the
Envoy/Authorino wire integration. Authorino's route is `/toys`; PPE's httpbin
route is `/anything`.
