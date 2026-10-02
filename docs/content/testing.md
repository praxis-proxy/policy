# Testing Policy

Test APL by loading a policy, driving operations through the runtime, and
asserting each outcome. Most route tests need no live backend.

## What to test

For each route, cover the outcomes its policy produces:

- Allow: a caller with the required attributes passes and the
  operation forwards.
- Deny: a caller missing a required attribute is rejected, with the
  expected reason code.
- Redaction: a field is present for an entitled caller and redacted
  for an unentitled one.
- Information flow: a session that acquired a taint label is blocked
  on a later operation that gates on it.
- Delegation: a passing caller mints a token with the requested
  scope, and a post-check denies when the granted scope is short.

## Testing the policy alone

To assert on what a policy block compiles to, without an engine, use the
`test-util` feature of `praxis-policy-apl-core`:

```toml
[dev-dependencies]
praxis-policy-apl-core = { version = "0.4", features = ["test-util"] }
```

`compile_test_policy(source, yaml)` compiles a document with a `route:`
block and any `plugins:` declarations; `compile_test_route` returns just
the compiled route. A block declaring no APL term compiles to an empty
route rather than vanishing, so a test that a section carries no policy
asserts `route.declared_phases().is_empty()` rather than an absence.

This replaces the removed `compile_config`, which accepted a route shape
that production never used.

## Testing through the engine

For behavior rather than compilation, load the policy into an engine and
drive operations through it:

```rust,ignore
async fn engine_with(policy: &str) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    praxis_policy::install_builtins(&engine);
    engine.load_config_yaml(policy).expect("policy should load");
    engine.initialize().await.expect("initialize");
    engine
}
```

A table keeps the allow and deny matrix readable, one row per case.
Anonymous callers are enough to exercise structural rules
(authentication gates, argument guards, `result` pipelines) with no IdP.
Identity-dependent rules need a token, which means either a real IdP or
a scripted transport.

## Testing what reaches outside the process

Plugins that fetch JWKS, exchange tokens, or dispatch approvals go
through the host's `HttpTransport`, which makes their failure paths
testable without a server. `praxis_policy_core::http_testing` provides
`FakeTransport`, a scripted transport that makes the cases a mock server
cannot reach assertable without sleeping: a timeout, a connect failure,
a key rotation between two fetches.

Those are the branches worth covering. A token exchange that returns a
short scope, a decision point that denies, an IdP that is unreachable:
policy exists to handle them, so a test that only covers the happy path
proves the least interesting half.

## Integration coverage

Unit-evaluating a route proves the policy logic. It does not prove the
plugins it dispatches behave correctly end to end. For effects that call
out, add an integration test that exercises the real plugin through the
engine, so the interaction is covered and not just the policy's intent.

The Valkey session store's tests are the standing example of the limit
here: they are `#[ignore]`-gated and need `VALKEY_TEST_URL` pointing at a
real server, because a session store is not meaningfully covered by a
fake. That component makes Session Taint survive a reload or
span a replica, so it is worth running them for real.

### Vault KV v2 live test

The Vault provider's normal suite uses `FakeTransport` for deterministic
HTTP-contract coverage. A live check is available with the `secrets-vault`
and `http-hyper` features and is `#[ignore]`-gated because it needs a
provisioned Vault instance. It uses AppRole, reads a normal KV v2 field, and
then reads a version soft-deleted with Vault's real HTTP 404 and
`data.data: null` response.

Start a disposable Vault 1.19 dev server, which already mounts `secret/` as
KV v2, and provision the policy, AppRole, and two test values (the root token
is development-only; the commands below use a local Vault CLI):

```console
docker run -d --rm --name ppe-vault -p 127.0.0.1:8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.19 server \
  -dev -dev-root-token-id=root
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
until vault status >/dev/null 2>&1; do sleep 1; done
vault policy write ppe-live-read - <<'EOF'
path "secret/data/live" { capabilities = ["read"] }
path "secret/data/live-deleted" { capabilities = ["read"] }
EOF
vault auth enable approle
vault write auth/approle/role/ppe-live token_policies=ppe-live-read
vault kv put secret/live password=live-value
vault kv put secret/live-deleted password=deleted-value
vault kv delete -versions=1 secret/live-deleted
export VAULT_ROLE_ID=$(vault read -field=role_id auth/approle/role/ppe-live/role-id)
export VAULT_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/ppe-live/secret-id)
```

Run the ignored test, then stop the container:

```console
cargo test -p praxis-policy --all-features --test vault_live -- --ignored --nocapture
docker stop ppe-vault
```

The test fails if the ordinary read is not `live-value`, or if the
soft-deleted response is not HTTP 404 with `data.data: null`, a deletion
timestamp, and a `SecretError::NotFound` mapping.

## Running

```console
cargo nextest run --workspace          # everything
cargo nextest run -p praxis-policy-apl-core --lib
make test                              # both feature passes, as CI runs them
```

Tests run twice, once with default features and once with
`--all-features`. The facade's `default` is empty, so its tests are
feature-gated and a single pass would hide them.

## Related documentation

- [Crates](crates.md): locate the APIs and test surfaces in the workspace.
- [Builtins](builtins.md): review the bundled components covered by integration
  tests.
- [Documentation index](index.md): return to the documentation map.
