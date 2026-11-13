# FIPS

Policy can run its cryptography on system OpenSSL under the FIPS provider. A
FIPS build disables default features and selects `fips`, the shared backend
for Policy's SHA-256 operations. Identity builtins are optional.

## Selections

| Features | What it adds |
|---|---|
| `fips` | The engine: session ids, instruction digests, decision-cache keys and audit content digests on OpenSSL FIPS SHA-256 |
| `fips,api-key` | `identity/api-key`; credentials are hashed with the shared backend |
| `fips,jwt-openssl-fips` | `identity/jwt` and DPoP; signatures are verified with OpenSSL |
| `fips,api-key,jwt-openssl-fips` | Both identity builtins |

```toml
# engine only
praxis-policy = { version = "0.6.0", default-features = false, features = ["fips"] }

# JWT and DPoP
praxis-policy = { version = "0.6.0", default-features = false, features = [
  "fips", "jwt-openssl-fips",
] }
```

These feature sets link OpenSSL and exclude RustCrypto, ring and AWS-LC.
`fips_profile_is_safe()` returns `true` for each one.
`jwt-openssl-fips` requires `fips` and cannot be combined with `jwt`, which
verifies with AWS-LC.

## Not covered

- **HMAC.** The FIPS backend provides no HMAC. Keyed content provenance is
  refused at config load (see [Auditing](auditing.md)), and HMAC JWTs are
  refused under `jwt-openssl-fips`.
- **Other builtins.** `basic`, OAuth delegation, Vault delegation and Valkey
  keep their own non-FIPS crypto. Enabling any of them, or ordinary `jwt`,
  makes `fips_profile_is_safe()` false. `basic` has no FIPS-safe
  configuration: its bcrypt, argon2 and sha-crypt verification is RustCrypto's
  whichever scheme the directory holds, so no choice of record moves it onto
  OpenSSL.
- **`http-hyper`.** It links ring for TLS, so it cannot be combined with
  `fips`.
- **The host.** The report describes Policy's compiled features only. It does
  not scan the host's other dependencies or check the runtime image.

## Host setup

Load the OpenSSL FIPS provider before calling `PolicyEngine::initialize()`.
With `jwt-openssl-fips`, also make it the default, since signature
verification and random generation select their implementation from the
default properties:

```ini
[algorithm_sect]
default_properties = fips=yes
```

A FIPS-mode host already arranges this. Set it for the running host, not for
build tools: Cargo's own TLS fails with FIPS-only defaults.

## Startup checks

`PolicyEngine::initialize()` validates shared SHA-256 before resolving
secrets or initializing plugins. JWT resolvers validate their provider
during construction, including configuration loading, before `jsonwebtoken`
can select another provider. Direct resolver users get the same validation
without an engine.

At startup, require the capability report too:

```rust,ignore
use praxis_policy::{crypto_capability_report, PolicyEngine};

let report = crypto_capability_report();
if !report.fips_profile_is_safe() {
    anyhow::bail!("Policy crypto graph is not FIPS safe: {report:?}");
}
let engine = PolicyEngine::default();
engine.initialize().await?;
tracing::info!(crypto = ?report, "Policy crypto providers are ready");
```

`validate_crypto_backend()` lets a host check shared SHA-256 before engine
initialization. Plugins with independent crypto need their own checks.

## JWT and DPoP

`jsonwebtoken` still parses tokens, selects JWKS keys and validates claims.
Signatures are verified with OpenSSL, and the DPoP `ath` hash and RFC 7638
thumbprint use Policy's shared SHA-256 backend.

- **Algorithms:** RS256, RS384, RS512, PS256, PS384, PS512, ES256 and ES384,
  for both `algorithms:` and `dpop.algorithms:`. HS256, HS384, HS512, EdDSA
  and the `secret` key kind fail config load with an error naming
  `jwt-openssl-fips`. DPoP algorithms are checked even while `dpop.mode` is
  `off`.
- **Keys:** RSA moduli of 2048 to 8192 bits with an odd public exponent
  between 2^16 and 2^256 (FIPS 186-5), and EC keys on P-256 or P-384.
  A DPoP proof key, which the client supplies, is refused when its proof is
  verified. Inline and file keys outside these are refused at load; a JWKS
  entry outside them is skipped on every fetch, including refreshes.
- **Provider:** JWT configuration loading validates shared SHA-256, OpenSSL's
  FIPS default properties (see [Host setup](#host-setup)) and the configured
  signature algorithms. A crypto failure stops config loading with
  `PluginError::Crypto` and logs `alarm = "policy_crypto_failure"` with
  `op = "jwt_provider"` or `"jwt_algorithm_probe"`. No separate JWT preflight
  call is required.
- **One provider per process:** `jsonwebtoken` takes one crypto provider per
  process. A host that installs its own, or calls `jsonwebtoken` before
  Policy builds a resolver, makes JWT resolvers refuse to build rather than
  verify with that provider.
- **Request path:** a backend failure while setting up verification, or in
  DPoP hashing, denies with `policy.crypto_failed` and logs
  `policy_crypto_failure` with `op = "jwt_verify"`, `"dpop_verify"`,
  `"dpop_provider"`, `"dpop_thumbprint"` or `"dpop_ath"`, at most once a
  minute per operation with a `suppressed` count. The signature check itself
  raises no alarm: OpenSSL reports a mismatched signature and a failure the
  same way, and a client must not be able to raise the alarm with a forged
  token. It denies as `auth.signature_invalid` or `auth.dpop_invalid`. The
  denial reason carries no backend detail.

## Accepted crates in the graph

`make check-fips-graph` fails on any crate in the FIPS graph that matches a
crypto pattern and is in neither its non-FIPS list nor `FIPS_GRAPH_ALLOWED`.
The allowed crates, and why:

| Crate | Why it is accepted |
|---|---|
| `uuid` | Trace, span and registry ids, CIBA poll owners and effect keys: identifiers, never keys or secrets |
| `getrandom` | The OS source behind `uuid::Uuid::new_v4` |
| `signature` | `jsonwebtoken`'s signer and verifier traits; it holds no algorithms |

Secret material, such as the OAuth cache-key secret, is drawn with
`praxis_policy_core::crypto::random_bytes`. Under `fips` that uses OpenSSL's
private DRBG, which is the FIPS DRBG when the FIPS provider is the process
default, and fails otherwise. A new key, nonce or secret must use it rather
than `uuid` or `getrandom`.

## Building plugins and hosts

Cargo combines features from every dependency edge, and the capability
report reflects that combined selection. Set `default-features = false` on
each Policy dependency, including plugin crates, so the host selects the
backend. Defaults enabled elsewhere can add `crypto-rustcrypto` to a FIPS
build and select both backends, which the build rejects. See
[Crypto backend](crates.md#crypto-backend).

## Next

- [Builtins](builtins.md): the full feature list.
- [Crates](crates.md#validate-shared-hashing-at-startup): startup validation
  and fallible hashing for embedders.
- [Testing](testing.md): the FIPS test targets.
