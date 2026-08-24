# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

> **Types of changes:**
>
> - **Added**: for new features.
> - **Changed**: for changes in existing functionality.
> - **Deprecated**: for soon-to-be removed features.
> - **Removed**: for now removed features.
> - **Fixed**: for any bug fixes.
> - **Security**: in case of vulnerabilities.

## [Unreleased]

### Added

- **PPE performs no outbound HTTP of its own.** A host installs an `HttpTransport` and plugins borrow it, so a process embedding PPE keeps one connection pool, one TLS trust store, and one egress path instead of two. `identity-jwt`, `delegator-oauth`, and `elicitation-ciba` all go through it; `reqwest` is gone from the workspace entirely. A proxy injects its own client via `PolicyEngine::set_http_transport`; anyone embedding PPE standalone can call `install_default_http_transport` for a bundled hyper implementation behind the non-default `http-hyper` feature. ([#20](https://github.com/praxis-proxy/policy/issues/20))

- **`perform_http` capability.** Gates outbound HTTP, and gates the *action* rather than a slot — the first capability that authorizes reaching outside the process. Withholding it stops the call rather than degrading it, because a plugin that quietly skipped its `IdP` call would fail open. **Breaking for existing config**: a plugin using `jwks_url`, an OAuth delegator, or a CIBA approver must now declare it or the engine refuses to start, naming the plugin and the capability to add.

- **Response bodies are bounded.** Every outbound call now carries a size ceiling — 256 KiB for a JWKS document, 64 KiB for a token response — so a compromised or broken endpoint cannot stream until the process dies. `reqwest` applied no limit on any of these paths, so this closes a gap rather than tightening a bound.

- **HTTP/2, where the peer supports it.** The bundled transport advertises ALPN `h2, http/1.1` and falls back to HTTP/1.1, which the previous `reqwest` configuration never enabled. A deployment minting a token per request carries those concurrently over one connection instead of one connection each.

- **Retries are keyed to whether a repeat is safe.** `RetryPolicy` distinguishes an operation that can be repeated from one that cannot, and `HttpTransportError::may_have_reached_peer` answers the question a caller actually needs. A JWKS `GET` retries freely; a token exchange and a CIBA dispatch retry only failures that provably never reached the peer, because a timeout cannot tell "never arrived" from "the reply was lost" and repeating either would mint a second credential or ask a human twice.

- **`delegation.egress_denied` / `elicitation.egress_denied`.** New deny codes for the case where the host refuses a call before it leaves the process — an egress policy, an SSRF guard, an open circuit. Kept distinct from `idp_unreachable` on purpose: "we declined to try" and "we tried and failed" send an operator to different places, and collapsing them turns a blocked destination into a phantom network problem. No behaviour changes until a host transport produces the refusal; the bundled hyper transport never does.

- **A shared table of addresses an outbound call must not reach.** `praxis_policy_core::http_addr` covers loopback, RFC 1918, link-local (the cloud-metadata range), CGNAT `100.64/10`, the IPv6 equivalents, and the embedded-IPv4 forms including NAT64. The table only; `praxis-policy-core` opens no sockets, so a transport enforces it where it dials. Sharing it stops three transports each writing a range list that drifts, and these are exactly the ranges that look finished while missing an entry.

- **`FakeTransport` for tests.** A scripted transport in `praxis-policy-core::http_testing`, which makes the paths a mock server cannot reach — a timeout, a connect failure, a rotation between two fetches — assertable without sleeping.

- **Claim mapping is configuration.** The JWT identity plugin's `claim_mapper` names any of four shipped presets (`standard`, `keycloak`, `auth0`, `cognito`), and a new `claim_map` field takes a map written inline, so an `IdP` that nests roles under `realm_access.roles` or namespaces them behind a URL no longer needs a patched crate. A field lists candidate paths tried in order, with options for shape, splitting, and whether a miss refuses the token, and `merge: union` takes every candidate that resolves, each value once, in first-seen order. Paths use dots for nesting, with `\.` for a literal dot. An existing config is unaffected: naming no mapper resolves to `standard`, which the tests hold to the previous Rust mapper. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A policy can gate on which `IdP` minted a token.** `claims: {include: [iss]}` returns a claim to the policy-visible bag, registered claims included, so `claim.iss` becomes readable. Registered claims were always dropped, so a deployment trusting several issuers could not gate on which one signed the token. `claims.exclude` drops a claim the other way, and both work with a preset or an inline map. Both lists take top-level claim names, since the bag is keyed by name: a dotted entry is refused at load rather than matching nothing, and a claim whose own name holds a dot is written with `\.`. A `role: caller_workload` resolver carries no claims bag, and says so at load rather than ignoring the setting quietly. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **Each shipped preset records what it omits.** Auth0 and Keycloak put their roles claim where no preset can name it, so those need a hand-written `claim_map`. Presets leave a field empty rather than filling it with the wrong concept, because Keycloak's `groups` holds realm roles and Cognito's `cognito:roles` holds IAM role ARNs. Each preset's description says what it covers and what is opt-in at the provider. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **Roles and permissions are readable as whole sets.** `subject.roles`, `subject.permissions`, `client.roles`, and `client.permissions` join `subject.teams` as `StringSet` bag keys, so a policy can write `"hr" in subject.roles` rather than enumerating `role.<name>` booleans. The flattened boolean keys are unchanged. ([#7](https://github.com/praxis-proxy/policy/pull/7))

### Changed

- **`Plugin::initialize_with` is what the engine calls.** It receives the host services the plugin's capabilities allow, and its default forwards to `initialize`, so a plugin needing nothing from the host is untouched. Override exactly one: the default body of `initialize_with` is what calls `initialize`, so overriding it replaces that call.

- **`identity-jwt` refreshes JWKS on demand instead of on a timer**, and `min_refresh_interval_secs` (default 30) is a new knob bounding how often one issuer may re-fetch. `refresh_secs` keeps its meaning as the staleness bound. See the fix below for why the timer went.

- **Unknown keys in the JWT plugin's config are rejected.** The resolver config and each `trusted_issuers` entry default every field, so a misspelling took effect silently, and a misspelled `audiences` turned audience checking off. **Breaking** for a config carrying a key the plugin does not read. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A SPIFFE ID with no trust domain is refused.** `spiffe:///ns/default/sa/agent` carries the scheme but no authority, so it named no trust boundary and the mapper still filed it as a workload identity whose trust domain was the empty string. It now declines, the same as any other non-SPIFFE subject, and a valid candidate behind it still resolves. **Breaking** for a deployment minting such a token, which was never a valid SPIFFE ID. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A workload's trust domain is no longer mappable.** It is the authority of the SPIFFE ID, so it is derived from the identity rather than read from a claim. ([#31](https://github.com/praxis-proxy/policy/pull/31))

### Fixed

- **Subject claims keep their JSON shape.** `SubjectExtension.claims` holds `serde_json::Value` and flattens into the attribute bag through `payload::walk`, so Keycloak's nested `realm_access.roles` is a `StringSet` a policy can test instead of one opaque string. Client claims always worked this way. **Breaking** for Rust callers reading `claims`; `SubjectExtension::claim_str` covers the scalar lookups. Scalar policies such as `claim.tenant == 'acme'` are unaffected, but a structured claim now sets only the flattened children beneath `claim.<name>`, not the key itself, and a claim whose value is `{}` or `null` sets no key at all where it previously landed as stringified text. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **A scalar array reaches the bag as a `StringSet` instead of no key.** `payload::walk` emitted nothing for `[]` or for any array holding a number or bool, so a user with no realm roles had no `claim.realm_access.roles`, and a provider minting `"group_ids": [1, 2]` had none of those either — a missing key is a CEL error that fail-closed handling denies. Numbers and bools now render as strings, so `claim.group_ids contains "1"`, matching how a float claim is carried through Cedar. An array holding a nested array or object still sets no key. Applies to `args.*`, `result.*`, `data.*` and `client.claim.*` too. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **A float claim no longer denies every request through a Cedar step.** Cedar has no floating-point type, and a claim arrives in whatever shape the `IdP` minted, so a float claim is carried as its string form rather than rejected. Operator-authored `resource.attributes` still rejects one and names the key. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **JWKS rotation was silently dead under any host that dropped the runtime it initialized on.** `identity-jwt` spawned a background refresh ticker during `initialize()`, and `tokio::spawn` binds a task to whichever runtime is current — so a host driving async initialization on a short-lived runtime (a sync filter factory does exactly this) had that task cancelled before it ticked once. Nothing errored and nothing logged; the task simply stopped existing.

  Two consequences, both permanent until a restart. A key roll denied every token signed with the new key. Worse, the deliberate soft-fail-at-boot became permanent-fail-at-boot: a brief `IdP` outage during startup denied an issuer indefinitely, so a rolling restart during `IdP` maintenance was enough to trigger it.

  Refresh now happens on the verify path, triggered by the two failures whose cause is stale keys, single-flighted per issuer and floored by `min_refresh_interval_secs` — the floor matters because an unknown `kid` is reachable with an unauthenticated request and would otherwise be an amplification attack on your own `IdP`. Rotation now recovers on the first token that needs the new key rather than at the next tick, and a failed boot fetch recovers on the next request. ([#29](https://github.com/praxis-proxy/policy/issues/29))

- **An empty set no longer reads as a missing attribute.** Every `StringSet` the CMF bridge emits is now present-but-empty instead of omitted. Under CEL a missing key is an evaluation error that fail-closed handling turns into a denial, so `"x" in subject.roles` denied every subject that had no roles — a routine state, since a plugin without `read_roles` is handed an empty set. Does not cover an absent extension slot, where the namespace is missing entirely. ([#7](https://github.com/praxis-proxy/policy/pull/7))

## [0.1.0] - 2026-08-14

First release. The engine was extracted from another project rather than written
here, so this entry records what moved, what changed on the way, and what the
public surface now is.

### Added

- **The policy engine, ported from [`contextforge-org/cpex`](https://github.com/contextforge-org/cpex) with history intact.** Extracted with `git-filter-repo` at source commit `aed0f15`, 192 files across 37 filtered commits, so `git log` and `git blame` reach back before this repository existed. The Rego decision point came in a second pass from `fa222c4`. [`docs/port-provenance.md`](docs/port-provenance.md) records both anchors, which is what any later comparison between the two trees needs.

- **`praxis-policy`, a host facade.** One dependency instead of a dozen. It re-exports the runtime (`PolicyEngine`, `AplOptions`, `register_apl`) and owns registration of the bundled extensions, each behind its own feature. `default` is empty, so the bare dependency is the engine alone with nothing extra compiled in; `builtins` turns on the whole set, or name a subset (`jwt`, `oauth`, `elicitation-ciba`, `cedar`, `cel`, `opa`, `valkey`).

- **Three decision points, selectable per route.** Cedar policy sets (`cedar:`), inline CEL expressions (`cel:`), and embedded OPA/Rego via regorus (`opa:`). One binary serves all three; a route picks one with a step.

- **Bundled extensions:** multi-source JWT identity, RFC 8693 OAuth token delegation, out-of-band human approval over OIDC CIBA, and a Valkey-backed session store for taint that survives a restart.

- **Sensitive headers never reach a decision point.** `Authorization`, `Cookie` and `X-API-Key` are stripped from the projection a PDP receives, matched case-insensitively because headers arrive in whatever case the client sent. For a remote PDP that projection crosses the network, so this is the difference between consulting a policy service and handing it a bearer token.

- **A documented path for plugins the engine does not bundle.** Implement `PluginFactory` against `praxis_policy_core::prelude` and register it with `PolicyEngine::register_factory` under the `kind:` your policy names. An unrecognised `kind` fails at load, so a missing registration is a startup error naming the kind rather than a plugin that silently never runs. The prelude's doc example is compiled, not `ignore`d, so it cannot drift from what a plugin actually needs.

### Changed

- **Renamed to the Praxis Policy Engine throughout,** crates, types and docs. Deliberately unchanged: the policy document format, the `kind:` strings an operator writes, and the violation codes a client sees. Those are the surface a deployment depends on, and `crates/ppe-core/tests/wire_compatibility.rs` pins them against a document authored before the rename.

- **Edition 2024 and resolver 3,** with the MSRV pinned to the same toolchain the formatter and coverage run on, so there is one Rust version to reason about.

- **Six core crates instead of eight.** `praxis-policy-sdk` became `praxis_policy_core::prelude`: every name in it was already re-exported from core, so the separate crate offered a curated namespace and no dependency saving, which a module provides without a second crate to version. `praxis-policy-builtins` folded into the facade, because the feature list, the factory re-exports and the registration table all describe one set and can disagree when split across two crates.

- **The PII scanner and audit logger are no longer published or bundled.** They live under `reference/plugins/` as worked examples a host registers itself. The scanner is regex matching with no Luhn check, and the logger writes to stderr; neither is something a policy engine should ship as supported, and both are what a deployment will want to replace. **This is breaking** for anyone who had `features = ["pii"]` or `["audit"]`, or who named `PiiScannerFactory` / `AuditLoggerFactory`: register the factory instead.

### Fixed

- **A float in a Cedar attribute source denied every request through that step.** Cedar's value model has no floating-point type, so `attributes: { score: 1.5 }` failed entity construction with a message that named neither the attribute nor the reason. It now reports which key holds the float and what to supply instead. The same walker covers the operator-authored resource block.

- **A quoted argument containing a lone quote aborted the policy parser** instead of being read as a literal.

- **Branch outcomes are keyed rather than positional,** so a concurrent effect's result can no longer be attributed to the wrong branch.

### Security

- **`nbf` is now enforced on inbound JWTs.** `validate_nbf` is off by default in jsonwebtoken, unlike `validate_exp`, and nothing turned it on. The module documented `auth.token_not_yet_valid` as a stable code and mapped `ImmatureSignature` to it, but that error could never be produced, so a token whose own issuer said it was not valid until later was accepted the moment it was minted. Enforced under the same leeway that already covers `exp`, so ordinary clock skew is still tolerated. A deployment whose IdP deliberately mints a future `nbf` will start seeing that code.

- **An issuer accepting no signature algorithms now rejects every token from it,** rather than treating the empty list as "any algorithm is acceptable" and handing algorithm choice to whoever minted the token.

### Internal

- **Line coverage at 95%,** gated in CI by `COVERAGE_FLOOR` so it cannot silently regress. The `nbf` gap and the Cedar float defect both surfaced while writing those tests, which is the argument for the exercise.

- **191 lint rules configured across rustc, clippy and rustdoc,** every one at an explicit level. Anything that could silently change an enforcement decision is denied; [`docs/lints.md`](docs/lints.md) explains each group that is not.

[Unreleased]: https://github.com/praxis-proxy/policy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/praxis-proxy/policy/releases/tag/v0.1.0
