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

- **Roles and permissions are readable as whole sets.** `subject.roles`, `subject.permissions`, `client.roles`, and `client.permissions` join `subject.teams` as `StringSet` bag keys, so a policy can write `"hr" in subject.roles` rather than enumerating `role.<name>` booleans. The flattened boolean keys are unchanged. ([#7](https://github.com/praxis-proxy/policy/pull/7))

### Fixed

- **Subject claims keep their JSON shape.** `SubjectExtension.claims` holds `serde_json::Value` and flattens into the attribute bag through `payload::walk`, so Keycloak's nested `realm_access.roles` is a `StringSet` a policy can test instead of one opaque string. Client claims always worked this way. **Breaking** for Rust callers reading `claims`; `SubjectExtension::claim_str` covers the scalar lookups. Scalar policies such as `claim.tenant == 'acme'` are unaffected, but a structured claim now sets only the flattened children beneath `claim.<name>`, not the key itself, and a claim whose value is `{}` or `null` sets no key at all where it previously landed as stringified text. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **A scalar array reaches the bag as a `StringSet` instead of no key.** `payload::walk` emitted nothing for `[]` or for any array holding a number or bool, so a user with no realm roles had no `claim.realm_access.roles`, and a provider minting `"group_ids": [1, 2]` had none of those either — a missing key is a CEL error that fail-closed handling denies. Numbers and bools now render as strings, so `claim.group_ids contains "1"`, matching how a float claim is carried through Cedar. An array holding a nested array or object still sets no key. Applies to `args.*`, `result.*`, `data.*` and `client.claim.*` too. ([#9](https://github.com/praxis-proxy/policy/pull/9))

- **A float claim no longer denies every request through a Cedar step.** Cedar has no floating-point type, and a claim arrives in whatever shape the `IdP` minted, so a float claim is carried as its string form rather than rejected. Operator-authored `resource.attributes` still rejects one and names the key. ([#9](https://github.com/praxis-proxy/policy/pull/9))

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
