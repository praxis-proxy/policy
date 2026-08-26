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

- **Delegated tokens can be reused until they expire.** The OAuth delegator runs one RFC 8693 exchange per `delegate` step; a `cache:` block lets it serve a token it already minted instead. Off unless enabled, and then only for `subject: this_workload` and `client`, whose number of cache entries is bounded by configuration rather than by the caller population. `user` and `caller_workload` are opt-in through `cache.subjects`. Concurrent requests for one uncached key produce one exchange rather than one each, and a failed exchange is not stored. A cached token stays usable after an `IdP`-side revocation until its entry retires, which `cache.ttl_ceiling_seconds` bounds. ([#30](https://github.com/praxis-proxy/policy/issues/30))

- **A route that delegates an unvalidated credential is reported at config load.** A `delegate` step whose subject exchanges the caller's own token relies on identity resolution having checked it, but `identity:` is per-route and optional, so a route can reach the delegator with a token this process has not validated. Loading the config now warns under `alarm = "delegation_without_identity_resolution"`, naming the route and the delegate plugins on it. `subject: this_workload` is excluded, since it carries no inbound credential. ([#30](https://github.com/praxis-proxy/policy/issues/30))

- **`cmf.http_response`, the return half of the L7 path.** `cmf.http_request` had no counterpart because authorization is an admission check that belongs entirely before the request is forwarded. Response filtering is not: stripping a header the upstream set, enforcing a content type, and attaching labels all belong after. Header and extension filtering only, since no response body exists in the model yet and the payload is unused on this path. A `global.apl` carrying `result:` or `post_invocation:` steps now installs a `Post`-phase handler under the same `http` / `*` coordinates the request hook uses; a policy that only authorizes gains nothing and installs nothing. PPE defining and routing a hook does not oblige a host to fire it, so a host that never does sees no change. For the host that does adopt it: a `global.apl` whose post steps were previously inert on the entity-less HTTP path becomes live the moment the hook is fired, and `result.*` keys do not exist for a request carrying no entity, so a step reading one denies. Check what the global post block does before firing.

- **One declaration per hook, holding both its name and its routing metadata.** `define_hooks!` emits a hook's `pub const` and its `hooks::metadata` row together, so a name without a row is unrepresentable rather than something to test for. A host declaring its own hooks can use it too, then register the resulting slice at startup. `crates/ppe-core/examples/plugin_demo.rs` shows the pattern.

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

- **A declared hook name is validated at config load.** `hooks:` carried free strings that nothing checked, so a typo loaded clean and nothing said so. What a typo cost depended on the plugin: a factory that derives its handler names from `config.hooks` (the `audit-logger` and `pii-scanner` reference plugins) registered under the misspelling and never fired, while one that hardcodes its hook name (`identity-jwt`, `delegator-oauth`, `elicitation-ciba`) fired correctly and left the `hooks:` list as decoration that disagreed with reality. Both are now refused, because a `hooks:` entry naming a hook nothing dispatches is a config error either way. An unknown name now refuses the config, naming the plugin, the name, and the nearest name that does dispatch: `tool_pre_invoke` suggests `cmf.tool_pre_invoke`, which is the exact mistake the removed constants and the old `PluginConfig` example taught. A name close to nothing in the table gets no suggestion rather than the least-bad match. **Breaking for existing config** carrying a misspelled or inert hook name. Validation reads the runtime registry, so a host with its own hooks passes once it has registered their metadata — which it must do *before* loading config that names them; registering afterwards is too late and the load refuses. The registry is process-wide while `PolicyEngine` is per-instance, so two engines in one process share one hook table and whichever loads first decides what the second accepts. A config can load under one process layout and refuse under another, such as a host embedding PPE twice or a test binary sharing a process across cases. Register every hook a process uses before loading any config, not only before the config that names them.

- **Config validation runs on every load path.** `PolicyEngine::load_config` and `from_config` take a pre-built `PolicyConfig` and ran neither `validate_config` nor the top-level `groups:` merge, so a host building its config in Rust got no duplicate-plugin-name check, no route-shape check, and no group resolution — routes silently lost the plugins and `authentication:` their group was meant to supply. Both now normalize and validate the way the YAML paths do. **Breaking**: a programmatic config with a duplicate plugin name, a malformed route, an unknown hook name, or a route naming a plugin absent from `plugins:` now fails where it previously loaded with the offending piece inert. That last case reaches a host that registers handlers with `register_handler` instead of declaring them under `plugins:` and then names them in a route.

- **`hooks::metadata::lookup` returns `Option<HookMetadata>`.** It used to substitute a wildcard for a name the registry did not hold, so an absent hook and a deliberately unphased one both read as `Unphased` and a caller reading phase could not tell a missing entry from a real one. `HookMetadata::unknown()` is renamed `permissive()` to match: the wildcard is now a default a caller opts into, not the shape of a failed lookup. **Breaking** for Rust callers; `lookup(name).unwrap_or_else(HookMetadata::permissive)` restores the old behavior exactly.

- **`Plugin::initialize_with` is what the engine calls.** It receives the host services the plugin's capabilities allow, and its default forwards to `initialize`, so a plugin needing nothing from the host is untouched. Override exactly one: the default body of `initialize_with` is what calls `initialize`, so overriding it replaces that call.

- **`identity-jwt` refreshes JWKS on demand instead of on a timer**, and `min_refresh_interval_secs` (default 30) is a new knob bounding how often one issuer may re-fetch. `refresh_secs` keeps its meaning as the staleness bound. See the fix below for why the timer went.

- **Unknown keys in the JWT plugin's config are rejected.** The resolver config and each `trusted_issuers` entry default every field, so a misspelling took effect silently, and a misspelled `audiences` turned audience checking off. **Breaking** for a config carrying a key the plugin does not read. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A SPIFFE ID with no trust domain is refused.** `spiffe:///ns/default/sa/agent` carries the scheme but no authority, so it named no trust boundary and the mapper still filed it as a workload identity whose trust domain was the empty string. It now declines, the same as any other non-SPIFFE subject, and a valid candidate behind it still resolves. **Breaking** for a deployment minting such a token, which was never a valid SPIFFE ID. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A workload's trust domain is no longer mappable.** It is the authority of the SPIFFE ID, so it is derived from the identity rather than read from a claim. ([#31](https://github.com/praxis-proxy/policy/pull/31))

### Removed

- **The `hooks::types::hook_names` and `hooks::types::cmf_hook_names` modules.** Sixteen `pub const`s that no dispatch site read. Six of `hook_names` shadowed CMF hooks under names nothing fires; two spelled identity and delegation `identity_resolve` / `token_delegate`, which no handler answers to. `cmf_hook_names` duplicated `cmf::constants` and got the prompt pair wrong, teaching `cmf.prompt_pre_fetch` where the dispatched name is `cmf.prompt_pre_invoke`. Because nothing consumed them they drifted unnoticed for months. **Breaking**, with no replacement needed: `praxis_policy_core::cmf::constants` holds the CMF names and is the supported import path, alongside `identity::HOOK_IDENTITY_RESOLVE`, `delegation::HOOK_TOKEN_DELEGATE`, and `elicitation::HOOK_ELICIT`. Those constants keep their paths and their values. The values are operator-facing, since a `hooks:` list in YAML names them as strings, so they are fixed as public API rather than free to rename.

### Fixed

- **Concurrent registration no longer loses plugins.** Every mutation of the engine's runtime snapshot was a load, clone, store with nothing serializing writers, so two threads that loaded the same snapshot each published their own copy and the last write discarded the other silently. A test putting sixteen threads through `register_handler` at once kept one plugin, and all sixteen calls returned `Ok`. Writers now serialize on a mutex held across the copy-on-write, covering `load_config`'s inline swap as well; the read path is untouched and still lock-free, and the generation counter still bumps exactly once per published mutation. Nothing in the workspace registers concurrently today, so no shipped configuration was affected, but registration takes `&self` on an `Arc`-shared engine and a host is free to call it from any thread. Neither that mutex nor the factory-registry `RwLock` is reentrant, so `load_config` now runs every `PluginFactory::create` holding neither: it resolves the factories, releases the registry lock, instantiates, and only then takes the writer lock for the registry clone and the swap. A factory that calls back into `register_handler`, `annotate_route`, `unregister_plugin`, or `register_factory` while being built would otherwise block on a lock its own caller was holding. Whatever such a factory registers on its way through is picked up by the clone rather than discarded by it. The two route-override paths already released the registry lock before `create` and are unchanged. `mutate_runtime` and `try_mutate_runtime` likewise release the writer lock before the snapshot they replaced goes out of scope: that snapshot usually holds the last reference to whatever the mutation discarded, and a plugin or annotation handler's `Drop` is host code too, so `remove_route_annotation` on a handler that called back would have blocked on the lock its own release was holding. A rejected `load_config` is the same story from the other end: the plugins its factories just built have nowhere else to live, and the registry drops the one whose name collided while the entries behind it are never registered at all. Registration now borrows the instances and hands the registry `Arc` clones, so the load keeps the last reference to every one of them and releases the lock before letting go. ([#23](https://github.com/praxis-proxy/policy/issues/23))

- **Three dispatched hooks had no routing metadata.** `cmf.http_request` and `elicit` were absent from the table entirely, so `lookup` reported them unphased and a consumer deriving request-versus-response direction from a hook's phase got neither for the L7 path. It never surfaced because the matcher treats an unphased hook as matching every context, so dispatch kept working while the phase it reported was wrong. All three, `cmf.http_response` included, now carry the phase and entity type they are installed under, and a test holds the table to what the dispatcher does. **This narrows dispatch as well as correcting it**: a hook with no row matched every entity type and every phase, so a plugin registered under `cmf.http_request` used to dispatch for `tool`, `llm`, `prompt`, and `resource` requests too. It now dispatches only for `entity_type: http` in the request phase. A deployment relying on that accidental reach registers the plugin under the hooks it actually serves, or restores the old behavior for that one name with `register_hook_metadata(HOOK_CMF_HTTP_REQUEST, HookMetadata::permissive())` at startup. `permissive()` is `phase: Unphased`, which is what makes it match every phase, so a hook registered that way reports `false` from both `is_pre` and `is_post`. A host that wants the phase reported rather than the reach restored writes the row out: `HookMetadata { entity_type: Some(ENTITY_HTTP), phase: HookPhase::Pre }`.

- **`MessageView::is_pre` and `is_post` were a second phase authority that disagreed with the first.** Both matched the hook's name against a substring, so four of the ten phased hooks answered `false` to both: `cmf.llm_input` and `cmf.http_request` are `Pre` and contain no "pre", `cmf.llm_output` and `cmf.http_response` are `Post` and contain no "post". The policy-visible `is_pre` / `is_post` fields of `to_dict` carried that. Both now read the metadata registry that dispatch reads, so a hook is pre-phase because it is registered that way. A host hook named `express_lane` no longer reads as pre-phase, and an unregistered name reports neither. Nothing outside `MessageView` read these, so this reaches plugin authors rather than a shipped path.

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
