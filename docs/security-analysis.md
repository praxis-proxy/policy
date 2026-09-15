# Security Analysis Pass

Issue: [#16](https://github.com/praxis-proxy/policy/issues/16).
Date: 2026-08-26.

The engine decides who may call which tool, what data comes back, and
where that data may go next. A bypass is an authorization failure. The review
used Cursor `/code-review` (security-review and Bugbot) and an
adversarial review of the priority surfaces in that issue. Every reported
finding received a disposition.

Prior fixes that set the class of defect to look for:

- an integer cast that wrapped `delegation.depth` and turned a depth
  rule into a bypass
- a dropped orchestrator outcome that became `Aborted` when it was
  really a `Deny`
- an empty issuer algorithm list read as "any algorithm acceptable"
- a missing `nbf` check on inbound JWTs

Those four findings are closed and tested. This record covers the remaining
review results and accepted fail-open controls.

## Reviews run

| Review | Scope | Result |
|---|---|---|
| Cursor security-review | Workspace priority surfaces plus recent HTTP / cache / Cedar work | Two medium findings (SSRF table unused; OAuth leg-2 leak), both accepted |
| Cursor Bugbot | Same surfaces (natural-language change description; no feature-branch diff) | One medium finding (parallel panic fail-open), accepted |
| CE-style adversarial pass | parser, evaluator, identity-jwt, delegator-oauth, executor, engine, PDP resolvers, orchestration | Four additional P1s accepted (empty audiences, `!=` on missing, non-finite amounts, unreadable handler result); one P2 accepted as documented stub |

`make audit` (`cargo deny check`) is part of the gate for this issue.

## Findings

| ID | Severity | Location | Disposition | Why |
|---|---|---|---|---|
| F1 | Medium | `crates/ppe-apl-core/src/evaluator.rs` (`dispatch_parallel`, `BranchOutcome::Panicked`) | Fix | A panicking parallel branch was discarded. A sibling `Allow` became the block's result, so a `parallel:` of two PDP gates could permit a request if one evaluator panicked. Same class as the dropped-Deny-became-Aborted bug. |
| F2 | Medium | `crates/ppe/src/http_hyper.rs` | Fix | `praxis_policy_core::http_addr` is a table with no caller. The bundled transport dialled loopback, RFC 1918, and link-local (including `169.254.169.254`) when `jwks_url` or a token endpoint pointed there. |
| F3 | Medium | `builtins/plugins/delegator-oauth/src/delegator.rs` (leg 2) | Fix | Leg 1 sanitizes IdP errors to the OAuth `error` code. Leg 2 appended `error_description` and, on non-JSON bodies, the raw body. Leg 2 submits the caller's bearer as `subject_token`; a hostile or buggy IdP that echoes it would put that token on `PluginViolation.reason`. Credential exposure, not an auth bypass. |
| F4 | Medium | `builtins/plugins/identity-jwt` (`audiences: []`) | Fix | Same class as the empty-algorithm bug. An omitted or empty `audiences` list set `validate_aud = false`, so a token minted for another app (valid `iss` + signature) was accepted. Config load now requires a list or `skip_audience_validation: true`. |
| F5 | Medium | `crates/ppe-apl-core/src/evaluator.rs` (`eval_comparison`, `NotEq`) | Fix | Missing attributes returned false for every operator, including `!=`. `subject.role != "admin": deny` did not fire when `role` was absent, so it did not match `!(subject.role == "admin")` and an unauthenticated request fell through to Allow. |
| F6 | Medium | `crates/ppe-apl-core/src/evaluator.rs` (`numeric_compare`) | Fix | String tool-args are coerced with `parse::<f64>()`, which accepts `NaN` / `inf`. IEEE `NaN > 10000` and `-inf > 10000` are false, so a max-amount deny skipped them. Treating non-finite as non-numeric (same as `"lots"`) still returned false, so the deny still skipped, and `"Infinity"` stopped matching too (`inf > 10000` is true). A present value that is not a finite number now Denies the phase; `!(...)` cannot invert that into Allow. |
| F7 | Medium | `crates/ppe-core/src/executor.rs` (`extract_erased` → Allow) | Fix | A handler that boxed the wrong `Any` type was logged and treated as Allow in both serial and concurrent paths. A deny the framework could not decode was dropped. Unreadable results are now execution errors; `on_error: fail` halts. |
| F8 | Low | `crates/ppe-apl-core/src/evaluator.rs` (`Stage::Scan`) | Accept with reason | `injection.scan` / `pii.detect` emit a taint label and continue; they do not inspect the field. Tests assert Pass on arbitrary text. The stage is a taint marker so a later `require` can gate; actual detection lives in `plugin(...)`. Operator-visible: a named scan that cannot fail does not block injection by itself. |

### F1 — parallel panic fail-open

Closed. `BranchOutcome::Panicked` and `TimedOut` are now `Decision::Deny`
with a reason that says `fail-closed`. `Aborted` stays a no-op: that is a
sibling that already denied, and short-circuit cancelled the rest on purpose.

Regression: `parallel_panic_is_fail_closed` in
`crates/ppe-apl-core/src/evaluator.rs`. A `parallel:` of `Allow` plus a
plugin that panics must Deny, and the reason must contain `fail-closed`
and `panic`. Removing the Halt conversion makes the test Allow.

`TimedOut` has no per-branch timeout configured today, so there is no
injection test. The arm is fail-closed if it ever fires.

### F2 — bundled transport ignored `http_addr`

Closed. IP literals are checked before connect, including IPv6
literals whose `Uri::host()` still has brackets (`[::1]`,
`[::ffff:169.254.169.254]`). Hostnames go through a DNS resolver that
drops addresses `private_address_reason` would refuse, which is the
connect-time check the table's docs require (a name that rebinds from
public to metadata is refused on the lookup that dials). IPv4-mapped
IPv6 literals are judged by the address they reach.

The connector dials the filtered `SocketAddr` list; it does not resolve
the name a second time. A DNS rebind after this lookup therefore cannot
change the peer we connect to. What remains is that a public address we
accepted could still forward to a private host, which this transport
cannot observe.

A filtered hostname used to surface as `HttpTransportError::Connect`
because hyper-util's Display is `client error (Connect)` and does not
include the resolver error. `classify` now walks `Error::source()`, so
the marker `EgressResolver` writes becomes `Rejected`. That is what
maps to `delegation.egress_denied` / `elicitation.egress_denied` and
what `http_retry` refuses to retry. IP literals never needed the walk:
they take the pre-connect check.

`HyperTransport::with_allow_private_destinations` is the hatch for a
local IdP or a mock on loopback. `install_default_http_transport` does
not set it. A host that injects its own transport never sees this knob;
that transport's egress policy is the one that counts.

Regression: `a_link_local_literal_is_rejected_without_dialling`,
`a_private_literal_is_rejected_without_dialling`,
`loopback_is_rejected_unless_the_hatch_is_set`,
`a_mapped_ipv6_metadata_literal_is_rejected_without_dialling`,
`an_ipv6_loopback_literal_is_rejected_without_dialling`, and
`a_hostname_resolving_to_loopback_is_rejected_not_connect` in
`crates/ppe/src/http_hyper.rs`. Each expects `HttpTransportError::Rejected`
and `may_have_reached_peer() == false`. The connection-refused test now
uses the hatch so it still exercises `Connect` on loopback.
`classify_walks_the_source_chain_for_the_egress_marker` pins the walk
without DNS.

### F3 — leg-2 IdP errors leaked bearer material

Closed. Leg 2 now matches leg 1: OAuth `error` code only, or
`token exchange rejected (HTTP {status})` when the body is not error
JSON. `error_description` and the raw body are not forwarded.

Regression: `a_leg2_rejection_does_not_leak_error_description` and the
updated `a_leg2_rejection_with_an_unparseable_body_falls_back_to_the_status`
in `builtins/plugins/delegator-oauth/tests/oauth_e2e.rs`. Both plant a
token-shaped string in the IdP body and require it absent from the
violation. Reverting the sanitization makes those assertions fail.

### F4 — omitted JWT audiences disabled `aud` checking

Closed. `TrustedIssuerConfig::validate` requires at least one
audience unless `skip_audience_validation: true` is set. Setting both
is refused. At verify, an emptied `audiences` field without the skip
flag is `NoAudiences` rather than `validate_aud = false`. A configured
list also requires the token to carry an `aud` claim
(`set_required_spec_claims`); jsonwebtoken otherwise skips audience
checking when the claim is absent.

Breaking for a config that listed no audiences. The operator-visible
hatch is `skip_audience_validation: true`, which accepts a token minted
for any app (or none). Without the hatch, a missing `aud` is refused
the same as a mismatch (`auth.audience_mismatch`).

Regression: `each_malformed_config_is_refused_at_load_with_a_message_naming_the_fault`
covers omitted and empty lists; `empty_audience_list_rejects_the_token`
covers the public-field hole; `a_token_with_no_aud_claim_is_refused`
covers an omitted claim; `skip_audience_validation_accepts_a_token_minted_for_another_app`
and `skip_audience_validation_accepts_a_token_with_no_aud_claim` pin the
hatch. Removing the load check without the skip flag makes those load
tests build.

### F5 — `!=` on a missing attribute did not deny

Closed. `eval_comparison` returns true for `NotEq` when the key is
absent, matching `!(x == y)`. Equality, membership, and order stay
false on missing, as before.

Regression: `missing_key_not_eq_is_true` and
`missing_attribute_not_eq_deny_fails_closed` in
`crates/ppe-apl-core/src/evaluator.rs`. An empty bag against
`subject.role != "admin": deny` must Deny; the same rule with
`subject.role = "admin"` must Allow.

### F6 — non-finite string amounts bypassed numeric deny rules

Closed. An order comparison on a present value that is not a finite
number Denies the phase. Returning `false` skipped `args.amount >
10000: deny`; returning `true` would invert under `!`. The Deny
reason says `fail-closed` and names the key. Missing amounts stay
false, as before (F5).

Regression: `non_numeric_amount_order_deny_fails_closed` and
`when_unorderable_amount_is_fail_closed` in
`crates/ppe-apl-core/src/evaluator.rs`. `"NaN"`, `"Infinity"`,
`"-Infinity"`, `"lots"`, and the matching `f64` values against
`args.amount > 10000: deny` must Deny, including under `!(...)`.
A finite `"5000"` still Allows; a missing amount still Allows.
Treating the comparison as false makes those assertions Allow.
Integers whose magnitude exceeds 2^53 are Unorderable on mixed
int/float (and on string-encoded integers), same as `NaN`:
`mixed_int_float_order_on_large_integers_is_fail_closed` and
`a_string_encoded_large_int_does_not_round_through_f64`.

### F7 — unreadable handler result was Allow

Closed. Serial and concurrent paths treat `extract_erased` returning
`None` as `PluginError::Execution`. `on_error: fail` in a blocking phase
halts; Ignore/Disable remain the documented knobs.

Regression: `a_concurrent_unreadable_result_under_fail_is_fail_closed`
and `a_serial_unreadable_result_under_fail_is_fail_closed` in
`crates/ppe-core/src/executor.rs`. A handler that boxes `u8` instead of
`ErasedResultFields` must halt under Fail. The Ignore companion test
pins that the hatch still works.

### F8 — `injection.scan` / `pii.detect` are taint markers

Accepted with reason. The evaluator comment states the actual
detection lives in `plugin(...)` variants. Closing this would mean
rejecting the stage at parse (breaking policies that use it as a taint
label) or shipping a scanner in-tree. Operator-visible consequence: a
pipeline that only scans, and never `require`s the taint or calls a
scanner plugin, does not block injection or PII.

## Deliberate fail-open (accepted with reason)

These are operator-visible knobs, not defects. Closing them would remove
a documented choice.

| Knob | Operator-visible consequence | Where |
|---|---|---|
| CEL / OPA `on_error: allow` | A runtime eval error (missing key, non-bool result) becomes Allow. Compile errors, Cedar eval errors, and OPA undefined still Deny. Logged at `error!` as fail-open. CEL cache-full under this knob also Allows; OPA cache-full still Denies. | `builtins/pdps/cel`, `builtins/pdps/opa` |
| Plugin `on_error: ignore` / APL `on_error: continue` | That plugin's deny or error does not halt the route. A later `require` or implicit allow can proceed. Delegate `on_error: continue` also swallows Deny, so the original bearer may continue. | `crates/ppe-core/src/executor.rs`, APL `delegate(..., on_error: continue)` |
| Plugin `mode: audit` / `transform` / `fire_and_forget` | Explicit Deny is suppressed (`can_block` is false). Identity JWT in audit mode cannot enforce. | `PluginMode::can_block` |
| JWT `skip_audience_validation: true` | Any `aud` (or none) is accepted if signature / `iss` / `exp` / `nbf` hold. | `identity-jwt` |
| JWT `insecure_http: true` on JWKS | Plaintext JWKS; MITM can swap keys. Default false. | `DecodingKeySource::JwksUrl` |
| OAuth `insecure_http: true` | Client secret + subject token over HTTP. Default false. | `delegator-oauth` |
| OAuth IdP omits `scope` | Subset check is skipped; requested scopes are recorded as granted (RFC 6749 “omitted = granted as requested”). | `delegator.rs` |
| Delegated-token cache `ttl_ceiling_seconds` | A cached token stays usable after an IdP-side revocation until the entry retires. Off unless `cache:` is enabled. | `delegator-oauth` |
| JWKS failed refresh keeps old keys | Withdrawn keys stay valid until a successful fetch (`refresh_secs`). | `identity-jwt` |
| `delegation_without_identity_resolution` | Config-load *alarm*, not a refused start. A `delegate` step can run without `identity:` having validated the inbound token; the IdP is the remaining backstop. | APL config visitor |
| Executor `OnError::Ignore` on concurrent panic | A plugin that declared Ignore and then panicked is skipped. Fail is Deny (`plugin_panic`). | `crates/ppe-core/src/executor.rs` |
| `restrict.on_empty: fallback` | Host may use the unconstrained backend set if the constraint prunes everything. Default is deny. | `constraint.rs` |
| JWT `leeway_seconds: 0` | Means “use the 60s resolver default”, not zero skew. Strict `exp`/`nbf` cannot be configured as zero. | `identity-jwt` |
| Identity omitted on a route | Payload flows through unauthenticated; needs `require(authenticated)`. | `RouteIdentityConfig` |
| `plugin_settings.fail_on_plugin_error` | Ignored. Operators may think it fail-closes; it does not. | `engine.rs` |
| APL empty rule list | Phase default-allows. | `evaluate_rules` |
| F8 scan stages | Taint only; see above. | `Stage::Scan` |

Cedar has no `on_error: allow`. An evaluation error Denies even when a
sibling permit fired (`evaluation_error_denies_even_when_a_permit_fired`).

## Rejected as false positive / already closed

| Claim | Why it is not a finding |
|---|---|
| Empty JWT `algorithms` = any algorithm | Config load rejects an empty list. Verify path is `NoAlgorithms`. Tested. |
| Missing `nbf` | `validate_nbf` is on. Tested. |
| `delegation.depth` wrap | Saturating conversion. Tested. |
| Orchestrator outcome paired off index | Keyed `BTreeMap`; length mismatch is `executor_invariant` Deny. |
| PDP `PdpError::Dispatch` becomes Allow | Evaluator `pdp_error_is_fail_closed`. |
| Cache serving the wrong caller's token | Cache key HMACs the bearer, delegator identity, audience, and scopes. E2E isolation test exists. |
| `alg=none` | `jsonwebtoken` 10.4 has no `Algorithm::None`. |

## Surfaces reviewed without a new accepted finding

- `crates/ppe-apl-core/src/parser.rs` — quote stripping shares one
  helper; a lone quote no longer slices `1..0`. Glob and default-deny
  fallthrough were not found to invert a match.
- `builtins/plugins/identity-jwt` — empty algorithms, `nbf`, JWKS
  refresh floor, unknown config keys. Empty audiences is F4.
- `crates/ppe-core/src/executor.rs` / `engine.rs` — Fail/Ignore pairing
  and the invariant guard. Unreadable results are F7. The remaining
  fail-open is the Ignore knob above.
- PDP resolvers — Cedar fail-closed override is tested; CEL/OPA
  `on_error: allow` is the documented knob.
- `builtins/plugins/delegator-oauth` — missing audience still rejects;
  omitted IdP `scope` is the documented RFC 6749 trust.
