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

> **Upgrading a 0.1.0 configuration?** `docs/upgrade-apl.md` lists every key and
> form that must be rewritten, with a before and an after for each. This release
> removes ten configuration keys, changes the default dispatch mode, and tightens
> the policy language's lexical rules, so a 0.1.0 document does not load unchanged.
>
> For what the language accepts now, rather than what changed,
> `docs/apl-grammar.md` is normative. It replaces a grammar that existed only as
> comments inside the parser.

### Added

- **`docs/apl-grammar.md`, the grammar as a document.** APL's grammar lived in
  comments beside the parser, and those comments were wrong on four counts: they
  described steps, pipe chains, `in` / `not in` / `exists()` and
  `sequential:` / `parallel:` as rejected, long after each was implemented. There is
  now one normative document, with the EBNF, the lexical rules, one precedence
  table, a per-position table of what each of the three positions accepts, the YAML
  shape, hook mode's key set beside policy mode's, and the surviving warts with the
  reason each survives.

  `crates/ppe-apl-core/tests/conformance/` is what holds the parser and the document
  in agreement: one accepted and one rejected case per production, per documented
  wart, and per breaking change, with each rejection asserting on the message rather
  than only on being an error.

- **`response:`, the custom denial block, documented at last.** It shipped in 0.1.0
  undocumented. A `response:` block on a route, a bundle, a `global.defaults.<entity>:`
  entry, or `global:` supplies the status and body a denial renders, and the
  most-specific layer wins on collision. `None` leaves the host's default denial
  behavior. Its resolution rule changed in this release too, which the Changed
  section covers.

- **Differential tests across Cedar, CEL, and OPA.** The three PDP resolvers each had their own suite; nothing checked that they agree on the same `AttributeBag`. `ppe-pdp-diff` feeds one bag and an equivalent policy intent to all three and compares verdicts and cause kinds. The shared semantic subset (bool, int, string, non-empty string set) must agree. Known splits — float claims, whole-number floats, Cedar resource floats, empty sets, missing collections, missing `subject.id` — live on an allowlist with a reason. An unlisted disagreement fails `make test`. Adding a fourth builtin PDP without a harness driver fails a facade test. ([#25](https://github.com/praxis-proxy/policy/issues/25))

- **Delegated tokens can be reused until they expire.** The OAuth delegator runs one RFC 8693 exchange per `delegate` step; a `cache:` block lets it serve a token it already minted instead. Off unless enabled, and then only for `subject: this_workload` and `client`, whose number of cache entries is bounded by configuration rather than by the caller population. `user` and `caller_workload` are opt-in through `cache.subjects`. Concurrent requests for one uncached key produce one exchange rather than one each, and a failed exchange is not stored. A cached token stays usable after an `IdP`-side revocation until its entry retires, which `cache.ttl_ceiling_seconds` bounds. ([#30](https://github.com/praxis-proxy/policy/issues/30))

- **A route that delegates an unvalidated credential is reported at config load.** A `delegate` step whose subject exchanges the caller's own token relies on identity resolution having checked it, but `identity:` is per-route and optional, so a route can reach the delegator with a token this process has not validated. Loading the config now warns under `alarm = "delegation_without_identity_resolution"`, naming the route and the delegate plugins on it. `subject: this_workload` is excluded, since it carries no inbound credential. ([#30](https://github.com/praxis-proxy/policy/issues/30))

- **`http.response`, the return half of the L7 path.** `http.request` had no counterpart because authorization is an admission check that belongs entirely before the request is forwarded. Response filtering is not: stripping a header the upstream set, enforcing a content type, and attaching labels all belong after. Header and extension filtering only, since no response body exists in the model yet and the payload is unused on this path. A `global:` block carrying `result:` or `post_invocation:` steps now installs a `Post`-phase handler under the same `http` / `*` coordinates the request hook uses; a policy that only authorizes gains nothing and installs nothing. PPE defining and routing a hook does not oblige a host to fire it, so a host that never does sees no change. For the host that does adopt it: a `global:` block whose post steps were previously inert on the entity-less HTTP path becomes live the moment the hook is fired, and `result.*` keys do not exist for a request carrying no entity, so a step reading one denies. Check what the global post block does before firing.

- **`http.status`, the response status a post-phase policy can read.** The HTTP
  model carried the request line and both header maps but no status, so a rule
  like `http.status >= 500: deny` had nothing to read and a response-phase policy
  could not act on what the upstream returned. `HttpExtension` now carries
  `status: Option<u16>`, and it reaches the attribute bag as an integer under
  `http.status`, so ordering and equality predicates both compare numerically. The
  host populates it on the response invocation only, the way `response_headers` is
  already populated, so the key is absent on the request half. A missing bag key
  makes a comparison false, which means a status rule placed under
  `pre_invocation:` is inert rather than denying; keep it under
  `post_invocation:`. It rides the `read_headers` capability with the rest of the
  `http` slot, and it is omitted from serialized output when unset, so a host that
  never sets it is unaffected. ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **`http:`, a route selector for generic HTTP requests.** L7 traffic carries
  no entity, so it resolved no route at all: no route-level plugins, no group
  membership, no static tags, no route-level `authentication:`. A route can now
  select on the request line, in three shapes. A bare path (`http: /healthz`)
  and a list (`http: [/livez, /readyz]`) match exact paths; the map form asks
  for a segment-boundary prefix (`http: {path_prefix: /v1/files}`) or an exact
  path (`http: {path: /v1/files/manifest}`), either optionally narrowed by
  `method:`. It requires `engine_settings.dispatch: policy`, which is the
  default, so an `http:` route is live as written; a load reports a set of
  `http:` routes that declares no catch-all, naming that a request matching
  none of them is governed by the global policy instead. A prefix matches at
  segment boundaries exactly as the gateway's own router reads one, so `/api`
  covers `/api`, `/api/`, and `/api/v1` but not `/apikeys`, and a trailing
  slash is insignificant. An exact path outranks every prefix, the longer
  prefix wins among prefixes, and a route narrowed by `method:` outranks the
  same path left open for the methods it names, with the narrower of two
  narrowings winning a method both name. Declaration order decides nothing
  among them, and among two selectors naming the same number of methods it is
  what is left. An exact path is compared byte for byte against the path the
  request arrived on, the way the gateway router's own exact arm compares it,
  so `/admin` and `/admin/` are two routes answering for two different
  requests.

  Two things worth knowing before writing the first one. An `http:` route
  carrying a policy body dispatches that body in place of its structural plugin
  chain, the same way an entity route does, so the `plugins:` the route also
  lists run only where a policy step names them; a load names each `http:`
  route that applies to. And a route's `authentication:` list applies only
  where the host supplies the request line at the identity hook. Where it does
  not, the global list governs exactly as it does today, and the engine now
  warns once naming the route, so which of the two a deployment is in is
  readable from what the engine emits rather than from the host's source.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

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

- **`require(P)` is a predicate, and means `!P`.** It was a rule-level shorthand
  with its own hand-written parser, which read a comma-or-pipe list of bare
  attribute names and nothing else. So `require(delegation.depth < 3)`,
  `require(!delegated)`, `require(a) & b` and `require(a) | require(b)` were all
  unwritable, not because any of them is ambiguous but because there was no code
  path to them. They parse now.

  **Every form already in use compiles to the tree it compiled to before**, and
  that is structural rather than a claim: negation is normalized down to the
  leaves, folding `!IsTrue` to `IsFalse` and applying De Morgan, so `require(a)` is
  `IsFalse(a)`, `require(a, b)` is `Or([IsFalse(a), IsFalse(b)])` and
  `require(a | b)` is `And([IsFalse(a), IsFalse(b)])`. Those three were the whole
  of what the old parser accepted, so no deployed policy changes what it decides.

  Two smaller changes come with it. Mixing `,` and `|` inside the parens used to be
  refused outright, because the old parser tracked one separator and had no
  precedence to appeal to; the comma binds lower than `&` and `|`, so
  `require(a, b | c)` is `!(a & (b | c))`. **A configuration that was rejected for
  mixing them now loads and decides something**, so read one before upgrading. And
  a `require(...)` rule's action can only be `deny`: the construct states what must
  hold and refuses when it does not, so `require(a): allow` is a contradiction and
  fails the load naming the inversion. The restriction is on the rule shape, so it
  holds in all three spellings: the string form, `when:` / `do:`, and the
  multi-effect shorthand. Nested inside a larger predicate, `require` is only the
  negation it desugars to, so `a & require(b): allow` stays legal.

- **A field operation in rule position is rejected.** `result.ssn | redact` where a
  rule belongs used to compile as a disjunction of two truthy attributes and take
  the default deny, so a chain one position too high enforced something its author
  never asked for. It now fails the load, naming the position and pointing at
  `args:` and `result:`. This is a property of the rule shape too, so it holds in
  all three spellings. A legal disjunction of two attribute paths
  (`result.x | result.y`) is untouched: what marks a field operation is a field
  head with a stage beside it, not a `|`.

- **`run(name)` is the only form that invokes a plugin.** `plugin(name)` was a
  second spelling for it in both step and stage position, so a reader had to know
  both and a document could use either. It is refused in both positions now, naming
  `run(name)`. The word survives as a noun: `plugin:` as a keyword argument inside
  `delegate(...)`, and the `delegate:` map form, both still parse.

- **An empty stage in a pipe chain is rejected.** A leading, trailing or doubled
  `|` left a position with no stage in it, and those positions were skipped, so a
  chain compiled shorter than its author wrote it. `parse_pipeline("")` still
  answers with an empty pipeline, because a caller hands it a field value that may
  be absent and absent is not malformed; what is refused is naming a stage and then
  leaving a position beside it empty.

  The `validate(name)` refusal now names `run(...)` rather than the removed
  spelling among its alternatives.

- **One rule for a quoted literal, and escapes that unescape.** Quoted text was
  read in ten places with three different escape rules and two different answers
  for an unterminated quote. The lexer processed no escapes at all, so there was no
  way to write a quote inside a literal delimited by that quote; the
  delegate-argument splitter let a backslash protect the next character; the pipe
  finder skipped two bytes after one. Two splitters treated an unterminated quote
  as an error and two silently swallowed the rest of the line, which is how a rule
  could lose its action with no diagnostic. Every site now reads a literal the same
  way.

  The escape set is exactly `\\`, `\'`, and `\"`. **Breaking for policy text that
  carries a backslash**, and this is the one change in the release that can break
  text which looks correct: a backslash used to pass through untouched, so a regex
  character class worked by accident. Write `regex("\\d+")` where you wrote
  `regex("\d+")`; the single form now fails the load naming the unrecognized
  escape rather than being reinterpreted. `\n` and `\t` are deliberately not
  escapes: a deny reason rides in a violation field a host renders, so a multi-line
  reason there is a display problem rather than a capability.

  Two things that were quietly wrong are now right. A closing paren inside a
  literal is content, so `deny("blocked (see policy)")` loads where it used to be
  refused as a malformed call. And a lone quote in a field stage is an unterminated
  literal, where `regex(")` used to compile to a pattern matching one quote
  character. A stage argument may still carry no quotes at all, so
  `enum(low, medium, high)` and `regex(^[A-Z]+$)` are unaffected.

- **An attribute path is a production, so a path that names nothing fails the
  load.** `a..b`, `a.`, `.a`, `data.t[]`, `data.t[a:b]`, and `data.t["a]"]` all
  lexed clean and then resolved to an absent attribute, which made a predicate
  silently false and a `require` silently deny: a policy that never matched and
  never said why. Each is now rejected naming the production it broke. A quoted key
  inside a subscript was the quiet one, since `data.t["a"]` looked up the four
  characters `"a"` including the quotes and so never matched anything; write
  `data.t[subject.tenant]` with the inner path unquoted.

  The rule splitter counts brackets now, which its two siblings already did. A
  colon inside a subscript used to be the only depth-zero colon on a
  bare-predicate line, so the rule split into a predicate and a nonsense action and
  the error named neither brackets nor quotes.

- **`not` is reserved, and a doubled boolean operator names the single form.**
  `not authenticated` used to read as an attribute called `not` followed by a stray
  token, so the error mentioned neither `not` nor `!`. It now names `!`. The
  `not in` phrase is unaffected, and it is the one place the word is legal; a path
  beginning `not.` is rejected too, which used to slip through because the keyword
  table compared the whole path. `a && b` and `a || b` name `&` and `|` instead of
  dumping a token. Spacing around an operator is not significant and never was,
  despite a comment in the lexer claiming a caller enforced it.

- **A number has one shape, and a position is a character offset.** Digits are
  required on both sides of the dot, so `1.` is rejected; `.5` was already rejected
  while `-.5` parsed as a float, and both now name the number. An exponent is
  rejected by name rather than producing a trailing-token error that never
  mentioned it. `007` is still the integer 7, deliberately: reading it as octal
  would alter a value silently.

  Lexer positions count characters rather than bytes, and name the real character.
  A non-ASCII identifier was reported at a byte index, and the character was
  rendered by casting a single byte to `char`, so the message named a character
  that was not in the input at all.

- **`engine_settings.dispatch:` defaults to `policy`.** It defaulted to `hooks`,
  where every declared plugin fires at every hook its own `hooks:` names. The
  document a policy engine is written in is the `routes:` / `groups:` / `global:`
  half, and defaulting to the other one meant the common config was the one whose
  policy did nothing until an operator found the key naming the mode. A config
  carrying `routes:`, `groups:`, or `global:` now needs no `engine_settings:`
  block at all.

  **Breaking for existing config**, and the widest break in this release. A config
  that declared plugins and relied on the old default fired all of them; under
  `policy` a plugin runs only where a step names it. `dispatch: hooks` restores
  the old behavior exactly and is the one-line upgrade for a config that wants it.
  Two checks make the difference visible rather than silent, below.

- **A declared plugin no policy reaches fails the load, by name.** Under
  `dispatch: policy` a plugin runs only from a step that names it, so a plugin
  nothing names is inert and every request it was meant to govern is ungoverned.
  The load now fails, naming each unreached plugin. The reference set is wider
  than a `run(name)` step: an `authentication:` list at any scope, a `delegate`
  call, and an elicitation verb's handler each reach a plugin, and a step under
  `global.authorization:` reaches one for every route it stacks onto. The check is
  per plugin rather than per config, so a config naming one of three still reports
  the other two. A host that registers no orchestrator gets a narrower version
  from the engine itself: policy mode, plugins declared, and no `routes:`,
  `groups:`, or `global:` block to name them from.

- **A plugin reached on fewer hooks than it declares is reported at load.** A
  plugin declaring three hooks and named by a step on one runs on that one, where
  hook dispatch ran it on three. Narrowing is often what an operator meant, so it
  warns rather than failing, under `alarm = "plugin_narrowed_by_policy"`, naming
  the plugin and every hook left uncovered. Add a step on the uncovered hooks, or
  narrow the plugin's own `hooks:` to match what the policy asks for.

- **A request the engine cannot identify is denied rather than dispatched against
  absent context.** A request carrying no `meta.entity_type` / `meta.entity_name`
  resolves no route, and it used to fall through to every entry registered on the
  hook. In the mode whose premise is that a policy decides, that both ran plugins
  against context which was not there and let a caller skip every rule by omitting
  metadata. It is now denied with the violation code `unidentified_request` and a
  400-class proto code, distinct from a policy's own deny because no rule was
  reached. **The guard is the configuration, not the mode**: a config declaring no
  policy at all passes the request exactly as before, so a deployment that has not
  written policy yet sees no new denials. An HTTP request is unaffected either way,
  since it names its entity type and resolves the global annotation.

- **The compiled IR stops speaking a vocabulary no config may use.** `Phase::Policy`
  and `Phase::PostPolicy` are `Phase::PreInvocation` and `Phase::PostInvocation`;
  `CompiledRoute.policy` and `.post_policy` are `.pre_invocation` and
  `.post_invocation`. The three config structs whose Rust field was `identity`
  behind `#[serde(rename = "authentication")]` now name the field
  `authentication`, matching the key a document writes. `CompiledRoute.args` and
  `.result` were already right and did not move.

  The old spellings were the config keys this release removes, so the IR was the
  last place naming a form a document is now rejected for writing. **Breaking** for
  Rust callers reading those fields or matching those variants. `Phase` and
  `CompiledRoute` both derive `Serialize`, so the **serialized keys change too**: a
  phase serializes as `pre_invocation` / `post_invocation` rather than `policy` /
  `post_policy`, and a serialized `CompiledRoute` names the two step lists the same
  way. A consumer reading either shape off the wire has to move with it. The
  `authentication` rename is Rust-only, since the serde key was already
  `authentication`.

- **A plugin only an unreachable layer names fails the reachability check.** The
  per-plugin check tallied a layer's references as soon as the layer compiled,
  which treated every compiled layer as executable. A group installs no handler
  and matches no request on its own, and an entity default only stacks onto routes
  of its type, so a plugin named in a group nothing joins, or in a default for an
  entity type no route declares, has no dispatch path and reported as reachable
  anyway. The tally now comes from the effective route, at the point a handler
  installs, so it counts the layers a route actually inherits.

  `global:` keeps its exception, and it is the only one: it installs the
  entity-less HTTP catch-all, which governs every request that resolves no route,
  so a config with no `routes:` at all still reaches its plugins.

  **Breaking for existing config**: a document that declares a group or an entity
  default no route reaches now fails the load naming the plugin, where it used to
  load with that policy dead. Join the group from a route, or drop it.

- **A route joining a group through `groups:` inherits that group's
  `authorization:`.** `groups: hr` and `meta: { tags: [hr] }` are documented as
  resolving identically, and they did not. Identity resolution read both
  spellings; the orchestrator that layers a bundle's policy read `meta.tags`
  alone, so a `groups:` membership inherited the group's `authentication:` and
  none of its `authorization:`.

  With the activation lists gone, authorization layering is most of what a group
  is for, so this was a fail-open rather than a metadata asymmetry: no layer
  contributed anything to the route, so no handler installed and the route was
  governed by nothing at all. Both chains now read one ordered stream of
  membership names, `meta.tags` in declaration order then `groups:`, which is
  also what makes `replace_inherited:` well defined at bundle scope. A name
  written in both spellings is one membership, so the group's steps run once.

  **Breaking for existing config**: a route joining a group through `groups:`
  begins enforcing that group's `authorization:`. If you were relying on the old
  asymmetry, that route will start denying what the group denies. Move the route
  out of the group, or move the policy off the group, whichever you meant.

- **A policy term with no visitor to compile it fails the load.** `authorization:`,
  `args:`, `result:`, `response:`, and the `global:` wiring keys are accepted at
  every section that can carry them, and their bodies live only in the raw
  document: the typed config model has no field for any of them, because the APL
  runtime's config visitor is what reads them. With no visitor registered the load
  committed the typed config and returned success having dropped every one, so a
  route declaring `authorization: [run(audit)]`, or an unconditional `deny`,
  loaded clean, installed no handler, and enforced nothing at all. The load now
  names the section, the keys, and the two ways out: register the visitor
  (`praxis_policy_apl_runtime::register_apl`), or write `dispatch: hooks`.

  The reachability backstop did not cover this and could not. It passes as soon as
  a document declares any route, group, default, or global authentication block,
  which the document in question does.

  The check runs before the typed config is installed, so a rejected document
  never becomes the live snapshot. It reads the key model rather than a written
  list, so a policy term added later cannot slip past it. `parse_config` is
  untouched: it parses and validates a document without loading it, and a host may
  well parse one for an engine that does have a visitor.

- **The two dispatch modes reject each other's keys by name.** Each used to
  ignore the other's silently, which is how a config asked for one mode's
  behavior and got the other's. Under `engine_settings.dispatch: hooks`,
  `routes:`, `groups:`, `global:`, and `global.defaults:` are load errors: hook
  dispatch resolves none of them, so a route written there matched nothing and
  reported nothing. Under `dispatch: policy`, a per-plugin `conditions:` is a
  load error: a policy decides dispatch, so the condition was never consulted.
  The error names the key and the mode that rejects it.

  A per-plugin `priority:` is a load error there too, for the same reason. It
  orders the entries one hook holds, and policy dispatch never runs more than one
  at a time: effects run in the order the document writes them, a `run(name)`
  step invokes the single plugin it names, and the runtime hands the executor a
  one-entry slice. Identity resolution is declaration order and reads no priority
  either. The key was accepted and inert, which is the ambiguity this release set
  out to remove. Order the steps under `authorization:` instead, or write
  `dispatch: hooks` to order by priority.

  Both checks read the document, so only a *declared* key is refused. The typed
  `PolicyConfig` boundary refuses the activation lists, `conditions:`, and the
  hook-mode scopes, but not `priority:`: the field is defaulted, so a host that
  set the default cannot be told apart from one that set nothing.

  **Breaking for existing config**: the mode is checked against the effective
  value, written or defaulted. A config declaring `routes:`, `groups:`, or
  `global:` needs nothing written, since `policy` is the default. One that
  declares plugins with their own `conditions:` or `priority:`, or relies on
  every declared plugin firing at the hooks it names, must write
  `dispatch: hooks`.

- **A tag bundle's `authentication.replace_inherited: true` is honored, and what
  it drops is reported at load.** The flag was read at bundle scope and only
  acted on at route scope, so writing it on a bundle was a documented no-op.
  It now drops everything the route accumulated before that bundle: the global
  `authentication:` layer and any bundle the route joined ahead of it. The
  bundles after it and the route's own block still append, and a route's own
  flag still drops every inherited layer. Bundle order is `meta.tags` in
  declaration order followed by `groups:` in declaration order, so which bundle
  replaces and which survive it are both readable from the document.
  **Breaking for existing config**: a config that already sets the flag on a
  bundle gets a route that authenticates with less than it did before, silently
  as far as the route's own block shows. That is why the load now warns under
  `alarm = "authentication_replaced_above_the_route"`, once per affected route,
  naming the route, the section that set the flag, and the steps the route no
  longer runs. Read those lines before upgrading: an authentication-removing
  control moved from route-local and visible to inherited and remote, and the
  route's author is not the person who wrote the section it comes from.

- **`attribute_files:`, `pdp:`, and `session_store:` are `global:` keys, and
  nowhere else.** `attribute_files:` was read only as `global.apl.attribute_files`,
  so it moves with the wrapper: write it as `global.attribute_files:`. `pdp:` and
  `session_store:` were accepted on a route, under `global.defaults.<entity>:`,
  and on a bundle, where the compiler dropped them and the load warned; they now
  fail the load naming the key. A PDP, the session store, and the static
  attribute tree are process-global, so the three engine blocks agree on their
  own scope for the first time. The diagnostic paths follow: an error that said
  `global.apl.attribute_files` now says `global.attribute_files`.

- **A key nothing reads now fails the load at every scope, not only on a
  route.** `GlobalConfig` and `PolicyGroup` drop an unknown field, so a
  misspelled `authorizaton:` under `global:`, `global.defaults.<entity>:`, or a
  bundle used to load clean and enforce nothing. Each of those scopes now
  reports every unrecognized key it carries, naming the section, the same way a
  route already did. A visitor's `extra_route_keys` are honored at those scopes
  too, so an out-of-tree orchestrator's own block stays loadable wherever it is
  written.

- **A `response:` block resolves by one rule.** It was read from the section and,
  failing that, from inside `apl:`, with the section winning — the inverse of the
  precedence the wrapper itself had. With no wrapper there is one source: the
  section. A `response:` nested inside anything is an unknown key.

- **`HookFamily::for_entity` reports an unmapped entity type instead of
  defaulting to CMF.** It returned `HookFamily` and treated every entity type
  other than `http` as the CMF family, so a route on an entity type nobody had
  mapped yet would install a handler that reports the CMF family and hands its
  plugins a chat message no host filled. The `else` also hid the omission from
  the compiler: the closed matches elsewhere in the crate flagged a new family,
  this function did not. It now returns `Option<HookFamily>` over the same
  entity types `hook_pair_for_entity` maps, and the visitor's install path logs
  and skips an unmapped one, which is what it already does for an entity type
  with no hook pair. **Breaking** for a caller that used the returned family
  directly; the fix is to handle `None` rather than assume CMF.

- **`HookFamily` is `#[non_exhaustive]` and `hook_type_name` is public.** The
  enum was public and exhaustive, so a third payload family would have been a
  breaking change for every downstream `match` on it, and its only interesting
  method was private, so a host could hold one and not ask it anything.
  `#[non_exhaustive]` is itself **breaking** for a downstream exhaustive
  `match`, which is the argument for doing it while the enum has two variants
  rather than at the moment a third one lands.

- **The generic-HTTP hooks are their own family: `http.request` and
  `http.response`.** Both used to be spelled `cmf.http_request` and
  `cmf.http_response` and both were typed on `CmfHook`, whose payload is an LLM
  chat message. Nothing on the HTTP path fills it, so a content-inspecting
  plugin written against `CmfHook` could register on the HTTP response hook,
  scan a fabricated message, find nothing, and report clean. An always-passing
  scanner is worse than no scanner. The family now has its own `HttpHook` type
  and an `HttpPayload` that carries no fields, so what a handler reads about an
  HTTP exchange is the `HttpExtension` it is passed and nothing pretends to hold
  content. The metadata rows moved out of the CMF table into the HTTP family's
  own, with the entity type and phases they already had: `http.request` is `Pre`
  under `entity_type: http`, `http.response` is `Post`. **Breaking for existing
  config**: a `hooks:` entry naming `cmf.http_request` or `cmf.http_response`
  now fails to load, and the refusal names the replacement. Rust callers rename
  `HOOK_CMF_HTTP_REQUEST` / `HOOK_CMF_HTTP_RESPONSE` to `HOOK_HTTP_REQUEST` /
  `HOOK_HTTP_RESPONSE`, which now live in `praxis_policy_core::http_hook`.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A plugin on an HTTP route receives the HTTP payload.** Dispatch follows the
  route's hook family now, so the plugins an `http:` route's policy steps name
  are invoked through `HttpHook` and handed an `HttpPayload`. Before this, every
  APL-dispatched plugin went through `CmfHook`, which meant a scanner named by
  an HTTP route's policy scanned a chat message the HTTP path never filled and
  reported clean. **Breaking for a host firing the HTTP hooks**: fire them as
  `invoke_named::<HttpHook>("http.request", HttpPayload, ...)` rather than
  through `CmfHook`, and a plugin registered on `http.request` or
  `http.response` implements `HookHandler<HttpHook>` rather than
  `HookHandler<CmfHook>`. Nothing about MCP or A2A dispatch changes: an entity
  route still builds a CMF invoker and its plugins still receive
  `MessagePayload`, field stages included. A handler that needs to know which
  half of an exchange fired reads `http.status`, which the host sets on the
  response invocation only; `PluginContext` carries no hook name, and the hook
  metadata documentation no longer claims it does.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **Registration refuses a handler the hook's payload does not fit.** A
  dedicated `HttpHook` type does not by itself keep a CMF plugin off an HTTP
  hook: `register_for_names::<H>` never consults `H`, and a plugin declared in
  YAML reaches the registry through a factory that names no hook type at all,
  which is the path the hazard travels. Each hook's metadata row now records
  the family whose payload the name carries, read off the hook type rather than
  written as a string, and registration compares it against the family the
  handler reports. A CMF handler taking `http.request` or `http.response` is
  refused at load, naming the plugin, the hook, and both families, instead of
  registering and scanning a message nothing filled. Registration stays
  all-or-nothing: a refused name leaves no part of that plugin registered. The
  check is load-time, not compile-time, and it covers what reaches the hook
  index, which is every path a plugin registers through. A host that installs a
  handler with `annotate_route` writes into the route-annotation map instead
  and is not checked there. A row with no family accepts a handler of any
  family, `HookMetadata::permissive()` included, so the open hook registry
  stays open and a host's own hooks need no type of their own. **Breaking for
  Rust callers**: `HookMetadata` carries a third field, and a `define_hooks!`
  row takes an optional `family:` naming the hook type.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **An `args:` or `result:` block on an `http:` route is refused at load.** A
  field stage addresses a path inside a message, and a generic HTTP request
  carries none, so such a stage would read nothing and rewrite nothing. The load
  now fails naming the declaration and the block, and points at
  `pre_invocation:` / `post_invocation:` with the `http.*` attributes instead.
  It covers both scopes that reach HTTP routes and nothing else: a route's own
  policy block and `global.defaults.http`. A `global:` block carrying `args:`
  still loads, because those stages are meaningful for the entity routes the
  global layer also stacks onto.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A declared hook name is validated at config load.** `hooks:` carried free strings that nothing checked, so a typo loaded clean and nothing said so. What a typo cost depended on the plugin: a factory that derives its handler names from `config.hooks` (the `audit-logger` and `pii-scanner` reference plugins) registered under the misspelling and never fired, while one that hardcodes its hook name (`identity-jwt`, `delegator-oauth`, `elicitation-ciba`) fired correctly and left the `hooks:` list as decoration that disagreed with reality. Both are now refused, because a `hooks:` entry naming a hook nothing dispatches is a config error either way. An unknown name now refuses the config, naming the plugin, the name, and the nearest name that does dispatch: `tool_pre_invoke` suggests `cmf.tool_pre_invoke`, which is the exact mistake the removed constants and the old `PluginConfig` example taught. A name close to nothing in the table gets no suggestion rather than the least-bad match. **Breaking for existing config** carrying a misspelled or inert hook name. Validation reads the runtime registry, so a host with its own hooks passes once it has registered their metadata — which it must do *before* loading config that names them; registering afterwards is too late and the load refuses. The registry is process-wide while `PolicyEngine` is per-instance, so two engines in one process share one hook table and whichever loads first decides what the second accepts. A config can load under one process layout and refuse under another, such as a host embedding PPE twice or a test binary sharing a process across cases. Register every hook a process uses before loading any config, not only before the config that names them.

- **Both route resolvers take the route already matched.**
  `resolve_plugins_for_entity` and `resolve_identity_plugins_for_route` receive
  the matched route instead of matching a second time, and the identity
  resolver no longer takes an entity type, because a matched route carries the
  one it matched under. The engine used to match once for the annotation lookup
  and again inside each resolver on every cache miss; matching once is also
  what lets the name a request resolved to be the only key the annotation table
  and the route cache ever see, so a request path never becomes a cache key.
  The layering each resolver does (global, entity-type default, group and tag
  bundles, then the route) is unchanged. **Breaking** for Rust callers, of
  which there were none outside this repository's engine; no configuration
  resolves differently.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **`annotate_route` reports whether it replaced a handler.** The annotation
  table was a plain insert, so a second handler at the same `(entity_type,
  entity_name, scope, hook_name)` dropped the first with nothing recording that
  either existed. It now returns whether it replaced one, and the APL visitor
  warns naming the coordinates. The later handler still wins, since a host may
  replace deliberately. **Breaking** for a Rust caller that binds the return
  type; ignoring the value compiles unchanged.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A path normalizer and a route-resolution error are public surface.**
  `praxis_policy_core::http_path::normalize_match_path` reads a request path and
  refuses one it cannot read: query and fragment removed, semicolon path
  parameters stripped, duplicate slashes collapsed, and `.` / `..` resolved
  including their percent-encoded spellings, with nothing ever percent-decoded
  so an encoded separator stays inside its own segment. Those rewriting rules
  mirror the gateway's `normalize_rewritten_path`, which the gateway applies to
  paths it produced itself and never to an inbound one, and the module names its
  source so the two can be compared. Route matching does not read the value it
  returns, and neither does a policy: `http.path` and `meta.entity_name` reach
  the attribute bag as the host set them, and the normalized form is written
  nowhere. What the function does for the engine is the refusal. A path that
  breaks its rules is denied with the stable code `unreadable_request_path` and
  a `400` wherever at least one `http:` route is declared, because a path PPE
  cannot read is one it cannot claim to have matched the router on. With no
  `http:` route declared, nothing about such a request changes.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **A route key nothing reads fails at load, naming the key and the route.**
  `RouteEntry` ignores unknown fields, so a misspelled selector left a route
  matching nothing and a stale key sat there looking effective. A raw-YAML scan
  now refuses a route key nothing consumes, and `ConfigVisitor` gained a method
  reporting the extra route keys its visitor reads, so an orchestrator's own
  block stays loadable. `deny_unknown_fields` cannot do this job: a route
  mapping legitimately carries `apl:`, `response:`, and the flat APL terms the
  visitor accepts alongside the keys the typed struct models. **Breaking**
  where a route carries a key nothing consumes, which was inert before and is a
  typo either way. A host whose visitor reads route keys of its own must load
  through `load_config_yaml`: `parse_config` and `load_config(path)` register no
  visitor, so they scan with the built-in list alone.
  ([#40](https://github.com/praxis-proxy/policy/issues/40))

- **Config validation runs on every load path.** `PolicyEngine::load_config` and `from_config` take a pre-built `PolicyConfig` and ran neither `validate_config` nor the top-level `groups:` merge, so a host building its config in Rust got no duplicate-plugin-name check, no route-shape check, and no group resolution — routes silently lost the plugins and `authentication:` their group was meant to supply. Both now normalize and validate the way the YAML paths do. **Breaking**: a programmatic config with a duplicate plugin name, a malformed route, an unknown hook name, or a route naming a plugin absent from `plugins:` now fails where it previously loaded with the offending piece inert. That last case reaches a host that registers handlers with `register_handler` instead of declaring them under `plugins:` and then names them in a route.

- **`hooks::metadata::lookup` returns `Option<HookMetadata>`.** It used to substitute a wildcard for a name the registry did not hold, so an absent hook and a deliberately unphased one both read as `Unphased` and a caller reading phase could not tell a missing entry from a real one. `HookMetadata::unknown()` is renamed `permissive()` to match: the wildcard is now a default a caller opts into, not the shape of a failed lookup. **Breaking** for Rust callers; `lookup(name).unwrap_or_else(HookMetadata::permissive)` restores the old behavior exactly.

- **`Plugin::initialize_with` is what the engine calls.** It receives the host services the plugin's capabilities allow, and its default forwards to `initialize`, so a plugin needing nothing from the host is untouched. Override exactly one: the default body of `initialize_with` is what calls `initialize`, so overriding it replaces that call.

- **`identity-jwt` refreshes JWKS on demand instead of on a timer**, and `min_refresh_interval_secs` (default 30) is a new knob bounding how often one issuer may re-fetch. `refresh_secs` keeps its meaning as the staleness bound. See the fix below for why the timer went.

- **Unknown keys in the JWT plugin's config are rejected.** The resolver config and each `trusted_issuers` entry default every field, so a misspelling took effect silently, and a misspelled `audiences` turned audience checking off. **Breaking** for a config carrying a key the plugin does not read. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A SPIFFE ID with no trust domain is refused.** `spiffe:///ns/default/sa/agent` carries the scheme but no authority, so it named no trust boundary and the mapper still filed it as a workload identity whose trust domain was the empty string. It now declines, the same as any other non-SPIFFE subject, and a valid candidate behind it still resolves. **Breaking** for a deployment minting such a token, which was never a valid SPIFFE ID. ([#31](https://github.com/praxis-proxy/policy/pull/31))

- **A workload's trust domain is no longer mappable.** It is the authority of the SPIFFE ID, so it is derived from the identity rather than read from a claim. ([#31](https://github.com/praxis-proxy/policy/pull/31))

### Removed

- **`compile_config`, and the second `routes:` shape it defined.** Along with it
  `ConfigYaml`, `CompiledConfig`, and the private `compile_route`. The function
  read a whole document whose `routes:` was a **map keyed by route name**, while a
  real configuration writes `routes:` as a list of selectors, so the project
  defined two incompatible shapes for one key and the one no host could load was
  the one the compiler's tests read. Nothing in production called it: the runtime
  compiles a section's policy block through `compile_policy_block_value`, which
  stays.

  **Breaking** for any Rust caller using it. What the tests wanted from it was
  narrower than a config, and that is what replaces it: `test_util::compile_test_policy`
  returns one compiled route plus the plugin registry its steps name, behind a new
  `test-util` feature on `praxis-policy-apl-core` so a test seam stays out of the
  semver-bound published surface. `ConfigYaml`'s lenient catch-all for unknown
  top-level keys is gone with it and has no replacement, which is the same
  direction as the rest of this release: an unrecognized key is reported, not
  swallowed. The has-APL gate is gone too, so a block declaring no APL term now
  compiles to an empty route rather than being dropped from a map; read
  `declared_phases().is_empty()` for that question.

  `make coverage` gains `--all-features`, without which the newly gated test
  targets would fall outside the coverage floor rather than being measured by it.

 A
  route's, a bundle's under `groups:`, a `global.defaults.<entity>:` entry's, and
  the reserved `all` bundle's were one construct, and under
  `engine_settings.dispatch: policy` all four are now load errors naming
  `run(name)` as the way a policy invokes a plugin. An empty list is refused with
  the rest: it is a shape the mode has no reading for, not a way to activate
  nothing. The `plugins:` **mapping** is untouched and still valid there — it
  overrides `config`, `capabilities`, and `on_error` for a plugin a step already
  names, which is a different construct that happens to share the key. Top-level
  `plugins:`, the declaration block, is untouched in both modes.

  **Breaking for existing config.** What replaces chain-wide activation is a
  `run(name)` step under `global.authorization`, which stacks onto every entity
  route, so a config using the `all` bundle migrates like this:

  ```yaml
  # Before
  groups:
    all:
      plugins: [audit-log]

  # After
  global:
    authorization:
      pre_invocation:
        - "run(audit-log)"
  ```

  A bundle's or a route's list moves the same way, into that section's own
  `authorization:` block. One case has no policy-mode spelling at all: a plugin
  that must fire at a hook no APL block annotates. `engine_settings.dispatch:
  hooks` is the answer for it — the plugin fires at the hooks its own `hooks:`
  declares, narrowed by its own `conditions:`. Both examples under
  `crates/ppe-core/examples/` are exactly that case and now run in hook mode.

  `resolve_plugins_for_entity` loses the four list sources with them, and its
  signature loses the entity type, the matched route, and the request tags,
  which nothing left in it reads. Under `dispatch: policy` it returns nothing.

- **The `http:` route inertness report.** A load reported that `http:` routes
  existed while `engine_settings.dispatch` was `hooks`. `routes:` is a load error
  in that mode now, so a config carrying an `http:` route is in policy mode by
  construction and the report had no reachable input. The report beside it, that
  a set of `http:` routes declares no catch-all, stays.

- **A route's `when:`.** The one removal here that takes a capability with it. A
  route could carry a conditional match expression, and nothing ever evaluated
  it: static resolution carried the string onto every plugin the route resolved
  and no dispatch site read it back. It was not inert in one respect, which is
  the part worth reading before upgrading. `when:` scored a specificity bonus, so
  declaring a narrowing condition made a route win more often, and a config with
  `when:` on one of two otherwise equally specific routes resolved to the one
  that declared it. That bonus is gone with the key, so those two routes now rank
  identically and the first declared wins. **Breaking for existing config**: the
  intent belongs in a `when:` / `do:` step under the route's `authorization:`
  block, which the evaluator does run against the payload the route carries.
  Check any pair of routes that relied on the bonus to order them, because the
  winner changes.

- **`plugin_dirs:`, `engine_settings.parallel_execution_within_band`,
  `engine_settings.fail_on_plugin_error`, and an `authentication:` step's
  `on_error:`.** Four keys the loader parsed and the runtime honored nowhere.
  Three of them warned at load, which put an operator in the worst position: the
  config said one thing, a log line said another, and the behavior was a third.
  The fourth was worse, because a step's key set flattened everything it did not
  model into a forward-compat bag, so a step's `on_error:` and a misspelled
  `confg:` both vanished without a word. Each of the four now fails the load
  naming itself and the spelling that does the job: `plugin_dirs:` becomes
  `register_factory()` plus a declaration in the `plugins:` block,
  `parallel_execution_within_band` becomes `mode: concurrent` on the individual
  plugin, `fail_on_plugin_error` becomes that plugin's `on_error: fail`, and a
  step's `on_error:` is the `on_error:` of the plugin's own `plugins:`
  declaration. `engine_settings:` and a map-form `authentication:` step each
  carry a closed key set now, so a typo in either is a load error rather than a
  silently dropped setting.

  **Breaking for embedders**: `PolicyConfig::plugin_dirs`,
  `EngineSettings::parallel_execution_within_band`,
  `EngineSettings::fail_on_plugin_error`, `RouteEntry::when`,
  `ResolvedPlugin::when`, `RouteIdentityStep::on_error`, and
  `RouteIdentityStep::extra` are all removed from `praxis-policy-core`.

- **`policy:`, `post_policy:`, `identity:`, and `global.policies:`.** The four
  keys that had already been replaced but were still recognized, each by its own
  rejection guard. Every config scope now carries one closed key set, so all four
  fail the load as the unknown keys they are, and the unknown-key error carries
  the replacement: a removed key's message names the spelling to write instead,
  while a plain misspelling gets the accept set and nothing invented. **Breaking
  for existing config**: `policy:` becomes `authorization.pre_invocation`,
  `post_policy:` becomes `authorization.post_invocation`, `identity:` becomes
  `authentication:`, and a bundle under `global.policies:` moves to the top-level
  `groups:` block, dedented one level. `groups:` is now the only place a document
  declares a bundle; the two locations no longer merge, and a name can no longer
  be declared twice with one shadowing the other. A bundle's own contents and the
  way a route joins it by name or by `meta.tags` are unchanged.

  **Breaking for embedders**: the rename tables and the errors that existed only
  to report these keys are gone with them. `config::RENAMED_APL_KEYS` and
  `config::renamed_apl_key_message` are removed from `praxis-policy-core`, and
  `ParseError::RenamedField` is removed from `praxis-policy-apl-core`; a removed
  key now arrives as the same unknown-key error every other bad key gets.
  `GlobalConfig::policies` is renamed to `GlobalConfig::bundles` and is no longer
  a serde field, since top-level `groups:` is what fills it.

- **Every top-level key the document model does not name.** `engine_settings:`,
  `global:`, `groups:`, `routes:`, and `plugins:` are the whole set, and anything
  else fails the load. This closes the last silent drop: a
  config still writing `plugin_settings:` lost every engine setting including
  `dispatch:`, so it ran in the default mode rather than the one it declared. The
  targeted rejection that shipped with the rename is now the general rule, and it
  still names `engine_settings` and the `dispatch: policy` spelling that replaced
  `routing_enabled: true`.

- **The route shape's catch-all in the policy compiler.** A route handed to the
  standalone compile entry point accepted any key and stashed the ones it did not
  model, so a flat `pre_invocation:` compiled a route with no policy in it. The
  shape now denies unknown fields: `authorization:`, `args:`, `result:`, and
  `plugins:` are the whole body, and anything else fails to compile. The
  config-load path already refused these through its key tables; this closes the
  same gap for a caller that compiles a document directly.

- **The flat `pre_invocation:` / `post_invocation:` spelling.** The two phase
  lists were accepted twice, nested under `authorization:` or written directly on
  a section, which needed a reconciliation rule for a section that wrote both.
  `authorization:` is now the only place they appear, at every scope, and a
  section still writing one flat fails the load naming it as the unknown key it
  is. A block must name at least one of the two: `authorization: {}`, and
  `authorization:` written with nothing under it, both used to load as an empty
  block that authorized nothing, and each now fails the load naming the missing
  phase. **Breaking for existing config**: nest each phase list under
  `authorization:`. `pre_invocation: [...]` on a route becomes
  `authorization: { pre_invocation: [...] }`. `args:` and `result:` are
  unaffected. They stay on the section and are never nested under
  `authorization:`, because they are phases rather than authorization steps.

  This retires a published guarantee. The 0.1.0 entry below names the policy
  document format as deliberately unchanged and as the surface a deployment
  depends on, pinned by `crates/ppe-core/tests/wire_compatibility.rs` against a
  document authored before the rename. That fixture wrote the flat form, so it
  has been rewritten and the test now guards the narrower surface: the plugin
  `kind:` strings, the plugin and route names, the hook names, and the violation
  codes. Those are unchanged. The phase spelling is not, and this is the notice
  rather than a diff nobody reads.

- **`args:` and `result:` under `global:`.** A field pipeline names one field of
  the payload a route carries, and `global:` covers every entity route at once
  rather than reaching a payload of its own. The two blocks are no longer keys
  there and each fails the load naming itself. This is a **removed capability,
  not a tightening**: it was the only spelling for one field pipeline covering
  every entity route, and there is no replacement that keeps that reach. Write
  the pipeline on each `global.defaults.<entity>:` block that has a payload for
  it to address, or on the routes themselves. Both blocks are unchanged at every
  other scope.

- **The `apl:` wrapper.** A section's policy terms were accepted twice, nested
  under `apl:` or written directly on the section, and the two spellings needed
  two precedence rules that pointed opposite ways: the wrapper won outright for
  the policy terms, while the section won for `response:`. The wrapper is gone at
  every scope — `global:`, `global.defaults.<entity>:`, `groups.<name>:`, and a
  `routes[]` entry — and a config still writing one fails the load naming the
  key rather than dropping the policy inside it. **Breaking for existing
  config**: lift each `apl:` block's contents onto the section that carried it.
  `apl: { authorization: {...} }` becomes `authorization: {...}`,
  `apl: { pdp: [...] }` under `global:` becomes `pdp: [...]`, and
  `global.apl.attribute_files` becomes `global.attribute_files`.

- **The `hooks::types::hook_names` and `hooks::types::cmf_hook_names` modules.** Sixteen `pub const`s that no dispatch site read. Six of `hook_names` shadowed CMF hooks under names nothing fires; two spelled identity and delegation `identity_resolve` / `token_delegate`, which no handler answers to. `cmf_hook_names` duplicated `cmf::constants` and got the prompt pair wrong, teaching `cmf.prompt_pre_fetch` where the dispatched name is `cmf.prompt_pre_invoke`. Because nothing consumed them they drifted unnoticed for months. **Breaking**, with no replacement needed: `praxis_policy_core::cmf::constants` holds the CMF names and is the supported import path, alongside `identity::HOOK_IDENTITY_RESOLVE`, `delegation::HOOK_TOKEN_DELEGATE`, and `elicitation::HOOK_ELICIT`. Those constants keep their paths and their values. The values are operator-facing, since a `hooks:` list in YAML names them as strings, so they are fixed as public API rather than free to rename.

### Fixed

- **A `delegate(...)` or elicitation step above route scope no longer fails the
  load.** The reachability check that makes `dispatch: policy` survivable asks
  which plugins a policy names, and it asked with two different reference sets:
  a route's tally counted delegation and elicitation, while a `global:`,
  `global.defaults.<entity>:`, or `groups.<name>:` layer's counted only
  `run(name)` steps and pipeline stages. A plugin named only by a
  `delegate(...)` in one of those sections was therefore reported as reaching
  nothing, and the load failed telling the operator to add a step that was
  already there. Any route stacking the section hid it, so it struck exactly
  the section-only configs the layer tally exists to cover. Both paths now read
  the same reference set. No configuration that loaded before stops loading.

- **`global.defaults.<entity>.authentication:` is read.** The key deserialized
  at that scope and the identity resolver walked global to tag bundles to route
  straight past it, so an entity type's default authentication steps were
  parsed, stored, and dropped: a key accepted and honored nowhere, which is the
  fault this release's key model exists to remove. The layer now stacks between
  the global block and the tag bundles, which is where the policy layers put
  the same section, and its `replace_inherited: true` drops what came before it
  the way a bundle's does, reported at load under the same alarm. **Breaking
  for existing config**: a document already carrying that block gains the
  identity steps it was silently going without. Under the APL visitor such a
  document did not load at all, since nothing recorded the plugin as reached;
  without a visitor it loaded and authenticated nobody for that entity type.

- **An `authorization:` block whose phases are all empty is refused.** A block
  naming neither phase was already a load error, since it authorizes nothing
  and the has-APL gate would then drop the route as if it carried no policy.
  `pre_invocation: []` reached that same end state by another spelling and
  loaded clean. Layers append, so an empty list overrides nothing and cannot be
  a way to opt out of an inherited phase. A phase written empty beside one that
  carries steps still loads and means what it says. **Breaking for existing
  config**: a section whose only authorization content is an empty list stops
  loading; delete the block.

- **Normalizing a request path that carries a query allocates nothing.** The query and the fragment are dropped by taking a shorter borrow of the request line, but the check for whether the path needed rewriting ran on the raw path, so the `?` and the `#` it found there forced the owned branch and every request carrying a query string paid for a rewrite with nothing to do. The check now runs on the path the borrow covers, so `/v1/files/q3.pdf?page=2` borrows the way `/v1/files/q3.pdf` already did. A path that still needs its dot segments resolved, its duplicate slashes collapsed, or its path parameters stripped is owned as before. Normalized paths are unchanged, except that a trailing slash sitting in front of a query is now kept the way `/a/` already kept its own.

- **Resolving an HTTP route's name stops cloning the selector's path list.** The name a request resolves to is what keys the annotation table and the route cache, so it has to be computed before either lookup, and computing it rendered a name for every path the selector declares and kept one. A twenty-path selector cost twenty discarded names per matching route per request, cached requests included, and a prefix selector built a one-element list for an answer that is a single rendered string. The scan now hands back the declared path it matched by borrow and renders only that name. The names themselves are unchanged: the names a route is annotated under and the name a request resolves to render through the same two functions, so neither can drift from the other. No configuration or behavior changes.

- **The unreachable-authentication check stops walking the route table on every request.** The warn-once latch was only set when the scan found something to report, so the ordinary configuration, where no `http:` route declares `authentication:`, rescanned the route table on every identity-hook invocation that carried no readable path. Which routes can lose their list depends only on the configuration, so the answer is now computed once when a config lands and the request path reads it. A reload recomputes it, so the warning keeps naming the routes the current configuration declares. No configuration or behavior changes.

- **A stale `policy:` on a route reports the rename, and a route's bad keys are reported together.** The route-key scan runs before any visitor and did not know the pre-rename names, so a route carrying `policy:` failed with an unknown-key error listing every key a route accepts rather than the message naming `authorization.pre_invocation`. The rename check now runs first, off the same table the APL visitor reads. The scan also collects every unrecognized key on a route and names them in one error, so three typos take one load to find rather than three. A stale key still fails the load, which is what keeps a dropped authorization block from failing open.

- **HTTP route matching runs on the request path as given.** It normalized the path first, and compared an exact path with one trailing slash treated as insignificant, so PPE could resolve a different route than the one the request is forwarded to. The gateway's router normalizes nothing: it matches on `ctx.rewritten_path` or `ctx.request.uri.path()`, and its exact arm is a byte compare. So `/v1/files/../healthz` resolved the `/healthz` route here while the gateway sent the request to the `/v1/files` cluster, and whatever `/v1/files` authenticates was dropped for it. Matching now uses the path the host supplied and compares an exact path byte for byte, which is how PPE applies the policy of the route the traffic actually goes to. **An exact route no longer matches a trailing-slash spelling of its path**: `http: /admin` answers for `/admin` and not for `/admin/`, a route declared `"/admin/"` answers for `/admin/` and not for `/admin`, and a deployment needing both declares both. Two routes declaring the two spellings now load rather than being refused as one name, and each is annotated under the path it was written as. Prefix matching is untouched and still agrees with the gateway's own `path_prefix_matches`, so a prefix route keeps matching `/api`, `/api/`, and `/api/v1`. The path normalizer still runs as a fail-closed guard, so an unreadable path is denied exactly as before.

- **Two routes narrowed by the same method in different case are refused at load.** Method matching ignores ASCII case, but the rendered route identity did not, so `method: GET` and `method: get` on one path passed the duplicate check and both matched every request, with the first declared silently winning. The identity now uppercases the method set before sorting it, so the two spellings are one name and the load fails naming both routes. A config carrying both stops loading, and a lowercase `method:` renders its name uppercase.

- **A route narrowed by `method:` now outranks the same path left open.** The narrowing gated the match without scoring, so two routes on one path resolved by declaration order: a broad `path_prefix: /api` written above `{path_prefix: /api, method: DELETE}` took the `DELETE` request, and swapping the two lines changed which policy ran. A present `method:` now adds to the score, below the per-character prefix weight so it breaks a tie within one path rather than reordering two paths, and below the scope bonus so a scoped route keeps winning its own scope. A configuration that pairs a broad route with a method-narrowed one moves those methods to the narrower policy.

- **A declared `http:` path that is not absolute is refused at load.** Matching reads the request path as given, so a selector whose path does not start with `/` can never match, and seven shapes of it loaded as dead routes with no signal at all. A bare path, a list element, `path:`, and `path_prefix:` are all checked now, and the error names the route and the path it read. A config declaring one stops loading; write the path with its leading slash.

- **A route can no longer claim the reserved catch-all name.** A route declaring `http: "*"` rendered `*` as its name, which is the name the entity-less catch-all policy is annotated under, so the route matched no request while its policy body governed every request that resolved no route, and it displaced the global `response:` block on the way. A route whose rendered names include the reserved name is now refused at load. The check reads the names the route contributes, so it covers every selector shape rather than the one spelling, and it runs whether or not routing is enabled, because the engine consults the annotation table either way.

- **An `http.method:` value that is not a method token is refused at load.** Methods are compared literally and there is no glob dialect, so `method: 'GET*'` matched nothing, and neither did a typo carrying a space or a slash. A value must now be an RFC 9110 token, with `*` excluded because it reads as a glob, and the error names the route and the value. An extension verb such as `PROPFIND` or `M-SEARCH` is unaffected.

- **Two routes narrowed by `method:` on one path no longer tie.** The narrowing scored a flat bonus whatever its method set held, so `{path: /a, method: [GET, POST]}` written above `{path: /a, method: GET}` took the `GET` request and the narrower policy never ran, with the declaration order deciding which one did. It failed in the fail-open direction, since the route that lost was the narrower one. The bonus now scales with how many methods the selector names, so one method outranks two on the same path, which is how the gateway's own router breaks a tie between equal paths: by counting constraints. The whole bonus still sits under the scope bonus, so a scoped broad route keeps winning its own scope, and far under the per-character prefix weight, so prefix length still decides between two different paths. A config pairing a wide narrowing with a narrow one moves the methods they share to the narrower policy.

- **A body-less `http:` route no longer silences the response half.** A route whose effective layers declare only pre-phase steps installed a post handler that ran nothing, and that empty handler short-circuited the response-side plugin chain, so a configuration gained a catch-all `http:` route and lost whatever governed the way out. Each half now installs on the route path only when the route declares steps for it, which is the rule the global catch-all already applies.

- **An entity route's post-half plugins begin running.** The same missing guard covered `tool:`, `llm:`, `prompt:`, and `resource:` routes: a route listing `plugins:` alongside a policy body that declares only pre-phase steps installed an empty post handler that suppressed those plugins, so a plugin the operator wrote onto the route never ran on the post half. It runs now, so a plugin that denies there begins denying a call that previously passed. Check what the post-half plugins on such a route do before upgrading.

- **Concurrent registration no longer loses plugins.** Every mutation of the engine's runtime snapshot was a load, clone, store with nothing serializing writers, so two threads that loaded the same snapshot each published their own copy and the last write discarded the other silently. A test putting sixteen threads through `register_handler` at once kept one plugin, and all sixteen calls returned `Ok`. Writers now serialize on a mutex held across the copy-on-write, covering `load_config`'s inline swap as well; the read path is untouched and still lock-free, and the generation counter still bumps exactly once per published mutation. Nothing in the workspace registers concurrently today, so no shipped configuration was affected, but registration takes `&self` on an `Arc`-shared engine and a host is free to call it from any thread. Neither that mutex nor the factory-registry `RwLock` is reentrant, so `load_config` now runs every `PluginFactory::create` holding neither: it resolves the factories, releases the registry lock, instantiates, and only then takes the writer lock for the registry clone and the swap. A factory that calls back into `register_handler`, `annotate_route`, `unregister_plugin`, or `register_factory` while being built would otherwise block on a lock its own caller was holding. Whatever such a factory registers on its way through is picked up by the clone rather than discarded by it. The two route-override paths already released the registry lock before `create` and are unchanged. `mutate_runtime` and `try_mutate_runtime` likewise release the writer lock before the snapshot they replaced goes out of scope: that snapshot usually holds the last reference to whatever the mutation discarded, and a plugin or annotation handler's `Drop` is host code too, so `remove_route_annotation` on a handler that called back would have blocked on the lock its own release was holding. A rejected `load_config` is the same story from the other end: the plugins its factories just built have nowhere else to live, and the registry drops the one whose name collided while the entries behind it are never registered at all. Registration now borrows the instances and hands the registry `Arc` clones, so the load keeps the last reference to every one of them and releases the lock before letting go. ([#23](https://github.com/praxis-proxy/policy/issues/23))

- **Three dispatched hooks had no routing metadata.** `http.request` and `elicit` were absent from the table entirely, so `lookup` reported them unphased and a consumer deriving request-versus-response direction from a hook's phase got neither for the L7 path. It never surfaced because the matcher treats an unphased hook as matching every context, so dispatch kept working while the phase it reported was wrong. All three, `http.response` included, now carry the phase and entity type they are installed under, and a test holds the table to what the dispatcher does. **This narrows dispatch as well as correcting it**: a hook with no row matched every entity type and every phase, so a plugin registered under `http.request` used to dispatch for `tool`, `llm`, `prompt`, and `resource` requests too. It now dispatches only for `entity_type: http` in the request phase. A deployment relying on that accidental reach registers the plugin under the hooks it actually serves, or restores the old behavior for that one name with `register_hook_metadata(HOOK_HTTP_REQUEST, HookMetadata::permissive())` at startup. `permissive()` is `phase: Unphased`, which is what makes it match every phase, so a hook registered that way reports `false` from both `is_pre` and `is_post`. A host that wants the phase reported rather than the reach restored writes the row out: `HookMetadata { family: Some(HttpHook::NAME), entity_type: Some(ENTITY_HTTP), phase: HookPhase::Pre }`.

- **`MessageView::is_pre` and `is_post` were a second phase authority that disagreed with the first.** Both matched the hook's name against a substring, so four of the ten phased hooks answered `false` to both: `cmf.llm_input` and `http.request` are `Pre` and contain no "pre", `cmf.llm_output` and `http.response` are `Post` and contain no "post". The policy-visible `is_pre` / `is_post` fields of `to_dict` carried that. Both now read the metadata registry that dispatch reads, so a hook is pre-phase because it is registered that way. A host hook named `express_lane` no longer reads as pre-phase, and an unregistered name reports neither. Nothing outside `MessageView` read these, so this reaches plugin authors rather than a shipped path.

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
