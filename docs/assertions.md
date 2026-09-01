<!--
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Praxis Contributors
-->

# `assertions:` — what the engine puts on the wire

PPE validates tokens, maps claims into typed identity, mints delegated
credentials, and accumulates labels. None of that reaches an upstream on its
own. The `assertions:` block is how an operator says which of it does, as
request headers, and which response headers an upstream is not allowed to send
a client.

The block sits beside `authentication:` and holds two contracts:

```yaml
global:
  assertions:
    request:                 # toward the upstream, on a pre-phase hook
      headers: [...]
      strip: [...]
    response:                # toward the client, on a post-phase hook
      headers: [...]
      strip: [...]
```

## The trust model, first

**What crosses either boundary is unsigned.** Whoever receives it believes it
because they believe the network path, not because they can verify anything. An
upstream reading `x-auth-user-id` is trusting that nothing between the gateway
and itself can set that header. If that is not true of your network, this
feature is not what makes it true.

The corollary is why removal is unconditional: every header an entry targets is
removed from the wire map before injection, whether or not the source resolved
to anything. Without that, an absent claim would leave the client's own value
standing under a name the upstream reads as the gateway's.

## An entry

```yaml
headers:
  - name: x-auth-user-id     # the target header
    from: subject.id         # one source
    on_missing: deny         # or `omit`, the default

  - name: x-auth-scope
    from: claim.projects
    encode: csv              # required: the source is a collection

  - name: x-auth-attributes  # one JSON object, keys operator-chosen
    members:
      roles:    subject.roles
      projects: claim.projects
```

`from:` and `members:` are alternatives; an entry carrying both fails to load.
So does a `members:` entry carrying `encode:`: a members entry always renders as
a JSON object, so the key could not change anything, and it is refused rather
than accepted and ignored.

`encode:` says how a value that is not a scalar renders into one header value.
`json` renders every value as JSON, so a string renders quoted and stays
distinguishable from a structured value that spells the same text. `csv` joins
an array with commas. With neither, a scalar renders bare and a structured
value renders as compact JSON. A source that is *always* a collection
(`subject.roles` and friends) must declare one, because a set reaching an
upstream in a shape nobody chose is a shape nobody can rely on.

Collections render sorted, and a members object's keys are sorted, so one
identity produces identical header bytes across requests. Audit hashes and
golden files stay stable.

A rendered value carrying CR, LF, or NUL is dropped rather than emitted. A
claim is provider-minted and therefore attacker-influenced, and a header that
splits is a second header nobody configured.

## Sources

Slot paths, addressed the way the rest of the config addresses request state:

    subject.id  subject.type  subject.roles  subject.teams  subject.permissions
    claim.<name>
    client.client_id  client.client_name  client.trust_level  client.roles
    client.permissions  client.teams  client.authorized_scopes
    client.authorized_audiences  client.claim.<name>

A claim name is taken whole, so a provider spelling one with dots needs no
escaping. A bare `claim` names the whole map rather than one claim and is
refused: a provider's claim set is not something to render wholesale.

**Fixed in code, never usable as a source, in either direction, with no config
surface to widen:**

    raw_credentials.*          the inbound bearer tokens, before validation
    http.request_headers.*     the client's own request headers
    http.response_headers.*    the upstream's own response headers

Rendering a client-supplied header into a header the upstream trusts is the
laundering this feature exists to prevent, and an upstream that controls a
response header must not be able to aim it at what the client trusts.

The request line and the response status (`http.method`, `http.path`,
`http.host`, `http.scheme`, `http.status`) are refused too, but as paths outside
the grammar rather than as credentials. They are host-populated, so admitting
them later is a grammar addition and not the reversal of a security decision.
The two refusals carry different messages.

## The two removal mechanisms

They are easy to conflate, and only one is configurable.

**Automatic.** Every header an entry targets is removed from the corresponding
wire map before injection: the client's request in the request direction, the
upstream's response in the response direction. It happens whether or not
`strip:` exists, and whether or not the source resolved, so absence never
leaves a wire value in place. It is also what stops an upstream echoing an
asserted header back at the client.

**`strip:`, operator-authored.** Removes names no entry targets. Accepts header
names and trailing-glob patterns, matched case-insensitively. Every level's
entries apply, so a subordinate level cannot narrow an inherited removal by
omitting it.

Removal and injection are one replacement of the direction's header map, so
there is no state in between where a client value and an asserted one both
exist.

## What each direction asserts is not symmetric

`request:` can withhold anything it does not name, because the engine
originates every value it asserts and the legitimate set is finite and known.

`response:` cannot. A response is a passthrough of the upstream's own output.
The engine originates none of it and cannot enumerate what is legitimate, so
default-deny there would remove `content-type`, `content-length`, `etag`,
`cache-control`, `retry-after`, the CORS set, and every rate-limit and tracing
header a client depends on. So a response header nothing names reaches the
client unchanged.

That asymmetry is about what each direction **asserts**. It says nothing about
`strip:`, which removes headers the engine did not originate and cannot
enumerate in either direction. So `strip:` gets the same treatment both ways.

## Both directions have a protocol floor

A **protocol floor** fixed in code holds the headers a `strip:` entry can never
remove. There is one per direction, holding what that direction's recipient
needs in order to interpret the message at all. A `strip:` entry that would
remove one fails at config load, naming the header the glob would have hit,
rather than breaking traffic in production. A `headers:` entry *targeting* a
floor header is refused for the same reason: an entry removes its target before
injecting, so one whose source resolved to nothing would take the floor header
with it.

The **request floor** is framing and addressing, which is all the engine can
assume an upstream needs: `host`, `content-type`, `content-length`,
`transfer-encoding`.

`authorization` is deliberately **not** in it. Stripping the client's own bearer
before forwarding to an upstream that runs on a delegated credential is a stated
use case, so it stays removable. Neither are `cookie`, `accept`, `user-agent` and
the rest of what a client says about itself: withholding those from an upstream
is a policy choice an operator is entitled to make, not a broken request.

The **response floor** is longer, because a client's caching, validation and
CORS behaviour all hang off headers the origin chose: content negotiation and
framing, caching and conditional requests, retry signalling, and the CORS
response set.

`set-cookie`, `server` and `x-powered-by` are deliberately **not** in it.
Removing those is a stated use case.

So `strip: ["*"]` fails to load in either direction, and the load error names
the first floor header the glob reached.

## Four levels, and they stack

A contract can be written at any of the four levels the config layers, and they
accumulate the way `authentication:` does:

1. `global:`
2. `global.defaults.<entity>:` — `tool`, `resource`, `prompt`, `llm`, `http`
3. `groups.<name>:` — the bundles a route joins
4. a `routes[]` entry

Resolution runs **per direction**, so a level may declare one direction and
leave the other to the levels above it.

An entity default covers an entity type rather than a route, so it reaches a
request of that type even when the request matched no route. A generic-HTTP
request that selected none of the `http:` routes is still governed by
`global.defaults.http`.

`headers:` unions by target header name, compared case-insensitively. A
repeated name takes the more specific level's entry **whole**, `members:` and
`on_missing:` included: a members object composed from two levels would have no
author. `strip:` unions and deduplicates.

Bundles are the one layer with no order among themselves, so two bundles on one
route asserting the same header in the same direction is a load error naming
the route, the direction, the header, and both bundles. Different headers union
and are fine, and so is the same header in different directions.

### Opting out

```yaml
routes:
  - tool: analytics.*
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-auth-user-id
            from: subject.id
```

`replace_inherited: true` drops what accumulated before that level, for the
direction it is written in and no other. It reaches **operator-authored
`headers:` and `strip:` content, and nothing else**: the unconditional removal
of an entry's target, the source exclusions, and the response floor are all
outside it. So the worst it can do is let through a name no entry targets; it
cannot be used to let a client header reach an upstream under a name the
gateway asserts.

Setting it on a route is silent, because that route's author can see it.
Setting it on a bundle or an entity default is reported at config load, naming
every route that lost content it never wrote.

## The host's obligation on `http:` routes

A route selecting on `http:` is matched from the request line the host puts on
the HTTP extension. **A contract written there is in force only at an
invocation that carries one.** Without it no `http:` route matches and the
levels above govern instead: `global.defaults.http`, then `global`. Nothing
errors.

The request and the response are separate invocations, so a host can supply the
request line on one and not the other. A route's `request:` then pairs with the
global `response:`, which is a contract nobody wrote.

The engine reports both cases rather than leaving them to be inferred from a
header that did not appear: once per such route at config load, and once per
direction at runtime when an invocation arrives with no readable path.

## What applies where

The direction comes from the hook's registered phase, not from a list of hook
names. A pre-phase hook applies `request:`, a post-phase hook applies
`response:`, and a hook that is neither is not a wire boundary and applies
neither. A hook family added later needs no change to this block, and a host
registering its own hook with a phase gets the contract with no config change.

The contract is applied **after** that phase's policy evaluation, so a policy
rule reads the client's headers unchanged. The cost is that a value under
`http.request_headers.x-auth-user-id` looks authoritative to a rule and is not.

A nested dispatch primitive is not a boundary and applies nothing:
`invoke_entries` is called from inside a handler the executor is running, and
the contract is applied once at the outer boundary after that handler returns.
A host driving `invoke_entries` as its outermost dispatch has no boundary, and
so no contract — nothing is asserted and nothing the contract names is removed.
The engine reports that on every such call, under
`alarm = "assertions_dispatch_without_a_boundary"`, rather than leaving it to be
inferred from a header that did not appear. Every call is a fresh lapse of the
property that a client cannot set an asserted header, so it is reported like one;
a host that configures no contract is not warned at all.

On a pipeline a plugin already denied, the request direction still removes what
it names — removal costs nothing and keeps a client value out of the extensions
the audit path sees — and injects nothing, and `on_missing` is not evaluated.
The response direction does not run at all: there is no upstream response.

## Reading the effective policy

The engine renders the whole boundary as one document at `info` when a block is
configured, and `praxis_policy_core::assertions::effective_policy` returns it so
a host can expose it. It covers every header that can be emitted with its
source and the capability gating that slot, the removal set including the entry
targets no `strip:` entry names, the exclusions and the floor with the reason
each entry is there, which dispatch paths are boundaries, and — per route — the
accumulated contract with the level each header came from.

A contract that spans four levels is harder to read than a one-level one. That
document is where the cost is paid.

## A worked example

`crates/ppe-core/tests/fixtures/assertions_worked_example.yaml` is a complete
configuration covering all four levels, both directions, an `http:` route, and
the configurations that fail to load. It is loaded by the test suite, so it
cannot drift from what the engine accepts.
