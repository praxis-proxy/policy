---
date: 2026-08-23
topic: assertions-header-contract
---

# Configuration for what the engine asserts on requests and responses

## Summary

Operators get an `assertions:` block, alongside `authentication:`, holding a `request:` and a `response:` contract. The request contract renders engine-derived state onto the upstream request as headers and removes the client-supplied headers that would collide with it. The response contract removes what an upstream should not be telling the client and adds what it should. Sources are slot paths addressed the way the rest of the config addresses extension state. A closed set fixed in code makes credentials and wire headers unusable as sources.

The two directions are deliberately not symmetric. The request direction is an allowlist; the response direction cannot be.

Addresses [praxis-proxy/policy#28](https://github.com/praxis-proxy/policy/issues/28); the response direction comes from review and exceeds that issue's stated criteria.

---

## Problem Frame

A service behind the gateway needs the conclusions of authentication without the credential that produced them. PPE derives that state already: it validates the token, maps claims into typed identity, mints delegated credentials, and accumulates labels. None of it reaches the upstream request, because nothing in PPE renders engine state onto the wire.

The gap has been closed once already, in the wrong place. Praxis PR #954 added an extension whose Rust type encodes what is safe to expose, plus a filter to read it. That has two costs. An operator cannot see or audit the policy, because it lives in a type rather than in config. And each consumer wanting a different slice needs another type.

The return path has the same shape and the opposite beneficiary. Where the request direction protects an upstream from the client, the response direction protects the client and the agent from the upstream, which in agent traffic is often a third-party tool server nobody here operates. It catches backend banners and debug headers, `set-cookie` issued on the gateway's own domain, and the case where an upstream echoes an asserted header back so the client learns what the gateway says on its behalf.

PPE has capability gating, but it answers a different question. `Capability` and the `build_filtered_*` functions govern what a plugin may *read* from the extensions tree. Nothing governs what is *emitted*. The read side already names the sensitive slots, so the vocabulary exists; what is missing is a surface that says which of them render to which header, and which can never render at all.

Two dependencies are now in place. Subject claims keep their JSON shape ([#9](https://github.com/praxis-proxy/policy/pull/9)), so a projected claim has structure to carry. The claim map is configurable ([#31](https://github.com/praxis-proxy/policy/pull/31)), so the typed fields are populated against real IdPs rather than only flat OIDC.

---

## Actors

- A1. Deployment operator: writes the config, owns the header contract in each direction, and must be able to answer "what crosses this boundary" from the config alone.
- A2. Upstream service: consumes request headers as trusted assertions, having no signature to check them against. Believes them because it believes the network path.
- A3. Security reviewer: audits what crosses the boundary in either direction, and needs the exclusions visible in what the engine reports rather than inferred from an absence in config.
- A4. Policy author: writes rules against the same state this renders. Unaffected in what they can read; affected in what leaves.
- A5. Client and agent: receive the response the gateway returns, and cannot tell which headers originated upstream and which the gateway vouches for.

---

## Requirements

**Config surface**

- R1. The block is `assertions:`, sitting beside `authentication:` at global, group, and route level. It holds `request:` and `response:`, each a contract carrying `headers:` and `strip:`.
- R2. An entry under `headers:` names its target header and takes either one source or a set of named members, never both.
- R3. Sources are slot paths (`subject.id`, `subject.roles`, `claim.<name>`), addressing extension state as the rest of the config does. The engine maps each path to the capability gating that slot, so the capability model stays the authority on reachability without operators writing capability names.
- R4. A claim source names one claim. A bare claim root is not a valid source, so a provider's claim map cannot be rendered wholesale.
- R5. A source that names no addressable slot fails at config load, naming the path and the direction it appeared in.

**What may be a source**

- R6. A closed set fixed in code is never usable as a source, in either direction: raw inbound tokens, delegated tokens, inbound request headers, and upstream response headers. It has no config surface, and cannot be removed, extended, or overridden. An entry naming one fails at config load, with a message distinguishing it from an unaddressable path.

**Request direction**

- R7. Only what a request entry names reaches upstream. A slot that is readable, and that no entry names, does not propagate.

**Response direction**

- R8. A response header that no `strip:` entry names passes through to the client unchanged. The response direction is a denylist, because the engine does not originate the upstream's output and cannot enumerate what is legitimate in it.
- R9. A protocol floor fixed in code cannot be removed by a response `strip:` entry, and naming one fails at config load. The floor holds the headers a client needs in order to interpret the response at all.

**Rendering**

- R10. A members entry renders one JSON object. Keys are operator-chosen; values keep the JSON shape of their sources.
- R11. A structured source renders as its JSON value, not as a JSON string holding serialized text. A claim whose value is the array `["a"]` renders distinguishably from a claim whose value is the string `"[\"a\"]"`.
- R12. Collection-valued sources render in a stable order, so one identity produces identical header bytes across requests.
- R13. A collection-valued source targeted at a single-value header fails at config load unless the entry declares how it encodes.
- R14. A rendered value containing a carriage return or line feed is not emitted. Sources carry provider-minted and therefore attacker-influenced data, and a header that splits is a second header nobody configured.

**Absent values**

- R15. A source that resolves to nothing omits its header. This is the default.
- R16. An entry may instead deny the request, under the spelling and denial code the claim map already uses for the same situation.
- R17. Omission never leaves a header from the wire in place. R18 holds independently of whether a value was derived.

**Header removal**

- R18. Every header an entry targets is removed from the corresponding wire map before injection, unconditionally: from the client's request in the request direction, and from the upstream's response in the response direction. This holds when the source resolved to nothing and when no identity was resolved at all. In the response direction it is what stops an upstream echoing an asserted header back to the client.
- R19. `strip:` accepts further header names and glob prefixes, removed alongside the entry targets.
- R20. Removal and injection are one replacement of the corresponding header map. No intermediate state exists in which a wire-supplied value has been accepted but not yet overwritten.
- R21. Removal matches header names case-insensitively, since HTTP field names are, so a rule written in lower case removes a value sent in any casing.

**When each direction runs**

- R22. Direction derives from the hook's registered phase rather than from a list of hook names: a pre-phase hook applies the `request:` contract, a post-phase hook applies the `response:` contract, and an unphased hook applies neither. A host that registers phase metadata for its own hook is covered without a config change.
- R23. Removal and injection happen after that phase's policy evaluation. Policy reads the wire headers unchanged, including a client-supplied value under a target name, so a rule can observe a spoofing attempt and deny it. Removal describes what crosses the boundary, not what policy sees.
- R24. On a pipeline a plugin already denied, request-direction removal still happens and injection does not, and R16's denial is not evaluated. The response direction does not run at all, because a denied request produces no upstream response.

**Layering**

- R25. A direction's contract is whole, and contracts never merge. Global, group, and route may each declare one, and the most specific present is the one in force, resolved per direction so a route may state its own `response:` while inheriting the global `request:`. A route joining two groups that both declare the same direction has no principled winner and fails at config load.
- R26. R6, R9, and R18 hold at every level, whichever contract is in force.

**Audit and defaults**

- R27. The engine renders the effective policy as one artifact covering both directions: the asserted headers, the code-fixed source exclusions, the response protocol floor, the removal sets, and the phase each direction fires on. A1 and A3 answer what crosses the boundary without reading Rust.
- R28. With no `assertions:` block, nothing is asserted and nothing is removed, in either direction.

---

## Acceptance Examples

- AE1. **Covers R2, R10, R11.** Given a token whose roles are nested and whose projects claim is an array, when one request entry declares members drawn from typed roles and from that claim, the header holds one JSON object whose projects value is an array rather than text that parses to one.
- AE2. **Covers R6.** Given an entry naming raw inbound tokens, config load fails and the message distinguishes it from a path that names nothing.
- AE3. **Covers R6.** Given an entry naming inbound request headers, config load fails, so a client-supplied header cannot be rendered into a trusted one; the same holds for a response entry naming upstream response headers.
- AE4. **Covers R7, R28.** Given a config with no block, no asserted header reaches upstream and no credential appears in the request.
- AE5. **Covers R4.** Given an entry naming a claim root rather than a claim, config load fails.
- AE6. **Covers R12.** Given one identity asserted twice, both requests carry byte-identical headers.
- AE7. **Covers R15, R16.** Given a token missing the mapped tenant claim, the tenant header is absent by default; given the same entry set to deny, the request is denied under the claim map's existing code.
- AE8. **Covers R17, R18.** Given a request carrying a client-supplied value under a target header name, and an engine that resolved no identity, the upstream sees no such header.
- AE9. **Covers R20.** Given a request carrying client-supplied values under every target name, no ordering of the pipeline exposes those values to the upstream.
- AE10. **Covers R25.** Given a global contract and a route that states its own, the route's upstream receives exactly the route's headers and none of the global ones.
- AE11. **Covers R3, R5.** Given an entry naming a source that exists as a capability but addresses no slot, config load fails naming the path.
- AE12. **Covers R27.** Given any config, the rendered artifact names every header that can cross in either direction, every source exclusion, and the response floor.
- AE13. **Covers R25.** Given two routes joining one group that declares a contract, both upstreams receive that group's headers; given a route that joins the group and also states its own, it receives only its own.
- AE14. **Covers R25.** Given a route joining two groups that each declare the same direction, config load fails and names both groups.
- AE15. **Covers R14.** Given a claim whose value contains a line feed, no header is emitted for that entry rather than two headers.
- AE16. **Covers R21.** Given a request carrying a target header name in mixed case, the upstream receives only the engine's value under that name.
- AE17. **Covers R23.** Given a request carrying a client-supplied value under a target name, a policy rule reading that header observes the client's value, and the upstream still receives only the engine's.
- AE18. **Covers R24.** Given a pipeline a plugin denied, the extensions returned carry no client-supplied value under any request target name, no asserted header was added, and the response contract did not run.
- AE19. **Covers R8.** Given a response carrying a header no `strip:` entry names, the client receives it unchanged.
- AE20. **Covers R9.** Given a response `strip:` entry whose glob would match a floor header, config load fails and names the floor header it would have removed.
- AE21. **Covers R18 in the response direction.** Given an upstream that echoes an asserted header back, the client receives the engine's value or none, never the upstream's.
- AE22. **Covers R22.** Given a host that registers its own hook with pre-phase metadata, the request contract fires on it with no config change; given the same hook registered unphased, neither contract fires.

---

## Traceability

Issue #28 states criteria for the request direction only. The response direction has no acceptance criterion there and is traced to review instead.

| Issue AC | Requirements |
|---|---|
| Declarative projection config | R1, R2, R3 |
| Deny list over tokens and provider payloads | R4, R6 |
| Deny precedes projection, with a test | R6, AE2, AE3 |
| Nothing unprojected propagates | R7, R28, AE4 |
| Claims carry structure | R10, R11, AE1 |
| Expressed in the existing vocabulary | R3 |
| Unknown field fails at config load | R5, R13, AE11 |
| Readable as an audit artifact | R27, AE12 |
| Tests that no credential reaches upstream | R6, R28, AE2, AE4 |
| *(from review, no issue AC)* response direction | R8, R9, R18, R22, AE19-AE22 |

---

## Success Criteria

- An operator answers "what crosses this boundary, in each direction" from the config and the rendered artifact, with no Rust.
- A deployment upgrading without adding the block propagates nothing new and removes nothing.
- A client cannot place a value under a request target name and have an upstream believe it, whether or not the engine derived a value of its own.
- An upstream cannot tell a client what the gateway asserts on its behalf by echoing it back.
- A response keeps every header a client needs to interpret it, no matter how greedy an operator's `strip:` glob is.
- A projected claim reaches its destination with the shape the IdP minted, and a consumer can tell an array from text that looks like one.
- The same identity produces the same header bytes, so audit hashes and golden files are stable.
- Planning does not need to invent the surface: naming, direction split, source vocabulary, exclusion model, response floor, layering, absent-value behavior, and removal semantics are decided here.

---

## Scope Boundaries

- Response bodies and trailers. The response direction covers headers only.
- Non-HTTP transports.
- Reading identity *from* inbound headers. A trusted-upstream identity resolver is a coherent feature and is not this one.
- Listener-level prefix reservation, which is praxis-side.
- A first-class tenant field on the subject. Tenant arrives as a claim and is asserted as one; promoting it is its own conversation.
- Delegated token attachment, which already exists and is unchanged. This surface is not a second path for attaching a credential.
- Per-plugin assertion surfaces.
- Conditional assertion gated on an evaluated predicate. Most of what looks conditional is whether the source resolved, which R15 already covers.
- An operator-authored exclusion list. See Key Decisions.

---

## Key Decisions

- **The two directions are not symmetric, and the response direction is a denylist.** The request direction can default-deny because the engine originates every value it asserts, so the legitimate set is finite and known. A response is a passthrough of an upstream's own output: the engine does not originate it and cannot enumerate what is legitimate in it. Default-deny there strips `content-type`, `etag`, `retry-after`, rate-limit and tracing headers, and CORS, and the client breaks. So the response direction removes what is named and passes the rest, with a protocol floor fixed in code that a greedy glob cannot reach. Making the two halves mirror each other would be tidier and wrong.

- **Direction derives from the hook's registered phase, not a list of hook names.** Hook types are open, so any fixed list silently fails to fire for a host that declares its own hook, which is a fail-open in a security control. The phase registry already classifies pre, post, and unphased, and already exists for a host to register against. Reading it means a new hook is covered by declaring what it is, rather than by editing this feature.

- **Slot paths over capability names as the source vocabulary.** The literal reading of the issue would put capability names in entries, which is unusable and, worse, ill-defined: `build_filtered_subject` includes id and subject type under any subject access while gating the other sub-fields individually, and `has_read_access` makes a sub-capability imply the parent. So the capabilities are not a tree and cannot express nesting. Slot paths nest correctly. The capability model stays the enforcement mechanism behind them, which is the part of the issue's intent that matters: no parallel set of names is invented.

- **`assertions:` over `upstream_headers:` and `identity_propagation:`.** The config already names security functions rather than mechanisms, and did so deliberately: the `authorization:` block is a rename of `policy:` / `post_policy:`. A mechanism name walks that back. What crosses the boundary is an unsigned statement about a principal, believed because the receiver believes the network path and having no signature to check against, which is what an assertion is; the word is unused as a domain term in this tree. Review argued against it on the grounds that "assertion" reads as "signed" to most people; the name is kept and the unsigned nature is stated wherever the surface is documented. Direction sits under it as `request:` / `response:`, so a second transport later is a sibling key rather than a second top-level entry. Propagation was rejected twice over: it describes flow where this renders once at a boundary, and taint already owns the word in prose. Identity was rejected as narrower than the mechanism.

- **Exclusions fixed in code, with no config surface to extend them.** The failure modes are asymmetric. An operator-maintained list leaks by omission when a new credential slot is added and some deployment's list was not updated. A fixed set requires an affirmative edit to a security-sensitive constant. An additive operator list was drafted and cut: it carries no runtime behavior, since R7 already governs propagation; it blocks a slot path rather than semantics, so excluding `subject.permissions` while asserting `claim.scope` reads as a guarantee it does not provide; and under R25 a route replacing the block would drop a global exclusion silently. R6 and R4 meet the issue's criteria without it.

- **Wire headers join the excluded set in both directions.** The issue lists neither. A uniform source vocabulary makes an inbound header addressable, and rendering a client-supplied header into a trusted upstream header is the exact laundering this design exists to prevent. The response direction has the mirror hazard: an upstream that controls a response header must not be able to aim it at what the client trusts.

- **Writing the header map over emitting a new typed slot.** Merging the http slot already replaces both header maps wholesale, which is what makes R20 atomic in either direction, and praxis applies that result today. This ships without a coordinated praxis change. The cost is that rendering happens inside PPE and the result is not distinguishable from another header write at the wire; R27's artifact covers the audit need instead.

- **Removal is a wire operation, not a visibility one.** It happens after the policy phase, so policy reads wire headers exactly as it does today. That keeps existing rules working, and lets an author deny a request that arrived carrying a target header name at all. The cost is a footgun: a value under `http.request_headers.x-auth-user-id` looks authoritative and is not. Stripping before the engine would close that, at the price of making spoof-detection impossible and silently changing what existing policies see.

- **One contract wins whole, at whichever level declares it, resolved per direction.** A header set is a contract with one counterparty; splicing a global mapping into a route's produces a set nobody designed. That rules out stacking, not levels, so global, group, and route each declare a complete contract and the most specific present wins. Resolving per direction means a route can state its own `response:` without restating the global `request:`. Groups carry it because several routes fronting one upstream is the ordinary case. This is deliberately unlike `authentication:`, which concatenates its layers; review argues additive is the right default here too, on the grounds that a union of allowlists can only weaken the global floor. That challenge is open and is recorded in the plan rather than settled here.
