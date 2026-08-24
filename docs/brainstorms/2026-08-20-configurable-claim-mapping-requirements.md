---
date: 2026-08-20
topic: configurable-claim-mapping
---

# Configurable claim mapping for identity plugins

## Summary

Operators get a declarative claim map in the JWT identity plugin's config — ordered candidate paths per typed field, dotted traversal into nested claims, and backslash escaping for literal dotted claim names — covering the subject, client, and workload roles. The OIDC standard shape becomes a shipped preset that runs through that same engine, pinned to today's behavior by an equivalence test.

Addresses [praxis-proxy/policy#27](https://github.com/praxis-proxy/policy/issues/27).

---

## Problem Frame

A deployment whose IdP puts roles anywhere other than a top-level `roles` array cannot express that from configuration. The mapping from claims to typed identity fields is hardcoded to the OIDC standard shape, so an operator running Keycloak — where realm roles live under a nested object, and per-client roles live under another — has to write Rust and inject a custom mapper at resolver construction. That is a source change and a rebuild, in a component an operator is otherwise expected to configure.

The config hook exists but leads nowhere: the mapper field accepts a name, and the only name accepted is the standard one. Everything else is rejected at construction. The doc comment anticipates named presets, but named presets cannot close the gap on their own — Keycloak's nested role location is fixed and presettable, while a namespaced Auth0 claim is per deployment, so no shipped preset can cover it.

The cost lands in two places. Deployments that need it fork the plugin or lose IdP coverage. Deployments that work around it push role logic into policy expressions against the raw claims bag, which means every policy author has to know the IdP's claim layout instead of gating on `subject.roles` — and a claim name containing a colon, as Cognito mints, is not addressable in the policy language at all.

Claim values keep their JSON shape as of [#9](https://github.com/praxis-proxy/policy/pull/9), so nested claim structure now survives into the identity extensions. Before that there was nothing for a path to point at.

---

## Actors

- A1. Deployment operator: writes the plugin config in unified-config YAML, wires the IdP, and owns the claim map. Cannot write or build Rust.
- A2. Policy author: writes rules that gate on typed identity fields and on the claims bag. Affected by what the map consumes and what stays visible.
- A3. Plugin integrator: builds a host that embeds the plugin, and may inject a custom Rust mapper for identity flows this config surface does not cover.

---

## Requirements

**Path syntax and resolution**

- R1. A field path addresses a value in the validated claim set by dot-separated segments, traversing nested objects. No new inputs: the map consumes only the claims the mapper already receives.
- R2. A backslash escapes a dot, making the escaped dot part of a single literal segment, so a namespaced claim name containing dots is addressable. A doubled backslash is a literal backslash.
- R3. A colon is not a separator and needs no escaping, so a colon-prefixed claim name is addressable as written.
- R4. A malformed path fails at construction, naming the field and the offending path — covering a trailing escape, an unrecognized escape, an empty segment, and an empty path.

**Per-field mapping**

- R5. Each mappable field accepts either a shorthand single path or an expanded form carrying an ordered list of candidate paths.
- R6. A candidate list resolves first-match by default. A field may instead declare that every resolving candidate contributes to the result, so a collection can be assembled from more than one source.
- R7. By default an array value contributes its elements and a string value contributes as one element. A field may declare that a delimited string is split into multiple elements.
- R8. A resolved value whose JSON shape cannot satisfy the field is ignored rather than rejected, preserving how an unusable audience shape behaves today.

**Role coverage**

- R9. A map covers the subject, client, and workload roles. A resolver instance uses the section matching its configured role.
- R10. A map that declares no section for the resolver's configured role fails at construction, rather than denying every request at runtime.
- R11. Workload mapping enforces the SPIFFE prefix on every candidate source and derives the trust domain from the identity URI when the trust domain is not explicitly mapped. Neither is configurable.
- R12. The required anchor for each role — subject identifier, client identifier, workload identity — continues to deny at runtime when no candidate resolves, under today's denial code.

**Presets and compatibility**

- R13. An absent mapper setting and the standard mapper name produce the same identity output as today for the same token, across all three roles.
- R14. The standard shape is expressed as a preset and is what the default resolves to. The Rust standard mapper remains part of the crate's public API.
- R15. An equivalence check compares the standard preset against the Rust standard mapper over a token corpus spanning all three roles and every fallback the Rust mapper implements. Divergence fails the gate.
- R16. Presets ship for Keycloak, Auth0, and Cognito, written in the same declarative surface an operator writes, and readable as configuration.
- R17. An unrecognized preset name fails at construction and lists the valid names, matching how an unknown mapper name fails today.
- R18. The custom Rust mapper trait remains available and its public shape is unchanged, so an integrator with an identity flow this surface does not cover keeps the code path.

**Diagnostics**

- R19. A field where no candidate resolved is distinguishable at runtime from a field whose path resolved to an empty collection. Both name the field; the former names every path tried.
- R20. A field may opt into denying the request when no candidate resolves, so a mistyped path fails loudly instead of minting an under-privileged identity. The default stays permissive.

**Claims bag**

- R21. A top-level claim consumed by a single-segment path is excluded from the claims bag. A nested path leaves its parent claim intact and visible to policy. Registered JWT claims are always excluded.
- R22. A map may override the inferred set, both to exclude an additional claim and to re-include one that would otherwise be dropped.

---

## Acceptance Examples

- AE1. **Covers R1, R5, R6.** Given a Keycloak token carrying realm roles in a nested object and per-client roles in another, when the subject role field lists both paths and declares that every candidate contributes, the subject's roles are the union of both sources.
- AE2. **Covers R2.** Given an Auth0 token carrying a namespaced roles claim whose name contains dots, when that name is written as one segment with its dots escaped, the roles resolve from that claim and are not treated as a traversal.
- AE3. **Covers R3.** Given a Cognito token carrying a colon-prefixed groups claim, when that name is written verbatim as a path, the teams resolve from it.
- AE4. **Covers R7.** Given a token whose permissions arrive as a single space-separated string, when the field declares splitting, each entry becomes its own permission; without that declaration the whole string is one entry.
- AE5. **Covers R13, R15.** Given any token in the equivalence corpus, when it is mapped through the standard preset and through the Rust standard mapper, both produce identical typed fields and identical claims bags.
- AE6. **Covers R19, R20.** Given a map with a mistyped role path, when a token is mapped, the diagnostic names the field and the path tried and is distinct from the diagnostic a genuinely empty role array produces; when that field opted into strict handling, the request is denied instead.
- AE7. **Covers R21.** Given a Keycloak map that reads roles from a nested path, when a token is mapped, the parent claim still appears whole in the claims bag, so a policy reading through it keeps working.
- AE8. **Covers R11.** Given a token whose subject is not SPIFFE-shaped but which carries a SPIFFE-shaped claim elsewhere, when mapped for the workload role, no workload identity is produced from the non-SPIFFE subject and the guard cannot be configured off.
- AE9. **Covers R10.** Given a resolver configured for the client role and a map declaring only a subject section, construction fails and names the missing role.
- AE10. **Covers R4.** Given a path ending in a lone escape character, construction fails and names both the field and the path.

---

## Success Criteria

- An operator running Keycloak, Auth0, or Cognito wires roles, permissions, and teams from configuration alone, with no Rust and no rebuild — including the nested and namespaced shapes that motivated the work.
- A deployment that upgrades without touching its config sees identity output identical to what it sees today, and the equivalence check is what proves it rather than review judgment.
- A policy author gating on typed identity fields no longer needs to know the IdP's claim layout, and a colon- or dot-containing claim name is reachable through the map even where the policy language cannot address it directly.
- A mistyped path is diagnosable from what the plugin emits, without reading source.
- Planning does not need to invent the config surface: path syntax, escaping rule, per-field shape, role coverage, preset behavior, and claims-bag rule are all decided here.

---

## Scope Boundaries

- Array indexing and wildcard segments in paths.
- Value transforms — casing, prefixing to disambiguate roles drawn from several sources, filtering, regex extraction.
- Mapping the client trust level or the workload attestation timestamp.
- Layering a preset with per-field overrides. An operator picks a preset or writes a map.
- A per-field expression language.
- Validating a map against a sample token as a config lint or CLI check.
- Any change to how claims flatten into the policy attribute bag downstream.
- The header-projection and capability-gating discussion in the referenced upstream thread. This work is the claim-map half only.

---

## Key Decisions

- **Backslash escaping over quoting, segment arrays, or a literal-name sigil**: one separator and one escape, general enough to escape a single segment inside a longer path, and authorable as a plain scalar in YAML. Quoting collides with YAML's own quoting; a segment array collides with candidate lists; a whole-name sigil cannot express a dotted segment inside a path.
- **Union merge ships in v1, though the issue did not ask for it**: Keycloak splits roles across realm-wide and per-client scopes and operators commonly want both. First-match cannot express that, so without union the Keycloak case is addressable but not usable.
- **Ordered candidate lists are not optional**: the standard shape is built on fallbacks — client identifier to authorized party, permissions to scope, teams to groups, subject to explicit identity claim. A single path per field cannot express the standard mapper, which would make expressing presets as configuration impossible.
- **The standard preset is the runtime path, not a tested twin**: one runtime mapping path, presets readable and forkable as configuration, and the standard shape serves as the worked example for preset authors. The Rust mapper stays public for API compatibility and becomes the equivalence oracle.
- **SPIFFE guards are invariants, not knobs**: the prefix check on every candidate source exists so a non-SPIFFE subject cannot smuggle in an arbitrary identity claim. Exposing it as configuration would make the config path a security downgrade from the Rust mapper.
- **Claims-bag exclusion is inferred, with overrides**: inference reproduces today's reserved set exactly, because every claim the standard shape consumes is addressed by a single-segment path — while a nested role path leaves its parent visible, so existing policies reading through it keep working. Excluding consumed parents would break them silently.
- **Strict handling is opt-in per field, not the default**: a legitimately absent optional claim is routine, so denying on it by default would deny users who simply hold no teams.

---

## Dependencies / Assumptions

- [#9](https://github.com/praxis-proxy/policy/pull/9) is merged, so claim values keep their JSON shape into the identity extensions. The structure paths address exists because of it.
- Plugin configuration reaches the plugin as JSON regardless of the format an operator authors, so the escaping rule must be authorable in both YAML and JSON. Verified against the plugin's config type.
- The plugin crate has no path-resolution helper reachable today, and the one that exists elsewhere in the workspace is in a crate this plugin does not depend on and has neither escaping nor the semantics required here. Verified against the crate's dependencies and that helper's implementation.
- The plugin crate carries no YAML dependency today. Verified against its manifest. Preset files are consumed in a format the crate can already parse; which format is a planning decision.
- Equivalence between the standard preset and the Rust mapper rests on corpus coverage, not proof. The corpus is a deliverable of this work, not test scaffolding.
- Repo convention: requirement identifiers from this document must not appear in commit messages, code comments, rustdoc, changelog entries, or pull-request descriptions. Describe the behavior instead.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R7][Technical] Split vocabulary — whitespace only, or an arbitrary delimiter. Whitespace covers every OAuth-style shape known to be needed; an arbitrary delimiter costs little but widens the surface.
- [Affects R6][Technical] Whether union deduplicates, and how ordering is made deterministic for the identity fields that preserve insertion order rather than holding a set.
- [Affects R15, R16][Needs research] Sourcing realistic token shapes for the corpus and the three presets, so fixtures reflect what these IdPs actually mint rather than what documentation summarizes.
- [Affects R14, R16][Technical] How preset definitions are embedded in the crate and validated as part of the gate, so a broken preset cannot ship.
- [Affects R19][Technical] Diagnostic levels and whether a per-field miss is rate-limited, given this runs on every request.
