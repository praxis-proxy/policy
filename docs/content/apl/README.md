# APL

APL (Authorization Policy Layer) defines the routes, predicates, effects, and
field pipelines that enforce a policy.

- [APL overview](index.md):
  define routes, request and response phases, predicates, and field pipelines
- [Effects and Sequencing](effects.md):
  order effects, stop on denial, and compose sequential or parallel steps
- [Identity](identity.md):
  resolve callers into the attributes policy reads
- [Static Attributes](attributes.md):
  supply configuration-time facts under `data.*`
- [Fetched Metadata](metadata.md):
  acquire request-time facts before later predicates and PDP calls
- [PDP Integration](pdp.md):
  evaluate decisions with Cedar, CEL, or OPA
- [Delegation](delegation.md):
  obtain scoped credentials for upstream calls
- [Elicitation](elicitation.md):
  pause an operation for human approval and resume it on retry
- [Session Taint](tainting.md):
  carry information-flow labels across requests
- [Backend Restriction](restrict.md):
  narrow the backends a router may select
- [Grammar](apl-grammar.md):
  the normative syntax, accepted forms, and invalid forms

See [Guides](../guides/README.md) for worked configurations and
[Reference](../reference/README.md) for configuration keys and contracts.

[Documentation index](../index.md)
