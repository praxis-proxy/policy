# Praxis Policy Engine Documentation

PPE is a policy enforcement runtime for AI agents: a deterministic
reference monitor that mediates every operation an agent triggers. It
decides who may call which tool, what data comes back, and where that
data is allowed to go next.

Each capability an agent can invoke defines its own enforcement
pipeline covering authorization, delegation, redaction, information
flow control, and audit. APL is the configuration that defines that
pipeline, and it runs in two phases: before the operation and after
its result.

## Getting started

- [Quick Start](quickstart.md):
  stand up an enforcement point and run your first policy
- [Overview](overview.md):
  how it works, followed through one scenario end to end
- [Use Cases](use-cases.md):
  the controls running behind a real gateway

## Why it exists

- [Vision](vision.md):
  the reference monitor model and where PPE sits in an agent stack
- [Threat Model](threat-model.md):
  the adversary, the trust boundary, and what each placement defends

## Writing policy

- [APL](apl/README.md):
  routes, phases, predicates, rules, and field pipelines
- [Grammar](apl-grammar.md):
  the normative grammar; where it and the parser disagree, one is a bug
- [Effects and Sequencing](apl/effects.md):
  the effect catalog, halt-on-deny, sequential and parallel composition
- [PDP Integration](apl/pdp.md):
  handing a decision to Cedar, CEL, or OPA
- [Identity](apl/identity.md):
  resolving a caller and what lands in the attribute bag
- [Static Attributes](apl/attributes.md):
  operator-maintained facts read under `data.*`
- [Delegation](apl/delegation.md):
  token exchange, delegation subjects, and token caching
- [Elicitation](apl/elicitation.md):
  human in the loop, and the suspend and resume model
- [Session Tainting](apl/tainting.md):
  information flow labels that outlive a single call
- [Backend Restriction](apl/restrict.md):
  constraining where a call is allowed to land

## Configuring and operating

- [Configuration](configuration.md):
  the config document, its five top-level keys, and both dispatch modes
- [HTTP Routing](http-routing.md):
  the `http:` route selector, precedence, and the catch-all report
- [Identity and Delegation](identity-delegation.md):
  inbound identity slots, outbound delegation subjects, and six recipes
- [Header Assertions](assertions.md):
  projecting derived identity onto upstream requests
- [Deployment](deployment.md):
  the same policy at a gateway, a sidecar, or in-framework
- [Patterns](patterns.md):
  layered enforcement, shadow rollout, guardrails, least privilege
- [Upgrading APL](upgrade-apl.md):
  every key and form an existing configuration must rewrite

## Architecture

- [Plugins and Pipeline](pipeline.md):
  hooks, the plugin manager, and execution modes
- [Canonical Message Format](cmf.md):
  the protocol-agnostic envelope policy reasons about
- [Extensions and Capability Gating](extensions.md):
  typed contextual state, and the capabilities that unlock it

## Reference

- [Crates](crates.md):
  what each crate in the workspace is for
- [Builtins](builtins.md):
  bundled plugins, decision points, session stores, and their features
- [Testing](testing.md):
  testing a policy as code

## Project

- [Lints](lints.md):
  rationale for the workspace lint set
- [Security Analysis](security-analysis.md):
  the point-in-time security review record
- [Import Provenance](port-provenance.md):
  where this tree came from and what was deliberately left behind
- [Contributing](../CONTRIBUTING.md) and
  [Changelog](../CHANGELOG.md)

## Notes on the diagrams

The diagrams here are SVG sources, editable as text. Two pages carry
fewer diagrams than they once did, because the originals existed only
as rendered images with no source to correct: `overview.md` lost its
scenario diagram and `deployment.md` lost its placement diagram.
