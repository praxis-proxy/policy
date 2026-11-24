# Concepts

The policy engine uses identity, request context, and session state to decide
which operations may run and how their data may flow.

- [How the Policy Engine works](overview.md):
  follow identity, authorization, redaction, and session state through one
  scenario
- [Use Cases](use-cases.md):
  see the controls in a gateway deployment, with scripts for each scenario
- [Vision](vision.md):
  the Reference Monitor model and PPE's place in an agent stack
- [Threat Model](threat-model.md):
  the assumed adversary, enforcement boundary, and coverage of each placement
- [Plugins and Pipeline](pipeline.md):
  hooks, plugin dispatch, and execution modes
- [Common Message Format](cmf.md):
  the envelope that represents tools, inference, prompts, and resources
- [Extensions and Capability Gating](extensions.md):
  typed request state and the capabilities that control plugin access
- [CMF extensions and the attribute bag](cmf-extensions.md):
  the flattened keys policy reads and their absent-value contracts

[Documentation index](../index.md)
