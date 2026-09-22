// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-pdp-cedar-direct — `PdpResolver` over the bare `cedar-policy` crate.
//
// # Where this lives in the stack
//
//   APL evaluator (praxis-policy-apl-core)
//        │  `cedar:(action:..., resource:..., context:...)` step
//        ▼
//   PdpRouter (praxis-policy-apl-runtime)        — dispatches by dialect
//        │  resolver.evaluate(call, bag)
//        ▼
//   CedarDirectResolver         — THIS CRATE
//        │  translate to cedar_policy::Request + Entities
//        ▼
//   cedar_policy::Authorizer    — Amazon's official Cedar evaluator
//
// # Inputs (`PdpCall.args`)
//
// APL routes call cedar like:
//
// ```yaml
// policy:
//   - cedar:
//       action: 'Action::"read"'
//       resource:
//         type: Document
//         id: doc-42
//         attributes:
//           classification: internal
//           owner: 'User::"alice"'
//       context:
//         request_time: "2026-05-18T10:00:00Z"
// ```
//
// Required keys: `action`, `resource.type`, `resource.id`. Optional:
// `resource.attributes`, `context`. Principal is NOT in `args` — see
// below.
//
// # Principal
//
// The principal entity is built from the `AttributeBag` that praxis-policy-apl-cmf
// populated from `SecurityExtension.subject`:
//
//   - `subject.id`        → entity id (required; missing → request-time error)
//   - `subject.type`      → entity type. The CMF bridge writes lowercase
//                            (`user` / `agent` / `service` / `system`). When
//                            the key is absent this crate defaults to `User`
//                            (PascalCase), so a type-scoped policy can miss a
//                            principal whose type was omitted.
//   - `role.<name>=true`  → principal.roles  : Set<String>
//   - `perm.<name>=true`  → principal.permissions : Set<String>
//   - `claim.<name>=v`    → principal.claims.<name> = v
//   - `subject.teams`     → principal.teams  : Set<String>
//   - `subject.id`        → principal.id     : String
//
// Operators with richer principal shapes (custom JWT claims, workload
// trust domains) populate them upstream via identity-hook plugins; this
// crate just reads what the bag carries.
//
// # PPE-provided context
//
// In addition to whatever the policy author put in `args.context`, the
// resolver merges in well-known PPE context paths so policies can
// reason about them with a stable schema:
//
//   - `context.delegation` — `{ chain: [...], depth: N }` from
//                            `DelegationExtension` (via bag's `delegation.*`).
//   - `context.meta`       — `{ entity_type, entity_name, scope, tags }`
//                            from `MetaExtension`.
//   - `context.security`   — `{ labels: [...], classification }`.
//
// Operators document this layout in their Cedar schema; policy authors
// rely on it.
//
// # Schema (optional)
//
// Cedar schemas validate policies at load time and requests at
// evaluation time. Recommended for production deployments; skipped here
// by default to keep the construction surface simple. Add via
// `CedarDirectResolver::with_schema(schema)`.
//
// # Decision attribution
//
// Cedar's `Response::diagnostics().reason()` returns the policy IDs of
// every policy that determined the decision. These flow back through
// `PdpDecision.diagnostics`, and the first one becomes the
// `rule_source` on Deny — so APL violations carry "denied via
// owner-override" instead of an opaque "cedar.deny."
//
// Policy authors should annotate every policy with `@id("...")`:
//
// ```
// @id("owner-override")
// permit(principal, action == Action::"read", resource)
// when { principal == resource.owner };
// ```
//
// Without `@id` annotations, Cedar generates `policy0`, `policy1`, …
// which is stable but meaningless. Worth documenting as best practice.

//! Cedar decision point, over the `cedar-policy` crate directly.
//!
//! Serves a route's `cedar:(...)` step. Builds Cedar entities from the
//! attribute bag, evaluates against the configured policy set, and returns a
//! permit or deny with the determining policy ids.

/// Converts bag values into Cedar attribute values.
pub mod cedar_attrs;
/// The decision returned to the evaluator, with determining policy ids.
pub mod decision;
/// Builds the Cedar principal, action, and resource entities.
pub mod entities;
/// Errors raised while building or evaluating a request.
pub mod error;
/// Constructs the resolver from configuration.
pub mod factory;
/// Assembles a Cedar authorization request.
pub mod request;
/// The `PdpResolver` implementation.
pub mod resolver;
/// Substitutes bag references into an authored call signature.
pub mod template;

pub use error::BuildError;
pub use factory::CedarDirectPdpFactory;
pub use resolver::CedarDirectResolver;
