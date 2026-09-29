// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Translation from `cedar_policy::Response` into `praxis_policy_apl_core::PdpDecision`.
//
// What we preserve:
//
//   - `decision`     — Allow ↔ Deny. One-to-one.
//   - `diagnostics`  — the set of policy IDs that *determined* the
//                      decision (not "matched" — Cedar's `reason()` is
//                      the policies whose effect produced the outcome).
//                      Operators who annotated their policies with
//                      `@id("...")` get meaningful identifiers; without
//                      annotations they get `policy0`, `policy1`, ….
//   - `rule_source`  — first policy ID from `diagnostics`. Becomes the
//                      violation code on Deny so audit logs / wire
//                      errors say "denied via owner-override" rather
//                      than "cedar.deny."
//
// What we drop (for now):
//
//   - Obligations — Cedar 4.10 doesn't have first-class obligations.
//     Policy annotations could carry them (`@obligation(...)`) but
//     wiring the annotation vocabulary is deferred.
//
// # Fail-closed on evaluation errors
//
// Cedar's `Response::diagnostics().errors()` lists policies that errored
// during runtime evaluation (e.g. type errors in a `when` clause that
// only manifest with certain entity data). If ANY policy errored, we
// return Deny regardless of what `decision()` says — an untrusted
// decision is worse than a closed gate. Each error flows into the Deny
// reason as its policy id and a fixed category. Cedar's own text is dropped,
// because it can quote context values such as extension function arguments
// or overflowing operands, and those can come from the client's payload.
//
// # Withheld structured input
//
// When the structured input holds a Cedar escape key, the step denies with
// `WITHHELD_CODE` before Cedar runs.

use cedar_policy::{AuthorizationError, Decision as CedarDecision, EvaluationError, PolicySet};
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::step::PdpDecision;

/// Violation code for a step whose structured input was withheld.
pub const WITHHELD_CODE: &str = "cedar.input_withheld";

/// Deny a step whose structured input holds a Cedar escape key. The reason
/// names no value or key from the input.
pub fn withheld() -> PdpDecision {
    PdpDecision {
        decision: Decision::Deny {
            reason: Some(
                "Cedar step denied: structured input holds a reserved Cedar escape key".to_owned(),
            ),
            rule_source: WITHHELD_CODE.to_owned(),
        },
        diagnostics: Vec::new(),
    }
}

/// The policy's `@id` annotation, or Cedar's auto-generated id.
fn policy_name(policy_set: &PolicySet, pid: &cedar_policy::PolicyId) -> String {
    policy_set
        .policy(pid)
        .and_then(|p| p.annotation("id"))
        .map_or_else(|| pid.to_string(), std::borrow::ToOwned::to_owned)
}

/// A value-free line for one evaluation error: the policy and a category.
fn error_line(error: &AuthorizationError, policy_set: &PolicySet) -> String {
    let AuthorizationError::PolicyEvaluationError(inner) = error;
    format!(
        "policy `{}`: {}",
        policy_name(policy_set, inner.policy_id()),
        error_category(inner.inner())
    )
}

/// A fixed category for an evaluation error, never Cedar's message text.
fn error_category(error: &EvaluationError) -> &'static str {
    match error {
        EvaluationError::EntityDoesNotExist(_) => "entity does not exist",
        EvaluationError::EntityAttrDoesNotExist(_) => "entity attribute or tag does not exist",
        EvaluationError::RecordAttrDoesNotExist(_) => "record attribute does not exist",
        EvaluationError::FailedExtensionFunctionLookup(_) => "extension function lookup failed",
        EvaluationError::TypeError(_) => "type error",
        EvaluationError::WrongNumArguments(_) => "wrong number of arguments",
        EvaluationError::IntegerOverflow(_) => "integer overflow",
        EvaluationError::UnlinkedSlot(_) => "unlinked template slot",
        EvaluationError::FailedExtensionFunctionExecution(_) => "extension function failed",
        EvaluationError::NonValue(_) => "expression contains unknowns",
        EvaluationError::RecursionLimit(_) => "recursion limit reached",
        #[allow(
            unreachable_patterns,
            reason = "an optional cedar feature adds a variant"
        )]
        _ => "evaluation error",
    }
}

/// Translate a `cedar_policy::Response` into the APL-side `PdpDecision`.
/// Captures policy-ID attribution into `diagnostics` and, on Deny,
/// surfaces the first firing policy as the `rule_source`.
///
/// # `@id` annotation lookup
///
/// `PolicySet::from_str` assigns auto-IDs (`policy0`, `policy1`, ...);
/// authors get *meaningful* identifiers by annotating each policy with
/// `@id("my-rule")`. We resolve auto-IDs to annotation values here so
/// the rest of the system sees the names operators chose. Policies
/// without `@id` annotations keep their auto-IDs — explicit-is-better
/// fallback rather than silent translation.
pub fn translate(response: &cedar_policy::Response, policy_set: &PolicySet) -> PdpDecision {
    let diagnostics = response.diagnostics();

    // Prefer the operator-supplied `@id("...")` annotation; fall back to
    // Cedar's auto-generated id when the policy is unannotated.
    let firing_policies: Vec<String> = diagnostics
        .reason()
        .map(|pid| policy_name(policy_set, pid))
        .collect();

    let errors: Vec<String> = diagnostics
        .errors()
        .map(|e| error_line(e, policy_set))
        .collect();

    // Fail-closed: any runtime evaluation error → Deny naming the policy
    // and error category so the operator sees what went wrong. Cedar's own
    // `decision()` may still say Allow when errors occurred; we override
    // because an Allow on a partially-failed evaluation isn't
    // trustworthy.
    if !errors.is_empty() {
        let reason = format!(
            "Cedar evaluation produced errors (fail-closed): {}",
            errors.join("; ")
        );
        let rule_source = firing_policies
            .first()
            .cloned()
            .unwrap_or_else(|| "cedar.evaluation_error".to_owned());
        return PdpDecision {
            decision: Decision::Deny {
                reason: Some(reason),
                rule_source,
            },
            diagnostics: firing_policies,
        };
    }

    let decision = match response.decision() {
        CedarDecision::Allow => Decision::Allow,
        CedarDecision::Deny => {
            // Build a human-readable reason from the firing policies so
            // wire errors and audit logs carry attribution. First
            // policy ID becomes the violation code.
            let reason = if firing_policies.is_empty() {
                // Cedar deny with no firing policy means no `permit`
                // matched — the "default deny" case.
                "no Cedar permit policy matched the request".to_owned()
            } else {
                format!("denied by Cedar policy: {}", firing_policies.join(", "))
            };
            let rule_source = firing_policies
                .first()
                .cloned()
                .unwrap_or_else(|| "cedar.default_deny".to_owned());
            Decision::Deny {
                reason: Some(reason),
                rule_source,
            }
        },
    };

    PdpDecision {
        decision,
        diagnostics: firing_policies,
    }
}
