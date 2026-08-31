// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Classify a resolver result into [`Outcome`] using stable markers, not the
//! full English `reason` sentence.

use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::step::{PdpDecision, PdpError};

use crate::outcome::{CauseKind, Outcome, Verdict};

/// Map `evaluate`'s `Result` onto a verdict and cause kind.
pub(crate) fn classify(result: Result<PdpDecision, PdpError>) -> Outcome {
    match result {
        Err(PdpError::Dispatch(_)) => Outcome::dispatch_error(),
        Err(PdpError::NoResolver(_)) => Outcome {
            // The harness always registers the three shipped dialects. A
            // missing resolver is a harness bug, not a policy deny. Treat it
            // as dispatch so the catalog fails loudly instead of looking like
            // a DefaultDeny.
            verdict: Verdict::DispatchError,
            kind: CauseKind::DispatchError,
        },
        Ok(decision) => classify_decision(&decision),
    }
}

fn classify_decision(decision: &PdpDecision) -> Outcome {
    match &decision.decision {
        Decision::Allow => Outcome::allow(),
        Decision::Deny {
            reason,
            rule_source,
        } => classify_deny(reason.as_deref().unwrap_or(""), rule_source),
    }
}

fn classify_deny(reason: &str, rule_source: &str) -> Outcome {
    if rule_source == "cedar.evaluation_error"
        || reason.starts_with("Cedar evaluation produced errors")
        || reason.starts_with("CEL eval error:")
        || reason.starts_with("OPA eval error:")
    {
        return Outcome::deny(CauseKind::EvalError);
    }
    if reason.starts_with("CEL compile error")
        || reason.starts_with("OPA inline module:")
        || reason.starts_with("OPA inline-module cache full")
    {
        return Outcome::deny(CauseKind::CompileError);
    }
    if rule_source == "cedar.default_deny" || reason == "OPA query undefined — request not granted"
    {
        return Outcome::deny(CauseKind::DefaultDeny);
    }
    if reason == "CEL expression evaluated to false" || reason == "OPA query evaluated to false" {
        return Outcome::deny(CauseKind::PolicyFalse);
    }
    if rule_source != "cel" && rule_source != "opa" && rule_source != "cedar.default_deny" {
        return Outcome::deny(CauseKind::ForbidMatched);
    }
    Outcome::deny(CauseKind::PolicyFalse)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn deny_decision(reason: &str, rule_source: &str) -> PdpDecision {
        PdpDecision {
            decision: Decision::Deny {
                reason: Some(reason.to_owned()),
                rule_source: rule_source.to_owned(),
            },
            diagnostics: vec![],
        }
    }

    #[test]
    fn allow_is_allow() {
        let d = PdpDecision {
            decision: Decision::Allow,
            diagnostics: vec![],
        };
        assert_eq!(classify(Ok(d)), Outcome::allow());
    }

    #[test]
    fn cel_false_is_policy_false() {
        let d = deny_decision("CEL expression evaluated to false", "cel");
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::PolicyFalse));
    }

    #[test]
    fn cel_eval_error_is_classified_by_prefix() {
        let d = deny_decision(
            "CEL eval error: no such key (expr references variables: [\"role\"]; \
             present in bag: []; missing: [\"role\"])",
            "cel",
        );
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::EvalError));
    }

    #[test]
    fn cedar_default_deny_uses_rule_source() {
        let d = deny_decision(
            "no Cedar permit policy matched the request",
            "cedar.default_deny",
        );
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::DefaultDeny));
    }

    #[test]
    fn cedar_eval_error_uses_rule_source() {
        let d = deny_decision(
            "Cedar evaluation produced errors (fail-closed): type error",
            "cedar.evaluation_error",
        );
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::EvalError));
    }

    #[test]
    fn opa_undefined_is_default_deny() {
        let d = deny_decision("OPA query undefined — request not granted", "opa");
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::DefaultDeny));
    }

    #[test]
    fn dispatch_error_is_not_a_decision() {
        let err = PdpError::Dispatch("floating-point value".to_owned());
        assert_eq!(classify(Err(err)), Outcome::dispatch_error());
    }

    #[test]
    fn cedar_forbid_is_forbid_matched() {
        let d = deny_decision("forbid policy matched", "cedar.policy_id");
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::ForbidMatched));
    }

    #[test]
    fn cel_compile_error_is_compile_error() {
        let d = deny_decision("CEL compile error: undeclared reference", "cel");
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::CompileError));
    }

    #[test]
    fn opa_inline_module_error_is_compile_error() {
        let d = deny_decision("OPA inline module: compile failed", "opa");
        assert_eq!(classify(Ok(d)), Outcome::deny(CauseKind::CompileError));
    }
}
