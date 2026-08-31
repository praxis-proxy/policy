// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Verdict and cause kind for one dialect's evaluation.

/// Allow, deny, or a dispatch error that never became a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The resolver returned [`Decision::Allow`](praxis_policy_apl_core::Decision::Allow).
    Allow,
    /// The resolver returned [`Decision::Deny`](praxis_policy_apl_core::Decision::Deny).
    Deny,
    /// `evaluate` returned `Err(PdpError::Dispatch(_))`.
    DispatchError,
}

/// Which Deny (or error) it was. Distinguishes "policy said no" from
/// "the engine could not decide" without pinning the full English `reason`
/// string, which includes library wording and bag dumps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CauseKind {
    /// `Decision::Allow`.
    Allow,
    /// CEL/OPA: the expression or query evaluated to `false`. The key was
    /// present. Cedar does not use this for a no-match (that is
    /// [`CauseKind::DefaultDeny`]).
    PolicyFalse,
    /// Cedar: no permit matched (`rule_source == "cedar.default_deny"`).
    /// OPA: the query was undefined (not granted).
    DefaultDeny,
    /// A named forbid / deny-set entry produced the deny.
    ForbidMatched,
    /// CEL eval error, Cedar runtime evaluation error.
    EvalError,
    /// CEL compile error or OPA inline-module compile error.
    CompileError,
    /// `PdpError::Dispatch` — for example Cedar rejecting a resource float.
    DispatchError,
}

/// One dialect's classified result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) verdict: Verdict,
    pub(crate) kind: CauseKind,
}

impl Outcome {
    pub(crate) const fn allow() -> Self {
        Self {
            verdict: Verdict::Allow,
            kind: CauseKind::Allow,
        }
    }

    pub(crate) const fn deny(kind: CauseKind) -> Self {
        Self {
            verdict: Verdict::Deny,
            kind,
        }
    }

    pub(crate) const fn dispatch_error() -> Self {
        Self {
            verdict: Verdict::DispatchError,
            kind: CauseKind::DispatchError,
        }
    }
}
