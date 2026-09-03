// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Known divergences. Each entry is a named split the catalog may cite.
//! An unused entry or an empty reason fails the meta tests — the allowlist
//! is either empty or every row is justified.

use crate::outcome::{CauseKind, Outcome};

/// One documented, asserted split between dialects.
pub(crate) struct AllowlistEntry {
    pub(crate) id: &'static str,
    /// Why this split is acceptable. Required; empty is a meta-test failure.
    pub(crate) reason: &'static str,
    pub(crate) cedar: Outcome,
    pub(crate) cel: Outcome,
    pub(crate) opa: Outcome,
}

/// Seed entries from issue #25 (floats, missing collections) plus the
/// omitted-scalar splits the CMF absent-value contract in
/// `docs/cmf-extensions.md` names (missing claim string/int, missing
/// principal). Present-empty `StringSet` is not a split: it lives in the
/// subset as `AgreeDeny`.
pub(crate) fn allowlist() -> Vec<AllowlistEntry> {
    vec![
        AllowlistEntry {
            id: "floats-claim",
            reason: "Cedar's value model has no floating-point type. A claim \
                     float is carried as its string form so an IdP-minted \
                     non-integer does not fail the request. CEL and OPA compare \
                     the value numerically, so `confidence > 0.5` allows. Cedar \
                     has no float literal; a decimal() compare against \
                     the stringified claim is a type error and fail-closed deny.",
            cedar: Outcome::deny(CauseKind::EvalError),
            cel: Outcome::allow(),
            opa: Outcome::allow(),
        },
        AllowlistEntry {
            id: "floats-whole",
            reason: "CEL and OPA coerce a whole-number float (2.0) to an \
                     integer so `n == 2` succeeds. Cedar still stringifies the \
                     claim, and string-vs-integer equality is false rather \
                     than a type error, so the permit does not match.",
            cedar: Outcome::deny(CauseKind::DefaultDeny),
            cel: Outcome::allow(),
            opa: Outcome::allow(),
        },
        AllowlistEntry {
            id: "floats-resource",
            reason: "Operator-authored Cedar `resource.attributes` holding a \
                     float is rejected at entity build (`PdpError::Dispatch`) \
                     because the operator can fix the YAML. CEL and OPA accept \
                     the same number from the bag natively.",
            cedar: Outcome::dispatch_error(),
            cel: Outcome::allow(),
            opa: Outcome::allow(),
        },
        AllowlistEntry {
            id: "missing-collection",
            reason: "No `role.*` keys and no `subject.roles` set. Cedar still \
                     has an empty `roles` set, so `contains` is a clean false \
                     (default deny). Unguarded CEL `role.hr` is an eval error \
                     (the `role` namespace is absent). OPA with no `default` \
                     leaves `allow` undefined — a clean deny. The bridge \
                     contract in `docs/cmf-extensions.md` is: write the \
                     original set present-empty and keep flattened bools \
                     presence-only. Authors who need agreement use \
                     `subject.roles` (see `empty-set` / `bridge-empty-teams`) \
                     or guard CEL with `has(role.hr)`.",
            cedar: Outcome::deny(CauseKind::DefaultDeny),
            cel: Outcome::deny(CauseKind::EvalError),
            opa: Outcome::deny(CauseKind::DefaultDeny),
        },
        AllowlistEntry {
            id: "missing-subject-id",
            reason: "Cedar cannot build a principal without `subject.id` and \
                     returns `PdpError::Dispatch`. CEL treating `subject.id` \
                     as undeclared is an eval error. OPA with no default \
                     leaves the query undefined. Identity is required for \
                     Cedar; the other dialects fail by their missing-key \
                     rules.",
            cedar: Outcome::dispatch_error(),
            cel: Outcome::deny(CauseKind::EvalError),
            opa: Outcome::deny(CauseKind::DefaultDeny),
        },
        AllowlistEntry {
            id: "missing-claim-string",
            reason: "Optional strings are omitted, not defaulted. Unguarded \
                     `claim.tenant == \"acme\"` is a CEL eval error (no \
                     `claim` namespace). Cedar injects an empty claims \
                     record, then a missing field is an evaluation error. \
                     OPA without `default` leaves the query undefined. APL \
                     would treat the comparison as false; that is why the \
                     native evaluator is not asserted here.",
            cedar: Outcome::deny(CauseKind::EvalError),
            cel: Outcome::deny(CauseKind::EvalError),
            opa: Outcome::deny(CauseKind::DefaultDeny),
        },
        AllowlistEntry {
            id: "missing-claim-int",
            reason: "Same omission as a missing string, for `Int`. \
                     `claim.depth <= 2` against an absent key is a CEL eval \
                     error, a Cedar evaluation error on the empty claims \
                     record, and an undefined OPA query. Emitting `0` would \
                     make a missing depth pass a `<= 2` gate.",
            cedar: Outcome::deny(CauseKind::EvalError),
            cel: Outcome::deny(CauseKind::EvalError),
            opa: Outcome::deny(CauseKind::DefaultDeny),
        },
    ]
}

pub(crate) fn allowlist_by_id(id: &str) -> Option<AllowlistEntry> {
    allowlist().into_iter().find(|e| e.id == id)
}
