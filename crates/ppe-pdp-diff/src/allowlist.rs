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

/// Seed entries from issue #25 (floats, empty collections) plus the
/// closely related splits the seed implies (whole floats, resource
/// floats, missing principal).
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
            id: "empty-set",
            reason: "An empty `StringSet` is present. Cedar always materializes \
                     `principal.teams` (possibly empty) because strict mode \
                     errors on a missing attribute; `contains` is false. CEL \
                     and OPA see an empty list/array and `in` is false. This \
                     is not the missing-key case.",
            cedar: Outcome::deny(CauseKind::DefaultDeny),
            cel: Outcome::deny(CauseKind::PolicyFalse),
            opa: Outcome::deny(CauseKind::PolicyFalse),
        },
        AllowlistEntry {
            id: "missing-collection",
            reason: "No `role.*` keys. Cedar still has an empty `roles` set, so \
                     `contains` is a clean false (default deny). Unguarded CEL \
                     `role.hr` is an eval error (the `role` namespace is \
                     absent). OPA with no `default` leaves `allow` undefined — \
                     a clean deny. Same absent-ish state, three mechanisms; \
                     only Cedar's empty set is guaranteed by the bridge.",
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
    ]
}

pub(crate) fn allowlist_by_id(id: &str) -> Option<AllowlistEntry> {
    allowlist().into_iter().find(|e| e.id == id)
}
