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
    /// When `Some`, the catalog case must carry an `apl_rule` whose verdict
    /// matches this flag. `None` for splits that have no APL spelling.
    pub(crate) apl_allows: Option<bool>,
}

/// Seed entries from issue #25 (floats, missing collections) plus a
/// missing principal, then the structured-input splits Cedar's value
/// model forces. Present-empty `StringSet` and omitted claim scalars are
/// not splits: they live in the subset as `AgreeDeny`.
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
            apl_allows: None,
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
            apl_allows: None,
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
            apl_allows: None,
        },
        AllowlistEntry {
            id: "missing-collection",
            reason: "No `role.*` keys and no `subject.roles` set. Cedar still \
                     has an empty `roles` set, so `contains` is a clean false \
                     (default deny). Unguarded CEL `role.hr` is an eval error \
                     (the `role` namespace is absent). OPA with no `default` \
                     leaves `allow` undefined — a clean deny. The bridge \
                     contract in `docs/content/cmf-extensions.md` is: write the \
                     original set present-empty and keep flattened bools \
                     presence-only. Authors who need agreement use \
                     `subject.roles` (see `empty-set` / `bridge-empty-teams` / \
                     `bridge-empty-roles`). `has(role.hr)` is not a CEL guard \
                     here: with no `role.*` keys the `role` namespace does not \
                     exist, and `has(role.hr)` is itself an eval error.",
            cedar: Outcome::deny(CauseKind::DefaultDeny),
            cel: Outcome::deny(CauseKind::EvalError),
            opa: Outcome::deny(CauseKind::DefaultDeny),
            apl_allows: None,
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
            apl_allows: None,
        },
        AllowlistEntry {
            id: "missing-claim-not-eq",
            reason: "APL `!=` on a missing key is true (duality with `!(==)`), \
                     so `require(claim.tenant != \"acme\")` Allows. CEL and \
                     Cedar treat the omitted claim as an eval error (Deny). \
                     OPA without `default` leaves the query undefined \
                     (DefaultDeny). Authors who need the denylist closed \
                     write `require(exists(claim.tenant) & claim.tenant != \
                     \"acme\")`. See `docs/content/cmf-extensions.md`.",
            cedar: Outcome::deny(CauseKind::EvalError),
            cel: Outcome::deny(CauseKind::EvalError),
            opa: Outcome::deny(CauseKind::DefaultDeny),
            apl_allows: Some(true),
        },
        AllowlistEntry {
            id: "missing-not-in",
            reason: "APL `not in` on a missing set is true, so \
                     `require(subject.type not in blocked_types)` Allows. CEL \
                     `!(subject.type in blocked_types)` is an eval error: \
                     `blocked_types` is undeclared. Cedar has no free \
                     `blocked_types` bag key; the catalog uses \
                     `!(principal.claims.blocked.contains(principal.type))`, \
                     which is an eval error on the missing claim set. OPA \
                     `not (x in y)` on an undefined `y` is true, so OPA \
                     Allows with APL. The split is CEL/Cedar Deny vs \
                     APL/OPA Allow.",
            cedar: Outcome::deny(CauseKind::EvalError),
            cel: Outcome::deny(CauseKind::EvalError),
            opa: Outcome::allow(),
            apl_allows: Some(true),
        },
        AllowlistEntry {
            id: "tool-deny-list-evaded",
            reason: "Cedar cannot express \"deny if any tool's field equals X\". \
                     Record-set `contains` matches only a whole record, so a \
                     forbidden tool with any extra field, here a description, \
                     slips past and Cedar Allows. CEL `exists` and OPA `some` \
                     test the one field and Deny. Pinned so the documented \
                     rule holds: do not use Cedar for deny-lists over \
                     `llm.request.tools`; use OPA or CEL.",
            cedar: Outcome::allow(),
            cel: Outcome::deny(CauseKind::PolicyFalse),
            opa: Outcome::deny(CauseKind::PolicyFalse),
            apl_allows: None,
        },
        AllowlistEntry {
            id: "tool-deny-list-unexpressible",
            reason: "All three Allow, but Cedar only by coincidence: its \
                     exact-match `contains` also Allows the forbidden tool \
                     (see `tool-deny-list-evaded`). Listed so Cedar never \
                     counts as agreeing on a deny-list over \
                     `llm.request.tools`.",
            cedar: Outcome::allow(),
            cel: Outcome::allow(),
            opa: Outcome::allow(),
            apl_allows: None,
        },
        AllowlistEntry {
            id: "null-absent",
            reason: "Cedar has no null, so the sanitizer drops a `null` \
                     field and `has` is false: a clean default deny. CEL \
                     `has` and OPA `object.keys` see the key with a null \
                     value and Allow. Policies that must treat null as \
                     missing test the value, not the key.",
            cedar: Outcome::deny(CauseKind::DefaultDeny),
            cel: Outcome::allow(),
            opa: Outcome::allow(),
            apl_allows: None,
        },
        AllowlistEntry {
            id: "duplicates-collapse",
            reason: "JSON arrays become Cedar sets, which are unordered and \
                     collapse duplicates, so `[7, 7, 9] == [7, 9]` holds and \
                     Cedar Allows. CEL lists and OPA arrays keep every \
                     element, so the compare is false. Cedar cannot count or \
                     order array elements.",
            cedar: Outcome::allow(),
            cel: Outcome::deny(CauseKind::PolicyFalse),
            opa: Outcome::deny(CauseKind::PolicyFalse),
            apl_allows: None,
        },
    ]
}

pub(crate) fn allowlist_by_id(id: &str) -> Option<AllowlistEntry> {
    allowlist().into_iter().find(|e| e.id == id)
}
