// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Helpers the adversarial cases share.

use praxis_policy_test_utils::fixtures::CLIENT_SECRET;
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::{self, TOKEN_EXCHANGE_URL};
use praxis_policy_test_utils::secrets::Planted;
use serde_json::Value;

/// The planted SSN of the Jane Smith record.
pub(crate) const JANE_SSN: &str = "123-45-6789";

/// The `kid` the realm publishes its key under.
pub(crate) fn realm_kid() -> String {
    idp::jwks()["keys"][0]["kid"]
        .as_str()
        .expect("the realm JWKS names a kid")
        .to_owned()
}

/// The call's own tokens plus the client secret every delegator and the
/// CIBA approver hold.
pub(crate) fn planted_for(call: &Call) -> Planted {
    let mut planted = call.planted();
    planted.plant("client secret", CLIENT_SECRET);
    planted
}

/// The bearer the upstream received in `authorization`, without its scheme.
pub(crate) fn forwarded_bearer(out: &Outcome) -> String {
    let seen = out.upstream.as_ref().expect("the upstream was called");
    seen.headers["authorization"]
        .trim_start_matches("Bearer ")
        .to_owned()
}

/// The elicitation id a pending deny carries.
pub(crate) fn elicitation_id(out: &Outcome) -> String {
    assert_eq!(
        out.violation_code(),
        Some("elicitation.pending"),
        "{:?}",
        out.violation
    );
    out.detail("elicitation_id")
        .and_then(Value::as_str)
        .expect("a pending deny carries its id")
        .to_owned()
}

/// Assert the call stopped at identity with `code`, before any CMF hook,
/// delegation or upstream call, then run the leak check.
pub(crate) fn assert_identity_deny(host: &RefHost, out: &Outcome, code: &str, planted: &Planted) {
    assert_eq!(out.denied_at, Some(Stage::Identity), "{:?}", out.violation);
    assert_eq!(out.violation_code(), Some(code), "{:?}", out.violation);
    assert!(
        out.events.audit_records().is_empty(),
        "no CMF hook ran, so the audit plugin did not"
    );
    assert_eq!(
        host.transport().call_count_for(TOKEN_EXCHANGE_URL),
        0,
        "nothing delegated"
    );
    assert!(out.upstream.is_none(), "the upstream was not called");
    assert!(
        host.upstream().requests().is_empty(),
        "the upstream saw nothing"
    );
    out.assert_no_leaks(planted);
}
