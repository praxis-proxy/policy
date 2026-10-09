// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 07: the PII scanner refuses an email carrying an SSN, after the audit
//! logger has recorded the attempt.

use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::Persona;
use serde_json::json;

use super::{audit_for, each_pdp, planted, upstream_calls};

#[tokio::test]
async fn bob_is_denied_an_email_carrying_an_ssn() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Bob, "send_email").args(json!({
            "to": "external@example.com",
            "subject": "compensation update",
            "body": "FYI, Jane Smith. Her SSN is 555-12-3456 if you need to update payroll.",
        }));
        let planted = planted(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request));
        assert_eq!(out.violation_code(), Some("pii.detected"));
        assert_eq!(out.proto_error_code(), None, "a plain -32001 deny");
        assert_eq!(upstream_calls(&host), 0);
        assert_eq!(
            audit_for(&out, "send_email").len(),
            1,
            "the denied attempt is on the audit trail: {:#?}",
            out.events.logs()
        );
        out.assert_no_leaks(&planted);
    })
    .await;
}
