// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `SubjectAccessReview` PPE sends and the verdict it reads back. The API
// server always sends `status.allowed` and omits `denied` unless it is true.
// With neither true, no authorizer had an opinion, which the API server itself
// treats as a denial.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::pdps::kubernetes_sar::config::Attributes;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The review endpoint, relative to the API server's base URL.
pub(crate) const REVIEW_PATH: &str = "/apis/authorization.k8s.io/v1/subjectaccessreviews";

/// The `apiVersion` of the review sent and of a valid answer.
const API_VERSION: &str = "authorization.k8s.io/v1";

/// The `kind` of the review sent and of a valid answer.
const KIND: &str = "SubjectAccessReview";

// -----------------------------------------------------------------------------
// Request
// -----------------------------------------------------------------------------

/// The review object.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewRequest {
    pub(crate) api_version: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) spec: ReviewSpec,
}

impl ReviewRequest {
    pub(crate) fn new(spec: ReviewSpec) -> Self {
        Self {
            api_version: API_VERSION,
            kind: KIND,
            spec,
        }
    }
}

/// Its `spec`.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewSpec {
    #[serde(flatten)]
    pub(crate) attributes: Attributes<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) extra: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) groups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) uid: Option<String>,
    pub(crate) user: String,
}

// -----------------------------------------------------------------------------
// Verdict
// -----------------------------------------------------------------------------

/// What the API server decided, with the text it gave for audit.
#[derive(Debug, PartialEq)]
pub(crate) enum Verdict {
    /// An authorizer allowed the request.
    Allowed(Vec<String>),
    /// An authorizer denied it, or none had an opinion.
    NotAllowed(Vec<String>),
}

/// Read the verdict from a review answer.
///
/// Only a `SubjectAccessReview` with a boolean `status.allowed` is a verdict,
/// so an endpoint that is not the review API cannot grant by answering with
/// some other object's `status`.
///
/// # Errors
///
/// A body that is not JSON or not a v1 `SubjectAccessReview`, has no `status`
/// object, lacks a boolean `allowed`, or carries a non-boolean `denied`.
pub(crate) fn read_verdict(body: &[u8]) -> Result<Verdict, String> {
    let parsed: Value =
        serde_json::from_slice(body).map_err(|e| format!("the review is not JSON: {e}"))?;
    if parsed.get("apiVersion").and_then(Value::as_str) != Some(API_VERSION)
        || parsed.get("kind").and_then(Value::as_str) != Some(KIND)
    {
        return Err(format!("the answer is not a `{API_VERSION}` `{KIND}`"));
    }
    let status = parsed
        .get("status")
        .and_then(Value::as_object)
        .ok_or("the review carries no `status` object")?;

    let allowed = status
        .get("allowed")
        .and_then(Value::as_bool)
        .ok_or("`status.allowed` is missing or not a boolean")?;
    let denied = match status.get("denied") {
        None => false,
        Some(value) => value.as_bool().ok_or("`status.denied` is not a boolean")?,
    };

    let mut diagnostics = Vec::new();
    for field in ["reason", "evaluationError"] {
        if let Some(text) = status.get(field).and_then(Value::as_str)
            && !text.is_empty()
        {
            diagnostics.push(format!("kubernetes-sar {field}: {text}"));
        }
    }
    if !allowed && !denied {
        diagnostics.push("kubernetes-sar: no authorizer had an opinion".to_owned());
    }

    // An authorizer chain stops at the first opinion, so both set is a broken
    // server; deny rather than trust either flag.
    Ok(if allowed && !denied {
        Verdict::Allowed(diagnostics)
    } else {
        Verdict::NotAllowed(diagnostics)
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::pdps::kubernetes_sar::config::NonResourceFields;

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn allowed_reads_as_allowed_with_the_reason() {
        let verdict = read_verdict(&answer(r#"{"allowed":true,"reason":"RBAC: allowed"}"#))
            .expect("a well-formed review");

        assert_eq!(
            verdict,
            Verdict::Allowed(vec!["kubernetes-sar reason: RBAC: allowed".to_owned()]),
            "the API server's reason is kept for audit"
        );
    }

    #[test]
    fn an_explicit_denial_is_not_allowed() {
        let verdict = read_verdict(&answer(r#"{"allowed":false,"denied":true}"#))
            .expect("a well-formed review");

        assert!(
            matches!(verdict, Verdict::NotAllowed(_)),
            "an explicit denial must deny"
        );
    }

    #[test]
    fn no_opinion_is_not_allowed_and_says_so() {
        let verdict = read_verdict(&answer(r#"{"allowed":false}"#)).expect("a well-formed review");

        assert_eq!(
            verdict,
            Verdict::NotAllowed(vec![
                "kubernetes-sar: no authorizer had an opinion".to_owned()
            ]),
            "no authorizer allowing is no opinion, which denies"
        );
    }

    #[test]
    fn allowed_and_denied_together_deny() {
        let verdict = read_verdict(&answer(r#"{"allowed":true,"denied":true}"#))
            .expect("a well-formed review");

        assert!(
            matches!(verdict, Verdict::NotAllowed(_)),
            "contradictory flags must not allow"
        );
    }

    #[test]
    fn an_evaluation_error_beside_allowed_still_allows() {
        let verdict = read_verdict(&answer(
            r#"{"allowed":true,"evaluationError":"webhook timed out"}"#,
        ))
        .expect("a well-formed review");

        assert_eq!(
            verdict,
            Verdict::Allowed(vec![
                "kubernetes-sar evaluationError: webhook timed out".to_owned()
            ]),
            "an authorizer later in the chain allowed, so the error is diagnostic only"
        );
    }

    #[test]
    fn malformed_answers_are_errors() {
        let cases = [
            ("not JSON", b"not json".to_vec()),
            (
                "no status",
                br#"{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview"}"#
                    .to_vec(),
            ),
            ("no allowed", answer("{}")),
            ("allowed not a boolean", answer(r#"{"allowed":"yes"}"#)),
            (
                "denied not a boolean",
                answer(r#"{"allowed":false,"denied":1}"#),
            ),
            ("no envelope", br#"{"status":{"allowed":true}}"#.to_vec()),
            (
                "another kind",
                br#"{"apiVersion":"v1","kind":"Status","status":{"allowed":true}}"#.to_vec(),
            ),
        ];
        for (case, body) in cases {
            assert!(
                read_verdict(&body).is_err(),
                "{case} must be refused, not read as a verdict"
            );
        }
    }

    #[test]
    fn the_request_omits_unset_fields() {
        let request = ReviewRequest::new(ReviewSpec {
            attributes: Attributes::NonResource(NonResourceFields {
                path: "/tools/search".to_owned(),
                verb: "post".to_owned(),
            }),
            extra: BTreeMap::new(),
            groups: Vec::new(),
            uid: None,
            user: "system:serviceaccount:team-a:agent".to_owned(),
        });

        assert_eq!(
            serde_json::to_value(&request).expect("serializes"),
            serde_json::json!({
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SubjectAccessReview",
                "spec": {
                    "user": "system:serviceaccount:team-a:agent",
                    "nonResourceAttributes": { "path": "/tools/search", "verb": "post" }
                }
            }),
            "empty groups and extra and an unset uid are omitted, not sent empty"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// A v1 review answer carrying `status`.
    fn answer(status: &str) -> Vec<u8> {
        format!(
            r#"{{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{status}}}"#
        )
        .into_bytes()
    }
}
