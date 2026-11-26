// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `SubjectAccessReview` PPE sends and the verdict it reads back. The API
// server omits `allowed` and `denied` when they are false; with both absent no
// authorizer had an opinion, which the API server itself treats as a denial.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The review endpoint, relative to the API server's base URL.
pub(crate) const REVIEW_PATH: &str = "/apis/authorization.k8s.io/v1/subjectaccessreviews";

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
            api_version: "authorization.k8s.io/v1",
            kind: "SubjectAccessReview",
            spec,
        }
    }
}

/// Its `spec`.
#[derive(Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewSpec {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) extra: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) groups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) non_resource_attributes: Option<NonResourceAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resource_attributes: Option<ResourceAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) uid: Option<String>,
    pub(crate) user: String,
}

/// `spec.nonResourceAttributes`.
#[derive(Debug, PartialEq, Serialize)]
pub(crate) struct NonResourceAttributes {
    pub(crate) path: String,
    pub(crate) verb: String,
}

/// `spec.resourceAttributes`.
#[derive(Debug, Default, PartialEq, Serialize)]
pub(crate) struct ResourceAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subresource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) verb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
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
/// # Errors
///
/// A body that is not JSON, has no `status` object, or carries a non-boolean
/// `allowed` or `denied`.
pub(crate) fn read_verdict(body: &[u8]) -> Result<Verdict, String> {
    let parsed: Value =
        serde_json::from_slice(body).map_err(|e| format!("the review is not JSON: {e}"))?;
    let status = parsed
        .get("status")
        .and_then(Value::as_object)
        .ok_or("the review carries no `status` object")?;

    let flag = |name: &str| match status.get(name) {
        None => Ok(false),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("`status.{name}` is not a boolean")),
    };
    let allowed = flag("allowed")?;
    let denied = flag("denied")?;

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

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn allowed_reads_as_allowed_with_the_reason() {
        let verdict = read_verdict(br#"{"status":{"allowed":true,"reason":"RBAC: allowed"}}"#)
            .expect("a well-formed review");

        assert_eq!(
            verdict,
            Verdict::Allowed(vec!["kubernetes-sar reason: RBAC: allowed".to_owned()])
        );
    }

    #[test]
    fn an_explicit_denial_is_not_allowed() {
        let verdict = read_verdict(br#"{"status":{"allowed":false,"denied":true}}"#)
            .expect("a well-formed review");

        assert!(
            matches!(verdict, Verdict::NotAllowed(_)),
            "an explicit denial must deny"
        );
    }

    #[test]
    fn no_opinion_is_not_allowed_and_says_so() {
        let verdict = read_verdict(br#"{"status":{}}"#).expect("a well-formed review");

        assert_eq!(
            verdict,
            Verdict::NotAllowed(vec![
                "kubernetes-sar: no authorizer had an opinion".to_owned()
            ]),
            "omitted flags mean no opinion, which denies"
        );
    }

    #[test]
    fn allowed_and_denied_together_deny() {
        let verdict = read_verdict(br#"{"status":{"allowed":true,"denied":true}}"#)
            .expect("a well-formed review");

        assert!(
            matches!(verdict, Verdict::NotAllowed(_)),
            "contradictory flags must not allow"
        );
    }

    #[test]
    fn an_evaluation_error_beside_allowed_still_allows() {
        let verdict =
            read_verdict(br#"{"status":{"allowed":true,"evaluationError":"webhook timed out"}}"#)
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
        for body in [
            &b"not json"[..],
            br#"{"spec":{}}"#,
            br#"{"status":{"allowed":"yes"}}"#,
        ] {
            assert!(
                read_verdict(body).is_err(),
                "{} must be refused",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn the_request_omits_unset_fields() {
        let request = ReviewRequest::new(ReviewSpec {
            user: "system:serviceaccount:team-a:agent".to_owned(),
            non_resource_attributes: Some(NonResourceAttributes {
                path: "/tools/search".to_owned(),
                verb: "post".to_owned(),
            }),
            ..ReviewSpec::default()
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
            })
        );
    }
}
