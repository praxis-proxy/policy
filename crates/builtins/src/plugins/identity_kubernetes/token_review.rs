// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A directory that is the Kubernetes API server. The answer is `201` for both
// outcomes, so the verdict is `status.authenticated`; a `401` or `403` is about
// PPE's own credential, not the caller's.

use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use praxis_policy_core::host::{HostServices, HttpRequestError};
use praxis_policy_core::http::HttpRequest;
use praxis_policy_core::http_retry::RetryPolicy;
use serde::Serialize;
use serde_json::Value;

use crate::plugins::identity_kubernetes::config::ApiServerConfig;
use crate::plugins::identity_kubernetes::reviewer_token::ReviewerToken;
use crate::token_lookup::directory::{DirectoryError, KeyDirectory, KeyRecord, PresentedKey};

/// The backend's name, for diagnostics.
pub const KIND: &str = "kubernetes_token_review";

/// The review endpoint, relative to the API server's base URL.
const REVIEW_PATH: &str = "/apis/authentication.k8s.io/v1/tokenreviews";

/// A ceiling on the buffered review answer.
const RESPONSE_MAX_BYTES: usize = 65_536; // 64 KiB

/// The `TokenReview` object PPE sends.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewRequest<'a> {
    api_version: &'static str,
    kind: &'static str,
    spec: ReviewSpec<'a>,
}

/// Its `spec`. An empty `audiences` is omitted, which asks for the API
/// server's own audience.
#[derive(Serialize)]
struct ReviewSpec<'a> {
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    audiences: &'a [String],
    token: &'a str,
}

/// Reviews tokens against the Kubernetes API server.
#[derive(Debug)]
pub struct TokenReviewDirectory {
    audiences: Vec<String>,
    connect_timeout: Option<Duration>,
    endpoint: String,
    reviewer: ReviewerToken,
    timeout: Duration,
}

impl TokenReviewDirectory {
    /// Build the backend, reading the reviewer token once.
    ///
    /// # Errors
    ///
    /// Whatever reading the reviewer token rejects.
    pub fn new(api_server: &ApiServerConfig, audiences: Vec<String>) -> Result<Self, String> {
        let reviewer = ReviewerToken::load(api_server.reviewer_token.clone())
            .map_err(|e| format!("`api_server.reviewer_token`: {e}"))?;
        Ok(Self {
            audiences,
            connect_timeout: api_server.connect_timeout_secs.map(Duration::from_secs),
            endpoint: format!("{}{REVIEW_PATH}", api_server.url.trim_end_matches('/')),
            reviewer,
            timeout: Duration::from_secs(api_server.timeout_secs),
        })
    }

    /// The `TokenReview` object for a token, serialized from borrowed fields
    /// so the caller's token is not copied on the way.
    fn body(&self, token: &str) -> Result<Vec<u8>, DirectoryError> {
        let review = ReviewRequest {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: ReviewSpec {
                audiences: &self.audiences,
                token,
            },
        };
        serde_json::to_vec(&review)
            .map_err(|e| DirectoryError::Malformed(format!("could not encode the review: {e}")))
    }

    /// Turn a review answer into an outcome.
    fn read_response(&self, body: &[u8], token: &str) -> Result<Option<KeyRecord>, DirectoryError> {
        let mut parsed: Value = serde_json::from_slice(body)
            .map_err(|e| DirectoryError::Malformed(format!("the review is not JSON: {e}")))?;
        let Some(status) = parsed.get_mut("status").and_then(Value::as_object_mut) else {
            return Err(DirectoryError::Malformed(
                "the review carries no `status` object".to_owned(),
            ));
        };

        // The API server omits `authenticated` when it is false.
        let authenticated = match status.get("authenticated") {
            None => false,
            Some(value) => value.as_bool().ok_or_else(|| {
                DirectoryError::Malformed("`status.authenticated` is not a boolean".to_owned())
            })?,
        };
        if !authenticated {
            let reason = status
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or_default();
            tracing::debug!(reason, "the API server did not authenticate the token");
            return Ok(None);
        }

        // Not trusted to the server: one that ignored `spec.audiences` would
        // authenticate the token for an audience nobody asked about.
        if !self.audiences.is_empty() {
            let granted = status
                .get("audiences")
                .and_then(Value::as_array)
                .is_some_and(|granted| {
                    granted
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|audience| self.audiences.iter().any(|wanted| wanted == audience))
                });
            if !granted {
                tracing::debug!("the token is not intended for a configured audience");
                return Ok(None);
            }
        }

        let Some(Value::Object(user)) = status.remove("user") else {
            return Err(DirectoryError::Malformed(
                "an authenticated review carries no `status.user`".to_owned(),
            ));
        };
        if user
            .get("username")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(DirectoryError::Malformed(
                "an authenticated review carries no `status.user.username`".to_owned(),
            ));
        }

        Ok(Some(KeyRecord {
            fields: user.into_iter().collect(),
            expires_at: jwt_expiry(token),
        }))
    }
}

#[async_trait::async_trait]
impl KeyDirectory for TokenReviewDirectory {
    async fn lookup(
        &self,
        presented: &PresentedKey,
        services: &dyn HostServices,
    ) -> Result<Option<KeyRecord>, DirectoryError> {
        if presented.is_empty() {
            return Ok(None);
        }
        let token = std::str::from_utf8(presented.as_bytes()).map_err(|_offset_in_token| {
            DirectoryError::Malformed(
                "the presented token is not UTF-8, so it cannot be sent as JSON".to_owned(),
            )
        })?;

        let reviewer = self.reviewer.get().await;
        let mut request = HttpRequest::post(&self.endpoint, self.body(token)?.into())
            .timeout(self.timeout)
            .max_response_bytes(RESPONSE_MAX_BYTES)
            .header("content-type", "application/json")
            .and_then(|r| r.header("accept", "application/json"))
            .and_then(|r| r.header("authorization", format!("Bearer {}", reviewer.as_str())))
            .map_err(|e| {
                DirectoryError::Unavailable(format!("could not build the review request: {e}"))
            })?;
        if let Some(connect_timeout) = self.connect_timeout {
            request = request.connect_timeout(connect_timeout);
        }

        // A review changes nothing on the server, so retrying is safe.
        let response = services
            .http_request(request, RetryPolicy::idempotent())
            .await
            .map_err(|error| match error {
                HttpRequestError::Unavailable(detail) => DirectoryError::Unavailable(format!(
                    "no HTTP transport for the API server: {detail}"
                )),
                other => DirectoryError::Unavailable(other.to_string()),
            })?;

        match response.status {
            200 | 201 => self.read_response(&response.body, token),
            status @ (401 | 403) => Err(DirectoryError::Unavailable(format!(
                "the API server refused the reviewer credential ({status}): check the reviewer \
                 token and that its identity may `create` `tokenreviews`"
            ))),
            status => Err(DirectoryError::Unavailable(format!(
                "the API server answered {status}"
            ))),
        }
    }

    fn kind(&self) -> &'static str {
        KIND
    }
}

/// The `exp` of a JWT, read without verifying it.
///
/// Safe because it runs only on a token the API server just authenticated,
/// and it can only shorten how long a cached answer is reused.
fn jwt_expiry(token: &str) -> Option<DateTime<Utc>> {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    numeric_date(claims.get("exp")?)
}

/// An RFC 7519 `NumericDate`, which may carry a fraction.
///
/// A fraction is floored, so the bound can only come earlier. The float goes
/// through its decimal text because a float-to-integer cast can truncate
/// silently; a value too large for an `i64` is far enough out to leave
/// unbounded.
fn numeric_date(value: &Value) -> Option<DateTime<Utc>> {
    let seconds = match value.as_i64() {
        Some(seconds) => seconds,
        None => format!("{:.0}", value.as_f64()?.floor()).parse().ok()?,
    };
    DateTime::from_timestamp(seconds, 0)
}
