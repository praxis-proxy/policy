// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Stable failure and observation contracts for metadata callouts.

use std::fmt;

use http::uri::Authority;
use serde::Serialize;

use crate::extensions::{MetadataCacheDisposition, MetadataOutcome};

/// Current serialized schema version for [`MetadataCalloutAuditEvent`].
pub const METADATA_CALLOUT_AUDIT_SCHEMA_VERSION: u16 = 1;

/// Whether a metadata source failure may succeed on a later attempt.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataCalloutErrorClass {
    /// A later attempt may succeed without configuration changes.
    Recoverable,
    /// Operator, policy, authentication, or response correction is required.
    Fatal,
}

/// Stable source-owned failure codes for HTTP metadata acquisition.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum MetadataCalloutErrorCode {
    /// No authenticated subject was available.
    #[serde(rename = "metadata.subject_required")]
    SubjectRequired,
    /// The connect, attempt, or invocation deadline expired.
    #[serde(rename = "metadata.timeout")]
    Timeout,
    /// The transport failed or the source returned a server error.
    #[serde(rename = "metadata.upstream_error")]
    UpstreamError,
    /// The source's concurrency limit was full.
    #[serde(rename = "metadata.overloaded")]
    Overloaded,
    /// The source circuit breaker refused the call.
    #[serde(rename = "metadata.circuit_open")]
    CircuitOpen,
    /// Source authentication or credential acquisition failed.
    #[serde(rename = "metadata.auth_failed")]
    AuthFailed,
    /// The response exceeded its configured byte ceiling.
    #[serde(rename = "metadata.response_too_large")]
    ResponseTooLarge,
    /// The status, media type, shape, bounds, or projection was invalid.
    #[serde(rename = "metadata.bad_response")]
    BadResponse,
    /// Host egress policy rejected the destination.
    #[serde(rename = "metadata.rejected_destination")]
    RejectedDestination,
}

impl MetadataCalloutErrorCode {
    /// Stable serialized policy spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubjectRequired => "metadata.subject_required",
            Self::Timeout => "metadata.timeout",
            Self::UpstreamError => "metadata.upstream_error",
            Self::Overloaded => "metadata.overloaded",
            Self::CircuitOpen => "metadata.circuit_open",
            Self::AuthFailed => "metadata.auth_failed",
            Self::ResponseTooLarge => "metadata.response_too_large",
            Self::BadResponse => "metadata.bad_response",
            Self::RejectedDestination => "metadata.rejected_destination",
        }
    }

    /// Operational recovery class defined by the metadata callout contract.
    #[must_use]
    pub const fn class(self) -> MetadataCalloutErrorClass {
        match self {
            Self::Timeout | Self::UpstreamError | Self::Overloaded | Self::CircuitOpen => {
                MetadataCalloutErrorClass::Recoverable
            },
            Self::SubjectRequired
            | Self::AuthFailed
            | Self::ResponseTooLarge
            | Self::BadResponse
            | Self::RejectedDestination => MetadataCalloutErrorClass::Fatal,
        }
    }
}

impl fmt::Display for MetadataCalloutErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<MetadataCalloutErrorCode> for String {
    fn from(code: MetadataCalloutErrorCode) -> Self {
        code.as_str().to_owned()
    }
}

/// One circuit-breaker state change associated with a callout.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataCircuitBreakerTransition {
    /// Counted failures opened a closed breaker.
    ClosedToOpen,
    /// The recovery interval admitted probes.
    OpenToHalfOpen,
    /// A successful probe restored normal operation.
    HalfOpenToClosed,
    /// A failed probe reopened the breaker.
    HalfOpenToOpen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
enum MetadataCalloutAuditResult {
    Success,
    Error {
        error_code: MetadataCalloutErrorCode,
    },
}

/// Versioned, value-free audit record for one metadata source operation.
///
/// The closed schema intentionally has no URL, header, body, secret, response
/// value, or raw-error field. `authority` is constructed from HTTP's parsed
/// [`Authority`] type, so query data cannot enter through it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataCalloutAuditEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_status: Option<u16>,
    authority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    breaker_transition: Option<MetadataCircuitBreakerTransition>,
    cache: MetadataCacheDisposition,
    credential_interpolation: bool,
    instance: String,
    rejected_key_count: u32,
    response_node_count: u32,
    #[serde(flatten)]
    result: MetadataCalloutAuditResult,
    schema_version: u16,
    stale: bool,
}

impl MetadataCalloutAuditEvent {
    /// Create an audit record for a successful source operation.
    #[must_use]
    pub fn success(
        instance: impl Into<String>,
        authority: &Authority,
        cache: MetadataCacheDisposition,
    ) -> Self {
        Self::new(
            instance,
            authority,
            cache,
            MetadataCalloutAuditResult::Success,
        )
    }

    /// Create an audit record for a normalized source failure.
    #[must_use]
    pub fn error(
        instance: impl Into<String>,
        authority: &Authority,
        cache: MetadataCacheDisposition,
        error_code: MetadataCalloutErrorCode,
    ) -> Self {
        Self::new(
            instance,
            authority,
            cache,
            MetadataCalloutAuditResult::Error { error_code },
        )
    }

    /// Attach an accepted upstream status selected for exposure.
    #[must_use]
    pub const fn with_accepted_status(mut self, status: u16) -> Self {
        self.accepted_status = Some(status);
        self
    }

    /// Attach a circuit-breaker transition caused by this operation.
    #[must_use]
    pub const fn with_breaker_transition(
        mut self,
        transition: MetadataCircuitBreakerTransition,
    ) -> Self {
        self.breaker_transition = Some(transition);
        self
    }

    /// Record that an explicitly permitted credential field was interpolated.
    #[must_use]
    pub const fn with_credential_interpolation(mut self) -> Self {
        self.credential_interpolation = true;
        self
    }

    /// Attach bounded structural response counts, never response values.
    #[must_use]
    pub const fn with_response_counts(mut self, nodes: u32, rejected_keys: u32) -> Self {
        self.response_node_count = nodes;
        self.rejected_key_count = rejected_keys;
        self
    }

    /// Parsed source authority without path or query data.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Cache disposition for this evaluation.
    #[must_use]
    pub const fn cache(&self) -> MetadataCacheDisposition {
        self.cache
    }

    /// Normalized source error code, when the operation failed.
    #[must_use]
    pub const fn error_code(&self) -> Option<MetadataCalloutErrorCode> {
        match self.result {
            MetadataCalloutAuditResult::Success => None,
            MetadataCalloutAuditResult::Error { error_code } => Some(error_code),
        }
    }

    /// Configured metadata source instance.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Source-owned acquisition outcome.
    #[must_use]
    pub const fn outcome(&self) -> MetadataOutcome {
        match self.result {
            MetadataCalloutAuditResult::Success => MetadataOutcome::Success,
            MetadataCalloutAuditResult::Error { .. } => MetadataOutcome::Error,
        }
    }

    fn new(
        instance: impl Into<String>,
        authority: &Authority,
        cache: MetadataCacheDisposition,
        result: MetadataCalloutAuditResult,
    ) -> Self {
        let authority = authority
            .as_str()
            .rsplit_once('@')
            .map_or_else(|| authority.as_str(), |(_, host)| host)
            .to_owned();
        Self {
            accepted_status: None,
            authority,
            breaker_transition: None,
            cache,
            credential_interpolation: false,
            instance: instance.into(),
            rejected_key_count: 0,
            response_node_count: 0,
            result,
            schema_version: METADATA_CALLOUT_AUDIT_SCHEMA_VERSION,
            stale: cache == MetadataCacheDisposition::Stale,
        }
    }
}

/// Consumer of value-free metadata callout observations.
pub trait CalloutObserver: Send + Sync {
    /// Observe one completed source operation.
    fn observe(&self, event: &MetadataCalloutAuditEvent);
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::extensions::AcquiredFacts;

    #[test]
    fn every_error_code_has_a_stable_spelling_and_class() {
        let cases = [
            (
                MetadataCalloutErrorCode::SubjectRequired,
                "metadata.subject_required",
                MetadataCalloutErrorClass::Fatal,
            ),
            (
                MetadataCalloutErrorCode::Timeout,
                "metadata.timeout",
                MetadataCalloutErrorClass::Recoverable,
            ),
            (
                MetadataCalloutErrorCode::UpstreamError,
                "metadata.upstream_error",
                MetadataCalloutErrorClass::Recoverable,
            ),
            (
                MetadataCalloutErrorCode::Overloaded,
                "metadata.overloaded",
                MetadataCalloutErrorClass::Recoverable,
            ),
            (
                MetadataCalloutErrorCode::CircuitOpen,
                "metadata.circuit_open",
                MetadataCalloutErrorClass::Recoverable,
            ),
            (
                MetadataCalloutErrorCode::AuthFailed,
                "metadata.auth_failed",
                MetadataCalloutErrorClass::Fatal,
            ),
            (
                MetadataCalloutErrorCode::ResponseTooLarge,
                "metadata.response_too_large",
                MetadataCalloutErrorClass::Fatal,
            ),
            (
                MetadataCalloutErrorCode::BadResponse,
                "metadata.bad_response",
                MetadataCalloutErrorClass::Fatal,
            ),
            (
                MetadataCalloutErrorCode::RejectedDestination,
                "metadata.rejected_destination",
                MetadataCalloutErrorClass::Fatal,
            ),
        ];

        for (code, spelling, class) in cases {
            assert_eq!(code.as_str(), spelling);
            assert_eq!(code.class(), class);
            assert_eq!(
                serde_json::to_value(code).expect("error code should serialize"),
                json!(spelling)
            );
        }
    }

    #[test]
    fn typed_source_code_builds_the_same_acquired_facts_record() {
        let facts = AcquiredFacts::error(
            MetadataCalloutErrorCode::UpstreamError,
            MetadataCacheDisposition::Disabled,
        );

        assert_eq!(facts.error_code(), Some("metadata.upstream_error"));
        assert_eq!(facts.outcome(), MetadataOutcome::Error);
    }

    #[test]
    fn audit_serialization_is_versioned_and_value_free() {
        let authority: Authority = "metadata.example:8443"
            .parse()
            .expect("authority should parse");
        let event = MetadataCalloutAuditEvent::error(
            "account",
            &authority,
            MetadataCacheDisposition::Miss,
            MetadataCalloutErrorCode::Timeout,
        )
        .with_accepted_status(503)
        .with_breaker_transition(MetadataCircuitBreakerTransition::ClosedToOpen)
        .with_credential_interpolation()
        .with_response_counts(17, 2);

        let value = serde_json::to_value(event).expect("audit event should serialize");

        assert_eq!(
            value,
            json!({
                "accepted_status": 503,
                "authority": "metadata.example:8443",
                "breaker_transition": "closed_to_open",
                "cache": "miss",
                "credential_interpolation": true,
                "error_code": "metadata.timeout",
                "instance": "account",
                "outcome": "error",
                "rejected_key_count": 2,
                "response_node_count": 17,
                "schema_version": 1,
                "stale": false
            })
        );
        let encoded = value.to_string();
        for forbidden in [
            "url",
            "query",
            "header",
            "body",
            "secret",
            "response_value",
            "upstream_text",
        ] {
            assert!(!encoded.contains(forbidden), "forbidden field: {forbidden}");
        }
    }
}
