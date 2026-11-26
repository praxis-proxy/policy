// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Private mechanics shared by HTTP-backed builtin adapters.

pub(crate) mod cache;
pub(crate) mod destinations;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod secrets;
mod template;

use praxis_policy_core::extensions::{AcquiredFacts, MetadataCacheDisposition};
use praxis_policy_core::metadata_callout::{
    CalloutObserver, MetadataCalloutAuditEvent, MetadataCalloutErrorCode,
};

/// A normalized runtime failure with no source-controlled detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CalloutFailure {
    code: MetadataCalloutErrorCode,
}

impl CalloutFailure {
    pub(crate) const fn new(code: MetadataCalloutErrorCode) -> Self {
        Self { code }
    }

    pub(crate) fn facts(self) -> AcquiredFacts {
        AcquiredFacts::error(self.code, MetadataCacheDisposition::Disabled)
    }

    pub(crate) const fn code(&self) -> MetadataCalloutErrorCode {
        self.code
    }
}

#[derive(Debug)]
pub(crate) struct TracingCalloutObserver;

impl CalloutObserver for TracingCalloutObserver {
    fn observe(&self, event: &MetadataCalloutAuditEvent) {
        match serde_json::to_string(event) {
            Ok(event) => tracing::info!(
                target: "praxis_policy::metadata_callout",
                audit_event = %event,
                "metadata callout completed"
            ),
            Err(error) => tracing::warn!(
                target: "praxis_policy::metadata_callout",
                error = %error,
                "metadata callout audit serialization failed"
            ),
        }
    }
}
