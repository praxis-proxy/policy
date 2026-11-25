// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Private mechanics shared by HTTP-backed builtin adapters.

pub(crate) mod request;
pub(crate) mod response;
mod template;

use praxis_policy_core::extensions::{AcquiredFacts, MetadataCacheDisposition};
use praxis_policy_core::metadata_callout::MetadataCalloutErrorCode;

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
}
