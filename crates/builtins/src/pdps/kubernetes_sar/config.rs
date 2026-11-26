// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use serde::{Deserialize, Serialize};

pub use crate::kubernetes::{ApiServerConfig, ReviewerTokenSource};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The user reviewed when neither the step nor the block names one.
pub const DEFAULT_USER: &str = "subject.id";

/// The groups reviewed when neither the step nor the block names them.
pub const DEFAULT_GROUPS: &str = "has(subject.roles) ? subject.roles : []";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// The `global.pdp[]` block for `kind: kubernetes-sar`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectAccessReviewConfig {
    /// The API server the review is sent to.
    pub api_server: ApiServerConfig,

    /// The decision when the API server gives no answer.
    #[serde(default)]
    pub on_error: OnError,

    /// Who is reviewed, unless a step says otherwise.
    #[serde(default)]
    pub subject: SubjectExprs,
}

/// The decision when the API server gives no answer: unreachable, refusing
/// PPE's credential, or answering with something that is not a review.
///
/// An expression that cannot be evaluated always denies, whatever this says,
/// since it means the policy could not say who or what to review.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Deny the request.
    #[default]
    Deny,
    /// Allow the request, logged at `error`. For an advisory check behind
    /// another decision point.
    Allow,
}

/// CEL expressions over the policy bag naming who is reviewed. An unset field
/// falls back to the block's value, then to [`DEFAULT_USER`] and
/// [`DEFAULT_GROUPS`]; `uid` and `extra` are sent only when set.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectExprs {
    /// A map of string to list of strings, sent as `spec.extra`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,

    /// A list of strings, sent as `spec.groups`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,

    /// A string, sent as `spec.uid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// A string, sent as `spec.user`. An empty result denies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

// -----------------------------------------------------------------------------
// Step Arguments
// -----------------------------------------------------------------------------

/// A `pdp(kubernetes-sar):` step. Exactly one of `resource_attributes` and
/// `non_resource_attributes` is set. Every value is a CEL expression that
/// evaluates to a string.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepArgs {
    /// "May the subject `verb` this URL path?"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_resource_attributes: Option<NonResourceExprs>,

    /// "May the subject `verb` this object?"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_attributes: Option<ResourceExprs>,

    /// Overrides the block's `subject`, field by field.
    #[serde(default)]
    pub subject: SubjectExprs,
}

/// `spec.nonResourceAttributes`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonResourceExprs {
    /// The URL path.
    pub path: String,
    /// The verb, such as `get` or `post`.
    pub verb: String,
}

/// `spec.resourceAttributes`. An unset field is omitted, which Kubernetes
/// reads as "any".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceExprs {
    /// The API group; `""` is the core group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The object's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The namespace; unset is cluster scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The resource, such as `pods`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// The subresource, such as `log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subresource: Option<String>,
    /// The verb, such as `get` or `create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    /// The API version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
