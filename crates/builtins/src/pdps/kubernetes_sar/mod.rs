// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Decides a request by asking the Kubernetes API server, through a
//! `SubjectAccessReview`, whether a subject may perform an action. The answer
//! comes from the cluster's whole authorizer chain: RBAC, Node, and any
//! webhook authorizer.
//!
//! The subject is usually the identity an earlier resolver put in the bag,
//! such as `identity/kubernetes-token-review`. Every field of the review is a
//! CEL expression over the bag, so only the values the policy names are sent.
//!
//! ```yaml
//! global:
//!   pdp:
//!     - kind: kubernetes-sar
//!       api_server:
//!         url: https://kubernetes.default.svc
//!         reviewer_token:
//!           kind: file
//!           path: /var/run/secrets/kubernetes.io/serviceaccount/token
//!
//! routes:
//!   - tool: "*"
//!     authorization:
//!       pre_invocation:
//!         - pdp(kubernetes-sar):
//!             non_resource_attributes:
//!               path: "'/tools/' + meta.entity_name"
//!               verb: "'post'"
//! ```
//!
//! The reviewer token's identity needs `create` on `subjectaccessreviews`.
//! A review the API server answers decides the step. An expression that fails
//! or yields the wrong type, or an empty user, always denies. When the API
//! server gives no answer, `on_error` decides: `deny` by default, or `allow`
//! as an advisory fallback.

/// The `global.pdp[]` block and the step arguments.
pub mod config;
/// Constructs the resolver from configuration.
pub mod factory;
/// The resolver that sends the review.
pub mod resolver;
mod review;

pub use config::{
    ApiServerConfig, Attributes, NonResourceFields, OnError, ResourceFields, ReviewerTokenSource,
    StepArgs, SubjectAccessReviewConfig, SubjectExprs,
};
pub use factory::{KIND, SubjectAccessReviewPdpFactory};
pub use resolver::{DIALECT, SubjectAccessReviewResolver};
