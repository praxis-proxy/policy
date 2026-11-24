// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Resolves a bearer token to an identity by asking the Kubernetes API server.
//!
//! Use this for legacy `ServiceAccount` tokens, webhook authentication, or
//! revocation checks that require cluster state. For `ServiceAccount` JWTs that
//! only need signature verification, `identity/jwt` avoids a `TokenReview` call
//! per request.
//!
//! `status.user` (`username`, `uid`, `groups`, `extra`) is what a
//! [`record_map`] projects. The presented token never leaves this plugin
//! except to the API server, and is not written to `raw_credentials`.
//!
//! [`record_map`]: crate::plugins::identity_kubernetes::config::TokenReviewResolverConfig::record_map

pub use crate::token_lookup::cache;
/// Plugin configuration and its validation.
pub mod config;
pub use crate::token_lookup::directory;
/// Constructs the resolver from configuration.
pub mod factory;
/// The identity hook handler.
pub mod resolver;
mod reviewer_token;
/// The backend that calls the `TokenReview` API.
pub mod token_review;

pub use cache::{CacheConfig, CachingDirectory};
pub use config::{ApiServerConfig, ReviewerTokenSource, TokenReviewResolverConfig};
pub use directory::{DirectoryError, KeyDirectory, KeyRecord, PresentedKey};
pub use factory::{KIND, TokenReviewIdentityFactory};
pub use resolver::{TokenReviewIdentityResolver, codes};
pub use token_review::TokenReviewDirectory;
