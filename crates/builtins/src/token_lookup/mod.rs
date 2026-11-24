// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Identity lookup shared by API-key and Kubernetes `TokenReview` resolvers.
//!
//! Each resolver supplies a [`KeyDirectory`] and [`LookupProfile`].
//!
//! [`KeyDirectory`]: directory::KeyDirectory
//! [`LookupProfile`]: resolver::LookupProfile

/// A cache in front of a directory.
pub mod cache;
/// Hashing a presented credential.
pub(crate) mod crypto;
/// Where identity records live.
pub mod directory;
/// The `identity.resolve` handler every lookup resolver runs.
pub(crate) mod resolver;
