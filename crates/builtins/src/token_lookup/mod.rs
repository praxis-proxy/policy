// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Identity from a credential that only a lookup can resolve.
//!
//! The shared core of the resolvers whose credential carries nothing that can
//! be verified locally. A plugin supplies a [`KeyDirectory`] backend and a
//! [`LookupProfile`]; extraction, caching, expiry and projection onto the
//! identity slots live here once.
//!
//! # What belongs here
//!
//! The core is closed: one trait, one cache, one resolver, and the profile as
//! the only thing that varies between plugins. A mechanism that needs a flag
//! or a branch in the resolver to fit is not this shape, and gets its own
//! plugin instead. Each mechanism is a backend behind its own feature, so
//! retiring one removes its plugin directory and feature line and leaves this
//! module untouched.
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
