// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Why a secret did not resolve.
//
// No variant carries secret material. A reference, a provider name, and a
// value name are all operator-authored config, safe to print and necessary to
// act on; the bytes behind them are neither. Every constructor here takes the
// address of a secret, never its contents, so there is no path by which a
// value reaches a log through an error.

use thiserror::Error;

/// Why a secret did not resolve.
///
/// The variants separate the three parties who fix the problem. A `Config`
/// fault is the operator's document, a `NotFound` or `Malformed` fault is what
/// the backend holds at the address they gave, and a `Backend` fault is the
/// backend itself. Collapsing them would send an operator to the wrong place.
///
/// `#[non_exhaustive]` because a backend outside this crate may distinguish a
/// failure it has no vocabulary for here; a host matching exhaustively today
/// should not break when one is added. The constructors below are how an
/// out-of-tree provider builds one.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SecretError {
    /// The `secrets:` block does not describe something resolvable: an unknown
    /// provider kind, a value naming a provider that is not declared, or a
    /// provider whose own settings are malformed.
    #[error("{message}")]
    Config {
        /// What is wrong and which name it is wrong for.
        message: String,
    },

    /// The reference is not addressable by this provider. Distinct from
    /// [`SecretError::NotFound`]: nothing was looked up, because the reference
    /// could not be turned into a lookup.
    #[error("`{reference}` is not a reference this provider can address: {reason}")]
    Reference {
        /// The reference as the operator wrote it.
        reference: String,
        /// What about it could not be addressed.
        reason: String,
    },

    /// The provider addressed the reference and the backend holds nothing
    /// there.
    #[error("`{reference}` resolved to nothing")]
    NotFound {
        /// The reference as the operator wrote it.
        reference: String,
    },

    /// The backend holds something at the reference that cannot be used as a
    /// secret. An empty value lands here rather than in
    /// [`SecretError::NotFound`], because a present-but-empty credential is a
    /// misconfiguration an operator must see rather than an absence a consumer
    /// could reasonably treat as "unset".
    #[error("`{reference}` holds a value that cannot be used: {reason}")]
    Malformed {
        /// The reference as the operator wrote it.
        reference: String,
        /// What about the value is unusable.
        reason: String,
    },

    /// The backend could not be reached, or refused the read. The one variant
    /// a refresh is expected to hit transiently, and the reason refresh keeps
    /// the last-good value rather than clearing it.
    ///
    /// Carries no provider name: a provider does not know the name it was
    /// declared under. [`SecretResolveError`] attaches that, along with the
    /// name of the value being read.
    #[error("{reason}")]
    Backend {
        /// What the backend reported, with nothing secret in it.
        reason: String,
    },
}

/// A resolution failure, naming which declared value failed and through which
/// provider.
///
/// The provider's own error says what went wrong; this says what it went wrong
/// *for*. With several providers and many values, "the read timed out" does not
/// tell an operator which credential the process is now missing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("secret `{secret}` via provider `{provider}`: {source}")]
pub struct SecretResolveError {
    /// The declared value that failed.
    pub secret: String,
    /// The provider it is bound to.
    pub provider: String,
    /// What the provider reported.
    #[source]
    pub source: SecretError,
}

impl SecretError {
    /// A config fault, naming what is wrong.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// A reference this provider cannot turn into a lookup.
    pub fn reference(reference: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Reference {
            reference: reference.into(),
            reason: reason.into(),
        }
    }

    /// Nothing at the reference.
    pub fn not_found(reference: impl Into<String>) -> Self {
        Self::NotFound {
            reference: reference.into(),
        }
    }

    /// Something at the reference that cannot be used.
    pub fn malformed(reference: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Malformed {
            reference: reference.into(),
            reason: reason.into(),
        }
    }

    /// The backend itself failed.
    pub fn backend(reason: impl Into<String>) -> Self {
        Self::Backend {
            reason: reason.into(),
        }
    }

    /// Whether a refresh that hit this should keep serving the last-good
    /// value.
    ///
    /// Every variant does, which is the point: once a value has resolved
    /// successfully, availability beats freshness for every later failure,
    /// including a backend that started answering "not found" because someone
    /// deleted the secret. This exists so that call sites read as a decision
    /// rather than as an unconditional `else`, and so a variant added later
    /// has to answer the question.
    #[must_use]
    pub const fn keeps_last_good(&self) -> bool {
        true
    }
}
