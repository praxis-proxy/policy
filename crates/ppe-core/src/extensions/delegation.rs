// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// DelegationExtension — token delegation chain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::authorization::AuthorizationDetail;
use super::security::SubjectType;

/// Delegation strategy used to mint the credential at this hop.
///
/// The known variants cover the reference implementations.
/// `Custom(String)` is the
/// escape hatch for host-defined strategies (UCAN variants, in-house mints).
/// Marked `#[non_exhaustive]` so new known variants can be added without a
/// breaking change to host code that exhaustively matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DelegationStrategy {
    /// RFC 8693 token exchange.
    TokenExchange,
    /// OAuth client credentials.
    ClientCredentials,
    /// A SPIFFE SVID.
    SpiffeSvid,
    /// The caller's own token, forwarded unchanged.
    Passthrough,
    /// A UCAN capability token.
    Ucan,
    /// A transaction token.
    TransactionToken,
    #[serde(untagged)]
    /// A host-defined mode, named here.
    Custom(String),
}

/// A single hop in the delegation chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationHop {
    /// Subject ID of the delegator.
    pub subject_id: String,

    /// Subject type of the delegator. Reuses the typed `SubjectType`
    /// enum from `SecurityExtension.subject`, not a freeform string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<SubjectType>,

    /// Target audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    /// Scopes granted in this delegation step.
    #[serde(default)]
    pub scopes_granted: Vec<String>,

    /// RFC 9396 `authorization_details` carried alongside scopes.
    /// Each hop's details must be structurally narrowed from the previous.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_details: Vec<AuthorizationDetail>,

    /// When this hop was minted. Default is the Unix epoch — production
    /// code constructs with `Utc::now()`; only tests rely on the default.
    /// A hop read from an inbound `act` claim carries the token's `iat`
    /// instead, a true upper bound, since the token does not date earlier hops.
    #[serde(default)]
    pub timestamp: DateTime<Utc>,

    /// Time-to-live in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,

    /// Delegation strategy used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DelegationStrategy>,

    /// Whether this hop was resolved from cache.
    #[serde(default)]
    pub from_cache: bool,
}

/// Delegation chain extension.
///
/// Append-only — each hop narrows scope. A delegate cannot have
/// more permissions than the delegator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationExtension {
    /// Ordered delegation chain.
    #[serde(default)]
    pub chain: Vec<DelegationHop>,

    /// Chain depth (number of hops). `u32` for wire-stable width.
    ///
    /// When read from an RFC 8693 `act` claim, this counts nested `act`
    /// objects, which section 4.1 calls informational only and not to be
    /// considered in access control decisions. It reflects only what the
    /// issuing STS chose to nest, so it can understate the real chain and is
    /// never overstated. A depth limit is a best-effort guard, not a hop limit;
    /// enforce a hard limit at the STS that mints the tokens.
    #[serde(default)]
    pub depth: u32,

    /// Subject ID of the original delegator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_subject_id: Option<String>,

    /// Subject ID of the current actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_subject_id: Option<String>,

    /// Whether delegation has occurred.
    #[serde(default)]
    pub delegated: bool,

    /// Age in seconds of the token that carried the chain, measured from its
    /// `iat`. On an exchanged token `iat` is the time of the latest exchange,
    /// so a re-exchange resets it; it is not the age of the whole chain.
    #[serde(default)]
    pub age_seconds: f64,
}

impl DelegationExtension {
    /// Append a delegation hop (monotonic — cannot remove).
    pub fn append_hop(&mut self, hop: DelegationHop) {
        self.chain.push(hop);
        // Saturating rather than wrapping: overflowing a u32 here would need a
        // chain far past what allocation allows, but a wrapped depth reads as
        // shallow and depth is what a `delegation.depth > N` rule tests.
        self.depth = u32::try_from(self.chain.len()).unwrap_or(u32::MAX);
        self.delegated = true;
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_starts_empty() {
        let del = DelegationExtension::default();
        assert!(del.chain.is_empty());
        assert_eq!(del.depth, 0);
        assert!(!del.delegated);
    }

    #[test]
    fn test_append_hop() {
        let mut del = DelegationExtension::default();
        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });

        assert_eq!(del.chain.len(), 1);
        assert_eq!(del.depth, 1);
        assert!(del.delegated);
        assert_eq!(del.chain[0].subject_id, "alice");
        assert_eq!(del.chain[0].scopes_granted, vec!["read_hr"]);
    }

    #[test]
    fn test_append_multiple_hops() {
        let mut del = DelegationExtension {
            origin_subject_id: Some("alice".into()),
            ..Default::default()
        };

        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            audience: Some("service-b".into()),
            scopes_granted: vec!["read".into(), "write".into()],
            strategy: Some(DelegationStrategy::TokenExchange),
            ..Default::default()
        });

        del.append_hop(DelegationHop {
            subject_id: "service-b".into(),
            audience: Some("service-c".into()),
            scopes_granted: vec!["read".into()], // narrowed scope
            ..Default::default()
        });

        assert_eq!(del.chain.len(), 2);
        assert_eq!(del.depth, 2);
        // Second hop has narrower scope
        assert_eq!(del.chain[1].scopes_granted, vec!["read"]);
    }

    #[test]
    fn test_strategy_serde_known_and_custom() {
        // Known variant serializes as snake_case string.
        let known = DelegationStrategy::TokenExchange;
        let json = serde_json::to_string(&known).unwrap();
        assert_eq!(json, "\"token_exchange\"");
        let back: DelegationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, DelegationStrategy::TokenExchange);

        // Custom variant serializes as a bare string (untagged).
        let custom = DelegationStrategy::Custom("in_house_mint".into());
        let json = serde_json::to_string(&custom).unwrap();
        assert_eq!(json, "\"in_house_mint\"");
        // Deserializing a string that doesn't match a known variant falls
        // through to Custom — the escape hatch.
        let back: DelegationStrategy = serde_json::from_str("\"in_house_mint\"").unwrap();
        assert_eq!(back, DelegationStrategy::Custom("in_house_mint".into()));
    }

    #[test]
    fn test_delegation_serde_roundtrip() {
        let mut del = DelegationExtension {
            origin_subject_id: Some("alice".into()),
            actor_subject_id: Some("service-b".into()),
            ..Default::default()
        };
        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            subject_type: Some(SubjectType::User),
            scopes_granted: vec!["admin".into()],
            from_cache: true,
            ..Default::default()
        });

        let json = serde_json::to_string(&del).unwrap();
        let deserialized: DelegationExtension = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.depth, 1);
        assert!(deserialized.delegated);
        assert_eq!(deserialized.origin_subject_id.as_deref(), Some("alice"));
        assert!(deserialized.chain[0].from_cache);
    }
}
