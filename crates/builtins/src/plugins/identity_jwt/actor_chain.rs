// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The delegation chain carried by an RFC 8693 `act` claim.
//!
//! A token minted by token exchange names the party acting on the subject's
//! behalf in `act`, and an actor that was itself acting for someone nests the
//! earlier `act` inside it:
//!
//! ```json
//! { "sub": "alice", "act": { "sub": "agent-b", "act": { "sub": "agent-a" } } }
//! ```
//!
//! reads as alice delegated to `agent-a`, which delegated to `agent-b`, the
//! current actor. The chain is as trustworthy as the issuer that signed the
//! token: the resolver only reads it from a token whose signature, issuer and
//! audience already verified, and takes it as presented. It never caps the
//! depth, since a clipped chain would read as shallower than it is and
//! `delegation.depth` is what a policy gates on. A malformed `act` is refused
//! instead, for the same reason: dropping it would make a delegated request
//! look direct.

use chrono::{DateTime, Utc};
use praxis_policy_core::extensions::{DelegationExtension, DelegationHop};
use praxis_policy_core::identity::mapping::ClaimMap;
use serde_json::Value;

/// Why an `act` claim could not be read as a delegation chain.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ActorChainError {
    /// An `act` value is not a JSON object.
    NotAnObject,
    /// An `act` object has no usable `sub`, so the actor is unnamed.
    MissingSubject,
    /// The token carries `act` but the subject has no id to anchor the chain.
    NoOrigin,
}

impl ActorChainError {
    /// The operator-readable reason for the denial.
    pub(crate) const fn reason(&self) -> &'static str {
        match self {
            Self::NotAnObject => "the `act` claim must be an object (RFC 8693 section 4.1)",
            Self::MissingSubject => {
                "every `act` claim must carry a non-empty string `sub` naming the actor"
            },
            Self::NoOrigin => {
                "the token carries an `act` claim but the claim map resolved no subject id \
                 to anchor the delegation chain"
            },
        }
    }
}

/// Read the `act` chain from `claims`.
///
/// Returns `Ok(None)` when the token carries no `act`, a direct call.
/// Otherwise the chain runs from the origin toward the current actor, one hop
/// per `act` object. A hop's `subject_id` is the party that delegated at that
/// step: the subject first, then each earlier actor. The current actor, who
/// delegated to nobody, is `actor_subject_id`. So the example above yields the
/// hops `alice` and `agent-a`, with `agent-b` as the actor, and a depth of 2.
///
/// `origin` is the subject id the claim map produced, so the chain is anchored
/// to the same identity every other policy attribute reads. `iat` dates the
/// chain: the token carries one issue time, so each hop keeps the default
/// timestamp and the chain's age is measured from `iat` instead.
pub(crate) fn read(
    claims: &ClaimMap,
    origin: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<DelegationExtension>, ActorChainError> {
    // A JSON null names no actor, the same as the claim being absent.
    let Some(outer) = claims.get("act").filter(|act| !act.is_null()) else {
        return Ok(None);
    };

    // Outermost first: the current actor, then each earlier one.
    let mut actors: Vec<&str> = Vec::new();
    let mut next = Some(outer);
    while let Some(act) = next {
        let act = act.as_object().ok_or(ActorChainError::NotAnObject)?;
        let sub = act
            .get("sub")
            .and_then(Value::as_str)
            .filter(|sub| !sub.is_empty())
            .ok_or(ActorChainError::MissingSubject)?;
        actors.push(sub);
        next = act.get("act").filter(|earlier| !earlier.is_null());
    }

    let origin = origin
        .filter(|id| !id.is_empty())
        .ok_or(ActorChainError::NoOrigin)?;
    let current = actors.first().map(|actor| (*actor).to_owned());
    let delegators = std::iter::once(origin).chain(actors.iter().skip(1).rev().copied());

    let mut chain = DelegationExtension {
        origin_subject_id: Some(origin.to_owned()),
        actor_subject_id: current,
        age_seconds: age_seconds(claims, now),
        ..DelegationExtension::default()
    };
    for delegator in delegators {
        chain.append_hop(DelegationHop {
            subject_id: delegator.to_owned(),
            ..DelegationHop::default()
        });
    }
    Ok(Some(chain))
}

/// Seconds since the token's `iat`, or zero when it has none, is not a number,
/// or lies ahead of the clock by skew. `iat` is a `NumericDate`, so it may carry
/// a fraction.
#[allow(
    clippy::cast_precision_loss,
    reason = "epoch seconds stay far below 2^53"
)]
fn age_seconds(claims: &ClaimMap, now: DateTime<Utc>) -> f64 {
    let Some(issued_at) = claims.get("iat").and_then(Value::as_f64) else {
        return 0.0;
    };
    (now.timestamp() as f64 - issued_at).max(0.0)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(value: &Value) -> ClaimMap {
        serde_json::from_value(value.clone()).expect("a claim map")
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).expect("a timestamp")
    }

    fn subjects(chain: &DelegationExtension) -> Vec<&str> {
        chain
            .chain
            .iter()
            .map(|hop| hop.subject_id.as_str())
            .collect()
    }

    #[test]
    fn a_token_without_act_is_a_direct_call() {
        let read = read(&claims(&json!({"sub": "alice"})), Some("alice"), at(0));
        assert!(matches!(read, Ok(None)));
    }

    #[test]
    fn one_act_is_one_hop_from_the_subject_to_the_actor() {
        let claims = claims(&json!({"sub": "alice", "act": {"sub": "agent-a"}}));
        let chain = read(&claims, Some("alice"), at(0)).unwrap().unwrap();
        assert_eq!(chain.depth, 1);
        assert!(chain.delegated);
        assert_eq!(subjects(&chain), ["alice"]);
        assert_eq!(chain.origin_subject_id.as_deref(), Some("alice"));
        assert_eq!(chain.actor_subject_id.as_deref(), Some("agent-a"));
    }

    #[test]
    fn nested_act_reads_oldest_delegator_first() {
        let claims = claims(&json!({
            "sub": "alice",
            "act": {"sub": "agent-c", "act": {"sub": "agent-b", "act": {"sub": "agent-a"}}},
        }));
        let chain = read(&claims, Some("alice"), at(0)).unwrap().unwrap();
        assert_eq!(chain.depth, 3);
        assert_eq!(subjects(&chain), ["alice", "agent-a", "agent-b"]);
        assert_eq!(chain.actor_subject_id.as_deref(), Some("agent-c"));
    }

    #[test]
    fn the_origin_is_the_mapped_subject_not_the_raw_sub() {
        let claims = claims(&json!({"sub": "opaque-id", "act": {"sub": "agent-a"}}));
        let chain = read(&claims, Some("alice@corp.com"), at(0))
            .unwrap()
            .unwrap();
        assert_eq!(chain.origin_subject_id.as_deref(), Some("alice@corp.com"));
        assert_eq!(subjects(&chain), ["alice@corp.com"]);
    }

    #[test]
    fn a_deep_chain_is_never_clipped() {
        let mut act = json!({"sub": "actor-0"});
        for n in 1..100 {
            act = json!({"sub": format!("actor-{n}"), "act": act});
        }
        let chain = read(&claims(&json!({"act": act})), Some("alice"), at(0))
            .unwrap()
            .unwrap();
        assert_eq!(chain.depth, 100);
        assert_eq!(chain.chain.len(), 100);
    }

    #[test]
    fn a_malformed_act_is_refused_at_any_level() {
        for act in [
            json!("agent-a"),
            json!(["agent-a"]),
            json!(7),
            json!({"sub": "agent-b", "act": "agent-a"}),
        ] {
            let result = read(&claims(&json!({"act": act})), Some("alice"), at(0));
            assert_eq!(result.unwrap_err(), ActorChainError::NotAnObject);
        }
        for act in [
            json!({}),
            json!({"sub": ""}),
            json!({"sub": 7}),
            json!({"client_id": "agent-a"}),
            json!({"sub": "agent-b", "act": {"iss": "x"}}),
        ] {
            let result = read(&claims(&json!({"act": act})), Some("alice"), at(0));
            assert_eq!(result.unwrap_err(), ActorChainError::MissingSubject);
        }
    }

    #[test]
    fn act_without_a_subject_id_to_anchor_it_is_refused() {
        let claims = claims(&json!({"act": {"sub": "agent-a"}}));
        for origin in [None, Some("")] {
            assert_eq!(
                read(&claims, origin, at(0)).unwrap_err(),
                ActorChainError::NoOrigin
            );
        }
    }

    #[test]
    fn a_null_act_names_no_actor() {
        let direct = claims(&json!({"act": null}));
        assert!(matches!(read(&direct, Some("alice"), at(0)), Ok(None)));

        let nested = claims(&json!({"act": {"sub": "agent-a", "act": null}}));
        let chain = read(&nested, Some("alice"), at(0)).unwrap().unwrap();
        assert_eq!(chain.depth, 1);
    }

    #[test]
    fn the_age_counts_from_iat() {
        let whole = claims(&json!({"iat": 1_000, "act": {"sub": "agent-a"}}));
        let chain = read(&whole, Some("alice"), at(1_090)).unwrap().unwrap();
        assert!((chain.age_seconds - 90.0).abs() < f64::EPSILON);

        let fractional = claims(&json!({"iat": 1_000.5, "act": {"sub": "agent-a"}}));
        let chain = read(&fractional, Some("alice"), at(1_090))
            .unwrap()
            .unwrap();
        assert!((chain.age_seconds - 89.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_missing_or_future_iat_gives_age_zero() {
        for iat in [json!({}), json!({"iat": 5_000}), json!({"iat": "soon"})] {
            let mut value = json!({"act": {"sub": "agent-a"}});
            value
                .as_object_mut()
                .unwrap()
                .extend(iat.as_object().unwrap().clone());
            let chain = read(&claims(&value), Some("alice"), at(1_000))
                .unwrap()
                .unwrap();
            assert!(chain.age_seconds.abs() < f64::EPSILON);
        }
    }
}
