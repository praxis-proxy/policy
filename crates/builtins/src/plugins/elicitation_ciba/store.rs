// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Correlation store — maps an elicitation id (the CIBA `auth_req_id`,
// which the agent echoes on retry) to the state the handler needs across
// the dispatch → check → validate lifetime: who the *expected* approver is
// (`login_hint`, set at dispatch) and, once `check` sees a successful poll,
// who *actually* approved (the approver claim extracted from the OP token).
//
// # Why we store the extracted claim, not the token
//
// CIBA hands the token back exactly once (a second poll on the same
// `auth_req_id` fails), and `validate` runs on a later request than
// `check` — so the relevant fact must be carried across. We extract the
// approver claim at `check` and store *that string*, then drop the token.
// `validate` compares the two stored strings (expected vs resolved); it
// never needs the token. This keeps a **bearer credential out of the
// store at rest** — so even a leaked/co-tenant store reveals only "who
// approved what," never a usable token. (The `require_step_up` path,
// which forwards the CIBA token, is separate and does not use this store.)
//
// `InMemoryCorrelationStore` survives retries within one process. The
// Valkey store (`valkey_store.rs`) shares state across replicas and
// restarts; it should run as its own ACL user so it is isolated from the
// session-store keyspace.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// State tracked per in-flight elicitation.
#[derive(Debug, Clone)]
pub struct Correlation {
    /// The approver the backchannel request named (`login_hint`), set at
    /// dispatch. `validate` cross-checks the resolved approver against it.
    pub expected_approver: String,
    /// Who actually approved — the approver claim (e.g. `preferred_username`)
    /// extracted from the OP token at `check`. `None` until a successful
    /// poll resolves it. We keep the **extracted claim, not the token**, so
    /// no bearer credential sits in the store at rest.
    pub resolved_approver: Option<String>,
    /// Policy route, including its scope, that opened this approval.
    pub route_key: String,
    /// Exact tool that opened this approval.
    pub tool: String,
    /// Authenticated subject id that opened this approval.
    pub requester: String,
    /// Store entries expire even when no retry arrives.
    pub expires_at: DateTime<Utc>,
}

/// Result of one atomic attempt to redeem a resolved approval.
#[derive(Debug)]
pub enum TakeResult {
    /// No live correlation exists for this id.
    Missing,
    /// The live route, tool, or requester differs from the stored binding.
    BindingMismatch,
    /// The OP has not supplied an approved identity yet.
    Pending,
    /// The resolved correlation was removed atomically and returned.
    Ready(Correlation),
}

/// Result of claiming the single-use OP poll for one correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollClaim {
    /// This caller owns the poll until it finishes or becomes uncertain.
    Acquired,
    /// Another caller is currently polling the OP.
    Busy,
    /// An earlier poll has already saved an approved identity.
    Resolved,
    /// The correlation has expired or was redeemed.
    Missing,
    /// The live correlation belongs to a different route, tool, or requester.
    BindingMismatch,
    /// A prior poll may have spent the OP request without saving its answer.
    Uncertain,
}

/// A backend failure that leaves the approval state unknown.
/// Callers must not treat it as a missing approval.
#[derive(Debug, thiserror::Error)]
#[error("correlation store unavailable: {0}")]
pub struct StoreError(String);

impl StoreError {
    /// Create a failure with a message for operator logs. Do not return the
    /// message to the request caller.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The failure description.
    pub fn message(&self) -> &str {
        &self.0
    }
}

/// Storage for in-flight CIBA correlations, keyed by elicitation id.
#[async_trait]
pub trait CorrelationStore: Send + Sync {
    /// Record a freshly dispatched elicitation.
    async fn put(&self, id: &str, correlation: Correlation) -> Result<(), StoreError>;
    /// Read the current state for an id, if present.
    async fn get(&self, id: &str) -> Result<Option<Correlation>, StoreError>;
    /// Atomically claim an unresolved OP poll. An expired claim becomes
    /// uncertain rather than allowing another poll of a possibly spent id.
    async fn claim_poll(
        &self,
        id: &str,
        owner: &str,
        lease: Duration,
        route_key: &str,
        tool: &str,
        requester: &str,
    ) -> Result<PollClaim, StoreError>;
    /// Release a claim after a definite result that did not consume approval.
    async fn release_poll(&self, id: &str, owner: &str) -> Result<(), StoreError>;
    /// Atomically save the approver and clear this owner's claim.
    async fn complete_poll(
        &self,
        id: &str,
        owner: &str,
        approver: String,
    ) -> Result<(), StoreError>;
    /// Mark a poll with an ambiguous outcome; it must not be repeated.
    async fn abandon_poll(&self, id: &str, owner: &str) -> Result<(), StoreError>;
    /// Record who approved (the extracted claim) against an existing
    /// correlation. No-op if the id is unknown.
    async fn set_resolved_approver(&self, id: &str, approver: String) -> Result<(), StoreError>;
    /// Atomically remove a resolved approval only for its route, tool, and requester.
    async fn take_if_ready(
        &self,
        id: &str,
        route_key: &str,
        tool: &str,
        requester: &str,
    ) -> Result<TakeResult, StoreError>;
}

/// In-process correlation store. Thread-safe; the plugin instance is
/// shared across requests, so this map persists across an agent's retries
/// within one gateway process.
#[derive(Debug, Default)]
pub struct InMemoryCorrelationStore {
    inner: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    correlations: HashMap<String, Correlation>,
    polls: HashMap<String, MemoryPoll>,
}

#[derive(Debug)]
enum MemoryPoll {
    InFlight { owner: String, deadline: Instant },
    Uncertain,
}

impl MemoryState {
    fn retain_live(&mut self) {
        let now = Utc::now();
        self.correlations.retain(|_, c| c.expires_at > now);
        self.polls
            .retain(|id, _| self.correlations.contains_key(id));
    }
}

impl InMemoryCorrelationStore {
    /// A new instance with nothing registered or stored yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a correlation synchronously for test setup.
    pub fn insert(&self, id: &str, correlation: Correlation) {
        self.put_sync(id, correlation);
    }
}

#[async_trait]
impl CorrelationStore for InMemoryCorrelationStore {
    async fn put(&self, id: &str, correlation: Correlation) -> Result<(), StoreError> {
        self.put_sync(id, correlation);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Correlation>, StoreError> {
        Ok(self.get_sync(id))
    }

    async fn claim_poll(
        &self,
        id: &str,
        owner: &str,
        lease: Duration,
        route_key: &str,
        tool: &str,
        requester: &str,
    ) -> Result<PollClaim, StoreError> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        let Some(correlation) = state.correlations.get(id) else {
            return Ok(PollClaim::Missing);
        };
        if correlation.route_key != route_key
            || correlation.tool != tool
            || correlation.requester != requester
        {
            return Ok(PollClaim::BindingMismatch);
        }
        if correlation.resolved_approver.is_some() {
            return Ok(PollClaim::Resolved);
        }
        let result = match state.polls.get(id) {
            Some(MemoryPoll::Uncertain) => PollClaim::Uncertain,
            Some(MemoryPoll::InFlight { deadline, .. }) if Instant::now() >= *deadline => {
                state.polls.insert(id.to_owned(), MemoryPoll::Uncertain);
                PollClaim::Uncertain
            },
            Some(MemoryPoll::InFlight { .. }) => PollClaim::Busy,
            None => {
                let deadline = Instant::now()
                    .checked_add(lease)
                    .ok_or_else(|| StoreError::new("poll lease is too large"))?;
                state.polls.insert(
                    id.to_owned(),
                    MemoryPoll::InFlight {
                        owner: owner.to_owned(),
                        deadline,
                    },
                );
                PollClaim::Acquired
            },
        };
        Ok(result)
    }

    async fn release_poll(&self, id: &str, owner: &str) -> Result<(), StoreError> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        require_owner(&state.polls, id, owner)?;
        state.polls.remove(id);
        Ok(())
    }

    async fn complete_poll(
        &self,
        id: &str,
        owner: &str,
        approver: String,
    ) -> Result<(), StoreError> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        require_owner(&state.polls, id, owner)?;
        let correlation = state
            .correlations
            .get_mut(id)
            .ok_or_else(|| StoreError::new("poll correlation expired"))?;
        correlation.resolved_approver = Some(approver);
        state.polls.remove(id);
        Ok(())
    }

    async fn abandon_poll(&self, id: &str, owner: &str) -> Result<(), StoreError> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        require_owner(&state.polls, id, owner)?;
        state.polls.insert(id.to_owned(), MemoryPoll::Uncertain);
        Ok(())
    }

    async fn set_resolved_approver(&self, id: &str, approver: String) -> Result<(), StoreError> {
        self.set_resolved_approver_sync(id, approver);
        Ok(())
    }

    async fn take_if_ready(
        &self,
        id: &str,
        route_key: &str,
        tool: &str,
        requester: &str,
    ) -> Result<TakeResult, StoreError> {
        Ok(self.take_if_ready_sync(id, route_key, tool, requester))
    }
}

impl InMemoryCorrelationStore {
    fn put_sync(&self, id: &str, correlation: Correlation) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        state.polls.remove(id);
        state.correlations.insert(id.to_owned(), correlation);
    }

    fn get_sync(&self, id: &str) -> Option<Correlation> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        state.correlations.get(id).cloned()
    }

    fn set_resolved_approver_sync(&self, id: &str, approver: String) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        if let Some(c) = state.correlations.get_mut(id) {
            c.resolved_approver = Some(approver);
        }
    }

    fn take_if_ready_sync(
        &self,
        id: &str,
        route_key: &str,
        tool: &str,
        requester: &str,
    ) -> TakeResult {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.retain_live();
        let Some(c) = state.correlations.get(id) else {
            return TakeResult::Missing;
        };
        if c.route_key != route_key || c.tool != tool || c.requester != requester {
            return TakeResult::BindingMismatch;
        }
        if c.resolved_approver.is_none() {
            return TakeResult::Pending;
        }
        state.polls.remove(id);
        match state.correlations.remove(id) {
            Some(c) => TakeResult::Ready(c),
            None => TakeResult::Missing,
        }
    }
}

fn require_owner(
    polls: &HashMap<String, MemoryPoll>,
    id: &str,
    owner: &str,
) -> Result<(), StoreError> {
    match polls.get(id) {
        Some(MemoryPoll::InFlight {
            owner: current,
            deadline,
        }) if current == owner && Instant::now() < *deadline => Ok(()),
        _ => Err(StoreError::new("poll claim is no longer owned")),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_poll_owner_can_complete_and_other_checkers_replay() {
        let store = InMemoryCorrelationStore::new();
        store.insert(
            "req",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: None,
                route_key: "tool:adjust@sandbox".into(),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            },
        );
        let claim = |owner| {
            store.claim_poll(
                "req",
                owner,
                Duration::from_secs(10),
                "tool:adjust@sandbox",
                "adjust",
                "bob",
            )
        };
        assert_eq!(claim("a").await.unwrap(), PollClaim::Acquired);
        assert_eq!(claim("b").await.unwrap(), PollClaim::Busy);
        assert!(
            store
                .complete_poll("req", "b", "alice".into())
                .await
                .is_err()
        );
        store
            .complete_poll("req", "a", "alice".into())
            .await
            .unwrap();
        assert_eq!(claim("b").await.unwrap(), PollClaim::Resolved);
        assert_eq!(
            store
                .get("req")
                .await
                .unwrap()
                .unwrap()
                .resolved_approver
                .as_deref(),
            Some("alice")
        );
    }

    #[tokio::test]
    async fn an_expired_or_ambiguous_poll_is_never_reclaimed() {
        let store = InMemoryCorrelationStore::new();
        store.insert(
            "req",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: None,
                route_key: "tool:adjust@sandbox".into(),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            },
        );
        assert_eq!(
            store
                .claim_poll(
                    "req",
                    "a",
                    Duration::ZERO,
                    "tool:adjust@sandbox",
                    "adjust",
                    "bob"
                )
                .await
                .unwrap(),
            PollClaim::Acquired
        );
        assert_eq!(
            store
                .claim_poll(
                    "req",
                    "b",
                    Duration::from_secs(10),
                    "tool:adjust@sandbox",
                    "adjust",
                    "bob"
                )
                .await
                .unwrap(),
            PollClaim::Uncertain
        );
        assert!(
            store
                .complete_poll("req", "a", "alice".into())
                .await
                .is_err()
        );
    }

    #[test]
    fn put_get_roundtrip() {
        let store = InMemoryCorrelationStore::new();
        store.put_sync(
            "req-1",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: None,
                route_key: "tool:adjust@sandbox".into(),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        let c = store.get_sync("req-1").expect("present");
        assert_eq!(c.expected_approver, "alice");
        assert!(c.resolved_approver.is_none());
        assert!(store.get_sync("missing").is_none());
    }

    #[test]
    fn set_resolved_approver_records_on_existing() {
        let store = InMemoryCorrelationStore::new();
        store.put_sync(
            "req-1",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: None,
                route_key: "tool:adjust@sandbox".into(),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        store.set_resolved_approver_sync("req-1", "alice".into());
        assert_eq!(
            store
                .get_sync("req-1")
                .unwrap()
                .resolved_approver
                .as_deref(),
            Some("alice")
        );
        // Unknown id is a silent no-op.
        store.set_resolved_approver_sync("missing", "x".into());
        assert!(store.get_sync("missing").is_none());
    }

    #[test]
    fn take_is_bound_single_use_and_expiry_evicts() {
        let store = InMemoryCorrelationStore::new();
        store.put_sync(
            "id",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: Some("alice".into()),
                route_key: "tool:adjust@sandbox".into(),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        assert!(matches!(
            store.take_if_ready_sync("id", "tool:adjust@sandbox", "bonus", "bob"),
            TakeResult::BindingMismatch
        ));
        assert!(matches!(
            store.take_if_ready_sync("id", "tool:adjust@prod", "adjust", "bob"),
            TakeResult::BindingMismatch
        ));
        assert!(matches!(
            store.take_if_ready_sync("id", "tool:adjust@sandbox", "adjust", "eve"),
            TakeResult::BindingMismatch
        ));
        assert!(matches!(
            store.take_if_ready_sync("id", "tool:adjust@sandbox", "adjust", "bob"),
            TakeResult::Ready(_)
        ));
        assert!(matches!(
            store.take_if_ready_sync("id", "tool:adjust@sandbox", "adjust", "bob"),
            TakeResult::Missing
        ));

        store.put_sync(
            "expired",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: Some("alice".into()),
                route_key: "tool:adjust@sandbox".into(),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() - chrono::Duration::seconds(1),
            },
        );
        assert!(store.get_sync("expired").is_none());
    }

    #[test]
    fn concurrent_redeemers_cannot_both_take_an_approval() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(InMemoryCorrelationStore::new());
        store.put_sync(
            "id",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: Some("alice".into()),
                route_key: "tool:adjust@sandbox".into(),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.take_if_ready_sync("id", "tool:adjust@sandbox", "adjust", "bob")
            }));
        }
        barrier.wait();
        let ready = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|result| matches!(result, TakeResult::Ready(_)))
            .count();
        assert_eq!(ready, 1);
    }
}
