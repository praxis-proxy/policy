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
// v1 is in-process (`InMemoryCorrelationStore`). That survives retries
// within one gateway process — enough for a single-node demo. The trait
// is the seam for a Valkey-backed store (cross-node / cross-restart) —
// deferred; when added, the CIBA store should use its own instance or an
// ACL-scoped user so it is isolated from the session-store keyspace.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

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
    /// The live tool or requester differs from the stored binding.
    BindingMismatch,
    /// The OP has not supplied an approved identity yet.
    Pending,
    /// The resolved correlation was removed atomically and returned.
    Ready(Correlation),
}

/// Storage for in-flight CIBA correlations, keyed by elicitation id.
pub trait CorrelationStore: Send + Sync {
    /// Record a freshly dispatched elicitation.
    fn put(&self, id: &str, correlation: Correlation);
    /// Read the current state for an id, if present.
    fn get(&self, id: &str) -> Option<Correlation>;
    /// Record who approved (the extracted claim) against an existing
    /// correlation. No-op if the id is unknown.
    fn set_resolved_approver(&self, id: &str, approver: String);
    /// Atomically remove a resolved approval only for its tool and requester.
    fn take_if_ready(&self, id: &str, tool: &str, requester: &str) -> TakeResult;
}

/// In-process correlation store. Thread-safe; the plugin instance is
/// shared across requests, so this map persists across an agent's retries
/// within one gateway process.
#[derive(Debug, Default)]
pub struct InMemoryCorrelationStore {
    inner: Mutex<HashMap<String, Correlation>>,
}

impl InMemoryCorrelationStore {
    /// A new instance with nothing registered or stored yet.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CorrelationStore for InMemoryCorrelationStore {
    fn put(&self, id: &str, correlation: Correlation) {
        let mut entries = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, c| c.expires_at > Utc::now());
        entries.insert(id.to_owned(), correlation);
    }

    fn get(&self, id: &str) -> Option<Correlation> {
        let mut entries = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, c| c.expires_at > Utc::now());
        entries.get(id).cloned()
    }

    fn set_resolved_approver(&self, id: &str, approver: String) {
        let mut entries = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, c| c.expires_at > Utc::now());
        if let Some(c) = entries.get_mut(id) {
            c.resolved_approver = Some(approver);
        }
    }

    fn take_if_ready(&self, id: &str, tool: &str, requester: &str) -> TakeResult {
        let mut entries = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, c| c.expires_at > Utc::now());
        let Some(c) = entries.get(id) else {
            return TakeResult::Missing;
        };
        if c.tool != tool || c.requester != requester {
            return TakeResult::BindingMismatch;
        }
        if c.resolved_approver.is_none() {
            return TakeResult::Pending;
        }
        match entries.remove(id) {
            Some(c) => TakeResult::Ready(c),
            None => TakeResult::Missing,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip() {
        let store = InMemoryCorrelationStore::new();
        store.put(
            "req-1",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: None,
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        let c = store.get("req-1").expect("present");
        assert_eq!(c.expected_approver, "alice");
        assert!(c.resolved_approver.is_none());
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn set_resolved_approver_records_on_existing() {
        let store = InMemoryCorrelationStore::new();
        store.put(
            "req-1",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: None,
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        store.set_resolved_approver("req-1", "alice".into());
        assert_eq!(
            store.get("req-1").unwrap().resolved_approver.as_deref(),
            Some("alice")
        );
        // Unknown id is a silent no-op.
        store.set_resolved_approver("missing", "x".into());
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn take_is_bound_single_use_and_expiry_evicts() {
        let store = InMemoryCorrelationStore::new();
        store.put(
            "id",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: Some("alice".into()),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        assert!(matches!(
            store.take_if_ready("id", "bonus", "bob"),
            TakeResult::BindingMismatch
        ));
        assert!(matches!(
            store.take_if_ready("id", "adjust", "eve"),
            TakeResult::BindingMismatch
        ));
        assert!(matches!(
            store.take_if_ready("id", "adjust", "bob"),
            TakeResult::Ready(_)
        ));
        assert!(matches!(
            store.take_if_ready("id", "adjust", "bob"),
            TakeResult::Missing
        ));

        store.put(
            "expired",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: Some("alice".into()),
                tool: "adjust".into(),
                requester: "bob".into(),
                expires_at: Utc::now() - chrono::Duration::seconds(1),
            },
        );
        assert!(store.get("expired").is_none());
    }

    #[test]
    fn concurrent_redeemers_cannot_both_take_an_approval() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(InMemoryCorrelationStore::new());
        store.put(
            "id",
            Correlation {
                expected_approver: "alice".into(),
                resolved_approver: Some("alice".into()),
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
                store.take_if_ready("id", "adjust", "bob")
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
