// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Bounded TTL map for PDP decisions.
//
// FIFO eviction is deterministic given the same insert sequence: the
// oldest live entry leaves first once expired entries have been
// stripped from the front. Expired entries are never returned.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use praxis_policy_apl_core::step::PdpDecision;

use super::key::CacheKey;

pub(crate) struct Store {
    entries: HashMap<CacheKey, Slot>,
    /// Oldest insertion at the front.
    order: VecDeque<CacheKey>,
    max_entries: usize,
}

struct Slot {
    decision: PdpDecision,
    expires_at: Instant,
}

#[derive(Debug)]
pub(crate) enum Lookup {
    Hit(PdpDecision),
    Expired,
    Miss,
}

#[derive(Debug)]
pub(crate) enum Insert {
    Stored,
    Evicted,
}

impl Store {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    pub(crate) fn lookup(&mut self, key: &CacheKey, now: Instant) -> Lookup {
        let Some(slot) = self.entries.get(key) else {
            return Lookup::Miss;
        };
        if slot.expires_at <= now {
            self.remove(key);
            return Lookup::Expired;
        }
        Lookup::Hit(slot.decision.clone())
    }

    pub(crate) fn insert(
        &mut self,
        key: CacheKey,
        decision: PdpDecision,
        expires_at: Instant,
        now: Instant,
    ) -> Insert {
        self.drop_expired_from_front(now);
        if let Entry::Occupied(mut occupied) = self.entries.entry(key) {
            occupied.insert(Slot {
                decision,
                expires_at,
            });
            return Insert::Stored;
        }
        let mut evicted = false;
        while self.entries.len() >= self.max_entries {
            self.drop_expired_from_front(now);
            if self.entries.len() < self.max_entries {
                break;
            }
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
                evicted = true;
            } else {
                break;
            }
        }
        self.order.push_back(key);
        self.entries.insert(
            key,
            Slot {
                decision,
                expires_at,
            },
        );
        if evicted {
            Insert::Evicted
        } else {
            Insert::Stored
        }
    }

    fn drop_expired_from_front(&mut self, now: Instant) {
        while let Some(front) = self.order.front().copied() {
            let expired = self
                .entries
                .get(&front)
                .is_none_or(|slot| slot.expires_at <= now);
            if !expired {
                break;
            }
            self.remove(&front);
        }
    }

    fn remove(&mut self, key: &CacheKey) {
        self.entries.remove(key);
        if let Some(index) = self.order.iter().position(|k| k == key) {
            self.order.remove(index);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use std::time::Duration;

    use praxis_policy_apl_core::evaluator::Decision;

    fn key(tag: u8) -> CacheKey {
        let mut bytes = [0_u8; 32];
        bytes[0] = tag;
        CacheKey(bytes)
    }

    fn allow() -> PdpDecision {
        PdpDecision {
            decision: Decision::Allow,
            diagnostics: Vec::new(),
        }
    }

    fn deny() -> PdpDecision {
        PdpDecision {
            decision: Decision::Deny {
                reason: Some("no".to_owned()),
                rule_source: "test".to_owned(),
            },
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn expired_lookup_is_not_a_hit() {
        let mut store = Store::new(4);
        let now = Instant::now();
        store.insert(key(1), allow(), now, now);
        match store.lookup(&key(1), now + Duration::from_millis(1)) {
            Lookup::Expired => {},
            other => panic!("expected Expired, got {other:?}"),
        }
        assert!(matches!(store.lookup(&key(1), now), Lookup::Miss));
    }

    #[test]
    fn fifo_evicts_the_oldest_live_entry() {
        let mut store = Store::new(2);
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        assert!(matches!(
            store.insert(key(1), allow(), later, now),
            Insert::Stored
        ));
        assert!(matches!(
            store.insert(key(2), deny(), later, now),
            Insert::Stored
        ));
        assert!(matches!(
            store.insert(key(3), allow(), later, now),
            Insert::Evicted
        ));
        assert!(matches!(store.lookup(&key(1), now), Lookup::Miss));
        assert!(matches!(store.lookup(&key(2), now), Lookup::Hit(_)));
        assert!(matches!(store.lookup(&key(3), now), Lookup::Hit(_)));
    }

    #[test]
    fn replacing_an_existing_key_does_not_grow_the_map() {
        let mut store = Store::new(1);
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        store.insert(key(1), allow(), later, now);
        assert!(matches!(
            store.insert(key(1), deny(), later, now),
            Insert::Stored
        ));
        match store.lookup(&key(1), now) {
            Lookup::Hit(decision) => {
                assert!(matches!(decision.decision, Decision::Deny { .. }));
            },
            other => panic!("expected Hit, got {other:?}"),
        }
    }
}
