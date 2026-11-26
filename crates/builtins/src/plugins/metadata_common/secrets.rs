// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Secret generation tracking for credential rotation and cache invalidation.
#![allow(
    dead_code,
    reason = "Phase 1: Secret generation types defined. Phase 2: Integrate with cache invalidation."
)]
//!
//! When credentials rotate (e.g., API keys, tokens), all cached entries that
//! depend on the old credential must be invalidated. This module tracks:
//! - Current generation ID for each credential
//! - Cache partitioning by credential generation
//! - Rotation detection and cache invalidation

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Non-secret identifier for a credential's current generation.
///
/// Credentials rotate frequently (OAuth tokens, API keys, etc.). Each rotation
/// produces a new generation ID. Cache entries include the generation ID in
/// their partition key, so old entries are automatically excluded after rotation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize)]
pub(crate) struct GenerationId(u64);

impl GenerationId {
    /// Create a new generation ID from a counter.
    pub(crate) fn new(counter: u64) -> Self {
        Self(counter)
    }

    /// Get the counter value.
    pub(crate) fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for GenerationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gen_{}", self.0)
    }
}

impl<'de> Deserialize<'de> for GenerationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}

/// Tracks current generation ID for each named credential.
///
/// A credential's generation advances when:
/// - API key is rotated
/// - OAuth token is refreshed
/// - Service account secret is updated
/// - Certificate is renewed
///
/// The generation ID is non-secret metadata used only for cache partitioning.
#[derive(Clone, Debug, Default)]
pub(crate) struct SecretGenerations {
    // Maps secret name (e.g., "entitlement-api-token") to current generation
    generations: BTreeMap<String, GenerationId>,
    // Next available generation counter (monotonically increasing)
    next_counter: u64,
}

impl SecretGenerations {
    /// Create a new secret generation tracker.
    pub(crate) fn new() -> Self {
        Self {
            generations: BTreeMap::new(),
            next_counter: 1,
        }
    }

    /// Get the current generation for a secret, initializing if needed.
    pub(crate) fn get_or_init(&mut self, secret_name: &str) -> GenerationId {
        if let Some(generation) = self.generations.get(secret_name) {
            *generation
        } else {
            let generation = GenerationId::new(self.next_counter);
            self.next_counter += 1;
            self.generations.insert(secret_name.to_owned(), generation);
            generation
        }
    }

    /// Mark a secret as rotated, returning the new generation.
    ///
    /// All cache entries for the old generation become stale.
    pub(crate) fn rotate(&mut self, secret_name: &str) -> GenerationId {
        let generation = GenerationId::new(self.next_counter);
        self.next_counter += 1;
        self.generations.insert(secret_name.to_owned(), generation);
        generation
    }

    /// Get all current generations (for cache invalidation on rotation).
    pub(crate) fn all_generations(&self) -> impl Iterator<Item = (&str, GenerationId)> {
        self.generations
            .iter()
            .map(|(name, generation)| (name.as_str(), *generation))
    }
}

/// Audit event for secret generation changes.
///
/// These events are recorded for every credential used in a metadata callout,
/// allowing detection of when old cached entries become invalid.
#[allow(dead_code, reason = "Phase 2: Audit event integration")]
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SecretGenerationEvent {
    /// Secret name (e.g., "entitlement-api-token").
    pub(crate) secret: String,
    /// Generation ID at time of callout.
    pub(crate) generation: GenerationId,
    /// Whether generation changed during this callout.
    pub(crate) rotated: bool,
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn generation_id_displays_as_gen_number() {
        let generation = GenerationId::new(42);
        assert_eq!(generation.to_string(), "gen_42");
    }

    #[test]
    fn secret_generations_starts_at_1() {
        let mut gens = SecretGenerations::new();
        let generation = gens.get_or_init("token");
        assert_eq!(generation.as_u64(), 1);
    }

    #[test]
    fn secret_generations_increments_per_secret() {
        let mut gens = SecretGenerations::new();
        let generation1 = gens.get_or_init("token1");
        let generation2 = gens.get_or_init("token2");
        let generation3 = gens.get_or_init("token3");
        assert_eq!(generation1.as_u64(), 1);
        assert_eq!(generation2.as_u64(), 2);
        assert_eq!(generation3.as_u64(), 3);
    }

    #[test]
    fn secret_generations_idempotent_for_same_secret() {
        let mut gens = SecretGenerations::new();
        let generation1a = gens.get_or_init("token");
        let generation1b = gens.get_or_init("token");
        assert_eq!(generation1a, generation1b);
        assert_eq!(generation1a.as_u64(), 1);
    }

    #[test]
    fn rotate_advances_generation_counter() {
        let mut gens = SecretGenerations::new();
        let generation1 = gens.get_or_init("token");
        assert_eq!(generation1.as_u64(), 1);

        let generation2 = gens.rotate("token");
        assert_eq!(generation2.as_u64(), 2);

        // Subsequent get returns the new generation
        let generation_check = gens.get_or_init("token");
        assert_eq!(generation_check.as_u64(), 2);
    }

    #[test]
    fn all_generations_returns_current_state() {
        let mut gens = SecretGenerations::new();
        let gen1a = gens.get_or_init("token1");
        let gen2a = gens.get_or_init("token2");
        // token1 is generation 1, token2 is generation 2
        assert_eq!(gen1a.as_u64(), 1);
        assert_eq!(gen2a.as_u64(), 2);

        let gen1b = gens.rotate("token1");
        // After rotate, token1 becomes generation 3
        assert_eq!(gen1b.as_u64(), 3);

        let all: Vec<_> = gens
            .all_generations()
            .map(|(name, generation)| (name.to_owned(), generation.as_u64()))
            .collect();

        assert_eq!(all.len(), 2);
        let token1_gen = all
            .iter()
            .find(|(name, _)| name.as_str() == "token1")
            .map(|(_, g)| *g);
        let token2_gen = all
            .iter()
            .find(|(name, _)| name.as_str() == "token2")
            .map(|(_, g)| *g);

        assert_eq!(token1_gen, Some(3), "token1 should be gen 3 after rotate");
        assert_eq!(token2_gen, Some(2), "token2 should be gen 2");
    }

    #[test]
    fn generation_id_serializes() {
        let generation = GenerationId::new(42);
        let json = serde_json::to_string(&generation).expect("serialize");
        assert_eq!(json, "42");
    }
}
