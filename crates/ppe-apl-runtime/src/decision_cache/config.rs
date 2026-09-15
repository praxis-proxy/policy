// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Operator knobs for the optional PDP decision cache.
//
// The block is opt-in. A `global.pdp[]` entry with no `cache:` is unchanged:
// every evaluate reaches the backend. Presence of `cache:` requires both a
// positive TTL and a positive entry bound; there is no half-enabled state.

use std::time::Duration;

use thiserror::Error;

/// Why a `cache:` block could not be turned into a [`DecisionCacheConfig`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecisionCacheConfigError {
    /// The block was not a mapping.
    #[error("PDP `cache:` must be a mapping with `ttl_seconds` and `max_entries`")]
    NotAMapping,
    /// A key in the block is not a string.
    #[error("PDP `cache:` keys must be strings")]
    NonStringKey,
    /// A key the cache does not read. Named so a typo fails at load.
    #[error("unknown PDP `cache:` key `{0}`; expected `ttl_seconds` and `max_entries`")]
    UnknownKey(String),
    /// `ttl_seconds` missing, zero, or not a positive integer.
    #[error("PDP `cache.ttl_seconds` must be a positive integer")]
    InvalidTtl,
    /// `max_entries` missing, zero, or not a positive integer.
    #[error("PDP `cache.max_entries` must be a positive integer")]
    InvalidMaxEntries,
}

/// Bounds for one PDP's decision cache. Constructed only from a valid
/// `cache:` block, so both fields are positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionCacheConfig {
    /// How long a stored Allow or Deny may be reused.
    pub ttl: Duration,
    /// Hard cap on live entries. Insertions past this evict deterministically.
    pub max_entries: usize,
}

impl DecisionCacheConfig {
    /// Parse a `cache:` mapping. Omission is handled by the caller: this
    /// function is only reached when the key is present.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionCacheConfigError`] when the block is not a mapping,
    /// names an unknown key, or carries a non-positive TTL or cap.
    pub fn from_yaml(value: &serde_yaml::Value) -> Result<Self, DecisionCacheConfigError> {
        let map = value
            .as_mapping()
            .ok_or(DecisionCacheConfigError::NotAMapping)?;

        let mut ttl_seconds: Option<u64> = None;
        let mut max_entries: Option<usize> = None;
        for (key, val) in map {
            let Some(name) = key.as_str() else {
                return Err(DecisionCacheConfigError::NonStringKey);
            };
            match name {
                "ttl_seconds" => {
                    ttl_seconds =
                        Some(positive_u64(val).ok_or(DecisionCacheConfigError::InvalidTtl)?);
                },
                "max_entries" => {
                    max_entries = Some(
                        positive_usize(val).ok_or(DecisionCacheConfigError::InvalidMaxEntries)?,
                    );
                },
                other => return Err(DecisionCacheConfigError::UnknownKey(other.to_owned())),
            }
        }

        let ttl_seconds = ttl_seconds.ok_or(DecisionCacheConfigError::InvalidTtl)?;
        let max_entries = max_entries.ok_or(DecisionCacheConfigError::InvalidMaxEntries)?;
        Ok(Self {
            ttl: Duration::from_secs(ttl_seconds),
            max_entries,
        })
    }
}

fn positive_u64(value: &serde_yaml::Value) -> Option<u64> {
    let n = value.as_u64()?;
    (n > 0).then_some(n)
}

fn positive_usize(value: &serde_yaml::Value) -> Option<usize> {
    let n = positive_u64(value)?;
    usize::try_from(n).ok().filter(|v| *v > 0)
}

/// Pull `cache:` off a `global.pdp[]` entry so backend factories never see
/// it. They reject unknown keys; the cache is a runtime wrapper, not a
/// Cedar/CEL/OPA setting.
///
/// # Errors
///
/// Returns [`DecisionCacheConfigError`] when `cache:` is present and invalid.
pub fn split_cache_block(
    entry: &serde_yaml::Value,
) -> Result<(serde_yaml::Value, Option<DecisionCacheConfig>), DecisionCacheConfigError> {
    let Some(map) = entry.as_mapping() else {
        return Ok((entry.clone(), None));
    };
    let mut stripped = map.clone();
    let Some(cache_val) = stripped.remove(serde_yaml::Value::String("cache".to_owned())) else {
        return Ok((entry.clone(), None));
    };
    let config = DecisionCacheConfig::from_yaml(&cache_val)?;
    Ok((serde_yaml::Value::Mapping(stripped), Some(config)))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<DecisionCacheConfig, DecisionCacheConfigError> {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        DecisionCacheConfig::from_yaml(&value)
    }

    #[test]
    fn valid_block_parses() {
        let cfg = parse("ttl_seconds: 30\nmax_entries: 64\n").unwrap();
        assert_eq!(cfg.ttl, Duration::from_secs(30));
        assert_eq!(cfg.max_entries, 64);
    }

    #[test]
    fn zero_ttl_is_refused() {
        assert_eq!(
            parse("ttl_seconds: 0\nmax_entries: 1\n"),
            Err(DecisionCacheConfigError::InvalidTtl)
        );
    }

    #[test]
    fn missing_cap_is_refused() {
        assert_eq!(
            parse("ttl_seconds: 1\n"),
            Err(DecisionCacheConfigError::InvalidMaxEntries)
        );
    }

    #[test]
    fn unknown_key_is_named() {
        let err = parse("ttl_seconds: 1\nmax_entries: 1\nfoo: 1\n").unwrap_err();
        assert!(matches!(err, DecisionCacheConfigError::UnknownKey(k) if k == "foo"));
    }

    #[test]
    fn split_omission_leaves_the_entry() {
        let entry: serde_yaml::Value = serde_yaml::from_str("kind: cel\n").unwrap();
        let (stripped, cfg) = split_cache_block(&entry).unwrap();
        assert!(cfg.is_none());
        assert_eq!(stripped, entry);
    }

    #[test]
    fn split_removes_cache_and_keeps_kind() {
        let entry: serde_yaml::Value =
            serde_yaml::from_str("kind: cel\ncache:\n  ttl_seconds: 5\n  max_entries: 2\n")
                .unwrap();
        let (stripped, cfg) = split_cache_block(&entry).unwrap();
        assert_eq!(cfg.unwrap().max_entries, 2);
        assert!(stripped.as_mapping().unwrap().get("cache").is_none());
        assert_eq!(
            stripped.as_mapping().unwrap().get("kind").unwrap().as_str(),
            Some("cel")
        );
    }
}
