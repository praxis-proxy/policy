// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RateLimitConfig {
    #[serde(default = "default_bindings")]
    pub bindings: BTreeMap<String, String>,
    #[serde(default = "default_counter_capacity")]
    pub counter_capacity: u64,
    pub limits: Vec<LimitConfig>,
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LimitConfig {
    #[serde(default)]
    pub conditions: Vec<String>,
    pub max: u64,
    pub seconds: u64,
    #[serde(default)]
    pub variables: Vec<String>,
}

const fn default_counter_capacity() -> u64 {
    10_000
}

fn default_bindings() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("subject_id".to_owned(), "subject.id".to_owned()),
        ("http_method".to_owned(), "http.method".to_owned()),
    ])
}

impl RateLimitConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.namespace.trim().is_empty() {
            return Err("namespace must be non-empty".to_owned());
        }
        if self.counter_capacity == 0 {
            return Err("counter_capacity must be greater than zero".to_owned());
        }
        if self.bindings.is_empty() {
            return Err("at least one attribute binding is required".to_owned());
        }
        for (variable, attribute) in &self.bindings {
            let mut chars = variable.chars();
            let valid_start = chars
                .next()
                .is_some_and(|character| character == '_' || character.is_ascii_alphabetic());
            if variable == "limit"
                || !valid_start
                || !chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
            {
                return Err(format!(
                    "binding '{variable}' must be a simple CEL variable other than 'limit'"
                ));
            }
            if attribute.trim().is_empty() {
                return Err(format!("binding '{variable}' must name a PPE attribute"));
            }
        }
        if self.limits.is_empty() {
            return Err("at least one limit is required".to_owned());
        }
        for (index, limit) in self.limits.iter().enumerate() {
            if limit.max == 0 || limit.seconds == 0 {
                return Err(format!(
                    "limits[{index}] max and seconds must be greater than zero"
                ));
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::RateLimitConfig;

    #[test]
    fn validate_rejects_each_invalid_field() -> Result<(), serde_json::Error> {
        for (label, config, expected) in [
            (
                "blank namespace",
                serde_json::json!({"namespace": " ", "limits": [{"max": 1, "seconds": 1}]}),
                "namespace must be non-empty",
            ),
            (
                "zero capacity",
                serde_json::json!({
                    "namespace": "n",
                    "counter_capacity": 0,
                    "limits": [{"max": 1, "seconds": 1}],
                }),
                "counter_capacity must be greater than zero",
            ),
            (
                "empty bindings",
                serde_json::json!({
                    "namespace": "n",
                    "bindings": {},
                    "limits": [{"max": 1, "seconds": 1}],
                }),
                "at least one attribute binding is required",
            ),
            (
                "binding named limit",
                serde_json::json!({
                    "namespace": "n",
                    "bindings": {"limit": "subject.id"},
                    "limits": [{"max": 1, "seconds": 1}],
                }),
                "binding 'limit' must be a simple CEL variable",
            ),
            (
                "binding with a leading digit",
                serde_json::json!({
                    "namespace": "n",
                    "bindings": {"1user": "subject.id"},
                    "limits": [{"max": 1, "seconds": 1}],
                }),
                "binding '1user' must be a simple CEL variable",
            ),
            (
                "binding with a dot",
                serde_json::json!({
                    "namespace": "n",
                    "bindings": {"user.id": "subject.id"},
                    "limits": [{"max": 1, "seconds": 1}],
                }),
                "binding 'user.id' must be a simple CEL variable",
            ),
            (
                "binding with a blank attribute",
                serde_json::json!({
                    "namespace": "n",
                    "bindings": {"user": " "},
                    "limits": [{"max": 1, "seconds": 1}],
                }),
                "binding 'user' must name a PPE attribute",
            ),
            (
                "no limits",
                serde_json::json!({"namespace": "n", "limits": []}),
                "at least one limit is required",
            ),
            (
                "zero max",
                serde_json::json!({"namespace": "n", "limits": [{"max": 0, "seconds": 1}]}),
                "limits[0] max and seconds must be greater than zero",
            ),
            (
                "zero seconds",
                serde_json::json!({
                    "namespace": "n",
                    "limits": [{"max": 1, "seconds": 1}, {"max": 1, "seconds": 0}],
                }),
                "limits[1] max and seconds must be greater than zero",
            ),
        ] {
            let config: RateLimitConfig = serde_json::from_value(config)?;
            let result = config.validate();
            assert!(
                matches!(&result, Err(error) if error.contains(expected)),
                "{label}: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn validate_accepts_the_default_bindings() -> Result<(), serde_json::Error> {
        let config: RateLimitConfig = serde_json::from_value(serde_json::json!({
            "namespace": "n",
            "limits": [{"max": 1, "seconds": 1}],
        }))?;
        assert_eq!(config.validate(), Ok(()), "a minimal config must validate");
        Ok(())
    }
}
