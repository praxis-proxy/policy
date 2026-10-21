// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RateLimitConfig {
    pub namespace: String,
    #[serde(default = "default_counter_capacity")]
    pub counter_capacity: u64,
    #[serde(default = "default_bindings")]
    pub bindings: BTreeMap<String, String>,
    pub limits: Vec<LimitConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LimitConfig {
    pub max: u64,
    pub seconds: u64,
    #[serde(default)]
    pub conditions: Vec<String>,
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
            return Err("ratelimit: namespace must be non-empty".to_owned());
        }
        if self.counter_capacity == 0 {
            return Err("ratelimit: counter_capacity must be greater than zero".to_owned());
        }
        if self.bindings.is_empty() {
            return Err("ratelimit: at least one attribute binding is required".to_owned());
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
                    "ratelimit: binding '{variable}' must be a simple CEL variable other than 'limit'"
                ));
            }
            if attribute.trim().is_empty() {
                return Err(format!(
                    "ratelimit: binding '{variable}' must name a PPE attribute"
                ));
            }
        }
        if self.limits.is_empty() {
            return Err("ratelimit: at least one limit is required".to_owned());
        }
        for (index, limit) in self.limits.iter().enumerate() {
            if limit.max == 0 || limit.seconds == 0 {
                return Err(format!(
                    "ratelimit: limits[{index}] max and seconds must be greater than zero"
                ));
            }
        }
        Ok(())
    }
}
