// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::BTreeMap;

use praxis_policy_apl_cmf::constants::{
    BAG_AUTHENTICATED, BAG_CALLER_WORKLOAD_PREFIX, BAG_CLAIM_PREFIX, BAG_CLIENT_PREFIX,
    BAG_DELEGATED, BAG_DELEGATION_PREFIX, BAG_HTTP_PATH, BAG_HTTP_QUERY,
    BAG_HTTP_REQUEST_HEADERS_PREFIX, BAG_PERM_PREFIX, BAG_ROLE_PREFIX, BAG_TEAM_PREFIX,
};
use praxis_policy_core::ratelimit_hook::{
    HOOK_RATELIMIT_POST_IDENTITY, HOOK_RATELIMIT_PRE_IDENTITY,
};
use serde::Deserialize;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Bag attributes that identity resolution writes, so none is present before
/// it runs. An entry ending in `.` matches every key under it.
const IDENTITY_DERIVED_ATTRIBUTES: &[&str] = &[
    "subject.",
    BAG_CLAIM_PREFIX,
    BAG_ROLE_PREFIX,
    BAG_PERM_PREFIX,
    BAG_TEAM_PREFIX,
    BAG_AUTHENTICATED,
    BAG_CLIENT_PREFIX,
    BAG_CALLER_WORKLOAD_PREFIX,
    BAG_DELEGATION_PREFIX,
    BAG_DELEGATED,
];

/// The default `counter_capacity`, and the floor below which a counter keyed
/// on an unbounded attribute warns at load.
pub(super) const DEFAULT_COUNTER_CAPACITY: u64 = 10_000; // qualified counters

/// Bag attributes the caller picks freely, so a counter keyed on one can be
/// reset by changing it. An entry ending in `.` matches every key under it.
const CALLER_CONTROLLED_ATTRIBUTES: &[&str] = &[
    BAG_HTTP_REQUEST_HEADERS_PREFIX,
    BAG_HTTP_QUERY,
    BAG_HTTP_PATH,
];

// -----------------------------------------------------------------------------
// Stage
// -----------------------------------------------------------------------------

/// The side of identity resolution an instance runs on, from its `hooks:`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    PreIdentity,
    PostIdentity,
}

impl Stage {
    /// The one stage `hooks` declares.
    pub(super) fn from_hooks(hooks: &[String]) -> Result<Self, String> {
        let mut stages = Vec::new();
        for hook in hooks {
            match hook.as_str() {
                HOOK_RATELIMIT_PRE_IDENTITY => stages.push(Self::PreIdentity),
                HOOK_RATELIMIT_POST_IDENTITY => stages.push(Self::PostIdentity),
                other => {
                    return Err(format!(
                        "hook `{other}` is not served by this kind; declare only \
                         `hooks: [{HOOK_RATELIMIT_PRE_IDENTITY}]` or \
                         `hooks: [{HOOK_RATELIMIT_POST_IDENTITY}]` and list the plugin under \
                         `rate_limits:`"
                    ));
                },
            }
        }
        stages.dedup();
        match stages.as_slice() {
            [stage] => Ok(*stage),
            [] => Err(format!(
                "no rate-limit hook is declared; set `hooks: [{HOOK_RATELIMIT_PRE_IDENTITY}]` or \
                 `hooks: [{HOOK_RATELIMIT_POST_IDENTITY}]`"
            )),
            _ => Err(format!(
                "both `{HOOK_RATELIMIT_PRE_IDENTITY}` and `{HOOK_RATELIMIT_POST_IDENTITY}` are \
                 declared, but an instance runs at one stage; declare a second plugin for the \
                 other stage"
            )),
        }
    }

    /// The hook this stage's handler registers on.
    pub(super) const fn hook(self) -> &'static str {
        match self {
            Self::PreIdentity => HOOK_RATELIMIT_PRE_IDENTITY,
            Self::PostIdentity => HOOK_RATELIMIT_POST_IDENTITY,
        }
    }
}

/// Whether identity resolution writes `attribute`.
pub(super) fn is_identity_derived(attribute: &str) -> bool {
    matches_any(attribute, IDENTITY_DERIVED_ATTRIBUTES)
}

/// Whether the caller chooses `attribute` freely.
pub(super) fn is_caller_controlled(attribute: &str) -> bool {
    matches_any(attribute, CALLER_CONTROLLED_ATTRIBUTES)
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

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
    DEFAULT_COUNTER_CAPACITY
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
// Private Utilities
// -----------------------------------------------------------------------------

fn matches_any(attribute: &str, entries: &[&str]) -> bool {
    entries.iter().any(|entry| {
        if entry.ends_with('.') {
            attribute.starts_with(entry)
        } else {
            attribute == *entry
        }
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{RateLimitConfig, Stage, is_caller_controlled, is_identity_derived};

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

    #[test]
    fn a_single_rate_limit_hook_selects_the_stage() {
        for (hooks, expected) in [
            (vec!["ratelimit.pre_identity"], Stage::PreIdentity),
            (vec!["ratelimit.post_identity"], Stage::PostIdentity),
            (
                vec!["ratelimit.post_identity", "ratelimit.post_identity"],
                Stage::PostIdentity,
            ),
        ] {
            let hooks: Vec<String> = hooks.into_iter().map(str::to_owned).collect();
            assert_eq!(
                Stage::from_hooks(&hooks),
                Ok(expected),
                "{hooks:?} must select {expected:?}"
            );
            assert_eq!(
                Some(expected.hook()),
                hooks.first().map(String::as_str),
                "the stage registers on the hook it was read from"
            );
        }
    }

    #[test]
    fn hooks_other_than_one_rate_limit_hook_are_rejected() {
        for (hooks, expected) in [
            (vec![], "no rate-limit hook is declared"),
            (
                vec!["ratelimit.pre_identity", "ratelimit.post_identity"],
                "an instance runs at one stage",
            ),
            (
                vec!["http.request"],
                "hook `http.request` is not served by this kind",
            ),
            (
                vec!["ratelimit.post_identity", "identity.resolve"],
                "hook `identity.resolve` is not served by this kind",
            ),
        ] {
            let hooks: Vec<String> = hooks.into_iter().map(str::to_owned).collect();
            let result = Stage::from_hooks(&hooks);
            assert!(
                matches!(&result, Err(error) if error.contains(expected)),
                "{hooks:?}: {result:?}"
            );
        }
    }

    #[test]
    fn identity_derived_attributes_cover_every_identity_family() {
        for attribute in [
            "subject.id",
            "subject.roles",
            "claim.plan",
            "role.admin",
            "perm.read",
            "team.core",
            "authenticated",
            "client.client_id",
            "caller_workload.spiffe_id",
            "delegation.depth",
            "delegated",
        ] {
            assert!(
                is_identity_derived(attribute),
                "{attribute} is written by identity resolution"
            );
        }
        for attribute in [
            "http.method",
            "http.path",
            "http.client_address",
            "agent.session_id",
            "authenticated_at",
            "subjects.id",
        ] {
            assert!(
                !is_identity_derived(attribute),
                "{attribute} is present before identity resolution"
            );
        }
    }

    #[test]
    fn caller_controlled_attributes_are_headers_query_and_path() {
        for attribute in ["http.request_headers.x-user", "http.query", "http.path"] {
            assert!(
                is_caller_controlled(attribute),
                "{attribute} is chosen by the caller"
            );
        }
        for attribute in [
            "http.client_address",
            "http.method",
            "subject.id",
            "http.paths",
        ] {
            assert!(
                !is_caller_controlled(attribute),
                "{attribute} is not a caller-chosen key"
            );
        }
    }
}
