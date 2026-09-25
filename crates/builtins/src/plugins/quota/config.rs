// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Typed configuration for the quota plugin, deserialized from
// `PluginConfig.config` once at construction.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What operators write under `plugins[<name>].config:`. One instance
/// enforces one per-consumer budget against one Limitador namespace. The
/// budget value lives in Limitador's `limits.yaml`, not here.
#[derive(Debug, Clone, Serialize, Deserialize)]
// Reject an unknown key rather than defaulting it. A typo in an optional
// field (`identityClaim` for `identity_claim`, `onError` for `on_error`)
// would otherwise key budgets on the wrong claim or silently fail open.
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    /// Limitador base URL, e.g. `http://limitador.grid-system.svc:8080`.
    /// The plugin POSTs to `{endpoint}/check` and `{endpoint}/report`.
    pub endpoint: String,

    /// Limitador limit namespace the counters live under, e.g. `grid-tokens`.
    pub namespace: String,

    /// Which resolved-identity value keys the budget, and the Limitador
    /// descriptor key. Default `sub` reads the authenticated subject id.
    ///
    /// Must name a claim the gateway verifies and that is always present on an
    /// authenticated request. `sub` is the only safe default: a client-supplied
    /// claim can be dropped or forged to dodge metering, so keying the budget on
    /// one is a bypass.
    #[serde(default = "default_identity_claim")]
    pub identity_claim: String,

    /// What to do when the Limitador call fails (unreachable, timeout, or a
    /// non-check status). `deny` (default) refuses, `allow` serves. Governs
    /// only transport failures, never an over-budget verdict.
    #[serde(default)]
    pub on_error: OnErrorMode,

    /// Fallback path to the token total in the response body, read only when
    /// the gateway's typed usage is absent, e.g. `usage.total_tokens`.
    /// Segments split on `.` or `/`.
    #[serde(default = "default_usage_json_path")]
    pub usage_json_path: String,

    /// Per-call HTTP timeout in seconds, so a slow Limitador fails fast into
    /// the `on_error` path rather than stalling the request. Default 5.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    /// Whether to serve a request that carries no resolved identity. Default
    /// false: with nothing to meter, the request is denied (fail closed),
    /// matching the posture for a missing backend, so a dropped identity claim
    /// cannot dodge the budget. Set true only when authentication is enforced
    /// upstream and an unauthenticated request should pass unmetered by design;
    /// every such request then logs a warning.
    #[serde(default)]
    pub allow_unauthenticated: bool,
}

/// How the plugin reacts when a Limitador call cannot be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnErrorMode {
    /// Fail closed: refuse when Limitador is unreachable. The default.
    #[default]
    Deny,
    /// Fail open: serve when Limitador is unreachable.
    Allow,
}

fn default_identity_claim() -> String {
    "sub".to_owned()
}

fn default_usage_json_path() -> String {
    "usage.total_tokens".to_owned()
}

/// Default per-call HTTP timeout, in seconds.
fn default_timeout_seconds() -> u64 {
    5
}

impl QuotaConfig {
    /// Reject an empty `endpoint` or `namespace` at construction.
    ///
    /// # Errors
    ///
    /// A message when `endpoint` or `namespace` is empty.
    pub fn validate(&self) -> Result<(), String> {
        if self.endpoint.trim().is_empty() {
            return Err("quota: endpoint must be non-empty".to_owned());
        }
        if self.namespace.trim().is_empty() {
            return Err("quota: namespace must be non-empty".to_owned());
        }
        Ok(())
    }

    /// The configured per-call HTTP timeout as a [`Duration`].
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_deserializes_with_defaults() {
        let cfg: QuotaConfig = serde_json::from_value(json!({
            "endpoint": "http://limitador.grid-system.svc:8080",
            "namespace": "grid-tokens",
        }))
        .unwrap();
        assert_eq!(cfg.identity_claim, "sub");
        assert_eq!(cfg.usage_json_path, "usage.total_tokens");
        assert_eq!(cfg.on_error, OnErrorMode::Deny);
        assert_eq!(cfg.timeout_seconds, 5);
        assert!(
            !cfg.allow_unauthenticated,
            "a request with no identity must fail closed by default"
        );
    }

    #[test]
    fn config_reads_explicit_fields() {
        let cfg: QuotaConfig = serde_json::from_value(json!({
            "endpoint": "http://lim:8080",
            "namespace": "ns",
            "identity_claim": "tenant",
            "on_error": "deny",
            "usage_json_path": "usage/total_tokens",
            "timeout_seconds": 2,
            "allow_unauthenticated": true,
        }))
        .unwrap();
        assert_eq!(cfg.identity_claim, "tenant");
        assert_eq!(cfg.on_error, OnErrorMode::Deny);
        assert_eq!(cfg.usage_json_path, "usage/total_tokens");
        assert_eq!(cfg.timeout_seconds, 2);
        assert!(cfg.allow_unauthenticated);
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        // A misspelled optional key (here `on_error` as camelCase) must fail
        // the parse rather than silently defaulting and failing open.
        let err = serde_json::from_value::<QuotaConfig>(json!({
            "endpoint": "http://lim:8080",
            "namespace": "ns",
            "onError": "allow",
        }))
        .unwrap_err();
        assert!(err.to_string().contains("onError"), "{err}");
    }

    #[test]
    fn an_empty_endpoint_is_rejected() {
        let cfg = QuotaConfig {
            endpoint: String::new(),
            namespace: "ns".to_owned(),
            identity_claim: default_identity_claim(),
            on_error: OnErrorMode::Allow,
            usage_json_path: default_usage_json_path(),
            timeout_seconds: 5,
            allow_unauthenticated: false,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("endpoint"), "{err}");
    }

    #[test]
    fn an_empty_namespace_is_rejected() {
        let cfg = QuotaConfig {
            endpoint: "http://lim:8080".to_owned(),
            namespace: "   ".to_owned(),
            identity_claim: default_identity_claim(),
            on_error: OnErrorMode::Allow,
            usage_json_path: default_usage_json_path(),
            timeout_seconds: 5,
            allow_unauthenticated: false,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("namespace"), "{err}");
    }
}
