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
    /// Limitador base URL, e.g. `https://limitador.grid-system.svc:8443`.
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

    /// What to do on a timeout, connect or I/O error, oversized response, or
    /// Limitador 5xx. `deny` (default) refuses, `allow` serves. Unexpected
    /// non-5xx statuses, egress denials, and over-budget verdicts fail closed
    /// regardless.
    #[serde(default)]
    pub on_error: OnErrorMode,

    /// Per-call HTTP timeout in seconds, so a slow Limitador fails fast into
    /// the `on_error` path rather than stalling the request. Must be nonzero;
    /// default 5.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    /// Tokens debited when usage cannot be determined (streaming, absent field).
    /// Non-zero so the balance still moves; over-charge is the fail-closed
    /// direction. Default 1000.
    #[serde(default = "default_missing_usage_charge")]
    pub missing_usage_charge: u64,

    /// Whether to serve a request that carries no resolved identity. Default
    /// false: with nothing to meter, the request is denied (fail closed),
    /// matching the posture for a missing backend, so a dropped identity claim
    /// cannot dodge the budget. Set true only when authentication is enforced
    /// upstream and an unauthenticated request should pass unmetered by design;
    /// every such request then logs a warning.
    #[serde(default)]
    pub allow_unauthenticated: bool,

    /// Allow a plaintext `http://` endpoint. Default false: the endpoint must be
    /// `https://` so the host transport establishes TLS to Limitador. The plugin
    /// sends each principal's subject id in the request body, so a plaintext
    /// endpoint exposes it on the wire. Set true only for a localhost or demo
    /// Limitador with no TLS. TLS, the CA trust store and any client certificate
    /// for mTLS live on the host transport, not in this plugin.
    #[serde(default)]
    pub insecure_http: bool,
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

/// Default per-call HTTP timeout, in seconds.
fn default_timeout_seconds() -> u64 {
    5
}

/// Default conservative debit when usage cannot be determined.
fn default_missing_usage_charge() -> u64 {
    1000
}

impl QuotaConfig {
    /// Reject invalid configuration at construction.
    ///
    /// # Errors
    ///
    /// A message when `endpoint` or `namespace` is empty, a charge or timeout
    /// is zero, or the endpoint scheme is disallowed.
    pub fn validate(&self) -> Result<(), String> {
        let endpoint = self.endpoint.trim();
        if endpoint.is_empty() {
            return Err("quota: endpoint must be non-empty".to_owned());
        }
        if self.namespace.trim().is_empty() {
            return Err("quota: namespace must be non-empty".to_owned());
        }
        if self.missing_usage_charge == 0 {
            return Err("quota: missing_usage_charge must be greater than zero".to_owned());
        }
        if self.timeout_seconds == 0 {
            return Err("quota: timeout_seconds must be greater than zero".to_owned());
        }
        // Allowlist, secure by default: https lets the host transport encrypt
        // the connection. Any other scheme fails here at construction rather
        // than at the connector, where a Connect error would ride on_error.
        let lowered = endpoint.to_ascii_lowercase();
        if lowered.starts_with("https://") {
            return Ok(());
        }
        if lowered.starts_with("http://") {
            if self.insecure_http {
                return Ok(());
            }
            return Err(
                "quota: endpoint must use https:// so the connection to Limitador is \
                 encrypted; set insecure_http: true to allow http:// for a localhost or \
                 demo Limitador only"
                    .to_owned(),
            );
        }
        Err(format!(
            "quota: endpoint '{endpoint}' must be an https:// URL (or http:// with \
             insecure_http: true)"
        ))
    }

    /// The configured per-call HTTP timeout as a [`Duration`].
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests assert deserialization and validation results"
)]
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
        assert_eq!(cfg.on_error, OnErrorMode::Deny);
        assert_eq!(cfg.timeout_seconds, 5);
        assert_eq!(cfg.missing_usage_charge, 1000);
        assert!(
            !cfg.allow_unauthenticated,
            "a request with no identity must fail closed by default"
        );
        assert!(
            !cfg.insecure_http,
            "https must be required by default (insecure_http off)"
        );
    }

    #[test]
    fn config_reads_explicit_fields() {
        let cfg: QuotaConfig = serde_json::from_value(json!({
            "endpoint": "http://lim:8080",
            "namespace": "ns",
            "identity_claim": "tenant",
            "on_error": "deny",
            "timeout_seconds": 2,
            "allow_unauthenticated": true,
            "insecure_http": true,
        }))
        .unwrap();
        assert_eq!(cfg.identity_claim, "tenant");
        assert_eq!(cfg.on_error, OnErrorMode::Deny);
        assert_eq!(cfg.timeout_seconds, 2);
        assert!(cfg.allow_unauthenticated);
        assert!(cfg.insecure_http);
    }

    fn config_with_endpoint(endpoint: &str, insecure_http: bool) -> QuotaConfig {
        QuotaConfig {
            endpoint: endpoint.to_owned(),
            namespace: "ns".to_owned(),
            identity_claim: default_identity_claim(),
            on_error: OnErrorMode::Deny,
            timeout_seconds: 5,
            missing_usage_charge: default_missing_usage_charge(),
            allow_unauthenticated: false,
            insecure_http,
        }
    }

    #[test]
    fn an_https_endpoint_is_accepted() {
        config_with_endpoint("https://limitador.grid-system.svc:8443", false)
            .validate()
            .unwrap();
    }

    #[test]
    fn a_plaintext_endpoint_is_rejected_by_default() {
        let err = config_with_endpoint("http://limitador.grid-system.svc:8080", false)
            .validate()
            .unwrap_err();
        assert!(err.contains("https"), "{err}");
        assert!(err.contains("insecure_http"), "{err}");
    }

    #[test]
    fn a_plaintext_endpoint_is_allowed_with_insecure_http() {
        config_with_endpoint("http://localhost:8080", true)
            .validate()
            .unwrap();
    }

    #[test]
    fn a_non_http_scheme_is_rejected_even_with_insecure_http() {
        // Fail at construction, not at the connector where a Connect error
        // would ride on_error: allow.
        for endpoint in [
            "ftp://limitador:21",
            "limitador:8080",
            "unix:///run/lim.sock",
        ] {
            let err = config_with_endpoint(endpoint, true).validate().unwrap_err();
            assert!(err.contains("https://"), "{endpoint}: {err}");
        }
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
        let err = config_with_endpoint("", false).validate().unwrap_err();
        assert!(err.contains("endpoint"), "{err}");
    }

    #[test]
    fn an_empty_namespace_is_rejected() {
        let mut cfg = config_with_endpoint("https://lim:8443", false);
        cfg.namespace = "   ".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("namespace"), "{err}");
    }

    #[test]
    fn a_zero_missing_usage_charge_is_rejected() {
        let mut cfg = config_with_endpoint("https://lim:8443", false);
        cfg.missing_usage_charge = 0;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("missing_usage_charge"), "{err}");
    }

    #[test]
    fn a_zero_timeout_is_rejected() {
        let mut cfg = config_with_endpoint("https://lim:8443", false);
        cfg.timeout_seconds = 0;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("timeout_seconds"), "{err}");
    }
}
