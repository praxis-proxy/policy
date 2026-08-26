// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Error types for the PPE plugin framework.
//
// Provides structured error types for plugin execution failures,
// policy violations, timeouts, and configuration errors.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level error type for the PPE framework.
///
/// Covers plugin execution failures, policy violations, timeouts,
/// and configuration issues. Each variant carries enough context
/// for the caller to log, report, or recover.
///
/// - `code` — business-logic error code (e.g., `"rate_limit_exceeded"`)
/// - `details` — structured diagnostic data for logging
/// - `proto_error_code` — protocol-level error code for the host to
///   map back to the wire format (MCP JSON-RPC, HTTP status, etc.)
#[derive(Debug, Error)]
pub enum PluginError {
    /// A plugin raised an execution error.
    #[error("plugin '{plugin_name}' failed: {message}")]
    Execution {
        /// The plugin that failed.
        plugin_name: String,
        /// What went wrong.
        message: String,
        /// The underlying error that caused this failure, if any — the
        /// error-chain `source` for `{:?}`/`Display` walking.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        /// Business-logic error code set by the plugin.
        code: Option<String>,
        /// Structured diagnostic data for logging or debugging.
        details: HashMap<String, serde_json::Value>,
        /// Protocol-level error code for the host to map to the wire
        /// format. MCP: JSON-RPC codes (e.g., -32603). HTTP: status
        /// codes. The host interprets this; PPE just carries it.
        proto_error_code: Option<i64>,
    },

    /// A plugin exceeded its execution timeout.
    #[error("plugin '{plugin_name}' timed out after {timeout_ms}ms")]
    Timeout {
        /// The plugin that timed out.
        plugin_name: String,
        /// The budget it exceeded.
        timeout_ms: u64,
        /// Protocol-level error code for the host.
        proto_error_code: Option<i64>,
    },

    /// A plugin returned a policy violation (deny).
    #[error("plugin '{plugin_name}' denied: {}", violation.reason)]
    Violation {
        /// The plugin that denied.
        plugin_name: String,
        /// The violation it reported.
        violation: PluginViolation,
    },

    /// Configuration parsing or validation failed.
    #[error("configuration error: {message}")]
    Config {
        /// What is wrong with the configuration.
        message: String,
    },

    /// A hook type was not found in the registry.
    #[error("unknown hook type: {hook_type}")]
    UnknownHook {
        /// The hook name that is not registered.
        hook_type: String,
    },
}

impl PluginError {
    /// Box this error for use in `Result<T, Box<PluginError>>`.
    ///
    /// Public APIs return `Result<T, Box<PluginError>>` rather than
    /// `Result<T, PluginError>` because the enum is large (~184 bytes
    /// — `details: HashMap` and the `source: Box<dyn Error>` push it
    /// well past clippy's `result_large_err` threshold). Boxing keeps
    /// `Result<T, _>` pointer-sized on the success path; the
    /// allocation only happens on the error path.
    ///
    /// `.boxed()` is sugar for `Box::new(...)` that reads better at
    /// construction sites: `PluginError::Config { ... }.boxed()`.
    /// `?` already calls `From::from`, and `From<T> for Box<T>` is
    /// built into std, so existing `?` chains keep working.
    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

/// A `Clone`-able, serialization-friendly snapshot of a `PluginError`.
///
/// Used in `PipelineResult.errors` to surface execution failures from
/// `on_error: ignore` / `on_error: disable` plugins to the caller —
/// previously those errors were only logged via `tracing::warn!` and
/// were invisible to programmatic consumers (agents, dashboards,
/// retry logic).
///
/// `PluginError` itself can't be `Clone` because of its
/// `Box<dyn std::error::Error + Send + Sync>` source field, and that
/// field doesn't survive serialization anyway. `PluginErrorRecord`
/// flattens the five enum variants into a single shape — the
/// `From<&PluginError>` impl handles the variant-to-fields mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginErrorRecord {
    /// The plugin that reported it, when known.
    pub plugin_name: String,
    /// Operator-facing explanation.
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Stable violation code, for callers that dispatch on category.
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    /// Extra structured context for diagnostics.
    pub details: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Protocol-level error code the host should surface, when one applies.
    pub proto_error_code: Option<i64>,
}

/// Forward `&Box<PluginError>` to the `&PluginError` impl.
///
/// Public APIs return `Result<T, Box<PluginError>>` (see
/// `PluginError::boxed`), which means error-handling code in the
/// pipeline (e.g., `Ok(Err(e))` inside `executor::run_*_phase`) holds
/// `e: Box<PluginError>`. This blanket forward keeps existing
/// `(&e).into()` call sites working without forcing every caller to
/// write `(&*e).into()` after the boxing migration.
impl From<&Box<PluginError>> for PluginErrorRecord {
    fn from(e: &Box<PluginError>) -> Self {
        PluginErrorRecord::from(e.as_ref())
    }
}

impl From<&PluginError> for PluginErrorRecord {
    fn from(e: &PluginError) -> Self {
        match e {
            PluginError::Execution {
                plugin_name,
                message,
                code,
                details,
                proto_error_code,
                ..
            } => Self {
                plugin_name: plugin_name.clone(),
                message: message.clone(),
                code: code.clone(),
                details: details.clone(),
                proto_error_code: *proto_error_code,
            },
            PluginError::Timeout {
                plugin_name,
                timeout_ms,
                proto_error_code,
            } => Self {
                plugin_name: plugin_name.clone(),
                message: format!("plugin timed out after {timeout_ms}ms"),
                code: Some("timeout".into()),
                details: HashMap::new(),
                proto_error_code: *proto_error_code,
            },
            PluginError::Violation {
                plugin_name,
                violation,
            } => Self {
                plugin_name: plugin_name.clone(),
                message: format!("plugin denied: {}", violation.reason),
                code: Some(violation.code.clone()),
                details: violation.details.clone(),
                proto_error_code: violation.proto_error_code,
            },
            PluginError::Config { message } => Self {
                plugin_name: String::new(),
                message: message.clone(),
                code: Some("config".into()),
                details: HashMap::new(),
                proto_error_code: None,
            },
            PluginError::UnknownHook { hook_type } => Self {
                plugin_name: String::new(),
                message: format!("unknown hook type: {hook_type}"),
                code: Some("unknown_hook".into()),
                details: HashMap::new(),
                proto_error_code: None,
            },
        }
    }
}

/// Structured policy violation returned by a plugin that denies execution.
///
/// Carries a machine-readable code, human-readable reason, and optional
/// diagnostic details.
///
/// # Examples
///
/// ```
/// use praxis_policy_core::error::PluginViolation;
///
/// let v = PluginViolation::new("missing_permission", "User lacks pii_access");
/// assert_eq!(v.code, "missing_permission");
/// assert_eq!(v.reason, "User lacks pii_access");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginViolation {
    /// Machine-readable violation identifier (e.g., `"missing_permission"`).
    pub code: String,

    /// Short human-readable reason for the denial.
    pub reason: String,

    /// Optional detailed explanation.
    pub description: Option<String>,

    /// Structured diagnostic data for logging or debugging.
    pub details: HashMap<String, serde_json::Value>,

    /// Name of the plugin that produced the violation.
    /// Set by the framework after the plugin returns, not by the plugin itself.
    pub plugin_name: Option<String>,

    /// Protocol-level error code for the host to map to the wire format.
    /// MCP: JSON-RPC codes (e.g., -32603). HTTP: status codes (e.g., 403).
    /// Set by the plugin; the host interprets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto_error_code: Option<i64>,
}

impl PluginViolation {
    /// Create a new violation with a code and reason.
    pub fn new(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
            description: None,
            details: HashMap::new(),
            plugin_name: None,
            proto_error_code: None,
        }
    }

    /// Attach a detailed description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Attach structured diagnostic details.
    pub fn with_details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = details;
        self
    }

    /// Attach a protocol-level error code.
    pub fn with_proto_error_code(mut self, code: i64) -> Self {
        self.proto_error_code = Some(code);
        self
    }
}

impl std::fmt::Display for PluginViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.reason)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    // `PluginErrorRecord` is what a programmatic consumer actually reads: an
    // `on_error: ignore` or `on_error: disable` plugin's failure surfaces only
    // through `PipelineResult.errors`, so a wrong field here makes a real
    // failure invisible or misattributed to the wrong plugin. The conversion had
    // no tests, and this file had no test module at all.

    fn execution() -> PluginError {
        PluginError::Execution {
            plugin_name: "jwt".into(),
            message: "signature invalid".into(),
            source: None,
            code: Some("invalid_token".into()),
            details: HashMap::from([("kid".to_owned(), serde_json::json!("abc"))]),
            proto_error_code: Some(-32_603),
        }
    }

    #[test]
    fn an_execution_error_carries_every_field_across_unchanged() {
        let rec: PluginErrorRecord = (&execution()).into();
        assert_eq!(rec.plugin_name, "jwt");
        assert_eq!(rec.message, "signature invalid");
        assert_eq!(rec.code.as_deref(), Some("invalid_token"));
        assert_eq!(rec.details.get("kid"), Some(&serde_json::json!("abc")));
        assert_eq!(rec.proto_error_code, Some(-32_603));
    }

    /// A timeout has no message of its own, so the conversion synthesizes one.
    /// The budget has to appear in it, or an operator reading the record cannot
    /// tell a slow plugin from a hung one.
    #[test]
    fn a_timeout_reports_the_budget_it_exceeded() {
        let e = PluginError::Timeout {
            plugin_name: "slow".into(),
            timeout_ms: 250,
            proto_error_code: Some(-32_000),
        };
        let rec: PluginErrorRecord = (&e).into();
        assert_eq!(rec.plugin_name, "slow");
        assert!(rec.message.contains("250"), "{}", rec.message);
        assert_eq!(rec.code.as_deref(), Some("timeout"));
        assert_eq!(rec.proto_error_code, Some(-32_000));
    }

    /// A denial is not a malfunction, and the record has to preserve the
    /// violation's own code rather than flatten it to a generic one: that code is
    /// what a caller branches on.
    #[test]
    fn a_violation_preserves_the_violation_code_and_details() {
        let violation = PluginViolation::new("role.hr_required", "not an HR user")
            .with_details(HashMap::from([(
                "required".to_owned(),
                serde_json::json!("hr"),
            )]))
            .with_proto_error_code(-32_001);
        let e = PluginError::Violation {
            plugin_name: "policy".into(),
            violation,
        };
        let rec: PluginErrorRecord = (&e).into();
        assert_eq!(rec.code.as_deref(), Some("role.hr_required"));
        assert!(rec.message.contains("not an HR user"), "{}", rec.message);
        assert_eq!(rec.details.get("required"), Some(&serde_json::json!("hr")));
        assert_eq!(rec.proto_error_code, Some(-32_001));
    }

    /// Config and unknown-hook failures are not attributable to a running
    /// plugin, so the name is empty rather than a placeholder that would read as
    /// a real plugin in a dashboard.
    #[test]
    fn config_and_unknown_hook_errors_carry_no_plugin_name() {
        let cfg: PluginErrorRecord = (&PluginError::Config {
            message: "missing token_endpoint".into(),
        })
            .into();
        assert_eq!(cfg.plugin_name, "");
        assert_eq!(cfg.code.as_deref(), Some("config"));
        assert_eq!(cfg.message, "missing token_endpoint");
        assert_eq!(cfg.proto_error_code, None);

        let unknown: PluginErrorRecord = (&PluginError::UnknownHook {
            hook_type: "cmf.not_a_hook".into(),
        })
            .into();
        assert_eq!(unknown.plugin_name, "");
        assert_eq!(unknown.code.as_deref(), Some("unknown_hook"));
        assert!(
            unknown.message.contains("cmf.not_a_hook"),
            "the message must name the hook: {}",
            unknown.message
        );
    }

    /// Errors travel boxed, so the blanket forward exists to keep `(&e).into()`
    /// working at call sites that hold a `Box`. It must produce the same record.
    #[test]
    fn converting_from_a_boxed_error_matches_the_unboxed_conversion() {
        let boxed = execution().boxed();
        let from_box: PluginErrorRecord = (&boxed).into();
        let from_ref: PluginErrorRecord = (&execution()).into();
        assert_eq!(from_box.plugin_name, from_ref.plugin_name);
        assert_eq!(from_box.message, from_ref.message);
        assert_eq!(from_box.code, from_ref.code);
        assert_eq!(from_box.proto_error_code, from_ref.proto_error_code);
    }

    #[test]
    fn a_violation_displays_its_code_and_reason() {
        let v = PluginViolation::new("pii.detected", "SSN in args");
        assert_eq!(v.to_string(), "[pii.detected] SSN in args");
    }

    #[test]
    fn a_violation_builder_sets_the_optional_fields() {
        let v = PluginViolation::new("c", "r").with_description("the long form");
        assert_eq!(v.description.as_deref(), Some("the long form"));
        // The builders are additive, so the required fields survive.
        assert_eq!(v.code, "c");
        assert_eq!(v.reason, "r");
    }
}
