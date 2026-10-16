// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use praxis_policy_core::cmf::Role;
use serde::{Deserialize, Serialize};

/// Plugin config — what operators write under
/// `plugins[<name>].config:` in unified-config YAML.
///
/// Unknown keys are refused: a misspelled `roles` would otherwise widen the
/// scan silently, and a misspelled `patterns` would be caught only because the
/// list is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptScannerConfig {
    /// Patterns to test history against. Must not be empty.
    pub patterns: Vec<TranscriptPattern>,

    /// Roles whose turns are scanned. Empty scans every role.
    #[serde(default)]
    pub roles: Vec<Role>,
}

/// One named pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptPattern {
    /// Name reported in the violation when this pattern matches.
    pub name: String,
    /// The regular expression to test each string against.
    pub regex: String,
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_full_config() {
        let cfg: TranscriptScannerConfig = serde_json::from_value(json!({
            "patterns": [{ "name": "api_key", "regex": "sk-[A-Za-z0-9]{8,}" }],
            "roles": ["user", "tool"],
        }))
        .unwrap();
        assert_eq!(cfg.patterns.len(), 1);
        assert_eq!(cfg.patterns[0].name, "api_key");
        assert_eq!(cfg.roles, vec![Role::User, Role::Tool]);
    }

    #[test]
    fn roles_default_to_every_role() {
        let cfg: TranscriptScannerConfig = serde_json::from_value(json!({
            "patterns": [{ "name": "x", "regex": "x" }],
        }))
        .unwrap();
        assert!(cfg.roles.is_empty());
    }

    #[test]
    fn a_misspelled_key_is_refused() {
        let err = serde_json::from_value::<TranscriptScannerConfig>(json!({
            "patterns": [{ "name": "x", "regex": "x" }],
            "role": ["user"],
        }));
        assert!(err.is_err(), "`role` is not `roles`");
    }
}
