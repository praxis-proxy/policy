// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Build-time errors for `CelResolver`. These fire at construction
// (parsing the unified-config block or registering host functions);
// never at request time.
//
// Request-time problems (a bad `expr`, an undeclared variable, a
// non-boolean result) flow through `praxis_policy_apl_core::PdpError` / a fail-closed
// `PdpDecision::Deny` because that's the trait's return surface —
// deliberately separate from build errors, which are config faults the
// operator fixes once.
//
// `BuildError` implements `std::error::Error` (via thiserror), so it
// boxes cleanly into `praxis_policy_apl_runtime::visitor::VisitorError` when the
// AplConfigVisitor builds a resolver from a unified-config block. The
// visitor wraps that into `praxis_policy_core::PluginError::Config` on its way out
// of `load_config_yaml`.

use thiserror::Error;

/// Error returned at resolver construction.
#[derive(Debug, Error)]
pub enum BuildError {
    /// Config block wasn't a mapping, or a field had the wrong shape /
    /// an unrecognized value (e.g. `on_error: maybe`).
    #[error("invalid CEL PDP config: {0}")]
    ConfigShape(String),
    /// A host function conflicts with an overload in the CEL environment.
    #[error("invalid CEL function registration: {0}")]
    FunctionRegistration(#[from] cel::DeclarationError),
}
