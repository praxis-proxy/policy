// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Hook type definitions.
//
// Hook types are open strings — hosts define hook points appropriate
// to their execution lifecycle. This module provides a newtype wrapper
// for type safety and built-in constants for the common hook points.
//
// The framework does not prescribe a fixed set of hook points. Each
// host places `invoke_hook()` calls at sites appropriate to its
// processing pipeline. The names PPE itself dispatches live with the
// modules that own them, declared by `define_hooks!`; the enumerations
// here are projections over the table those declarations build.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A named hook point in the host's execution lifecycle.
///
/// Wraps a string identifier. Hook types are open — hosts register
/// their own alongside the built-in constants.
///
/// # Examples
///
/// ```
/// use praxis_policy_core::cmf::constants::HOOK_CMF_TOOL_PRE_INVOKE;
/// use praxis_policy_core::hooks::HookType;
///
/// // Use a dispatched hook's name constant
/// let hook = HookType::new(HOOK_CMF_TOOL_PRE_INVOKE);
/// assert_eq!(hook.as_str(), "cmf.tool_pre_invoke");
///
/// // Define a custom hook
/// let custom = HookType::new("generation_pre_call");
/// assert_eq!(custom.as_str(), "generation_pre_call");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HookType(String);

impl HookType {
    /// Create a new hook type from a string.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Return the hook type as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for HookType {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for HookType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Returns all built-in hook types, projected from the hook metadata
/// table.
///
/// Derived rather than written out: a hand-maintained copy drifted from
/// the table for months, and because nothing read it there was nothing
/// to fail. Adding a hook to the authority extends this with no second
/// edit.
pub fn builtin_hook_types() -> Vec<HookType> {
    crate::hooks::metadata::BUILTIN_METADATA
        .iter()
        .map(|(name, _)| HookType::new(*name))
        .collect()
}

/// Look up a hook type by name. Returns the canonical instance if
/// it matches a built-in, otherwise creates a new custom `HookType`.
pub fn hook_type_from_str(name: &str) -> HookType {
    crate::hooks::metadata::BUILTIN_METADATA
        .iter()
        .find(|(builtin, _)| *builtin == name)
        .map_or_else(
            || HookType::new(name),
            |(builtin, _)| HookType::new(*builtin),
        )
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

    #[test]
    fn test_hook_type_equality() {
        let a = HookType::new("cmf.tool_pre_invoke");
        let b = HookType::new("cmf.tool_pre_invoke");
        assert_eq!(a, b);
    }

    #[test]
    fn test_hook_type_display() {
        let h = HookType::new("cmf.llm_input");
        assert_eq!(h.to_string(), "cmf.llm_input");
    }

    #[test]
    fn test_hook_type_from_str() {
        let h: HookType = "custom_hook".into();
        assert_eq!(h.as_str(), "custom_hook");
    }

    #[test]
    fn the_enumeration_is_the_authoritys_key_set() {
        let derived: Vec<String> = builtin_hook_types()
            .iter()
            .map(|h| h.as_str().to_owned())
            .collect();
        let authority: Vec<String> = crate::hooks::metadata::BUILTIN_METADATA
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        assert_eq!(derived, authority);
    }

    #[test]
    fn adding_a_row_to_the_authority_needs_no_second_edit() {
        // The enumeration is a projection, so its length is the table's.
        // No count is restated here; a new row shows up on its own.
        assert_eq!(
            builtin_hook_types().len(),
            crate::hooks::metadata::BUILTIN_METADATA.len(),
        );
    }

    #[test]
    fn hook_type_from_str_is_canonical_for_a_builtin_and_custom_otherwise() {
        let builtin = crate::cmf::constants::HOOK_CMF_TOOL_PRE_INVOKE;
        assert_eq!(hook_type_from_str(builtin).as_str(), builtin);
        assert_eq!(
            hook_type_from_str("host.custom_hook").as_str(),
            "host.custom_hook",
        );
    }
}
