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
    crate::hooks::metadata::BUILTIN_HOOK_METADATA
        .iter()
        .map(|(name, _)| HookType::new(*name))
        .collect()
}

/// Wrap a hook name, built-in or custom, in a [`HookType`].
///
/// `HookType` owns its string and compares by value, so a built-in name and
/// a custom one produce equivalent values and there is nothing to canonicalize.
/// An earlier version scanned the metadata table to return "the canonical
/// instance", which allocated the same string either way; validating the name
/// is [`crate::config`]'s job, not this function's.
pub fn hook_type_from_str(name: &str) -> HookType {
    HookType::new(name)
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
    fn the_enumeration_names_the_hooks_that_dispatch() {
        // Anchored on names, not on the table's own length or key order:
        // comparing a projection to the thing it projects cannot fail. Every
        // name here was wrong in the hand-maintained list this replaced, so
        // the old list would fail this test.
        let derived: Vec<String> = builtin_hook_types()
            .iter()
            .map(|h| h.as_str().to_owned())
            .collect();
        let has = |name: &str| derived.iter().any(|d| d == name);
        for expected in [
            // Absent from the old list entirely.
            "cmf.http_request",
            "cmf.http_response",
            "elicit",
            // The old list spelled the prompt pair `_fetch`.
            "cmf.prompt_pre_invoke",
            "cmf.prompt_post_invoke",
            // The old list spelled these with underscores.
            "identity.resolve",
            "token.delegate",
        ] {
            assert!(has(expected), "{expected} is not enumerated");
        }
        for gone in [
            "tool_pre_invoke",
            "identity_resolve",
            "cmf.prompt_pre_fetch",
            "cmf.prompt_post_fetch",
        ] {
            assert!(!has(gone), "{gone} is still enumerated");
        }
    }

    #[test]
    fn every_enumerated_hook_resolves_in_the_registry() {
        // The projection and the registry are both fed by the table, so a
        // name that enumerates but does not resolve means one of the two
        // stopped reading it.
        for hook in builtin_hook_types() {
            assert!(
                crate::hooks::lookup_hook_metadata(hook.as_str()).is_some(),
                "{hook} is enumerated but absent from the registry",
            );
        }
    }

    #[test]
    fn hook_type_from_str_wraps_builtin_and_custom_names_alike() {
        let builtin = crate::cmf::constants::HOOK_CMF_TOOL_PRE_INVOKE;
        assert_eq!(hook_type_from_str(builtin).as_str(), builtin);
        assert_eq!(
            hook_type_from_str("host.custom_hook").as_str(),
            "host.custom_hook",
        );
    }
}
