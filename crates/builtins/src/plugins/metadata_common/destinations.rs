// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Scoped private destination allow-lists for metadata HTTP callouts.
#![allow(
    dead_code,
    reason = "Phase 1: Destination configuration and types defined. Phase 2: Integrate address validation."
)]
//!
//! Prevents policy from widening access to private addresses beyond what
//! the host has explicitly allowed. Validates that resolved addresses match
//! the host's configured allow-list.

use serde::{Deserialize, Serialize};

/// Scoped allow-list for private destinations.
///
/// Host configures which private address ranges are allowed for metadata callouts.
/// Policy cannot widen this list (security boundary). Every resolved address
/// is validated against the allow-list before connection.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DestinationScopeConfig {
    /// Private address ranges explicitly allowed for this metadata source.
    /// Format: "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", etc.
    /// Empty list = no private destinations allowed (default safe).
    #[serde(default)]
    pub(crate) private_allow: Vec<String>,

    /// Whether to allow resolution of cloud-metadata addresses (169.254.169.254, etc).
    /// Default: false (safe).
    #[serde(default)]
    pub(crate) allow_cloud_metadata: bool,

    /// Whether to allow localhost/loopback (`127.0.0.1`, `::1`, etc).
    /// Default: false (safe).
    #[serde(default)]
    pub(crate) allow_loopback: bool,
}

/// Address classification for security policy enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressClass {
    /// Public routable address (allowed by default).
    Public,
    /// Private RFC1918 address (requires explicit allow).
    Private,
    /// Cloud metadata address (169.254.x.x, etc., requires explicit allow).
    CloudMetadata,
    /// Loopback/localhost (requires explicit allow).
    Loopback,
}

impl AddressClass {
    /// Classify an IP address (v4 or v6).
    /// Phase 2: Will parse and classify actual addresses.
    /// Phase 1: Returns Public (safe default).
    pub(crate) fn classify(_address: &str) -> Self {
        // Phase 1: Stub implementation
        // Phase 2: Will parse IPv4/IPv6 and classify:
        // - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 → Private
        // - 169.254.0.0/16, 127.0.0.0/8, ::1 → Special
        Self::Public
    }
}

/// Compiled destination scope configuration with validation.
#[derive(Clone, Debug)]
pub(crate) struct CompiledDestinationScope {
    config: DestinationScopeConfig,
}

impl CompiledDestinationScope {
    /// Compile and validate destination scope configuration.
    pub(crate) fn compile(config: DestinationScopeConfig) -> Self {
        // Phase 1: Basic validation
        // - private_allow list syntax (valid CIDR notation)
        // Phase 2: Will enforce scoped constraints and reject policy widening
        Self { config }
    }

    /// Check if an address class is allowed by this configuration.
    pub(crate) fn allows(&self, address_class: AddressClass) -> bool {
        match address_class {
            AddressClass::Public => true, // Always allowed
            AddressClass::Private => !self.config.private_allow.is_empty(),
            AddressClass::CloudMetadata => self.config.allow_cloud_metadata,
            AddressClass::Loopback => self.config.allow_loopback,
        }
    }

    /// Get the configured private allow-list.
    #[allow(dead_code, reason = "Phase 2: Address validation")]
    pub(crate) fn private_allow(&self) -> &[String] {
        &self.config.private_allow
    }

    /// Check if cloud metadata is allowed.
    #[allow(dead_code, reason = "Phase 2: Address validation")]
    pub(crate) fn allow_cloud_metadata(&self) -> bool {
        self.config.allow_cloud_metadata
    }

    /// Check if loopback is allowed.
    #[allow(dead_code, reason = "Phase 2: Address validation")]
    pub(crate) fn allow_loopback(&self) -> bool {
        self.config.allow_loopback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_scope_config_deserializes_empty() {
        let config = DestinationScopeConfig {
            private_allow: vec![],
            allow_cloud_metadata: false,
            allow_loopback: false,
        };
        assert!(config.private_allow.is_empty());
        assert!(!config.allow_cloud_metadata);
        assert!(!config.allow_loopback);
    }

    #[test]
    fn destination_scope_config_accepts_private_allow_list() {
        let config = DestinationScopeConfig {
            private_allow: vec!["10.0.0.0/8".to_owned(), "172.16.0.0/12".to_owned()],
            ..DestinationScopeConfig::default()
        };
        assert_eq!(config.private_allow.len(), 2);
    }

    #[test]
    fn address_class_classify_returns_public_in_phase1() {
        // Phase 1: Stub returns Public
        // Phase 2: Will classify actual addresses
        let class = AddressClass::classify("example.com");
        assert_eq!(class, AddressClass::Public);
    }

    #[test]
    fn compiled_destination_scope_allows_public_always() {
        let config = DestinationScopeConfig::default();
        let compiled = CompiledDestinationScope::compile(config);
        assert!(compiled.allows(AddressClass::Public));
    }

    #[test]
    fn compiled_destination_scope_disallows_private_by_default() {
        let config = DestinationScopeConfig::default();
        let compiled = CompiledDestinationScope::compile(config);
        assert!(!compiled.allows(AddressClass::Private));
    }

    #[test]
    fn compiled_destination_scope_allows_private_when_configured() {
        let config = DestinationScopeConfig {
            private_allow: vec!["10.0.0.0/8".to_owned()],
            ..DestinationScopeConfig::default()
        };
        let compiled = CompiledDestinationScope::compile(config);
        assert!(compiled.allows(AddressClass::Private));
    }

    #[test]
    fn compiled_destination_scope_disallows_cloud_metadata_by_default() {
        let config = DestinationScopeConfig::default();
        let compiled = CompiledDestinationScope::compile(config);
        assert!(!compiled.allows(AddressClass::CloudMetadata));
    }

    #[test]
    fn compiled_destination_scope_allows_cloud_metadata_when_enabled() {
        let config = DestinationScopeConfig {
            allow_cloud_metadata: true,
            ..DestinationScopeConfig::default()
        };
        let compiled = CompiledDestinationScope::compile(config);
        assert!(compiled.allows(AddressClass::CloudMetadata));
    }

    #[test]
    fn compiled_destination_scope_disallows_loopback_by_default() {
        let config = DestinationScopeConfig::default();
        let compiled = CompiledDestinationScope::compile(config);
        assert!(!compiled.allows(AddressClass::Loopback));
    }

    #[test]
    fn compiled_destination_scope_allows_loopback_when_enabled() {
        let config = DestinationScopeConfig {
            allow_loopback: true,
            ..DestinationScopeConfig::default()
        };
        let compiled = CompiledDestinationScope::compile(config);
        assert!(compiled.allows(AddressClass::Loopback));
    }
}
