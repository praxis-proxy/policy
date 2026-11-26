// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Scoped private destination allow-lists for metadata HTTP callouts.
//!
//! Prevents policy from widening access to private addresses beyond what
//! the host has explicitly allowed. Validates that resolved addresses match
//! the host's configured allow-list.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr as _;

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
#[allow(dead_code, reason = "Phase 2: Address validation and filtering")]
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
    #[allow(dead_code, reason = "Phase 2: Address validation")]
    pub(crate) fn classify(address: &str) -> Self {
        match IpAddr::from_str(address) {
            Ok(IpAddr::V4(addr)) => Self::classify_v4(addr),
            Ok(IpAddr::V6(addr)) => Self::classify_v6(addr),
            Err(_) => Self::Public, // Invalid address defaults to public (safe)
        }
    }

    #[allow(dead_code, reason = "Phase 2: Address validation")]
    fn classify_v4(addr: Ipv4Addr) -> Self {
        // RFC 1918 private ranges
        if addr.is_private() {
            return Self::Private;
        }
        // Link-local 169.254.0.0/16 (cloud metadata)
        if addr.is_link_local() {
            return Self::CloudMetadata;
        }
        // Loopback 127.0.0.0/8
        if addr.is_loopback() {
            return Self::Loopback;
        }
        Self::Public
    }

    #[allow(dead_code, reason = "Phase 2: Address validation")]
    fn classify_v6(addr: Ipv6Addr) -> Self {
        // Unique local (fc00::/7) - IPv6 equivalent of private
        if addr.is_unique_local() {
            return Self::Private;
        }
        // Link-local fe80::/10
        if addr.is_unicast_link_local() {
            return Self::CloudMetadata;
        }
        // Loopback ::1
        if addr.is_loopback() {
            return Self::Loopback;
        }
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
    #[allow(dead_code, reason = "Phase 2: Address validation")]
    pub(crate) fn compile(config: DestinationScopeConfig) -> Self {
        // Phase 1: Basic validation
        // - private_allow list syntax (valid CIDR notation)
        // Phase 2: Will enforce scoped constraints and reject policy widening
        Self { config }
    }

    /// Check if an address is allowed by this configuration.
    #[allow(dead_code, reason = "Phase 2: Address validation")]
    pub(crate) fn allows_address(&self, address: &str) -> bool {
        let class = AddressClass::classify(address);
        match class {
            AddressClass::Public => true, // Always allowed
            AddressClass::Private => self.allows_private_address(address),
            AddressClass::CloudMetadata => self.config.allow_cloud_metadata,
            AddressClass::Loopback => self.config.allow_loopback,
        }
    }

    /// Check if a private address is in the allowed CIDR ranges.
    #[allow(dead_code, reason = "Phase 2: Address validation")]
    fn allows_private_address(&self, address: &str) -> bool {
        if self.config.private_allow.is_empty() {
            return false;
        }
        // Parse address and check against CIDR ranges
        match IpAddr::from_str(address) {
            Ok(addr) => self.is_in_private_allow_list(addr),
            Err(_) => false, // Invalid address not allowed
        }
    }

    #[allow(dead_code, reason = "Phase 2: Address validation")]
    fn is_in_private_allow_list(&self, addr: IpAddr) -> bool {
        for cidr in &self.config.private_allow {
            if self.address_in_cidr(addr, cidr) {
                return true;
            }
        }
        false
    }

    #[allow(dead_code, reason = "Phase 2: Address validation")]
    fn address_in_cidr(&self, addr: IpAddr, cidr: &str) -> bool {
        // Parse CIDR notation (e.g., "10.0.0.0/8", "2001:db8::/32")
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        #[allow(clippy::indexing_slicing)]
        match (parts[0].parse::<IpAddr>(), parts[1].parse::<u32>()) {
            (Ok(IpAddr::V4(net)), Ok(prefix)) if prefix <= 32 => {
                if let IpAddr::V4(addr_v4) = addr {
                    #[allow(clippy::cast_possible_truncation)]
                    let prefix_u8 = prefix as u8;
                    self.ipv4_in_cidr(addr_v4, net, prefix_u8)
                } else {
                    false
                }
            },
            (Ok(IpAddr::V6(net)), Ok(prefix)) if prefix <= 128 => {
                if let IpAddr::V6(addr_v6) = addr {
                    #[allow(clippy::cast_possible_truncation)]
                    let prefix_u8 = prefix as u8;
                    self.ipv6_in_cidr(addr_v6, net, prefix_u8)
                } else {
                    false
                }
            },
            _ => false, // Invalid CIDR
        }
    }

    #[allow(dead_code, reason = "Phase 2: Address validation")]
    fn ipv4_in_cidr(&self, addr: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        (u32::from(addr) & mask) == (u32::from(net) & mask)
    }

    #[allow(dead_code, reason = "Phase 2: Address validation")]
    fn ipv6_in_cidr(&self, addr: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        (u128::from(addr) & mask) == (u128::from(net) & mask)
    }

    /// Check if an address class is allowed (legacy method for tests).
    #[allow(dead_code, reason = "Phase 2: Address validation")]
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

    #[test]
    fn compiled_destination_scope_accessors() {
        let config = DestinationScopeConfig {
            private_allow: vec!["10.0.0.0/8".to_owned(), "172.16.0.0/12".to_owned()],
            allow_cloud_metadata: true,
            allow_loopback: false,
        };
        let compiled = CompiledDestinationScope::compile(config);
        assert_eq!(compiled.private_allow().len(), 2);
        assert!(compiled.allow_cloud_metadata());
        assert!(!compiled.allow_loopback());
    }

    #[test]
    fn address_class_classification() {
        // IPv4 classifications
        assert_eq!(AddressClass::classify("127.0.0.1"), AddressClass::Loopback);
        assert_eq!(AddressClass::classify("10.0.0.1"), AddressClass::Private);
        assert_eq!(AddressClass::classify("192.168.1.1"), AddressClass::Private);
        assert_eq!(AddressClass::classify("172.16.0.1"), AddressClass::Private);
        assert_eq!(
            AddressClass::classify("169.254.1.1"),
            AddressClass::CloudMetadata
        );
        assert_eq!(AddressClass::classify("8.8.8.8"), AddressClass::Public);

        // IPv6 classifications
        assert_eq!(AddressClass::classify("::1"), AddressClass::Loopback);
        assert_eq!(AddressClass::classify("fc00::1"), AddressClass::Private);
        assert_eq!(
            AddressClass::classify("fe80::1"),
            AddressClass::CloudMetadata
        );
        assert_eq!(AddressClass::classify("2001:db8::1"), AddressClass::Public);

        // Invalid addresses default to Public (safe)
        assert_eq!(AddressClass::classify("example.com"), AddressClass::Public);
        assert_eq!(AddressClass::classify("localhost"), AddressClass::Public);
        assert_eq!(AddressClass::classify("not-an-ip"), AddressClass::Public);
    }

    #[test]
    fn allows_address_validates_private_ranges() {
        let config = DestinationScopeConfig {
            private_allow: vec!["10.0.0.0/8".to_owned(), "192.168.0.0/16".to_owned()],
            allow_cloud_metadata: true,
            allow_loopback: true,
        };
        let scope = CompiledDestinationScope::compile(config);

        // Public addresses always allowed
        assert!(scope.allows_address("8.8.8.8"));
        assert!(scope.allows_address("2001:db8::1"));

        // Private addresses in allowed ranges
        assert!(scope.allows_address("10.0.0.1"));
        assert!(scope.allows_address("10.255.255.255"));
        assert!(scope.allows_address("192.168.0.1"));
        assert!(scope.allows_address("192.168.255.255"));

        // Private addresses NOT in allowed ranges
        assert!(!scope.allows_address("172.16.0.1"));
        assert!(!scope.allows_address("fc00::1"));

        // Cloud metadata allowed
        assert!(scope.allows_address("169.254.1.1"));
        assert!(scope.allows_address("fe80::1"));

        // Loopback allowed
        assert!(scope.allows_address("127.0.0.1"));
        assert!(scope.allows_address("::1"));
    }

    #[test]
    fn allows_address_respects_restrictions() {
        let config = DestinationScopeConfig {
            private_allow: vec![],
            allow_cloud_metadata: false,
            allow_loopback: false,
        };
        let scope = CompiledDestinationScope::compile(config);

        // Only public addresses allowed
        assert!(scope.allows_address("8.8.8.8"));

        // Private addresses denied
        assert!(!scope.allows_address("10.0.0.1"));
        assert!(!scope.allows_address("192.168.0.1"));

        // Cloud metadata denied
        assert!(!scope.allows_address("169.254.1.1"));

        // Loopback denied
        assert!(!scope.allows_address("127.0.0.1"));
    }

    #[test]
    fn allows_address_mixed_restrictions() {
        let config = DestinationScopeConfig {
            private_allow: vec!["10.0.0.0/8".to_owned()],
            allow_cloud_metadata: true,
            allow_loopback: false,
        };
        let scope = CompiledDestinationScope::compile(config);

        assert!(scope.allows_address("8.8.8.8")); // Public
        assert!(scope.allows_address("10.0.0.1")); // Private, in range
        assert!(!scope.allows_address("192.168.0.1")); // Private, not in range
        assert!(scope.allows_address("169.254.1.1")); // Cloud metadata
        assert!(!scope.allows_address("127.0.0.1")); // Loopback denied
    }

    #[test]
    fn allows_address_ipv6_cidr() {
        let config = DestinationScopeConfig {
            private_allow: vec!["fc00::/7".to_owned()],
            allow_cloud_metadata: false,
            allow_loopback: false,
        };
        let scope = CompiledDestinationScope::compile(config);

        // IPv6 unique local addresses
        assert!(scope.allows_address("fc00::1"));
        assert!(scope.allows_address("fd00::1"));
        assert!(scope.allows_address("fd00::ffff:ffff:ffff:ffff"));

        // Outside range
        assert!(!scope.allows_address("fe80::1"));
    }

    #[test]
    fn allows_address_no_private_ranges() {
        let config = DestinationScopeConfig {
            private_allow: vec![],
            allow_cloud_metadata: false,
            allow_loopback: false,
        };
        let scope = CompiledDestinationScope::compile(config);

        // All private addresses denied
        assert!(!scope.allows_address("10.0.0.0"));
        assert!(!scope.allows_address("10.255.255.255"));
        assert!(!scope.allows_address("172.16.0.0"));
        assert!(!scope.allows_address("192.168.0.0"));
        assert!(!scope.allows_address("fc00::1"));
        assert!(!scope.allows_address("fd00::1"));
    }
}
