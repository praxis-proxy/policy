// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Which IP addresses an outbound policy call must not reach.
//
// A URL in policy config — a `jwks_url`, a token endpoint — is a
// destination the engine fetches on an operator's behalf. That makes it
// a server-side request forgery primitive whenever anyone who is not the
// operator can influence it: a multi-tenant deployment where tenants
// supply their own IdP, a config store someone else can write, a
// config-injection bug. The gateway sits inside the perimeter, so it can
// reach what the requester cannot — cloud metadata at 169.254.169.254
// hands out credentials to anything on the instance, and an internal
// admin API usually assumes the network is the authentication.
//
// This module is only the *table*. It performs no I/O and knows nothing
// about sockets, because `praxis-policy-core` never opens one: a
// transport enforces the policy where it dials.
//
// Sharing the table is the point. Three transports would otherwise each
// write their own range list and drift, and the ranges are exactly the
// kind of thing that looks finished while missing an entry. `100.64/10`
// is routinely forgotten, and an IPv4-mapped IPv6 address is the same
// address wearing a hat — `::ffff:169.254.169.254` reaches metadata
// through a check that only looked at `Ipv6Addr` variants.
//
// # Enforcing this correctly
//
// Check the address you are about to *connect to*, never one resolved
// earlier. DNS can answer differently the second time, which is the
// whole of DNS rebinding: the validating lookup returns a public
// address, the connecting lookup returns 169.254.169.254. For hyper that
// means filtering inside a custom `Resolve` rather than pre-checking a
// URL; for any transport it means the check sits next to the socket.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an address is not a legitimate public destination, or `None` when
/// it is one.
///
/// The reason exists so a refusal can name the rule it broke. An operator
/// who pointed a `jwks_url` at their own Keycloak needs to read "private
/// address" and reach for the escape hatch, not stare at a generic denial.
pub fn private_address_reason(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => v4_reason(v4),
        IpAddr::V6(v6) => v6_reason(v6),
    }
}

/// Whether `ip` is private, reserved, or otherwise not a public
/// destination.
///
/// See [`private_address_reason`] when the caller wants to say why.
pub fn is_private_address(ip: &IpAddr) -> bool {
    private_address_reason(ip).is_some()
}

fn v4_reason(ip: &Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = ip.octets();
    // Ordered roughly by how often each actually turns up in an attack,
    // so the common cases exit early.
    if ip.is_loopback() {
        return Some("loopback address (127.0.0.0/8)");
    }
    if ip.is_link_local() {
        // 169.254.0.0/16. The cloud metadata endpoint lives here, which
        // makes it the single most valuable address on this list.
        return Some("link-local address (169.254.0.0/16), which includes cloud metadata");
    }
    if ip.is_private() {
        return Some("private address (RFC 1918)");
    }
    if a == 100 && (64..128).contains(&b) {
        // Carrier-grade NAT, RFC 6598. Routinely omitted from
        // hand-written range lists, and routable inside a provider
        // network.
        return Some("shared address space (100.64.0.0/10)");
    }
    if ip.is_unspecified() || a == 0 {
        return Some("unspecified address (0.0.0.0/8)");
    }
    if ip.is_broadcast() {
        return Some("broadcast address");
    }
    if ip.is_multicast() {
        return Some("multicast address (224.0.0.0/4)");
    }
    if a >= 240 {
        return Some("reserved address (240.0.0.0/4)");
    }
    if a == 192 && b == 0 && c == 0 {
        return Some("IETF protocol assignment (192.0.0.0/24)");
    }
    if a == 198 && (b == 18 || b == 19) {
        return Some("benchmarking range (198.18.0.0/15)");
    }
    if ip.is_documentation() {
        return Some("documentation range");
    }
    None
}

fn v6_reason(ip: &Ipv6Addr) -> Option<&'static str> {
    // Unwrap the embedded-IPv4 forms first. An address that carries a v4
    // address inside it reaches the same host, so judging it by its v6
    // shape alone is how `::ffff:169.254.169.254` gets through.
    if let Some(v4) = embedded_v4(ip) {
        // Judged by the address it actually reaches, not by its v6
        // shape. Refusing every mapped form outright would be simpler
        // and wrong: a dual-stack resolver hands back `::ffff:8.8.8.8`
        // for an ordinary public host.
        return v4_reason(&v4);
    }

    let segments = ip.segments();
    if ip.is_loopback() {
        return Some("loopback address (::1)");
    }
    if ip.is_unspecified() {
        return Some("unspecified address (::)");
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Some("unique local address (fc00::/7)");
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some("link-local address (fe80::/10)");
    }
    if ip.is_multicast() {
        return Some("multicast address (ff00::/8)");
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some("documentation range (2001:db8::/32)");
    }
    None
}

/// The IPv4 address inside an IPv6 one, for every form that carries one.
///
/// Covers IPv4-mapped (`::ffff:a.b.c.d`), the deprecated IPv4-compatible
/// form (`::a.b.c.d`), and the NAT64 well-known prefix
/// (`64:ff9b::a.b.c.d`) — that last one matters because a NAT64 gateway
/// will happily forward to a private v4 address, so ignoring it leaves
/// the guard open on any network that runs one.
fn embedded_v4(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new(
        (s[6] >> 8) as u8,
        (s[6] & 0xff) as u8,
        (s[7] >> 8) as u8,
        (s[7] & 0xff) as u8,
    );

    // ::ffff:0:0/96 — IPv4-mapped.
    if s[0..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return Some(tail);
    }
    // 64:ff9b::/96 — NAT64 well-known prefix.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(tail);
    }
    // ::/96 — deprecated IPv4-compatible. `::` and `::1` are handled by
    // their own rules, so exclude them here rather than reporting them
    // as embedded v4.
    if s[0..6] == [0, 0, 0, 0, 0, 0] && !(s[6] == 0 && (s[7] == 0 || s[7] == 1)) {
        return Some(tail);
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("a valid address")
    }

    #[test]
    fn the_metadata_endpoint_is_refused() {
        // The single most valuable address on the list: it serves IAM
        // credentials to anything on the instance, with no
        // authentication, on the theory that being on the box is proof
        // enough.
        let reason = private_address_reason(&ip("169.254.169.254")).expect("must be refused");
        assert!(reason.contains("metadata"), "{reason}");
    }

    #[test]
    fn the_usual_private_ranges_are_refused() {
        for addr in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.1",
            "172.31.255.255",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            assert!(
                is_private_address(&ip(addr)),
                "{addr} must not be a public destination"
            );
        }
    }

    #[test]
    fn carrier_grade_nat_is_refused() {
        // 100.64.0.0/10. Routinely missing from hand-written lists, and
        // routable inside a provider network — which is exactly where a
        // gateway tends to run.
        assert!(is_private_address(&ip("100.64.0.1")));
        assert!(is_private_address(&ip("100.127.255.255")));
        // The boundaries: 100.63.x and 100.128.x are ordinary public
        // space and must not be swept up.
        assert!(!is_private_address(&ip("100.63.255.255")));
        assert!(!is_private_address(&ip("100.128.0.0")));
    }

    #[test]
    fn an_ipv4_address_wearing_an_ipv6_hat_is_still_refused() {
        // The check a naive guard misses: judging by the v6 shape alone
        // lets every mapped form straight through to the same host.
        for addr in [
            "::ffff:169.254.169.254", // IPv4-mapped
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::169.254.169.254", // NAT64 well-known prefix
            "::169.254.169.254",        // deprecated IPv4-compatible
        ] {
            assert!(
                is_private_address(&ip(addr)),
                "{addr} reaches the same host as its embedded IPv4 address"
            );
        }
    }

    #[test]
    fn ipv6_private_ranges_are_refused() {
        for addr in ["::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1"] {
            assert!(is_private_address(&ip(addr)), "{addr} must be refused");
        }
    }

    #[test]
    fn ordinary_public_addresses_pass() {
        // The other half of the contract. A guard that refuses
        // everything is not a guard, it is an outage — and an IdP on a
        // public address is the ordinary case.
        for addr in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(
                !is_private_address(&ip(addr)),
                "{addr} is a legitimate public destination"
            );
        }
    }

    #[test]
    fn a_mapped_public_address_still_passes() {
        // The complement of the mapped-address test: unwrapping must not
        // turn a public destination into a refusal.
        assert!(!is_private_address(&ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn the_reason_names_the_rule_that_was_broken() {
        // An operator who pointed a jwks_url at their own Keycloak needs
        // to read "private address" and reach for the escape hatch,
        // rather than staring at a generic denial.
        assert!(
            private_address_reason(&ip("10.1.2.3"))
                .expect("refused")
                .contains("private"),
        );
        assert!(
            private_address_reason(&ip("127.0.0.1"))
                .expect("refused")
                .contains("loopback"),
        );
        assert_eq!(private_address_reason(&ip("8.8.8.8")), None);
    }
}
