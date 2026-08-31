// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The response protocol floor: the headers a `strip:` entry can never remove.
//
// The response direction is a denylist, so a greedy glob is the way a client
// breaks. The floor holds what a client needs in order to interpret the
// response at all, and a config whose glob would reach one of these names
// fails to load rather than removing it in production.
//
// Same shape as the excluded-source set and the opposite polarity: an
// enumerated list with a reason per entry, so adding a name is a visible
// change with a stated justification rather than a silent widening.

use crate::config::Pattern;

/// One floor header and why a client needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorEntry {
    /// The header name, lowercase.
    pub name: &'static str,

    /// Why removing it breaks a client.
    pub reason: &'static str,
}

/// The response headers no `strip:` entry can remove.
///
/// Deliberately absent: `set-cookie`, because removing one issued on the
/// gateway's own domain is a stated use case, and `server` / `x-powered-by`,
/// which are banners an operator should be able to strip. Nothing
/// vendor-specific belongs here either.
pub const RESPONSE_FLOOR: &[FloorEntry] = &[
    FloorEntry {
        name: "content-type",
        reason: "the client cannot parse a body whose media type it does not know",
    },
    FloorEntry {
        name: "content-length",
        reason: "framing: a client reading a fixed-length body needs the length",
    },
    FloorEntry {
        name: "content-encoding",
        reason: "a compressed body decodes to nothing readable without it",
    },
    FloorEntry {
        name: "transfer-encoding",
        reason: "framing: a chunked body cannot be read as a whole",
    },
    FloorEntry {
        name: "cache-control",
        reason: "removing it leaves caching to a client's default, which is not the origin's call",
    },
    FloorEntry {
        name: "etag",
        reason: "a conditional request has no validator to send",
    },
    FloorEntry {
        name: "last-modified",
        reason: "the other validator a conditional request sends",
    },
    FloorEntry {
        name: "expires",
        reason: "freshness for a client that reads no cache-control",
    },
    FloorEntry {
        name: "vary",
        reason: "a cache without it serves one representation for every request",
    },
    FloorEntry {
        name: "retry-after",
        reason: "a client told to back off cannot tell for how long",
    },
    FloorEntry {
        name: "access-control-allow-origin",
        reason: "a browser client fails the request silently without the CORS set",
    },
    FloorEntry {
        name: "access-control-allow-credentials",
        reason: "a credentialed cross-origin request is rejected by the browser",
    },
    FloorEntry {
        name: "access-control-allow-methods",
        reason: "a preflight answer a browser cannot act on",
    },
    FloorEntry {
        name: "access-control-allow-headers",
        reason: "a preflight answer a browser cannot act on",
    },
    FloorEntry {
        name: "access-control-expose-headers",
        reason: "a client's script cannot read the response headers it was meant to",
    },
    FloorEntry {
        name: "access-control-max-age",
        reason: "a browser re-preflights every request without it",
    },
];

/// Whether a header name is in the floor, compared case-insensitively.
#[must_use]
pub fn is_floor(name: &str) -> bool {
    let lower = name.to_lowercase();
    RESPONSE_FLOOR.iter().any(|entry| entry.name == lower)
}

/// The floor, for a validation error and for the effective-policy artifact.
#[must_use]
pub fn floor_names() -> &'static [FloorEntry] {
    RESPONSE_FLOOR
}

/// The first floor header a `strip:` pattern would remove, or `None` when it
/// reaches none of them.
///
/// Matched with the dialect the removal itself uses, so the load-time check
/// cannot be looser than what happens at request time.
#[must_use]
pub fn glob_would_match_floor(pattern: &str) -> Option<&'static str> {
    let matcher = Pattern::new(pattern.to_lowercase());
    RESPONSE_FLOOR
        .iter()
        .find(|entry| matcher.matches(entry.name))
        .map(|entry| entry.name)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn every_floor_name_matches_case_insensitively() {
        for entry in RESPONSE_FLOOR {
            assert!(is_floor(entry.name), "{}", entry.name);
            assert!(is_floor(&entry.name.to_uppercase()), "{}", entry.name);
        }
    }

    #[test]
    fn a_glob_reaching_a_floor_header_names_it() {
        assert_eq!(glob_would_match_floor("content-*"), Some("content-type"));
        assert_eq!(glob_would_match_floor("etag"), Some("etag"));
        assert_eq!(glob_would_match_floor("ETag"), Some("etag"));
        assert_eq!(
            glob_would_match_floor("access-control-*"),
            Some("access-control-allow-origin")
        );
        assert_eq!(glob_would_match_floor("*"), Some("content-type"));
    }

    #[test]
    fn a_glob_reaching_nothing_in_the_floor_is_allowed() {
        for pattern in ["x-backend-*", "server", "x-debug-*", "x-auth-*"] {
            assert_eq!(glob_would_match_floor(pattern), None, "{pattern}");
        }
    }

    /// Removing these is a stated use case, so they are outside the floor.
    #[test]
    fn the_strippable_headers_are_not_in_the_floor() {
        for name in ["set-cookie", "server", "x-powered-by"] {
            assert!(!is_floor(name), "{name}");
            assert_eq!(glob_would_match_floor(name), None, "{name}");
        }
    }

    /// An addition cannot land undocumented.
    #[test]
    fn every_floor_entry_carries_a_reason() {
        for entry in RESPONSE_FLOOR {
            assert!(!entry.name.is_empty());
            assert!(!entry.reason.is_empty(), "{} has no reason", entry.name);
            assert_eq!(
                entry.name,
                entry.name.to_lowercase(),
                "floor names are lowercase so a comparison needs one case fold"
            );
        }
    }

    #[test]
    fn a_name_is_listed_once() {
        for (i, entry) in RESPONSE_FLOOR.iter().enumerate() {
            assert!(
                !RESPONSE_FLOOR
                    .iter()
                    .take(i)
                    .any(|seen| seen.name == entry.name),
                "{} is listed twice",
                entry.name
            );
        }
    }
}
