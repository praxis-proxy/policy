// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The protocol floors: the headers a `strip:` entry can never remove, one set
// per direction.
//
// `strip:` is a denylist in both directions, so a greedy glob is the way the
// other side breaks. It removes headers the engine did not originate and cannot
// enumerate, which is the whole argument for a floor, and that argument does not
// care which way the traffic is going. Each floor holds what its recipient needs
// in order to interpret the message at all, and a config whose glob would reach
// one of those names fails to load rather than removing it in production.
//
// The two lists differ because the recipients differ, not because one direction
// is trusted. The request floor is short: an upstream needs framing and the
// authority it was addressed under, and nothing else here is the engine's to
// guess. The response floor is long because a client's caching, validation and
// CORS behaviour all hang off headers the origin chose.
//
// Same shape as the excluded-source set and the opposite polarity: an
// enumerated list with a reason per entry, so adding a name is a visible
// change with a stated justification rather than a silent widening.

use crate::assertions::Direction;
use crate::config::Pattern;

/// One floor header and why its recipient needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorEntry {
    /// The header name, lowercase.
    pub name: &'static str,

    /// Why removing it breaks the side that receives the message: the upstream
    /// for a request entry, the client for a response one.
    pub reason: &'static str,
}

/// The request headers no `strip:` entry can remove.
///
/// Deliberately absent: `authorization`. Removing the client's own bearer
/// before forwarding to an upstream that runs on a delegated credential is a
/// stated use case, so it sits outside this floor the way `set-cookie` sits
/// outside the response one. Also absent are `cookie`, `accept` and the rest of
/// what a client sends about itself: an operator withholding those from an
/// upstream is making a policy choice, not breaking the protocol.
pub const REQUEST_FLOOR: &[FloorEntry] = &[
    FloorEntry {
        name: "host",
        reason: "the upstream cannot tell which authority the request was addressed to",
    },
    FloorEntry {
        name: "content-type",
        reason: "the upstream cannot parse a body whose media type it does not know",
    },
    FloorEntry {
        name: "content-length",
        reason: "framing: an upstream reading a fixed-length body needs the length",
    },
    FloorEntry {
        name: "transfer-encoding",
        reason: "framing: a chunked body cannot be read as a whole",
    },
];

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

/// One direction's floor, for a validation error and for the
/// effective-policy artifact.
#[must_use]
pub fn floor_for(direction: Direction) -> &'static [FloorEntry] {
    match direction {
        Direction::Request => REQUEST_FLOOR,
        Direction::Response => RESPONSE_FLOOR,
    }
}

/// Whether a header name is in one direction's floor, compared
/// case-insensitively.
#[must_use]
pub fn is_floor(direction: Direction, name: &str) -> bool {
    let lower = name.to_lowercase();
    floor_for(direction).iter().any(|entry| entry.name == lower)
}

/// The first floor header a `strip:` pattern would remove in this direction, or
/// `None` when it reaches none of them.
///
/// Matched with the dialect the removal itself uses, so the load-time check
/// cannot be looser than what happens at request time.
#[must_use]
pub fn glob_would_match_floor(direction: Direction, pattern: &str) -> Option<&'static str> {
    let matcher = Pattern::new(pattern.to_lowercase());
    floor_for(direction)
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

    const BOTH: [Direction; 2] = [Direction::Request, Direction::Response];

    #[test]
    fn every_floor_name_matches_case_insensitively() {
        for direction in BOTH {
            for entry in floor_for(direction) {
                assert!(is_floor(direction, entry.name), "{}", entry.name);
                assert!(
                    is_floor(direction, &entry.name.to_uppercase()),
                    "{}",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn a_glob_reaching_a_floor_header_names_it() {
        let response = Direction::Response;
        assert_eq!(
            glob_would_match_floor(response, "content-*"),
            Some("content-type")
        );
        assert_eq!(glob_would_match_floor(response, "etag"), Some("etag"));
        assert_eq!(glob_would_match_floor(response, "ETag"), Some("etag"));
        assert_eq!(
            glob_would_match_floor(response, "access-control-*"),
            Some("access-control-allow-origin")
        );
        assert_eq!(glob_would_match_floor(response, "*"), Some("content-type"));
    }

    /// The request direction has a floor of its own, so the greedy glob that a
    /// response block is refused for is refused here too.
    #[test]
    fn a_request_glob_reaching_the_request_floor_names_it() {
        let request = Direction::Request;
        assert_eq!(glob_would_match_floor(request, "*"), Some("host"));
        assert_eq!(glob_would_match_floor(request, "host"), Some("host"));
        assert_eq!(glob_would_match_floor(request, "Host"), Some("host"));
        assert_eq!(
            glob_would_match_floor(request, "content-*"),
            Some("content-type")
        );
        assert_eq!(
            glob_would_match_floor(request, "transfer-encoding"),
            Some("transfer-encoding")
        );
    }

    #[test]
    fn a_glob_reaching_nothing_in_the_floor_is_allowed() {
        for pattern in ["x-backend-*", "server", "x-debug-*", "x-auth-*"] {
            assert_eq!(
                glob_would_match_floor(Direction::Response, pattern),
                None,
                "{pattern}"
            );
        }
        for pattern in ["x-auth-*", "x-user-id", "cookie", "user-agent"] {
            assert_eq!(
                glob_would_match_floor(Direction::Request, pattern),
                None,
                "{pattern}"
            );
        }
    }

    /// Removing these is a stated use case, so they are outside the floor.
    #[test]
    fn the_strippable_headers_are_not_in_the_floor() {
        for name in ["set-cookie", "server", "x-powered-by"] {
            assert!(!is_floor(Direction::Response, name), "{name}");
            assert_eq!(
                glob_would_match_floor(Direction::Response, name),
                None,
                "{name}"
            );
        }
    }

    /// `authorization` is outside the request floor on purpose: an upstream
    /// reached on a delegated credential should not also receive the client's
    /// own bearer, so stripping it has to stay legal.
    #[test]
    fn authorization_is_strippable_from_a_request() {
        assert!(!is_floor(Direction::Request, "authorization"));
        assert_eq!(
            glob_would_match_floor(Direction::Request, "authorization"),
            None
        );
        assert_eq!(
            glob_would_match_floor(Direction::Request, "Authorization"),
            None
        );
    }

    /// An addition cannot land undocumented.
    #[test]
    fn every_floor_entry_carries_a_reason() {
        for direction in BOTH {
            for entry in floor_for(direction) {
                assert!(!entry.name.is_empty());
                assert!(!entry.reason.is_empty(), "{} has no reason", entry.name);
                assert_eq!(
                    entry.name,
                    entry.name.to_lowercase(),
                    "floor names are lowercase so a comparison needs one case fold"
                );
            }
        }
    }

    #[test]
    fn a_name_is_listed_once() {
        for direction in BOTH {
            let floor = floor_for(direction);
            for (i, entry) in floor.iter().enumerate() {
                assert!(
                    !floor.iter().take(i).any(|seen| seen.name == entry.name),
                    "{} is listed twice",
                    entry.name
                );
            }
        }
    }

    /// The two lists are separate, and the request one is the shorter of the
    /// two: a name in the response floor is not automatically refused on the
    /// way in.
    #[test]
    fn the_two_floors_are_independent() {
        assert!(is_floor(Direction::Response, "etag"));
        assert!(!is_floor(Direction::Request, "etag"));
        assert!(is_floor(Direction::Request, "host"));
        assert!(!is_floor(Direction::Response, "host"));
    }
}
