// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Parsing a raw `Cookie` header value and a raw URL query string into
// name-value pairs, deterministically and independent of which HTTP
// framework the host runs.
//
// # Why PPE parses instead of the host
//
// Cookie and query-string extraction must produce the same result no
// matter which HTTP framework the host uses — Envoy sidecar, Node
// gateway, Rust proxy. Different frameworks parse duplicate names,
// whitespace, and encoding differently; if each host parsed its own
// way, the same JWT could be extracted or rejected depending on which
// host runs it. The host hands PPE the raw string and PPE applies one
// parser to every request.
//
// # No percent-decoding
//
// JWTs are base64url and never contain characters that need
// percent-encoding. Skipping percent-decoding avoids a new dependency
// (`percent-encoding` / `form_urlencoded`) for a case that credential
// extraction never needs. A future non-JWT plugin that needs decoded
// values can revisit this contract.

use std::collections::HashMap;

use thiserror::Error;

/// Maximum size, in bytes, of a raw `Cookie` header value or raw query
/// string this module will parse. RFC 6265 §6.1 recommends servers
/// support at least 4096 bytes per cookie; most servers cap total
/// header size at 8-16 KiB. 8 KiB keeps parsing cheap and bounds the
/// `HashMap` a hostile request could force us to allocate.
const MAX_INPUT_LEN: usize = 8 * 1024;

/// Reason a raw credential string was rejected during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialParseError {
    /// The raw input exceeds [`MAX_INPUT_LEN`].
    #[error("{location} input is {len} bytes, exceeding the {max}-byte limit")]
    TooLong {
        /// Where the input came from (`"cookie"` or `"query_param"`).
        location: &'static str,
        /// The input's actual length.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// The raw input contains a control character (`\r`, `\n`, or
    /// `\0`) — a defense against header-smuggling attacks that inject
    /// a fake header via `\r\n` in a value the host's own parser
    /// failed to strip.
    #[error("{location} input contains a control character")]
    ControlCharacter {
        /// Where the input came from (`"cookie"` or `"query_param"`).
        location: &'static str,
    },

    /// A credential name appeared more than once. Ambiguous input is
    /// rejected outright rather than resolved by "first wins" or "last
    /// wins" — a deterministic-but-arbitrary tiebreak would let an
    /// attacker who can inject a second same-named cookie or query
    /// parameter silently override which value a resolver reads.
    #[error("duplicate {location} name '{name}'")]
    Duplicate {
        /// Where the duplicate was found (`"cookie"` or `"query_param"`).
        location: &'static str,
        /// The repeated name.
        name: String,
    },
}

/// Reject oversized or control-character input before parsing.
fn validate(raw: &str, location: &'static str) -> Result<(), CredentialParseError> {
    if raw.len() > MAX_INPUT_LEN {
        return Err(CredentialParseError::TooLong {
            location,
            len: raw.len(),
            max: MAX_INPUT_LEN,
        });
    }
    if raw.contains(['\r', '\n', '\0']) {
        return Err(CredentialParseError::ControlCharacter { location });
    }
    Ok(())
}

/// Insert `(name, value)` into `map`, rejecting a duplicate name.
fn insert_unique(
    map: &mut HashMap<String, String>,
    location: &'static str,
    name: String,
    value: String,
) -> Result<(), CredentialParseError> {
    if map.contains_key(&name) {
        return Err(CredentialParseError::Duplicate { location, name });
    }
    map.insert(name, value);
    Ok(())
}

/// Parse a raw `Cookie` header value (RFC 6265 §4.2.1) into name-value
/// pairs. Rejects oversized input, control characters, and duplicate
/// names.
///
/// Splits on `; ` (with tolerance for a bare `;`), trims whitespace
/// from names but not values (RFC 6265 does not define value
/// trimming), and does not percent-decode. A pair with no `=` is
/// tolerated as a name with an empty value.
///
/// # Errors
///
/// [`CredentialParseError::TooLong`] when `raw` exceeds the size
/// limit, [`CredentialParseError::ControlCharacter`] when it contains
/// `\r`, `\n`, or `\0`, and [`CredentialParseError::Duplicate`] when
/// the same cookie name appears twice.
pub fn parse_cookie_header(raw: &str) -> Result<HashMap<String, String>, CredentialParseError> {
    validate(raw, "cookie")?;

    let mut out = HashMap::new();
    for pair in raw.split(';') {
        // Tolerate both "; " and ";" as separators — trim leading
        // whitespace left over from either.
        let pair = pair.trim_start();
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((n, v)) => (n.trim(), v),
            None => (pair.trim(), ""),
        };
        insert_unique(&mut out, "cookie", name.to_owned(), value.to_owned())?;
    }
    Ok(out)
}

/// Parse a raw query string (the part after `?`, without the `?`)
/// into name-value pairs. Rejects oversized input, control
/// characters, and duplicate names.
///
/// Splits on `&`, splits each segment on the first `=`, and does not
/// percent-decode. A segment with no `=` is tolerated as a name with
/// an empty value.
///
/// # Errors
///
/// [`CredentialParseError::TooLong`] when `raw` exceeds the size
/// limit, [`CredentialParseError::ControlCharacter`] when it contains
/// `\r`, `\n`, or `\0`, and [`CredentialParseError::Duplicate`] when
/// the same parameter name appears twice.
pub fn parse_query_string(raw: &str) -> Result<HashMap<String, String>, CredentialParseError> {
    validate(raw, "query_param")?;

    let mut out = HashMap::new();
    for segment in raw.split('&') {
        if segment.is_empty() {
            continue;
        }
        let (name, value) = match segment.split_once('=') {
            Some((n, v)) => (n, v),
            None => (segment, ""),
        };
        insert_unique(&mut out, "query_param", name.to_owned(), value.to_owned())?;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::get_unwrap,
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
    fn cookie_single() {
        let m = parse_cookie_header("session=abc123").unwrap();
        assert_eq!(m.get("session").map(String::as_str), Some("abc123"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn cookie_multiple() {
        let m = parse_cookie_header("a=1; b=2; c=3").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
        assert_eq!(m.get("c").map(String::as_str), Some("3"));
    }

    #[test]
    fn cookie_trailing_semicolon() {
        let m = parse_cookie_header("a=1;").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn cookie_no_value_entry() {
        let m = parse_cookie_header("flag; a=1").unwrap();
        assert_eq!(m.get("flag").map(String::as_str), Some(""));
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
    }

    #[test]
    fn cookie_whitespace_tolerance() {
        // No leading space (";" tolerance, no trailing space) still works.
        let m = parse_cookie_header("a=1;b=2").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
    }

    #[test]
    fn cookie_value_containing_equals() {
        let m = parse_cookie_header("jwt=eyJhbGciOiJIUzI1NiJ9.abc.def=extra").unwrap();
        assert_eq!(
            m.get("jwt").map(String::as_str),
            Some("eyJhbGciOiJIUzI1NiJ9.abc.def=extra")
        );
    }

    #[test]
    fn cookie_duplicate_name_errors() {
        let err = parse_cookie_header("a=1; a=2").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::Duplicate {
                location: "cookie",
                name: "a".into()
            }
        );
    }

    #[test]
    fn cookie_empty_input() {
        let m = parse_cookie_header("").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn cookie_too_long_rejected() {
        let raw = format!("a={}", "x".repeat(MAX_INPUT_LEN + 1));
        let err = parse_cookie_header(&raw).unwrap_err();
        assert!(matches!(err, CredentialParseError::TooLong { .. }));
    }

    #[test]
    fn cookie_control_character_rejected() {
        let err = parse_cookie_header("a=1\r\nInjected: header").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::ControlCharacter { location: "cookie" }
        );
    }

    #[test]
    fn query_single() {
        let m = parse_query_string("access_token=eyJ.abc.def").unwrap();
        assert_eq!(
            m.get("access_token").map(String::as_str),
            Some("eyJ.abc.def")
        );
    }

    #[test]
    fn query_multiple() {
        let m = parse_query_string("a=1&b=2").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
    }

    #[test]
    fn query_no_value_param() {
        let m = parse_query_string("flag&a=1").unwrap();
        assert_eq!(m.get("flag").map(String::as_str), Some(""));
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
    }

    #[test]
    fn query_value_containing_equals() {
        let m = parse_query_string("token=abc=def").unwrap();
        assert_eq!(m.get("token").map(String::as_str), Some("abc=def"));
    }

    #[test]
    fn query_duplicate_name_errors() {
        let err = parse_query_string("a=1&a=2").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::Duplicate {
                location: "query_param",
                name: "a".into()
            }
        );
    }

    #[test]
    fn query_empty_input() {
        let m = parse_query_string("").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn query_too_long_rejected() {
        let raw = format!("a={}", "x".repeat(MAX_INPUT_LEN + 1));
        let err = parse_query_string(&raw).unwrap_err();
        assert!(matches!(err, CredentialParseError::TooLong { .. }));
    }

    #[test]
    fn query_control_character_rejected() {
        let err = parse_query_string("a=1%0d%0a\ninjected").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::ControlCharacter {
                location: "query_param"
            }
        );
    }
}
