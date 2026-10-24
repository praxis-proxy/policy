// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Parse raw Cookie and query strings here so hosts using different HTTP
// frameworks agree on duplicates, whitespace, and encoded names.

use std::collections::HashMap;

use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const MAX_INPUT_LEN: usize = 16_384; // 16 KiB

/// Reason a raw credential string was rejected during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialParseError {
    /// The raw input exceeds the maximum allowed length.
    #[error("{location} input is {len} bytes, exceeding the {max}-byte limit")]
    TooLong {
        /// Where the input came from (`"cookie"` or `"query_param"`).
        location: &'static str,
        /// The input's actual length.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },

    /// The raw input contains an ASCII control character other than HTAB.
    #[error("{location} input contains a control character")]
    ControlCharacter {
        /// Where the input came from (`"cookie"` or `"query_param"`).
        location: &'static str,
    },

    /// The configured credential name appeared more than once. Other
    /// duplicate names keep their first value.
    #[error("duplicate {location} name '{name}'")]
    Duplicate {
        /// Where the duplicate was found (`"cookie"` or `"query_param"`).
        location: &'static str,
        /// The repeated name.
        name: String,
    },

    /// A query parameter name matches the credential name only after
    /// percent-decoding.
    #[error(
        "query parameter '{encoded}' matches credential name '{credential}' \
         only after percent-decoding; the request source must send the \
         name literally"
    )]
    PercentEncodedName {
        /// The encoded name found in the query string.
        encoded: String,
        /// The configured credential name.
        credential: String,
    },
}

fn percent_decode_name(input: &str) -> Option<String> {
    if !input.contains('%') {
        return None;
    }
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.as_bytes().iter();
    while let Some(&b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next()?;
            let lo = bytes.next()?;
            let hex = [*hi, *lo];
            let decoded = u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?;
            out.push(decoded);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

fn validate(raw: &str, location: &'static str) -> Result<(), CredentialParseError> {
    if raw.len() > MAX_INPUT_LEN {
        return Err(CredentialParseError::TooLong {
            location,
            len: raw.len(),
            max: MAX_INPUT_LEN,
        });
    }
    if raw.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
        return Err(CredentialParseError::ControlCharacter { location });
    }
    Ok(())
}

fn insert_unique(
    map: &mut HashMap<String, String>,
    location: &'static str,
    credential_name: &str,
    name: String,
    value: String,
) -> Result<(), CredentialParseError> {
    if name == credential_name && map.contains_key(&name) {
        return Err(CredentialParseError::Duplicate { location, name });
    }
    map.entry(name).or_insert(value);
    Ok(())
}

/// Parse a raw `Cookie` header into the name-value pairs described by
/// [RFC 6265 Section 4.2.1].
///
/// Names are trimmed; values and percent escapes remain literal. A name
/// without `=` has an empty value. Duplicate occurrences of
/// `credential_name` are rejected; other duplicates keep their first value.
///
/// # Errors
///
/// Returns [`CredentialParseError::TooLong`] for input over 16 KiB,
/// [`CredentialParseError::ControlCharacter`] for a control character,
/// or [`CredentialParseError::Duplicate`] for a repeated credential name.
///
/// # Examples
///
/// ```
/// use praxis_policy_core::http_credential::parse_cookie_header;
///
/// let cookies = parse_cookie_header("theme=dark; session=abc", "session")?;
/// assert_eq!(cookies.get("session").map(String::as_str), Some("abc"));
/// # Ok::<(), praxis_policy_core::http_credential::CredentialParseError>(())
/// ```
///
/// [RFC 6265 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6265#section-4.2.1
pub fn parse_cookie_header(
    raw: &str,
    credential_name: &str,
) -> Result<HashMap<String, String>, CredentialParseError> {
    validate(raw, "cookie")?;

    let mut out = HashMap::new();
    for pair in raw.split(';') {
        let pair = pair.trim_start();
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((n, v)) => (n.trim(), v),
            None => (pair.trim(), ""),
        };
        insert_unique(
            &mut out,
            "cookie",
            credential_name,
            name.to_owned(),
            value.to_owned(),
        )?;
    }
    Ok(out)
}

/// Parse a raw query string (without the `?`) into name-value pairs.
///
/// Names and values remain literal; percent escapes are not decoded.
/// A name without `=` has an empty value. Duplicate occurrences of
/// `credential_name` are rejected; other duplicates keep their first value.
/// An encoded name that would match `credential_name` is rejected when
/// no literal match is present.
///
/// # Errors
///
/// Returns [`CredentialParseError::TooLong`] for input over 16 KiB,
/// [`CredentialParseError::ControlCharacter`] for a control character,
/// [`CredentialParseError::Duplicate`] for a repeated credential name,
/// or [`CredentialParseError::PercentEncodedName`] for an encoded match.
///
/// # Examples
///
/// ```
/// use praxis_policy_core::http_credential::{
///     CredentialParseError, parse_query_string,
/// };
///
/// let err = parse_query_string("token=a&token=b", "token").unwrap_err();
/// assert!(matches!(err, CredentialParseError::Duplicate { .. }));
/// ```
pub fn parse_query_string(
    raw: &str,
    credential_name: &str,
) -> Result<HashMap<String, String>, CredentialParseError> {
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
        insert_unique(
            &mut out,
            "query_param",
            credential_name,
            name.to_owned(),
            value.to_owned(),
        )?;
    }

    if !out.contains_key(credential_name) {
        for key in out.keys() {
            if let Some(decoded) = percent_decode_name(key)
                && decoded == credential_name
            {
                return Err(CredentialParseError::PercentEncodedName {
                    encoded: key.clone(),
                    credential: credential_name.to_owned(),
                });
            }
        }
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
        let m = parse_cookie_header("session=abc123", "_").unwrap();
        assert_eq!(m.get("session").map(String::as_str), Some("abc123"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn cookie_multiple() {
        let m = parse_cookie_header("a=1; b=2; c=3", "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
        assert_eq!(m.get("c").map(String::as_str), Some("3"));
    }

    #[test]
    fn cookie_trailing_semicolon() {
        let m = parse_cookie_header("a=1;", "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn cookie_no_value_entry() {
        let m = parse_cookie_header("flag; a=1", "_").unwrap();
        assert_eq!(m.get("flag").map(String::as_str), Some(""));
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
    }

    #[test]
    fn cookie_whitespace_tolerance() {
        let m = parse_cookie_header("a=1;b=2", "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
    }

    #[test]
    fn cookie_value_containing_equals() {
        let m = parse_cookie_header("jwt=eyJhbGciOiJIUzI1NiJ9.abc.def=extra", "_").unwrap();
        assert_eq!(
            m.get("jwt").map(String::as_str),
            Some("eyJhbGciOiJIUzI1NiJ9.abc.def=extra")
        );
    }

    #[test]
    fn cookie_duplicate_name_errors() {
        let err = parse_cookie_header("a=1; a=2", "a").unwrap_err();
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
        let m = parse_cookie_header("", "_").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn cookie_too_long_rejected() {
        let raw = format!("a={}", "x".repeat(MAX_INPUT_LEN + 1));
        let err = parse_cookie_header(&raw, "_").unwrap_err();
        assert!(matches!(err, CredentialParseError::TooLong { .. }));
    }

    #[test]
    fn cookie_control_character_rejected() {
        let err = parse_cookie_header("a=1\r\nInjected: header", "_").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::ControlCharacter { location: "cookie" }
        );
    }

    #[test]
    fn cookie_vertical_tab_rejected() {
        let err = parse_cookie_header("a=1\x0B", "_").unwrap_err();
        assert!(matches!(err, CredentialParseError::ControlCharacter { .. }));
    }

    #[test]
    fn cookie_del_rejected() {
        let err = parse_cookie_header("a=1\x7F", "_").unwrap_err();
        assert!(matches!(err, CredentialParseError::ControlCharacter { .. }));
    }

    #[test]
    fn cookie_tab_allowed() {
        let m = parse_cookie_header("a=1\t", "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1\t"));
    }

    #[test]
    fn query_single() {
        let m = parse_query_string("access_token=eyJ.abc.def", "_").unwrap();
        assert_eq!(
            m.get("access_token").map(String::as_str),
            Some("eyJ.abc.def")
        );
    }

    #[test]
    fn query_multiple() {
        let m = parse_query_string("a=1&b=2", "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
    }

    #[test]
    fn query_no_value_param() {
        let m = parse_query_string("flag&a=1", "_").unwrap();
        assert_eq!(m.get("flag").map(String::as_str), Some(""));
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
    }

    #[test]
    fn query_value_containing_equals() {
        let m = parse_query_string("token=abc=def", "_").unwrap();
        assert_eq!(m.get("token").map(String::as_str), Some("abc=def"));
    }

    #[test]
    fn query_duplicate_name_errors() {
        let err = parse_query_string("a=1&a=2", "a").unwrap_err();
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
        let m = parse_query_string("", "_").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn query_too_long_rejected() {
        let raw = format!("a={}", "x".repeat(MAX_INPUT_LEN + 1));
        let err = parse_query_string(&raw, "_").unwrap_err();
        assert!(matches!(err, CredentialParseError::TooLong { .. }));
    }

    #[test]
    fn query_control_character_rejected() {
        let err = parse_query_string("a=1%0d%0a\ninjected", "_").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::ControlCharacter {
                location: "query_param"
            }
        );
    }

    #[test]
    fn query_vertical_tab_rejected() {
        let err = parse_query_string("a=1\x0B", "_").unwrap_err();
        assert!(matches!(err, CredentialParseError::ControlCharacter { .. }));
    }

    #[test]
    fn query_del_rejected() {
        let err = parse_query_string("a=1\x7F", "_").unwrap_err();
        assert!(matches!(err, CredentialParseError::ControlCharacter { .. }));
    }

    #[test]
    fn query_tab_allowed() {
        let m = parse_query_string("a=1\t", "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1\t"));
    }

    #[test]
    fn query_leading_and_trailing_ampersand_tolerated() {
        let m = parse_query_string("&a=1&", "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn cookie_exactly_at_limit_accepted() {
        let value = "x".repeat(MAX_INPUT_LEN - "a=".len());
        let raw = format!("a={value}");
        assert_eq!(raw.len(), MAX_INPUT_LEN);
        let m = parse_cookie_header(&raw, "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some(value.as_str()));
    }

    #[test]
    fn query_exactly_at_limit_accepted() {
        let value = "x".repeat(MAX_INPUT_LEN - "a=".len());
        let raw = format!("a={value}");
        assert_eq!(raw.len(), MAX_INPUT_LEN);
        let m = parse_query_string(&raw, "_").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some(value.as_str()));
    }

    #[test]
    fn cookie_duplicate_non_credential_name_tolerated() {
        let m = parse_cookie_header("tag=a; tag=b; jwt=eyJ.tok", "jwt").unwrap();
        assert_eq!(m.get("jwt").map(String::as_str), Some("eyJ.tok"));
        assert_eq!(m.get("tag").map(String::as_str), Some("a"));
    }

    #[test]
    fn query_duplicate_non_credential_name_tolerated() {
        let m = parse_query_string("tag=a&tag=b&access_token=eyJ.tok", "access_token").unwrap();
        assert_eq!(m.get("access_token").map(String::as_str), Some("eyJ.tok"));
        assert_eq!(m.get("tag").map(String::as_str), Some("a"));
    }

    #[test]
    fn cookie_duplicate_credential_name_still_errors() {
        let err = parse_cookie_header("jwt=a; jwt=b", "jwt").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::Duplicate {
                location: "cookie",
                name: "jwt".into()
            }
        );
    }

    #[test]
    fn query_duplicate_credential_name_still_errors() {
        let err = parse_query_string("token=a&token=b", "token").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::Duplicate {
                location: "query_param",
                name: "token".into()
            }
        );
    }

    #[test]
    fn query_percent_encoded_credential_name_detected() {
        let err = parse_query_string("access%5Ftoken=eyJ.tok", "access_token").unwrap_err();
        assert_eq!(
            err,
            CredentialParseError::PercentEncodedName {
                encoded: "access%5Ftoken".into(),
                credential: "access_token".into(),
            }
        );
    }

    #[test]
    fn query_percent_encoded_unrelated_name_ignored() {
        let m = parse_query_string("ta%67=a&access_token=eyJ.tok", "access_token").unwrap();
        assert_eq!(m.get("access_token").map(String::as_str), Some("eyJ.tok"));
    }

    #[test]
    fn query_literal_credential_name_skips_decode_check() {
        let m = parse_query_string("access_token=eyJ.tok&access%5Ftoken=other", "access_token")
            .unwrap();
        assert_eq!(m.get("access_token").map(String::as_str), Some("eyJ.tok"));
    }

    #[test]
    fn query_malformed_percent_encoding_ignored() {
        let m = parse_query_string("access%ZZtoken=eyJ&access_token=tok", "access_token").unwrap();
        assert_eq!(m.get("access_token").map(String::as_str), Some("tok"));
    }
}
