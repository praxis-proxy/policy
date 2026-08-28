// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Reading a host-supplied request path, and refusing one that cannot be
// read safely.
//
// The rewriting rules mirror `normalize_rewritten_path` in
// `filter/src/builtins/http/transformation/path_sanitize.rs` of the praxis
// tree. PPE cannot depend on that crate, so the duplication is deliberate
// and the oracle test at the bottom of this file pins the two together case
// for case. Name both files when either moves.
//
// # A guard, not the matcher
//
// The gateway applies `normalize_rewritten_path` only to paths it produced
// itself: a URL rewrite, a path rewrite, a redirect `Location`. Its router
// never sees the output. The router matches an inbound request on
// `ctx.rewritten_path` or `ctx.request.uri.path()` with no normalization of
// any kind, and its exact arm is a byte compare
// (`traffic_management/router/mod.rs`, `router/matching.rs`).
//
// So route matching in PPE runs on the request path as given, which is what
// makes it resolve the route the request is actually forwarded to. What this
// module contributes is fail-closed instead: a path it cannot read denies
// when the configuration declares an `http:` route. The value it returns is
// not the matcher and must not be wired back into matching.
//
// Five rules here are this module's own rather than the gateway's: the
// fragment is stripped, the query is stripped, path parameters are
// stripped per segment, a path that is not absolute comes back as given
// rather than gaining a leading slash, and a dot segment carrying a path
// parameter is refused rather than resolved. Everything else agrees case
// for case.
//
// Nothing is percent-decoded, which is the whole reason this module exists
// instead of a call into a URL crate. A percent-encoded separator stays
// inside its own segment. Decode it and this function turns
// `/admin/x/..%2f..%2fv1%2fok` into `/v1/ok`, a path under a prefix the
// host's router never sends the request to, which is the wrong answer for
// any caller reading the result. Because nothing is decoded there is no
// charset rule, no UTF-8 validation, and no question about a non-UTF-8
// octet.
//
// # The output is written nowhere
//
// The normalized form is never written back to `HttpExtension` or into the
// attribute bag, and route matching does not read it either. `http.path`
// reads what the host set, so a rule written against it keeps the meaning it
// has today.
//
// # Why the input is trustworthy as request identity
//
// The path comes from the request line on the extensions container, and
// `merge_http` in `extensions/container.rs` always preserves the request
// line from canonical state. A plugin's returned `http` slot contributes
// headers only, so no plugin can move a request onto another route by
// rewriting its own view of the path.
//
// # What fails, and what does not
//
// Malformed input fails: a percent-escape that is not two hex digits, one
// truncated at the end of the path, or a raw control character anywhere in
// the input.
//
// A dot segment carrying a path parameter fails too. Whether `..;x` is a
// traversal depends on the backend: one that strips parameters reads it as
// `..`, one that does not reads it as a directory name. Resolving it would
// pick the more permissive of the two readings and apply the policy for
// the shallower path to a request a literal-reading backend serves from
// the deeper one. No client sends that shape on purpose, so there is
// nothing to preserve by guessing.
//
// A path that is not absolute does not fail. `OPTIONS *` is
// legitimate traffic rather than a crafted bypass, so a non-absolute path
// comes back exactly as given, and a caller treats a result without a
// leading `/` the way it treats an absent path: nothing matches and the
// global fallback applies.

use std::borrow::Cow;

use thiserror::Error;

/// Why a request path could not be read as a path.
///
/// Each variant carries a byte offset rather than the path itself, so a
/// refusal names the rule it broke without copying request content into a
/// log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PathError {
    /// A percent sign not followed by two hexadecimal digits.
    #[error("percent-escape at byte {index} is not two hex digits")]
    InvalidEscape {
        /// Byte offset of the percent sign.
        index: usize,
    },

    /// A percent-escape cut short by the end of the path.
    #[error("percent-escape at byte {index} is truncated")]
    TruncatedEscape {
        /// Byte offset of the percent sign.
        index: usize,
    },

    /// A dot segment carrying a path parameter, such as `..;x`.
    ///
    /// Refused rather than resolved because the two readings a backend
    /// might take differ in which is more permissive.
    #[error("path parameter on a traversal segment at byte {index}")]
    ParameterizedTraversal {
        /// Byte offset where the segment starts.
        index: usize,
    },

    /// A raw control character, which no legitimate request line carries.
    #[error("control character 0x{byte:02x} at byte {index}")]
    ControlCharacter {
        /// Byte offset of the character.
        index: usize,
        /// The offending byte.
        byte: u8,
    },
}

/// A request path with its query, fragment, path parameters, duplicate
/// slashes, and dot segments resolved away, or an error when it cannot be
/// read safely.
///
/// Route matching does not use this. PPE matches on the path as given, the
/// way the host router does; this runs alongside as a guard, and an `Err` is
/// what denies a request the router and PPE could not agree on.
///
/// Borrows when the path is already normal, which is the common case and
/// must not allocate. A query or a fragment is not a rewrite: it is
/// stripped by taking a shorter borrow of the same string. A path that is
/// not absolute comes back byte for byte as given.
///
/// # Errors
///
/// [`PathError`] when an escape is malformed, a control character is
/// present, or a dot segment carries a path parameter. Escapes are checked
/// on the path portion only, since a query string routinely carries a bare
/// `%` that no route ever matches on.
pub fn normalize_match_path(raw: &str) -> Result<Cow<'_, str>, PathError> {
    reject_control_characters(raw)?;
    let path = strip_fragment_and_query(raw);
    reject_malformed_escapes(path)?;

    // A path that is not absolute is left alone. Prepending a `/` the way
    // the gateway's rewrite helper does would turn `*` into a path that
    // could match a route, and no route should answer for a request that
    // named no path at all.
    if !path.starts_with('/') {
        return Ok(Cow::Borrowed(raw));
    }
    // Asked of the stripped path, and answered with a borrow of that same
    // slice, so a request carrying a query allocates nothing.
    if !needs_rewrite(path) {
        return Ok(Cow::Borrowed(path));
    }
    Ok(Cow::Owned(rewrite(path)?))
}

/// Everything before the first `#`, then before the first `?`.
fn strip_fragment_and_query(raw: &str) -> &str {
    let without_fragment = raw.split_once('#').map_or(raw, |(head, _)| head);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(head, _)| head)
}

/// Whether the path would come out of [`rewrite`] any different.
///
/// Takes the path with the fragment and the query already stripped, so
/// neither can appear here. Mirrors the gateway's own fast check, plus the
/// path parameters and encoded traversals it does not strip because it runs
/// on a path the gateway itself produced.
fn needs_rewrite(path: &str) -> bool {
    path.contains("//")
        || path.contains("/./")
        || path.contains("/../")
        || path.ends_with("/.")
        || path.ends_with("/..")
        || path.contains(';')
        || path.split('/').any(is_traversal_segment)
}

/// Resolve dot segments and collapse repeated slashes.
///
/// Splits on raw `/` only, so an encoded separator never becomes one. A
/// `..` that would pop past the root clamps at the root, which is what the
/// gateway does, so escaping the root is not reachable.
///
/// # Errors
///
/// [`PathError::ParameterizedTraversal`] when stripping a segment's
/// parameters leaves a traversal segment behind.
fn rewrite(path: &str) -> Result<String, PathError> {
    let mut segments: Vec<&str> = Vec::new();
    let mut index = 0_usize;

    for raw_segment in path.split('/') {
        let start = index;
        index += raw_segment.len() + 1;
        // Path parameters are not part of the path. A `jsessionid` must not
        // defeat an exact-path selector, so it goes before the segment is
        // classified.
        let segment = raw_segment
            .split_once(';')
            .map_or(raw_segment, |(head, _)| head);
        match segment {
            "" | "." => {},
            _ if is_traversal_segment(segment) => {
                // Only a bare traversal resolves. A parameter hiding one is
                // refused, because resolving it would pick the reading a
                // parameter-stripping backend takes and lose the policy a
                // literal-reading backend still needs.
                if segment != raw_segment {
                    return Err(PathError::ParameterizedTraversal { index: start });
                }
                segments.pop();
            },
            _ => segments.push(segment),
        }
    }

    let mut out = String::with_capacity(path.len().max(1));
    if segments.is_empty() {
        out.push('/');
    } else {
        for segment in &segments {
            out.push('/');
            out.push_str(segment);
        }
    }
    Ok(out)
}

/// Whether a segment is exactly two dots, literal or percent-encoded.
///
/// The gateway's rule, and the reason `..config`, `.`, and `%2e%2e%2e` are
/// ordinary names rather than traversals.
fn is_traversal_segment(segment: &str) -> bool {
    if segment == ".." {
        return true;
    }
    let mut dots = 0_u32;
    // Bytes of a `%2e` escape still expected, counting down from the `%`.
    let mut escape = 0_u8;
    for byte in segment.bytes() {
        match escape {
            0 => match byte {
                b'.' => dots += 1,
                b'%' => escape = 2,
                _ => return false,
            },
            2 => {
                if !byte.eq_ignore_ascii_case(&b'2') {
                    return false;
                }
                escape = 1;
            },
            _ => {
                if !byte.eq_ignore_ascii_case(&b'e') {
                    return false;
                }
                dots += 1;
                escape = 0;
            },
        }
        if dots > 2 {
            return false;
        }
    }
    escape == 0 && dots == 2
}

/// Refuse a raw control character, wherever it sits.
///
/// A control character in a request line is a smuggling signal rather than
/// something to sanitize, so it is refused before anything is stripped.
fn reject_control_characters(raw: &str) -> Result<(), PathError> {
    for (index, byte) in raw.bytes().enumerate() {
        if byte.is_ascii_control() {
            return Err(PathError::ControlCharacter { index, byte });
        }
    }
    Ok(())
}

/// Refuse an escape that is not a percent sign and two hex digits.
fn reject_malformed_escapes(path: &str) -> Result<(), PathError> {
    // Digits still expected, and where the escape they belong to started.
    let mut expected = 0_u8;
    let mut index = 0_usize;
    for (offset, byte) in path.bytes().enumerate() {
        if expected == 0 {
            if byte == b'%' {
                expected = 2;
                index = offset;
            }
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err(PathError::InvalidEscape { index });
        }
        expected -= 1;
    }
    if expected != 0 {
        return Err(PathError::TruncatedEscape { index });
    }
    Ok(())
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

    fn normalized(raw: &str) -> String {
        normalize_match_path(raw)
            .expect("a readable path")
            .into_owned()
    }

    #[test]
    fn a_normal_path_is_borrowed_and_allocates_nothing() {
        for raw in ["/", "/v1/files", "/v1/files/q3.pdf", "/api/", "/a/..config"] {
            let result = normalize_match_path(raw).expect("a readable path");
            assert!(
                matches!(result, Cow::Borrowed(_)),
                "{raw} is already normal and must not allocate"
            );
            assert_eq!(&*result, raw, "{raw} must come back unchanged");
        }
    }

    #[test]
    fn the_query_and_the_fragment_are_removed() {
        assert_eq!(
            normalized("/a/b?x=1"),
            "/a/b",
            "a query is not part of the path"
        );
        assert_eq!(
            normalized("/a/b#frag"),
            "/a/b",
            "a fragment is not part of the path"
        );
        assert_eq!(
            normalized("/a/b?x=1#frag"),
            "/a/b",
            "a query and a fragment together are both removed"
        );
        assert_eq!(
            normalized("/a/b#frag?x=1"),
            "/a/b",
            "a query inside a fragment is removed with it"
        );
        assert_eq!(normalized("/?x=1"), "/", "a root path keeps its root");
    }

    #[test]
    fn a_query_or_a_fragment_is_stripped_by_borrowing() {
        // Ordinary traffic carries a query, and the path in front of one is
        // usually already normal, so dropping it is a shorter borrow rather
        // than an allocation.
        for (raw, expected) in [
            ("/v1/files/q3.pdf?page=2", "/v1/files/q3.pdf"),
            ("/v1/files/q3.pdf#page-2", "/v1/files/q3.pdf"),
            ("/v1/files/q3.pdf?page=2#top", "/v1/files/q3.pdf"),
            ("/?x=1", "/"),
        ] {
            let result = normalize_match_path(raw).expect("a readable path");
            assert!(
                matches!(result, Cow::Borrowed(_)),
                "{raw} needs no rewriting once its query and fragment are gone"
            );
            assert_eq!(&*result, expected, "{raw} must normalize to `{expected}`");
        }

        // A query does not make the path in front of it normal. One that
        // still has to be rewritten allocates, as it must.
        let result = normalize_match_path("/a//b?x=1").expect("a readable path");
        assert!(
            matches!(result, Cow::Owned(_)),
            "a path needing a rewrite is owned however its query reads"
        );
        assert_eq!(&*result, "/a/b", "the rewrite still runs on the path alone");
    }

    #[test]
    fn semicolon_path_parameters_are_removed() {
        assert_eq!(
            normalized("/v1/files;jsessionid=abc/q3.pdf"),
            "/v1/files/q3.pdf",
            "a session parameter must not defeat an exact-path selector"
        );
        assert_eq!(normalized("/a;p"), "/a", "a trailing parameter is removed");
        assert_eq!(
            normalized("/admin;x/secret"),
            "/admin/secret",
            "a parameter on an ordinary segment is still stripped, which reads \
             the deeper path and so is the conservative direction"
        );
        assert_eq!(
            normalized("/;p"),
            "/",
            "a parameter on the only segment leaves the root"
        );
    }

    #[test]
    fn a_parameter_on_a_traversal_segment_is_refused() {
        // Do not "fix" this into resolving. Whether `..;x` is a traversal
        // depends on the backend, and the two readings differ in which is
        // more permissive: resolving `/admin/..;x/public` to `/public`
        // applies the policy guarding `/public` to a request a
        // literal-reading backend serves from under `/admin`. Refusing is
        // correct under both readings.
        for raw in [
            "/admin/..;x/public",
            "/admin/..;/public",
            "/admin/%2e%2e;x/public",
            "/admin/%2E%2E;x/public",
            "/admin/.%2e;x/public",
            "/admin/%2e.;x/public",
        ] {
            assert_eq!(
                normalize_match_path(raw),
                Err(PathError::ParameterizedTraversal { index: 7 }),
                "{raw} hides a traversal behind a path parameter"
            );
        }
        assert!(
            PathError::ParameterizedTraversal { index: 7 }
                .to_string()
                .contains("parameter"),
            "the message must say what was wrong"
        );
    }

    #[test]
    fn a_traversal_segment_with_no_parameter_still_resolves() {
        // The refusal above is about the parameter and nothing else. A bare
        // traversal, literal or encoded, resolves as it always did.
        assert_eq!(
            normalized("/admin/../public"),
            "/public",
            "a bare traversal resolves"
        );
        assert_eq!(
            normalized("/admin/%2e%2e/public"),
            "/public",
            "a bare encoded traversal resolves"
        );
        assert_eq!(
            normalized("/admin/..%2e;x/public"),
            "/admin/..%2e/public",
            "three dots are an ordinary name, so its parameter is merely stripped"
        );
    }

    #[test]
    fn duplicate_slashes_and_dot_segments_resolve() {
        assert_eq!(normalized("//a//b"), "/a/b", "repeated slashes collapse");
        assert_eq!(normalized("/a/./b"), "/a/b", "a dot segment is dropped");
        assert_eq!(normalized("/a/c/../b"), "/a/b", "a dot-dot segment pops");
    }

    #[test]
    fn encoded_and_literal_traversal_resolve_the_same_way() {
        for raw in [
            "/v1/files/%2e%2e/%2e%2e/admin",
            "/v1/files/../../admin",
            "/v1/files/.%2e/%2E./admin",
        ] {
            assert_eq!(
                normalized(raw),
                "/admin",
                "{raw} must resolve out of /v1/files, so it cannot match that prefix"
            );
        }
    }

    #[test]
    fn an_encoded_separator_stays_inside_its_segment() {
        // The case this module exists for. Decoding `%2f` would resolve
        // this to /v1/ok and apply a public policy to a request the host's
        // router still sends to the /admin cluster.
        let raw = "/admin/x/..%2f..%2fv1%2fok";
        let result = normalize_match_path(raw).expect("a readable path");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "an encoded separator needs no rewriting"
        );
        assert_eq!(&*result, raw, "the path must stay under /admin, verbatim");
        assert_ne!(
            &*result, "/v1/ok",
            "an encoded separator must never become a separator"
        );
    }

    #[test]
    fn no_charset_rule_is_applied() {
        for raw in ["/files/caf%E9.pdf", "/files/caf%e9.pdf", "/files/café.pdf"] {
            let result = normalize_match_path(raw).expect("a readable path");
            assert!(
                matches!(result, Cow::Borrowed(_)),
                "{raw} needs no rewriting"
            );
            assert_eq!(&*result, raw, "{raw} must pass through untouched");
        }
    }

    #[test]
    fn a_malformed_escape_names_its_cause() {
        assert_eq!(
            normalize_match_path("/a/%zz"),
            Err(PathError::InvalidEscape { index: 3 }),
            "a non-hex escape is refused"
        );
        assert_eq!(
            normalize_match_path("/a%"),
            Err(PathError::TruncatedEscape { index: 2 }),
            "a trailing percent sign is refused"
        );
        assert_eq!(
            normalize_match_path("/a%2"),
            Err(PathError::TruncatedEscape { index: 2 }),
            "a one-digit escape is refused"
        );
        assert!(
            PathError::InvalidEscape { index: 3 }
                .to_string()
                .contains("hex"),
            "the message must say what was wrong"
        );
        assert!(
            PathError::TruncatedEscape { index: 2 }
                .to_string()
                .contains("truncated"),
            "the message must say what was wrong"
        );
    }

    #[test]
    fn a_raw_control_character_is_refused() {
        assert_eq!(
            normalize_match_path("/a\u{7}b"),
            Err(PathError::ControlCharacter { index: 2, byte: 7 }),
            "a bell is not a path character"
        );
        assert_eq!(
            normalize_match_path("/a\rb"),
            Err(PathError::ControlCharacter {
                index: 2,
                byte: b'\r'
            }),
            "a carriage return is a smuggling signal"
        );
        assert_eq!(
            normalize_match_path("/a\u{7f}"),
            Err(PathError::ControlCharacter {
                index: 2,
                byte: 0x7f
            }),
            "delete is a control character too"
        );
        assert!(
            PathError::ControlCharacter { index: 2, byte: 7 }
                .to_string()
                .contains("control"),
            "the message must say what was wrong"
        );
    }

    #[test]
    fn a_control_character_outranks_a_bad_escape() {
        assert_eq!(
            normalize_match_path("/a\n/%zz"),
            Err(PathError::ControlCharacter {
                index: 2,
                byte: b'\n'
            }),
            "the request line is judged before the path is read"
        );
    }

    #[test]
    fn a_bad_escape_in_the_query_is_not_the_paths_problem() {
        // A bare `%` in a query value is common enough in the wild that
        // refusing it would deny legitimate traffic, and nothing matches
        // on a query.
        assert_eq!(
            normalized("/checkout?discount=50%"),
            "/checkout",
            "the query is discarded before escapes are judged"
        );
    }

    #[test]
    fn traversal_past_the_root_clamps_to_the_root() {
        for raw in ["/../../..", "/..", "/a/../../..", "///"] {
            assert_eq!(
                normalized(raw),
                "/",
                "{raw} must clamp to the root, not fail"
            );
        }
    }

    #[test]
    fn a_path_that_is_not_absolute_is_returned_as_given() {
        // `OPTIONS *` is legitimate traffic. It matches no route and the
        // caller falls back, the same as for an absent path, which the
        // missing leading slash is what tells it.
        for raw in ["*", "", "no-slash", "a/../b"] {
            let result = normalize_match_path(raw).expect("a readable path");
            assert!(
                matches!(result, Cow::Borrowed(_)),
                "{raw} must not allocate"
            );
            assert_eq!(&*result, raw, "{raw} must come back exactly as given");
            assert!(
                !result.starts_with('/'),
                "{raw} must stay distinguishable from a normalized absolute path"
            );
        }
    }

    #[test]
    fn a_trailing_slash_is_preserved_as_the_gateway_preserves_it() {
        // The mirrored gateway function keeps a single trailing slash, so this
        // one does too. It costs no match either way, since matching runs on
        // the path as given: `/a/` is `/a/` to the exact comparison, which is
        // a byte compare, and one trailing slash is insignificant only to the
        // prefix matcher, which strips it from the declared prefix.
        assert_eq!(normalized("/a/"), "/a/", "a trailing slash survives");
        assert_eq!(
            normalized("/a//"),
            "/a",
            "a doubled trailing slash does not"
        );
    }

    #[test]
    fn only_a_segment_of_exactly_two_dots_is_a_traversal() {
        assert!(is_traversal_segment(".."), "literal dot-dot");
        assert!(is_traversal_segment("%2e%2e"), "fully encoded");
        assert!(is_traversal_segment("%2E%2E"), "uppercase encoded");
        assert!(is_traversal_segment(".%2e"), "dot then encoded dot");
        assert!(is_traversal_segment("%2e."), "encoded dot then dot");
        assert!(
            !is_traversal_segment("."),
            "a single dot is not a traversal"
        );
        assert!(
            !is_traversal_segment("..config"),
            "a name beginning with dots is not"
        );
        assert!(
            !is_traversal_segment("%2e%2e%2e"),
            "three encoded dots are not"
        );
        assert!(
            !is_traversal_segment("..%2f"),
            "an encoded separator does not extend it"
        );
        assert!(!is_traversal_segment("%2"), "a truncated escape is not");
        assert!(!is_traversal_segment(".%"), "a bare percent sign is not");
    }

    #[test]
    fn the_mirrored_gateway_rewrite_agrees_case_for_case() {
        // What this pins: this function still agrees with the gateway's
        // `normalize_rewritten_path` case for case, so the duplicated rewrite
        // has not drifted from the one it was copied from. The corpus is that
        // function's own, from its rules and its test suite, with its outputs
        // written out here because this crate cannot depend on it.
        //
        // What this does not pin: how PPE selects a route. The gateway applies
        // `normalize_rewritten_path` to paths it produced itself and never to
        // an inbound one, so agreement here says nothing about route
        // selection. PPE agrees with the router by matching on the path as
        // given; the tests for that live in `config.rs`.
        //
        // Inputs carrying a query, a fragment, path parameters, or no leading
        // slash are excluded: those three strips, the non-absolute rule, and
        // the refusal of a parameterized dot segment are this module's five
        // deliberate departures, pinned by their own tests above.
        let corpus = [
            ("/a/b/c", "/a/b/c"),
            ("/", "/"),
            ("/a/../b", "/b"),
            ("/a/./b", "/a/b"),
            ("/a//b", "/a/b"),
            ("/a///b", "/a/b"),
            ("/../../../etc/passwd", "/etc/passwd"),
            ("/a/../../..", "/"),
            ("/a/b/..", "/a"),
            ("/a/b/.", "/a/b"),
            ("/a/.", "/a"),
            ("/a//../b//c/../d", "/b/d"),
            ("/..", "/"),
            ("///", "/"),
            ("/a/%2e%2e/b", "/b"),
            ("/a/%2E%2E/b", "/b"),
            ("/a/.%2e/b", "/b"),
            ("/a/%2e./b", "/b"),
            ("/a%2fb", "/a%2fb"),
            ("/a/..config", "/a/..config"),
            ("/a/%2e%2e%2e", "/a/%2e%2e%2e"),
        ];
        for (raw, expected) in corpus {
            assert_eq!(
                normalized(raw),
                expected,
                "{raw} must normalize the way the gateway normalizes it"
            );
        }
        // A long run of encoded dots is a name, not a traversal, and the
        // gateway leaves it alone.
        let long = format!("/a/{}", "%2e".repeat(258));
        assert_eq!(
            normalized(&long),
            long,
            "a long encoded dot segment is an ordinary name"
        );
    }
}
