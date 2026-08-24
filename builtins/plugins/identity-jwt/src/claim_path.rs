// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Claim paths address a value inside a validated claim set by
// dot-separated segments. Only `.` and `\` are special, which is what
// makes real claim names reachable: `cognito:groups`,
// `custom:department`, and `https://my-app.example.com/roles` are all
// single segments, the last one written with escaped dots.

use std::collections::HashMap;
use std::fmt;

use serde_json::Value;

/// A parsed claim path: the segments to walk to reach one claim value.
///
/// Parse once at construction with [`ClaimPath::parse`], then
/// [`ClaimPath::resolve`] on the request path. Nothing parses a path per
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPath {
    segments: Vec<String>,
}

impl ClaimPath {
    /// Parse an authored path.
    ///
    /// `.` separates segments. `\.` is a literal dot and `\\` a literal
    /// backslash; every other character is a literal, `:` and `/` included.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending path when it is empty, has an
    /// empty segment (`a..b`, `.a`, `a.`), ends in a lone `\`, or carries an
    /// escape other than `\.` or `\\`. The caller prepends the field name,
    /// since only it knows which field the path was written for.
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut segments: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut chars = input.chars();

        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('.') => current.push('.'),
                    Some('\\') => current.push('\\'),
                    Some(other) => {
                        return Err(format!(
                            "path '{input}': unrecognized escape `\\{other}`; only `\\.` and \
                             `\\\\` are escapes"
                        ));
                    },
                    None => {
                        return Err(format!("path '{input}': trailing `\\` escapes nothing"));
                    },
                },
                '.' => {
                    if current.is_empty() {
                        return Err(format!("path '{input}': empty segment"));
                    }
                    segments.push(std::mem::take(&mut current));
                },
                other => current.push(other),
            }
        }

        if current.is_empty() {
            return Err(if segments.is_empty() {
                "path is empty".to_owned()
            } else {
                format!("path '{input}': empty segment")
            });
        }
        segments.push(current);

        Ok(Self { segments })
    }

    /// Resolve against a claim set, or `None` when the path leads nowhere.
    ///
    /// A path crossing a scalar or an array resolves to `None`: traversal
    /// needs objects, and array indexing is not part of the grammar. A claim
    /// whose value is JSON `null` resolves to `Some(Value::Null)`, which is
    /// distinct from absent.
    pub fn resolve<'a>(&self, claims: &'a HashMap<String, Value>) -> Option<&'a Value> {
        let (first, rest) = self.segments.split_first()?;
        let mut current = claims.get(first)?;
        for segment in rest {
            current = current.get(segment.as_str())?;
        }
        Some(current)
    }

    /// The path's segments, already unescaped.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// The single segment this path consumes whole, or `None` when it
    /// traverses.
    ///
    /// The claims bag excludes a claim a single-segment path consumed and
    /// leaves a traversed parent intact, so it needs to tell the two apart.
    pub fn single_segment(&self) -> Option<&str> {
        match self.segments.as_slice() {
            [only] => Some(only.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for ClaimPath {
    /// Render the path back in authored form, re-escaping `.` and `\` so a
    /// diagnostic echoes what the operator wrote.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.segments.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            for c in segment.chars() {
                match c {
                    '.' => f.write_str("\\.")?,
                    '\\' => f.write_str("\\\\")?,
                    other => write!(f, "{other}")?,
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(value: Value) -> HashMap<String, Value> {
        value.as_object().unwrap().clone().into_iter().collect()
    }

    fn parse(input: &str) -> ClaimPath {
        ClaimPath::parse(input).unwrap_or_else(|e| panic!("'{input}' should parse: {e}"))
    }

    fn segments(input: &str) -> Vec<String> {
        parse(input).segments().to_vec()
    }

    // ---- traversal --------------------------------------------------------

    #[test]
    fn a_single_segment_resolves_a_top_level_claim() {
        let claims = claims(json!({"sub": "alice"}));
        assert_eq!(parse("sub").resolve(&claims), Some(&json!("alice")));
    }

    #[test]
    fn a_dotted_path_traverses_into_a_nested_object() {
        let claims = claims(json!({"realm_access": {"roles": ["admin", "hr"]}}));
        assert_eq!(
            parse("realm_access.roles").resolve(&claims),
            Some(&json!(["admin", "hr"])),
        );
    }

    #[test]
    fn a_three_deep_path_resolves() {
        let claims = claims(json!({"a": {"b": {"c": "deep"}}}));
        assert_eq!(parse("a.b.c").resolve(&claims), Some(&json!("deep")));
    }

    /// A colon is not a separator, so a Cognito claim name is one segment and
    /// needs no escaping.
    #[test]
    fn a_colon_is_a_literal_and_needs_no_escape() {
        assert_eq!(segments("cognito:groups"), vec!["cognito:groups"]);
        let claims = claims(json!({"cognito:groups": ["eng"]}));
        assert_eq!(
            parse("cognito:groups").resolve(&claims),
            Some(&json!(["eng"])),
        );
    }

    /// Auth0's documented namespaced-claim name, verbatim: the whole URL is
    /// the claim name, so every dot in it is escaped and the slashes are not.
    #[test]
    fn an_escaped_url_claim_name_is_one_segment() {
        let authored = "https://my-app\\.example\\.com/roles";
        assert_eq!(segments(authored), vec!["https://my-app.example.com/roles"],);
        let claims = claims(json!({"https://my-app.example.com/roles": ["editor"]}));
        assert_eq!(parse(authored).resolve(&claims), Some(&json!(["editor"])));
    }

    /// Auth0 also documents a namespace with no path segment, where the claim
    /// name is a bare URL.
    #[test]
    fn a_url_claim_name_with_no_path_segment_resolves() {
        let authored = "https://namespace\\.exampleco\\.com";
        let claims = claims(json!({"https://namespace.exampleco.com": "value"}));
        assert_eq!(parse(authored).resolve(&claims), Some(&json!("value")));
    }

    #[test]
    fn a_doubled_backslash_is_one_literal_backslash() {
        assert_eq!(segments("a\\\\b"), vec!["a\\b"]);
        let claims = claims(json!({"a\\b": 1}));
        assert_eq!(parse("a\\\\b").resolve(&claims), Some(&json!(1)));
    }

    /// A Kubernetes projected `ServiceAccount` token puts a dot inside a
    /// top-level claim name whose value is an object, so one path needs an
    /// escaped dot and then real traversal.
    #[test]
    fn an_escaped_dot_and_traversal_combine_in_one_path() {
        let authored = "kubernetes\\.io.serviceaccount.name";
        assert_eq!(
            segments(authored),
            vec!["kubernetes.io", "serviceaccount", "name"],
        );
        let claims = claims(json!({
            "sub": "system:serviceaccount:default:agent",
            "kubernetes.io": {
                "namespace": "default",
                "serviceaccount": {"name": "agent", "uid": "b3c1"},
            },
        }));
        assert_eq!(parse(authored).resolve(&claims), Some(&json!("agent")));
    }

    /// Characters that are neither `.` nor `\` are literals wherever they
    /// appear, including inside a traversed leaf segment.
    #[test]
    fn non_separator_characters_need_no_escaping() {
        let claims = claims(json!({
            "cognito:groups": ["eng"],
            "custom:department": "platform",
            "allowed-origins": ["https://app.example"],
            "trusted-certs": [],
            "cnf": {"x5t#S256": "abc123"},
        }));
        assert_eq!(
            parse("custom:department").resolve(&claims),
            Some(&json!("platform")),
        );
        assert_eq!(
            parse("allowed-origins").resolve(&claims),
            Some(&json!(["https://app.example"])),
        );
        assert_eq!(parse("trusted-certs").resolve(&claims), Some(&json!([])));
        assert_eq!(
            parse("cnf.x5t#S256").resolve(&claims),
            Some(&json!("abc123")),
        );
    }

    // ---- resolution misses ------------------------------------------------

    #[test]
    fn an_unmatched_first_segment_resolves_to_none() {
        let claims = claims(json!({"sub": "alice"}));
        assert!(parse("roles").resolve(&claims).is_none());
    }

    #[test]
    fn a_path_crossing_a_scalar_resolves_to_none() {
        let claims = claims(json!({"sub": "alice"}));
        assert!(parse("sub.x").resolve(&claims).is_none());
    }

    /// Array indexing is not part of the grammar, so a numeric segment against
    /// an array is a miss rather than an element.
    #[test]
    fn a_path_into_an_array_resolves_to_none() {
        let claims = claims(json!({"roles": ["admin"]}));
        assert!(parse("roles.0").resolve(&claims).is_none());
    }

    /// A `null`-valued claim is present. Callers decide it is unusable for
    /// their field; the path resolver must not conflate it with absence.
    #[test]
    fn a_null_claim_resolves_to_null_rather_than_absent() {
        let claims = claims(json!({"teams": Value::Null}));
        assert_eq!(parse("teams").resolve(&claims), Some(&Value::Null));
    }

    // ---- rejection --------------------------------------------------------

    #[test]
    fn a_trailing_lone_escape_is_rejected() {
        let err = ClaimPath::parse("roles\\").expect_err("a trailing `\\` escapes nothing");
        assert!(err.contains("roles\\"), "message must echo the path: {err}");
        assert!(err.contains("trailing"), "{err}");
    }

    #[test]
    fn an_unrecognized_escape_is_rejected_and_named() {
        let err = ClaimPath::parse("roles\\x").expect_err("`\\x` is not an escape");
        assert!(err.contains("\\x"), "message must name the escape: {err}");
    }

    /// Escaping a colon is the likely mistake for anyone who reaches for a
    /// backslash on sight of a URL. It is rejected rather than accepted as the
    /// colon, so the operator learns the rule at load instead of debugging a
    /// path that quietly addresses a different claim name.
    #[test]
    fn an_escaped_colon_is_rejected_because_a_colon_is_already_a_literal() {
        let err = ClaimPath::parse("https\\://my-app\\.example\\.com/roles")
            .expect_err("`\\:` is not an escape");
        assert!(err.contains("\\:"), "message must name the escape: {err}");
    }

    #[test]
    fn an_empty_path_is_rejected() {
        let err = ClaimPath::parse("").expect_err("an empty path addresses nothing");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn an_empty_segment_is_rejected_wherever_it_appears() {
        for input in ["a..b", ".a", "a."] {
            let err = ClaimPath::parse(input)
                .expect_err("a path with an empty segment addresses nothing");
            assert!(
                err.contains("empty segment"),
                "'{input}' must be rejected as an empty segment, got: {err}"
            );
        }
    }

    // ---- display ----------------------------------------------------------

    /// `Display` echoes the authored form, not the resolved text, so a
    /// diagnostic naming a tried path matches what the operator wrote.
    #[test]
    fn display_round_trips_every_accepted_path() {
        for authored in [
            "sub",
            "realm_access.roles",
            "a.b.c",
            "cognito:groups",
            "custom:department",
            "allowed-origins",
            "cnf.x5t#S256",
            "https://my-app\\.example\\.com/roles",
            "https://namespace\\.exampleco\\.com",
            "a\\\\b",
            "kubernetes\\.io.serviceaccount.name",
        ] {
            assert_eq!(parse(authored).to_string(), authored);
        }
    }

    #[test]
    fn single_segment_distinguishes_a_consumed_claim_from_a_traversed_one() {
        assert_eq!(parse("roles").single_segment(), Some("roles"));
        assert_eq!(
            parse("https://my-app\\.example\\.com/roles").single_segment(),
            Some("https://my-app.example.com/roles"),
        );
        assert!(parse("realm_access.roles").single_segment().is_none());
    }
}
