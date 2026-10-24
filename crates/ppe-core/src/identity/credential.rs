// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::HashMap;

use crate::extensions::raw_credentials::Credential;
use crate::hooks::payload::Extensions;
use crate::http_credential;

/// Where the credential sits, and what marks it as this resolver's.
///
/// Use a prefix to select which resolver handles a credential when several
/// key populations share a route. The prefix may include an auth scheme,
/// which is stripped before the key is presented for lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLocation {
    /// The wire location.
    pub credential: Credential,

    /// What the value must start with to be one this resolver services.
    ///
    /// A prefix such as `Bearer sk-oai-` accepts `Bearer sk-oai-abc` and
    /// yields `sk-oai-abc`. The auth scheme is case-insensitive; the key
    /// leader is case-sensitive and stays in the presented credential.
    /// A prefix without a space is entirely a key leader. `None` accepts
    /// every value at the configured location.
    pub prefix: Option<String>,
}

/// Outcome of reading a configured credential location.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum Extraction {
    /// A credential this resolver services.
    Found,

    /// Nothing was supplied at the configured location.
    ///
    /// Denies as `auth.missing_credential`.
    Missing,

    /// The location held a value and it was empty.
    ///
    /// Denies as `auth.empty_credential`.
    Empty,

    /// The location held a value that does not carry this resolver's
    /// prefix.
    ///
    /// This resolver declines without denying the request, so another
    /// resolver can handle the credential.
    WrongPrefix,

    /// The credential name appeared more than once, or multiple
    /// same-logical-header entries with different casing exist.
    ///
    /// Denies as `auth.ambiguous_credential`.
    Ambiguous,

    /// The credential input is structurally malformed — a parse
    /// failure that is neither missing nor ambiguous.
    ///
    /// Denies as `auth.malformed_credential`.
    Malformed,
}

fn strip_prefix_ignore_case<'v>(value: &'v str, prefix: &str) -> Option<&'v str> {
    let (head, tail) = value.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

fn map_parse_error(e: http_credential::CredentialParseError) -> Extraction {
    use http_credential::CredentialParseError;
    match e {
        CredentialParseError::Duplicate { .. } => Extraction::Ambiguous,
        _ => Extraction::Malformed,
    }
}

impl CredentialLocation {
    /// Pair a location with the prefix that gates it.
    pub fn new(credential: Credential, prefix: Option<String>) -> Self {
        Self { credential, prefix }
    }

    /// The name of the wire location, whatever kind it is.
    pub fn name(&self) -> &str {
        match &self.credential {
            Credential::Header { name }
            | Credential::Cookie { name }
            | Credential::QueryParam { name } => name,
        }
    }

    /// Read a credential from headers or a raw query string. Header names
    /// are matched without ASCII case; the configured prefix selects which
    /// credentials this resolver handles.
    ///
    /// # Errors
    ///
    /// Returns an `Extraction` outcome when the credential is missing,
    /// empty, ambiguous, malformed, or belongs to another resolver.
    pub fn raw(
        &self,
        headers: &HashMap<String, String>,
        raw_query_string: Option<&str>,
    ) -> Result<String, Extraction> {
        match &self.credential {
            Credential::Header { name } => self.extract_header(headers, name),
            Credential::Cookie { name } => self.extract_cookie(headers, name),
            Credential::QueryParam { name } => self.extract_query_param(raw_query_string, name),
        }
    }

    fn extract_header(
        &self,
        headers: &HashMap<String, String>,
        name: &str,
    ) -> Result<String, Extraction> {
        let name_lc = name.to_ascii_lowercase();
        let matches: Vec<&str> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(&name_lc))
            .map(|(_, v)| v.as_str())
            .collect();

        let raw = match matches.as_slice() {
            [single] => single,
            [] => return Err(Extraction::Missing),
            _ => return Err(Extraction::Ambiguous),
        };

        self.gate(raw).map(str::to_owned)
    }

    fn extract_cookie(
        &self,
        headers: &HashMap<String, String>,
        name: &str,
    ) -> Result<String, Extraction> {
        let cookie_values: Vec<&str> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.as_str())
            .collect();

        let cookie_header = match cookie_values.as_slice() {
            [single] => single,
            [] => return Err(Extraction::Missing),
            _ => return Err(Extraction::Ambiguous),
        };

        let cookies =
            http_credential::parse_cookie_header(cookie_header, name).map_err(map_parse_error)?;

        match cookies.get(name) {
            None => Err(Extraction::Missing),
            Some(v) if v.is_empty() => Err(Extraction::Empty),
            Some(v) => self.gate(v).map(str::to_owned),
        }
    }

    fn extract_query_param(
        &self,
        raw_query_string: Option<&str>,
        name: &str,
    ) -> Result<String, Extraction> {
        let Some(qs) = raw_query_string else {
            return Err(Extraction::Missing);
        };

        let params = http_credential::parse_query_string(qs, name).map_err(map_parse_error)?;

        match params.get(name) {
            None => Err(Extraction::Missing),
            Some(v) if v.is_empty() => Err(Extraction::Empty),
            Some(v) => self.gate(v).map(str::to_owned),
        }
    }

    fn gate<'v>(&self, raw: &'v str) -> Result<&'v str, Extraction> {
        let after = match self.prefix.as_deref() {
            Some(prefix) => Self::strip_gate(raw, prefix)?,
            None => raw,
        };
        if after.is_empty() {
            return Err(Extraction::Empty);
        }
        Ok(after)
    }

    fn strip_gate<'v>(raw: &'v str, prefix: &str) -> Result<&'v str, Extraction> {
        let Some((scheme, leader)) = prefix.split_once(' ') else {
            return raw
                .starts_with(prefix)
                .then_some(raw)
                .ok_or(Extraction::WrongPrefix);
        };

        let after_scheme = strip_prefix_ignore_case(raw, scheme).ok_or(Extraction::WrongPrefix)?;
        let credential = after_scheme.trim_start_matches(' ');
        if credential.len() == after_scheme.len() {
            return Err(Extraction::WrongPrefix);
        }

        credential
            .starts_with(leader.trim_start_matches(' '))
            .then_some(credential)
            .ok_or(Extraction::WrongPrefix)
    }

    /// What reading the configured location produced.
    pub fn extract(
        &self,
        headers: &HashMap<String, String>,
        raw_query_string: Option<&str>,
    ) -> Extraction {
        match self.raw(headers, raw_query_string) {
            Ok(_) => Extraction::Found,
            Err(outcome) => outcome,
        }
    }

    /// Read a credential using the query string in `Extensions.http.query`.
    ///
    /// # Errors
    ///
    /// Returns an `Extraction` outcome when the credential is missing,
    /// empty, ambiguous, malformed, or belongs to another resolver.
    pub fn raw_from_ext(
        &self,
        headers: &HashMap<String, String>,
        ext: &Extensions,
    ) -> Result<String, Extraction> {
        let query = ext.http.as_ref().and_then(|h| h.query.as_deref());
        self.raw(headers, query)
    }

    /// Validate a credential name and optional prefix before use.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty name or prefix, invalid name
    /// characters, or a prefix starting with a space.
    pub fn validate(&self) -> Result<(), String> {
        let (kind, name) = match &self.credential {
            Credential::Header { name } => ("header", name.as_str()),
            Credential::Cookie { name } => ("cookie", name.as_str()),
            Credential::QueryParam { name } => ("query_param", name.as_str()),
        };

        if name.trim().is_empty() {
            return Err(format!(
                "`credential: {{ kind: {kind} }}` name must be non-empty"
            ));
        }
        if name != name.trim() || name.contains(char::is_whitespace) {
            return Err(format!(
                "`credential: {{ kind: {kind}, name: '{name}' }}` \
                 must not contain leading, trailing, or interior whitespace"
            ));
        }
        if matches!(self.credential, Credential::Cookie { .. }) && name.contains(['=', ';']) {
            return Err(format!(
                "`credential: {{ kind: cookie, name: '{name}' }}` must not contain '=' or ';'"
            ));
        }
        if matches!(self.credential, Credential::QueryParam { .. }) && name.contains(['&', '=']) {
            return Err(format!(
                "`credential: {{ kind: query_param, name: '{name}' }}` \
                 must not contain '&' or '='"
            ));
        }
        if self.prefix.as_ref().is_some_and(String::is_empty) {
            return Err(format!(
                "{}: `prefix` is present and empty, which gates nothing. Remove it to accept \
                 every value at this location",
                self.credential
            ));
        }
        if self.prefix.as_ref().is_some_and(|p| p.starts_with(' ')) {
            return Err(format!(
                "{}: `prefix` starts with a space, which no value can match",
                self.credential
            ));
        }
        Ok(())
    }
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
    fn new_constructs_with_all_credential_variants() {
        let header = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer ".into()),
        );
        assert_eq!(header.name(), "Authorization");

        let cookie = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        assert_eq!(cookie.name(), "__Host-jwt");

        let query = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        assert_eq!(query.name(), "access_token");
    }

    #[test]
    fn extraction_variants_are_reachable() {
        for variant in [
            Extraction::Found,
            Extraction::Missing,
            Extraction::Empty,
            Extraction::WrongPrefix,
            Extraction::Ambiguous,
            Extraction::Malformed,
        ] {
            let _debug = format!("{variant:?}");
        }
    }

    #[test]
    fn strip_prefix_ignore_case_preserves_existing_behavior() {
        assert_eq!(
            strip_prefix_ignore_case("Bearer tok", "Bearer"),
            Some(" tok")
        );
        assert_eq!(
            strip_prefix_ignore_case("bearer tok", "Bearer"),
            Some(" tok")
        );
        assert_eq!(
            strip_prefix_ignore_case("BEARER tok", "Bearer"),
            Some(" tok")
        );
        assert_eq!(strip_prefix_ignore_case("Basic tok", "Bearer"), None);
        assert_eq!(strip_prefix_ignore_case("Be", "Bearer"), None);
    }

    #[test]
    fn prefix_gate_scheme_only() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer ".into()),
        );
        assert_eq!(loc.gate("Bearer tok").unwrap(), "tok");
        assert_eq!(loc.gate("bearer tok").unwrap(), "tok");
        assert_eq!(loc.gate("bearer   tok").unwrap(), "tok");
        assert_eq!(loc.gate("Basic tok"), Err(Extraction::WrongPrefix));
    }

    #[test]
    fn prefix_gate_leader_only() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "x-api-key".into(),
            },
            Some("sk-oai-".into()),
        );
        assert_eq!(loc.gate("sk-oai-abc").unwrap(), "sk-oai-abc");
        assert_eq!(loc.gate("pk-live-abc"), Err(Extraction::WrongPrefix));
    }

    #[test]
    fn prefix_gate_scheme_plus_leader() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer sk-oai-".into()),
        );
        assert_eq!(loc.gate("Bearer sk-oai-abc").unwrap(), "sk-oai-abc");
        assert_eq!(loc.gate("bearer sk-oai-abc").unwrap(), "sk-oai-abc");
        assert_eq!(loc.gate("Bearer pk-live-abc"), Err(Extraction::WrongPrefix));
    }

    #[test]
    fn prefix_gate_no_prefix() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "x-api-key".into(),
            },
            None,
        );
        assert_eq!(loc.gate("any-value").unwrap(), "any-value");
        assert_eq!(loc.gate(""), Err(Extraction::Empty));
    }

    #[test]
    fn header_extraction_round_trip() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some("Bearer ".into()),
        );
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "Bearer my-jwt".to_owned());

        assert_eq!(loc.raw(&headers, None).unwrap(), "my-jwt");
        assert_eq!(loc.extract(&headers, None), Extraction::Found);
    }

    #[test]
    fn header_extraction_missing() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Missing));
    }

    #[test]
    fn header_extraction_empty() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "x-api-key".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_owned(), String::new());
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Empty));
    }

    #[test]
    fn cookie_extraction_happy_path() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            "analytics=x; __Host-jwt=eyJ.tok.sig; theme=dark".to_owned(),
        );
        assert_eq!(loc.raw(&headers, None).unwrap(), "eyJ.tok.sig");
    }

    #[test]
    fn cookie_extraction_missing_cookie_header() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Missing));
    }

    #[test]
    fn cookie_extraction_missing_credential_cookie() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "analytics=x; theme=dark".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Missing));
    }

    #[test]
    fn cookie_extraction_empty_value() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "session".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "session=".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Empty));
    }

    #[test]
    fn query_param_extraction_happy_path() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        assert_eq!(
            loc.raw(&headers, Some("page=1&access_token=eyJ.tok&limit=10"))
                .unwrap(),
            "eyJ.tok"
        );
    }

    #[test]
    fn query_param_extraction_no_query_string() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Missing));
    }

    #[test]
    fn query_param_extraction_missing_param() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("page=1&limit=10")),
            Err(Extraction::Missing)
        );
    }

    #[test]
    fn query_param_extraction_empty_value() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("access_token=")),
            Err(Extraction::Empty)
        );
    }

    #[test]
    fn validate_accepts_all_variants() {
        for cred in [
            Credential::Header {
                name: "Authorization".into(),
            },
            Credential::Cookie {
                name: "__Host-jwt".into(),
            },
            Credential::QueryParam {
                name: "access_token".into(),
            },
        ] {
            let loc = CredentialLocation::new(cred, None);
            loc.validate().unwrap();
        }
    }

    #[test]
    fn validate_rejects_empty_name() {
        for cred in [
            Credential::Header {
                name: String::new(),
            },
            Credential::Cookie { name: "  ".into() },
            Credential::QueryParam {
                name: String::new(),
            },
        ] {
            let loc = CredentialLocation::new(cred, None);
            assert!(loc.validate().is_err());
        }
    }

    #[test]
    fn validate_rejects_whitespace_in_name() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "X Api Key".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());

        let loc = CredentialLocation::new(
            Credential::Header {
                name: " Authorization".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_cookie_with_equals_or_semicolon() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "bad=name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());

        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "bad;name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_query_param_with_ampersand_or_equals() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "bad&name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());

        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "bad=name".into(),
            },
            None,
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_prefix() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some(String::new()),
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn validate_rejects_leading_space_prefix() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            Some(" Bearer".into()),
        );
        assert!(loc.validate().is_err());
    }

    #[test]
    fn header_duplicate_casing_returns_ambiguous() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "Bearer tok1".to_owned());
        headers.insert("Authorization".to_owned(), "Bearer tok2".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Ambiguous));
    }

    #[test]
    fn cookie_duplicate_header_casing_returns_ambiguous() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "session".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "session=abc".to_owned());
        headers.insert("Cookie".to_owned(), "session=def".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Ambiguous));
    }

    #[test]
    fn cookie_duplicate_credential_name_returns_ambiguous() {
        let loc = CredentialLocation::new(Credential::Cookie { name: "jwt".into() }, None);
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "jwt=a; jwt=b".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Ambiguous));
    }

    #[test]
    fn query_param_duplicate_name_returns_ambiguous() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("token=a&token=b")),
            Err(Extraction::Ambiguous)
        );
    }

    #[test]
    fn query_param_percent_encoded_name_returns_malformed() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "access_token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("access%5Ftoken=eyJ.tok")),
            Err(Extraction::Malformed)
        );
    }

    #[test]
    fn cookie_control_character_returns_malformed() {
        let loc = CredentialLocation::new(Credential::Cookie { name: "jwt".into() }, None);
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "jwt=a\r\nInjected: header".to_owned());
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Malformed));
    }

    #[test]
    fn cookie_extraction_with_prefix_gate() {
        let loc = CredentialLocation::new(
            Credential::Cookie {
                name: "api_key".into(),
            },
            Some("sk-oai-".into()),
        );
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "api_key=sk-oai-secret".to_owned());
        assert_eq!(loc.raw(&headers, None).unwrap(), "sk-oai-secret");
    }

    #[test]
    fn query_param_extraction_with_prefix_gate() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            Some("sk-".into()),
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("token=sk-abc123")).unwrap(),
            "sk-abc123"
        );
    }

    #[test]
    fn query_param_wrong_prefix_returns_wrong_prefix() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            Some("sk-".into()),
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("token=pk-abc123")),
            Err(Extraction::WrongPrefix)
        );
    }

    #[test]
    fn extract_returns_ambiguous_for_duplicate_headers() {
        let loc = CredentialLocation::new(
            Credential::Header {
                name: "Authorization".into(),
            },
            None,
        );
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "tok1".to_owned());
        headers.insert("Authorization".to_owned(), "tok2".to_owned());
        assert_eq!(loc.extract(&headers, None), Extraction::Ambiguous);
    }

    #[test]
    fn extract_returns_malformed_for_control_character_cookie() {
        let loc = CredentialLocation::new(Credential::Cookie { name: "jwt".into() }, None);
        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), "jwt=a\r\nEvil: header".to_owned());
        assert_eq!(loc.extract(&headers, None), Extraction::Malformed);
    }

    #[test]
    fn oversize_cookie_returns_malformed() {
        let loc = CredentialLocation::new(Credential::Cookie { name: "jwt".into() }, None);
        let mut headers = HashMap::new();
        let oversize = format!("jwt={}", "x".repeat(16 * 1024 + 1));
        headers.insert("cookie".to_owned(), oversize);
        assert_eq!(loc.raw(&headers, None), Err(Extraction::Malformed));
        assert_eq!(loc.extract(&headers, None), Extraction::Malformed);
    }

    #[test]
    fn oversize_query_string_returns_malformed() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        let oversize = format!("token={}", "x".repeat(16 * 1024 + 1));
        assert_eq!(
            loc.raw(&headers, Some(&oversize)),
            Err(Extraction::Malformed)
        );
        assert_eq!(
            loc.extract(&headers, Some(&oversize)),
            Extraction::Malformed
        );
    }

    #[test]
    fn query_param_empty_string_is_missing() {
        let loc = CredentialLocation::new(
            Credential::QueryParam {
                name: "token".into(),
            },
            None,
        );
        let headers = HashMap::new();
        assert_eq!(
            loc.raw(&headers, Some("")),
            Err(Extraction::Missing),
            "an empty query string has no parameters"
        );
    }
}
