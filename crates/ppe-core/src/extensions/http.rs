// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// HttpExtension — HTTP request and response headers, the request line, and
// the response status.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize, Serializer};

/// Engine-recorded provenance for secret assertion headers. Contains no secret values.
#[derive(Debug, Clone, Default)]
pub struct SecretHeaderProvenance {
    pub(crate) markers: HashMap<String, String>,
}

/// HTTP-related extensions.
///
/// Carries both request and response headers separately. The host
/// populates what's available at each hook point:
/// - Pre-invoke: `request_headers` filled, `response_headers` empty, `status` unset
/// - Post-invoke: both header maps filled (request from original, response from
///   upstream) and `status` set to the status the upstream returned
///
/// Capability-gated: requires `read_headers` to see, `write_headers`
/// to modify (both request and response). Secret assertions are withheld from
/// plugin views, `Debug`, and serialization.
#[derive(Clone, Default, Deserialize)]
pub struct HttpExtension {
    /// HTTP request headers (inbound from caller).
    #[serde(default)]
    pub request_headers: HashMap<String, String>,

    /// Preserve across hooks. Plugins cannot replace canonical provenance.
    #[serde(skip)]
    pub secret_headers: SecretHeaderProvenance,

    /// HTTP response headers (from upstream, populated post-invoke).
    #[serde(default)]
    pub response_headers: HashMap<String, String>,

    /// HTTP response status the upstream returned (e.g. `200`, `502`).
    /// The host populates this on the response invocation only, so it is
    /// `None` on the request half, where no status exists yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,

    /// HTTP request method (e.g. `GET`, `POST`). Set by the host when
    /// the request is HTTP; `None` for non-HTTP transports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// HTTP request path (e.g. `/api/v1/widgets`). Excludes the query
    /// string unless the host chooses to include it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// HTTP request authority/host. The host MUST populate this from a
    /// validated authority (e.g. the HTTP/2 `:authority` pseudo-header),
    /// never a raw client-supplied `Host` header, so host-based policy
    /// is not bypassable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// HTTP request scheme (`http` / `https`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

// Both diagnostics and serialization use the same safe header map as plugin views.
#[derive(Debug, Serialize)]
#[serde(rename = "HttpExtension")]
struct HttpView<'a> {
    request_headers: Cow<'a, HashMap<String, String>>,
    response_headers: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheme: Option<&'a str>,
}

impl Serialize for HttpExtension {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.view().serialize(serializer)
    }
}

impl fmt::Debug for HttpExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.view().fmt(f)
    }
}

impl HttpExtension {
    fn view(&self) -> HttpView<'_> {
        HttpView {
            request_headers: self.redacted_request_headers(),
            response_headers: &self.response_headers,
            status: self.status,
            method: self.method.as_deref(),
            path: self.path.as_deref(),
            host: self.host.as_deref(),
            scheme: self.scheme.as_deref(),
        }
    }

    pub(crate) fn redacted_request_headers(&self) -> Cow<'_, HashMap<String, String>> {
        if self.secret_headers.markers.is_empty() {
            return Cow::Borrowed(&self.request_headers);
        }
        Cow::Owned(
            self.request_headers
                .iter()
                .map(|(name, value)| {
                    let value = self
                        .secret_headers
                        .markers
                        .get(&name.to_ascii_lowercase())
                        .unwrap_or(value);
                    (name.clone(), value.clone())
                })
                .collect(),
        )
    }

    // -- Request header helpers --

    /// Set a request header (overwrites if exists).
    pub fn set_request_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.request_headers.insert(name.into(), value.into());
    }

    /// Get a request header value (case-insensitive lookup).
    pub fn get_request_header(&self, name: &str) -> Option<&str> {
        get_header_ci(&self.request_headers, name)
    }

    /// Check if a request header exists (case-insensitive).
    pub fn has_request_header(&self, name: &str) -> bool {
        self.get_request_header(name).is_some()
    }

    /// Add request header only if it doesn't exist. Returns true if added.
    pub fn add_request_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> bool {
        let name = name.into();
        if self.has_request_header(&name) {
            return false;
        }
        self.request_headers.insert(name, value.into());
        true
    }

    /// Remove a request header by name. Returns the removed value.
    pub fn remove_request_header(&mut self, name: &str) -> Option<String> {
        remove_header_ci(&mut self.request_headers, name)
    }

    // -- Response header helpers --

    /// Set a response header (overwrites if exists).
    pub fn set_response_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.response_headers.insert(name.into(), value.into());
    }

    /// Get a response header value (case-insensitive lookup).
    pub fn get_response_header(&self, name: &str) -> Option<&str> {
        get_header_ci(&self.response_headers, name)
    }

    /// Check if a response header exists (case-insensitive).
    pub fn has_response_header(&self, name: &str) -> bool {
        self.get_response_header(name).is_some()
    }

    // -- Convenience aliases (backward-compatible, default to request) --

    /// Set a header on request headers (convenience alias).
    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.set_request_header(name, value);
    }

    /// Get a header from request headers (convenience alias, case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.get_request_header(name)
    }

    /// Check if a request header exists (convenience alias).
    pub fn has_header(&self, name: &str) -> bool {
        self.has_request_header(name)
    }
}

// -- Internal helpers --

fn get_header_ci<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    let lower = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == lower)
        .map(|(_, v)| v.as_str())
}

fn remove_header_ci(headers: &mut HashMap<String, String>, name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    let key = headers.keys().find(|k| k.to_lowercase() == lower).cloned();
    key.and_then(|k| headers.remove(&k))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
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
    fn test_request_header_set_and_get() {
        let mut http = HttpExtension::default();
        http.set_request_header("Content-Type", "application/json");
        assert_eq!(
            http.get_request_header("Content-Type"),
            Some("application/json")
        );
    }

    #[test]
    fn test_request_header_case_insensitive() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer tok");
        assert_eq!(http.get_request_header("authorization"), Some("Bearer tok"));
        assert_eq!(http.get_request_header("AUTHORIZATION"), Some("Bearer tok"));
    }

    #[test]
    fn test_response_header_set_and_get() {
        let mut http = HttpExtension::default();
        http.set_response_header("Content-Type", "text/html");
        assert_eq!(http.get_response_header("Content-Type"), Some("text/html"));
        assert!(http.has_response_header("content-type"));
    }

    #[test]
    fn test_request_and_response_independent() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer req-tok");
        http.set_response_header("X-Response-Time", "42ms");

        // Request headers don't leak into response
        assert!(http.get_response_header("Authorization").is_none());
        // Response headers don't leak into request
        assert!(http.get_request_header("X-Response-Time").is_none());
    }

    #[test]
    fn test_convenience_aliases_default_to_request() {
        let mut http = HttpExtension::default();
        http.set_header("X-Custom", "value");
        assert_eq!(http.get_header("X-Custom"), Some("value"));
        assert!(http.has_header("X-Custom"));
        // Verify it went to request_headers
        assert_eq!(http.get_request_header("X-Custom"), Some("value"));
    }

    #[test]
    fn test_add_request_header_only_if_absent() {
        let mut http = HttpExtension::default();
        assert!(http.add_request_header("X-New", "first"));
        assert!(!http.add_request_header("X-New", "second"));
        assert_eq!(http.get_request_header("X-New"), Some("first"));
    }

    #[test]
    fn test_remove_request_header() {
        let mut http = HttpExtension::default();
        http.set_request_header("X-Remove", "value");
        let removed = http.remove_request_header("x-remove");
        assert_eq!(removed, Some("value".to_owned()));
        assert!(!http.has_request_header("X-Remove"));
    }

    #[test]
    fn test_status_absent_from_serialized_output_when_unset() {
        // A host that never populates a status must produce the same wire
        // bytes it produced before the field existed.
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer tok");
        let json = serde_json::to_string(&http).unwrap();
        assert!(!json.contains("status"), "{json}");
        assert!(http.status.is_none());
    }

    #[test]
    fn test_status_survives_a_roundtrip() {
        let http = HttpExtension {
            status: Some(502),
            ..Default::default()
        };
        let json = serde_json::to_string(&http).unwrap();
        let back: HttpExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, Some(502));
    }

    #[test]
    fn test_status_defaults_to_none_when_the_field_is_missing() {
        // A peer serialized before the field existed still deserializes.
        let back: HttpExtension =
            serde_json::from_str(r#"{"request_headers":{},"response_headers":{}}"#).unwrap();
        assert_eq!(back.status, None);
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer tok");
        http.set_request_header("X-Request-ID", "req-123");
        http.set_response_header("Content-Type", "application/json");
        http.set_response_header("X-Response-Time", "15ms");

        let json = serde_json::to_string(&http).unwrap();
        let deserialized: HttpExtension = serde_json::from_str(&json).unwrap();

        assert_eq!(
            deserialized.get_request_header("Authorization"),
            Some("Bearer tok")
        );
        assert_eq!(
            deserialized.get_response_header("Content-Type"),
            Some("application/json")
        );
    }

    #[test]
    fn secret_headers_are_safe_in_debug_and_serialization() {
        let mut http = HttpExtension {
            status: Some(201),
            method: Some("POST".into()),
            path: Some("/tool".into()),
            host: Some("example.test".into()),
            scheme: Some("https".into()),
            ..Default::default()
        };
        http.set_request_header("X-Key", "credential");
        http.set_request_header("x-key", "credential");
        http.set_request_header("x-user", "alice");
        http.set_response_header("x-result", "ok");
        http.secret_headers
            .markers
            .insert("x-key".into(), "<redacted secret.key>".into());
        let debug = format!("{http:?}");
        let json = serde_json::to_string(&http).unwrap();
        for output in [debug, json.clone()] {
            assert!(!output.contains("credential"), "{output}");
            assert!(output.contains("<redacted secret.key>"), "{output}");
        }
        let safe: HttpExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(safe.request_headers["X-Key"], "<redacted secret.key>");
        assert_eq!(safe.request_headers["x-key"], "<redacted secret.key>");
        assert_eq!(safe.get_request_header("x-user"), Some("alice"));
        assert_eq!(safe.get_response_header("x-result"), Some("ok"));
        assert_eq!(safe.status, http.status);
        assert_eq!(safe.method, http.method);
        assert_eq!(safe.path, http.path);
        assert_eq!(safe.host, http.host);
        assert_eq!(safe.scheme, http.scheme);
        assert_eq!(http.get_request_header("x-key"), Some("credential"));
    }
}
