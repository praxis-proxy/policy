// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// HttpExtension — HTTP request and response headers, the request line, and
// the response status.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize, Serializer};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Placeholder emitted in place of a withheld value. Chosen to match the
/// redaction marker other secret request values use, so a query credential
/// reads the same in a log as a redacted header does.
const REDACTED: &str = "[REDACTED]";

/// Engine-recorded provenance for secret assertion headers. Contains no secret values.
#[derive(Debug, Clone, Default)]
pub struct SecretHeaderProvenance {
    pub(crate) markers: HashMap<String, String>,
}

/// The trusted client address a host supplies, normalized on construction.
///
/// An IPv4 address, or an IPv4-mapped IPv6 address, becomes its dotted form.
/// Any other IPv6 address becomes its /64 prefix, such as
/// `2001:db8:1:2::/64`, because one subscriber usually holds a whole /64.
/// A port is stripped, and the `<prefix>/64` form is accepted so a serialized
/// address reads back unchanged. An empty or unparseable value, or any other
/// prefix length, leaves the address unset.
/// `Debug` shows only whether an address is present.
///
/// ```
/// use praxis_policy_core::extensions::ClientAddress;
///
/// let mapped = ClientAddress::parse("[::ffff:203.0.113.7]:443");
/// assert_eq!(mapped.as_str(), Some("203.0.113.7"));
///
/// let v6 = ClientAddress::parse("2001:db8:1:2::5");
/// assert_eq!(v6.as_str(), Some("2001:db8:1:2::/64"));
///
/// assert!(ClientAddress::parse("not-an-ip").is_unset());
/// ```
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "Option<String>", into = "Option<String>")]
pub struct ClientAddress(Option<String>);

impl ClientAddress {
    /// Normalize a host-supplied address, or leave it unset when it is not one.
    pub fn parse(raw: &str) -> Self {
        let normalized = parse_ip(raw.trim()).map(normalize_ip);
        if normalized.is_none() && !raw.is_empty() {
            tracing::debug!("dropped an unparseable client address");
        }
        Self(normalized)
    }

    /// The normalized address, or `None` when unset.
    pub fn as_str(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// Whether no address is set.
    pub fn is_unset(&self) -> bool {
        self.0.is_none()
    }
}

// A client address is personal data, so logs see only its presence.
impl fmt::Debug for ClientAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClientAddress")
            .field(&self.0.as_ref().map(|_| REDACTED))
            .finish()
    }
}

// Deserialized input passes through the same normalization as host input.
impl From<Option<String>> for ClientAddress {
    fn from(raw: Option<String>) -> Self {
        raw.map_or_else(Self::default, |raw| Self::parse(&raw))
    }
}

impl From<ClientAddress> for Option<String> {
    fn from(address: ClientAddress) -> Self {
        address.0
    }
}

/// HTTP-related extensions.
///
/// Carries both request and response headers separately. The host
/// populates what's available at each hook point:
/// - Pre-invoke: `request_headers` filled, `response_headers` empty, `status` unset
/// - Post-invoke: both header maps filled (request from original, response from
///   upstream) and `status` set to the status the upstream returned
///
/// Headers and non-query request-line fields require `read_headers` to see.
/// `write_headers` permits modifying request and response headers. The raw
/// query requires `read_query`. Secret assertions are withheld from plugin
/// views, `Debug`, and serialization.
#[derive(Clone, Default, Deserialize)]
pub struct HttpExtension {
    /// HTTP request headers (inbound from caller).
    #[serde(default)]
    pub request_headers: HashMap<String, String>,

    /// Trusted client address, set with [`set_client_address`]. The host takes
    /// it from the TCP peer or a trusted proxy hop, never from a caller header.
    /// Plugins cannot change it.
    ///
    /// [`set_client_address`]: Self::set_client_address
    #[serde(default, skip_serializing_if = "ClientAddress::is_unset")]
    pub client_address: ClientAddress,

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
    /// string, which the host carries separately in [`query`](Self::query).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// HTTP request query string, WITHOUT the leading `?` (e.g.
    /// `service=git-upload-pack&foo=bar`). Separate from [`path`](Self::path)
    /// so a policy can gate on it without the path matcher ever seeing it (the
    /// path matcher normalizes a query away by design). `None` when the request
    /// carried no query; an empty string means a bare trailing `?`. The host
    /// populates this from the request-target, which is why it can distinguish
    /// two requests that share a path and differ only by query — the case a
    /// query-blind policy cannot express.
    ///
    /// Treated as potentially secret: a query can embed a credential (a
    /// query-parameter JWT, say). PDPs read the live value from the canonical
    /// attribute bag; plugin views need `read_query` to receive it. This extension's `Serialize` and
    /// `Debug` output and built-in PDP diagnostics redact it. The attribute bag
    /// itself contains the raw value and must be handled as sensitive data.
    /// Because this extension redacts on serialize, its query does not survive
    /// a serialize/deserialize round-trip: the reconstructed value is the
    /// placeholder, not the original policy input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,

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
    #[serde(skip_serializing_if = "ClientAddress::is_unset")]
    client_address: &'a ClientAddress,
    response_headers: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<&'a str>,
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
            client_address: &self.client_address,
            response_headers: &self.response_headers,
            status: self.status,
            method: self.method.as_deref(),
            path: self.path.as_deref(),
            // The query can embed a credential (a query-parameter JWT, say), so
            // it is redacted to presence-only in this view. Both
            // `Serialize` and `Debug` route through this view, so this one site
            // covers both: a present query renders as `Some("[REDACTED]")`, an
            // absent one as `None`. PDPs read the canonical attribute bag,
            // not this diagnostic/serialization view.
            query: self.query.as_ref().map(|_| REDACTED),
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

    /// The normalized client address, or `None` when the host set none.
    pub fn client_address(&self) -> Option<&str> {
        self.client_address.as_str()
    }

    /// Set the client address from the TCP peer or a trusted proxy hop.
    ///
    /// The value is normalized as [`ClientAddress::parse`] describes, and an
    /// unparseable one clears the address.
    ///
    /// [`ClientAddress::parse`]: ClientAddress::parse
    pub fn set_client_address(&mut self, raw: &str) {
        self.client_address = ClientAddress::parse(raw);
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

fn parse_ip(raw: &str) -> Option<IpAddr> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(socket) = raw.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    if let Some(prefix) = raw.strip_suffix("/64") {
        return prefix
            .parse::<Ipv6Addr>()
            .ok()
            .filter(|v6| v6.to_ipv4_mapped().is_none())
            .map(IpAddr::V6);
    }
    raw.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
        .map(IpAddr::V6)
}

fn normalize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let [a, b, c, d, ..] = v6.segments();
            format!("{}/64", Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        },
    }
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
            query: Some("service=git-upload-pack".into()),
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
        // The query is redacted on output (see the query-redaction tests), so a
        // round-trip recovers only its presence, not its value — asserted there
        // rather than here. The live value stays readable in `http` itself.
        assert_eq!(http.query.as_deref(), Some("service=git-upload-pack"));
        assert_eq!(safe.host, http.host);
        assert_eq!(safe.scheme, http.scheme);
        assert_eq!(http.get_request_header("x-key"), Some("credential"));
    }

    #[test]
    fn query_value_is_redacted_in_serialization_and_debug() {
        // A query can carry a credential (e.g. a query-parameter JWT), so its
        // VALUE must never reach serialized output, a log, or a Debug render —
        // only its presence. Both outbound paths route through the same view,
        // so this one case covers Serialize and Debug together.
        let http = HttpExtension {
            path: Some("/x/info/refs".into()),
            query: Some("access_token=super-secret-jwt&service=git-upload-pack".into()),
            ..Default::default()
        };
        let debug = format!("{http:?}");
        let json = serde_json::to_string(&http).unwrap();
        for output in [&debug, &json] {
            assert!(
                !output.contains("super-secret-jwt"),
                "query value leaked: {output}"
            );
            // Not even the non-secret part of the query is emitted: the whole
            // value is opaque, so redaction is all-or-nothing.
            assert!(
                !output.contains("git-upload-pack"),
                "query value leaked: {output}"
            );
            assert!(output.contains("[REDACTED]"), "{output}");
        }
        // The live value is still readable on the struct itself, for the host
        // and for the attribute-bag path a PDP evaluates.
        assert_eq!(
            http.query.as_deref(),
            Some("access_token=super-secret-jwt&service=git-upload-pack")
        );
    }

    #[test]
    fn query_presence_is_visible_but_value_is_not() {
        // Redaction preserves whether a query was present: a present query
        // renders as `Some("[REDACTED]")`, an absent one as `None`. A policy
        // author (or an auditor) can see that a query existed without seeing it.
        let with_query = HttpExtension {
            query: Some("access_token=secret".into()),
            ..Default::default()
        };
        let without_query = HttpExtension {
            path: Some("/x/info/refs".into()),
            ..Default::default()
        };
        assert!(format!("{with_query:?}").contains(r#"query: Some("[REDACTED]")"#));
        assert!(format!("{without_query:?}").contains("query: None"));

        // An absent query is omitted from serialized output entirely (the field
        // is `skip_serializing_if` None), so the wire form is unchanged for a
        // request that carried no query.
        let json = serde_json::to_string(&without_query).unwrap();
        assert!(!json.contains("query"), "{json}");
    }

    #[test]
    fn query_value_absent_after_serialize_roundtrip() {
        // Because the value is redacted on serialize, it cannot survive a
        // serialize -> deserialize round-trip: a peer reconstructing an
        // HttpExtension from its serialized form recovers `[REDACTED]`, never
        // the original credential. The live value is only ever carried in the
        // in-process struct the host builds, not rehydrated from the wire.
        for value in ["access_token=secret", "service=git-upload-pack", ""] {
            let http = HttpExtension {
                query: Some(value.to_owned()),
                ..Default::default()
            };
            let json = serde_json::to_string(&http).unwrap();
            let back: HttpExtension = serde_json::from_str(&json).unwrap();
            assert_eq!(
                back.query.as_deref(),
                Some("[REDACTED]"),
                "round-trip must recover the placeholder, not the value: {json}"
            );
        }
    }

    #[test]
    fn empty_query_is_redacted_not_dropped() {
        // A bare trailing `?` is a present-but-empty query (`Some("")`), which
        // is distinct from an absent one (`None`). Redaction must treat it as
        // present, so its presence is not silently lost.
        let http = HttpExtension {
            query: Some(String::new()),
            ..Default::default()
        };
        assert!(format!("{http:?}").contains(r#"query: Some("[REDACTED]")"#));
        let json = serde_json::to_string(&http).unwrap();
        assert!(json.contains("[REDACTED]"), "{json}");
    }

    #[test]
    fn ipv4_forms_normalize_to_the_bare_address() {
        for raw in [
            "203.0.113.7",
            "203.0.113.7:4431",
            "::ffff:203.0.113.7",
            "[::ffff:203.0.113.7]:443",
            " 203.0.113.7 ",
        ] {
            assert_eq!(
                ClientAddress::parse(raw).as_str(),
                Some("203.0.113.7"),
                "{raw:?} should normalize to the bare IPv4 address"
            );
        }
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_normalize_to_its_prefix() {
        for raw in [
            "[2001:db8:1:2::5]:443",
            "2001:db8:1:2:aaaa::1",
            "[2001:DB8:1:2::9]",
            "2001:0db8:0001:0002:ffff:ffff:ffff:ffff",
        ] {
            assert_eq!(
                ClientAddress::parse(raw).as_str(),
                Some("2001:db8:1:2::/64"),
                "{raw:?} should collapse to its /64 prefix"
            );
        }
        assert_eq!(
            ClientAddress::parse("2001:db8:1:3::5").as_str(),
            Some("2001:db8:1:3::/64"),
            "a neighbouring /64 must stay distinct"
        );
    }

    #[test]
    fn empty_and_unparseable_addresses_are_dropped() {
        for raw in [
            "",
            "   ",
            "garbage",
            "203.0.113",
            "203.0.113.7:",
            "203.0.113.7:99999",
            "[203.0.113.7]",
            "2001:db8:1:2::/48",
            "2001:db8:1:2::/128",
            "203.0.113.0/64",
            "::ffff:203.0.113.7/64",
            "[2001:db8:1:2::]/64",
            "fe80::1%eth0",
        ] {
            assert!(
                ClientAddress::parse(raw).is_unset(),
                "{raw:?} must leave the address unset"
            );
        }
    }

    #[test]
    fn setting_an_unparseable_address_clears_a_previous_one() {
        let mut http = HttpExtension::default();
        http.set_client_address("203.0.113.7");
        assert_eq!(
            http.client_address(),
            Some("203.0.113.7"),
            "a valid address is set"
        );

        http.set_client_address("garbage");
        assert_eq!(
            http.client_address(),
            None,
            "a bad value must not keep the earlier address"
        );
    }

    #[test]
    fn client_address_is_serialized_but_not_in_debug() {
        let mut http = HttpExtension::default();
        http.set_client_address("203.0.113.7:4431");

        let debug = format!("{http:?}");
        assert!(
            !debug.contains("203.0.113"),
            "Debug output goes to logs and must not carry the address: {debug}"
        );
        assert!(
            debug.contains(r#"client_address: ClientAddress(Some("[REDACTED]"))"#),
            "Debug output still shows that an address is present: {debug}"
        );

        let json = serde_json::to_string(&http).unwrap();
        assert!(
            json.contains(r#""client_address":"203.0.113.7""#),
            "the serialized view audit sinks read keeps the address: {json}"
        );
        let back: HttpExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.client_address(),
            Some("203.0.113.7"),
            "an IPv4 address must survive a serde round trip"
        );
    }

    #[test]
    fn ipv6_client_address_survives_a_serde_round_trip() {
        let mut http = HttpExtension::default();
        http.set_client_address("[2001:db8:1:2::5]:443");

        let json = serde_json::to_string(&http).unwrap();
        assert!(
            json.contains(r#""client_address":"2001:db8:1:2::/64""#),
            "the serialized form is the normalized /64 prefix: {json}"
        );
        let back: HttpExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.client_address(),
            Some("2001:db8:1:2::/64"),
            "the serialized /64 prefix must read back unchanged"
        );
        assert_eq!(
            ClientAddress::parse("2001:db8:1:2:aaaa::1/64").as_str(),
            Some("2001:db8:1:2::/64"),
            "a /64 with host bits set re-normalizes to its prefix"
        );
    }

    #[test]
    fn unset_client_address_is_absent_from_serialized_output() {
        let json = serde_json::to_string(&HttpExtension::default()).unwrap();
        assert!(!json.contains("client_address"), "{json}");
    }

    #[test]
    fn deserialized_client_address_is_normalized() {
        let back: HttpExtension = serde_json::from_str(
            r#"{"request_headers":{},"response_headers":{},"client_address":"[2001:db8:1:2::5]:443"}"#,
        )
        .unwrap();
        assert_eq!(
            back.client_address(),
            Some("2001:db8:1:2::/64"),
            "a deserialized address is normalized like host input"
        );

        let bad: HttpExtension = serde_json::from_str(
            r#"{"request_headers":{},"response_headers":{},"client_address":"garbage"}"#,
        )
        .unwrap();
        assert_eq!(
            bad.client_address(),
            None,
            "deserialization must not bypass normalization"
        );
    }
}
