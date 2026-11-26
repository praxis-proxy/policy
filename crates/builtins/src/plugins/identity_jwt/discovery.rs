// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// OpenID Connect Discovery for a trusted issuer: the `oidc_discovery` key
// source's settings, their load-time checks, and what makes a fetched
// provider configuration document acceptable.
//
// Everything but `fetch_document` is pure, so the acceptance rules are tested
// without a transport. The refresh procedure that drives them lives in
// `discovery_refresh`.

use std::str::FromStr as _;

use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};

use praxis_policy_core::host::HostServices;

use crate::plugins::identity_jwt::config::{
    FetchBounds, KeySourceError, conditional_get, default_min_refresh_interval_secs,
    default_refresh_secs, require_https,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Appended to the issuer to find its provider configuration.
const WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";

/// Ceiling on a discovery document. Real ones run to a few kilobytes.
const DISCOVERY_MAX_BYTES: usize = 65_536; // 64 KiB

/// Ceiling on an advertised `jwks_uri`, so a hostile document cannot make
/// the issuer hold an arbitrarily long string.
const MAX_JWKS_URI_BYTES: usize = 2_048; // 2 KiB

/// How much of a document-supplied string a log line or error carries.
const MAX_ECHOED_CHARS: usize = 256;

/// How many ignored algorithm names a document can make the resolver keep
/// for its log line.
const MAX_IGNORED_NAMES: usize = 16;

/// The algorithm OIDC Discovery requires every provider to
/// support, used when a document does not list its algorithms.
const MANDATORY_ALGORITHM: Algorithm = Algorithm::RS256;

/// Asymmetric algorithms the active backend verifies. A discovered issuer is
/// held to these whatever its document advertises.
#[cfg(not(feature = "jwt-openssl-fips"))]
const SUPPORTED_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Asymmetric algorithms the active backend verifies. A discovered issuer is
/// held to these whatever its document advertises.
#[cfg(feature = "jwt-openssl-fips")]
const SUPPORTED_ALGORITHMS: [Algorithm; 8] =
    crate::plugins::identity_jwt::openssl_fips::APPROVED_ALGORITHMS;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Settings for a `decoding_key` of `kind: oidc_discovery`.
///
/// The trusted issuer's `issuer` is both the `iss` its tokens must carry and,
/// unless `discovery_url` says otherwise, where its provider configuration
/// is found: `<issuer>/.well-known/openid-configuration`, per
/// [OpenID Connect Discovery 1.0 Section 4]. The document's `jwks_uri` names
/// the key set, and its `id_token_signing_alg_values_supported` the
/// algorithms, narrowed by the issuer's `algorithms` when that is non-empty.
/// Shared-secret algorithms and `none` are never accepted.
///
/// ```
/// use praxis_policy_builtins::plugins::identity_jwt::OidcDiscoveryConfig;
///
/// let cfg: OidcDiscoveryConfig = serde_json::from_value(serde_json::json!({}))?;
/// assert_eq!(cfg.refresh_secs, 600);
/// assert_eq!(
///     cfg.discovery_url("https://idp.example/realms/apps/"),
///     "https://idp.example/realms/apps/.well-known/openid-configuration",
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
///
/// [OpenID Connect Discovery 1.0 Section 4]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcDiscoveryConfig {
    /// The `issuer` the document must advertise, when it differs from the
    /// `iss` the tokens carry: an `IdP` reached at an internal address that
    /// describes itself by that address. Only valid with `discovery_url`.
    /// Still compared exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_issuer: Option<String>,

    /// The document's full URL, used verbatim, query included. For an `IdP`
    /// reached at a different address than the issuer it names in its
    /// tokens. Omitted, it is derived from the issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,

    /// Permits plaintext HTTP for the document and for the JWKS it names,
    /// for local development only.
    #[serde(default)]
    pub insecure_http: bool,

    /// Floor between refresh attempts for this issuer, one attempt being at
    /// most a document fetch and a JWKS fetch.
    #[serde(default = "default_min_refresh_interval_secs")]
    pub min_refresh_interval_secs: u64,

    /// How old the document and the key set may get before a verify
    /// refreshes them.
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
}

impl Default for OidcDiscoveryConfig {
    fn default() -> Self {
        Self {
            discovery_issuer: None,
            discovery_url: None,
            insecure_http: false,
            min_refresh_interval_secs: default_min_refresh_interval_secs(),
            refresh_secs: default_refresh_secs(),
        }
    }
}

impl OidcDiscoveryConfig {
    /// Where the provider configuration for `issuer` is fetched from:
    /// `discovery_url` when set, else the issuer with any trailing `/`
    /// removed and the well-known path appended.
    pub fn discovery_url(&self, issuer: &str) -> String {
        self.discovery_url
            .clone()
            .unwrap_or_else(|| format!("{}{WELL_KNOWN_PATH}", issuer.trim_end_matches('/')))
    }

    /// The `issuer` value the document must advertise.
    pub fn expected_issuer<'a>(&'a self, issuer: &'a str) -> &'a str {
        self.discovery_issuer.as_deref().unwrap_or(issuer)
    }

    /// Refuse settings that could not work or would weaken the check, before
    /// any request is made. `algorithms` is the trusted issuer's configured
    /// list.
    ///
    /// # Errors
    ///
    /// A message naming the issuer and the offending setting.
    pub fn validate(&self, issuer: &str, algorithms: &[Algorithm]) -> Result<(), String> {
        let fault = |message: String| format!("trusted_issuer '{issuer}': {message}");

        // OpenID Connect Discovery 1.0 Section 2: the issuer is an https URL
        // with no query or fragment, so the well-known path appends cleanly.
        if let Some(reason) = url_fault(issuer, false) {
            return Err(fault(format!(
                "`issuer` must be an absolute http(s) URL for oidc_discovery, \
                 with a host and no userinfo, query or fragment; it {reason}"
            )));
        }
        if let Some(url) = &self.discovery_url
            && let Some(reason) = url_fault(url, true)
        {
            return Err(fault(format!(
                "`decoding_key.discovery_url` must be an absolute http(s) URL with a host and \
                 no userinfo or fragment; it {reason}"
            )));
        }
        if let Some(expected) = &self.discovery_issuer {
            if self.discovery_url.is_none() {
                return Err(fault(
                    "`decoding_key.discovery_issuer` is only valid together with \
                     `decoding_key.discovery_url`"
                        .to_owned(),
                ));
            }
            if let Some(reason) = url_fault(expected, false) {
                return Err(fault(format!(
                    "`decoding_key.discovery_issuer` must be an absolute http(s) URL with a \
                     host and no userinfo, query or fragment; it {reason}"
                )));
            }
        }
        require_https(
            "OIDC discovery URL",
            &self.discovery_url(issuer),
            self.insecure_http,
        )
        .map_err(&fault)?;
        if let Some(alg) = algorithms
            .iter()
            .find(|a| !crate::plugins::identity_jwt::dpop::is_asymmetric(**a))
        {
            return Err(fault(format!(
                "`algorithms` lists {alg:?}, a shared-secret algorithm; an oidc_discovery \
                 issuer's keys come from a published key set, which cannot hold a secret"
            )));
        }
        if self.min_refresh_interval_secs == 0 || self.refresh_secs < self.min_refresh_interval_secs
        {
            return Err(fault(format!(
                "`decoding_key.min_refresh_interval_secs` must be at least 1 and \
                 `decoding_key.refresh_secs` at least `min_refresh_interval_secs` \
                 (got {} and {})",
                self.min_refresh_interval_secs, self.refresh_secs
            )));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Provider configuration documents
// -----------------------------------------------------------------------------

/// What an accepted document is checked against.
#[derive(Debug, Clone, Copy)]
pub(super) struct Expectations<'a> {
    /// The `issuer` the document must advertise, exactly.
    pub(super) issuer: &'a str,
    /// Whether an `http` `jwks_uri` is acceptable.
    pub(super) insecure_http: bool,
    /// The trusted issuer's configured algorithms, possibly empty.
    pub(super) configured: &'a [Algorithm],
}

/// A provider configuration document that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Document {
    /// Where the issuer publishes its keys.
    pub(super) jwks_uri: String,
    /// The algorithms a token from this issuer may use.
    pub(super) algorithms: Vec<Algorithm>,
    /// Advertised algorithm names left out because they are symmetric,
    /// `none`, unknown or unsupported here, clipped for logging.
    pub(super) ignored: Vec<String>,
    /// Whether the document listed no algorithms, so `algorithms` is the
    /// configured list or the mandatory one.
    pub(super) algorithms_omitted: bool,
}

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rejection {
    /// What was wrong, for the operator. Never quotes the body beyond a
    /// clipped document-supplied string.
    pub(super) reason: String,
    /// Whether an operator has to change something, as opposed to an `IdP`
    /// that is unhelpful right now.
    pub(super) config_fault: bool,
}

impl Rejection {
    fn transient(reason: String) -> Self {
        Self {
            reason,
            config_fault: false,
        }
    }

    fn config(reason: String) -> Self {
        Self {
            reason,
            config_fault: true,
        }
    }
}

/// The fields this resolver reads. Every other member is ignored, since
/// providers publish dozens this resolver has no use for.
#[derive(Deserialize)]
struct RawDocument {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

/// Check a fetched document against `expected`.
///
/// The document can only choose keys and narrow algorithms: nothing in it
/// changes the issuer, audiences or anything else the operator configured.
///
/// # Errors
///
/// A [`Rejection`] when the body is not a JSON object with string `issuer`
/// and `jwks_uri`, when the issuer differs from the expected one in any
/// byte, when `jwks_uri` is not an acceptable URL, or when no algorithm
/// survives [`effective_algorithms`].
pub(super) fn parse_document(
    body: &[u8],
    expected: &Expectations<'_>,
) -> Result<Document, Rejection> {
    // The serde message is not echoed: it can quote the body.
    let raw: RawDocument = serde_json::from_slice(body).map_err(|e| {
        Rejection::transient(format!(
            "the discovery document is not a JSON object with string `issuer` and `jwks_uri` \
             ({:?} error at line {}, column {})",
            e.classify(),
            e.line(),
            e.column()
        ))
    })?;

    // OpenID Connect Discovery 1.0 Section 4.3: exact equality, no
    // normalization, so a document cannot vouch for an issuer it is not.
    if raw.issuer != expected.issuer {
        return Err(Rejection::config(format!(
            "the discovery document advertises issuer '{}', expected '{}'; set \
             `discovery_issuer` (with `discovery_url`) only if the IdP genuinely describes \
             itself by another address",
            clip(&raw.issuer),
            expected.issuer
        )));
    }

    check_jwks_uri(&raw.jwks_uri, expected.insecure_http)?;

    let advertised = raw.id_token_signing_alg_values_supported;
    let choice = effective_algorithms(advertised.as_deref(), expected.configured)?;
    Ok(Document {
        jwks_uri: raw.jwks_uri,
        algorithms: choice.algorithms,
        ignored: choice.ignored,
        algorithms_omitted: advertised.is_none(),
    })
}

/// Refuse a `jwks_uri` that is too long, malformed, or plaintext without
/// `insecure_http`.
fn check_jwks_uri(uri: &str, insecure_http: bool) -> Result<(), Rejection> {
    if uri.len() > MAX_JWKS_URI_BYTES {
        return Err(Rejection::transient(format!(
            "the discovery document's jwks_uri is {} bytes, over the {MAX_JWKS_URI_BYTES}-byte \
             limit",
            uri.len()
        )));
    }
    if let Some(reason) = url_fault(uri, true) {
        return Err(Rejection::transient(format!(
            "the discovery document's jwks_uri '{}' is not an absolute http(s) URL with a host \
             and no userinfo or fragment; it {reason}",
            clip(uri)
        )));
    }
    require_https("the discovery document's jwks_uri", uri, insecure_http)
        .map_err(Rejection::config)
}

/// The algorithms a discovered issuer accepts, and the advertised names
/// left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AlgorithmChoice {
    /// The effective set a token's `alg` must belong to. Never empty.
    pub(super) algorithms: Vec<Algorithm>,
    /// Advertised names left out, at most [`MAX_IGNORED_NAMES`], each
    /// clipped.
    pub(super) ignored: Vec<String>,
}

/// Derive the accepted algorithms from what a document `advertised` and the
/// issuer `configured`.
///
/// Advertised names outside the supported asymmetric set (`HS*`, `none`,
/// unknown strings) are ignored rather than failing the document. A
/// non-empty configured list intersects the rest. A document listing nothing
/// falls back to the configured list, or to `RS256`, which
/// [OpenID Connect Discovery 1.0 Section 3] requires every provider to
/// support.
///
/// # Errors
///
/// A configuration-fault [`Rejection`] when nothing remains.
///
/// [OpenID Connect Discovery 1.0 Section 3]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
pub(super) fn effective_algorithms(
    advertised: Option<&[String]>,
    configured: &[Algorithm],
) -> Result<AlgorithmChoice, Rejection> {
    let Some(advertised) = advertised else {
        let algorithms = if configured.is_empty() {
            vec![MANDATORY_ALGORITHM]
        } else {
            configured.to_vec()
        };
        return Ok(AlgorithmChoice {
            algorithms,
            ignored: Vec::new(),
        });
    };

    let mut supported: Vec<Algorithm> = Vec::new();
    let mut ignored: Vec<String> = Vec::new();
    for name in advertised {
        match Algorithm::from_str(name) {
            Ok(alg) if SUPPORTED_ALGORITHMS.contains(&alg) => {
                if !supported.contains(&alg) {
                    supported.push(alg);
                }
            },
            _ => {
                if ignored.len() < MAX_IGNORED_NAMES {
                    ignored.push(clip(name));
                }
            },
        }
    }
    let algorithms: Vec<Algorithm> = if configured.is_empty() {
        supported.clone()
    } else {
        supported
            .iter()
            .copied()
            .filter(|a| configured.contains(a))
            .collect()
    };
    if algorithms.is_empty() {
        return Err(Rejection::config(format!(
            "no usable signing algorithm: the discovery document advertises {} (usable here: \
             {supported:?}) and the issuer configures {configured:?}",
            clip(&advertised.join(", "))
        )));
    }
    Ok(AlgorithmChoice {
        algorithms,
        ignored,
    })
}

// -----------------------------------------------------------------------------
// Fetching
// -----------------------------------------------------------------------------

/// What a discovery fetch came back with.
#[derive(Debug)]
pub(super) enum DocumentFetch {
    /// An accepted document, and its `ETag` when the peer sent one.
    Accepted {
        document: Document,
        etag: Option<String>,
    },
    /// The peer answered `304` to a conditional request.
    NotModified,
}

/// Why a discovery fetch yielded no document.
#[derive(Debug)]
pub(super) enum DiscoveryError {
    /// The request could not be made or did not complete.
    Fetch(KeySourceError),
    /// The peer answered with something unusable.
    Rejected(Rejection),
}

impl DiscoveryError {
    /// Whether an operator has to change something to clear it.
    pub(super) fn is_config_fault(&self) -> bool {
        match self {
            Self::Fetch(e) => e.is_fatal(),
            Self::Rejected(r) => r.config_fault,
        }
    }
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(e) => write!(f, "{e}"),
            Self::Rejected(r) => write!(f, "{}", r.reason),
        }
    }
}

/// Fetch the provider configuration at `url` and check it.
///
/// Redirects are not followed: a `3xx` is refused, and the operator points
/// `discovery_url` at the final location instead.
///
/// # Errors
///
/// [`DiscoveryError::Fetch`] when the request could not be made, fatally so
/// when no transport is available. [`DiscoveryError::Rejected`] for any
/// answer that is not an acceptable document or a `304` to a conditional
/// request.
pub(super) async fn fetch_document(
    url: &str,
    expected: &Expectations<'_>,
    svc: &dyn HostServices,
    bounds: FetchBounds,
    if_none_match: Option<&str>,
) -> Result<DocumentFetch, DiscoveryError> {
    let resp = conditional_get(
        "OIDC discovery",
        url,
        svc,
        bounds,
        DISCOVERY_MAX_BYTES,
        if_none_match,
    )
    .await
    .map_err(DiscoveryError::Fetch)?;

    if resp.is_not_modified() {
        if if_none_match.is_some() {
            return Ok(DocumentFetch::NotModified);
        }
        return Err(DiscoveryError::Rejected(Rejection::transient(format!(
            "OIDC discovery GET {url} answered 304 to a request carrying no If-None-Match"
        ))));
    }
    if (300..400).contains(&resp.status) {
        return Err(DiscoveryError::Rejected(Rejection::config(format!(
            "OIDC discovery GET {url} answered {}, a redirect; redirects are not followed, so \
             set `discovery_url` to the final location",
            resp.status
        ))));
    }
    if !resp.is_success() {
        return Err(DiscoveryError::Rejected(Rejection::transient(format!(
            "OIDC discovery GET {url} returned non-2xx: {}",
            resp.status
        ))));
    }

    let etag = resp.etag().map(ToOwned::to_owned);
    let document = parse_document(&resp.body, expected).map_err(|r| {
        DiscoveryError::Rejected(Rejection {
            reason: format!("OIDC discovery GET {url}: {}", r.reason),
            config_fault: r.config_fault,
        })
    })?;
    Ok(DocumentFetch::Accepted { document, etag })
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// The `host[:port]` part of an absolute URL, for telling whether a moved
/// `jwks_uri` changed hosts.
pub(super) fn authority(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    rest.split(['/', '?', '#']).next()
}

/// Why `url` is not an absolute `http`/`https` URL with a host and no
/// userinfo or fragment (nor query, unless `allow_query`), or `None` when it
/// is one. The reason reads after "it".
///
/// RFC 3986 URIs are ASCII, so anything else is refused: an accepted URL is
/// then safe to log as is.
fn url_fault(url: &str, allow_query: bool) -> Option<&'static str> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Some("contains whitespace or control characters");
    }
    if !url.is_ascii() {
        return Some("contains non-ASCII characters (percent-encode them, punycode the host)");
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return Some("is not an absolute URL");
    };
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return Some("does not use the http or https scheme");
    }
    if rest.contains('#') {
        return Some("carries a fragment");
    }
    if !allow_query && rest.contains('?') {
        return Some("carries a query");
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.contains('@') {
        return Some("carries userinfo");
    }
    if authority.is_empty() || authority.starts_with(':') {
        return Some("has no host");
    }
    None
}

/// `s` cut to [`MAX_ECHOED_CHARS`] characters and made safe for one log
/// line, for echoing a remotely supplied string.
///
/// Control characters, line and paragraph separators and bidirectional
/// overrides are escaped (`\n`, `\u{2028}`): a text log renders a raw newline
/// as a new line, so an unescaped one would let whoever serves the document
/// write lines of their own.
pub(super) fn clip(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_ECHOED_CHARS));
    for (n, c) in s.chars().enumerate() {
        if n == MAX_ECHOED_CHARS {
            out.push_str("...");
            break;
        }
        if breaks_log_lines(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether `c` could end a log line, reorder how one displays, or hide in
/// it (directional marks and zero-width characters).
fn breaks_log_lines(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
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
    use serde_json::json;

    #[test]
    fn defaults_match_the_jwks_url_source() {
        let cfg: OidcDiscoveryConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(cfg.refresh_secs, 600, "refresh_secs defaults to 10 minutes");
        assert_eq!(
            cfg.min_refresh_interval_secs, 30,
            "the refresh floor defaults to 30 seconds"
        );
        assert!(!cfg.insecure_http, "plaintext is opt-in");
        assert_eq!(cfg, OidcDiscoveryConfig::default());
    }

    #[test]
    fn the_derived_url_has_exactly_one_slash_before_the_well_known_path() {
        let cfg = OidcDiscoveryConfig::default();
        for issuer in ["https://idp/realms/a", "https://idp/realms/a/"] {
            assert_eq!(
                cfg.discovery_url(issuer),
                "https://idp/realms/a/.well-known/openid-configuration",
                "issuer {issuer}"
            );
        }
        assert_eq!(
            cfg.discovery_url("https://t.example/"),
            "https://t.example/.well-known/openid-configuration"
        );
    }

    #[test]
    fn an_explicit_discovery_url_is_used_verbatim() {
        let cfg = OidcDiscoveryConfig {
            discovery_url: Some(
                "https://login.example/tenant/v2.0/.well-known/openid-configuration?p=b2c_1_signin"
                    .to_owned(),
            ),
            ..OidcDiscoveryConfig::default()
        };
        assert_eq!(
            cfg.discovery_url("https://ignored.example"),
            "https://login.example/tenant/v2.0/.well-known/openid-configuration?p=b2c_1_signin",
            "the query must survive"
        );
        cfg.validate("https://issuer.example", &[])
            .expect("a query is allowed in discovery_url");
    }

    #[test]
    fn the_expected_issuer_is_the_issuer_unless_discovery_issuer_is_set() {
        let plain = OidcDiscoveryConfig::default();
        assert_eq!(plain.expected_issuer("https://a"), "https://a");
        let split = OidcDiscoveryConfig {
            discovery_issuer: Some("https://internal".to_owned()),
            ..OidcDiscoveryConfig::default()
        };
        assert_eq!(split.expected_issuer("https://a"), "https://internal");
    }

    #[test]
    fn an_unknown_key_is_rejected_and_named() {
        let err = serde_json::from_value::<OidcDiscoveryConfig>(json!({ "refresh_sec": 60 }))
            .expect_err("a typo must not be ignored");
        assert!(err.to_string().contains("refresh_sec"), "{err}");
    }

    #[test]
    fn a_plaintext_issuer_needs_insecure_http() {
        let err = OidcDiscoveryConfig::default()
            .validate("http://idp.local/realms/a", &[])
            .expect_err("plaintext discovery must be opted into");
        assert!(err.contains("https"), "{err}");
        assert!(err.contains("insecure_http"), "{err}");

        OidcDiscoveryConfig {
            insecure_http: true,
            ..OidcDiscoveryConfig::default()
        }
        .validate("http://idp.local/realms/a", &[])
        .expect("insecure_http permits a plaintext issuer");
    }

    #[test]
    fn a_plaintext_discovery_url_needs_insecure_http() {
        let cfg = OidcDiscoveryConfig {
            discovery_url: Some("HTTP://idp.svc/realms/a/.well-known/openid-configuration".into()),
            ..OidcDiscoveryConfig::default()
        };
        let err = cfg
            .validate("https://idp.example/realms/a", &[])
            .expect_err("the scheme check is case-insensitive");
        assert!(err.contains("insecure_http"), "{err}");
    }

    #[test]
    fn a_malformed_issuer_is_refused_with_the_reason() {
        let cases = [
            ("https://idp.example/realms/a?x=1", "query"),
            ("https://idp.example/realms/a#frag", "fragment"),
            ("https://user:pw@idp.example/realms/a", "userinfo"),
            ("https:///realms/a", "no host"),
            ("https://:443/realms/a", "no host"),
            ("spiffe://example.org/ns/a", "scheme"),
            ("idp.example/realms/a", "absolute"),
            ("https://idp.example/realms a", "whitespace"),
            ("https://idp.ex\u{430}mple/realms/a", "non-ASCII"),
        ];
        for (issuer, reason) in cases {
            let err = OidcDiscoveryConfig::default()
                .validate(issuer, &[])
                .expect_err(issuer);
            assert!(err.contains("`issuer`"), "{issuer}: {err}");
            assert!(
                err.contains(reason),
                "{issuer} should mention {reason}: {err}"
            );
        }
    }

    #[test]
    fn a_malformed_discovery_url_is_refused() {
        for url in [
            "https://idp.example/x#frag",
            "https://user@idp.example/x",
            "ftp://idp.example/x",
        ] {
            let cfg = OidcDiscoveryConfig {
                discovery_url: Some(url.to_owned()),
                ..OidcDiscoveryConfig::default()
            };
            let err = cfg.validate("https://idp.example", &[]).expect_err(url);
            assert!(err.contains("discovery_url"), "{url}: {err}");
        }
    }

    #[test]
    fn discovery_issuer_needs_discovery_url_and_a_well_formed_value() {
        let alone = OidcDiscoveryConfig {
            discovery_issuer: Some("https://internal.example".into()),
            ..OidcDiscoveryConfig::default()
        };
        let err = alone
            .validate("https://idp.example", &[])
            .expect_err("discovery_issuer alone is refused");
        assert!(err.contains("discovery_issuer"), "{err}");
        assert!(err.contains("discovery_url"), "{err}");

        let malformed = OidcDiscoveryConfig {
            discovery_issuer: Some("https://internal.example?x".into()),
            discovery_url: Some("https://internal.example/.well-known/openid-configuration".into()),
            ..OidcDiscoveryConfig::default()
        };
        let err = malformed
            .validate("https://idp.example", &[])
            .expect_err("discovery_issuer is held to the issuer's shape");
        assert!(err.contains("discovery_issuer"), "{err}");

        let paired = OidcDiscoveryConfig {
            discovery_issuer: Some("https://internal.example".into()),
            discovery_url: Some("https://internal.example/.well-known/openid-configuration".into()),
            ..OidcDiscoveryConfig::default()
        };
        paired
            .validate("https://idp.example", &[])
            .expect("discovery_issuer with discovery_url loads");
    }

    #[test]
    fn a_shared_secret_algorithm_is_refused() {
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            let err = OidcDiscoveryConfig::default()
                .validate("https://idp.example", &[Algorithm::RS256, alg])
                .expect_err("an HMAC algorithm cannot verify against a public key set");
            assert!(err.contains(&format!("{alg:?}")), "{err}");
            assert!(err.contains("shared-secret"), "{err}");
        }
    }

    #[test]
    fn the_refresh_floor_must_be_positive_and_below_the_ttl() {
        for (floor, ttl) in [(0, 600), (60, 30)] {
            let cfg = OidcDiscoveryConfig {
                min_refresh_interval_secs: floor,
                refresh_secs: ttl,
                ..OidcDiscoveryConfig::default()
            };
            let err = cfg
                .validate("https://idp.example", &[])
                .expect_err("an unusable floor is refused");
            assert!(err.contains("min_refresh_interval_secs"), "{err}");
            assert!(err.contains("refresh_secs"), "{err}");
        }
        OidcDiscoveryConfig {
            min_refresh_interval_secs: 30,
            refresh_secs: 30,
            ..OidcDiscoveryConfig::default()
        }
        .validate("https://idp.example", &[])
        .expect("a floor equal to the TTL is allowed");
    }

    #[test]
    fn an_accepted_document_yields_its_jwks_uri_and_algorithms() {
        let doc = parse(json!({
            "issuer": ISSUER,
            "jwks_uri": "https://keys.example/certs",
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "token_endpoint": "https://idp.example/token",
        }))
        .expect("a well-formed document is accepted");
        assert_eq!(doc.jwks_uri, "https://keys.example/certs");
        assert_eq!(doc.algorithms, vec![Algorithm::RS256, Algorithm::ES256]);
        assert!(doc.ignored.is_empty());
        assert!(!doc.algorithms_omitted);
    }

    #[test]
    fn the_issuer_must_match_byte_for_byte() {
        for advertised in [
            "https://idp.example/realms/a/",
            "https://IDP.example/realms/a",
            "https://other.example",
        ] {
            let r = parse(json!({ "issuer": advertised, "jwks_uri": "https://idp.example/k" }))
                .expect_err(advertised);
            assert!(
                r.config_fault,
                "an issuer mismatch is the operator's to fix"
            );
            assert!(
                r.reason.contains(advertised),
                "names the actual: {}",
                r.reason
            );
            assert!(
                r.reason.contains(ISSUER),
                "names the expected: {}",
                r.reason
            );
        }
    }

    #[test]
    fn a_trailing_slash_issuer_matches_only_itself() {
        let expected = Expectations {
            issuer: "https://t.example/",
            insecure_http: false,
            configured: &[],
        };
        let body = |iss: &str| json!({ "issuer": iss, "jwks_uri": "https://t.example/k" });
        parse_document(body("https://t.example/").to_string().as_bytes(), &expected)
            .expect("the same string is accepted");
        parse_document(body("https://t.example").to_string().as_bytes(), &expected)
            .expect_err("no normalization");
    }

    #[test]
    fn malformed_documents_are_transient_rejections() {
        let long = format!("https://idp.example/{}", "k".repeat(MAX_JWKS_URI_BYTES));
        let cases: [(&str, Vec<u8>); 9] = [
            ("not JSON", b"<html>".to_vec()),
            ("not UTF-8", vec![0xff, 0xfe, b'{']),
            (
                "no issuer",
                body(json!({ "jwks_uri": "https://idp.example/k" })),
            ),
            ("no jwks_uri", body(json!({ "issuer": ISSUER }))),
            (
                "issuer of the wrong type",
                body(json!({ "issuer": 7, "jwks_uri": "https://idp.example/k" })),
            ),
            (
                "algorithms of the wrong type",
                body(json!({
                    "issuer": ISSUER, "jwks_uri": "https://idp.example/k",
                    "id_token_signing_alg_values_supported": "RS256",
                })),
            ),
            (
                "jwks_uri too long",
                body(json!({ "issuer": ISSUER, "jwks_uri": long })),
            ),
            (
                "jwks_uri with a fragment",
                body(json!({ "issuer": ISSUER, "jwks_uri": "https://idp.example/k#x" })),
            ),
            (
                "jwks_uri with userinfo",
                body(json!({ "issuer": ISSUER, "jwks_uri": "https://u@idp.example/k" })),
            ),
        ];
        for (label, bytes) in cases {
            let r = parse_document(&bytes, &expect(&[])).expect_err(label);
            assert!(!r.config_fault, "{label} is the IdP's to fix: {}", r.reason);
        }
    }

    #[test]
    fn a_rejection_does_not_quote_the_body() {
        let r = parse_document(
            br#"{"issuer": "https://idp.example/realms/a", "jwks_uri": ["secret-ish-value"]}"#,
            &expect(&[]),
        )
        .expect_err("jwks_uri of the wrong type");
        assert!(
            !r.reason.contains("secret-ish-value"),
            "the body must not be echoed: {}",
            r.reason
        );
    }

    #[test]
    fn a_plaintext_jwks_uri_needs_insecure_http() {
        let doc = json!({ "issuer": ISSUER, "jwks_uri": "http://idp.example/k" });
        let r = parse(doc.clone()).expect_err("plaintext keys are refused");
        assert!(r.config_fault, "{}", r.reason);
        assert!(r.reason.contains("insecure_http"), "{}", r.reason);

        let lenient = Expectations {
            insecure_http: true,
            ..expect(&[])
        };
        parse_document(doc.to_string().as_bytes(), &lenient)
            .expect("insecure_http permits a plaintext jwks_uri");
    }

    #[test]
    fn a_non_ascii_jwks_uri_is_refused() {
        for uri in [
            "https://idp.example/certs?v=\u{202e}txt.exe",
            "https://idp.ex\u{430}mple/certs",
        ] {
            let r = parse(json!({ "issuer": ISSUER, "jwks_uri": uri })).expect_err(uri);
            assert!(!r.config_fault, "{uri}: {}", r.reason);
            assert!(r.reason.contains("non-ASCII"), "{uri}: {}", r.reason);
            assert!(
                !r.reason.contains('\u{202e}'),
                "echoed escaped: {}",
                r.reason
            );
        }
    }

    #[test]
    fn a_cross_origin_jwks_uri_is_accepted() {
        let doc = parse(
            json!({ "issuer": ISSUER, "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs" }),
        )
        .expect("the JWKS may live on another host");
        assert_eq!(authority(&doc.jwks_uri), Some("www.googleapis.com"));
    }

    #[test]
    fn symmetric_none_and_unknown_algorithms_are_ignored() {
        let choice = effective_algorithms(
            Some(&names(&[
                "HS256", "RS256", "none", "ES512", "RS256", "made-up",
            ])),
            &[],
        )
        .expect("RS256 survives");
        assert_eq!(choice.algorithms, vec![Algorithm::RS256], "deduplicated");
        assert_eq!(
            choice.ignored,
            names(&["HS256", "none", "ES512", "made-up"])
        );
    }

    #[test]
    fn configured_algorithms_narrow_the_advertised_ones() {
        let choice = effective_algorithms(Some(&names(&["RS256", "ES256"])), &[Algorithm::ES256])
            .expect("ES256 is in both");
        assert_eq!(choice.algorithms, vec![Algorithm::ES256]);
    }

    #[test]
    fn an_empty_intersection_is_a_config_fault_naming_both_sides() {
        let r = effective_algorithms(Some(&names(&["RS256"])), &[Algorithm::ES256])
            .expect_err("nothing in common");
        assert!(r.config_fault);
        assert!(r.reason.contains("RS256"), "{}", r.reason);
        assert!(r.reason.contains("ES256"), "{}", r.reason);
    }

    #[test]
    fn only_symmetric_algorithms_advertised_is_rejected() {
        let r = effective_algorithms(Some(&names(&["HS256"])), &[]).expect_err("nothing usable");
        assert!(r.config_fault);
    }

    #[test]
    fn omitted_algorithms_fall_back_to_configured_then_rs256() {
        let configured = effective_algorithms(None, &[Algorithm::PS256]).expect("configured");
        assert_eq!(configured.algorithms, vec![Algorithm::PS256]);
        let mandatory = effective_algorithms(None, &[]).expect("mandatory");
        assert_eq!(mandatory.algorithms, vec![Algorithm::RS256]);

        let doc = parse(json!({ "issuer": ISSUER, "jwks_uri": "https://idp.example/k" }))
            .expect("algorithms are optional in practice");
        assert!(
            doc.algorithms_omitted,
            "the omission is reported for a warning"
        );
    }

    #[cfg(not(feature = "jwt-openssl-fips"))]
    #[test]
    fn eddsa_is_accepted_outside_fips() {
        let choice = effective_algorithms(Some(&names(&["EdDSA"])), &[]).expect("EdDSA");
        assert_eq!(choice.algorithms, vec![Algorithm::EdDSA]);
    }

    #[cfg(feature = "jwt-openssl-fips")]
    #[test]
    fn eddsa_is_ignored_under_fips() {
        let choice =
            effective_algorithms(Some(&names(&["EdDSA", "RS256"])), &[]).expect("RS256 survives");
        assert_eq!(choice.algorithms, vec![Algorithm::RS256]);
        assert_eq!(choice.ignored, names(&["EdDSA"]));
    }

    #[test]
    fn echoed_strings_are_clipped() {
        let long = "x".repeat(MAX_ECHOED_CHARS + 10);
        let clipped = clip(&long);
        assert_eq!(clipped.chars().count(), MAX_ECHOED_CHARS + 3);
        assert_eq!(clip("short"), "short");
    }

    #[test]
    fn echoed_strings_cannot_break_a_log_line() {
        assert_eq!(clip("a\nb\rc"), r"a\nb\rc", "newlines are escaped");
        assert_eq!(
            clip("x\u{1b}[2J\u{7}"),
            r"x\u{1b}[2J\u{7}",
            "escapes and bells"
        );
        assert_eq!(
            clip("a\u{2028}b\u{202e}c"),
            r"a\u{2028}b\u{202e}c",
            "line separators and bidi overrides"
        );
        assert_eq!(
            clip("k\u{200e}i\u{200b}d\u{061c}-\u{feff}1"),
            r"k\u{200e}i\u{200b}d\u{61c}-\u{feff}1",
            "directional marks and zero-width characters"
        );
        assert_eq!(
            clip("Ünïcödé kid-1 \"q\""),
            "Ünïcödé kid-1 \"q\"",
            "printable text is kept"
        );
        let long = "\n".repeat(MAX_ECHOED_CHARS + 10);
        let clipped = clip(&long);
        assert!(!clipped.contains('\n'), "{clipped}");
        assert!(clipped.ends_with("..."), "still clipped: {clipped}");
    }

    #[test]
    fn authority_reads_host_and_port() {
        assert_eq!(
            authority("https://a.example:8443/x?y"),
            Some("a.example:8443")
        );
        assert_eq!(authority("not a url"), None);
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    const ISSUER: &str = "https://idp.example/realms/a";

    fn expect(configured: &[Algorithm]) -> Expectations<'_> {
        Expectations {
            issuer: ISSUER,
            insecure_http: false,
            configured,
        }
    }

    fn body(doc: serde_json::Value) -> Vec<u8> {
        doc.to_string().into_bytes()
    }

    fn parse(doc: serde_json::Value) -> Result<Document, Rejection> {
        parse_document(&body(doc), &expect(&[]))
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }
}
