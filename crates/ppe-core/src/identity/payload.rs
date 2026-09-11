// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `IdentityPayload` — the unified state struct threaded through the
// IdentityResolve hook chain. Plays two roles in one type:
//
//   * **Input** (private fields, read-only after construction) —
//     `raw_token`, `source`, `source_header`, `headers`,
//     `raw_query_string`, `client_host`, `client_port`. Populated by
//     the host once at request entry and
//     never mutated by handlers. Privacy is enforced at the module
//     boundary: external code reads through `pub fn raw_token() -> &str`
//     etc. and has no setters or mutable field access, so even a
//     `payload.clone()` followed by `clone.raw_token = ...` fails to
//     compile.
//
//   * **Accumulating output** (`pub` fields) — `subject`, `client`,
//     `caller_workload`, `delegation`, `raw_credentials`, `rejected`,
//     `reject_status`, `reject_reason`, `resolved_at`, `raw_claims`.
//     Handlers clone the payload, populate the output fields they care
//     about, and return the updated payload via
//     `PluginResult::modify_payload`. Sequential-phase executor
//     semantics thread plugin N's output into plugin N+1's input,
//     producing a natural accumulator chain.
//
// # Why one struct instead of separate Payload + Result
//
// Splitting input and output into `IdentityPayload` and `IdentityResult` makes
// the first handler awkward: it receives an "empty IdentityResult" with no way to
// read
// the raw token without dropping back to `Extensions`. Folding the
// two types into one means handler N always has the inputs it needs
// (private getters) plus whatever previous handlers have already
// accumulated (read direct pub fields), and the hook signature stays
// uniform with everything else in the framework — `invoke_named::<H>`
// with `PluginResult<H::Payload>` on the way out.
//
// # Rejection model
//
// Handlers reject via `PluginResult::deny(PluginViolation::new(code,
// reason))` — the same path every other hook uses. The executor's
// `continue_processing = false` check halts the chain at the
// framework level, so no later handler can run and accidentally
// overwrite the decision. There is intentionally no `rejected` /
// `reject_status` / `reject_reason` flag on the payload itself —
// duplicating the rejection state in a `pub` field would let a
// later handler clone the payload, clear the flag, and quietly
// turn a 401 into a 200. The framework's existing halt machinery
// already does the right thing.
//
// Host-side HTTP mapping is conventional: `PluginViolation.code`
// is the resolution-specific identifier (`auth.expired`,
// `auth.audience_mismatch`, `auth.missing_scope`), and the host
// maps it to a status code (401 / 403 / etc.). Same pattern as
// CMF tool-pre-invoke denials.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::executor::PipelineResult;
use crate::extensions::{
    ClientExtension, DelegationExtension, Extensions, RawCredentialsExtension, SecurityExtension,
    SubjectExtension, WorkloadIdentity,
};
use crate::impl_plugin_payload;

/// Where the raw credential was extracted from. Lets handlers
/// short-circuit on payloads they don't service (an mTLS-only
/// resolver ignores `Bearer` payloads). `Custom(String)` is the
/// escape hatch for bespoke wire formats.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenSource {
    /// `Authorization: Bearer <jwt>` style.
    #[default]
    Bearer,
    /// `X-User-Token` style — explicit user-identity header alongside
    /// a separate gateway-access token in `Authorization`.
    UserToken,
    /// mTLS — credential is the peer X.509 chain (surfaced via
    /// `X-Forwarded-Client-Cert`). `raw_token` may be empty in this
    /// case; the chain itself flows through `headers`.
    Mtls,
    /// SPIFFE JWT-SVID — JWT-shaped but with SPIFFE-specific claims.
    SpiffeJwtSvid,
    /// API key in a header or query param.
    ApiKey,
    /// Operator-defined extraction path.
    #[serde(untagged)]
    Custom(String),
}

/// State threaded through the `IdentityResolve` hook chain.
///
/// See the module-level docs for the input/output split. In short:
/// **input fields are private** (set once via the constructor +
/// builders, never mutated), **output fields are `pub`** (handlers
/// populate them on clones and return the updated payload).
///
/// Implements `PluginPayload` so it can flow through the executor's
/// existing Sequential-phase machinery — no bespoke plumbing.
///
/// `Debug` is hand-written rather than derived — see the impl below — so
/// that `tracing::debug!(?payload)` and similar diagnostics never print
/// `raw_token` or `raw_query_string`, either of which can carry a live
/// bearer token in plaintext.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityPayload {
    /// Raw credential bytes. Cleared on drop via `Zeroizing`.
    /// `#[serde(skip)]` — never appears in serialized output.
    #[serde(skip)]
    raw_token: Zeroizing<String>,

    /// Where the credential was extracted from.
    source: TokenSource,

    /// HTTP header (or other wire-level slot) the token arrived in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_header: Option<String>,

    /// Full request headers — escape hatch for custom auth flows.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    headers: HashMap<String, String>,

    /// Raw query string from the request URL, without the leading
    /// `?`. Set explicitly by the host; `None` otherwise. PPE parses
    /// this deterministically via `http_credential::parse_query_string`
    /// — hosts must not pre-parse it.
    ///
    /// Must not be derived from `HttpExtension.path`. A credential
    /// resolver that reads a query-parameter credential needs a
    /// request target supplied explicitly by the host, independent of
    /// whether `HttpExtension.path` happens to include a query string.
    ///
    /// `#[serde(skip)]` — the query string may contain a bearer token
    /// (e.g. `access_token=eyJ...`). Like `raw_token`, it must never
    /// appear in serialized output, logs, or diagnostics.
    #[serde(skip)]
    raw_query_string: Option<String>,

    /// Client IP, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_host: Option<String>,

    /// Client TCP port, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_port: Option<u16>,

    /// Resolved user identity. `None` until a handler populates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectExtension>,

    /// Resolved OAuth client / gateway-access identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientExtension>,

    /// Resolved attested workload identity for the inbound peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_workload: Option<WorkloadIdentity>,

    /// Initial delegation chain parsed from `act` / equivalent claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationExtension>,

    /// Raw inbound tokens to stash in
    /// `Extensions.raw_credentials.inbound_tokens` after the chain
    /// completes (gated by `read_inbound_credentials` for consumers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_credentials: Option<RawCredentialsExtension>,

    /// Optional resolution timestamp. Audit-useful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,

    /// Raw decoded token claims, when a handler wants to expose them
    /// for audit/policy without elevating each claim to a typed
    /// field.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub raw_claims: HashMap<String, serde_json::Value>,
}

impl std::fmt::Debug for IdentityPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityPayload")
            .field("raw_token", &"<redacted>")
            .field("source", &self.source)
            .field("source_header", &self.source_header)
            .field("headers", &self.headers)
            .field(
                "raw_query_string",
                &self.raw_query_string.as_ref().map(|_| "<redacted>"),
            )
            .field("client_host", &self.client_host)
            .field("client_port", &self.client_port)
            .field("subject", &self.subject)
            .field("client", &self.client)
            .field("caller_workload", &self.caller_workload)
            .field("delegation", &self.delegation)
            .field("raw_credentials", &self.raw_credentials)
            .field("resolved_at", &self.resolved_at)
            .field("raw_claims", &self.raw_claims)
            .finish()
    }
}

impl IdentityPayload {
    /// Construct a payload with the required input fields populated.
    /// The most common entry point — hosts call this once per request
    /// before invoking the hook. Optional input slots
    /// (`source_header`, `headers`, `client_host`, `client_port`) are
    /// set via the `.with_*` builders below; output fields start as
    /// `None` / `false` / empty and accumulate as handlers run.
    pub fn new(raw_token: impl Into<String>, source: TokenSource) -> Self {
        Self {
            raw_token: Zeroizing::new(raw_token.into()),
            source,
            source_header: None,
            headers: HashMap::new(),
            raw_query_string: None,
            client_host: None,
            client_port: None,
            subject: None,
            client: None,
            caller_workload: None,
            delegation: None,
            raw_credentials: None,
            resolved_at: None,
            raw_claims: HashMap::new(),
        }
    }

    /// Set the header the token came from.
    pub fn with_source_header(mut self, h: impl Into<String>) -> Self {
        self.source_header = Some(h.into());
        self
    }

    /// Set the inbound headers.
    pub fn with_headers(mut self, h: HashMap<String, String>) -> Self {
        self.headers = h;
        self
    }

    /// Set the raw query string (without the leading `?`).
    pub fn with_raw_query_string(mut self, qs: impl Into<String>) -> Self {
        self.raw_query_string = Some(qs.into());
        self
    }

    /// Set the client host.
    pub fn with_client_host(mut self, h: impl Into<String>) -> Self {
        self.client_host = Some(h.into());
        self
    }

    /// Set the client port.
    pub fn with_client_port(mut self, port: u16) -> Self {
        self.client_port = Some(port);
        self
    }

    /// The raw credential bytes. Borrowed — handlers cannot move
    /// or replace the underlying `Zeroizing<String>` through this
    /// accessor.
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    /// Where the token came from.
    pub fn source(&self) -> &TokenSource {
        &self.source
    }

    /// The header the token came from.
    pub fn source_header(&self) -> Option<&str> {
        self.source_header.as_deref()
    }

    /// The inbound headers.
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// The raw query string (without the leading `?`), when the host
    /// supplied one.
    pub fn raw_query_string(&self) -> Option<&str> {
        self.raw_query_string.as_deref()
    }

    /// The client host.
    pub fn client_host(&self) -> Option<&str> {
        self.client_host.as_deref()
    }

    /// The client port.
    pub fn client_port(&self) -> Option<u16> {
        self.client_port
    }

    /// Layer another payload's *output* fields onto this one's,
    /// following "Some replaces None, last write wins per slot."
    /// Input fields are not touched — the running payload's input
    /// is canonical for the whole chain.
    ///
    /// Rejection is *not* a merged field — handlers reject via
    /// `PluginResult::deny`, which halts the chain at the framework
    /// level rather than being expressed as payload state. See the
    /// module docs for the rationale.
    pub fn merge(&mut self, other: IdentityPayload) {
        if other.subject.is_some() {
            self.subject = other.subject;
        }
        if other.client.is_some() {
            self.client = other.client;
        }
        if other.caller_workload.is_some() {
            self.caller_workload = other.caller_workload;
        }
        if other.delegation.is_some() {
            self.delegation = other.delegation;
        }
        if other.raw_credentials.is_some() {
            self.raw_credentials = other.raw_credentials;
        }
        if other.resolved_at.is_some() {
            self.resolved_at = other.resolved_at;
        }
        for (k, v) in other.raw_claims {
            self.raw_claims.insert(k, v);
        }
    }

    /// Pull the resolved `IdentityPayload` out of a `PipelineResult`
    /// returned by `mgr.invoke_named::<IdentityHook>(...)`. Returns
    /// `None` when the pipeline was denied (no `modified_payload`)
    /// or when the result's payload wasn't an `IdentityPayload` — a
    /// programmer error if the latter, since the executor produces
    /// `modified_payload` typed per the hook's `HookTypeDef::Payload`.
    ///
    /// Clones the inner payload — the original `Box<dyn PluginPayload>`
    /// stays in the `PipelineResult` so callers can also inspect
    /// `continue_processing`, `violation`, etc.
    pub fn from_pipeline_result(result: &PipelineResult) -> Option<Self> {
        result
            .modified_payload
            .as_ref()
            .and_then(|p| p.as_any().downcast_ref::<IdentityPayload>())
            .cloned()
    }

    /// Apply this payload's resolved identity slots back into an
    /// `Extensions` container. Returns a new `Extensions` ready to
    /// hand to the next hook in the request lifecycle (`cmf.tool_pre_invoke`,
    /// etc.) — downstream plugins read `security.subject` /
    /// `security.client` / `security.caller_workload` /
    /// `raw_credentials` etc. through the standard capability-gated
    /// filter.
    ///
    /// Merging rules:
    ///
    /// - **`security.subject` / `.client` / `.caller_workload`** —
    ///   `Some` values on the payload overwrite the existing slot;
    ///   other security fields (labels, classification, `this_workload`,
    ///   `auth_method`, objects, data) are preserved from the input
    ///   Extensions.
    /// - **`raw_credentials`** — replaced wholesale when populated on
    ///   the payload. Wholesale rather than merged because handlers
    ///   produce the complete set of inbound tokens for this request;
    ///   the host's pre-invoke Extensions wouldn't normally carry one.
    /// - **`delegation`** — replaced wholesale when populated.
    ///   Initial chain from `act` claims in the inbound credential.
    ///
    /// Input fields on the payload (`raw_token`, `headers`, …) are
    /// **not** copied into Extensions — they're the resolver's
    /// internal workspace, not request-wide state.
    pub fn apply_to_extensions(&self, mut ext: Extensions) -> Extensions {
        let needs_security_update =
            self.subject.is_some() || self.client.is_some() || self.caller_workload.is_some();

        if needs_security_update {
            // Clone-out the existing security extension (or default a
            // fresh one) so we can write our identity slots while
            // preserving labels / classification / etc.
            let mut sec: SecurityExtension = ext
                .security
                .as_ref()
                .map(|arc| (**arc).clone())
                .unwrap_or_default();
            if let Some(s) = &self.subject {
                sec.subject = Some(s.clone());
            }
            if let Some(c) = &self.client {
                sec.client = Some(c.clone());
            }
            if let Some(w) = &self.caller_workload {
                sec.caller_workload = Some(w.clone());
            }
            ext.security = Some(Arc::new(sec));
        }

        if let Some(rc) = &self.raw_credentials {
            ext.raw_credentials = Some(Arc::new(rc.clone()));
        }

        if let Some(d) = &self.delegation {
            ext.delegation = Some(Arc::new(d.clone()));
        }

        ext
    }
}

impl_plugin_payload!(IdentityPayload);

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
    fn raw_token_serializes_without_secret() {
        let p = IdentityPayload::new("eyJhbGciOiJSUzI1NiJ9.payload.sig", TokenSource::Bearer);
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("eyJhbGciOiJSUzI1NiJ9"),
            "raw_token leaked into serialized form: {json}",
        );
        assert!(json.contains("bearer"));
    }

    #[test]
    fn deserialize_yields_empty_raw_token() {
        let json = r#"{"source":"bearer"}"#;
        let p: IdentityPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.raw_token(), "");
        assert_eq!(p.source(), &TokenSource::Bearer);
    }

    #[test]
    fn token_source_custom_round_trips() {
        let s = TokenSource::Custom("magic-link".into());
        let json = serde_json::to_string(&s).unwrap();
        let back: TokenSource = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn input_builders_chain() {
        let mut h = HashMap::new();
        h.insert("user-agent".to_owned(), "curl/8.0".to_owned());
        let p = IdentityPayload::new("tok", TokenSource::Bearer)
            .with_source_header("Authorization")
            .with_headers(h)
            .with_client_host("10.0.0.1")
            .with_client_port(443);
        assert_eq!(p.raw_token(), "tok");
        assert_eq!(p.source_header(), Some("Authorization"));
        assert_eq!(p.client_host(), Some("10.0.0.1"));
        assert_eq!(p.client_port(), Some(443));
        assert_eq!(
            p.headers().get("user-agent").map(String::as_str),
            Some("curl/8.0")
        );
    }

    #[test]
    fn raw_query_string_builder_and_getter() {
        let p = IdentityPayload::new("tok", TokenSource::Bearer)
            .with_raw_query_string("access_token=eyJ.fake.jwt");
        assert_eq!(p.raw_query_string(), Some("access_token=eyJ.fake.jwt"));
    }

    #[test]
    fn raw_query_string_absent_by_default() {
        let p = IdentityPayload::new("tok", TokenSource::Bearer);
        assert_eq!(p.raw_query_string(), None);
    }

    #[test]
    fn raw_query_string_never_serialized() {
        let p = IdentityPayload::new("tok", TokenSource::Bearer)
            .with_raw_query_string("access_token=super-secret-value");
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("super-secret-value"),
            "raw_query_string leaked into serialized form: {json}"
        );
    }

    #[test]
    fn debug_output_redacts_raw_token_and_raw_query_string() {
        let p = IdentityPayload::new("eyJ.super-secret-bearer-token.sig", TokenSource::Bearer)
            .with_raw_query_string("access_token=super-secret-query-value");
        let debug = format!("{p:?}");
        assert!(
            !debug.contains("super-secret-bearer-token"),
            "raw_token leaked into Debug output: {debug}"
        );
        assert!(
            !debug.contains("super-secret-query-value"),
            "raw_query_string leaked into Debug output: {debug}"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn debug_output_shows_whether_raw_query_string_was_present() {
        // The redaction hides the value but keeps the Some/None shape visible,
        // so a reader can tell "a query string was supplied but its content is
        // hidden" apart from "no query string was supplied at all".
        let with_qs = IdentityPayload::new("tok", TokenSource::Bearer)
            .with_raw_query_string("access_token=secret");
        let without_qs = IdentityPayload::new("tok", TokenSource::Bearer);
        assert!(format!("{with_qs:?}").contains(r#"raw_query_string: Some("<redacted>")"#));
        assert!(format!("{without_qs:?}").contains("raw_query_string: None"));
    }

    #[test]
    fn handler_can_populate_output_on_clone() {
        // Exercises the typical handler pattern: clone the running
        // payload, set the output fields the handler is responsible
        // for, return the updated payload. Input fields survive
        // the clone unchanged.
        let original = IdentityPayload::new("eyJ.tok", TokenSource::Bearer);
        let mut updated = original.clone();
        updated.subject = Some(SubjectExtension {
            id: Some("alice".into()),
            ..Default::default()
        });
        assert_eq!(updated.raw_token(), "eyJ.tok"); // input preserved
        assert_eq!(
            updated.subject.as_ref().unwrap().id.as_deref(),
            Some("alice")
        );
        // Original unchanged — the clone is a separate value.
        assert!(original.subject.is_none());
    }

    #[test]
    fn merge_overlays_some_onto_none() {
        // Cross-handler chaining: handler 1 resolves the subject,
        // handler 2 contributes the workload. Merged result carries
        // both.
        let mut base = IdentityPayload::new("tok", TokenSource::Bearer);
        base.subject = Some(SubjectExtension {
            id: Some("alice".into()),
            ..Default::default()
        });
        let mut overlay = IdentityPayload::new("tok", TokenSource::Bearer);
        overlay.caller_workload = Some(WorkloadIdentity {
            spiffe_id: Some("spiffe://corp.com/inbound".into()),
            ..Default::default()
        });
        base.merge(overlay);
        assert_eq!(base.subject.as_ref().unwrap().id.as_deref(), Some("alice"));
        assert!(base.caller_workload.is_some());
    }
}
