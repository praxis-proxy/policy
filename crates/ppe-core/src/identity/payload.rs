// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `IdentityPayload` — the unified state struct threaded through the
// IdentityResolve hook chain. Plays two roles in one type:
//
//   * **Input** (private fields, read-only after construction) —
//     `raw_token`, `source`, `source_header`, `headers`,
//     `client_host`, `client_port`. Populated by
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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::executor::PipelineResult;
use crate::extensions::raw_credentials::{RawInboundToken, TokenRole};
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
    /// `Authorization: Basic <base64(user-id:password)>` per RFC 7617.
    Basic,
    /// Operator-defined extraction path.
    #[serde(untagged)]
    Custom(String),
}

/// Request inputs and resolved identities shared by identity resolvers.
///
/// Hosts set private inputs through constructors and builders. Resolvers
/// fill the public output fields.
///
/// `Debug` output redacts the raw token and all header values.
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
    /// Serde-skipped: headers may carry credentials and must not
    /// appear in serialized output.
    #[serde(skip)]
    headers: HashMap<String, String>,

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

    /// At least one credential resolver declined this value as belonging to
    /// another population. Kept inside the hook pipeline, never serialized.
    #[serde(skip)]
    credential_declined: bool,

    /// The roles whose token the resolver now running supplied through
    /// [`supply_inbound_token`](Self::supply_inbound_token). Cleared after
    /// each resolver, never serialized.
    #[serde(skip)]
    tokens_supplied: HashSet<TokenRole>,
}

struct RedactedHeaders<'a>(&'a HashMap<String, String>);

impl std::fmt::Debug for RedactedHeaders<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, "[REDACTED]")))
            .finish()
    }
}

impl std::fmt::Debug for IdentityPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityPayload")
            .field("raw_token", &"[REDACTED]")
            .field("source", &self.source)
            .field("source_header", &self.source_header)
            .field("headers", &RedactedHeaders(&self.headers))
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
            client_host: None,
            client_port: None,
            subject: None,
            client: None,
            caller_workload: None,
            delegation: None,
            raw_credentials: None,
            resolved_at: None,
            raw_claims: HashMap::new(),
            credential_declined: false,
            tokens_supplied: HashSet::new(),
        }
    }

    /// Record that a resolver did not recognize this credential's population.
    /// The next resolver may still resolve it; the executor rejects only when
    /// the complete chain finishes without an identity.
    pub fn mark_credential_declined(&mut self) {
        self.credential_declined = true;
    }

    pub(crate) fn credential_declined(&self) -> bool {
        self.credential_declined
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
    ///
    /// A token `other` carried over for a slot it gave a different identity
    /// is dropped; see [`supply_inbound_token`](Self::supply_inbound_token).
    pub fn merge(&mut self, other: IdentityPayload) {
        let after = Slots {
            subject: other.subject.as_ref().or(self.subject.as_ref()),
            client: other.client.as_ref().or(self.client.as_ref()),
            caller_workload: other
                .caller_workload
                .as_ref()
                .or(self.caller_workload.as_ref()),
            tokens: other
                .raw_credentials
                .as_ref()
                .or(self.raw_credentials.as_ref()),
        };
        let left_behind = left_behind(&self.slots(), &after, &other.tokens_supplied);
        self.merge_fields(other);
        self.forget_tokens(&left_behind);
    }

    /// Store `token` as the request's inbound token for `role`: the
    /// credential behind the identity this resolver put in that role's slot.
    ///
    /// A token belongs to the identity its slot held when the token was
    /// stored. A later resolver that changes the slot in any way keeps the
    /// token only by supplying it here again, or by storing a different one.
    /// Otherwise the token is dropped when that resolver returns, so the new
    /// identity never acts on the old one's credential: a revocation checker
    /// would vouch for it, and a delegator would exchange it.
    pub fn supply_inbound_token(&mut self, role: TokenRole, token: RawInboundToken) {
        self.raw_credentials
            .get_or_insert_with(RawCredentialsExtension::default)
            .inbound_tokens
            .insert(role.clone(), token);
        self.tokens_supplied.insert(role);
    }

    /// Drop each token the resolver that turned `before` into this payload
    /// left behind, and clear what it supplied, so the next resolver starts
    /// from nothing supplied.
    pub(crate) fn settle_tokens_after(&mut self, before: &Self) {
        let left_behind = left_behind(&before.slots(), &self.slots(), &self.tokens_supplied);
        self.forget_tokens(&left_behind);
    }

    /// The identity slots and inbound tokens, borrowed.
    fn slots(&self) -> Slots<'_> {
        Slots {
            subject: self.subject.as_ref(),
            client: self.client.as_ref(),
            caller_workload: self.caller_workload.as_ref(),
            tokens: self.raw_credentials.as_ref(),
        }
    }

    /// Remove the tokens for `roles`, and the record of what was supplied.
    fn forget_tokens(&mut self, roles: &[TokenRole]) {
        if let Some(raw) = self.raw_credentials.as_mut() {
            for role in roles {
                raw.inbound_tokens.remove(role);
            }
        }
        self.tokens_supplied.clear();
    }

    /// The field-by-field overlay [`merge`](Self::merge) applies.
    fn merge_fields(&mut self, other: IdentityPayload) {
        self.credential_declined |= other.credential_declined;
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

/// A payload's identity slots and inbound tokens, borrowed.
struct Slots<'a> {
    subject: Option<&'a SubjectExtension>,
    client: Option<&'a ClientExtension>,
    caller_workload: Option<&'a WorkloadIdentity>,
    tokens: Option<&'a RawCredentialsExtension>,
}

/// The roles whose token a resolver left behind going from `before` to
/// `after`: the role's slot changed, the token is still the one `before`
/// carried, and the resolver did not supply it again.
///
/// The whole slot is compared, not an ID. The same ID from two authorities, a
/// JWT `sub` of `42` and an API key's subject `42`, is two identities, and
/// `iss` is not in a subject's claims unless the operator maps it.
fn left_behind(
    before: &Slots<'_>,
    after: &Slots<'_>,
    supplied: &HashSet<TokenRole>,
) -> Vec<TokenRole> {
    [
        (TokenRole::User, before.subject != after.subject),
        (TokenRole::Client, before.client != after.client),
        (
            TokenRole::CallerWorkload,
            before.caller_workload != after.caller_workload,
        ),
    ]
    .into_iter()
    .filter(|(role, slot_changed)| {
        *slot_changed
            && !supplied.contains(role)
            && token(before.tokens, role)
                .zip(token(after.tokens, role))
                .is_some_and(|(then, now)| then == now)
    })
    .map(|(role, _)| role)
    .collect()
}

/// The inbound token stored for `role`.
fn token<'a>(tokens: Option<&'a RawCredentialsExtension>, role: &TokenRole) -> Option<&'a str> {
    tokens?.inbound_tokens.get(role).map(|t| t.token.as_str())
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
    fn debug_output_redacts_raw_token() {
        let p = IdentityPayload::new("eyJ.super-secret-bearer-token.sig", TokenSource::Bearer);
        let debug = format!("{p:?}");
        assert!(
            !debug.contains("super-secret-bearer-token"),
            "raw_token leaked into Debug output: {debug}"
        );
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn debug_output_redacts_header_values() {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_owned(),
            "Bearer eyJ.secret.jwt".to_owned(),
        );
        headers.insert("cookie".to_owned(), "session=abc123".to_owned());
        headers.insert("x-user-token".to_owned(), "custom-secret-token".to_owned());
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        let p = IdentityPayload::new("tok", TokenSource::Bearer).with_headers(headers);
        let debug = format!("{p:?}");
        assert!(
            !debug.contains("eyJ.secret.jwt"),
            "authorization value leaked: {debug}"
        );
        assert!(!debug.contains("abc123"), "cookie value leaked: {debug}");
        assert!(
            !debug.contains("custom-secret-token"),
            "x-user-token value leaked: {debug}"
        );
        assert!(
            !debug.contains("application/json"),
            "content-type value leaked: {debug}"
        );
        assert!(
            debug.contains("authorization"),
            "header name missing: {debug}"
        );
        assert!(debug.contains("cookie"), "header name missing: {debug}");
        assert!(
            debug.contains("x-user-token"),
            "header name missing: {debug}"
        );
        assert!(
            debug.contains("content-type"),
            "header name missing: {debug}"
        );
        assert!(
            debug.contains("[REDACTED]"),
            "redaction placeholder missing: {debug}"
        );
    }

    #[test]
    fn headers_never_serialized() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "Bearer secret-jwt".to_owned());
        headers.insert("x-user-token".to_owned(), "custom-secret".to_owned());
        let p = IdentityPayload::new("tok", TokenSource::Bearer).with_headers(headers);
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("secret-jwt"),
            "authorization value leaked into serialized form: {json}"
        );
        assert!(
            !json.contains("custom-secret"),
            "x-user-token value leaked into serialized form: {json}"
        );
        assert!(
            !json.contains("headers"),
            "headers field should be skipped in serialization: {json}"
        );
    }

    #[test]
    fn headers_absent_after_deserialize_round_trip() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_owned(), "Bearer tok".to_owned());
        let p = IdentityPayload::new("tok", TokenSource::Bearer).with_headers(headers);
        let json = serde_json::to_string(&p).unwrap();
        let restored: IdentityPayload = serde_json::from_str(&json).unwrap();
        assert!(
            restored.headers().is_empty(),
            "headers is serde-skipped and must be empty after round-trip"
        );
    }

    #[test]
    fn handler_can_populate_output_on_clone() {
        let original = IdentityPayload::new("eyJ.tok", TokenSource::Bearer);
        let mut updated = original.clone();
        updated.subject = Some(SubjectExtension {
            id: Some("alice".into()),
            ..Default::default()
        });
        assert_eq!(updated.raw_token(), "eyJ.tok");
        assert_eq!(
            updated.subject.as_ref().unwrap().id.as_deref(),
            Some("alice")
        );
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

    // -------------------------------------------------------------------------
    // Token Binding
    // -------------------------------------------------------------------------

    #[test]
    fn a_replaced_subject_drops_the_token_it_left_behind() {
        let before = authenticated("alice", "alice-jwt");
        let mut after = before.clone();
        after.subject = Some(subject("bob"));

        after.settle_tokens_after(&before);

        assert_eq!(user_token(&after), None, "bob must not carry alice's token");
    }

    #[test]
    fn resolving_the_same_identity_again_keeps_its_token() {
        let before = authenticated("alice", "alice-jwt");
        let mut after = before.clone();
        after.subject = Some(subject("alice"));

        after.settle_tokens_after(&before);

        assert_eq!(user_token(&after), Some("alice-jwt"));
    }

    #[test]
    fn a_resolver_that_brings_its_own_token_keeps_it() {
        let before = authenticated("alice", "alice-jwt");
        let after_resolver = authenticated("bob", "bob-jwt");
        let mut after = after_resolver.clone();

        after.settle_tokens_after(&before);

        assert_eq!(user_token(&after), Some("bob-jwt"));
    }

    #[test]
    fn a_resolver_that_supplies_the_same_token_again_keeps_it() {
        let before = authenticated("alice", "alice-jwt");
        let mut after = before.clone();
        after.subject = Some(subject("alice@corp"));
        after.supply_inbound_token(TokenRole::User, inbound("alice-jwt"));

        after.settle_tokens_after(&before);

        assert_eq!(
            user_token(&after),
            Some("alice-jwt"),
            "the resolver mapped the same credential to a new subject and said so"
        );
    }

    #[test]
    fn the_same_id_from_another_authority_drops_the_token() {
        let mut before = authenticated("42", "jwt-for-42");
        before.subject = Some(SubjectExtension {
            claims: HashMap::from([("azp".to_owned(), "web".into())]),
            ..subject("42")
        });
        let mut after = before.clone();
        after.subject = Some(subject("42"));

        after.settle_tokens_after(&before);

        assert_eq!(
            user_token(&after),
            None,
            "an API-key subject 42 is not the JWT's subject 42"
        );
    }

    #[test]
    fn a_supplied_token_is_not_protected_from_the_next_resolver() {
        let anonymous = IdentityPayload::new("alice-jwt", TokenSource::Bearer);
        let mut first = anonymous.clone();
        first.subject = Some(subject("alice"));
        first.supply_inbound_token(TokenRole::User, inbound("alice-jwt"));
        first.settle_tokens_after(&anonymous);
        let mut second = first.clone();
        second.subject = Some(subject("bob"));

        second.settle_tokens_after(&first);

        assert_eq!(
            user_token(&first),
            Some("alice-jwt"),
            "the first resolver's"
        );
        assert_eq!(user_token(&second), None, "supplied once, not forever");
    }

    #[test]
    fn filling_another_slot_keeps_the_subjects_token() {
        let before = authenticated("alice", "alice-jwt");
        let mut after = before.clone();
        after.client = Some(ClientExtension {
            client_id: "agent".into(),
            ..Default::default()
        });

        after.settle_tokens_after(&before);

        assert_eq!(user_token(&after), Some("alice-jwt"));
    }

    #[test]
    fn merge_drops_a_token_its_slot_no_longer_owns() {
        let mut base = authenticated("alice", "alice-jwt");
        let mut overlay = IdentityPayload::new("key", TokenSource::Bearer);
        overlay.subject = Some(subject("bob"));

        base.merge(overlay);

        assert_eq!(base.subject.as_ref().unwrap().id.as_deref(), Some("bob"));
        assert_eq!(user_token(&base), None, "bob must not carry alice's token");
    }

    #[test]
    fn merge_keeps_a_token_the_overlay_supplied() {
        let mut base = authenticated("alice", "alice-jwt");
        let mut overlay = base.clone();
        overlay.subject = Some(subject("alice@corp"));
        overlay.supply_inbound_token(TokenRole::User, inbound("alice-jwt"));

        base.merge(overlay);

        assert_eq!(user_token(&base), Some("alice-jwt"));
        assert!(base.tokens_supplied.is_empty(), "settled");
    }

    fn subject(id: &str) -> SubjectExtension {
        SubjectExtension {
            id: Some(id.into()),
            ..Default::default()
        }
    }

    fn inbound(token: &str) -> RawInboundToken {
        use crate::extensions::raw_credentials::{Credential, TokenKind};

        RawInboundToken::new(
            token,
            Credential::Header {
                name: "Authorization".into(),
            },
            TokenKind::Jwt,
        )
    }

    /// A payload whose `subject` is `id`, authenticated by `token`, stored
    /// the way a resolver that predates `supply_inbound_token` stores it.
    fn authenticated(id: &str, token: &str) -> IdentityPayload {
        let mut payload = IdentityPayload::new(token, TokenSource::Bearer);
        payload.subject = Some(subject(id));
        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(TokenRole::User, inbound(token));
        payload.raw_credentials = Some(raw);
        payload
    }

    fn user_token(payload: &IdentityPayload) -> Option<&str> {
        payload
            .raw_credentials
            .as_ref()?
            .inbound_tokens
            .get(&TokenRole::User)
            .map(|t| t.token.as_str())
    }
}
