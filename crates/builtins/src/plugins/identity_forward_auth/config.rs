// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The config block an operator writes, and what it rejects at load.
//
// Everything checkable is checked here. A resolver that builds and then denies
// every request reads as an outage, and the operator looking at it is reading
// the wrong logs.

use praxis_policy_core::extensions::raw_credentials::TokenRole;
use praxis_policy_core::http::Method;
use praxis_policy_core::identity::mapping::{ClaimMapConfig, ClaimsOverrides, ConfiguredClaimMap};
use serde::{Deserialize, Serialize};

fn default_method() -> String {
    "GET".to_owned()
}

fn default_forward_headers() -> Vec<String> {
    vec!["cookie".to_owned()]
}

fn default_identity_headers() -> Vec<String> {
    // The common `X-Auth-Request-*` convention a forward-auth endpoint sets on
    // its validation response. An operator fronting an endpoint that emits a
    // different set overrides the list; these are the defaults that make the
    // common deployment work with no extra config, and the claim map decides
    // which of them become a subject.
    vec![
        "x-auth-request-user".to_owned(),
        "x-auth-request-preferred-username".to_owned(),
        "x-auth-request-email".to_owned(),
        "x-auth-request-groups".to_owned(),
    ]
}

fn default_success_status() -> Vec<u16> {
    vec![200, 202]
}

fn default_unauthenticated_status() -> Vec<u16> {
    // The status a reachable endpoint uses to say the session is absent or no
    // longer valid. A validation endpoint typically answers `401`; an endpoint
    // that bounces with a `302` to login instead lists that status here. Only
    // these resolve *unauthenticated* — every other unexpected status fails
    // closed, so an endpoint fault is never mistaken for a signed-out caller.
    vec![401]
}

fn default_timeout_secs() -> u64 {
    5
}

fn default_max_response_bytes() -> usize {
    // The auth sub-request answers with a verdict and a handful of identity
    // headers; its body is empty or tiny. A small ceiling stops a broken or
    // replaced endpoint streaming without end into a buffer on the request path.
    64 * 1024
}

/// The `config:` block under a `kind: identity/forward-auth` plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardAuthConfig {
    /// Where the auth sub-request is sent, e.g.
    /// `http://127.0.0.1:4180/oauth2/auth`.
    ///
    /// The endpoint validates the opaque credential and answers with a verdict
    /// and, on success, the identity headers the claim map reads. PPE never
    /// parses the credential itself — that is the whole point of delegating.
    pub endpoint: String,

    /// The method the sub-request uses.
    ///
    /// `GET` by default, which is what a `ForwardAuth` / `auth_request` endpoint
    /// expects. The sub-request must be side-effect free whatever this is: it
    /// is retried on an undelivered failure.
    #[serde(default = "default_method")]
    pub method: String,

    /// Inbound request headers copied verbatim onto the sub-request.
    ///
    /// The session credential rides here. `cookie` by default, because the BFF
    /// owns a cookie; a deployment carrying the session elsewhere lists that
    /// header instead. When the request carries none of these, there is nothing
    /// to delegate and the caller resolves unauthenticated with no round trip.
    #[serde(default = "default_forward_headers")]
    pub forward_headers: Vec<String>,

    /// Response headers read into the record the claim map projects.
    ///
    /// Only these reach the map, so the endpoint's own bookkeeping headers
    /// (`content-type`, `date`, …) never leak into the claims bag. Matched
    /// case-insensitively and exposed to the claim map under their lowercase
    /// name, so an operator writes `id: x-auth-request-user`.
    #[serde(default = "default_identity_headers")]
    pub identity_headers: Vec<String>,

    /// Statuses that mean the credential is valid.
    ///
    /// `[200, 202]` by default — a validation endpoint commonly answers `200` or
    /// `202 Accepted` on a valid session. These project the identity headers onto
    /// the subject.
    #[serde(default = "default_success_status")]
    pub success_status: Vec<u16>,

    /// Statuses that mean the credential is absent or not valid.
    ///
    /// `[401]` by default — a reachable endpoint saying the session is not
    /// valid. These resolve *unauthenticated* (no subject, no `deny`) so the
    /// authorization layer can bounce a browser to login; an endpoint that
    /// answers `302` instead of `401` lists that status here. A reachable status
    /// that is neither a success nor listed here is not a credential verdict and
    /// fails closed (see the resolver), so an endpoint fault is never mistaken
    /// for a signed-out caller.
    #[serde(default = "default_unauthenticated_status")]
    pub unauthenticated_status: Vec<u16>,

    /// The identity headers onto the subject slots.
    #[serde(default)]
    pub claim_map: ClaimMapConfig,

    /// Which fields the projected claims bag keeps or drops.
    #[serde(default)]
    pub claims: ClaimsOverrides,

    /// Overall deadline for the sub-request, covering connect and I/O.
    ///
    /// It sits on the request path, so this is a ceiling on how long a caller
    /// waits for an endpoint that has stopped answering.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Bound on connection establishment alone. Left to the transport when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,

    /// Ceiling on the response body the sub-request will buffer.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

impl ForwardAuthConfig {
    /// The configured method, parsed.
    ///
    /// # Errors
    ///
    /// A string that is not a legal HTTP method.
    pub fn http_method(&self) -> Result<Method, String> {
        Method::try_from(self.method.as_str())
            .map_err(|e| format!("`method` is not a valid HTTP method: {e}"))
    }

    /// Reject what cannot work, before a request depends on it, and return the
    /// mapper the checking produced.
    ///
    /// Compiling the `claim_map` *is* most of the validation, so the compiled
    /// map comes back rather than being thrown away and rebuilt: two compiles
    /// is two places that could disagree about what an operator wrote.
    ///
    /// # Errors
    ///
    /// An endpoint that is not absolute HTTP(S), an unparseable method, an empty
    /// header list or header name, an empty success-status or
    /// unauthenticated-status list, a status that is both, a zero timeout or body
    /// ceiling, a `claim_map` the shared compiler refuses, a map with no subject
    /// section (which would decline every valid session), or a subject path that
    /// names no configured identity header (which would compile and then fail
    /// every session with `auth.mapping_failed`).
    pub fn validate(&self) -> Result<ConfiguredClaimMap, String> {
        if !(self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://")) {
            return Err(format!(
                "`endpoint` must be an absolute http or https URL, got '{}'",
                self.endpoint
            ));
        }
        self.http_method()?;
        if self.forward_headers.is_empty() {
            return Err(
                "`forward_headers` is empty, so no credential would ever be delegated".to_owned(),
            );
        }
        if self.forward_headers.iter().any(|h| h.trim().is_empty()) {
            return Err("`forward_headers` has an empty header name".to_owned());
        }
        if self.identity_headers.is_empty() {
            return Err(
                "`identity_headers` is empty, so no response header would ever map to a subject"
                    .to_owned(),
            );
        }
        if self.identity_headers.iter().any(|h| h.trim().is_empty()) {
            return Err("`identity_headers` has an empty header name".to_owned());
        }
        if self.success_status.is_empty() {
            return Err(
                "`success_status` is empty, so no answer could ever authenticate a session"
                    .to_owned(),
            );
        }
        if self.unauthenticated_status.is_empty() {
            return Err(
                "`unauthenticated_status` is empty, so a rejected session could never resolve \
                 unauthenticated to bounce to login"
                    .to_owned(),
            );
        }
        if let Some(status) = self
            .success_status
            .iter()
            .find(|status| self.unauthenticated_status.contains(status))
        {
            return Err(format!(
                "status {status} is in both `success_status` and `unauthenticated_status`; a \
                 status cannot mean both a valid and an invalid session"
            ));
        }
        if self.timeout_secs == 0 {
            return Err("`timeout_secs` is zero, so every sub-request would time out".to_owned());
        }
        if self.max_response_bytes == 0 {
            return Err("`max_response_bytes` is zero".to_owned());
        }
        let mapper = crate::plugins::identity_forward_auth::response_map::compile(
            &self.claim_map,
            &self.claims,
        )?;
        // A map that declares no subject section maps nothing, every time, and
        // the resulting `auth.mapping_failed` names a record rather than the
        // config that cannot project one.
        let subject = mapper.compiled().role(&TokenRole::User).map_err(|e| {
            format!("`claim_map` has no `subject` section, so no session could authenticate: {e}")
        })?;
        // The record the map reads is keyed by the identity headers, lowercased
        // (see the resolver). A single-segment subject path names one such key
        // directly, so a path pointing at a header that is not in
        // `identity_headers` would compile and then miss every record, failing
        // each session with `auth.mapping_failed`. Catch it at load, matching
        // case-insensitively because the record keys are lowercased.
        for (field, compiled) in subject.fields() {
            for candidate in compiled.candidates() {
                let Some(segment) = candidate.path().single_segment() else {
                    // A traversing path cannot name a flat record key; leave it
                    // to the shared compiler rather than second-guessing it here.
                    continue;
                };
                if !self
                    .identity_headers
                    .iter()
                    .any(|header| header.eq_ignore_ascii_case(segment))
                {
                    return Err(format!(
                        "`claim_map` subject field `{field}` reads `{segment}`, which names no \
                         configured identity header; `identity_headers` = {:?}",
                        self.identity_headers
                    ));
                }
            }
        }
        Ok(mapper)
    }
}
