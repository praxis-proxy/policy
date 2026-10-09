// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `identity.resolve` handler.
//
// Delegate the opaque session credential to an external authentication
// endpoint, and project the identity it answers with onto the subject slot. The
// credential is never parsed and never written back: it does not reach
// `raw_credentials`, so nothing downstream can forward the caller's own session
// to an upstream that never authenticated it.
//
// # Unauthenticated is not a deny
//
// A reachable endpoint that says the session is not valid resolves
// *unauthenticated* — no subject, no `deny`. This is deliberate, and the whole
// reason this plugin can front a browser. A hard identity-layer `deny` takes the
// host's rejection path, which answers a fixed 401 and ignores a route's
// `denyWith`; leaving the identity unresolved lets the authorization layer run
// and emit the configured 302 bounce to login. Only a transport failure denies,
// fail-closed.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::host::{HostServices as _, HttpRequestError};
use praxis_policy_core::http::{HeaderMap, HttpRequest, Method};
use praxis_policy_core::http_retry::RetryPolicy;
use praxis_policy_core::identity::mapping::{ClaimMapper as _, ConfiguredClaimMap};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload};
use praxis_policy_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};
use serde_json::Value;

use crate::plugins::identity_forward_auth::config::ForwardAuthConfig;

/// Denial codes, which a host maps to a status.
///
/// They stay apart so an operator watching a spike can tell a refused caller
/// from a broken deployment. `FORBIDDEN` is the endpoint reaching a verdict and
/// refusing the session; `ENDPOINT_UNAVAILABLE` and `MAPPING_FAILED` are
/// deployment faults — an endpoint that cannot be reached or answered with a
/// status that is no verdict at all, or one that accepted the session without
/// returning the identity headers the map needs. A merely *rejected* session
/// (an `unauthenticated_status`) resolves unauthenticated and never reaches here.
pub mod codes {
    /// The sub-request could not be built or completed, or the endpoint answered
    /// with a status that is neither a success nor a configured unauthenticated
    /// verdict (a `503`, say) — no credential verdict to act on, so fail closed.
    pub const ENDPOINT_UNAVAILABLE: &str = "auth.endpoint_unavailable";
    /// The endpoint accepted the session but returned no mappable identity.
    pub const MAPPING_FAILED: &str = "auth.mapping_failed";
    /// The endpoint reached a verdict and forbade the session (HTTP 403).
    pub const FORBIDDEN: &str = "auth.forbidden";
}

/// HTTP 403: the endpoint refusing a session it did reach a verdict on. RFC 9110
/// §15.5.4 — understood but refused, distinct from the unauthenticated statuses.
const FORBIDDEN_STATUS: u16 = 403;

/// Resolves an opaque session to an identity by delegating to an endpoint.
#[derive(Debug)]
pub struct ForwardAuthResolver {
    config: PluginConfig,
    settings: ForwardAuthConfig,
    method: Method,
    mapper: ConfiguredClaimMap,
}

impl ForwardAuthResolver {
    /// Build a resolver from its `config:` block.
    ///
    /// # Errors
    ///
    /// `PluginError::Config` for anything the settings or the claim map reject,
    /// surfaced at config load so a misconfiguration stops startup instead of
    /// denying every request as though the endpoint were down.
    pub fn new(config: PluginConfig) -> Result<Self, Box<PluginError>> {
        if config.mode != PluginMode::Sequential || config.on_error != OnError::Fail {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "{}: an identity resolver needs `mode: sequential` and `on_error: fail`",
                    config.name
                ),
            }));
        }
        let block = config.config.clone().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!("{}: `config:` block is required", config.name),
            })
        })?;
        let mut settings: ForwardAuthConfig =
            serde_json::from_value(block).map_err(|e| PluginError::Config {
                message: format!("{}: {e}", config.name),
            })?;
        // The mapper falls out of validation rather than being compiled a
        // second time from the same block.
        let mapper = settings.validate().map_err(|e| PluginError::Config {
            message: format!("{}: {e}", config.name),
        })?;
        let method = settings.http_method().map_err(|e| PluginError::Config {
            message: format!("{}: {e}", config.name),
        })?;
        // Headers are matched case-insensitively against a lowercase inbound map
        // and a case-insensitive response map; normalising once at load keeps
        // the hot path a plain lookup and the record keys predictable for the
        // claim map.
        for header in &mut settings.forward_headers {
            *header = header.to_ascii_lowercase();
        }
        for header in &mut settings.identity_headers {
            *header = header.to_ascii_lowercase();
        }
        Ok(Self {
            config,
            settings,
            method,
            mapper,
        })
    }

    /// Read the configured identity headers off the response into the record the
    /// claim map projects.
    ///
    /// A header present more than once becomes a JSON array, which the map reads
    /// natively — so a repeated `X-Auth-Request-Groups` maps to `teams` with no
    /// splitting. A single value stays a string.
    ///
    /// Values are decoded as UTF-8 rather than restricted to visible ASCII, so a
    /// claim such as `zoë` maps intact instead of being silently dropped. A value
    /// that is not valid UTF-8 is skipped.
    fn record_from_headers(&self, headers: &HeaderMap) -> HashMap<String, Value> {
        let mut record = HashMap::new();
        for name in &self.settings.identity_headers {
            let mut values = headers
                .get_all(name.as_str())
                .iter()
                .filter_map(|value| std::str::from_utf8(value.as_bytes()).ok())
                .map(|text| Value::String(text.to_owned()));
            match (values.next(), values.next()) {
                (None, _) => {},
                (Some(first), None) => {
                    record.insert(name.clone(), first);
                },
                (Some(first), Some(second)) => {
                    let mut array = vec![first, second];
                    array.extend(values);
                    record.insert(name.clone(), Value::Array(array));
                },
            }
        }
        record
    }
}

#[async_trait::async_trait]
impl Plugin for ForwardAuthResolver {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<IdentityHook> for ForwardAuthResolver {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        // Gather the forwardable headers the request actually carries. With
        // none of them, there is no session to delegate: resolve unauthenticated
        // without spending a round trip on a request that cannot be signed in.
        let headers = payload.headers();
        let present: Vec<(&String, &String)> = self
            .settings
            .forward_headers
            .iter()
            .filter_map(|name| headers.get_key_value(name))
            .collect();
        if present.is_empty() {
            return PluginResult::modify_payload(payload.clone());
        }

        let mut request = HttpRequest::new(self.method.clone(), &self.settings.endpoint)
            .timeout(Duration::from_secs(self.settings.timeout_secs))
            .max_response_bytes(self.settings.max_response_bytes);
        if let Some(secs) = self.settings.connect_timeout_secs {
            request = request.connect_timeout(Duration::from_secs(secs));
        }
        for (name, value) in present {
            match request.header(name, value) {
                Ok(next) => request = next,
                Err(error) => {
                    // The value arrived as an inbound header, so this is close to
                    // unreachable; denying rather than dropping the header keeps a
                    // request from being signed in on a credential we failed to
                    // forward intact.
                    tracing::warn!(header = %name, %error, "forward_auth could not forward a header");
                    return PluginResult::deny(PluginViolation::new(
                        codes::ENDPOINT_UNAVAILABLE,
                        "could not build the authentication sub-request",
                    ));
                },
            }
        }

        // `Extensions` is the request's carrier of host services, already
        // capability filtered by the executor, so egress is reached through the
        // same value every hook receives. Retry only an *undelivered* attempt:
        // the sub-request is a side-effect-free read, but `idempotent()` also
        // retries a delivered attempt that timed out, which would let a stalled
        // endpoint hold a caller for up to `max_attempts × timeout_secs` despite
        // the per-request `timeout_secs` ceiling.
        let response = match ext
            .http_request(request, RetryPolicy::undelivered_only())
            .await
        {
            Ok(response) => response,
            Err(error) => {
                // A transport fault is a deployment fault, not a rejected
                // caller. Fail-closed: `on_error: fail` is required, so a browser
                // is held at the edge rather than let through unauthenticated.
                let detail = match error {
                    HttpRequestError::Unavailable(detail) => {
                        format!("no HTTP transport for the auth endpoint: {detail}")
                    },
                    other => other.to_string(),
                };
                tracing::warn!(error = %detail, "forward_auth sub-request failed");
                return PluginResult::deny(PluginViolation::new(
                    codes::ENDPOINT_UNAVAILABLE,
                    "the authentication endpoint could not be reached",
                ));
            },
        };

        // Classify the status explicitly rather than treating "not a success" as
        // "unauthenticated": an endpoint fault (a `503`) is not a credential
        // verdict, and signing a caller out on one would be wrong.
        let status = response.status;
        if self.settings.success_status.contains(&status) {
            let record = self.record_from_headers(&response.headers);
            match self.mapper.map_subject(&record) {
                Some(subject) => {
                    let mut updated = payload.clone();
                    updated.subject = Some(subject);
                    updated.resolved_at = Some(Utc::now());
                    // `raw_credentials` is deliberately not populated: the
                    // session stops here, so no PPE step such as `delegate`
                    // forwards it. The inbound `Cookie` header itself still
                    // reaches the upstream unless `assertions.request.strip`
                    // lists `cookie` — strip it before a less-trusted upstream.
                    PluginResult::modify_payload(updated)
                },
                // The session is valid but the endpoint returned no identity the
                // map could project — the BFF is not emitting the identity
                // headers (e.g. `--set-xauthrequest` is off). A deployment fault,
                // not a rejected caller: denying surfaces it instead of bouncing
                // a signed-in user to login forever.
                None => PluginResult::deny(PluginViolation::new(
                    codes::MAPPING_FAILED,
                    "the authentication endpoint accepted the session but returned no mappable \
                     identity: check that it sets the configured identity headers",
                )),
            }
        } else if self.settings.unauthenticated_status.contains(&status) {
            // Reachable, and the endpoint says the session is absent or not
            // valid. Resolve unauthenticated — no subject, no deny — so the
            // authorization layer can emit the configured bounce to login rather
            // than the host's fixed 401. See the module header.
            PluginResult::modify_payload(payload.clone())
        } else if status == FORBIDDEN_STATUS {
            // The endpoint reached a verdict and refused the session outright.
            // That is a denied caller, not "sign in again" and not an outage, so
            // it carries its own code to keep the three spikes apart.
            tracing::warn!(status, "forward_auth endpoint forbade the session");
            PluginResult::deny(PluginViolation::new(
                codes::FORBIDDEN,
                "the authentication endpoint forbade the session",
            ))
        } else {
            // Neither a success, a configured unauthenticated status, nor a
            // forbidden verdict: the endpoint answered something that is no
            // credential verdict at all (a `503`, say). Fail closed rather than
            // signing the caller out on an endpoint fault.
            tracing::warn!(
                status,
                "forward_auth endpoint returned an unexpected status"
            );
            PluginResult::deny(PluginViolation::new(
                codes::ENDPOINT_UNAVAILABLE,
                "the authentication endpoint returned an unexpected status",
            ))
        }
    }
}
