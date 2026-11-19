// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `revocation.check` handler. For each slot the engine asks about, it
// takes the slot's raw inbound token, confirms the token names the configured
// issuer, and asks that issuer whether the token is still active. Slots are
// introspected concurrently, so the check costs one round trip, not three.

use std::time::Duration;

use base64::Engine as _;
use futures::future::join_all;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::host::HostServices as _;
use praxis_policy_core::http::{HttpRequest, form_urlencode};
use praxis_policy_core::http_retry::RetryPolicy;
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::revocation::{
    IdentitySlot, REVOCATION_UNAVAILABLE_CODE, REVOCATION_UNAVAILABLE_REASON, REVOKED_CODE,
    REVOKED_REASON, RevocationCheck, RevocationHook,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::plugins::revocation_introspection::KIND;
use crate::plugins::revocation_introspection::config::IntrospectionConfig;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// An introspection response is a small JSON object. The ceiling stops a
/// broken endpoint streaming without end.
const RESPONSE_MAX_BYTES: usize = 16 * 1024;

// -----------------------------------------------------------------------------
// Checker
// -----------------------------------------------------------------------------

/// What the issuer said about one token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Status {
    Active,
    Inactive,
    Unavailable,
}

/// The RFC 7662 response fields this checker reads.
#[derive(Deserialize)]
struct IntrospectionResponse {
    active: bool,
}

/// The claims read from a token before it is sent anywhere.
#[derive(Deserialize)]
struct Issuer {
    iss: String,
}

/// An RFC 7662 revocation checker bound to one issuer.
pub struct IntrospectionChecker {
    config: PluginConfig,
    typed: IntrospectionConfig,
    authorization: Zeroizing<String>,
    timeout: Duration,
}

impl std::fmt::Debug for IntrospectionChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionChecker")
            .field("name", &self.config.name)
            .field("issuer", &self.typed.issuer)
            .field("introspection_endpoint", &self.typed.introspection_endpoint)
            .field("authorization", &"<elided>")
            .finish_non_exhaustive()
    }
}

impl IntrospectionChecker {
    /// Build the checker from its plugin config.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Config`] when the `config:` block is missing or
    /// malformed, a required field is empty, the endpoint is not `https://`
    /// without `insecure_http`, the timeout is zero, or the client secret
    /// cannot be read.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let fail = |message: String| {
            PluginError::Config {
                message: format!("plugin '{}' ({KIND}): {message}", cfg.name),
            }
            .boxed()
        };
        let raw = cfg
            .config
            .as_ref()
            .ok_or_else(|| fail("requires a `config:` block".to_owned()))?;
        let typed: IntrospectionConfig = serde_json::from_value(raw.clone())
            .map_err(|e| fail(format!("config parse failed: {e}")))?;

        if typed.issuer.trim().is_empty() {
            return Err(fail("issuer must be non-empty".to_owned()));
        }
        if typed.client_id.trim().is_empty() {
            return Err(fail("client_id must be non-empty".to_owned()));
        }
        if typed.timeout_ms == 0 {
            return Err(fail("timeout_ms must be nonzero".to_owned()));
        }
        require_https(&typed.introspection_endpoint, typed.insecure_http)
            .map_err(|e| fail(format!("introspection_endpoint {e}")))?;
        let secret = Zeroizing::new(typed.client_secret_source.resolve().map_err(fail)?);
        let authorization = basic_authorization(&typed.client_id, &secret);
        let timeout = typed.timeout();

        Ok(Self {
            config: cfg,
            typed,
            authorization,
            timeout,
        })
    }

    /// The slot's raw inbound token, when it names this checker's issuer.
    fn token_for<'ext>(&self, ext: &'ext Extensions, slot: IdentitySlot) -> Option<&'ext str> {
        let token = ext
            .raw_credentials
            .as_ref()?
            .inbound_tokens
            .get(&slot.token_role())?;
        (issuer_of(&token.token).as_deref() == Some(self.typed.issuer.as_str()))
            .then_some(token.token.as_str())
    }

    /// Ask the issuer about one slot's token, logging what the caller is
    /// not told.
    async fn status(&self, ext: &Extensions, slot: IdentitySlot, token: &str) -> Status {
        match self.introspect(ext, token).await {
            Ok(true) => Status::Active,
            Ok(false) => {
                tracing::info!(plugin = %self.config.name, ?slot, "credential revoked");
                Status::Inactive
            },
            Err(error) => {
                tracing::warn!(
                    plugin = %self.config.name,
                    ?slot,
                    endpoint = %self.typed.introspection_endpoint,
                    %error,
                    "revocation status unavailable"
                );
                Status::Unavailable
            },
        }
    }

    /// POST the token to the introspection endpoint and read `active`.
    async fn introspect(&self, ext: &Extensions, token: &str) -> Result<bool, String> {
        let body = form_urlencode(&[("token", token), ("token_type_hint", "access_token")]);
        let request = HttpRequest::post(&self.typed.introspection_endpoint, body)
            .timeout(self.timeout)
            .max_response_bytes(RESPONSE_MAX_BYTES)
            .header("content-type", "application/x-www-form-urlencoded")
            .and_then(|r| r.header("accept", "application/json"))
            .and_then(|r| r.header("authorization", self.authorization.as_str()))
            .map_err(|e| format!("request could not be built: {e}"))?;
        let response = ext
            .http_request(request, RetryPolicy::undelivered_only())
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if response.status != 200 {
            return Err(format!("status {}", response.status));
        }
        serde_json::from_slice::<IntrospectionResponse>(&response.body)
            .map(|parsed| parsed.active)
            .map_err(|e| format!("malformed response: {e}"))
    }
}

impl Plugin for IntrospectionChecker {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<RevocationHook> for IntrospectionChecker {
    async fn handle(
        &self,
        check: &RevocationCheck,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<RevocationCheck> {
        let covered = check
            .slots()
            .iter()
            .filter_map(|&slot| self.token_for(ext, slot).map(|token| (slot, token)));
        let statuses = join_all(
            covered.map(|(slot, token)| async move { (slot, self.status(ext, slot, token).await) }),
        )
        .await;

        if statuses
            .iter()
            .any(|&(_, status)| status == Status::Inactive)
        {
            return PluginResult::deny(PluginViolation::new(REVOKED_CODE, REVOKED_REASON));
        }
        if statuses
            .iter()
            .any(|&(_, status)| status == Status::Unavailable)
        {
            return PluginResult::deny(PluginViolation::new(
                REVOCATION_UNAVAILABLE_CODE,
                REVOCATION_UNAVAILABLE_REASON,
            ));
        }
        PluginResult::modify_payload(
            statuses
                .into_iter()
                .fold(check.clone(), |answered, (slot, _)| answered.vouch(slot)),
        )
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// The `iss` claim of a JWT, read without verifying it.
///
/// Authentication already verified the token. This only decides whether the
/// token belongs to this checker's issuer, so a token is never sent to an
/// issuer that did not mint it. An opaque token has no readable issuer and is
/// left for another checker.
fn issuer_of(token: &str) -> Option<String> {
    let claims = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims)
        .ok()?;
    serde_json::from_slice::<Issuer>(&decoded)
        .ok()
        .map(|issuer| issuer.iss)
}

/// `Basic base64(client_id:client_secret)`, as the OAuth delegator sends it.
fn basic_authorization(client_id: &str, secret: &str) -> Zeroizing<String> {
    let raw = Zeroizing::new(format!("{client_id}:{secret}"));
    Zeroizing::new(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    ))
}

/// Accept `https://`, and `http://` only with `insecure_http`.
fn require_https(url: &str, insecure_http: bool) -> Result<(), String> {
    let lowered = url.trim_start().to_ascii_lowercase();
    if lowered.starts_with("https://") || (insecure_http && lowered.starts_with("http://")) {
        return Ok(());
    }
    Err(format!(
        "must use https:// (got '{url}'); `insecure_http: true` allows http:// for local \
         development only"
    ))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use praxis_policy_core::extensions::raw_credentials::{
        Credential, RawCredentialsExtension, RawInboundToken, TokenKind,
    };
    use praxis_policy_core::host::HttpTransportSlot;
    use praxis_policy_core::http::{HttpTransport, HttpTransportError};
    use praxis_policy_core::http_testing::FakeTransport;
    use praxis_policy_core::revocation::CheckPoint;
    use serde_json::json;

    use super::*;

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    const ISSUER: &str = "https://idp.example/realms/demo";

    fn checker(overrides: serde_json::Value) -> IntrospectionChecker {
        let mut config = json!({
            "issuer": ISSUER,
            "introspection_endpoint": "https://idp.example/introspect",
            "client_id": "ppe",
            "client_secret_source": { "kind": "literal", "secret": "s3cret" },
        });
        for (key, value) in overrides.as_object().unwrap() {
            config[key] = value.clone();
        }
        IntrospectionChecker::new(PluginConfig {
            name: "introspect".into(),
            kind: KIND.into(),
            config: Some(config),
            ..Default::default()
        })
        .expect("the fixture config builds")
    }

    fn jwt(iss: &str) -> String {
        let encode = |value: serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        format!(
            "{}.{}.signature",
            encode(json!({ "alg": "RS256" })),
            encode(json!({ "iss": iss, "sub": "alice" }))
        )
    }

    fn ext(transport: &Arc<FakeTransport>, tokens: &[(IdentitySlot, String)]) -> Extensions {
        let http: Arc<dyn HttpTransport> = transport.clone();
        let inbound_tokens: HashMap<_, _> = tokens
            .iter()
            .map(|(slot, token)| {
                (
                    slot.token_role(),
                    RawInboundToken::new(
                        token.clone(),
                        Credential::Header {
                            name: "authorization".into(),
                        },
                        TokenKind::Jwt,
                    ),
                )
            })
            .collect();
        Extensions {
            http_transport: HttpTransportSlot::installed(http),
            raw_credentials: Some(Arc::new(RawCredentialsExtension {
                inbound_tokens,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn asked(slots: &[IdentitySlot]) -> RevocationCheck {
        RevocationCheck::new(CheckPoint::AfterAuthentication, slots.iter().copied())
    }

    async fn run(
        checker: &IntrospectionChecker,
        check: &RevocationCheck,
        ext: &Extensions,
    ) -> PluginResult<RevocationCheck> {
        let mut ctx = PluginContext::default();
        checker.handle(check, ext, &mut ctx).await
    }

    fn vouched(result: &PluginResult<RevocationCheck>) -> Vec<IdentitySlot> {
        assert!(result.violation.is_none(), "{:?}", result.violation);
        result
            .modified_payload
            .as_ref()
            .expect("an allow carries the answer")
            .vouched()
            .iter()
            .copied()
            .collect()
    }

    fn denied_with(result: &PluginResult<RevocationCheck>) -> (&str, &str, bool) {
        let violation = result.violation.as_ref().expect("a deny");
        (
            violation.code.as_str(),
            violation.reason.as_str(),
            violation.details.is_empty(),
        )
    }

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    #[test]
    fn a_plaintext_endpoint_needs_insecure_http() {
        let config = |insecure: bool| PluginConfig {
            name: "introspect".into(),
            kind: KIND.into(),
            config: Some(json!({
                "issuer": ISSUER,
                "introspection_endpoint": "http://localhost:8080/introspect",
                "client_id": "ppe",
                "client_secret_source": { "kind": "literal", "secret": "s" },
                "insecure_http": insecure,
            })),
            ..Default::default()
        };

        assert!(
            IntrospectionChecker::new(config(false)).is_err(),
            "http:// is refused by default"
        );
        assert!(
            IntrospectionChecker::new(config(true)).is_ok(),
            "insecure_http allows it"
        );
    }

    #[test]
    fn construction_rejects_each_unusable_setting() {
        for (key, value) in [
            ("issuer", json!(" ")),
            ("client_id", json!("")),
            ("timeout_ms", json!(0)),
            (
                "introspection_endpoint",
                json!("ftp://idp.example/introspect"),
            ),
            (
                "client_secret_source",
                json!({ "kind": "env_var", "name": "_PPE_INTROSPECTION_SECRET_NOT_SET_" }),
            ),
        ] {
            let mut config = json!({
                "issuer": ISSUER,
                "introspection_endpoint": "https://idp.example/introspect",
                "client_id": "ppe",
                "client_secret_source": { "kind": "literal", "secret": "s" },
            });
            config[key] = value;

            let error = IntrospectionChecker::new(PluginConfig {
                name: "introspect".into(),
                kind: KIND.into(),
                config: Some(config),
                ..Default::default()
            })
            .expect_err(key);

            assert!(
                matches!(*error, PluginError::Config { .. }),
                "{key}: {error}"
            );
        }
    }

    #[test]
    fn debug_output_elides_the_client_secret() {
        let rendered = format!("{:?}", checker(json!({})));

        assert!(!rendered.contains("s3cret"), "{rendered}");
        assert!(
            !rendered.contains(&basic_authorization("ppe", "s3cret").to_string()),
            "{rendered}"
        );
    }

    // -------------------------------------------------------------------------
    // Verdicts
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn an_active_token_vouches_for_its_slot() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let ext = ext(&transport, &[(IdentitySlot::Client, jwt(ISSUER))]);

        let result = run(&checker(json!({})), &asked(&[IdentitySlot::Client]), &ext).await;

        assert_eq!(vouched(&result), vec![IdentitySlot::Client], "vouched");
    }

    #[tokio::test]
    async fn an_inactive_token_denies_as_revoked_with_no_detail() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":false}"#));
        let ext = ext(&transport, &[(IdentitySlot::Subject, jwt(ISSUER))]);

        let result = run(&checker(json!({})), &asked(&[IdentitySlot::Subject]), &ext).await;

        assert_eq!(
            denied_with(&result),
            (REVOKED_CODE, REVOKED_REASON, true),
            "fixed code and reason, empty details"
        );
    }

    #[tokio::test]
    async fn each_failed_lookup_denies_as_unavailable_with_no_detail() {
        for transport in [
            FakeTransport::new().json("/introspect", 500, "upstream exploded"),
            FakeTransport::new().json("/introspect", 401, r#"{"error":"invalid_client"}"#),
            FakeTransport::new().json("/introspect", 200, "not json"),
            FakeTransport::new().json("/introspect", 200, r#"{"scope":"read"}"#),
            FakeTransport::new().fail("/introspect", HttpTransportError::Timeout),
        ] {
            let transport = Arc::new(transport);
            let ext = ext(&transport, &[(IdentitySlot::Client, jwt(ISSUER))]);

            let result = run(&checker(json!({})), &asked(&[IdentitySlot::Client]), &ext).await;

            assert_eq!(
                denied_with(&result),
                (
                    REVOCATION_UNAVAILABLE_CODE,
                    REVOCATION_UNAVAILABLE_REASON,
                    true
                ),
                "a failure is never a pass and names no upstream detail"
            );
        }
    }

    #[tokio::test]
    async fn a_revoked_slot_outranks_an_unavailable_one() {
        let transport = Arc::new(
            FakeTransport::new()
                .json("/introspect", 200, r#"{"active":false}"#)
                .json("/introspect", 500, ""),
        );
        let ext = ext(
            &transport,
            &[
                (IdentitySlot::Subject, jwt(ISSUER)),
                (IdentitySlot::Client, jwt(ISSUER)),
            ],
        );

        let result = run(
            &checker(json!({})),
            &asked(&[IdentitySlot::Subject, IdentitySlot::Client]),
            &ext,
        )
        .await;

        assert_eq!(denied_with(&result).0, REVOKED_CODE, "revoked wins");
    }

    // -------------------------------------------------------------------------
    // Coverage
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn a_token_from_another_issuer_is_neither_sent_nor_vouched() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let ext = ext(
            &transport,
            &[(IdentitySlot::Client, jwt("https://other.example/realms/x"))],
        );

        let result = run(&checker(json!({})), &asked(&[IdentitySlot::Client]), &ext).await;

        assert!(vouched(&result).is_empty(), "not this checker's issuer");
        assert_eq!(transport.call_count(), 0, "the token never left");
    }

    #[tokio::test]
    async fn a_slot_with_no_raw_token_or_an_opaque_one_is_left_unvouched() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let ext = ext(&transport, &[(IdentitySlot::Client, "opaque-token".into())]);

        let result = run(
            &checker(json!({})),
            &asked(&[IdentitySlot::Subject, IdentitySlot::Client]),
            &ext,
        )
        .await;

        assert!(
            vouched(&result).is_empty(),
            "nothing this checker can cover"
        );
        assert_eq!(transport.call_count(), 0, "nothing was sent");
    }

    #[tokio::test]
    async fn only_the_slots_asked_about_are_checked() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let ext = ext(
            &transport,
            &[
                (IdentitySlot::Subject, jwt(ISSUER)),
                (IdentitySlot::Client, jwt(ISSUER)),
            ],
        );

        let result = run(&checker(json!({})), &asked(&[IdentitySlot::Client]), &ext).await;

        assert_eq!(vouched(&result), vec![IdentitySlot::Client], "vouched");
        assert_eq!(transport.call_count(), 1, "one slot, one call");
    }

    // -------------------------------------------------------------------------
    // Request
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn the_request_carries_the_token_and_client_credentials() {
        let token = jwt(ISSUER);
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let ext = ext(&transport, &[(IdentitySlot::Client, token.clone())]);

        run(&checker(json!({})), &asked(&[IdentitySlot::Client]), &ext).await;

        let request = transport.last_request().expect("a request was sent");
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        assert_eq!(
            String::from_utf8_lossy(&request.body),
            String::from_utf8_lossy(&form_urlencode(&[
                ("token", &token),
                ("token_type_hint", "access_token"),
            ])),
            "body"
        );
        assert_eq!(
            header("authorization"),
            Some(basic_authorization("ppe", "s3cret").to_string()),
            "client_secret_basic"
        );
        assert_eq!(
            header("content-type").as_deref(),
            Some("application/x-www-form-urlencoded"),
            "content type"
        );
        assert_eq!(request.timeout, Duration::from_millis(500), "timeout");
    }
}
