// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `identity.resolve` handler. It authenticates a bearer token by asking
// the issuer about it (RFC 7662), and maps the active response onto one
// identity slot through the shared claim mapper. This is how a token that no
// offline resolver can verify, an opaque one, becomes an identity.
//
// The token is stored for later plugins with the issuer recorded on it, so a
// revocation check by this same plugin can cover it although it carries no
// readable `iss`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::extensions::raw_credentials::{
    Credential, RawInboundToken, TokenKind, TokenRole,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::mapping::{
    ClaimMapConfig, ClaimMapper as _, ConfiguredClaimMap, MappingProfile,
};
use praxis_policy_core::identity::{
    CredentialLocation, ExtractionError, IdentityHook, IdentityPayload,
};
use praxis_policy_core::plugin::PluginConfig;
use serde::Deserialize;
use serde_json::Value;

use crate::plugins::oauth_introspection::IntrospectionPlugin;
use crate::plugins::oauth_introspection::cache::Answer;
use crate::plugins::oauth_introspection::client::issuer_of;
use crate::plugins::oauth_introspection::config::IdentitySettings;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Denial codes this resolver adds. The rest are the ones `identity/jwt` and
/// `identity/api-key` already use for the same failures.
pub(crate) mod codes {
    /// The issuer reports the token is not active: unknown, expired, or
    /// revoked. RFC 7662 does not say which, and neither does this code.
    pub(crate) const TOKEN_INACTIVE: &str = "auth.token_inactive";
    /// The introspection endpoint could not answer.
    pub(crate) const INTROSPECTION_UNAVAILABLE: &str = "auth.introspection_unavailable";
}

/// How a response maps. The registered names are kept out of the claims bag,
/// as `identity/jwt` keeps them out, plus `active` and `token_type`, which
/// describe the answer rather than the identity.
const PROFILE: MappingProfile = MappingProfile {
    reserved_names: &[
        "active",
        "aud",
        "exp",
        "iat",
        "iss",
        "jti",
        "nbf",
        "sub",
        "token_type",
    ],
    attestor: "oauth_introspection",
};

/// The map an absent `record_map` uses: `identity/jwt`'s `standard` preset.
/// An RFC 7662 response carries the same claim names a JWT does.
const STANDARD_MAP: &str = include_str!("../identity_jwt/presets/standard.json");

#[derive(Deserialize)]
struct Preset {
    claim_map: ClaimMapConfig,
}

// -----------------------------------------------------------------------------
// Resolution
// -----------------------------------------------------------------------------

/// The compiled `identity:` block.
pub(crate) struct Resolution {
    role: TokenRole,
    location: CredentialLocation,
    mapper: ConfiguredClaimMap,
    audiences: Vec<String>,
    leeway: Duration,
}

impl Resolution {
    /// Compile the block for the plugin `cfg` describes.
    ///
    /// # Errors
    ///
    /// A location no request can satisfy, a query-parameter location without
    /// the `read_query` capability, a map the shared compiler refuses, or a
    /// map with no section for the configured role.
    pub(crate) fn new(settings: &IdentitySettings, cfg: &PluginConfig) -> Result<Self, String> {
        let location =
            CredentialLocation::new(settings.credential.clone(), settings.prefix.clone());
        location.validate()?;
        if matches!(location.credential, Credential::QueryParam { .. })
            && !cfg.capabilities.contains("read_query")
        {
            return Err("`credential.kind: query_param` needs the `read_query` capability".into());
        }
        let map = match &settings.record_map {
            Some(map) => map.clone(),
            None => standard_map()?,
        };
        let mapper = ConfiguredClaimMap::new(
            map.compile()?.with_claims(settings.claims.compile()?),
            PROFILE,
        );
        mapper.compiled().role(&settings.role).map_err(|e| {
            format!(
                "`record_map` has no section for `role: {:?}`: {e}",
                settings.role
            )
        })?;
        Ok(Self {
            role: settings.role.clone(),
            location,
            mapper,
            audiences: settings.audiences.clone(),
            leeway: Duration::from_secs(settings.leeway_seconds),
        })
    }

    /// Whether `answer` authenticates a caller of `issuer` at `now`.
    fn accept(
        &self,
        answer: &Answer,
        issuer: &str,
        now: SystemTime,
    ) -> Result<(), Box<PluginViolation>> {
        let refuse = |code: &str, reason: &str| Err(Box::new(PluginViolation::new(code, reason)));
        if !answer.active {
            return refuse(
                codes::TOKEN_INACTIVE,
                "the issuer reports the token is not active",
            );
        }
        let expired = answer.exp.is_some_and(|exp| {
            at(exp)
                .and_then(|deadline| deadline.checked_add(self.leeway))
                .is_none_or(|deadline| deadline <= now)
        });
        if expired {
            return refuse(
                "auth.token_expired",
                "the introspection response's `exp` has passed",
            );
        }
        let early = number(answer, "nbf").is_some_and(|nbf| {
            at(nbf)
                .and_then(|start| start.checked_sub(self.leeway))
                .is_none_or(|start| start > now)
        });
        if early {
            return refuse(
                "auth.token_not_yet_valid",
                "the introspection response's `nbf` has not been reached",
            );
        }
        if answer
            .claims
            .get("iss")
            .and_then(Value::as_str)
            .is_some_and(|named| named != issuer)
        {
            return refuse(
                "auth.untrusted_issuer",
                "the introspection response names another issuer",
            );
        }
        if !self.audiences.is_empty() && !audience_matches(answer, &self.audiences) {
            return refuse(
                "auth.audience_mismatch",
                "the introspection response's `aud` names none of the configured audiences",
            );
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------------

impl HookHandler<IdentityHook> for IntrospectionPlugin {
    async fn handle(
        &self,
        payload: &IdentityPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<IdentityPayload> {
        // The factory registers this handler only with an `identity:` block.
        let Some(resolution) = &self.identity else {
            return PluginResult::deny(PluginViolation::new(
                "auth.misconfigured",
                "the plugin declares no `identity:` block",
            ));
        };
        let token = match resolution.location.raw_from_ext(payload.headers(), ext) {
            Ok(token) => token,
            Err(ExtractionError::WrongPrefix) => return declined(payload),
            Err(error) => {
                return PluginResult::deny(extraction_violation(
                    &error,
                    &resolution.location.credential,
                ));
            },
        };
        // A JWT another issuer minted is never sent here. Declining leaves it
        // for the resolver that trusts that issuer.
        let named = issuer_of(&token);
        if named
            .as_deref()
            .is_some_and(|named| named != self.settings.issuer)
        {
            return declined(payload);
        }

        let answer = match self.client.answer(ext, &token).await {
            Ok(answer) => answer,
            Err(error) => {
                tracing::warn!(
                    plugin = %self.config.name,
                    endpoint = %self.client.endpoint(),
                    %error,
                    "introspection could not authenticate the token",
                );
                return PluginResult::deny(PluginViolation::new(
                    codes::INTROSPECTION_UNAVAILABLE,
                    "the issuer's introspection endpoint could not answer",
                ));
            },
        };
        if let Err(violation) = resolution.accept(&answer, &self.settings.issuer, SystemTime::now())
        {
            return PluginResult::deny(*violation);
        }

        let mut updated = payload.clone();
        match &resolution.role {
            TokenRole::User => match resolution.mapper.map_subject(&answer.claims) {
                Some(subject) => updated.subject = Some(subject),
                None => return mapping_failed("subject"),
            },
            TokenRole::Client => match resolution.mapper.map_client(&answer.claims) {
                Some(client) => updated.client = Some(client),
                None => return mapping_failed("client"),
            },
            TokenRole::CallerWorkload => match resolution.mapper.map_workload(&answer.claims) {
                Some(workload) => updated.caller_workload = Some(workload),
                None => return mapping_failed("workload"),
            },
            // `TokenRole` is `#[non_exhaustive]`, and `Resolution::new` refuses
            // a role the map has no section for.
            other => {
                return PluginResult::deny(PluginViolation::new(
                    "auth.misconfigured",
                    format!("role {other:?} is not supported"),
                ));
            },
        }
        let kind = if named.is_some() {
            TokenKind::Jwt
        } else {
            TokenKind::Opaque
        };
        updated.supply_inbound_token(
            resolution.role.clone(),
            RawInboundToken::new(token, resolution.location.credential.clone(), kind)
                .with_issuer(self.settings.issuer.clone()),
        );
        updated.resolved_at = Some(chrono::Utc::now());
        PluginResult::modify_payload(updated)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Parse the `standard` preset.
fn standard_map() -> Result<ClaimMapConfig, String> {
    serde_json::from_str::<Preset>(STANDARD_MAP)
        .map(|preset| preset.claim_map)
        .map_err(|e| format!("the standard claim map does not parse: {e}"))
}

/// Leave the payload as it was and say the credential is not this
/// resolver's, so the next resolver can take it.
fn declined(payload: &IdentityPayload) -> PluginResult<IdentityPayload> {
    let mut updated = payload.clone();
    updated.mark_credential_declined();
    PluginResult::modify_payload(updated)
}

/// The denial for a credential that could not be read, with the codes the
/// other resolvers use.
fn extraction_violation(error: &ExtractionError, at: &Credential) -> PluginViolation {
    match error {
        ExtractionError::Missing => {
            PluginViolation::new("auth.missing_credential", format!("no credential at {at}"))
        },
        ExtractionError::Empty => PluginViolation::new(
            "auth.empty_credential",
            format!("{at} holds an empty credential"),
        ),
        ExtractionError::Ambiguous => PluginViolation::new(
            "auth.ambiguous_credential",
            format!("ambiguous credential at {at}"),
        ),
        _ => PluginViolation::new(
            "auth.malformed_credential",
            format!("malformed credential at {at}"),
        ),
    }
}

/// The denial for a response the map could not project.
fn mapping_failed(slot: &str) -> PluginResult<IdentityPayload> {
    PluginResult::deny(PluginViolation::new(
        "auth.mapping_failed",
        format!(
            "the record map produced no {slot} from the introspection response. Raise the log \
             level to debug to see which fields and which paths were tried"
        ),
    ))
}

/// A response field that holds a number.
fn number(answer: &Answer, name: &str) -> Option<f64> {
    answer.claims.get(name).and_then(Value::as_f64)
}

/// `secs` after the Unix epoch, when that is a time.
fn at(secs: f64) -> Option<SystemTime> {
    Duration::try_from_secs_f64(secs)
        .ok()
        .and_then(|since| UNIX_EPOCH.checked_add(since))
}

/// Whether the response's `aud`, a string or an array of them, names one of
/// `audiences`.
fn audience_matches(answer: &Answer, audiences: &[String]) -> bool {
    let named = |aud: &str| audiences.iter().any(|wanted| wanted == aud);
    match answer.claims.get("aud") {
        Some(Value::String(aud)) => named(aud),
        Some(Value::Array(auds)) => auds.iter().filter_map(Value::as_str).any(named),
        _ => false,
    }
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

    use praxis_policy_core::http_testing::FakeTransport;
    use praxis_policy_core::identity::{HOOK_IDENTITY_RESOLVE, TokenSource};
    use praxis_policy_core::revocation::{
        CheckPoint, HOOK_REVOCATION_CHECK, IdentitySlot, RevocationCheck, RevocationHook,
    };
    use serde_json::json;

    use super::*;
    use crate::plugins::oauth_introspection::test_support::{ISSUER, ext, jwt, plugin_for};

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    const OPAQUE: &str = "opaque-8xLq";

    /// A resolver for [`ISSUER`] with `identity` as its `identity:` block and
    /// `extra` laid over the rest of the config.
    fn resolver(identity: serde_json::Value, extra: serde_json::Value) -> IntrospectionPlugin {
        let mut overrides = extra;
        overrides["identity"] = identity;
        plugin_for(&[HOOK_IDENTITY_RESOLVE], overrides)
    }

    /// A request carrying `authorization`, or no credential when `None`.
    fn presenting(authorization: Option<&str>) -> IdentityPayload {
        let headers = authorization
            .map(|value| HashMap::from([("authorization".to_owned(), value.to_owned())]))
            .unwrap_or_default();
        IdentityPayload::new("", TokenSource::Bearer).with_headers(headers)
    }

    /// A transport answering every introspection with `body`.
    fn answering(body: &serde_json::Value) -> Arc<FakeTransport> {
        Arc::new(FakeTransport::new().json("/introspect", 200, &body.to_string()))
    }

    async fn resolve(
        plugin: &IntrospectionPlugin,
        payload: &IdentityPayload,
        transport: &Arc<FakeTransport>,
    ) -> PluginResult<IdentityPayload> {
        let mut ctx = PluginContext::default();
        HookHandler::<IdentityHook>::handle(plugin, payload, &ext(transport, &[]), &mut ctx).await
    }

    fn resolved(result: &PluginResult<IdentityPayload>) -> &IdentityPayload {
        assert!(result.violation.is_none(), "{:?}", result.violation);
        result
            .modified_payload
            .as_ref()
            .expect("an allow carries the identity")
    }

    fn denied(result: &PluginResult<IdentityPayload>) -> &str {
        result.violation.as_ref().expect("a deny").code.as_str()
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // -------------------------------------------------------------------------
    // Resolution
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn an_active_opaque_token_becomes_the_subject() {
        let transport = answering(&json!({
            "active": true, "sub": "alice", "scope": "read write", "iss": ISSUER,
        }));
        let plugin = resolver(json!({}), json!({}));

        let result = resolve(
            &plugin,
            &presenting(Some(&format!("Bearer {OPAQUE}"))),
            &transport,
        )
        .await;

        let identity = resolved(&result);
        let subject = identity.subject.as_ref().expect("a subject");
        assert_eq!(subject.id.as_deref(), Some("alice"), "sub");
        assert!(subject.permissions.contains("read"), "scope, split");
        let token = identity
            .raw_credentials
            .as_ref()
            .and_then(|raw| raw.inbound_tokens.get(&TokenRole::User))
            .expect("the token is kept for later plugins");
        assert_eq!(token.token.as_str(), OPAQUE, "without the scheme");
        assert!(matches!(token.kind, TokenKind::Opaque), "opaque");
        assert_eq!(token.issuer.as_deref(), Some(ISSUER), "the issuer recorded");
    }

    #[tokio::test]
    async fn the_client_role_fills_the_client_slot() {
        let transport = answering(&json!({ "active": true, "client_id": "agent-7" }));
        let plugin = resolver(json!({ "role": "client" }), json!({}));

        let result = resolve(
            &plugin,
            &presenting(Some(&format!("Bearer {OPAQUE}"))),
            &transport,
        )
        .await;

        let identity = resolved(&result);
        assert_eq!(
            identity.client.as_ref().map(|c| c.client_id.as_str()),
            Some("agent-7"),
            "client_id"
        );
        assert!(identity.subject.is_none(), "only the configured slot");
    }

    #[tokio::test]
    async fn a_jwt_naming_this_issuer_is_introspected_and_kept_as_a_jwt() {
        let transport = answering(&json!({ "active": true, "sub": "alice" }));
        let plugin = resolver(json!({}), json!({}));

        let result = resolve(
            &plugin,
            &presenting(Some(&format!("Bearer {}", jwt(ISSUER)))),
            &transport,
        )
        .await;

        let token = resolved(&result)
            .raw_credentials
            .as_ref()
            .and_then(|raw| raw.inbound_tokens.get(&TokenRole::User))
            .expect("kept");
        assert!(matches!(token.kind, TokenKind::Jwt), "a JWT");
        assert_eq!(transport.call_count(), 1, "introspected");
    }

    // -------------------------------------------------------------------------
    // Refusals
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn each_unacceptable_response_denies_with_its_code() {
        let now = now_secs();
        for (identity, body, code) in [
            (json!({}), json!({ "active": false }), codes::TOKEN_INACTIVE),
            (
                json!({}),
                json!({ "active": true, "sub": "a", "exp": now - 5 }),
                "auth.token_expired",
            ),
            (
                json!({}),
                json!({ "active": true, "sub": "a", "nbf": now + 60 }),
                "auth.token_not_yet_valid",
            ),
            (
                json!({}),
                json!({ "active": true, "sub": "a", "iss": "https://other.example" }),
                "auth.untrusted_issuer",
            ),
            (
                json!({ "audiences": ["mcp-gateway"] }),
                json!({ "active": true, "sub": "a", "aud": ["billing"] }),
                "auth.audience_mismatch",
            ),
            (json!({}), json!({ "active": true }), "auth.mapping_failed"),
        ] {
            let transport = answering(&body);
            let plugin = resolver(identity, json!({}));

            let result = resolve(
                &plugin,
                &presenting(Some(&format!("Bearer {OPAQUE}"))),
                &transport,
            )
            .await;

            assert_eq!(denied(&result), code, "{body}");
        }
    }

    #[tokio::test]
    async fn leeway_and_a_matching_audience_are_accepted() {
        let transport = answering(&json!({
            "active": true, "sub": "a", "exp": now_secs() - 5, "aud": ["billing", "mcp-gateway"],
        }));
        let plugin = resolver(
            json!({ "leeway_seconds": 30, "audiences": ["mcp-gateway"] }),
            json!({}),
        );

        let result = resolve(
            &plugin,
            &presenting(Some(&format!("Bearer {OPAQUE}"))),
            &transport,
        )
        .await;

        assert!(result.violation.is_none(), "{:?}", result.violation);
    }

    #[tokio::test]
    async fn a_failed_lookup_denies_as_unavailable() {
        let transport = Arc::new(FakeTransport::new().json("/introspect", 500, "down"));
        let plugin = resolver(json!({}), json!({}));

        let result = resolve(
            &plugin,
            &presenting(Some(&format!("Bearer {OPAQUE}"))),
            &transport,
        )
        .await;

        assert_eq!(denied(&result), codes::INTROSPECTION_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_missing_credential_denies() {
        let transport = answering(&json!({ "active": true, "sub": "a" }));
        let plugin = resolver(json!({}), json!({}));

        let result = resolve(&plugin, &presenting(None), &transport).await;

        assert_eq!(denied(&result), "auth.missing_credential");
        assert_eq!(transport.call_count(), 0, "nothing sent");
    }

    // -------------------------------------------------------------------------
    // Declines
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn a_token_that_is_not_this_resolvers_is_declined_and_never_sent() {
        for authorization in [
            format!("Bearer {}", jwt("https://other.example/realms/x")),
            "Basic dXNlcjpwYXNz".to_owned(),
        ] {
            let transport = answering(&json!({ "active": true, "sub": "a" }));
            let plugin = resolver(json!({}), json!({}));

            let result = resolve(&plugin, &presenting(Some(&authorization)), &transport).await;

            let left = resolved(&result);
            assert!(left.subject.is_none(), "{authorization}: no identity");
            assert_eq!(transport.call_count(), 0, "{authorization}: never sent");
        }
    }

    // -------------------------------------------------------------------------
    // With the revocation hook
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn the_revocation_check_covers_the_token_it_authenticated_from_one_answer() {
        let transport = answering(&json!({ "active": true, "sub": "alice" }));
        let plugin = plugin_for(
            &[HOOK_IDENTITY_RESOLVE, HOOK_REVOCATION_CHECK],
            json!({ "identity": {}, "cache_ttl_seconds": 60 }),
        );

        let result = resolve(
            &plugin,
            &presenting(Some(&format!("Bearer {OPAQUE}"))),
            &transport,
        )
        .await;
        let after_auth = resolved(&result).apply_to_extensions(ext(&transport, &[]));
        let mut ctx = PluginContext::default();
        let check = HookHandler::<RevocationHook>::handle(
            &plugin,
            &RevocationCheck::new(CheckPoint::AfterAuthentication, [IdentitySlot::Subject]),
            &after_auth,
            &mut ctx,
        )
        .await;

        assert!(check.violation.is_none(), "{:?}", check.violation);
        assert!(
            check
                .modified_payload
                .as_ref()
                .is_some_and(|answer| answer.vouched().contains(&IdentitySlot::Subject)),
            "the opaque token is covered through its recorded issuer"
        );
        assert_eq!(transport.call_count(), 1, "one answer served both hooks");
    }
}
