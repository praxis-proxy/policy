// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `revocation.check` handler. For each slot the engine asks about, it
// takes the slot's raw inbound token, confirms the token names the configured
// issuer, and asks that issuer whether the token is still active. Slots are
// introspected concurrently, so the check costs one round trip, not three.

use futures::future::join_all;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::extensions::raw_credentials::TokenKind;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::revocation::{
    IdentitySlot, REVOCATION_UNAVAILABLE_CODE, REVOCATION_UNAVAILABLE_REASON, REVOKED_CODE,
    REVOKED_REASON, RevocationCheck, RevocationHook,
};

use crate::plugins::oauth_introspection::IntrospectionPlugin;
use crate::plugins::oauth_introspection::client::issuer_of;

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

impl IntrospectionPlugin {
    /// The slot's raw inbound token, when it belongs to this plugin's issuer.
    ///
    /// The issuer the authenticating resolver recorded decides, so an opaque
    /// token it vouched for is covered, and a JWT it recorded for another
    /// issuer is not sent here whatever its `iss` says. With nothing
    /// recorded, a token stored as a JWT is ours when its `iss` matches, and
    /// any other kind is left alone without being parsed.
    fn token_for<'ext>(&self, ext: &'ext Extensions, slot: IdentitySlot) -> Option<&'ext str> {
        let token = ext
            .raw_credentials
            .as_ref()?
            .inbound_tokens
            .get(&slot.token_role())?;
        let ours = match token.issuer.as_deref() {
            Some(recorded) => recorded == self.settings.issuer,
            None => {
                matches!(token.kind, TokenKind::Jwt | TokenKind::SpiffeJwt)
                    && issuer_of(&token.token).as_deref() == Some(self.settings.issuer.as_str())
            },
        };
        ours.then_some(token.token.as_str())
    }

    /// Ask the issuer about one slot's token, logging what the caller is
    /// not told.
    async fn status(&self, ext: &Extensions, slot: IdentitySlot, token: &str) -> Status {
        match self.client.answer(ext, token).await.map(|a| a.active) {
            Ok(true) => Status::Active,
            Ok(false) => {
                tracing::info!(plugin = %self.config.name, ?slot, "credential revoked");
                Status::Inactive
            },
            Err(error) => {
                tracing::warn!(
                    plugin = %self.config.name,
                    ?slot,
                    endpoint = %self.client.endpoint(),
                    %error,
                    "revocation status unavailable"
                );
                Status::Unavailable
            },
        }
    }
}

impl HookHandler<RevocationHook> for IntrospectionPlugin {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use praxis_policy_core::http::HttpTransportError;
    use praxis_policy_core::http_testing::FakeTransport;
    use praxis_policy_core::revocation::CheckPoint;
    use serde_json::json;

    use super::*;
    use crate::plugins::oauth_introspection::test_support::{
        ISSUER, ext, ext_with, inbound, jwt, plugin as checker,
    };

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    fn asked(slots: &[IdentitySlot]) -> RevocationCheck {
        RevocationCheck::new(CheckPoint::AfterAuthentication, slots.iter().copied())
    }

    async fn run(
        checker: &IntrospectionPlugin,
        check: &RevocationCheck,
        ext: &Extensions,
    ) -> PluginResult<RevocationCheck> {
        let mut ctx = PluginContext::default();
        HookHandler::<RevocationHook>::handle(checker, check, ext, &mut ctx).await
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

    #[tokio::test]
    async fn an_opaque_token_recorded_for_this_issuer_is_checked() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let token = inbound("opaque-8xLq", TokenKind::Opaque).with_issuer(ISSUER);
        let ext = ext_with(&transport, &[(IdentitySlot::Subject, token)]);

        let result = run(&checker(json!({})), &asked(&[IdentitySlot::Subject]), &ext).await;

        assert_eq!(vouched(&result), vec![IdentitySlot::Subject], "vouched");
        assert_eq!(transport.call_count(), 1, "sent to the issuer that vouched");
    }

    #[tokio::test]
    async fn a_recorded_issuer_outranks_the_one_a_jwt_names() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let token = inbound(&jwt(ISSUER), TokenKind::Jwt).with_issuer("https://other.example");
        let ext = ext_with(&transport, &[(IdentitySlot::Subject, token)]);

        let result = run(&checker(json!({})), &asked(&[IdentitySlot::Subject]), &ext).await;

        assert!(vouched(&result).is_empty(), "recorded for another issuer");
        assert_eq!(transport.call_count(), 0, "the token never left");
    }

    #[tokio::test]
    async fn an_opaque_token_with_no_recorded_issuer_is_never_parsed_or_sent() {
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        // Opaque by kind, although its bytes would decode to this issuer.
        let token = inbound(&jwt(ISSUER), TokenKind::Opaque);
        let ext = ext_with(&transport, &[(IdentitySlot::Subject, token)]);

        let result = run(&checker(json!({})), &asked(&[IdentitySlot::Subject]), &ext).await;

        assert!(vouched(&result).is_empty(), "not ours to check");
        assert_eq!(transport.call_count(), 0, "the token never left");
    }

    // -------------------------------------------------------------------------
    // Cache
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn with_no_cache_window_every_check_asks_the_issuer() {
        let transport = Arc::new(
            FakeTransport::new()
                .json("/introspect", 200, r#"{"active":true}"#)
                .json("/introspect", 200, r#"{"active":false}"#),
        );
        let ext = ext(&transport, &[(IdentitySlot::Client, jwt(ISSUER))]);
        let checker = checker(json!({}));

        let first = run(&checker, &asked(&[IdentitySlot::Client]), &ext).await;
        let second = run(&checker, &asked(&[IdentitySlot::Client]), &ext).await;

        assert_eq!(vouched(&first), vec![IdentitySlot::Client], "first");
        assert_eq!(denied_with(&second).0, REVOKED_CODE, "the revocation lands");
        assert_eq!(transport.call_count(), 2, "both checks were live");
    }

    #[tokio::test]
    async fn an_answer_is_reused_within_the_window() {
        for (body, expect_vouched) in [(r#"{"active":true}"#, true), (r#"{"active":false}"#, false)]
        {
            let transport = Arc::new(FakeTransport::new().json("/introspect", 200, body));
            let ext = ext(&transport, &[(IdentitySlot::Client, jwt(ISSUER))]);
            let checker = checker(json!({ "cache_ttl_seconds": 60 }));

            for _ in 0..3 {
                let result = run(&checker, &asked(&[IdentitySlot::Client]), &ext).await;
                assert_eq!(result.violation.is_none(), expect_vouched, "{body}");
            }

            assert_eq!(transport.call_count(), 1, "{body}: one call, then cached");
        }
    }

    #[tokio::test]
    async fn an_answer_is_not_reused_past_its_exp() {
        let passed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1;
        let transport = Arc::new(
            FakeTransport::new()
                .json(
                    "/introspect",
                    200,
                    &format!(r#"{{"active":true,"exp":{passed}}}"#),
                )
                .json("/introspect", 200, r#"{"active":false}"#),
        );
        let ext = ext(&transport, &[(IdentitySlot::Client, jwt(ISSUER))]);
        let checker = checker(json!({ "cache_ttl_seconds": 60 }));

        let first = run(&checker, &asked(&[IdentitySlot::Client]), &ext).await;
        let second = run(&checker, &asked(&[IdentitySlot::Client]), &ext).await;

        assert_eq!(vouched(&first), vec![IdentitySlot::Client], "first");
        assert_eq!(
            denied_with(&second).0,
            REVOKED_CODE,
            "RFC 7662 section 4: not cached past exp"
        );
        assert_eq!(transport.call_count(), 2, "asked again");
    }

    #[tokio::test]
    async fn a_failed_lookup_is_asked_again() {
        let transport = Arc::new(FakeTransport::new().json("/introspect", 500, "").json(
            "/introspect",
            200,
            r#"{"active":true}"#,
        ));
        let ext = ext(&transport, &[(IdentitySlot::Client, jwt(ISSUER))]);
        let checker = checker(json!({ "cache_ttl_seconds": 60 }));

        let failed = run(&checker, &asked(&[IdentitySlot::Client]), &ext).await;
        let retried = run(&checker, &asked(&[IdentitySlot::Client]), &ext).await;

        assert_eq!(denied_with(&failed).0, REVOCATION_UNAVAILABLE_CODE, "first");
        assert_eq!(vouched(&retried), vec![IdentitySlot::Client], "retried");
        assert_eq!(transport.call_count(), 2, "the failure was not stored");
    }

    #[tokio::test]
    async fn concurrent_checks_of_one_token_share_one_call() {
        let transport = Arc::new(
            FakeTransport::new()
                .json("/introspect", 200, r#"{"active":true}"#)
                .with_latency(Duration::from_millis(50)),
        );
        let ext = ext(&transport, &[(IdentitySlot::Client, jwt(ISSUER))]);
        let checker = checker(json!({ "cache_ttl_seconds": 60 }));
        let check = asked(&[IdentitySlot::Client]);

        let results =
            join_all(std::iter::repeat_with(|| run(&checker, &check, &ext)).take(4)).await;

        assert!(
            results.iter().all(|result| result.violation.is_none()),
            "all pass"
        );
        assert_eq!(transport.call_count(), 1, "coalesced");
    }
}
