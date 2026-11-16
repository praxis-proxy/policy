// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The engine's revocation check: run the route's checkers through the
// ordinary hook pipeline and turn their answer into pass or deny.
//
// The pipeline is sequential and chained, so the first checker to deny, in
// list order, stops it, and on allow the final payload's `vouched` holds every
// checker's vouches. A checker can only add to that set through
// `RevocationCheck::vouch`; one that discards the payload can only remove
// vouches, which denies, so no checker can make another's slot pass.

use tracing::warn;

use super::hook::{HOOK_REVOCATION_CHECK, RevocationHook};
use super::payload::{CheckPoint, IdentitySlot, RevocationCheck};
use super::{REVOCATION_UNAVAILABLE_CODE, REVOCATION_UNAVAILABLE_REASON, REVOKED_CODE};
use crate::engine::PolicyEngine;
use crate::error::PluginViolation;
use crate::extensions::Extensions;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The codes the executor gives a checker that failed rather than answered:
/// an error, a timeout, a panic. Their reasons name the plugin and the
/// underlying failure, so they are replaced before reaching the caller.
const EXECUTION_FAILURE_CODES: [&str; 3] = ["plugin_error", "plugin_timeout", "plugin_panic"];

impl PolicyEngine {
    /// Check whether the identities `extensions` carries still hold authority
    /// on this route, at `check_point`.
    ///
    /// Returns `None` to pass and the violation to deny with otherwise. Passes
    /// without dispatching when the request resolved no identity or the route
    /// runs no checker. Denies when a checker denies, when a checker fails
    /// ([`REVOCATION_UNAVAILABLE_CODE`], with a fixed reason), and when a
    /// populated identity slot was vouched for by no checker.
    ///
    /// [`REVOCATION_UNAVAILABLE_CODE`]: super::REVOCATION_UNAVAILABLE_CODE
    pub async fn check_revocation(
        &self,
        extensions: &Extensions,
        check_point: CheckPoint,
        route_key: &str,
    ) -> Option<PluginViolation> {
        let slots = IdentitySlot::populated(extensions.security.as_deref());
        if slots.is_empty() {
            return None;
        }

        let check = RevocationCheck::new(check_point, route_key, slots.iter().copied());
        let (result, _background) = self
            .invoke_named::<RevocationHook>(HOOK_REVOCATION_CHECK, check, extensions.clone(), None)
            .await;

        if let Some(violation) = result.violation {
            return Some(caller_facing(violation, check_point, route_key));
        }
        if result.decision_log.steps().is_empty() {
            return None;
        }

        let vouched = RevocationCheck::from_pipeline_result(&result)
            .map(RevocationCheck::vouched)
            .cloned()
            .unwrap_or_default();
        let unclaimed: Vec<IdentitySlot> = slots.difference(&vouched).copied().collect();
        if unclaimed.is_empty() {
            return None;
        }
        warn!(
            route = route_key,
            check_point = ?check_point,
            slots = ?unclaimed,
            "no revocation checker vouched for these identities, so the request is denied; \
             the route needs a checker that covers how they authenticate, or an exclusion",
        );
        Some(unavailable())
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// The violation a checker's deny becomes for the caller.
///
/// A checker that failed instead of answering becomes
/// [`REVOCATION_UNAVAILABLE_CODE`] with the fixed reason, logged with what the
/// executor reported. A deny under any code but the two revocation codes still
/// denies, with a warning.
fn caller_facing(
    violation: PluginViolation,
    check_point: CheckPoint,
    route_key: &str,
) -> PluginViolation {
    if EXECUTION_FAILURE_CODES.contains(&violation.code.as_str()) {
        warn!(
            route = route_key,
            check_point = ?check_point,
            plugin = violation.plugin_name.as_deref().unwrap_or_default(),
            code = %violation.code,
            reason = %violation.reason,
            "a revocation checker failed, so the request is denied as unavailable",
        );
        let mut replaced = unavailable();
        replaced.plugin_name = violation.plugin_name;
        return replaced;
    }
    if violation.code != REVOKED_CODE && violation.code != REVOCATION_UNAVAILABLE_CODE {
        warn!(
            route = route_key,
            plugin = violation.plugin_name.as_deref().unwrap_or_default(),
            code = %violation.code,
            "a revocation checker denied with a code other than auth.revoked or \
             auth.revocation_unavailable; the request is denied, but callers and audit expect \
             one of those two",
        );
    }
    violation
}

/// The violation for a revocation status that could not be established.
fn unavailable() -> PluginViolation {
    PluginViolation::new(REVOCATION_UNAVAILABLE_CODE, REVOCATION_UNAVAILABLE_REASON)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn a_failed_checker_is_reported_as_unavailable_without_its_reason() {
        for code in EXECUTION_FAILURE_CODES {
            let mut failed = PluginViolation::new(code, "Plugin 'kc' failed: https://kc.internal");
            failed.plugin_name = Some("kc".to_owned());

            let shown = caller_facing(failed, CheckPoint::AfterAuthentication, "tool:t");

            assert_eq!(shown.code, REVOCATION_UNAVAILABLE_CODE, "{code}");
            assert_eq!(shown.reason, REVOCATION_UNAVAILABLE_REASON, "{code}");
            assert_eq!(shown.plugin_name.as_deref(), Some("kc"), "{code}");
        }
    }

    #[test]
    fn a_checker_deny_passes_through_unchanged() {
        for code in [REVOKED_CODE, REVOCATION_UNAVAILABLE_CODE, "custom.blocked"] {
            let denied = PluginViolation::new(code, "reason");

            let shown = caller_facing(denied.clone(), CheckPoint::BeforeDispatch, "tool:t");

            assert_eq!(shown, denied, "{code} denies as the checker wrote it");
        }
    }

    #[tokio::test]
    async fn a_config_without_revocation_never_dispatches_the_hook() {
        let (engine, calls) = engine("routes:\n  - tool: t\n").await;

        let outcome = check(&engine, both_slots()).await;

        assert_eq!(outcome, None, "no checker configured, nothing to deny");
        assert_eq!(calls.load(Ordering::Acquire), 0, "the hook is never called");
    }

    #[tokio::test]
    async fn a_request_with_no_identity_is_not_checked() {
        let (engine, calls) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject] }")
        ))
        .await;

        let outcome = check(&engine, Extensions::default().with_meta()).await;

        assert_eq!(outcome, None, "an anonymous request has no slot to check");
        assert_eq!(calls.load(Ordering::Acquire), 0, "the hook is never called");
    }

    #[tokio::test]
    async fn every_slot_vouched_for_passes() {
        let (engine, _) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client] }")
        ))
        .await;

        assert_eq!(
            check(&engine, both_slots()).await,
            None,
            "both slots vouched"
        );
    }

    #[tokio::test]
    async fn a_slot_no_checker_vouched_for_denies_as_unavailable() {
        let (engine, _) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [client] }")
        ))
        .await;

        let denied = check(&engine, both_slots())
            .await
            .expect("the subject was vouched for by no checker");

        assert_eq!(
            denied.code, REVOCATION_UNAVAILABLE_CODE,
            "unclaimed is unavailable"
        );
        assert_eq!(
            denied.reason, REVOCATION_UNAVAILABLE_REASON,
            "the fixed reason"
        );
    }

    #[tokio::test]
    async fn two_checkers_together_cover_both_slots() {
        let (engine, _) = engine(&format!(
            "{}{}global:\n  revocation: [users, agents]\nroutes:\n  - tool: t\n",
            checker("users", "{ vouch: [subject] }"),
            checker("agents", "{ vouch: [client] }")
        ))
        .await;

        assert_eq!(
            check(&engine, both_slots()).await,
            None,
            "each checker's vouch survives the next checker"
        );
    }

    #[tokio::test]
    async fn a_deny_wins_over_another_checkers_vouch() {
        let (engine, _) = engine(&format!(
            "{}{}global:\n  revocation: [kc, kill-list]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client] }"),
            checker("kill-list", "{ deny: auth.revoked }")
        ))
        .await;

        let denied = check(&engine, both_slots())
            .await
            .expect("the kill list denies");

        assert_eq!(
            denied.code, REVOKED_CODE,
            "the checker's own code reaches the caller"
        );
    }

    #[tokio::test]
    async fn a_failing_checker_denies_as_unavailable_without_its_detail() {
        let (engine, _) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ fail: true }")
        ))
        .await;

        let denied = check(&engine, both_slots())
            .await
            .expect("a failed check denies");

        assert_eq!(
            denied.code, REVOCATION_UNAVAILABLE_CODE,
            "a failure is unavailable"
        );
        assert_eq!(
            denied.reason, REVOCATION_UNAVAILABLE_REASON,
            "the executor's reason, which names the plugin and its error, is replaced"
        );
    }

    #[tokio::test]
    async fn a_step_config_runs_its_own_instance() {
        let (engine, _) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n    revocation:\n      \
             replace_inherited: true\n      steps:\n        - name: kc\n          config: {{ \
             vouch: [subject, client] }}\n",
            checker("kc", "{ vouch: [] }")
        ))
        .await;

        assert_eq!(
            check(&engine, both_slots()).await,
            None,
            "the route's step vouches through its own config, not the base instance's"
        );
    }

    #[tokio::test]
    async fn an_unregistered_checker_denies_as_unavailable() {
        let (engine, _) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client] }")
        ))
        .await;
        engine.unregister("kc");

        let denied = check(&engine, both_slots())
            .await
            .expect("a configured checker that is gone must not let requests through");

        assert_eq!(denied.code, REVOCATION_UNAVAILABLE_CODE, "missing checker");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use crate::context::PluginContext;
    use crate::error::PluginError;
    use crate::extensions::MetaExtension;
    use crate::extensions::security::{ClientExtension, SecurityExtension, SubjectExtension};
    use crate::factory::{PluginFactory, PluginInstance};
    use crate::hooks::payload::PluginPayload;
    use crate::hooks::trait_def::{HookTypeDef as _, PluginResult};
    use crate::plugin::{Plugin, PluginConfig};
    use crate::registry::AnyHookHandler;

    const KIND: &str = "test/checker";

    /// A checker plugin declaration with the behavior `config` describes.
    fn checker(name: &str, config: &str) -> String {
        format!(
            "plugins:\n  - name: {name}\n    kind: {KIND}\n    hooks: [revocation.check]\n    \
             config: {config}\n"
        )
    }

    /// An initialized engine for `yaml`, and a count of checker invocations.
    async fn engine(yaml: &str) -> (PolicyEngine, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let engine = PolicyEngine::default();
        engine.register_factory(KIND, Box::new(CheckerFactory(Arc::clone(&calls))));
        let document = merge_plugin_lists(yaml);
        engine
            .load_config(crate::config::parse_config(&document).expect("the fixture parses"))
            .expect("the fixture loads");
        engine.initialize().await.expect("initialize");
        (engine, calls)
    }

    /// Fold repeated `plugins:` headers from concatenated [`checker`] fixtures
    /// into one list.
    fn merge_plugin_lists(yaml: &str) -> String {
        let mut seen = false;
        yaml.split_inclusive('\n')
            .filter(|line| {
                if *line == "plugins:\n" {
                    let first = !seen;
                    seen = true;
                    first
                } else {
                    true
                }
            })
            .collect()
    }

    async fn check(engine: &PolicyEngine, extensions: Extensions) -> Option<PluginViolation> {
        engine
            .check_revocation(&extensions, CheckPoint::AfterAuthentication, "tool:t")
            .await
    }

    /// A request on `tool:t` carrying a subject and a client.
    fn both_slots() -> Extensions {
        Extensions {
            security: Some(Arc::new(SecurityExtension {
                client: Some(ClientExtension::default()),
                subject: Some(SubjectExtension::default()),
                ..SecurityExtension::default()
            })),
            ..Extensions::default().with_meta()
        }
    }

    trait WithMeta {
        fn with_meta(self) -> Self;
    }

    impl WithMeta for Extensions {
        fn with_meta(self) -> Self {
            Self {
                meta: Some(Arc::new(MetaExtension {
                    entity_type: Some("tool".to_owned()),
                    entity_name: Some("t".to_owned()),
                    ..Default::default()
                })),
                ..self
            }
        }
    }

    struct Checker {
        calls: Arc<AtomicUsize>,
        cfg: PluginConfig,
    }

    impl Checker {
        fn setting(&self, key: &str) -> Option<&serde_json::Value> {
            self.cfg.config.as_ref().and_then(|config| config.get(key))
        }
    }

    #[async_trait]
    impl Plugin for Checker {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    struct CheckerHandler(Arc<Checker>);

    #[async_trait]
    impl AnyHookHandler for CheckerHandler {
        async fn invoke(
            &self,
            payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            let checker = &self.0;
            checker.calls.fetch_add(1, Ordering::AcqRel);
            if checker.setting("fail") == Some(&serde_json::Value::Bool(true)) {
                return Err(Box::new(PluginError::Config {
                    message: "introspection endpoint https://kc.internal unreachable".to_owned(),
                }));
            }
            if let Some(code) = checker.setting("deny").and_then(serde_json::Value::as_str) {
                return Ok(crate::executor::erase_result(
                    PluginResult::<RevocationCheck>::deny(PluginViolation::new(code, "revoked")),
                ));
            }
            let mut answer = payload
                .as_any()
                .downcast_ref::<RevocationCheck>()
                .expect("the revocation hook carries a RevocationCheck")
                .clone();
            for slot in checker
                .setting("vouch")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
            {
                answer = answer.vouch(match slot {
                    "subject" => IdentitySlot::Subject,
                    "client" => IdentitySlot::Client,
                    _ => IdentitySlot::CallerWorkload,
                });
            }
            Ok(crate::executor::erase_result(PluginResult::modify_payload(
                answer,
            )))
        }

        fn hook_type_name(&self) -> &'static str {
            RevocationHook::NAME
        }
    }

    struct CheckerFactory(Arc<AtomicUsize>);

    impl PluginFactory for CheckerFactory {
        fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
            let checker = Arc::new(Checker {
                calls: Arc::clone(&self.0),
                cfg: config.clone(),
            });
            let plugin: Arc<dyn Plugin> = checker.clone();
            Ok(PluginInstance {
                plugin,
                handlers: vec![(HOOK_REVOCATION_CHECK, Arc::new(CheckerHandler(checker)))],
            })
        }
    }
}
