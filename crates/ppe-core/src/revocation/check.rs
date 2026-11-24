// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The engine's revocation check: where it runs, what it asks a route's
// checkers, and how their answer becomes pass or deny. The engine dispatches
// the question itself, on the snapshot of the dispatch being checked.
//
// The pipeline is sequential and chained, so the first checker to deny, in
// list order, stops it, and on allow the final payload's `vouched` holds every
// checker's vouches. A checker can only add to that set through
// `RevocationCheck::vouch`; one that discards the payload can only remove
// vouches, which denies, so no checker can make another's slot pass.

use tracing::warn;

use super::payload::{CheckPoint, IdentitySlot, RevocationCheck};
use super::{REVOCATION_UNAVAILABLE_CODE, REVOCATION_UNAVAILABLE_REASON, REVOKED_CODE};
use crate::error::PluginViolation;
use crate::executor::PipelineResult;
use crate::extensions::Extensions;
use crate::hooks::HookPhase;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The codes the executor gives a checker that failed rather than answered:
/// an error, a timeout, a panic. Their reasons name the plugin and the
/// underlying failure, so they are replaced before reaching the caller.
const EXECUTION_FAILURE_CODES: [&str; 3] = ["plugin_error", "plugin_timeout", "plugin_panic"];

// -----------------------------------------------------------------------------
// Check Points
// -----------------------------------------------------------------------------

/// Where the engine checks revocation around one dispatch of `hook_name`:
/// before its pipeline runs, and after the pipeline allowed.
///
/// Keyed on the hook's registered phase, so no hook is named here. A `Pre`
/// hook is the request on its way to the upstream and is checked on both
/// sides of its pipeline. A `Post` hook is the response on its way back and
/// is checked once it allowed. Any other hook (identity resolution, rate
/// limits, delegation, the revocation hook itself) is not a wire boundary and
/// is not checked.
pub(crate) fn check_points(hook_name: &str) -> (Option<CheckPoint>, Option<CheckPoint>) {
    match crate::hooks::lookup_hook_metadata(hook_name).map(|meta| meta.phase) {
        Some(HookPhase::Pre) => (
            Some(CheckPoint::AfterAuthentication),
            Some(CheckPoint::BeforeDispatch),
        ),
        Some(HookPhase::Post) => (None, Some(CheckPoint::BeforeRelease)),
        Some(HookPhase::Unphased) | None => (None, None),
    }
}

// -----------------------------------------------------------------------------
// Question and Verdict
// -----------------------------------------------------------------------------

/// The question to put to a route's checkers at `check_point`: every identity
/// slot `extensions` has populated. `None` when the request resolved no
/// identity, which passes without asking.
pub(crate) fn question(
    extensions: &Extensions,
    check_point: CheckPoint,
) -> Option<RevocationCheck> {
    let slots = IdentitySlot::populated(extensions.security.as_deref());
    if slots.is_empty() {
        return None;
    }
    Some(RevocationCheck::new(check_point, slots))
}

/// Turn the checkers' answer to `asked` into pass (`None`) or the violation to
/// deny with.
///
/// Passes when no checker ran, because the route runs none: the engine refuses
/// a route whose checker is missing or disabled before any runs. Denies when a
/// checker denies, when a checker fails ([`REVOCATION_UNAVAILABLE_CODE`], with
/// a fixed reason), and when a slot `asked` names was vouched for by no
/// checker.
pub(crate) fn verdict(asked: &RevocationCheck, result: PipelineResult) -> Option<PluginViolation> {
    let check_point = asked.check_point();
    let no_checker_ran = result.decision_log.steps().is_empty();
    if let Some(violation) = result.violation {
        // No checker ran, so the engine refused the dispatch itself, for a
        // route it could not resolve or a checker missing from the snapshot.
        // That violation is already the caller's.
        if no_checker_ran {
            return Some(violation);
        }
        return Some(caller_facing(violation, check_point));
    }
    if no_checker_ran {
        return None;
    }

    let vouched = RevocationCheck::from_pipeline_result(&result)
        .map(RevocationCheck::vouched)
        .cloned()
        .unwrap_or_default();
    let unclaimed: Vec<IdentitySlot> = asked.slots().difference(&vouched).copied().collect();
    if unclaimed.is_empty() {
        return None;
    }
    warn!(
        check_point = ?check_point,
        slots = ?unclaimed,
        "no revocation checker vouched for these identities, so the request is denied; the \
         route needs a checker that covers how they authenticate, or an exclusion",
    );
    Some(unavailable())
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
fn caller_facing(violation: PluginViolation, check_point: CheckPoint) -> PluginViolation {
    if EXECUTION_FAILURE_CODES.contains(&violation.code.as_str()) {
        warn!(
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
            check_point = ?check_point,
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

            let shown = caller_facing(failed, CheckPoint::AfterAuthentication);

            assert_eq!(shown.code, REVOCATION_UNAVAILABLE_CODE, "{code}");
            assert_eq!(shown.reason, REVOCATION_UNAVAILABLE_REASON, "{code}");
            assert_eq!(shown.plugin_name.as_deref(), Some("kc"), "{code}");
        }
    }

    #[test]
    fn a_checker_deny_passes_through_unchanged() {
        for code in [REVOKED_CODE, REVOCATION_UNAVAILABLE_CODE, "custom.blocked"] {
            let denied = PluginViolation::new(code, "reason");

            let shown = caller_facing(denied.clone(), CheckPoint::BeforeDispatch);

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

    #[tokio::test]
    async fn a_disabled_checker_denies_as_unavailable() {
        let (engine, calls) = engine(&format!(
            "{}{}engine_settings:\n  require_revocation: true\nglobal:\n  revocation: [kc, \
             kill-list]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client] }"),
            checker("kill-list", "{ deny: auth.revoked }")
        ))
        .await;
        engine
            .get_plugin("kill-list")
            .expect("registered")
            .disable();

        let denied = check(&engine, both_slots())
            .await
            .expect("a configured checker that cannot run must not let requests through");

        assert_eq!(denied.code, REVOCATION_UNAVAILABLE_CODE, "disabled checker");
        assert_eq!(
            calls.load(Ordering::Acquire),
            0,
            "the route is refused before any checker runs, so kc cannot vouch alone"
        );
    }

    /// Every built-in hook, and where revocation is checked around it. A hook
    /// added to the metadata tables fails this until someone decides whether
    /// it is a request, a response, or internal to the engine, because an
    /// unphased boundary would let a revoked identity through unchecked.
    #[test]
    fn every_built_in_hook_has_its_check_points_decided() {
        const REQUEST: (Option<CheckPoint>, Option<CheckPoint>) = (
            Some(CheckPoint::AfterAuthentication),
            Some(CheckPoint::BeforeDispatch),
        );
        const RESPONSE: (Option<CheckPoint>, Option<CheckPoint>) =
            (None, Some(CheckPoint::BeforeRelease));
        const INTERNAL: (Option<CheckPoint>, Option<CheckPoint>) = (None, None);

        let decided: Vec<_> = BUILTIN_HOOK_METADATA
            .iter()
            .map(|(name, _)| (*name, check_points(name)))
            .collect();

        assert_eq!(
            decided,
            vec![
                ("cmf.tool_pre_invoke", REQUEST),
                ("cmf.tool_post_invoke", RESPONSE),
                ("cmf.llm_input", REQUEST),
                ("cmf.llm_output", RESPONSE),
                ("cmf.prompt_pre_invoke", REQUEST),
                ("cmf.prompt_post_invoke", RESPONSE),
                ("cmf.resource_pre_fetch", REQUEST),
                ("cmf.resource_post_fetch", RESPONSE),
                ("http.request", REQUEST),
                ("http.response", RESPONSE),
                ("identity.resolve", INTERNAL),
                ("token.delegate", INTERNAL),
                ("elicit", INTERNAL),
                ("metadata.fetch", INTERNAL),
                ("ratelimit.pre_identity", INTERNAL),
                ("ratelimit.post_identity", INTERNAL),
                ("revocation.check", INTERNAL),
            ],
            "the revocation check points of the built-in hooks changed"
        );
        assert_eq!(
            check_points("no.such.hook"),
            INTERNAL,
            "a hook with no metadata"
        );
    }

    #[tokio::test]
    async fn a_revoked_request_is_denied_on_a_hook_with_no_plugin() {
        let (engine, calls) = engine(&format!(
            "{}global:\n  revocation: [kill-list]\nroutes:\n  - tool: t\n",
            checker("kill-list", "{ deny: auth.revoked }")
        ))
        .await;

        let result = invoke(&engine, HOOK_CMF_TOOL_PRE_INVOKE).await;

        assert_eq!(
            result.violation.map(|v| v.code).as_deref(),
            Some(REVOKED_CODE),
            "the route has no plugin on the hook, and the request is still refused"
        );
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "refused before the pipeline"
        );
    }

    #[tokio::test]
    async fn an_allowed_request_is_checked_before_and_after_its_pipeline() {
        let (engine, calls) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client] }")
        ))
        .await;

        let result = invoke(&engine, HOOK_CMF_TOOL_PRE_INVOKE).await;

        assert!(!result.is_denied(), "both slots vouched at both points");
        assert_eq!(calls.load(Ordering::Acquire), 2, "two check points");
    }

    #[tokio::test]
    async fn checks_share_the_request_context_table() {
        let (engine, _) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client], tally: true }")
        ))
        .await;
        let kc = engine.get_plugin("kc").expect("registered").id();
        let mut seeded = PluginContextTable::default();
        seeded
            .local_states
            .insert(kc, HashMap::from([("tally".to_owned(), 10.into())]));

        let (result, _) = engine
            .invoke_by_name(
                HOOK_CMF_TOOL_PRE_INVOKE,
                Box::new(RevocationCheck::new(CheckPoint::AfterAuthentication, [])),
                both_slots(),
                Some(seeded),
            )
            .await;

        assert!(!result.is_denied(), "vouched at both points");
        assert_eq!(
            result
                .context_table
                .local_states
                .get(&kc)
                .and_then(|s| s.get("tally")),
            Some(&12.into()),
            "the check before the pipeline saw the host's 10, the check after it saw 11, and \
             the host gets 12 back"
        );
    }

    #[tokio::test]
    async fn a_revocation_during_the_pipeline_is_caught_before_dispatch() {
        let (engine, calls) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client], revoke_from_call: 2 }")
        ))
        .await;

        let result = invoke(&engine, HOOK_CMF_TOOL_PRE_INVOKE).await;

        assert_eq!(
            result.violation.map(|v| v.code).as_deref(),
            Some(REVOKED_CODE),
            "the pipeline allowed, and the check after it denied"
        );
        assert!(
            result.modified_payload.is_none(),
            "a denial carries no payload"
        );
        assert_eq!(calls.load(Ordering::Acquire), 2, "two check points");
    }

    #[tokio::test]
    async fn a_response_is_checked_once_before_release() {
        let (engine, calls) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client], revoke_from_call: 1 }")
        ))
        .await;

        let result = invoke(&engine, HOOK_CMF_TOOL_POST_INVOKE).await;

        assert_eq!(
            result.violation.map(|v| v.code).as_deref(),
            Some(REVOKED_CODE),
            "the response is withheld"
        );
        assert_eq!(calls.load(Ordering::Acquire), 1, "one check point");
    }

    #[tokio::test]
    async fn an_unphased_hook_is_never_checked() {
        let (engine, calls) = engine(&format!(
            "{}global:\n  revocation: [kill-list]\nroutes:\n  - tool: t\n",
            checker("kill-list", "{ deny: auth.revoked }")
        ))
        .await;

        let result = invoke(&engine, HOOK_IDENTITY_RESOLVE).await;

        assert!(!result.is_denied(), "identity resolution is not a boundary");
        assert_eq!(calls.load(Ordering::Acquire), 0, "never asked");
    }

    #[tokio::test]
    async fn an_http_route_checker_with_no_path_warns_once() {
        let (engine, _) = engine(&format!(
            "{}{}global:\n  revocation: [kc]\nroutes:\n  - http: {{ path_prefix: /v1 }}\n    \
             revocation: [kill-list]\n",
            checker("kc", "{ vouch: [subject, client] }"),
            checker("kill-list", "{ deny: auth.revoked }")
        ))
        .await;
        let (events, sink) = capturing();

        for _ in 0..3 {
            let result = dispatch(&engine, HOOK_HTTP_RESPONSE, response_without_path()).await;
            assert!(
                !result.is_denied(),
                "without a path only the global checker can run"
            );
        }

        let warnings = events.matching("declares revocation:");
        assert_eq!(warnings.len(), 1, "the warning latches: {warnings:?}");
        assert!(
            warnings
                .first()
                .is_some_and(|warning| warning.contains("/v1")),
            "the warning names the route whose checkers could not run: {warnings:?}"
        );
        drop(sink);
    }

    #[tokio::test]
    async fn checker_entries_never_enter_the_route_cache() {
        let (engine, calls) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client] }")
        ))
        .await;

        let result = invoke(&engine, HOOK_CMF_TOOL_PRE_INVOKE).await;

        assert!(!result.is_denied(), "both slots vouched");
        assert_eq!(calls.load(Ordering::Acquire), 2, "both check points ran");
        assert_eq!(
            engine.routing_cache_size(),
            0,
            "a fill from a request on an older snapshot would outlive a reload's clear and keep \
             serving that generation's checkers"
        );
    }

    #[tokio::test]
    async fn a_host_is_told_to_call_every_checked_hook() {
        let (engine, _) = engine(&format!(
            "{}global:\n  revocation: [kc]\nroutes:\n  - tool: t\n",
            checker("kc", "{ vouch: [subject, client] }")
        ))
        .await;

        let reported: Vec<_> = BUILTIN_HOOK_METADATA
            .iter()
            .filter(|(name, _)| engine.has_hooks_for(name))
            .map(|(name, _)| *name)
            .collect();

        assert_eq!(
            reported,
            vec![
                "cmf.tool_pre_invoke",
                "cmf.tool_post_invoke",
                "cmf.llm_input",
                "cmf.llm_output",
                "cmf.prompt_pre_invoke",
                "cmf.prompt_post_invoke",
                "cmf.resource_pre_fetch",
                "cmf.resource_post_fetch",
                "http.request",
                "http.response",
                "revocation.check",
            ],
            "a host that skips a hook has_hooks_for denies would skip its revocation check"
        );
    }

    #[tokio::test]
    async fn without_revocation_no_hook_is_reported_for_it() {
        let (engine, _) = engine("routes:\n  - tool: t\n").await;

        let reported: Vec<_> = BUILTIN_HOOK_METADATA
            .iter()
            .filter(|(name, _)| engine.has_hooks_for(name))
            .map(|(name, _)| *name)
            .collect();

        assert!(reported.is_empty(), "nothing is configured: {reported:?}");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use crate::cmf::constants::{
        ENTITY_HTTP, ENTITY_NAME_GLOBAL, HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
    };
    use crate::context::{PluginContext, PluginContextTable};
    use crate::engine::PolicyEngine;
    use crate::error::PluginError;
    use crate::extensions::HttpExtension;
    use crate::extensions::MetaExtension;
    use crate::extensions::security::{ClientExtension, SecurityExtension, SubjectExtension};
    use crate::factory::{PluginFactory, PluginInstance};
    use crate::hooks::metadata::BUILTIN_HOOK_METADATA;
    use crate::hooks::payload::PluginPayload;
    use crate::hooks::trait_def::{HookTypeDef as _, PluginResult};
    use crate::http_hook::HOOK_HTTP_RESPONSE;
    use crate::identity::HOOK_IDENTITY_RESOLVE;
    use crate::plugin::{Plugin, PluginConfig};
    use crate::registry::AnyHookHandler;
    use crate::revocation::{HOOK_REVOCATION_CHECK, RevocationHook};
    use crate::trace_capture::capturing;

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

    /// Run one check point, the one a response gets, for `extensions`.
    async fn check(engine: &PolicyEngine, extensions: Extensions) -> Option<PluginViolation> {
        dispatch(engine, HOOK_CMF_TOOL_POST_INVOKE, extensions)
            .await
            .violation
    }

    /// Dispatch `hook` for a request on `tool:t` carrying a subject and a
    /// client.
    async fn invoke(engine: &PolicyEngine, hook: &str) -> PipelineResult {
        dispatch(engine, hook, both_slots()).await
    }

    /// Dispatch `hook` with `extensions`, as a host would. No plugin reads the
    /// payload, so any will do.
    async fn dispatch(engine: &PolicyEngine, hook: &str, extensions: Extensions) -> PipelineResult {
        let payload = RevocationCheck::new(CheckPoint::AfterAuthentication, []);
        engine
            .invoke_by_name(hook, Box::new(payload), extensions, None)
            .await
            .0
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

    /// An HTTP response carrying a subject and a client but no request path.
    fn response_without_path() -> Extensions {
        Extensions {
            http: Some(Arc::new(HttpExtension::default())),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(ENTITY_HTTP.to_owned()),
                entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
                ..Default::default()
            })),
            ..both_slots()
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
            ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            let checker = &self.0;
            let call = checker.calls.fetch_add(1, Ordering::AcqRel) + 1;
            if checker.setting("tally") == Some(&serde_json::Value::Bool(true)) {
                let seen = ctx
                    .local_state
                    .get("tally")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default();
                ctx.local_state.insert("tally".into(), (seen + 1).into());
            }
            let revoked_by_now = checker
                .setting("revoke_from_call")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|from| call as u64 >= from);
            if revoked_by_now {
                return Ok(crate::executor::erase_result(
                    PluginResult::<RevocationCheck>::deny(PluginViolation::new(
                        REVOKED_CODE,
                        "revoked",
                    )),
                ));
            }
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
