// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Request-time crypto failures without a loaded FIPS provider.

#![cfg(feature = "fips")]

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "tests inspect expected failures and fixture construction"
)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
    use std::time::Duration;

    use async_trait::async_trait;
    use praxis_policy_apl_cmf::constants::{
        DETAIL_HTTP_BODY, DETAIL_HTTP_HEADERS, DETAIL_HTTP_STATUS,
    };
    use praxis_policy_apl_core::AttributeBag;
    use praxis_policy_apl_core::evaluator::Decision;
    use praxis_policy_apl_core::plugin_decl::PluginRegistry;
    use praxis_policy_apl_core::route::StructuredInput;
    use praxis_policy_apl_core::rules::{CompiledRoute, DenyResponse, Effect};
    use praxis_policy_apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};
    use praxis_policy_apl_runtime::session_resolver::resolve_session;
    use praxis_policy_apl_runtime::{
        AplRouteHandler, CachedPdpResolver, DecisionCacheConfig, DecisionCacheStats, DispatchCache,
        HookFamily, HttpPluginInvoker, Phase, RouteDispatchPlan, SessionStore, SessionStoreError,
    };
    use praxis_policy_core::CryptoError;
    use praxis_policy_core::engine::PolicyEngine;
    use praxis_policy_core::executor::extract_erased;
    use praxis_policy_core::extensions::{
        AgentExtension, Extensions, LlmInstruction, LlmInstructionRole, LlmRequest,
        LlmRequestParts, SecurityExtension, SubjectExtension,
    };
    use praxis_policy_core::http_hook::HttpPayload;
    use praxis_policy_core::plugin::PluginConfig;
    use praxis_policy_core::registry::AnyHookHandler as _;

    // -----------------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------------

    const PRIVATE_INSTRUCTION: &str = "private instruction for route hashing coverage";
    const PRIVATE_SESSION: &str = "private upstream session";
    const PRIVATE_SUBJECT: &str = "private authenticated subject";

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[tokio::test]
    async fn a_hashing_failure_denies_the_route_before_authorization() {
        assert_provider_absent();
        let engine = Arc::new(PolicyEngine::default());
        let pdp = Arc::new(CountingPdp::default());
        let store = Arc::new(CountingStore::default());
        let (events, _capture) = capturing();

        for phase in [Phase::Pre, Phase::Post] {
            let effect = Effect::Pdp {
                call: pdp_call(),
                on_allow: vec![Effect::Allow],
                on_deny: Vec::new(),
            };
            let mut route = CompiledRoute::new("crypto-failure-route");
            route.pre_invocation.push(effect.clone());
            route.post_invocation.push(effect);
            route.response = Some(DenyResponse {
                status: Some(503),
                body: Some("Policy is unavailable".to_owned()),
                headers: BTreeMap::from([("Retry-After".to_owned(), "1".to_owned())]),
            });
            let handler = AplRouteHandler::new(
                PluginConfig::default(),
                Arc::new(route),
                phase,
                HookFamily::Http,
                Arc::new(PluginRegistry::default()),
                Arc::new(DispatchCache::new()),
                store.clone(),
                Arc::downgrade(&engine),
            )
            .with_pdp(pdp.clone());
            let extensions = Extensions {
                llm_request: Some(LlmRequest::from_parts(LlmRequestParts {
                    instructions: vec![LlmInstruction {
                        role: LlmInstructionRole::System,
                        text: PRIVATE_INSTRUCTION.to_owned(),
                    }],
                    ..Default::default()
                })),
                ..Default::default()
            };
            let result = handler
                .invoke(&HttpPayload, &extensions, &mut Default::default())
                .await
                .expect("handler returns a denial");
            let result = extract_erased(result).expect("handler result");
            assert!(
                !result.continue_processing,
                "{phase:?} must stop processing"
            );
            assert!(result.modified_payload.is_none());
            assert!(result.modified_extensions.is_none());
            let violation = result.violation.expect("hashing failure denies");
            assert_eq!(violation.code, "policy.crypto_failed");
            assert_eq!(violation.reason, "the request could not be hashed");
            assert_eq!(
                violation.details.get(DETAIL_HTTP_STATUS),
                Some(&serde_json::json!(503))
            );
            assert_eq!(
                violation.details.get(DETAIL_HTTP_BODY),
                Some(&serde_json::json!("Policy is unavailable"))
            );
            assert_eq!(
                violation.details.get(DETAIL_HTTP_HEADERS),
                Some(&serde_json::json!({"Retry-After": "1"}))
            );
            assert_safe(&format!("{} {:?}", violation.reason, violation.details));
        }

        assert_eq!(
            pdp.calls.load(Ordering::Acquire),
            0,
            "authorization must not run"
        );
        assert_eq!(store.reads.load(Ordering::Acquire), 0);
        assert_eq!(store.writes.load(Ordering::Acquire), 0);
        assert_alarm(&events, "attribute_bag", 2);
        assert!(
            events
                .recorded()
                .iter()
                .all(|event| !event.contains(PRIVATE_INSTRUCTION))
        );
        for event in events.matching("policy_crypto_failure") {
            assert!(event.contains("route=crypto-failure-route"), "{event}");
        }
    }

    #[tokio::test]
    async fn a_hashing_failure_skips_the_pdp_and_decision_cache() {
        assert_provider_absent();
        let pdp = Arc::new(CountingPdp::default());
        let cache = CachedPdpResolver::wrap(
            pdp.clone(),
            DecisionCacheConfig::new(Duration::from_secs(60), NonZeroUsize::MIN)
                .expect("cache config"),
            Weak::new(),
        );
        let mut bag = AttributeBag::new();
        bag.set("subject.id", PRIVATE_SUBJECT);
        let (events, _capture) = capturing();

        for _ in 0..2 {
            let error = cache
                .evaluate_structured(&pdp_call(), &bag, &StructuredInput::default())
                .await
                .expect_err("hashing must fail");
            assert!(
                matches!(&error, PdpError::Dispatch(message) if message == "PDP cache key hashing failed")
            );
            assert_safe(&error.to_string());
            assert_eq!(
                cache.stats(),
                DecisionCacheStats::default(),
                "no cache lookup or insertion"
            );
        }

        assert_eq!(
            pdp.calls.load(Ordering::Acquire),
            0,
            "the PDP must not see the request"
        );
        assert_alarm(&events, "pdp_cache_key", 2);
        assert!(
            events
                .recorded()
                .iter()
                .all(|event| !event.contains(PRIVATE_SUBJECT))
        );
    }

    #[test]
    fn a_hashing_failure_is_not_a_raw_or_sessionless_session_id() {
        assert_provider_absent();
        for (tier, extensions) in session_requests() {
            assert!(
                matches!(resolve_session(&extensions), Err(CryptoError::OpenSsl(_))),
                "{tier} must propagate the hash failure"
            );
        }
        assert_eq!(
            resolve_session(&Extensions::default()).expect("sessionless requests do not hash"),
            None
        );
    }

    #[tokio::test]
    async fn a_hashing_failure_stops_session_hydration() {
        assert_provider_absent();
        let engine = Arc::new(PolicyEngine::default());
        let store = Arc::new(CountingStore::default());
        let (events, _capture) = capturing();

        for (tier, extensions) in session_requests() {
            let error = HttpPluginInvoker::for_request(
                engine.clone(),
                extensions,
                HttpPayload,
                Arc::new(RouteDispatchPlan::default()),
                store.clone(),
            )
            .await
            .err()
            .expect("hashing failure must prevent invoker construction");
            assert!(
                matches!(&error, SessionStoreError::Backend(message) if message == "session id hashing failed"),
                "{tier} must report a safe hashing failure: {error}"
            );
            assert_safe(&error.to_string());
        }

        HttpPluginInvoker::for_request(
            engine,
            Extensions::default(),
            HttpPayload,
            Arc::new(RouteDispatchPlan::default()),
            store.clone(),
        )
        .await
        .expect("sessionless requests need no provider or store");
        assert_eq!(
            store.reads.load(Ordering::Acquire),
            0,
            "a failed hash cannot address the store"
        );
        assert_eq!(store.writes.load(Ordering::Acquire), 0);
        assert_alarm(&events, "session_id", 3);
        assert!(
            events
                .recorded()
                .iter()
                .all(|event| !event.contains(PRIVATE_SESSION) && !event.contains(PRIVATE_SUBJECT))
        );
    }

    #[test]
    fn a_hashing_failure_omits_unkeyed_content_provenance() {
        assert_provider_absent();
        let (events, _capture) = capturing();
        assert_eq!(
            praxis_policy_core::hooks::payload::ContentKey::Unkeyed
                .digest(PRIVATE_INSTRUCTION.as_bytes()),
            None,
            "a failed hash must not emit a fabricated audit digest"
        );
        let failures = events.matching("content digest failed");
        assert_eq!(failures.len(), 1, "{failures:?}");
        for failure in failures {
            assert!(failure.contains("[ERROR]"), "{failure}");
            assert!(!failure.contains(PRIVATE_INSTRUCTION), "{failure}");
        }
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn assert_provider_absent() {
        assert!(
            matches!(
                praxis_policy_core::validate_crypto_backend(),
                Err(CryptoError::OpenSsl(_))
            ),
            "these tests need the FIPS provider absent; run `make test-fips-no-provider`"
        );
    }

    fn assert_safe(rendered: &str) {
        for private in [
            "OpenSSL",
            "fips=yes",
            PRIVATE_INSTRUCTION,
            PRIVATE_SESSION,
            PRIVATE_SUBJECT,
        ] {
            assert!(
                !rendered.contains(private),
                "client response exposed {private}: {rendered}"
            );
        }
    }

    fn assert_alarm(events: &Events, op: &str, count: usize) {
        let alarms = events.matching("policy_crypto_failure");
        assert_eq!(alarms.len(), count, "{alarms:?}");
        for alarm in alarms {
            assert!(
                alarm.contains("[ERROR]") && alarm.contains(&format!("op={op}")),
                "{alarm}"
            );
        }
    }

    fn pdp_call() -> PdpCall {
        PdpCall {
            dialect: PdpDialect::Cel,
            args: serde_yaml::Value::Null,
        }
    }

    fn session_requests() -> [(&'static str, Extensions); 3] {
        let identity = Extensions {
            security: Some(Arc::new(SecurityExtension {
                subject: Some(SubjectExtension {
                    id: Some(PRIVATE_SUBJECT.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut agent = identity.clone();
        agent.agent = Some(Arc::new(AgentExtension {
            session_id: Some(PRIVATE_SESSION.to_owned()),
            ..Default::default()
        }));
        let mut claim = identity.clone();
        Arc::make_mut(claim.security.as_mut().expect("security fixture"))
            .subject
            .as_mut()
            .expect("subject fixture")
            .claims
            .insert("session_id".to_owned(), serde_json::json!(PRIVATE_SESSION));
        [
            ("agent", agent),
            ("token claim", claim),
            ("identity", identity),
        ]
    }

    #[derive(Default)]
    struct CountingPdp {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl PdpResolver for CountingPdp {
        fn dialect(&self) -> PdpDialect {
            PdpDialect::Cel
        }

        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: Vec::new(),
            })
        }
    }

    #[derive(Default)]
    struct CountingStore {
        reads: AtomicUsize,
        writes: AtomicUsize,
    }

    #[async_trait]
    impl SessionStore for CountingStore {
        async fn append_labels(
            &self,
            _session_id: &str,
            _labels: &[String],
        ) -> Result<(), SessionStoreError> {
            self.writes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        async fn load_labels(&self, _session_id: &str) -> Result<Vec<String>, SessionStoreError> {
            self.reads.fetch_add(1, Ordering::AcqRel);
            Ok(Vec::new())
        }
    }

    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<String>>>);

    impl Events {
        fn matching(&self, needle: &str) -> Vec<String> {
            self.recorded()
                .into_iter()
                .filter(|event| event.contains(needle))
                .collect()
        }

        fn recorded(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    thread_local! { static SINK: RefCell<Option<Events>> = const { RefCell::new(None) }; }

    struct Capture;
    struct Sink;

    impl Drop for Sink {
        fn drop(&mut self) {
            SINK.with_borrow_mut(|sink| *sink = None);
        }
    }

    struct Render(String);

    impl tracing::field::Visit for Render {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            SINK.with_borrow(|sink| {
                if let Some(events) = sink {
                    let mut render = Render(format!("[{}]", event.metadata().level()));
                    event.record(&mut render);
                    events
                        .0
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(render.0);
                }
            });
        }

        fn exit(&self, _: &tracing::span::Id) {}

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }
    }

    fn capturing() -> (Events, Sink) {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            tracing::subscriber::set_global_default(Capture)
                .expect("one subscriber per test binary");
        });
        let events = Events::default();
        SINK.with_borrow_mut(|sink| *sink = Some(events.clone()));
        (events, Sink)
    }
}
