// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PdpRouter` — composite `PdpResolver` that dispatches each call to the
// resolver matching the requested `PdpDialect`. Lets a single host (or a
// single `AplRouteHandler`) carry resolvers for several backends at the
// same time without having to pick one at construction.
//
// The PDP backends that ship in this workspace, each its own crate
// registered here by dialect:
//
//   - **cedar** — in-process Cedar policy-set
//     evaluation.
//   - **opa** — Open Policy Agent / Rego.
//   - **authzen** — AuthZen-protocol external decision point.
//   - **nemo** — NeMo reasoning backend.
//   - **cel** — inline CEL boolean predicates authored in
//     the route YAML (`cel: { expr: "..." }`); smallest dep tree, no
//     external policy store.
//
// Routing is by dialect equality. The first registered resolver for a
// given dialect wins on duplicate registration — registering Cedar twice
// keeps the original and logs a warning. Unknown-dialect calls return
// `PdpError::NoResolver(dialect)`.
//
// `PdpRouter` is itself a `PdpResolver`, so it slots straight into
// `AplRouteHandler::with_pdp`. Its own `dialect()` method returns
// `PdpDialect::Custom("router")` — a sentinel the evaluator doesn't
// branch on; only inner resolvers' dialects matter.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{
    PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver, StructuredInputAvailability,
};

/// Dispatches PDP calls to the right resolver based on
/// `Step::Pdp.call.dialect`. Construct with `new()`, add resolvers via
/// `register`, then hand the router to a route handler.
///
/// Cloning is cheap (refcount bumps on each resolver `Arc`) — the
/// `AplConfigVisitor` snapshots its accumulated router into an `Arc`
/// for every installed route handler so a config reload that mutates
/// the visitor state doesn't tear in-flight handlers.
#[derive(Clone)]
pub struct PdpRouter {
    resolvers: HashMap<PdpDialect, Arc<dyn PdpResolver>>,
}

impl PdpRouter {
    /// A new instance with nothing registered or stored yet.
    pub fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
        }
    }

    /// Register a resolver for its declared dialect. If a resolver is
    /// already registered for that dialect the new one is dropped and a
    /// warning is logged — explicit replacement should go through
    /// `replace` instead so the intent is visible at call sites.
    pub fn register(&mut self, resolver: Arc<dyn PdpResolver>) -> &mut Self {
        let dialect = resolver.dialect();
        if self.resolvers.contains_key(&dialect) {
            tracing::warn!(
                dialect = ?dialect,
                "PdpRouter: resolver for dialect already registered — keeping existing",
            );
            return self;
        }
        self.resolvers.insert(dialect, resolver);
        self
    }

    /// Replace any existing resolver for the new resolver's dialect.
    /// Use this when the host genuinely wants to swap in a different
    /// implementation (testing, A/B rollout).
    pub fn replace(&mut self, resolver: Arc<dyn PdpResolver>) -> &mut Self {
        let dialect = resolver.dialect();
        self.resolvers.insert(dialect, resolver);
        self
    }

    /// Number of registered resolvers. Useful for tests.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether no resolver is registered.
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

impl Default for PdpRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PdpResolver for PdpRouter {
    fn dialect(&self) -> PdpDialect {
        // Sentinel — evaluator routes per `Step::Pdp.call.dialect`, not
        // the resolver's own declared dialect. The router never claims to
        // be one of the real dialects so a stray equality check can't
        // accidentally pick it.
        PdpDialect::Custom("router".to_owned())
    }

    async fn evaluate(&self, call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        let resolver = self
            .resolvers
            .get(&call.dialect)
            .ok_or_else(|| PdpError::NoResolver(call.dialect.clone()))?;
        resolver.evaluate(call, bag).await
    }

    async fn evaluate_structured(
        &self,
        call: &PdpCall,
        bag: &AttributeBag,
        structured: &StructuredInput,
    ) -> Result<PdpDecision, PdpError> {
        let resolver = self
            .resolvers
            .get(&call.dialect)
            .ok_or_else(|| PdpError::NoResolver(call.dialect.clone()))?;
        resolver.evaluate_structured(call, bag, structured).await
    }

    /// Forwards to the resolver for the call's dialect. A dialect with no
    /// resolver passes, so it still fails per request as `NoResolver`.
    fn validate_call(&self, call: &PdpCall) -> Result<(), String> {
        call.validate_input_options()?;
        self.resolvers
            .get(&call.dialect)
            .map_or_else(|| Ok(()), |resolver| resolver.validate_call(call))
    }

    fn validate_call_with_input(
        &self,
        call: &PdpCall,
        input: StructuredInputAvailability,
    ) -> Result<(), String> {
        call.validate_input_options()?;
        if call.requires_llm_request() && !input.llm_request {
            return Err("`require_llm_request: true` requires a route that can carry a host request document".to_owned());
        }
        self.resolvers
            .get(&call.dialect)
            .map_or(Ok(()), |resolver| {
                resolver.validate_call_with_input(call, input)
            })
    }
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
    use praxis_policy_apl_core::evaluator::Decision;

    struct FakePdp {
        dialect: PdpDialect,
        decision: Decision,
    }

    #[async_trait]
    impl PdpResolver for FakePdp {
        fn dialect(&self) -> PdpDialect {
            self.dialect.clone()
        }

        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            Ok(PdpDecision {
                decision: self.decision.clone(),
                diagnostics: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn routes_by_dialect() {
        let mut router = PdpRouter::new();
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Cedar,
            decision: Decision::Allow,
        }));
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Opa,
            decision: Decision::Deny {
                reason: Some("opa says no".into()),
                rule_source: "opa".into(),
            },
        }));

        let bag = AttributeBag::default();
        let cedar_call = PdpCall {
            dialect: PdpDialect::Cedar,
            args: serde_yaml::Value::Null,
        };
        let opa_call = PdpCall {
            dialect: PdpDialect::Opa,
            args: serde_yaml::Value::Null,
        };

        let cedar_res = router.evaluate(&cedar_call, &bag).await.unwrap();
        assert!(matches!(cedar_res.decision, Decision::Allow));

        let opa_res = router.evaluate(&opa_call, &bag).await.unwrap();
        assert!(matches!(opa_res.decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn missing_dialect_returns_no_resolver() {
        let router = PdpRouter::new();
        let bag = AttributeBag::default();
        let call = PdpCall {
            dialect: PdpDialect::Cedar,
            args: serde_yaml::Value::Null,
        };
        let err = router.evaluate(&call, &bag).await.unwrap_err();
        assert!(matches!(err, PdpError::NoResolver(_)));
    }

    struct StrictPdp;

    #[async_trait]
    impl PdpResolver for StrictPdp {
        fn dialect(&self) -> PdpDialect {
            PdpDialect::Cedar
        }

        async fn evaluate(
            &self,
            _call: &PdpCall,
            _bag: &AttributeBag,
        ) -> Result<PdpDecision, PdpError> {
            Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: Vec::new(),
            })
        }

        fn validate_call(&self, call: &PdpCall) -> Result<(), String> {
            if call.args.is_null() {
                Err("args required".to_owned())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn validate_call_forwards_by_dialect() {
        let mut router = PdpRouter::new();
        router.register(Arc::new(StrictPdp));
        let call = |dialect| PdpCall {
            dialect,
            args: serde_yaml::Value::Null,
        };
        assert_eq!(
            router.validate_call(&call(PdpDialect::Cedar)),
            Err("args required".to_owned())
        );
        // No resolver for the dialect: load passes, as it did before.
        assert_eq!(router.validate_call(&call(PdpDialect::Opa)), Ok(()));
    }

    #[tokio::test]
    async fn duplicate_register_keeps_first() {
        let mut router = PdpRouter::new();
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Cedar,
            decision: Decision::Allow,
        }));
        router.register(Arc::new(FakePdp {
            dialect: PdpDialect::Cedar,
            decision: Decision::Deny {
                reason: Some("shouldn't fire".into()),
                rule_source: "test".into(),
            },
        }));
        let call = PdpCall {
            dialect: PdpDialect::Cedar,
            args: serde_yaml::Value::Null,
        };
        let res = router
            .evaluate(&call, &AttributeBag::default())
            .await
            .unwrap();
        assert!(matches!(res.decision, Decision::Allow));
    }
}
