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
// Routing is by dialect equality. Host registrations (`register`) keep
// the first resolver per dialect. Config-supplied resolvers are a
// separate set, replaced wholesale on each load; a host registration
// wins when both layers name the same dialect. Unknown-dialect calls
// return `PdpError::NoResolver(dialect)`.
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
/// `Step::Pdp.call.dialect`. Construct with `new()`, add host resolvers
/// via `register`, then hand the router to a route handler.
///
/// Host registrations survive a config reload. Resolvers built from
/// `global.pdp[]` live in a separate set that is replaced on each load.
/// When both layers have a dialect, the host registration is the one
/// `evaluate` calls.
///
/// Cloning is cheap (refcount bumps on each resolver `Arc`) — the
/// `AplConfigVisitor` snapshots its accumulated router into an `Arc`
/// for every installed route handler so a config reload that mutates
/// the visitor state doesn't tear in-flight handlers.
#[derive(Clone)]
pub struct PdpRouter {
    /// Host registrations. The first `register` per dialect wins.
    code: HashMap<PdpDialect, Arc<dyn PdpResolver>>,
    /// Rebuilt from `global.pdp[]` on every config load. Never contains
    /// a dialect that `code` already owns.
    config: HashMap<PdpDialect, Arc<dyn PdpResolver>>,
}

impl PdpRouter {
    /// A new instance with nothing registered or stored yet.
    pub fn new() -> Self {
        Self {
            code: HashMap::new(),
            config: HashMap::new(),
        }
    }

    /// Register a code-supplied resolver for its declared dialect.
    ///
    /// The first registration per dialect wins. A later one is dropped
    /// and a warning is logged — an intentional swap goes through
    /// [`Self::replace`]. A config-supplied resolver for the same dialect
    /// is removed, so this registration is the one `evaluate` uses, including
    /// across later config reloads.
    pub fn register(&mut self, resolver: Arc<dyn PdpResolver>) -> &mut Self {
        let dialect = resolver.dialect();
        if self.code.contains_key(&dialect) {
            tracing::warn!(
                dialect = ?dialect,
                "PdpRouter: code-supplied resolver for dialect already registered — keeping existing",
            );
            return self;
        }
        self.config.remove(&dialect);
        self.code.insert(dialect, resolver);
        self
    }

    /// Swap the code-supplied resolver for this dialect.
    ///
    /// Drops a config-supplied resolver for the same dialect so the swap
    /// is what `evaluate` calls. Config reload does not use this: it
    /// replaces only the config-owned set.
    pub fn replace(&mut self, resolver: Arc<dyn PdpResolver>) -> &mut Self {
        let dialect = resolver.dialect();
        self.config.remove(&dialect);
        self.code.insert(dialect, resolver);
        self
    }

    /// Whether a host registration already owns `dialect`.
    pub(crate) fn has_code_resolver(&self, dialect: &PdpDialect) -> bool {
        self.code.contains_key(dialect)
    }

    /// Replace the config-owned set. Host registrations are left in place.
    ///
    /// Entries whose dialect is already code-supplied are dropped. A dialect
    /// absent from `resolvers` is removed, including when `resolvers` is empty.
    pub(crate) fn set_config_resolvers(
        &mut self,
        mut resolvers: HashMap<PdpDialect, Arc<dyn PdpResolver>>,
    ) {
        resolvers.retain(|dialect, _| !self.code.contains_key(dialect));
        self.config = resolvers;
    }

    /// Number of dialects `evaluate` can dispatch. Useful for tests.
    pub fn len(&self) -> usize {
        self.code.len() + self.config.len()
    }

    /// Whether no resolver is registered.
    pub fn is_empty(&self) -> bool {
        self.code.is_empty() && self.config.is_empty()
    }

    fn resolver(&self, dialect: &PdpDialect) -> Option<&Arc<dyn PdpResolver>> {
        self.code.get(dialect).or_else(|| self.config.get(dialect))
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
            .resolver(&call.dialect)
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
            .resolver(&call.dialect)
            .ok_or_else(|| PdpError::NoResolver(call.dialect.clone()))?;
        resolver.evaluate_structured(call, bag, structured).await
    }

    /// Forwards to the resolver for the call's dialect. A dialect with no
    /// resolver passes, so it still fails per request as `NoResolver`.
    fn validate_call(&self, call: &PdpCall) -> Result<(), String> {
        call.validate_input_options()?;
        self.resolver(&call.dialect)
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
        self.resolver(&call.dialect).map_or(Ok(()), |resolver| {
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

        let mut config_only = PdpRouter::new();
        config_only.set_config_resolvers(config_of(vec![Arc::new(StrictPdp)]));
        assert_eq!(
            config_only.validate_call(&call(PdpDialect::Cedar)),
            Err("args required".to_owned())
        );
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

    fn allow(dialect: PdpDialect) -> Arc<dyn PdpResolver> {
        Arc::new(FakePdp {
            dialect,
            decision: Decision::Allow,
        })
    }

    fn deny(dialect: PdpDialect, reason: &str) -> Arc<dyn PdpResolver> {
        Arc::new(FakePdp {
            dialect,
            decision: Decision::Deny {
                reason: Some(reason.to_owned()),
                rule_source: "test".to_owned(),
            },
        })
    }

    fn config_of(
        resolvers: Vec<Arc<dyn PdpResolver>>,
    ) -> HashMap<PdpDialect, Arc<dyn PdpResolver>> {
        resolvers
            .into_iter()
            .map(|resolver| {
                let dialect = resolver.dialect();
                (dialect, resolver)
            })
            .collect()
    }

    async fn decision(router: &PdpRouter, dialect: PdpDialect) -> Decision {
        router
            .evaluate(
                &PdpCall {
                    dialect,
                    args: serde_yaml::Value::Null,
                },
                &AttributeBag::default(),
            )
            .await
            .expect("dialect is registered")
            .decision
    }

    #[tokio::test]
    async fn config_resolvers_are_replaced_as_a_set() {
        let mut router = PdpRouter::new();
        router.set_config_resolvers(config_of(vec![
            allow(PdpDialect::Cedar),
            deny(PdpDialect::Opa, "opa"),
        ]));
        assert!(matches!(
            decision(&router, PdpDialect::Cedar).await,
            Decision::Allow
        ));
        assert!(matches!(
            decision(&router, PdpDialect::Opa).await,
            Decision::Deny { .. }
        ));

        router.set_config_resolvers(config_of(vec![deny(PdpDialect::Cedar, "reloaded")]));
        match decision(&router, PdpDialect::Cedar).await {
            Decision::Deny { reason, .. } => assert_eq!(reason.as_deref(), Some("reloaded")),
            Decision::Allow => panic!("reload must replace the cedar resolver"),
        }
        let err = router
            .evaluate(
                &PdpCall {
                    dialect: PdpDialect::Opa,
                    args: serde_yaml::Value::Null,
                },
                &AttributeBag::default(),
            )
            .await
            .expect_err("a dialect the reload removed must be gone");
        assert!(matches!(err, PdpError::NoResolver(_)));
        assert_eq!(router.len(), 1);
    }

    #[tokio::test]
    async fn code_registration_wins_over_config_and_survives_a_reload() {
        let mut router = PdpRouter::new();
        router.register(allow(PdpDialect::Cedar));
        router.set_config_resolvers(config_of(vec![
            deny(PdpDialect::Cedar, "from-config"),
            deny(PdpDialect::Opa, "opa"),
        ]));
        assert!(
            matches!(decision(&router, PdpDialect::Cedar).await, Decision::Allow),
            "a code-supplied resolver stays ahead of global.pdp"
        );
        assert!(matches!(
            decision(&router, PdpDialect::Opa).await,
            Decision::Deny { .. }
        ));
        assert_eq!(
            router.len(),
            2,
            "the shadowed config cedar resolver is not kept"
        );

        router.set_config_resolvers(HashMap::new());
        assert!(matches!(
            decision(&router, PdpDialect::Cedar).await,
            Decision::Allow
        ));
        let err = router
            .evaluate(
                &PdpCall {
                    dialect: PdpDialect::Opa,
                    args: serde_yaml::Value::Null,
                },
                &AttributeBag::default(),
            )
            .await
            .expect_err("clearing the config set removes config-owned dialects");
        assert!(matches!(err, PdpError::NoResolver(_)));
        assert_eq!(router.len(), 1);
    }

    #[tokio::test]
    async fn replace_swaps_the_code_resolver_and_drops_the_config_one() {
        let mut router = PdpRouter::new();
        router.set_config_resolvers(config_of(vec![deny(PdpDialect::Opa, "config")]));
        router.replace(allow(PdpDialect::Opa));
        assert!(matches!(
            decision(&router, PdpDialect::Opa).await,
            Decision::Allow
        ));
        assert_eq!(router.len(), 1);
        assert!(router.has_code_resolver(&PdpDialect::Opa));
    }
}
