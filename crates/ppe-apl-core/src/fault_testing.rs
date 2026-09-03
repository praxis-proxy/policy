// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A PDP resolver that panics, returns an error, or hangs, on demand.
//!
//! Drive this through [`crate::fault_testing::drive_pdp`] and assert the
//! decision. `docs/safety-invariants.md` is the catalog.
//!
//! Behind `test-util`. A `FaultPdp` that reached production would either
//! deny every request or hang it.

#![allow(clippy::panic, reason = "the harness panics on demand")]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::attributes::AttributeBag;
use crate::evaluator::{Decision, PDP_EVALUATE_TIMEOUT, evaluate_effects};
use crate::route::RoutePayload;
use crate::rules::Effect;
use crate::step::{
    NoopDelegationInvoker, NoopElicitationInvoker, PdpCall, PdpDecision, PdpDialect, PdpError,
    PdpResolver, PluginError, PluginInvocation, PluginInvoker, PluginOutcome,
};

/// How the resolver fails. `None` is the control: the resolver allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedFailure {
    /// Return `Decision::Allow`.
    None,
    /// Return `PdpError::Dispatch`.
    Error,
    /// Sleep longer than the evaluator's 30-second PDP budget.
    Hang,
    /// `panic!` inside `evaluate`.
    Panic,
}

impl InjectedFailure {
    /// Every injected failure the catalog drives, including the control.
    pub const fn all() -> [Self; 4] {
        [Self::None, Self::Error, Self::Hang, Self::Panic]
    }
}

/// Resolver that injects [`InjectedFailure`]. `dialect` is reported to
/// the evaluator; the injected failure does not depend on it. Catalog
/// cells still label each shipped dialect so adding one fails the test
/// until a cell is added.
pub struct FaultPdp {
    /// Which dialect this instance claims to serve.
    pub dialect: PdpDialect,
    /// What `evaluate` does.
    pub failure: InjectedFailure,
}

impl FaultPdp {
    /// Construct a resolver for `dialect` that injects `failure`.
    pub fn new(dialect: PdpDialect, failure: InjectedFailure) -> Self {
        Self { dialect, failure }
    }
}

#[async_trait]
impl PdpResolver for FaultPdp {
    fn dialect(&self) -> PdpDialect {
        self.dialect.clone()
    }

    async fn evaluate(
        &self,
        _call: &PdpCall,
        _bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        match self.failure {
            InjectedFailure::None => Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: vec![],
            }),
            InjectedFailure::Error => Err(PdpError::Dispatch("injected PDP error".into())),
            InjectedFailure::Hang => {
                tokio::time::sleep(PDP_EVALUATE_TIMEOUT + Duration::from_secs(30)).await;
                Ok(PdpDecision {
                    decision: Decision::Allow,
                    diagnostics: vec![],
                })
            },
            InjectedFailure::Panic => panic!("injected panic inside a PDP resolver"),
        }
    }
}

struct NullPlugins;

#[async_trait]
impl PluginInvoker for NullPlugins {
    async fn invoke(
        &self,
        name: &str,
        _bag: &AttributeBag,
        _invocation: PluginInvocation<'_>,
    ) -> Result<PluginOutcome, PluginError> {
        Err(PluginError::NotFound(name.into()))
    }
}

/// Run one PDP effect through the evaluator, the same path a route uses.
pub async fn drive_pdp(pdp: Arc<dyn PdpResolver>) -> Decision {
    let dialect = pdp.dialect();
    let effects = vec![Effect::Pdp {
        call: PdpCall {
            dialect,
            args: serde_yaml::Value::Null,
        },
        on_deny: vec![],
        on_allow: vec![],
    }];
    let mut bag = AttributeBag::new();
    let mut payload = RoutePayload::new(serde_json::Value::Null);
    let plugins: Arc<dyn PluginInvoker> = Arc::new(NullPlugins);
    let delegations: Arc<dyn crate::step::DelegationInvoker> = Arc::new(NoopDelegationInvoker);
    let elicitations: Arc<dyn crate::step::ElicitationInvoker> = Arc::new(NoopElicitationInvoker);
    evaluate_effects(
        &effects,
        &mut bag,
        &pdp,
        &plugins,
        &delegations,
        &elicitations,
        crate::step::DispatchPhase::Pre,
        &mut payload,
    )
    .await
    .decision
}

/// Dialects with an in-tree resolver. Exhaustive on [`PdpDialect`] so a new
/// builtin is a compile error until the catalog gains a cell. `AuthZen`,
/// `NeMo`, and `Custom` have no in-tree resolver; they are not harness
/// dialects.
pub fn shipped_harness_dialects() -> [PdpDialect; 3] {
    match PdpDialect::Cedar {
        PdpDialect::Cedar | PdpDialect::Cel | PdpDialect::Opa => {},
        PdpDialect::AuthZen | PdpDialect::NeMo | PdpDialect::Custom(_) => {},
    }
    [PdpDialect::Cedar, PdpDialect::Cel, PdpDialect::Opa]
}
