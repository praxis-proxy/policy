// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// APL core — Authorization Policy Language compiler + evaluator.
//
// This crate is the language nucleus. It does not depend on PPE directly;
// the bridge from praxis-policy-core extensions into the AttributeBag lives in
// `praxis-policy-apl-cmf`, and the `PolicyEvaluator` implementation lives in `praxis-policy-apl-runtime`.

#![doc = "APL — Authorization Policy Language."]

/// External attribute sources loaded at config time.
pub mod attribute_source;
/// The flat attribute bag policies are evaluated against.
pub mod attributes;
/// Value constraints used by validation pipelines.
pub mod constraint;
/// Evaluates rules and effects against an attribute bag.
pub mod evaluator;
/// Parses policy documents into the rule and step forms below.
pub mod parser;
/// Field pipelines: the validate, mask, and redact stages.
pub mod pipeline;
/// Plugin declarations and their per-route overrides.
pub mod plugin_decl;
/// A compiled route and the phases it runs.
pub mod route;
/// Rules, predicates, and effects.
pub mod rules;
/// Steps: plugin calls, delegation, taint, and decision point calls.
pub mod step;

/// The one reader for a quoted literal, and the one rule for escapes inside one.
mod lexical;

/// A PDP resolver that panics, errors, or hangs on demand. Behind `test-util`.
#[cfg(feature = "test-util")]
pub mod fault_testing;
/// Test scaffolding, behind the `test-util` feature.
#[cfg(feature = "test-util")]
pub mod test_util;

pub use attribute_source::{AttributeError, AttributeSource, AttributeTree};
pub use attributes::{AttributeBag, AttributeExtractor, AttributeValue};
pub use evaluator::{
    Decision, FieldOutcome, PipelineEvaluation, evaluate_effects, evaluate_pipeline, evaluate_rules,
};
pub use parser::{
    ParseError, RouteYaml, compile_policy_block_value, parse_pipeline, parse_predicate, parse_rule,
};
pub use pipeline::{FieldRule, Pipeline, ScanKind, Stage, TaintEvent, TaintScope, TypeCheck};
pub use plugin_decl::{
    CapsView, EffectivePlugin, PluginDeclaration, PluginOverride, PluginRegistry,
};
pub use route::{
    RouteDecision, RoutePayload, evaluate_post, evaluate_pre, evaluate_route, get_dotted,
};
pub use rules::{
    CompareOp, CompiledRoute, Condition, DenyResponse, Effect, Expression, Literal, Phase,
    PhaseSet, Rule,
};
pub use step::{
    AutoApprovingElicitor, DelegateStep, DelegationError, DelegationInvoker, DelegationOutcome,
    DispatchPhase, ElicitKind, ElicitStep, ElicitationDispatch, ElicitationError,
    ElicitationInvoker, ElicitationOutcome, ElicitationStatus, ElicitationValidation,
    NoopDelegationInvoker, NoopElicitationInvoker, PdpCall, PdpDecision, PdpDialect, PdpError,
    PdpFactory, PdpResolver, PendingElicitation, PluginError, PluginInvocation, PluginInvoker,
    PluginOutcome, delegation_bag_keys, elicitation_bag_keys,
};
