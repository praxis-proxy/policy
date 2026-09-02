// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Phase orchestration: runs `args → pre_invocation → result → post_invocation` against a
// `CompiledRoute` and a mutable payload, returning a unified decision plus
// accumulated taints.
//
// This is the entry point praxis-policy-apl-runtime calls into. Each phase has its own
// evaluator (see `evaluator.rs`); this module's job is to drive them in
// the right order with the right transitions (apply field mutations, halt
// on deny, thread taints across phases).
//
// Phase semantics:
//   - args: walk field rules; Replace/Omit mutate `payload.args`; Deny halts
//   - policy: walk steps; Deny halts
//   - result: only runs if `payload.result.is_some()`; same as args
//   - post_invocation: walks steps; the spec leaves room for "observed only"
//     handling, but praxis-policy-apl-core surfaces the deny — the host (praxis-policy-apl-runtime) chooses
//     whether to enforce it
//
// Missing fields are skipped silently — a pipeline can't transform what
// isn't there. If a route needs to require presence, that's a policy-phase
// `require(exists(args.X))` rule.

use std::sync::Arc;

use crate::attributes::AttributeBag;
use crate::evaluator::{Decision, FieldOutcome, evaluate_effects, evaluate_pipeline};
use crate::pipeline::TaintEvent;
use crate::rules::CompiledRoute;
use crate::step::{
    DelegationInvoker, DispatchPhase, ElicitationInvoker, PdpResolver, PluginInvoker,
};

/// Mutable payload for a route invocation. `args` is the request arguments
/// object; `result` is the response object (`None` on the inbound path,
/// `Some` once the tool/resource has produced a value).
#[derive(Debug, Clone)]
pub struct RoutePayload {
    /// The call arguments.
    pub args: serde_json::Value,
    /// The response, once the call has been made.
    pub result: Option<serde_json::Value>,
}

impl RoutePayload {
    /// A pre-call payload carrying only arguments.
    pub fn new(args: serde_json::Value) -> Self {
        Self { args, result: None }
    }

    /// A post-call payload carrying both arguments and response.
    pub fn with_result(args: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            args,
            result: Some(result),
        }
    }
}

/// Full outcome of running all four phases for a route.
///
/// `#[non_exhaustive]`: this outcome type keeps gaining fields as the engine
/// grows (taints, constraints, pending elicitations, …), so it is sealed
/// against external struct-literal construction — hosts read it, they don't
/// build it. New fields can be added without breaking downstream readers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RouteDecision {
    /// The verdict for the phase.
    pub decision: Decision,
    /// Taints accumulated from any phase. Empty unless a pipeline emitted them.
    pub taints: Vec<TaintEvent>,
    /// Backend candidate constraints emitted by `restrict` effects in any
    /// phase. Empty unless a `restrict` fired. The host bridge (praxis-policy-apl-runtime)
    /// folds these into a `CandidateConstraintExtension` it serializes to
    /// the router.
    pub constraints: Vec<crate::constraint::CandidateConstraint>,
    /// True if any args field was rewritten or omitted.
    pub args_modified: bool,
    /// True if any result field was rewritten or omitted.
    pub result_modified: bool,
    /// Set when a phase suspended on an unresolved elicitation. `Some`
    /// means the host must emit JSON-RPC `-32120` (retry) and **not**
    /// forward — `decision` is `Allow` in that case. The host forwards
    /// only when `decision` is `Allow` AND `pending.is_none()`. See
    /// [`crate::step::PendingElicitation`].
    pub pending: Option<crate::step::PendingElicitation>,
}

/// Run the **pre-invocation** phases: `args` then `pre_invocation`. Used by
/// orchestrators bound to a pre-invocation hook — by the time
/// post-invoke fires, the tool has produced a response, so result/
/// `post_invocation` belong to [`evaluate_post`].
///
/// On a phase Deny, halts and returns immediately. `args_modified` is
/// set if any args field was rewritten or omitted; `result_modified` is
/// always `false` (post hasn't run). Taints emitted during args/policy
/// land in the returned `taints` vec — survive even on a Deny so audit
/// sees what fired before the halt.
pub async fn evaluate_pre(
    route: &CompiledRoute,
    bag: &mut AttributeBag,
    payload: &mut RoutePayload,
    pdp: &Arc<dyn PdpResolver>,
    plugins: &Arc<dyn PluginInvoker>,
    delegations: &Arc<dyn DelegationInvoker>,
    elicitations: &Arc<dyn ElicitationInvoker>,
) -> RouteDecision {
    let mut taints: Vec<TaintEvent> = Vec::new();
    let mut args_modified = false;

    for rule in &route.args {
        // Expand intermediate arrays; excessive fan-out fails closed.
        let Some(paths) = expand_field_paths(&payload.args, &rule.field) else {
            return RouteDecision {
                decision: Decision::Deny {
                    reason: Some(format!(
                        "args field `{}` expands to too many elements to redact safely",
                        rule.field
                    )),
                    rule_source: rule.source.clone(),
                },
                taints,
                constraints: Vec::new(),
                args_modified,
                result_modified: false,
                pending: None,
            };
        };
        for path in paths {
            let Some(current) = get_dotted(&payload.args, &path).cloned() else {
                continue; // missing field on this element → no pipeline to run
            };
            let eval = evaluate_pipeline(
                &rule.pipeline,
                &current,
                bag,
                plugins,
                &rule.field,
                DispatchPhase::Pre,
            )
            .await;
            taints.extend(eval.taints);
            match eval.outcome {
                FieldOutcome::Pass => {},
                FieldOutcome::Replace(new_val) => {
                    if set_dotted(&mut payload.args, &path, new_val) {
                        args_modified = true;
                    }
                },
                FieldOutcome::Omit => {
                    if remove_dotted(&mut payload.args, &path) {
                        args_modified = true;
                    }
                },
                FieldOutcome::Deny { reason, .. } => {
                    return RouteDecision {
                        decision: Decision::Deny {
                            reason: Some(reason),
                            rule_source: rule.source.clone(),
                        },
                        taints,
                        // `restrict` only fires in the policy phase (below);
                        // an args-pipeline deny short-circuits before it.
                        constraints: Vec::new(),
                        args_modified,
                        result_modified: false,
                        pending: None,
                    };
                },
            }
        }
    }

    let policy_eval = evaluate_effects(
        &route.pre_invocation,
        bag,
        pdp,
        plugins,
        delegations,
        elicitations,
        DispatchPhase::Pre,
        payload,
    )
    .await;
    // FieldOps inside `do:` may have rewritten args during policy —
    // surface that to the host the same way as an `args:` pipeline.
    args_modified |= policy_eval.args_modified;
    taints.extend(policy_eval.taints);
    RouteDecision {
        decision: policy_eval.decision,
        taints,
        constraints: policy_eval.constraints,
        args_modified,
        result_modified: false,
        pending: policy_eval.pending,
    }
}

/// Run the **post-invocation** phases: `result` (if a response payload
/// is present) then `post_invocation`. Used by orchestrators bound to a
/// post-invocation hook.
///
/// On a phase Deny, halts. `result_modified` is set if any result field
/// was rewritten or omitted; `args_modified` is always `false` (this
/// function doesn't touch args).
pub async fn evaluate_post(
    route: &CompiledRoute,
    bag: &mut AttributeBag,
    payload: &mut RoutePayload,
    pdp: &Arc<dyn PdpResolver>,
    plugins: &Arc<dyn PluginInvoker>,
    delegations: &Arc<dyn DelegationInvoker>,
    elicitations: &Arc<dyn ElicitationInvoker>,
) -> RouteDecision {
    let mut taints: Vec<TaintEvent> = Vec::new();
    let mut result_modified = false;

    if let Some(result) = payload.result.as_mut() {
        for rule in &route.result {
            // Expand intermediate arrays; excessive fan-out fails closed.
            let Some(paths) = expand_field_paths(result, &rule.field) else {
                return RouteDecision {
                    decision: Decision::Deny {
                        reason: Some(format!(
                            "result field `{}` expands to too many elements to redact safely",
                            rule.field
                        )),
                        rule_source: rule.source.clone(),
                    },
                    taints,
                    constraints: Vec::new(),
                    args_modified: false,
                    result_modified,
                    pending: None,
                };
            };
            for path in paths {
                let Some(current) = get_dotted(result, &path).cloned() else {
                    continue;
                };
                let eval = evaluate_pipeline(
                    &rule.pipeline,
                    &current,
                    bag,
                    plugins,
                    &rule.field,
                    DispatchPhase::Post,
                )
                .await;
                taints.extend(eval.taints);
                match eval.outcome {
                    FieldOutcome::Pass => {},
                    FieldOutcome::Replace(new_val) => {
                        if set_dotted(result, &path, new_val) {
                            result_modified = true;
                        }
                    },
                    FieldOutcome::Omit => {
                        if remove_dotted(result, &path) {
                            result_modified = true;
                        }
                    },
                    FieldOutcome::Deny { reason, .. } => {
                        return RouteDecision {
                            decision: Decision::Deny {
                                reason: Some(reason),
                                rule_source: rule.source.clone(),
                            },
                            taints,
                            // `restrict` fires in post_invocation (below); a
                            // result-pipeline deny short-circuits before it.
                            constraints: Vec::new(),
                            args_modified: false,
                            result_modified,
                            pending: None,
                        };
                    },
                }
            }
        }
    }

    let post_eval = evaluate_effects(
        &route.post_invocation,
        bag,
        pdp,
        plugins,
        delegations,
        elicitations,
        DispatchPhase::Post,
        payload,
    )
    .await;
    // Same reason as the policy phase: a `do:`-embedded FieldOp may
    // have rewritten result fields during post_invocation.
    result_modified |= post_eval.result_modified;
    taints.extend(post_eval.taints);

    RouteDecision {
        decision: post_eval.decision,
        taints,
        constraints: post_eval.constraints,
        args_modified: false,
        result_modified,
        pending: post_eval.pending,
    }
}

/// Run all four phases against `payload`, mutating it in place.
/// Convenience wrapper for callers that don't need the pre/post split
/// (tests, single-hook hosts). Calls [`evaluate_pre`] then [`evaluate_post`],
/// skipping post entirely on a pre-side Deny. Taints from both halves
/// concatenate; `args_modified` and `result_modified` carry their
/// respective flags independently.
///
/// Orchestrators that need to fire on distinct pre/post hooks should
/// call [`evaluate_pre`] and [`evaluate_post`] separately so the post
/// half sees the payload after the tool has produced its response.
pub async fn evaluate_route(
    route: &CompiledRoute,
    bag: &mut AttributeBag,
    payload: &mut RoutePayload,
    pdp: &Arc<dyn PdpResolver>,
    plugins: &Arc<dyn PluginInvoker>,
    delegations: &Arc<dyn DelegationInvoker>,
    elicitations: &Arc<dyn ElicitationInvoker>,
) -> RouteDecision {
    let pre = evaluate_pre(route, bag, payload, pdp, plugins, delegations, elicitations).await;
    // Halt before the tool call on a pre-side Deny OR a pending
    // elicitation. Pending means the inbound phase suspended awaiting a
    // human — the tool must not run, so `post` (which processes the tool's
    // response) is skipped and the host emits `-32120` from `pre.pending`.
    if matches!(pre.decision, Decision::Deny { .. }) || pre.pending.is_some() {
        return pre;
    }
    let post = evaluate_post(route, bag, payload, pdp, plugins, delegations, elicitations).await;
    let mut taints = pre.taints;
    taints.extend(post.taints);
    let mut constraints = pre.constraints;
    constraints.extend(post.constraints);
    RouteDecision {
        decision: post.decision,
        taints,
        constraints,
        args_modified: pre.args_modified,
        result_modified: post.result_modified,
        pending: post.pending,
    }
}

/// Maximum traversal depth, counting path segments and implicit array fan-out.
const MAX_FANOUT_DEPTH: usize = 128;

/// Maximum number of concrete leaf paths one field rule may fan out into
/// before failing closed.
const MAX_EXPANDED_PATHS: usize = 100_000;

/// Resolve one path segment against a value. Object segments index by key; a
/// numeric segment indexes into an array, so a path produced by
/// [`expand_field_paths`] resolves.
fn segment_get<'a>(value: &'a serde_json::Value, seg: &str) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(_) => value.get(seg),
        serde_json::Value::Array(items) => seg.parse::<usize>().ok().and_then(|i| items.get(i)),
        _ => None,
    }
}

/// Expand a dotted field path into the concrete paths it names once arrays
/// along the way are accounted for.
///
/// Intermediate arrays fan out into indexed paths; missing leaves are skipped.
/// A terminal array remains one path so whole-value operations still apply.
/// Returns `None` when depth or leaf-count bounds are exceeded, allowing callers
/// to fail closed rather than apply a partial transformation.
pub(crate) fn expand_field_paths(root: &serde_json::Value, path: &str) -> Option<Vec<String>> {
    fn join(prefix: &str, seg: &str) -> String {
        if prefix.is_empty() {
            seg.to_owned()
        } else {
            format!("{prefix}.{seg}")
        }
    }

    fn walk(
        value: &serde_json::Value,
        segs: &[&str],
        prefix: &str,
        depth: usize,
        out: &mut Vec<String>,
    ) -> bool {
        if depth > MAX_FANOUT_DEPTH || out.len() > MAX_EXPANDED_PATHS {
            return false;
        }
        let Some((seg, rest)) = segs.split_first() else {
            out.push(prefix.to_owned());
            return true;
        };
        if let serde_json::Value::Array(items) = value {
            if let Ok(idx) = seg.parse::<usize>() {
                if let Some(child) = items.get(idx) {
                    return walk(child, rest, &join(prefix, seg), depth + 1, out);
                }
            } else {
                // Apply an unnamed intermediate array to every element.
                for (i, item) in items.iter().enumerate() {
                    if !walk(item, segs, &join(prefix, &i.to_string()), depth + 1, out) {
                        return false;
                    }
                }
            }
            return true;
        }
        let Some(child) = segment_get(value, seg) else {
            return true; // missing segment on this branch, so emit no path
        };
        walk(child, rest, &join(prefix, seg), depth + 1, out)
    }

    let segs: Vec<&str> = path.split('.').collect();
    let mut out = Vec::new();
    walk(root, &segs, "", 0, &mut out).then_some(out)
}

/// Descend to the parent value of a dotted path, following object keys and
/// numeric array indices. Returns `None` if any parent segment is missing or
/// crosses a scalar. Shared by `set_dotted` / `remove_dotted` so both write
/// through arrays the same way `get_dotted` reads through them.
fn parent_mut<'a>(
    root: &'a mut serde_json::Value,
    parents: &[&str],
) -> Option<&'a mut serde_json::Value> {
    let mut cur = root;
    for seg in parents {
        cur = match cur {
            serde_json::Value::Object(map) => map.get_mut(*seg)?,
            serde_json::Value::Array(items) => seg
                .parse::<usize>()
                .ok()
                .and_then(move |i| items.get_mut(i))?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Read `root.a.b.c` from a JSON value via dot-separated path. Returns
/// `None` if any segment is missing. Object segments index by key; a numeric
/// segment indexes into an array, so a path expanded by
/// `expand_field_paths` resolves.
///
/// Public because host bridges read fields back out of their own payload
/// projections — a plugin dispatched from a pipeline stage reports a new
/// value for the field it was pointed at, and finding that field has to
/// use the same path semantics the evaluator used to write it.
pub fn get_dotted<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = root;
    for seg in path.split('.') {
        cur = segment_get(cur, seg)?;
    }
    Some(cur)
}

/// Write to `root.a.b.c` via dot-separated path. Returns true on success;
/// false if the parent path doesn't exist or the leaf's parent is a scalar.
/// Does not create missing parents. A numeric leaf overwrites an array element.
pub(crate) fn set_dotted(
    root: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let (leaf, parents) = match parts.split_last() {
        Some(x) => x,
        None => return false,
    };
    let Some(cur) = parent_mut(root, parents) else {
        return false;
    };
    match cur {
        serde_json::Value::Object(map) => {
            map.insert((*leaf).to_owned(), value);
            true
        },
        serde_json::Value::Array(items) => match leaf.parse::<usize>().ok() {
            Some(i) => match items.get_mut(i) {
                Some(slot) => {
                    *slot = value;
                    true
                },
                None => false,
            },
            None => false,
        },
        _ => false,
    }
}

/// Remove `root.a.b.c` from a JSON value. Returns true if removal happened. A
/// numeric leaf segment removes that array element.
pub(crate) fn remove_dotted(root: &mut serde_json::Value, path: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let (leaf, parents) = match parts.split_last() {
        Some(x) => x,
        None => return false,
    };
    let Some(cur) = parent_mut(root, parents) else {
        return false;
    };
    match cur {
        serde_json::Value::Object(map) => map.remove(*leaf).is_some(),
        serde_json::Value::Array(items) => match leaf.parse::<usize>().ok() {
            Some(i) if i < items.len() => {
                items.remove(i);
                true
            },
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unreachable,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::pipeline::{FieldRule, Pipeline, Stage, TaintScope, TypeCheck};
    use crate::rules::{Effect, Expression, Rule};
    use crate::step::{
        NoopDelegationInvoker, NoopElicitationInvoker, PdpCall, PdpDecision, PdpDialect, PdpError,
        PluginError, PluginInvocation, PluginOutcome,
    };
    use async_trait::async_trait;
    use serde_json::json;

    struct AllowPdp;
    #[async_trait]
    impl PdpResolver for AllowPdp {
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
                diagnostics: vec![],
            })
        }
    }

    struct NoPlugins;
    #[async_trait]
    impl PluginInvoker for NoPlugins {
        async fn invoke(
            &self,
            name: &str,
            _bag: &AttributeBag,
            _invocation: PluginInvocation<'_>,
        ) -> Result<PluginOutcome, PluginError> {
            Err(PluginError::NotFound(name.into()))
        }
    }

    /// Elicitation invoker that always reports Pending — for the
    /// route-level suspend test.
    struct PendingElicitor;
    #[async_trait]
    impl ElicitationInvoker for PendingElicitor {
        async fn dispatch(
            &self,
            _step: &crate::step::ElicitStep,
            _resolved_from: &str,
        ) -> Result<crate::step::ElicitationDispatch, crate::step::ElicitationError> {
            Ok(crate::step::ElicitationDispatch {
                id: "elic-route-1".into(),
                approver: None,
                intent_id: None,
                expires_at: None,
            })
        }
        async fn check(
            &self,
            _step: &crate::step::ElicitStep,
            _id: &str,
        ) -> Result<crate::step::ElicitationStatus, crate::step::ElicitationError> {
            Ok(crate::step::ElicitationStatus::Pending)
        }
        async fn validate(
            &self,
            _step: &crate::step::ElicitStep,
            _id: &str,
        ) -> Result<crate::step::ElicitationValidation, crate::step::ElicitationError> {
            unreachable!("validate must not run while pending")
        }
    }

    // `evaluate_route` takes `&Arc<dyn PluginInvoker>` / `&Arc<dyn DelegationInvoker>`
    // so the path through `dispatch_parallel` can `Arc::clone` into each
    // spawned branch. These helpers wrap the no-op test stubs once per call.
    fn pdp_arc() -> Arc<dyn PdpResolver> {
        Arc::new(AllowPdp)
    }
    fn plugins() -> Arc<dyn PluginInvoker> {
        Arc::new(NoPlugins)
    }
    fn delegations() -> Arc<dyn DelegationInvoker> {
        Arc::new(NoopDelegationInvoker)
    }
    fn elicitations() -> Arc<dyn ElicitationInvoker> {
        Arc::new(NoopElicitationInvoker)
    }

    fn field_rule(field: &str, stages: Vec<Stage>) -> FieldRule {
        FieldRule {
            field: field.into(),
            pipeline: Pipeline { stages },
            source: format!("test.{field}"),
        }
    }

    fn deny_rule(source: &str, reason: &str) -> Rule {
        Rule::single(
            Expression::Always,
            Effect::Deny {
                reason: Some(reason.into()),
                code: None,
            },
            source,
        )
    }

    #[tokio::test]
    async fn empty_route_allows() {
        let route = CompiledRoute::new("noop");
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({}));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.args_modified);
        assert!(!r.result_modified);
        assert!(r.taints.is_empty());
    }

    #[tokio::test]
    async fn pending_elicitation_suspends_route_and_skips_post() {
        // A pending elicitation in `policy:` must suspend the whole route:
        // decision Allow + pending Some, and the `result:` phase (which
        // would mutate the response) must NOT run.
        let mut route = CompiledRoute::new("payroll");
        route
            .pre_invocation
            .push(Effect::Elicit(crate::step::ElicitStep {
                kind: crate::step::ElicitKind::Approval,
                plugin_name: "manager-approver".into(),
                channel: Some("ciba".into()),
                from: "user.manager".into(),
                purpose: None,
                scope: None,
                timeout: None,
                config_override: None,
                on_error: None,
                source: "payroll.policy[0]".into(),
            }));
        // A result rule that WOULD mask — proves post didn't run if untouched.
        route
            .result
            .push(field_rule("ssn", vec![Stage::Mask { keep_last: 4 }]));

        let elicitor: Arc<dyn ElicitationInvoker> = Arc::new(PendingElicitor);
        let mut bag = AttributeBag::new();
        // The step's `from` is an attribute ref — seed it so it resolves
        // (an unresolved attribute `from` now fails closed by design).
        bag.set("user.manager", "manager@corp.com");
        let mut payload = RoutePayload::with_result(json!({}), json!({ "ssn": "123-45-6789" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitor,
        )
        .await;

        assert_eq!(r.decision, Decision::Allow, "pending is not a deny");
        let bundle = r.pending.expect("route surfaced the pending bundle");
        assert_eq!(bundle.id, "elic-route-1");
        assert_eq!(bundle.plugin_name, "manager-approver");
        // post never ran → result untouched (no masking applied).
        assert!(!r.result_modified);
        assert_eq!(
            payload.result.as_ref().unwrap()["ssn"],
            json!("123-45-6789")
        );
    }

    #[tokio::test]
    async fn args_pipeline_mutates_payload() {
        let mut route = CompiledRoute::new("ping");
        route
            .args
            .push(field_rule("ssn", vec![Stage::Mask { keep_last: 4 }]));
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "ssn": "123-45-6789" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.args_modified);
        assert_eq!(payload.args["ssn"], json!("*******6789"));
    }

    #[tokio::test]
    async fn args_deny_halts_route() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule(
            "amount",
            vec![
                Stage::Type(TypeCheck::Int),
                Stage::Range {
                    min: Some(0),
                    max: Some(100),
                },
            ],
        ));
        // Also has a policy rule that would deny — should NOT be reached
        // (args deny short-circuits). If reached, source would be "policy[0]"
        // instead of the args rule's source.
        route
            .pre_invocation
            .push(Effect::from(deny_rule("policy[0]", "policy denied too")));

        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "amount": 200 }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        match r.decision {
            Decision::Deny { rule_source, .. } => {
                assert!(
                    rule_source.contains("amount"),
                    "expected args rule source, got {rule_source}"
                );
            },
            d => panic!("expected Deny from args phase, got {d:?}"),
        }
    }

    #[tokio::test]
    async fn args_missing_field_is_skipped() {
        // Pipeline references `compensation`, payload doesn't have it →
        // missing-field rule is skipped silently, route allows.
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule(
            "compensation",
            vec![Stage::Type(TypeCheck::Int)],
        ));
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "other_field": 5 }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.args_modified);
    }

    #[tokio::test]
    async fn args_omit_drops_field() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule("secret", vec![Stage::Omit]));
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({ "secret": "xyz", "keep": 1 }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.args_modified);
        assert!(payload.args.get("secret").is_none());
        assert_eq!(payload.args["keep"], json!(1));
    }

    #[tokio::test]
    async fn policy_deny_halts_before_result() {
        let mut route = CompiledRoute::new("ping");
        route
            .pre_invocation
            .push(Effect::from(deny_rule("policy[0]", "blocked")));
        // Result rule should never run.
        route
            .result
            .push(field_rule("ssn", vec![Stage::Redact { condition: None }]));

        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(json!({}), json!({ "ssn": "123" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        match r.decision {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "policy[0]"),
            d => panic!("expected policy deny, got {d:?}"),
        }
        assert!(!r.result_modified);
        // Result payload not mutated — redact didn't run.
        assert_eq!(payload.result.as_ref().unwrap()["ssn"], json!("123"));
    }

    #[tokio::test]
    async fn result_phase_skipped_when_no_response() {
        let mut route = CompiledRoute::new("ping");
        route
            .result
            .push(field_rule("ssn", vec![Stage::Redact { condition: None }]));
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({})); // no result
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.result_modified);
    }

    #[tokio::test]
    async fn result_pipeline_redacts_field() {
        let mut route = CompiledRoute::new("ping");
        route
            .result
            .push(field_rule("ssn", vec![Stage::Redact { condition: None }]));
        let mut bag = AttributeBag::new();
        let mut payload =
            RoutePayload::with_result(json!({}), json!({ "ssn": "123-45-6789", "name": "alice" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.result_modified);
        let result = payload.result.as_ref().unwrap();
        assert_eq!(result["ssn"], json!("[REDACTED]"));
        assert_eq!(result["name"], json!("alice"));
    }

    #[tokio::test]
    async fn taints_accumulate_across_phases() {
        let mut route = CompiledRoute::new("ping");
        // args emits a taint
        route.args.push(field_rule(
            "input",
            vec![Stage::Taint {
                label: "args_seen".into(),
                scopes: vec![TaintScope::Session],
            }],
        ));
        // result emits a different taint
        route.result.push(field_rule(
            "output",
            vec![Stage::Taint {
                label: "result_seen".into(),
                scopes: vec![TaintScope::Message],
            }],
        ));
        let mut bag = AttributeBag::new();
        let mut payload =
            RoutePayload::with_result(json!({ "input": "hello" }), json!({ "output": "world" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        let labels: Vec<&str> = r.taints.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(labels, vec!["args_seen", "result_seen"]);
    }

    #[tokio::test]
    async fn nested_field_path_resolves_and_writes() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule(
            "user.profile.ssn",
            vec![Stage::Mask { keep_last: 4 }],
        ));
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::new(json!({
            "user": { "profile": { "ssn": "123-45-6789", "name": "alice" } }
        }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.args_modified);
        assert_eq!(payload.args["user"]["profile"]["ssn"], json!("*******6789"));
        assert_eq!(payload.args["user"]["profile"]["name"], json!("alice"));
    }

    #[tokio::test]
    async fn nested_field_missing_intermediate_is_skipped() {
        let mut route = CompiledRoute::new("ping");
        route.args.push(field_rule(
            "user.profile.ssn",
            vec![Stage::Mask { keep_last: 4 }],
        ));
        let mut bag = AttributeBag::new();
        // `profile` segment is missing → get_dotted returns None → skip.
        let mut payload = RoutePayload::new(json!({ "user": { "name": "alice" } }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.args_modified);
    }

    #[test]
    fn expand_field_paths_fans_out_over_intermediate_arrays() {
        let v = json!({
            "rows": [ { "ssn": "a" }, { "ssn": "b" }, { "other": 1 } ]
        });
        let mut paths = expand_field_paths(&v, "rows.ssn").expect("within bounds");
        paths.sort();
        assert_eq!(
            paths,
            vec!["rows.0.ssn".to_owned(), "rows.1.ssn".to_owned()]
        );

        assert_eq!(
            expand_field_paths(&v, "rows"),
            Some(vec!["rows".to_owned()])
        );

        let flat = json!({ "a": { "b": 1 } });
        assert_eq!(
            expand_field_paths(&flat, "a.b"),
            Some(vec!["a.b".to_owned()])
        );

        assert_eq!(
            expand_field_paths(&v, "rows.0.ssn"),
            Some(vec!["rows.0.ssn".to_owned()])
        );
    }

    #[test]
    fn expand_field_paths_fails_closed_on_deep_nesting() {
        let mut v = json!({ "leaf": 1 });
        for _ in 0..(super::MAX_FANOUT_DEPTH + 5) {
            v = serde_json::Value::Array(vec![v]);
        }
        let root = json!({ "rows": v });
        assert_eq!(
            expand_field_paths(&root, "rows.leaf"),
            None,
            "deep nesting must fail closed"
        );
    }

    #[test]
    fn expand_field_paths_fails_closed_on_wide_array() {
        let mut rows = Vec::with_capacity(super::MAX_EXPANDED_PATHS + 2);
        for i in 0..(super::MAX_EXPANDED_PATHS + 2) {
            rows.push(json!({ "ssn": i }));
        }
        let root = json!({ "rows": serde_json::Value::Array(rows) });
        assert_eq!(
            expand_field_paths(&root, "rows.ssn"),
            None,
            "a wide array past the leaf cap must fail closed"
        );
    }

    #[test]
    fn dotted_helpers_index_into_arrays() {
        let mut v = json!({ "rows": [ { "ssn": "a" }, { "ssn": "b" } ] });
        assert_eq!(get_dotted(&v, "rows.1.ssn"), Some(&json!("b")));
        assert!(set_dotted(&mut v, "rows.0.ssn", json!("[REDACTED]")));
        assert_eq!(v["rows"][0]["ssn"], json!("[REDACTED]"));
        assert!(remove_dotted(&mut v, "rows.1.ssn"));
        assert!(v["rows"][1].get("ssn").is_none());
    }

    #[tokio::test]
    async fn result_pipeline_redacts_every_array_element() {
        let mut route = CompiledRoute::new("test");
        route.result.push(field_rule(
            "rows.ssn",
            vec![Stage::Redact { condition: None }],
        ));

        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(
            json!({}),
            json!({
                "rows": [
                    { "ssn": "111-11-1111", "name": "a" },
                    { "ssn": "222-22-2222", "name": "b" }
                ]
            }),
        );

        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;

        assert_eq!(r.decision, Decision::Allow);
        assert!(r.result_modified, "the redaction must register");
        let result = payload.result.as_ref().unwrap();
        assert_eq!(result["rows"][0]["ssn"], json!("[REDACTED]"));
        assert_eq!(result["rows"][1]["ssn"], json!("[REDACTED]"));
        assert_eq!(result["rows"][0]["name"], json!("a"));
    }

    #[tokio::test]
    async fn route_result_over_large_fanout_denies() {
        let mut route = CompiledRoute::new("ping");
        route.result.push(field_rule(
            "rows.leaf",
            vec![Stage::Redact { condition: None }],
        ));

        let mut nested = json!({ "leaf": "secret" });
        for _ in 0..(super::MAX_FANOUT_DEPTH + 5) {
            nested = serde_json::Value::Array(vec![nested]);
        }
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(json!({}), json!({ "rows": nested }));

        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        match r.decision {
            Decision::Deny {
                reason,
                rule_source,
            } => {
                let reason = reason.unwrap_or_default();
                assert!(reason.contains("result field"), "reason: {reason}");
                assert!(
                    reason.contains("too many elements to redact safely"),
                    "reason: {reason}"
                );
                assert_eq!(rule_source, "test.rows.leaf");
            },
            other => panic!("over-large result fan-out must deny, got {other:?}"),
        }
        assert!(
            !r.result_modified,
            "nothing may be redacted on a fail-closed deny"
        );
    }

    #[tokio::test]
    async fn post_invocation_runs_after_result() {
        let mut route = CompiledRoute::new("ping");
        // Result mutates a field, then post_invocation denies.
        route
            .result
            .push(field_rule("ssn", vec![Stage::Redact { condition: None }]));
        route.post_invocation.push(Effect::from(deny_rule(
            "post_invocation[0]",
            "after-the-fact",
        )));

        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(json!({}), json!({ "ssn": "123" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        match r.decision {
            Decision::Deny { rule_source, .. } => assert_eq!(rule_source, "post_invocation[0]"),
            d => panic!("expected post_invocation deny, got {d:?}"),
        }
        // Result was still mutated before the post_invocation deny fired.
        assert!(r.result_modified);
        assert_eq!(payload.result.as_ref().unwrap()["ssn"], json!("[REDACTED]"));
    }

    #[test]
    fn dotted_get_simple_and_nested() {
        let v = json!({ "a": { "b": { "c": 7 } } });
        assert_eq!(get_dotted(&v, "a.b.c"), Some(&json!(7)));
        assert_eq!(get_dotted(&v, "a.b"), Some(&json!({ "c": 7 })));
        assert!(get_dotted(&v, "a.b.x").is_none());
        assert!(get_dotted(&v, "missing").is_none());
    }

    #[test]
    fn dotted_set_overwrites_leaf() {
        let mut v = json!({ "a": { "b": 1 } });
        assert!(set_dotted(&mut v, "a.b", json!(99)));
        assert_eq!(v["a"]["b"], json!(99));
    }

    #[test]
    fn dotted_set_does_not_create_missing_parents() {
        // Strict: if `a.b` parent doesn't exist, set fails (no auto-vivify).
        let mut v = json!({});
        assert!(!set_dotted(&mut v, "a.b", json!(1)));
        assert_eq!(v, json!({}));
    }

    #[test]
    fn dotted_remove_leaf() {
        let mut v = json!({ "a": { "b": 1, "c": 2 } });
        assert!(remove_dotted(&mut v, "a.b"));
        assert_eq!(v, json!({ "a": { "c": 2 } }));
        assert!(!remove_dotted(&mut v, "a.b"));
    }

    #[tokio::test]
    async fn evaluate_pre_runs_args_and_policy_only() {
        // Route with both args validators + result transforms. evaluate_pre
        // should run args (mutating payload.args), policy (allow here),
        // but NOT result — payload.result stays exactly as given.
        let mut route = CompiledRoute::new("test");
        route
            .args
            .push(field_rule("id", vec![Stage::Mask { keep_last: 2 }]));
        route
            .result
            .push(field_rule("ssn", vec![Stage::Redact { condition: None }]));

        let mut payload =
            RoutePayload::with_result(json!({ "id": "ABCDEFGH" }), json!({ "ssn": "555-12-3456" }));
        let mut bag = AttributeBag::new();
        let r = evaluate_pre(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(
            r.args_modified,
            "args mask stage should have rewritten the field"
        );
        assert!(!r.result_modified, "evaluate_pre must not touch result");
        // Args was rewritten by mask(2).
        assert_eq!(payload.args["id"], json!("******GH"));
        // Result is untouched — post hasn't run.
        assert_eq!(
            payload.result.as_ref().unwrap()["ssn"],
            json!("555-12-3456")
        );
    }

    #[tokio::test]
    async fn evaluate_post_runs_result_and_post_invocation_only() {
        // Route with args + result. evaluate_post skips args entirely
        // (no mutation), runs result + post_invocation.
        let mut route = CompiledRoute::new("test");
        route
            .args
            .push(field_rule("id", vec![Stage::Mask { keep_last: 2 }]));
        route
            .result
            .push(field_rule("ssn", vec![Stage::Redact { condition: None }]));

        let mut payload =
            RoutePayload::with_result(json!({ "id": "ABCDEFGH" }), json!({ "ssn": "555-12-3456" }));
        let mut bag = AttributeBag::new();
        let r = evaluate_post(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(!r.args_modified, "evaluate_post must not touch args");
        assert!(r.result_modified, "result redact should have fired");
        // Args is untouched by evaluate_post.
        assert_eq!(payload.args["id"], json!("ABCDEFGH"));
        // Result was redacted.
        assert_eq!(payload.result.as_ref().unwrap()["ssn"], json!("[REDACTED]"));
    }

    #[tokio::test]
    async fn evaluate_pre_deny_halts_before_policy() {
        // Args has a type validator that fails → pre denies before policy runs.
        let mut route = CompiledRoute::new("test");
        route
            .args
            .push(field_rule("id", vec![Stage::Type(TypeCheck::Uuid)]));
        // Policy that would always deny if it ran — assert it doesn't.
        route.pre_invocation.push(Effect::from(Rule::single(
            Expression::Always,
            Effect::Deny {
                reason: Some("policy_should_not_run".into()),
                code: None,
            },
            "test.policy[0]",
        )));

        let mut payload = RoutePayload::new(json!({ "id": "not-a-uuid" }));
        let mut bag = AttributeBag::new();
        let r = evaluate_pre(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        match r.decision {
            Decision::Deny { rule_source, .. } => {
                assert!(
                    rule_source.contains("test.id"),
                    "args denial got source {rule_source}"
                );
            },
            d => panic!("expected args-side Deny, got {d:?}"),
        }
    }

    #[tokio::test]
    async fn evaluate_route_skips_post_on_pre_deny() {
        // Wrapper preserves "deny halts before post" — proves the
        // refactor didn't regress evaluate_route's semantics.
        let mut route = CompiledRoute::new("test");
        route.pre_invocation.push(Effect::from(Rule::single(
            Expression::Always,
            Effect::Deny {
                reason: Some("policy_deny".into()),
                code: None,
            },
            "test.policy[0]",
        )));
        route
            .result
            .push(field_rule("ssn", vec![Stage::Redact { condition: None }]));
        route.post_invocation.push(Effect::Taint {
            label: "should_not_emit".into(),
            scopes: vec![TaintScope::Session],
        });

        let mut payload = RoutePayload::with_result(json!({}), json!({ "ssn": "555-12-3456" }));
        let mut bag = AttributeBag::new();
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert!(matches!(r.decision, Decision::Deny { .. }));
        assert!(!r.result_modified, "post must be skipped on pre-side Deny");
        // post_invocation never ran, so its taint never landed.
        assert!(r.taints.is_empty());
        // Result untouched.
        assert_eq!(
            payload.result.as_ref().unwrap()["ssn"],
            json!("555-12-3456")
        );
    }

    // ---- the result pipeline's remaining outcomes --------------------------
    //
    // The args phase covers Replace, Omit and Deny; the result phase only had
    // Replace. That asymmetry matters because the result phase is what runs on
    // data coming back from a tool, which is where an exfiltration control would
    // sit. Each outcome is checked to reach the payload, not just the decision.

    /// `omit` removes the key outright rather than blanking it. A reader of the
    /// response has to be unable to tell the field was ever there.
    #[tokio::test]
    async fn result_pipeline_omit_removes_the_key() {
        let mut route = CompiledRoute::new("ping");
        route.result.push(field_rule("ssn", vec![Stage::Omit]));
        let mut bag = AttributeBag::new();
        let mut payload =
            RoutePayload::with_result(json!({}), json!({ "ssn": "123-45-6789", "name": "alice" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(r.result_modified);
        let result = payload.result.as_ref().unwrap();
        assert!(
            result.get("ssn").is_none(),
            "omit must remove the key, not blank it: {result}"
        );
        assert_eq!(result["name"], json!("alice"), "siblings are untouched");
    }

    /// A result-pipeline deny turns an otherwise-allowed call into a denial after
    /// the tool has already run. The decision has to carry the rule source, since
    /// that is what an operator reads to find which rule fired.
    #[tokio::test]
    async fn result_pipeline_deny_fails_the_call_and_names_the_rule() {
        let mut route = CompiledRoute::new("ping");
        route.result.push(field_rule(
            "ssn",
            vec![Stage::Length {
                min: Some(1),
                max: Some(3),
            }],
        ));
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(json!({}), json!({ "ssn": "123-45-6789" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        match r.decision {
            Decision::Deny {
                reason,
                rule_source,
            } => {
                assert!(
                    reason.unwrap_or_default().contains("length"),
                    "the reason must say what failed"
                );
                assert_eq!(rule_source, "test.ssn", "and which rule it was");
            },
            other => panic!("expected a Deny from the result pipeline, got {other:?}"),
        }
        assert!(
            r.constraints.is_empty(),
            "a result deny short-circuits before restrict, so no constraints"
        );
    }

    /// A rule naming a field the result does not carry is skipped, not an error.
    /// Denying on absence would break every route whose tool returns an optional
    /// field.
    #[tokio::test]
    async fn a_result_rule_for_an_absent_field_is_skipped() {
        let mut route = CompiledRoute::new("ping");
        route.result.push(field_rule(
            "missing",
            vec![Stage::Redact { condition: None }],
        ));
        let mut bag = AttributeBag::new();
        let mut payload = RoutePayload::with_result(json!({}), json!({ "name": "alice" }));
        let r = evaluate_route(
            &route,
            &mut bag,
            &mut payload,
            &pdp_arc(),
            &plugins(),
            &delegations(),
            &elicitations(),
        )
        .await;
        assert_eq!(r.decision, Decision::Allow);
        assert!(
            !r.result_modified,
            "nothing matched, so nothing was rewritten"
        );
    }

    // ---- dotted-path helpers ----------------------------------------------

    /// `set_dotted` and `remove_dotted` are how a pipeline reaches a nested
    /// field. Both report whether they changed anything, and that boolean is what
    /// sets `result_modified`, so a wrong answer there misreports the response as
    /// untouched.
    #[test]
    fn dotted_helpers_reach_nested_fields_and_report_whether_they_changed_it() {
        let mut v = json!({ "outer": { "inner": "old" }, "flat": 1 });
        assert!(set_dotted(&mut v, "outer.inner", json!("new")));
        assert_eq!(v["outer"]["inner"], json!("new"));
        assert!(remove_dotted(&mut v, "outer.inner"));
        assert!(v["outer"].get("inner").is_none());
    }

    #[test]
    fn dotted_helpers_decline_paths_that_do_not_exist() {
        let mut v = json!({ "flat": 1 });
        assert!(
            !set_dotted(&mut v, "nope.inner", json!("x")),
            "a missing parent is not created"
        );
        assert!(
            !remove_dotted(&mut v, "nope.inner"),
            "removing through a missing parent reports no change"
        );
        assert!(
            !remove_dotted(&mut v, "flat.inner"),
            "a scalar parent cannot be traversed"
        );
        assert!(
            !set_dotted(&mut v, "flat.inner", json!("x")),
            "nor written through"
        );
    }
}
