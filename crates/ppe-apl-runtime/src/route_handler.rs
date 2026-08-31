// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `AplRouteHandler` — synthetic plugin that drives APL evaluation when
// praxis-policy-core's `filter_entries_by_route` matches an annotated route. Each
// instance is bound to ONE phase (Pre or Post) so the unified-config
// `cmf.tool_pre_invoke` and `cmf.tool_post_invoke` hooks can carry
// distinct handler logic without an in-handler hook-name discriminator.
//
// # Why a phase-bound handler
//
// The PPE engine's annotation table is keyed on
// `(entity_type, entity_name, scope, hook_name)`. The visitor registers
// one handler per route per phase; the engine picks the right one based
// on the dispatching hook name. Inside `invoke`, no hook-name plumbing is
// needed — the handler already knows which phase it's running.
//
// # Why the family is fixed at install too
//
// The route's entity type decides which hook family its handler is
// annotated under, and the family decides the payload the executor hands
// it: a CMF message for the MCP and A2A entities, `HttpPayload` for
// generic HTTP. So the family is recorded at install alongside the phase,
// and it selects both the payload `invoke` accepts and the typed invoker
// the request's plugins are dispatched through.
//
// # Lifetime / weak engine handle
//
// The handler holds `Weak<PolicyEngine>` because the engine owns the
// snapshot that owns the annotation that owns the handler — a strong
// reference would create a cycle. Each `invoke` upgrades to `Arc` for
// the duration of the call. If the upgrade fails (engine has been
// dropped) the call returns a configuration error.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use serde_json::Value;

use praxis_policy_core::cmf::constants::{
    ENTITY_HTTP, ENTITY_LLM, ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL,
};
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::executor::ErasedResultFields;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::hooks::PluginPayload;
use praxis_policy_core::hooks::trait_def::HookTypeDef;
use praxis_policy_core::http_hook::HttpHook;
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::AnyHookHandler;

use praxis_policy_apl_cmf::constants::{DETAIL_HTTP_BODY, DETAIL_HTTP_HEADERS, DETAIL_HTTP_STATUS};
use praxis_policy_apl_cmf::{BagBuilder, extract_args, extract_result};
use praxis_policy_apl_core::AttributeTree;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::plugin_decl::PluginRegistry;

use crate::candidate_constraint::fold_candidate_constraints;
use praxis_policy_apl_core::route::{RoutePayload, evaluate_post, evaluate_pre};
use praxis_policy_apl_core::rules::{CompiledRoute, DenyResponse};
use praxis_policy_apl_core::step::PdpResolver;

use crate::cmf_invoker::HookPluginInvoker;
use crate::delegation_invoker::DelegationPluginInvoker;
use crate::dispatch_plan::DispatchCache;
use crate::elicitation_invoker::ElicitationPluginInvoker;
use crate::message_projection::{
    apply_changed_paths, extract_args_from_message, extract_result_from_message,
    write_args_back_to_message, write_result_back_to_message,
};
use crate::payload_fields::PayloadFields;
use crate::pdp_router::PdpRouter;
use crate::session_store::SessionStore;

/// JSON-RPC error code the host emits when a phase suspends on a pending
/// elicitation: "request not complete — retry echoing the elicitation id."
/// In the application-reserved JSON-RPC range; carried via
/// `PluginViolation::proto_error_code` for the host to put on the wire.
/// The agent SDK keys its pause/resume loop on this code.
pub const ELICITATION_PENDING_CODE: i64 = -32120;

/// Header an agent echoes on retry to continue a suspended elicitation —
/// its value is the `elicitation_id` from a prior `-32120`. The handler
/// seeds it into the bag (`elicitation.id`) before evaluation so the
/// runtime *checks* the existing elicitation instead of dispatching a new
/// one. Mirrors how `X-User-Token` carries request-scoped context.
pub const ELICITATION_ID_HEADER: &str = "X-Policy-Elicitation-Id";

/// JSON-RPC error code emitted when an agent re-checks an approval in
/// *peek* mode and it has resolved approved: "approved — confirm to apply."
/// The phase does NOT forward to the tool; the agent confirms with the
/// requester and re-sends *without* the peek header to actually run it.
/// Lets a human authorize while the requester separately commits execution.
pub const ELICITATION_APPROVED_CODE: i64 = -32121;

/// Header an agent sets (alongside `X-Policy-Elicitation-Id`) to *peek* at an
/// approval — resolve its status without committing the action. Truthy
/// value ("1"/"true"/anything non-empty) enables it.
pub const ELICITATION_PEEK_HEADER: &str = "X-Policy-Elicitation-Peek";

/// Which APL phase this handler runs. Pre covers `args` + `pre_invocation`; Post
/// covers `result` + `post_invocation`. Set once at construction and never
/// changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Before the call, addressing arguments.
    Pre,
    /// After the call, addressing the result.
    Post,
}

/// Which hook family this handler was installed for, and so which payload
/// the executor hands it. One handler type serves both families, so the
/// answer is fixed at install from the route's entity type rather than
/// discovered per request.
///
/// `#[non_exhaustive]`: a third family is a payload shape this crate does
/// not yet hand out, and adding one must not silently fall into a
/// downstream `match` arm written for two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HookFamily {
    /// The CMF family, carrying a chat message.
    Cmf,
    /// The generic-HTTP family, whose payload carries no fields.
    Http,
}

impl HookFamily {
    /// The family a route's entity type belongs to, or `None` for an entity
    /// type with no family. The mapped entity types other than `http` name
    /// MCP or A2A entities carrying a CMF message.
    ///
    /// The mapped set is the same one [`crate::visitor::hook_pair_for_entity`]
    /// covers, so a new entity type is unmapped in both places and the visitor
    /// logs and skips rather than installing a handler on a guessed payload.
    pub fn for_entity(entity_type: &str) -> Option<Self> {
        match entity_type {
            ENTITY_HTTP => Some(Self::Http),
            ENTITY_TOOL | ENTITY_LLM | ENTITY_PROMPT | ENTITY_RESOURCE => Some(Self::Cmf),
            _ => None,
        }
    }

    /// The registered hook type's name, read off the type so this cannot
    /// drift from what the executor sees on the handler.
    pub fn hook_type_name(self) -> &'static str {
        match self {
            Self::Cmf => CmfHook::NAME,
            Self::Http => HttpHook::NAME,
        }
    }
}

/// Synthetic plugin that drives APL evaluation for one route + one phase.
///
/// Implements `Plugin` (so praxis-policy-core treats it like any other plugin —
/// `mode/capabilities/on_error` come from the `PluginConfig` the visitor
/// supplied at `annotate_route` time) and `AnyHookHandler` (so the
/// executor dispatches into it through the normal type-erased path).
pub struct AplRouteHandler {
    config: PluginConfig,
    route: Arc<CompiledRoute>,
    phase: Phase,
    /// The hook family this handler dispatches. Decides which payload
    /// `invoke` expects and which typed invoker a request builds.
    family: HookFamily,
    plugin_registry: Arc<PluginRegistry>,
    dispatch_cache: Arc<DispatchCache>,
    session_store: Arc<dyn SessionStore>,
    /// Weak handle to the engine so we can resolve plugin entries +
    /// dispatch into them by-name. `Weak` avoids the
    /// engine↔snapshot↔annotation↔handler cycle.
    engine: Weak<PolicyEngine>,
    /// PDP resolver. APL routes that don't use `pdp(...)` steps never
    /// touch this. Default is an empty [`PdpRouter`] — any `pdp(...)`
    /// step against an unregistered dialect returns
    /// `PdpError::NoResolver`. Hosts that need Cedar, OPA, `NeMo`, etc.
    /// install resolvers via [`Self::with_pdp`].
    pdp: Arc<dyn PdpResolver>,
    /// Static `data.*` attribute tree, flattened into every request's
    /// bag. Shared `Arc` (the visitor hands the same tree to every
    /// handler); empty by default when no source was configured.
    attribute_tree: Arc<AttributeTree>,
}

impl AplRouteHandler {
    /// Build a handler. Visitor calls this twice per route — once for
    /// each phase — and passes the resulting `Arc` to `annotate_route`.
    ///
    /// `family` comes from the route's entity type via
    /// [`HookFamily::for_entity`] and decides which payload the handler
    /// accepts, so it has to agree with the hook name the handler is
    /// annotated under. An entity type that maps to no family gets no
    /// handler at all.
    pub fn new(
        config: PluginConfig,
        route: Arc<CompiledRoute>,
        phase: Phase,
        family: HookFamily,
        plugin_registry: Arc<PluginRegistry>,
        dispatch_cache: Arc<DispatchCache>,
        session_store: Arc<dyn SessionStore>,
        engine: Weak<PolicyEngine>,
    ) -> Self {
        Self {
            config,
            route,
            phase,
            family,
            plugin_registry,
            dispatch_cache,
            session_store,
            engine,
            pdp: Arc::new(PdpRouter::new()),
            attribute_tree: Arc::new(praxis_policy_apl_core::AttributeTree::empty()),
        }
    }

    /// Install the static `data.*` attribute tree flattened into every
    /// request's bag. Defaults to empty; the visitor sets it from the
    /// configured [`AttributeSource`](praxis_policy_apl_core::AttributeSource).
    pub fn with_attribute_tree(mut self, tree: Arc<AttributeTree>) -> Self {
        self.attribute_tree = tree;
        self
    }

    /// Install a `PdpResolver`. Pass a [`PdpRouter`] when the host needs
    /// to support multiple dialects (Cedar + OPA + `NeMo`) on the same
    /// route — the router dispatches each `pdp(...)` step by dialect.
    /// Pass a single resolver when only one dialect is in use; APL
    /// steps for any other dialect will then return
    /// `PdpError::NoResolver` at evaluation time.
    pub fn with_pdp(mut self, pdp: Arc<dyn PdpResolver>) -> Self {
        self.pdp = pdp;
        self
    }
}

#[async_trait]
impl Plugin for AplRouteHandler {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

#[async_trait]
impl AnyHookHandler for AplRouteHandler {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        // The route's entity type decided the family at install, and the
        // family decides the payload. Two monomorphizations of the same
        // evaluation, one trait object out of each.
        match self.family {
            HookFamily::Cmf => self.evaluate::<CmfHook>(payload, extensions).await,
            HookFamily::Http => self.evaluate::<HttpHook>(payload, extensions).await,
        }
    }

    fn hook_type_name(&self) -> &'static str {
        self.family.hook_type_name()
    }
}

impl AplRouteHandler {
    /// Evaluate this route for one invocation of hook family `H`.
    ///
    /// Generic so the plugins a policy step names are dispatched through
    /// `H`, which is what hands an HTTP route's plugins an `HttpPayload`
    /// instead of a chat message nothing filled. The message-shaped work
    /// (projecting `args:` / `result:`, folding a pipeline's edits back) is
    /// gated on the payload actually being a message, which an HTTP route
    /// is not and cannot become: a field stage on one is refused at load.
    async fn evaluate<H: HookTypeDef>(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>>
    where
        H::Payload: PayloadFields,
    {
        // The executor resolves the handler off the hook name, and the
        // family this handler was installed for fixes the payload that name
        // carries. A mismatch indicates a framework wiring bug.
        let typed_payload = payload
            .as_any()
            .downcast_ref::<H::Payload>()
            .ok_or_else(|| {
                Box::new(PluginError::Config {
                    message: format!(
                        "AplRouteHandler '{}': the '{}' family expects {}, \
                         which is not what this invocation carried",
                        self.route.route_key,
                        H::NAME,
                        std::any::type_name::<H::Payload>(),
                    ),
                })
            })?;

        // The message a field pipeline addresses, when this family carries
        // one. `None` for a payload with no fields, which is what makes
        // every projection and write-back below a no-op there.
        let message: Option<&Message> = typed_payload
            .as_any()
            .downcast_ref::<MessagePayload>()
            .map(|msg| &msg.message);

        let engine = self.engine.upgrade().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "AplRouteHandler '{}': PolicyEngine dropped before invoke",
                    self.route.route_key
                ),
            })
        })?;

        // Build (or reuse) the dispatch plan for this route. Cache keyed
        // by `(route_key, engine.config_generation())` — if the engine
        // has reloaded since the last invoke, the next lookup rebuilds.
        let plan = self
            .dispatch_cache
            .get_or_build(&self.route, &self.plugin_registry, &engine)
            .await;

        // The invoker carries the request-scoped payload + extensions
        // under interior mutability so successive plugin calls accumulate
        // mutations. It is bound to `H`, so the plugins a policy step names
        // are dispatched through this route's own family.
        // Hydration + persistence are no-ops when there's no
        // session id (the common case for the first request in a session).
        // Wrapped in Arc so it can be erased to `Arc<dyn PluginInvoker>`
        // for the praxis-policy-apl-core entry points (which take `&Arc<dyn PluginInvoker>`
        // so `dispatch_parallel` can clone an owned, 'static reference into
        // each spawned branch). Inherent-method calls on the invoker
        // (e.g. `extensions_arc`, `persist_session`) deref through the Arc.
        // Hydration loads accumulated session labels. A store failure
        // here happens *before* any policy decision, so we fail the
        // request closed immediately: deny with a
        // distinguished violation rather than proceeding as if the
        // session carried no taint. Sessionless traffic never reaches
        // the store, so this only denies session-bearing requests.
        let invoker = match HookPluginInvoker::<H>::for_request(
            Arc::clone(&engine),
            extensions.clone(),
            typed_payload.clone(),
            plan,
            Arc::clone(&self.session_store),
        )
        .await
        {
            Ok(inv) => Arc::new(inv),
            Err(e) => {
                tracing::error!(
                    alarm = "session_store_failure",
                    op = "load",
                    route = %self.route.route_key,
                    error = %e,
                    "session label load failed; failing request closed"
                );
                let mut v = PluginViolation::new(
                    "session.load_failed",
                    "session state could not be loaded",
                );
                decorate_denial_response(&mut v, self.route.response.as_ref());
                return Ok(Box::new(ErasedResultFields {
                    continue_processing: false,
                    modified_payload: None,
                    modified_extensions: None,
                    violation: Some(v),
                }));
            },
        };

        // Build the attribute bag. APL predicates read flat keys; the
        // BagBuilder bridges typed PPE extensions into that namespace.
        // `route.key` lets default/policy-bundle predicates branch on
        // which route they're attached to.
        let post_extensions = invoker.current_extensions().await;
        let mut bag = BagBuilder::new()
            .with_extensions(&post_extensions)
            .with_route_key(&self.route.route_key)
            .with_data(&self.attribute_tree)
            .build();

        // Retry seeding: if the agent echoed an elicitation id (from
        // a prior `-32120`) in the `X-Policy-Elicitation-Id` header, seed it
        // into the bag *before* evaluation. `dispatch_elicitation` then takes
        // the "id present → check" path (poll the existing approval) instead
        // of dispatching a fresh one. Without this, every retry would open a
        // new approval and the loop would never resolve.
        if let Some(elicitation_id) = elicitation_id_from_headers(&post_extensions) {
            bag.set(
                praxis_policy_apl_core::step::elicitation_bag_keys::ID,
                elicitation_id,
            );
        }

        // Build `RoutePayload.args` from the message. Per-content shape:
        //   * ToolCall      → arguments map (JSON Object)
        //   * PromptRequest → arguments map (JSON Object)
        //   * Text-only     → JSON String of concatenated text content
        //
        // Field pipelines operate on `args.<name>` paths. Result starts
        // as Null on Pre (no upstream response yet); the Post phase
        // would extract from a ToolResult / PromptResult — deferred
        // until result-side handling lands.
        //
        // A payload carrying no message projects `Null` on both sides. That
        // is the whole of what a field stage could read there, and a field
        // stage on such a route is refused at load rather than left to read
        // it.
        let args_value = message.map_or(Value::Null, extract_args_from_message);
        let mut route_payload = match self.phase {
            Phase::Pre => RoutePayload::new(args_value),
            Phase::Post => {
                // Pull the upstream result out of the message so APL
                // `result.<field>` predicates and the `result:`
                // pipeline have something to operate on. Falls back to
                // `Value::Null` when the message has no ToolResult /
                // PromptResult / Resource content (e.g. for hooks that
                // fire on entities without a structured result).
                let result_value = message.map_or(Value::Null, extract_result_from_message);
                RoutePayload::with_result(args_value, result_value)
            },
        };

        // Flatten the call args into the bag under `args.<path>`. APL's
        // own args pipelines read from `route_payload.args` directly,
        // but PDP steps and predicates that reference `${args.X}` /
        // `args.X` resolve through the bag. Mirroring the args here
        // makes both consumers see the same vocabulary the
        // `MessageView` exposes. (Bag-mutation via redact during the
        // args pipeline isn't reflected back into the bag; that's fine
        // — args predicates today read from `route_payload.args`, and
        // the cedar substitution snapshots the pre-args view, which is
        // what an author writing `cedar:(resource.id: ${args.X})` would
        // expect.)
        extract_args(&route_payload.args, &mut bag);
        // Post phase: also project the upstream result into the bag
        // under `result.<path>`. This is what enables predicates like
        // `redact(result.ssn) when !perm.view_ssn` and `require(...)`
        // gates that branch on the result. Pre phases skip this — the
        // result is `None` by construction.
        if matches!(self.phase, Phase::Post)
            && let Some(result_value) = route_payload.result.as_ref()
        {
            extract_result(result_value, &mut bag);
        }

        // Real delegation invoker, sharing the CMF invoker's
        // extensions Mutex so a `delegate(...)` step's writes to
        // raw_credentials / delegation are visible to downstream CMF
        // plugins and to the post phase. Routes that don't declare
        // any `Step::Delegate` won't have entries in the plan's
        // `delegation_entries` map; if such a route accidentally hits
        // `delegate(...)`, the invoker returns `NotFound` and the
        // evaluator translates it via the step's `on_error`.
        let delegations = Arc::new(DelegationPluginInvoker::new(
            Arc::clone(&engine),
            invoker.extensions_arc(),
            invoker.plan_arc(),
        ));

        // Unsized coercion: `Arc<ConcreteType>` → `Arc<dyn Trait>`. The
        // erased forms get borrowed into `evaluate_pre`/`evaluate_post`;
        // `dispatch_parallel` can then `Arc::clone` an owned 'static
        // reference into each branch closure.
        // Elicitation bridge — resolves `require_approval(...)` /
        // `confirm(...)` steps to `ElicitationHook` plugins by name off
        // the same plan, sharing the request's Extensions so the handler
        // reads the same identity. Routes with no elicitation steps have
        // an empty `elicitation_entries` map; an accidental `Effect::Elicit`
        // then returns `NotFound`, handled by the step's `on_error`.
        let elicitations = Arc::new(ElicitationPluginInvoker::new(
            Arc::clone(&engine),
            invoker.extensions_arc(),
            invoker.plan_arc(),
        ));

        let invoker_dyn: Arc<dyn praxis_policy_apl_core::step::PluginInvoker> = invoker.clone();
        let delegations_dyn: Arc<dyn praxis_policy_apl_core::step::DelegationInvoker> =
            delegations.clone();
        let elicitations_dyn: Arc<dyn praxis_policy_apl_core::step::ElicitationInvoker> =
            elicitations.clone();

        let decision = match self.phase {
            Phase::Pre => {
                evaluate_pre(
                    &self.route,
                    &mut bag,
                    &mut route_payload,
                    &self.pdp,
                    &invoker_dyn,
                    &delegations_dyn,
                    &elicitations_dyn,
                )
                .await
            },
            Phase::Post => {
                evaluate_post(
                    &self.route,
                    &mut bag,
                    &mut route_payload,
                    &self.pdp,
                    &invoker_dyn,
                    &delegations_dyn,
                    &elicitations_dyn,
                )
                .await
            },
        };

        // Drain Session-scoped taints (from `taint(label, session)` /
        // pipeline `Stage::Taint`) into `extensions.security.labels`
        // so the existing label-diff flow inside `persist_session`
        // picks them up. Message-scoped taints are filtered out by
        // `apply_session_taints` — they need their own destination.
        // No-op when no taints emitted.
        invoker.apply_session_taints(&decision.taints).await;

        // Fold this request's `restrict` constraints into one typed
        // `CandidateConstraintExtension`. A custom-label contradiction
        // (two restricts requiring the same label to differ) cannot be
        // honored by any backend, so it fails closed below (mirrors the
        // persist-failure handling). `Ok(None)` = no restrict fired.
        let (folded_constraint, constraint_conflict) =
            match fold_candidate_constraints(&decision.constraints) {
                Ok(folded) => (folded, None),
                Err(e) => (None, Some(e)),
            };

        // Commit any session-scoped labels accumulated during this
        // request. No-op when there was no session id. The result is
        // folded into the decision below — captured here because
        // `continue_processing`/`violation` are computed after persist.
        let persist_result = invoker.persist_session().await;

        // Surface the final mutated payload + extensions back into the
        // PipelineResult the executor returns to the host. The host's
        // body re-serialization picks up edits made by APL pipelines
        // (e.g. a redact stage that rewrote args.text).
        let final_payload = invoker.current_payload().await;
        let final_extensions = invoker.current_extensions().await;

        // The pre-evaluation projections. No longer used to *detect*
        // pipeline edits (the decision reports those) — they're the
        // baseline for folding those edits back in below, which needs to
        // know which paths the pipeline touched.
        //
        // Each side is projected only in the phase that can edit it:
        // `evaluate_pre` never sets `result_modified` and `evaluate_post`
        // never sets `args_modified`, so the other projection would be
        // unread work on every request.
        let pre_args = match self.phase {
            Phase::Pre => message.map(extract_args_from_message),
            Phase::Post => None,
        };
        let pre_result = match self.phase {
            Phase::Pre => None,
            Phase::Post => message.map(extract_result_from_message),
        };
        // Which of the three sources changed the payload, in precedence
        // order. Each condition is a signal from the code that performed
        // the change: the decision's flags are set when a pipeline's
        // `set_dotted` / `remove_dotted` actually writes, and the
        // invoker's flag is set when a plugin's payload is accepted.
        // Nothing here infers a change by comparing values.
        let modified_payload: Option<Box<dyn PluginPayload>> = if decision.args_modified {
            // An args pipeline (Pre) rewrote a field. Fold the new
            // args back into a fresh MessagePayload so downstream
            // readers (the host's body re-serializer) see the
            // change.
            //
            // Only the paths the pipeline touched are applied. A plugin
            // may have rewritten other arguments on the same tool call,
            // and those edits aren't in `route_payload.args` (it was
            // projected before any plugin ran), so writing it wholesale
            // would silently drop them.
            //
            // Without a pre-projection there is no way to tell which
            // paths the pipeline changed, so write nothing rather than
            // fold in an unattributable diff — a wholesale write is
            // exactly the clobbering this merge exists to prevent. Only
            // the Pre phase sets `args_modified`, and only the Pre phase
            // projects `pre_args`, so this holds by construction.
            //
            // The fold is message-shaped, so it is gated on the payload
            // being one. `pre_args` is already `None` for a payload that
            // carries no message, and a route on such a family cannot
            // declare the `args:` stage that sets this flag, so the gate
            // never has anything to skip.
            let mut updated = final_payload.clone();
            if let Some(pre) = pre_args.as_ref()
                && let Some(target) = updated.as_any_mut().downcast_mut::<MessagePayload>()
            {
                let mut merged = extract_args_from_message(&target.message);
                apply_changed_paths(&mut merged, pre, &route_payload.args);
                write_args_back_to_message(&mut target.message, &merged);
            }
            Some::<Box<dyn PluginPayload>>(Box::new(updated))
        } else if decision.result_modified {
            // A `result:` pipeline rewrote a field in the upstream
            // response. Fold the new result back into the message
            // so the host's response body re-serializer can write
            // it out before forwarding downstream. Only the Post phase
            // can set this — a Pre route has no result to rewrite.
            //
            // Same per-path merge as the args branch above, for the same
            // reason: a plugin may have redacted a different part of the
            // same tool result.
            // Same "no pre-projection, no write" rule as the args branch
            // above, and the same message gate for the same reason.
            let mut updated = final_payload.clone();
            if let (Some(result_value), Some(pre)) =
                (route_payload.result.as_ref(), pre_result.as_ref())
                && let Some(target) = updated.as_any_mut().downcast_mut::<MessagePayload>()
            {
                let mut merged = extract_result_from_message(&target.message);
                apply_changed_paths(&mut merged, pre, result_value);
                write_result_back_to_message(&mut target.message, &merged);
            }
            Some::<Box<dyn PluginPayload>>(Box::new(updated))
        } else if invoker.payload_was_modified() {
            // A plugin mutated the message directly via `modify_payload`
            // (not through a field pipeline). Pass the invoker's view
            // through unchanged.
            //
            // The invoker records this when it accepts the mutation,
            // which is the only point it can be known. Comparing message
            // content here instead would read text parts only, so a
            // redacted tool result, a rewritten tool call, or an edited
            // thinking block would look identical to no mutation and get
            // dropped.
            tracing::debug!(
                route = %self.route.route_key,
                "plugin mutated the payload directly; forwarding the mutated view"
            );
            Some::<Box<dyn PluginPayload>>(Box::new(final_payload))
        } else {
            None
        };

        let mut modified_extensions =
            extensions_changed(extensions, &final_extensions).then(|| final_extensions.cow_copy());

        // Write the folded constraint into the typed
        // `candidate_constraint` extension slot so the host router reads
        // it TYPED off `PipelineResult.modified_extensions` — the same
        // in-process, type-shared channel `raw_credentials.delegated_tokens`
        // rides. `extensions_changed` doesn't track this
        // slot, so we force `modified_extensions` to `Some` here to
        // guarantee the constraint reaches the executor's merge.
        if let Some(constraint) = folded_constraint {
            let mut owned = modified_extensions
                .take()
                .unwrap_or_else(|| final_extensions.cow_copy());
            owned.candidate_constraint = Some(constraint);
            modified_extensions = Some(owned);
        }

        // A suspended phase reports `Allow` with a pending bundle — it
        // must NOT forward. Fail closed with a distinguished violation that
        // carries the elicitation id (mapped to JSON-RPC `-32120`) so the
        // suspend is visible and the unapproved call never proceeds.
        let pending_elicitation = decision.pending.clone();

        // Attach the route's transpiled `denyWith` to a violation at each
        // genuine-denial site (below) via `decorate_denial_response`, rather
        // than blanket-decorating whatever `violation` is set. This keeps the
        // custom response off any future non-denial signal (e.g. an
        // elicitation/retry/confirm violation) that must reach the host with
        // its own wire shape intact.
        let (mut continue_processing, mut violation) = match decision.decision {
            Decision::Allow => (true, None),
            Decision::Deny {
                reason,
                rule_source,
            } => {
                let code = if rule_source.is_empty() {
                    "policy.deny".to_owned()
                } else {
                    rule_source
                };
                let reason = reason.unwrap_or_else(|| "access denied".to_owned());
                let mut v = PluginViolation::new(code, reason);
                decorate_denial_response(&mut v, self.route.response.as_ref());
                (false, Some(v))
            },
        };

        if let Some(p) = &pending_elicitation {
            tracing::info!(
                route = %self.route.route_key,
                elicitation_id = %p.id,
                plugin = %p.plugin_name,
                "policy suspended on pending elicitation; emitting -32120 (retry)"
            );
            // The phase suspended awaiting a human. Do NOT forward. Surface
            // a structured "request not complete — retry echoing this id"
            // via the protocol error code the host maps to the wire
            // (JSON-RPC `-32120`). Left undecorated by `denyWith` — it is a
            // retry signal, not a denial.
            continue_processing = false;
            violation = Some(pending_violation(p));
        }

        // Peek (confirm-then-apply): the agent re-checked an approval but
        // asked NOT to commit yet (the `X-Policy-Elicitation-Peek` header). If
        // the elicitation resolved approved (Allow, not pending), report
        // "approved — confirm to apply" (-32121) and do NOT forward. The
        // agent then asks the requester, who re-sends without the peek header
        // to actually run the tool (the plugin replays the cached approval).
        if continue_processing
            && elicitation_peek_from_headers(&post_extensions)
            && bag.get_string(praxis_policy_apl_core::step::elicitation_bag_keys::OUTCOME)
                == Some("approved")
        {
            continue_processing = false;
            violation = Some(approved_peek_violation(&bag));
        }

        // Append fail-closed with merge precedence:
        //   - decision Allow + append Err → flip to Deny with a
        //     distinguished `session.persist_failed` violation.
        //   - decision Deny + append Err → keep the original policy
        //     violation (preserve attribution); the request is already
        //     denied. The append failure surfaces only as the alarm.
        // The alarm/metric fires on every append failure regardless of
        // decision, since the dangerous residual is a *selective*
        // failure (append rejected while reads still succeed).
        if let Err(e) = persist_result {
            tracing::error!(
                alarm = "session_store_failure",
                op = "append",
                route = %self.route.route_key,
                decision_was_allow = continue_processing,
                error = %e,
                "session label persist failed; failing request closed"
            );
            if continue_processing {
                continue_processing = false;
                let mut v = PluginViolation::new(
                    "session.persist_failed",
                    "session state could not be persisted",
                );
                decorate_denial_response(&mut v, self.route.response.as_ref());
                violation = Some(v);
            }
        }

        // Fail closed: a `restrict` custom-label contradiction means no
        // backend can satisfy the request's routing constraints. Deny
        // rather than emit an unhonorable constraint. On an already-denied
        // request, keep the original policy attribution (same precedence
        // as the persist-failure block above).
        if let Some(conflict) = constraint_conflict {
            tracing::warn!(
                route = %self.route.route_key,
                error = %conflict,
                "restrict constraints conflict; failing request closed"
            );
            if continue_processing {
                continue_processing = false;
                violation = Some(PluginViolation::new(
                    "policy.restrict_conflict",
                    conflict.to_string(),
                ));
            }
        }

        Ok(Box::new(ErasedResultFields {
            continue_processing,
            modified_payload,
            modified_extensions,
            violation,
        }))
    }
}

/// Attach a route's transpiled `denyWith` (status/body/headers) to a
/// denial `violation`'s `details` map so the host can render a custom HTTP
/// denial response. Carried via `details` (not new violation fields) to
/// keep the violation type stable. `None` response leaves the host default.
///
/// Call this only from genuine-denial sites — never blanket-apply it to
/// whatever violation happens to be set, or a non-denial signal (e.g. an
/// elicitation/retry/confirm) would get stamped with a `403`-shaped
/// response the host would render instead of the intended wire signal.
fn decorate_denial_response(violation: &mut PluginViolation, response: Option<&DenyResponse>) {
    let Some(resp) = response else {
        return;
    };
    if let Some(status) = resp.status {
        violation
            .details
            .insert(DETAIL_HTTP_STATUS.to_owned(), serde_json::json!(status));
    }
    if let Some(body) = &resp.body {
        violation
            .details
            .insert(DETAIL_HTTP_BODY.to_owned(), serde_json::json!(body));
    }
    if !resp.headers.is_empty() {
        violation.details.insert(
            DETAIL_HTTP_HEADERS.to_owned(),
            serde_json::json!(resp.headers),
        );
    }
}

/// Cheap pointer-equality check across the few mutable extension slots
/// the executor would care about. False positives (claiming a change
/// when there isn't one) are cheap — the executor re-validates anyway.
fn extensions_changed(before: &Extensions, after: &Extensions) -> bool {
    let security_changed = match (before.security.as_ref(), after.security.as_ref()) {
        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
        (None, None) => false,
        _ => true,
    };
    let delegation_changed = match (before.delegation.as_ref(), after.delegation.as_ref()) {
        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
        (None, None) => false,
        _ => true,
    };
    // `delegate(...)` steps write minted tokens into
    // `raw_credentials.delegated_tokens` via the shared Mutex —
    // without this check, a route whose only Extensions mutation is
    // a delegate (no security / delegation chain edit) looks
    // unchanged, so the executor never merges the minted token back
    // and downstream readers (our HttpFilter attaching the token to
    // the upstream request) see nothing.
    let raw_creds_changed = match (
        before.raw_credentials.as_ref(),
        after.raw_credentials.as_ref(),
    ) {
        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
        (None, None) => false,
        _ => true,
    };
    security_changed || delegation_changed || raw_creds_changed
}

/// Extract the elicitation id an agent echoes on retry from the
/// `X-Policy-Elicitation-Id` request header. `None` when absent/empty.
/// Pure so it's unit-testable without the full handler path.
fn elicitation_id_from_headers(ext: &Extensions) -> Option<String> {
    ext.http
        .as_ref()
        .and_then(|h| h.get_request_header(ELICITATION_ID_HEADER))
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// True when the agent set `X-Policy-Elicitation-Peek` to a truthy value —
/// it wants to resolve the approval's status without committing the action.
fn elicitation_peek_from_headers(ext: &Extensions) -> bool {
    ext.http
        .as_ref()
        .and_then(|h| h.get_request_header(ELICITATION_PEEK_HEADER))
        .is_some_and(|v| !v.is_empty() && !v.eq_ignore_ascii_case("false") && v != "0")
}

/// Build the `-32121` "approved — confirm to apply" violation for a peek
/// that resolved approved. Carries the elicitation id + approver in
/// `details` so the agent can ask the requester and then re-send (without
/// the peek header) to actually run the tool.
fn approved_peek_violation(
    bag: &praxis_policy_apl_core::attributes::AttributeBag,
) -> PluginViolation {
    use praxis_policy_apl_core::step::elicitation_bag_keys as bk;
    let mut details: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    if let Some(id) = bag.get_string(bk::ID) {
        details.insert("elicitation_id".into(), Value::String(id.to_owned()));
    }
    if let Some(approver) = bag.get_string(bk::APPROVER) {
        details.insert("approver".into(), Value::String(approver.to_owned()));
    }
    PluginViolation::new(
        "elicitation.approved",
        "approved — confirm to apply (re-send without the peek header)".to_owned(),
    )
    .with_proto_error_code(ELICITATION_APPROVED_CODE)
    .with_details(details)
}

/// Build the `-32120` violation for a suspended phase: a distinguished
/// code, the protocol error code the host maps to the wire, and the
/// elicitation bundle in `details` so the agent can show who's approving /
/// when it expires and retry by re-sending the id.
fn pending_violation(p: &praxis_policy_apl_core::step::PendingElicitation) -> PluginViolation {
    let mut details: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    details.insert("elicitation_id".into(), Value::String(p.id.clone()));
    details.insert("plugin".into(), Value::String(p.plugin_name.clone()));
    for (key, val) in [
        ("approver", &p.approver),
        ("channel", &p.channel),
        ("expires_at", &p.expires_at),
        ("intent_id", &p.intent_id),
    ] {
        if let Some(v) = val {
            details.insert(key.into(), Value::String(v.clone()));
        }
    }
    PluginViolation::new(
        "elicitation.pending",
        format!(
            "awaiting approval `{}` via `{}` — retry with this id",
            p.id, p.plugin_name
        ),
    )
    .with_proto_error_code(ELICITATION_PENDING_CODE)
    .with_details(details)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::get_unwrap,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::extensions::HttpExtension;

    fn handler_for(entity_type: &str) -> AplRouteHandler {
        AplRouteHandler::new(
            PluginConfig::default(),
            Arc::new(CompiledRoute::new("k")),
            Phase::Pre,
            HookFamily::for_entity(entity_type).expect("mapped entity type"),
            Arc::new(PluginRegistry::default()),
            Arc::new(DispatchCache::new()),
            Arc::new(crate::session_store::MemorySessionStore::new()),
            Weak::new(),
        )
    }

    /// The handler a route installs reports the family it was built for, so a
    /// registry check reads the truth rather than a literal that was right for
    /// one family only.
    #[test]
    fn a_handler_reports_the_family_its_entity_type_belongs_to() {
        assert_eq!(handler_for(ENTITY_HTTP).hook_type_name(), HttpHook::NAME);
        for entity_type in ["tool", "resource", "prompt", "llm"] {
            assert_eq!(handler_for(entity_type).hook_type_name(), CmfHook::NAME);
        }
    }

    /// An entity type this does not map gets no family rather than the CMF
    /// one, so a route on a new entity type cannot be handed a chat message
    /// by omission.
    #[test]
    fn an_unmapped_entity_type_has_no_family() {
        for entity_type in ["webhook", "agent", ""] {
            assert_eq!(HookFamily::for_entity(entity_type), None);
        }
    }

    fn pending(id: &str) -> praxis_policy_apl_core::step::PendingElicitation {
        praxis_policy_apl_core::step::PendingElicitation {
            id: id.to_owned(),
            plugin_name: "manager-approver".to_owned(),
            approver: Some("alice".to_owned()),
            intent_id: None,
            channel: Some("ciba".to_owned()),
            expires_at: Some("2026-12-31T00:00:00Z".to_owned()),
            source: "route.payroll.policy[0]".to_owned(),
        }
    }

    #[test]
    fn pending_violation_carries_minus32120_and_bundle() {
        let v = pending_violation(&pending("elic-1"));
        assert_eq!(v.proto_error_code, Some(ELICITATION_PENDING_CODE));
        assert_eq!(v.code, "elicitation.pending");
        assert_eq!(v.details.get("elicitation_id").unwrap(), "elic-1");
        assert_eq!(v.details.get("approver").unwrap(), "alice");
        assert_eq!(v.details.get("channel").unwrap(), "ciba");
        assert_eq!(v.details.get("expires_at").unwrap(), "2026-12-31T00:00:00Z");
        // Absent optional → not in details.
        assert!(!v.details.contains_key("intent_id"));
    }

    #[test]
    fn elicitation_id_extracted_from_header_case_insensitively() {
        let mut http = HttpExtension::default();
        http.set_request_header("x-policy-elicitation-id", "elic-42");
        let ext = Extensions {
            http: Some(Arc::new(http)),
            ..Extensions::default()
        };
        assert_eq!(
            elicitation_id_from_headers(&ext).as_deref(),
            Some("elic-42")
        );
    }

    #[test]
    fn no_header_yields_none() {
        // No http extension at all.
        assert!(elicitation_id_from_headers(&Extensions::default()).is_none());
        // Header present but empty → treated as absent.
        let mut http = HttpExtension::default();
        http.set_request_header(ELICITATION_ID_HEADER, "");
        let ext = Extensions {
            http: Some(Arc::new(http)),
            ..Extensions::default()
        };
        assert!(elicitation_id_from_headers(&ext).is_none());
    }

    // ---- the approved-peek violation --------------------------------------

    /// The peek response is a distinct code from pending, and the distinction is
    /// load-bearing: `-32120` means retry later, `-32121` means the approval
    /// landed and the caller must re-send without the peek header to apply it.
    /// Collapsing them would either loop the agent forever or apply an effect
    /// the caller only asked to inspect.
    #[test]
    fn approved_peek_violation_is_a_distinct_code_from_pending() {
        use praxis_policy_apl_core::attributes::AttributeBag;
        use praxis_policy_apl_core::step::elicitation_bag_keys as bk;

        let mut bag = AttributeBag::new();
        bag.set(bk::ID, "elic-7");
        bag.set(bk::APPROVER, "alice");
        let v = approved_peek_violation(&bag);

        assert_eq!(v.code, "elicitation.approved");
        assert_eq!(v.proto_error_code, Some(ELICITATION_APPROVED_CODE));
        assert_ne!(
            ELICITATION_APPROVED_CODE, ELICITATION_PENDING_CODE,
            "peek and pending must not share a wire code"
        );
        assert_eq!(v.details.get("elicitation_id").unwrap(), "elic-7");
        assert_eq!(v.details.get("approver").unwrap(), "alice");
        assert!(
            v.reason.contains("re-send"),
            "the reason must tell the caller what to do next: {}",
            v.reason
        );
    }

    /// The bag may carry neither key, and the violation still has to be
    /// well-formed rather than fabricate values.
    #[test]
    fn approved_peek_violation_omits_details_it_has_no_value_for() {
        use praxis_policy_apl_core::attributes::AttributeBag;
        let v = approved_peek_violation(&AttributeBag::new());
        assert_eq!(v.code, "elicitation.approved");
        assert!(
            v.details.is_empty(),
            "no keys in the bag, no details invented"
        );
    }

    // ---- extensions_changed ------------------------------------------------
    //
    // This decides whether the executor merges a phase's Extensions mutations
    // back. A false negative silently drops them, which is how a minted
    // delegation token would fail to reach the upstream request.

    fn with_security(sec: praxis_policy_core::extensions::SecurityExtension) -> Extensions {
        Extensions {
            security: Some(Arc::new(sec)),
            ..Extensions::default()
        }
    }

    #[test]
    fn identical_extensions_report_unchanged() {
        let a = Extensions::default();
        assert!(
            !extensions_changed(&a, &a),
            "nothing was touched, so nothing to merge"
        );
    }

    /// Comparison is by `Arc` identity, not by value, so a fresh `Arc` counts as
    /// changed even when the contents match. That is deliberate: cloning to
    /// mutate is exactly what a phase does.
    #[test]
    fn a_replaced_arc_reports_changed_even_when_the_value_matches() {
        use praxis_policy_core::extensions::SecurityExtension;
        let before = with_security(SecurityExtension::default());
        let after = with_security(SecurityExtension::default());
        assert!(
            extensions_changed(&before, &after),
            "a new Arc is a change, since a phase clones to mutate"
        );
    }

    #[test]
    fn a_shared_arc_reports_unchanged() {
        use praxis_policy_core::extensions::SecurityExtension;
        let shared = Arc::new(SecurityExtension::default());
        let before = Extensions {
            security: Some(Arc::clone(&shared)),
            ..Extensions::default()
        };
        let after = Extensions {
            security: Some(shared),
            ..Extensions::default()
        };
        assert!(!extensions_changed(&before, &after));
    }

    /// Appearing or disappearing is a change. Both directions, because only one
    /// of them is the `_ => true` arm.
    #[test]
    fn a_slot_appearing_or_disappearing_is_a_change() {
        use praxis_policy_core::extensions::SecurityExtension;
        let none = Extensions::default();
        let some = with_security(SecurityExtension::default());
        assert!(extensions_changed(&none, &some), "absent to present");
        assert!(extensions_changed(&some, &none), "present to absent");
    }

    /// The case the check exists for. A route whose only mutation is a
    /// `delegate(...)` touches neither security nor the delegation chain, so
    /// without watching `raw_credentials` the minted token would look like no
    /// change and never reach the upstream request.
    #[test]
    fn a_raw_credentials_change_alone_is_detected() {
        use praxis_policy_core::extensions::raw_credentials::RawCredentialsExtension;
        let before = Extensions::default();
        let after = Extensions {
            raw_credentials: Some(Arc::new(RawCredentialsExtension::default())),
            ..Extensions::default()
        };
        assert!(
            extensions_changed(&before, &after),
            "a minted token must not be mistaken for no change"
        );
    }

    #[test]
    fn a_delegation_chain_change_alone_is_detected() {
        use praxis_policy_core::extensions::DelegationExtension;
        let before = Extensions::default();
        let after = Extensions {
            delegation: Some(Arc::new(DelegationExtension::default())),
            ..Extensions::default()
        };
        assert!(extensions_changed(&before, &after));
    }

    /// The arm that actually runs in production, for both slots that a route can
    /// mutate without touching security.
    ///
    /// The tests above cover absent-to-present. But by the time a route runs, a
    /// JWT resolver has usually already stashed the inbound token, so
    /// `raw_credentials` is `Some` before the pipeline starts and the comparison
    /// that decides whether to merge is the pointer check between two present
    /// values. If that arm answered "unchanged", a `delegate(...)` step would
    /// mint a token the upstream request never receives, and the route would
    /// report success while the downstream call went out unauthenticated.
    ///
    /// Both directions are asserted per slot: a replaced `Arc` is a change, and
    /// the same `Arc` on both sides is not. Without the second, an
    /// always-changed answer would pass.
    #[test]
    fn a_replaced_slot_is_a_change_and_the_same_arc_is_not() {
        use praxis_policy_core::extensions::DelegationExtension;
        use praxis_policy_core::extensions::raw_credentials::RawCredentialsExtension;

        let creds = Arc::new(RawCredentialsExtension::default());
        let with_creds = |c: &Arc<RawCredentialsExtension>| Extensions {
            raw_credentials: Some(Arc::clone(c)),
            ..Extensions::default()
        };
        assert!(
            !extensions_changed(&with_creds(&creds), &with_creds(&creds)),
            "the same raw_credentials Arc on both sides is not a change"
        );
        assert!(
            extensions_changed(
                &with_creds(&creds),
                &with_creds(&Arc::new(RawCredentialsExtension::default()))
            ),
            "a replaced raw_credentials Arc carries the minted token and must \
             be detected"
        );

        let chain = Arc::new(DelegationExtension::default());
        let with_chain = |c: &Arc<DelegationExtension>| Extensions {
            delegation: Some(Arc::clone(c)),
            ..Extensions::default()
        };
        assert!(
            !extensions_changed(&with_chain(&chain), &with_chain(&chain)),
            "the same delegation Arc on both sides is not a change"
        );
        assert!(
            extensions_changed(
                &with_chain(&chain),
                &with_chain(&Arc::new(DelegationExtension::default()))
            ),
            "a replaced delegation chain must be detected"
        );
    }
}
