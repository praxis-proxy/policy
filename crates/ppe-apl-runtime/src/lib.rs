// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-apl-runtime — bridge between APL evaluator (`praxis-policy-apl-core`) and PPE runtime
// (`praxis-policy-core`).
//
// `praxis-policy-apl-core::PluginInvoker` is string-typed by design (so `praxis-policy-apl-core`
// stays free of PPE deps). The actual typed boundary lives in this
// crate: [`HookPluginInvoker`] is parameterized over the `HookTypeDef` it
// dispatches, so the payload is locked to the family and the compiler
// rejects a mismatched dispatch. A route's entity type picks the parameter
// ([`CmfPluginInvoker`] for the MCP and A2A entities, [`HttpPluginInvoker`]
// for generic HTTP), and the generic is erased at `Arc<dyn PluginInvoker>`,
// which carries no payload.
//
// # v0 simplification — single-view-per-Message
//
// CMF distinguishes two messaging patterns:
//   - LLM wire format — bundled multi-part Messages (thinking + text +
//     tool_call(s)) — many MessageViews per Message.
//   - Framework/protocol format (MCP, A2A, LangGraph) — single
//     ContentPart per Message — one view per Message.
//
// v0 only handles request-side flows (outbound LLM call from the user,
// outbound MCP tools/call from the agent). Both are single-part, so the
// route → MessageView matching collapses to "one route fires per
// Message." When response-side handling lands, this assumption breaks
// and praxis-policy-apl-core's route-matching layer needs to switch from
// routes-as-map to routes-as-list with a `match:` block filtering on
// MessageView attributes. See the APL implementation memory's
// "list-with-matchers" deferred item.

//! Connects the APL evaluator to the plugin runtime.
//!
//! The evaluator's invoker traits are string-typed so the language crate stays
//! free of runtime dependencies. The typed boundary lives here: the invoker is
//! parameterized over the hook type it dispatches, so the payload is locked to
//! the family and the compiler rejects a mismatched dispatch.

/// Loads external attribute trees for the evaluator.
pub mod attribute_source;
/// Applies a route's backend candidate constraint.
pub mod candidate_constraint;
/// Dispatches plugin steps to one hook family's hooks.
pub mod cmf_invoker;
/// Dispatches delegation steps to the delegation hook.
pub mod delegation_invoker;
/// The per-request plan of which handlers run in which phase.
pub mod dispatch_plan;
/// Dispatches elicitation steps to the elicitation hook.
pub mod elicitation_invoker;
/// Folds a plugin's payload edits back into the request.
mod message_projection;
/// Rejects plugins whose mode is unsafe inside a `parallel:` block.
pub mod parallel_safety;
/// What a field stage can address on a hook payload.
pub mod payload_fields;
/// Routes a decision point call to the resolver for its dialect.
pub mod pdp_router;
/// Wires the runtime into a policy engine.
pub mod register;
/// Runs a compiled route for one hook invocation.
pub mod route_handler;
/// Resolves the session identity a taint label attaches to.
pub mod session_resolver;
/// The session store trait and its in-memory default.
pub mod session_store;
/// Compiles route blocks at config load time.
pub mod visitor;

pub use attribute_source::{FileAttributeSource, merge_attribute_docs};
pub use candidate_constraint::{ConstraintConflict, fold_candidate_constraints};
pub use cmf_invoker::{CmfPluginInvoker, HookPluginInvoker, HttpPluginInvoker};
pub use delegation_invoker::DelegationPluginInvoker;
pub use dispatch_plan::{DispatchCache, RouteDispatchPlan, RoutePluginEntry};
pub use elicitation_invoker::ElicitationPluginInvoker;
pub use payload_fields::PayloadFields;
pub use pdp_router::PdpRouter;
pub use register::{AplOptions, register_apl};
pub use route_handler::{
    AplRouteHandler, ELICITATION_APPROVED_CODE, ELICITATION_ID_HEADER, ELICITATION_PEEK_HEADER,
    ELICITATION_PENDING_CODE, HookFamily, Phase,
};
pub use session_store::{MemorySessionStore, SessionStore, SessionStoreError, SessionStoreFactory};
pub use visitor::AplConfigVisitor;
