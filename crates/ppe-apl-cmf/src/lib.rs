// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-apl-cmf — bridges typed praxis-policy-core extensions into praxis-policy-apl-core's flat
// AttributeBag. This is where the *attribute vocabulary* APL policy
// authors write against gets defined.
//
// Layering:
//
//   praxis-policy-core  : typed extension data (SecurityExtension, …)
//   praxis-policy-apl-cmf    : ←── this crate, flat-key bridge
//   praxis-policy-apl-core   : language IR + evaluator (AttributeBag, predicates, pipelines)
//   praxis-policy-apl-runtime   : runtime adapter (hooks, PluginInvoker, PdpResolver)
//
// The crate is intentionally simple: each bridge is a pure function that
// reads its typed source and writes flat keys into a borrowed bag. No
// async, no I/O. Composition is via the convenience `BagBuilder`.
//
// Attribute namespace contract (each module owns the detail comment):
//   SecurityExtension.subject         → subject.*, role.*, perm.*, claim.*, authenticated
//   SecurityExtension.client          → client.*, client.role.*, client.perm.*, client.claim.*
//   SecurityExtension.caller_workload → caller_workload.*   (inbound attested peer)
//   SecurityExtension.this_workload   → this_workload.*     (our own attested identity —
//                                         not `agent.*`, which is `AgentExtension`)
//   SecurityExtension                  → security.labels, security.classification, auth_method
//   DelegationExtension           → delegation.*, delegated
//   AgentExtension                 → agent.*       (session, conversation, lineage)
//   MetaExtension                  → meta.*
//   RequestExtension               → request.*
//   HttpExtension                  → http.method, http.path, http.host, http.scheme,
//                                     http.status, http.request_headers.*,
//                                     http.response_headers.*
//   LLMExtension                   → llm.*
//   MCPExtension                   → mcp.tool.*, mcp.resource.*, mcp.prompt.*
//   CompletionExtension            → completion.*
//   ProvenanceExtension            → provenance.*
//   FrameworkExtension             → framework.*  (incl. framework.metadata.*)
//   Extensions.custom              → custom.*
//   Request args object            → args.*
//   Response result object         → result.*

//! Flattens typed extensions into the attribute vocabulary policies are written
//! against.
//!
//! Each bridge is a pure function that reads one typed source and writes flat
//! keys into a borrowed bag: no async, no I/O. This crate defines which keys a
//! policy author may reference, so adding one here widens the language.

/// Bridges agent session and lineage into `agent.*` keys.
pub mod agent;
/// Maps a plugin capability to the key prefixes it may read.
pub mod capability_namespaces;
/// Bridges completion metadata into `completion.*` keys.
pub mod completion;
/// The attribute key and capability name constants.
pub mod constants;
/// Bridges host-supplied values into `custom.*` keys.
pub mod custom;
/// Bridges the delegation chain into `delegation.*` keys.
pub mod delegation;
/// Runs every bridge over one extension container.
pub mod extensions_bridge;
/// Bridges framework context into `framework.*` keys.
pub mod framework;
/// Bridges request and response headers into `http.*` keys.
pub mod http;
/// Bridges model identity into `llm.*` keys.
pub mod llm;
/// Bridges tool and resource metadata into `mcp.*` keys.
pub mod mcp;
/// Bridges operational metadata into `meta.*` keys.
pub mod meta;
/// Bridges the message payload into `args.*` and `result.*` keys.
pub mod payload;
/// Bridges origin and threading into `provenance.*` keys.
pub mod provenance;
/// Bridges execution environment into `request.*` keys.
pub mod request;
/// Bridges identity and labels into `subject.*`, `role.*`, and `perm.*` keys.
pub mod security;

pub use agent::extract_agent;
pub use capability_namespaces::{
    capability_namespaces, known_read_capabilities, unlocked_bag_prefixes,
};
pub use completion::extract_completion;
pub use custom::extract_custom;
pub use delegation::extract_delegation;
pub use extensions_bridge::extract_extensions;
pub use framework::extract_framework;
pub use http::extract_http;
pub use llm::extract_llm;
pub use mcp::extract_mcp;
pub use meta::extract_meta;
pub use payload::{extract_args, extract_data, extract_result};
pub use provenance::extract_provenance;
pub use request::extract_request;
pub use security::{extract_client, extract_security, extract_workload};

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::{DelegationExtension, Extensions, SecurityExtension};

/// Fluent builder that composes the typed sources into a single bag.
///
/// Lets the host (praxis-policy-apl-runtime) write:
/// ```ignore
/// let bag = BagBuilder::new()
///     .with_security(&sec)
///     .with_delegation(&del)
///     .with_args(&payload.args)
///     .build();
/// ```
///
/// Order of `with_*` calls is irrelevant — keys live in disjoint namespaces.
#[derive(Default)]
pub struct BagBuilder {
    bag: AttributeBag,
}

impl BagBuilder {
    /// A builder over an empty bag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bridge identity, roles, and labels into the bag.
    pub fn with_security(mut self, sec: &SecurityExtension) -> Self {
        extract_security(sec, &mut self.bag);
        self
    }

    /// Bridge the delegation chain into the bag.
    pub fn with_delegation(mut self, del: &DelegationExtension) -> Self {
        extract_delegation(del, &mut self.bag);
        self
    }

    /// Bridge every present slot in an `Extensions` container at once —
    /// security, delegation, agent, meta, request, http, llm, mcp,
    /// completion, provenance, framework, custom.
    pub fn with_extensions(mut self, ext: &Extensions) -> Self {
        extract_extensions(ext, &mut self.bag);
        self
    }

    /// Bridge the call arguments into `args.*` keys.
    pub fn with_args(mut self, args: &serde_json::Value) -> Self {
        extract_args(args, &mut self.bag);
        self
    }

    /// Bridge the response into `result.*` keys.
    pub fn with_result(mut self, result: &serde_json::Value) -> Self {
        extract_result(result, &mut self.bag);
        self
    }

    /// Flatten a static attribute tree into the `data.*` namespace.
    /// The tree is shared and startup-loaded, but this
    /// re-walks it and re-inserts every leaf into the bag on **each call**
    /// (a `format!` per node, a `bag.set` per leaf) — so `data.*` reads are
    /// **not** free on the request hot path. The route handler invokes this
    /// per request (once per phase), meaning a large tree is re-flattened on
    /// every request until a per-request caching optimization lands.
    pub fn with_data(mut self, tree: &praxis_policy_apl_core::AttributeTree) -> Self {
        extract_data(tree, &mut self.bag);
        self
    }

    /// Set the route key under `route.key` for policy predicates that
    /// branch on which route is running (mostly useful in default/policy
    /// bundles applied across routes).
    pub fn with_route_key(mut self, route_key: impl Into<String>) -> Self {
        self.bag.set("route.key", route_key.into());
        self
    }

    /// The finished bag.
    pub fn build(self) -> AttributeBag {
        self.bag
    }
}
