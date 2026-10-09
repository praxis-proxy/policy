// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A reference host: drives a real engine through the per-request sequence
//! of the praxis `policy` filter and reports what happened.
//!
//! # Mirrored
//!
//! From `praxis/crates/filter/src/builtins/http/security/policy/` at praxis
//! commit [`PRAXIS_COMMIT`], the files listed in [`MIRRORED`]:
//!
//! - `filter.rs`: `PolicyFilter::new` (builtins, host factories, transport,
//!   load, initialize, `parse_config` for the assertions contract),
//!   `identity_gate` (`on_request`), `on_request_body`,
//!   `extensions_from_identity`, `attach_http_attributes`,
//!   `attach_delegated_tokens`, `on_response`, `on_response_body`.
//! - `assertions.rs`: `GovernedNames` and the govern-then-diff application of
//!   rendered headers, in both directions.
//! - `json_rpc.rs`: the tool-call content parts and both body rewrites.
//! - `common_message_format.rs`: `tools/call` to the tool hooks.
//! - `error.rs`: what a deny carries (code, reason, `proto_error_code`,
//!   `details`). The driver returns those fields, not the wire envelope.
//! - `dispatch.rs`: the runtime bound on the synchronous response-body
//!   hook, which this driver does not reproduce (see "Not mirrored").
//!
//! The sequence, per call:
//!
//! 1. Header phase: the identity gate resolves identity at the entity-less
//!    HTTP coordinates and stops the request on a deny.
//! 2. Body phase: identity again at the tool's coordinates, then
//!    `cmf.tool_pre_invoke` with identity, meta, HTTP attributes and the
//!    `X-Session-Id` session. On allow: delegated tokens, then request
//!    assertions, then the rewritten arguments into the body.
//! 3. The [`Upstream`] stand-in answers.
//! 4. Response headers: `http.response` and response assertions, when the
//!    policy has either.
//! 5. Response body: `cmf.tool_post_invoke` on the result, then the
//!    rewritten result into the body.
//!
//! The driver assumes `body_access: read_write` and a `tools/call` request
//! the classifier already attributed, as in the demo.
//!
//! # Not mirrored
//!
//! - Praxis supplies no HTTP extension to `cmf.tool_post_invoke`. This driver
//!   carries the pre-invoke view, including `secret_headers`, as required by
//!   `docs/content/assertions.md`. Both hosts rebuild the `http.response`
//!   view from inbound headers plus response headers and status.
//! - Praxis bounds the synchronous CMF response-body hook on `dispatch.rs`'s
//!   two-worker runtime by `max(2 * plugin_timeout, 1s)`. This driver awaits
//!   it directly. Both hosts await `http.response` directly.
//!
//! # Host-owned behavior not reproduced
//!
//! Each lives in praxis and is tested there:
//!
//! - the SSRF-checking transport (private and loopback destinations). The
//!   resilience suite's `dependency_failure::ssrf` is the one full-engine
//!   check, through `HyperTransport` and without this driver;
//! - Content-Length fitting of a rewritten response, and the
//!   `gateway.response_rewrite_overflow` deny when a rewrite grows;
//! - JSON-RPC parsing of an invalid body, and classifier metadata;
//! - body size ceilings;
//! - comma-joining duplicate header lines, and header name and value
//!   validity on the wire.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use praxis_policy::{
    AplOptions, PolicyEngine, SessionStoreFactory, builtin_pdp_factories,
    builtin_session_store_factories, register_apl, register_builtin_plugins, registry_with_vault,
};
use praxis_policy_core::assertions::{Direction, StripPattern};
use praxis_policy_core::cmf::constants::{
    ENTITY_HTTP, ENTITY_NAME_GLOBAL, ENTITY_TOOL, HOOK_CMF_TOOL_POST_INVOKE,
    HOOK_CMF_TOOL_PRE_INVOKE,
};
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use praxis_policy_core::config::{PolicyConfig, parse_config};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginErrorRecord, PluginViolation};
use praxis_policy_core::executor::{BackgroundTasks, PipelineResult};
use praxis_policy_core::extensions::{Extensions, MetaExtension};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::TypedHandlerAdapter;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::http_hook::{HOOK_HTTP_RESPONSE, HttpHook, HttpPayload};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::AnyHookHandler;
use serde_json::{Value, json};

use crate::capture::{self, Events};
use crate::fixtures::Fixture;
use crate::idp::{self, Ciba, Exchange, Persona};
use crate::live::{self, Targets};
use crate::mcp;
use crate::secrets::{IssuedTokens, Planted};
use crate::upstream::{Upstream, UpstreamRequest};

/// The praxis commit the mirrored files were last checked against. The
/// `host-drift` job in `.github/workflows/integration-live.yml` diffs
/// [`MIRRORED`] from here to praxis `main`, so keep the full SHA.
pub const PRAXIS_COMMIT: &str = "0e65081241e34226343e4edd01417cae1de89822";

/// The praxis files this driver mirrors, relative to the praxis root.
pub const MIRRORED: [&str; 6] = [
    "crates/filter/src/builtins/http/security/policy/filter.rs",
    "crates/filter/src/builtins/http/security/policy/assertions.rs",
    "crates/filter/src/builtins/http/security/policy/json_rpc.rs",
    "crates/filter/src/builtins/http/security/policy/common_message_format.rs",
    "crates/filter/src/builtins/http/security/policy/error.rs",
    "crates/filter/src/builtins/http/security/policy/dispatch.rs",
];

/// `kind:` of the header probe a fixture may declare.
const PROBE_KIND: &str = "test/header-probe";

/// An engine with every builtin, the APL visitor and the reference plugins,
/// registered piece by piece as a host does.
///
/// `session_stores` are registered beside the builtin session-store
/// factories, so a fixture's `global.session_store` can select a test store.
#[must_use]
pub fn engine(session_stores: Vec<Arc<dyn SessionStoreFactory>>) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    register_builtin_plugins(&engine);
    let mut opts = AplOptions::in_process();
    opts.pdp_factories = builtin_pdp_factories();
    opts.session_store_factories = builtin_session_store_factories();
    opts.session_store_factories.extend(session_stores);
    let _visitor = register_apl(&engine, opts);
    engine.register_factory(
        praxis_policy_plugin_pii_scanner::KIND,
        Box::new(praxis_policy_plugin_pii_scanner::PiiScannerFactory),
    );
    engine.register_factory(
        praxis_policy_plugin_audit_logger::KIND,
        Box::new(praxis_policy_plugin_audit_logger::AuditLoggerFactory),
    );
    engine
}

// -----------------------------------------------------------------------------
// Header probe
// -----------------------------------------------------------------------------

/// The request headers each probe invocation was shown, in order.
type Views = Arc<Mutex<Vec<(String, BTreeMap<String, String>)>>>;

/// Records the request headers its capability-filtered view carries.
struct HeaderProbe {
    cfg: PluginConfig,
    views: Views,
}

impl Plugin for HeaderProbe {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for HeaderProbe {
    async fn handle(
        &self,
        payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let phase = if payload
            .message
            .content
            .iter()
            .any(|p| matches!(p, ContentPart::ToolResult { .. }))
        {
            HOOK_CMF_TOOL_POST_INVOKE
        } else {
            HOOK_CMF_TOOL_PRE_INVOKE
        };
        let seen = ext
            .http
            .as_deref()
            .map(|h| h.request_headers.clone().into_iter().collect())
            .unwrap_or_default();
        self.views
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((phase.to_owned(), seen));
        PluginResult::allow()
    }
}

struct HeaderProbeFactory(Views);

impl PluginFactory for HeaderProbeFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let probe = Arc::new(HeaderProbe {
            cfg: config.clone(),
            views: Arc::clone(&self.0),
        });
        let handlers = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, Arc<dyn AnyHookHandler>) {
                let hook: &'static str = Box::leak(h.clone().into_boxed_str());
                (
                    hook,
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&probe))),
                )
            })
            .collect();
        Ok(PluginInstance {
            plugin: probe,
            handlers,
        })
    }
}

// -----------------------------------------------------------------------------
// Assertions contract (assertions.rs)
// -----------------------------------------------------------------------------

/// Header names one direction's assertion blocks govern, across every level.
#[derive(Debug, Default)]
struct GovernedNames {
    names: HashSet<String>,
    strip: Vec<StripPattern>,
}

impl GovernedNames {
    fn from_config(config: &PolicyConfig, direction: Direction) -> Self {
        let mut out = Self::default();
        let levels = config
            .global
            .assertions
            .iter()
            .chain(
                config
                    .global
                    .defaults
                    .values()
                    .filter_map(|s| s.assertions.as_ref()),
            )
            .chain(
                config
                    .global
                    .bundles
                    .values()
                    .filter_map(|s| s.assertions.as_ref()),
            )
            .chain(config.groups.values().filter_map(|s| s.assertions.as_ref()))
            .chain(config.routes.iter().filter_map(|r| r.assertions.as_ref()));
        for block in levels.filter_map(|level| direction.block_of(level)) {
            out.names
                .extend(block.headers.iter().map(|e| e.name.to_ascii_lowercase()));
            out.strip.extend(block.strip.iter().cloned());
        }
        out
    }

    fn governs(&self, lowercase: &str) -> bool {
        self.names.contains(lowercase) || self.strip.iter().any(|p| p.matches_lowercase(lowercase))
    }

    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.strip.is_empty()
    }

    fn candidates<'a>(&'a self, in_play: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self.names.iter().cloned().collect();
        out.extend(
            in_play
                .filter(|n| self.strip.iter().any(|p| p.matches_lowercase(n)))
                .map(str::to_owned),
        );
        out
    }
}

/// The request mutations praxis queues, applied remove then set.
#[derive(Debug, Default)]
struct Queued {
    set: Vec<(String, String)>,
    remove: Vec<String>,
}

impl Queued {
    fn purge(&mut self, lowercase: &str) -> bool {
        let before = self.set.len();
        self.set.retain(|(name, _)| name != lowercase);
        self.set.len() != before
    }

    fn forwarded(&self, inbound: &HashMap<String, String>) -> HashMap<String, String> {
        let mut out = inbound.clone();
        for name in &self.remove {
            out.remove(name);
        }
        for (name, value) in &self.set {
            out.insert(name.clone(), value.clone());
        }
        out
    }
}

/// `apply_request_assertions`: govern the contract's names, then diff what
/// plugins wrote against the inbound headers.
fn apply_request_assertions(
    queued: &mut Queued,
    inbound: &HashMap<String, String>,
    extensions: Option<&Extensions>,
    governed: &GovernedNames,
) {
    let Some(asserted) = extensions.and_then(|e| e.http.as_deref()) else {
        return;
    };
    let rendered: HashMap<String, String> = asserted
        .request_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();

    if !governed.is_empty() {
        let in_play: Vec<String> = inbound
            .keys()
            .chain(rendered.keys())
            .cloned()
            .chain(queued.set.iter().map(|(n, _)| n.clone()))
            .collect();
        for name in governed.candidates(in_play.iter().map(String::as_str)) {
            let had_pending = queued.purge(&name);
            if let Some(value) = rendered.get(&name) {
                queued.set.push((name, value.clone()));
            } else if inbound.contains_key(&name) || had_pending {
                queued.remove.push(name);
            }
        }
    }
    for (name, value) in &rendered {
        if !governed.governs(name) && inbound.get(name) != Some(value) {
            queued.set.push((name.clone(), value.clone()));
        }
    }
    for name in inbound.keys() {
        if !governed.governs(name) && !rendered.contains_key(name) {
            queued.remove.push(name.clone());
        }
    }
}

/// `apply_response_assertions`, editing the response headers in place.
fn apply_response_assertions(
    headers: &mut BTreeMap<String, String>,
    extensions: Option<&Extensions>,
    governed: &GovernedNames,
) {
    let Some(asserted) = extensions.and_then(|e| e.http.as_deref()) else {
        return;
    };
    let upstream = headers.clone();
    let rendered: HashMap<String, String> = asserted
        .response_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    if !governed.is_empty() {
        let in_play: Vec<&str> = upstream
            .keys()
            .chain(rendered.keys())
            .map(String::as_str)
            .collect();
        for name in governed.candidates(in_play.into_iter()) {
            if let Some(value) = rendered.get(&name) {
                headers.insert(name, value.clone());
            } else {
                headers.remove(&name);
            }
        }
    }
    for (name, value) in &rendered {
        if !governed.governs(name) && upstream.get(name) != Some(value) {
            headers.insert(name.clone(), value.clone());
        }
    }
    for name in upstream.keys() {
        if !governed.governs(name) && !rendered.contains_key(name) {
            headers.remove(name);
        }
    }
}

/// `attach_delegated_tokens`: one `Bearer` header per outbound name, first
/// audience wins, and the inbound credential headers removed once any is
/// attached.
fn attach_delegated_tokens(queued: &mut Queued, extensions: Option<&Extensions>) -> usize {
    let Some(raw) = extensions.and_then(|e| e.raw_credentials.as_deref()) else {
        return 0;
    };
    let mut tokens: Vec<_> = raw.delegated_tokens.values().collect();
    tokens.sort_by(|a, b| {
        a.outbound_header
            .to_ascii_lowercase()
            .cmp(&b.outbound_header.to_ascii_lowercase())
            .then_with(|| a.audience.cmp(&b.audience))
    });
    let mut attached = HashSet::new();
    for token in tokens {
        let name = token.outbound_header.to_ascii_lowercase();
        if attached.insert(name.clone()) {
            queued
                .set
                .push((name, format!("Bearer {}", token.token.as_str())));
        }
    }
    if !attached.is_empty() {
        for inbound in raw.inbound_tokens.values() {
            let name = inbound.source_header.to_ascii_lowercase();
            if !attached.contains(&name) {
                queued.remove.push(name);
            }
        }
    }
    attached.len()
}

// -----------------------------------------------------------------------------
// Bodies (json_rpc.rs)
// -----------------------------------------------------------------------------

/// Read the JSON-RPC id as the string passed to CMF hooks.
fn id_string(body: &Value) -> String {
    match body.get("id").cloned().unwrap_or(Value::Null) {
        Value::String(s) => s,
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `reserialize_json_rpc_body` for `tools/call`.
fn rewrite_request(mut body: Value, message: &Message) -> Value {
    let args = message.content.iter().find_map(|p| match p {
        ContentPart::ToolCall { content } => Some(&content.arguments),
        _ => None,
    });
    if let (Some(params), Some(args)) =
        (body.get_mut("params").and_then(Value::as_object_mut), args)
    {
        let args: serde_json::Map<String, Value> =
            args.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        params.insert("arguments".to_owned(), Value::Object(args));
    }
    body
}

/// `build_response_content_for_method` for `tools/call`.
fn response_content(body: &Value, tool: &str, call_id: &str) -> Option<MessagePayload> {
    let result = body.get("result")?;
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content = if let Some(structured) = result.get("structuredContent") {
        structured.clone()
    } else {
        let texts: Vec<&str> = result
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect();
        match texts.as_slice() {
            [] => Value::Null,
            [single] => serde_json::from_str(single).unwrap_or_else(|_| json!({ "text": single })),
            many => json!({ "text": many.join("\n") }),
        }
    };
    Some(mcp::tool_result(call_id, tool, content, is_error))
}

/// `reserialize_json_rpc_response_body` for `tools/call`.
fn rewrite_response(mut body: Value, message: &Message) -> Value {
    let Some(new_content) = message.content.iter().find_map(|p| match p {
        ContentPart::ToolResult { content } => Some(content.content.clone()),
        _ => None,
    }) else {
        return body;
    };
    if let Some(result) = body.get_mut("result").and_then(Value::as_object_mut) {
        if result.contains_key("content") {
            let text = serde_json::to_string(&new_content).unwrap_or_default();
            result.insert(
                "content".to_owned(),
                json!([{ "type": "text", "text": text }]),
            );
        }
        if result.contains_key("structuredContent") {
            result.insert("structuredContent".to_owned(), new_content);
        }
    }
    body
}

/// Extract a policy rewrite from a pipeline result, if any.
fn modified_message(result: &PipelineResult) -> Option<&Message> {
    result
        .modified_payload
        .as_ref()
        .and_then(|p| p.as_any().downcast_ref::<MessagePayload>())
        .map(|p| &p.message)
}

// -----------------------------------------------------------------------------
// Calls and outcomes
// -----------------------------------------------------------------------------

/// One MCP `tools/call`, as the demo's `_lib.sh` sends it.
#[derive(Clone, Debug)]
pub struct Call {
    tool: String,
    args: Value,
    headers: Vec<(String, String)>,
}

impl Call {
    /// `user` calling `tool` through the `hr-copilot` agent: a fresh user
    /// token in `X-User-Token` and the agent's in `Authorization`.
    #[must_use]
    pub fn new(user: Persona, tool: &str) -> Self {
        Self::with_tokens(tool, &user.token(), &Persona::HrCopilot.token())
    }

    /// `tool` with tokens minted elsewhere, such as by a live realm.
    #[must_use]
    pub fn with_tokens(tool: &str, user_token: &str, agent_token: &str) -> Self {
        Self::anonymous(tool)
            .header("x-user-token", user_token)
            .header("authorization", &format!("Bearer {agent_token}"))
    }

    /// A call carrying no token at all.
    #[must_use]
    pub fn anonymous(tool: &str) -> Self {
        Self {
            tool: tool.to_owned(),
            args: json!({}),
            headers: Vec::new(),
        }
    }

    /// The tool arguments.
    #[must_use]
    pub fn args(mut self, args: Value) -> Self {
        self.args = args;
        self
    }

    /// Thread `X-Session-Id`.
    #[must_use]
    pub fn session(self, id: &str) -> Self {
        self.header("x-session-id", id)
    }

    /// Echo a pending elicitation's id, as a retry does.
    #[must_use]
    pub fn elicitation_id(self, id: &str) -> Self {
        self.header("x-policy-elicitation-id", id)
    }

    /// Ask for the elicitation's status without applying the call.
    #[must_use]
    pub fn peek(self) -> Self {
        self.header("x-policy-elicitation-peek", "true")
    }

    /// Any other request header. A later value for a name replaces an
    /// earlier one, including the tokens [`Call::new`] set.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }

    /// The call's own credentials, planted: the user token and the agent
    /// token, under `user token` and `client token`.
    #[must_use]
    pub fn planted(&self) -> Planted {
        let inbound = self.inbound();
        let mut planted = Planted::new();
        if let Some(token) = inbound.get("x-user-token") {
            planted.plant("user token", token.clone());
        }
        if let Some(token) = inbound.get("authorization") {
            planted.plant(
                "client token",
                token.strip_prefix("Bearer ").unwrap_or(token),
            );
        }
        planted
    }

    /// The headers the gateway receives, names lowercased.
    fn inbound(&self) -> HashMap<String, String> {
        let mut out = HashMap::from([("content-type".to_owned(), "application/json".to_owned())]);
        out.extend(self.headers.iter().cloned());
        out
    }
}

/// Where a denied call stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Identity, in the header phase or the body phase. No CMF hook ran.
    Identity,
    /// `cmf.tool_pre_invoke`. The upstream was not called.
    Request,
    /// The response phase. The upstream was called.
    Response,
}

/// What one call did.
#[derive(Debug)]
pub struct Outcome {
    issued_tokens: IssuedTokens,
    /// `None` when the call was allowed through both phases.
    pub denied_at: Option<Stage>,
    /// The deny's violation, as praxis would put it on the wire.
    pub violation: Option<PluginViolation>,
    /// The request the upstream received, when it was called.
    pub upstream: Option<UpstreamRequest>,
    /// The JSON-RPC body the client receives after the response phase, when
    /// the upstream was called and the response phase allowed it.
    pub response: Option<Value>,
    /// The response headers the client receives.
    pub response_headers: BTreeMap<String, String>,
    /// Every plugin error the call's pipelines recorded.
    pub errors: Vec<PluginErrorRecord>,
    /// The logs and audit records emitted during the call, on a
    /// current-thread runtime. Empty on a multi-thread one, where plugins
    /// run on other workers: read [`capture::CapturingRuntime::events`].
    pub events: Events,
}

impl Outcome {
    /// Whether the call went through both phases.
    #[must_use]
    pub fn allowed(&self) -> bool {
        self.denied_at.is_none()
    }

    /// The deny's violation code.
    #[must_use]
    pub fn violation_code(&self) -> Option<&str> {
        self.violation.as_ref().map(|v| v.code.as_str())
    }

    /// The protocol code a deny carries in place of the generic `-32001`,
    /// such as `-32120` for a pending elicitation.
    #[must_use]
    pub fn proto_error_code(&self) -> Option<i64> {
        self.violation.as_ref().and_then(|v| v.proto_error_code)
    }

    /// One entry of the deny's `details`, which praxis merges into the
    /// JSON-RPC `error.data`.
    #[must_use]
    pub fn detail(&self, key: &str) -> Option<&Value> {
        self.violation.as_ref().and_then(|v| v.details.get(key))
    }

    /// The tool's result record: the response's single text part parsed as
    /// JSON, which is how `server.py` answers.
    #[must_use]
    pub fn record(&self) -> Option<Value> {
        let text = self.response.as_ref()?["result"]["content"][0]["text"].as_str()?;
        serde_json::from_str(text).ok()
    }

    /// Assert no planted secret reached anything the caller or an operator
    /// observes: the violation, the errors, the response and its headers,
    /// the logs and the audit records. The upstream request is exempt,
    /// since delivering credentials there is the point. Includes every OAuth
    /// token returned by this host's dependencies, across calls and denials.
    ///
    /// # Panics
    ///
    /// Naming the place and the labels of every secret found.
    pub fn assert_no_leaks(&self, planted: &Planted) {
        let mut all = self.issued_tokens.snapshot();
        all.extend(planted);
        let planted = &all;
        if let Some(v) = &self.violation {
            planted.assert_absent_json(
                "the violation",
                &serde_json::to_value(v).unwrap_or_default(),
            );
        }
        for error in &self.errors {
            planted.assert_absent_json(
                "a pipeline error",
                &serde_json::to_value(error).unwrap_or_default(),
            );
        }
        if let Some(response) = &self.response {
            planted.assert_absent_json("the response", response);
        }
        planted.assert_absent_json(
            "the response headers",
            &serde_json::to_value(&self.response_headers).unwrap_or_default(),
        );
        planted.assert_absent_events(&self.events);
    }
}

// -----------------------------------------------------------------------------
// The host
// -----------------------------------------------------------------------------

/// How to build a [`RefHost`].
#[derive(Default)]
pub struct HostBuilder {
    transport: FakeTransport,
    session_stores: Vec<Arc<dyn SessionStoreFactory>>,
    live_bases: Vec<String>,
}

impl std::fmt::Debug for HostBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostBuilder")
            .field("session_stores", &self.session_stores.len())
            .field("live_bases", &self.live_bases)
            .finish_non_exhaustive()
    }
}

impl HostBuilder {
    /// Start from `transport`. Its responders are registered before the
    /// host's own, so they win: a test scripts a failing endpoint with a
    /// responder for that URL, since a queued reply loses to a responder.
    /// A queued JWKS reply is consumed during initialization, then followed
    /// by the host's JWKS reply on refresh. Script JWKS, exchange and CIBA
    /// faults with `respond_with` instead.
    #[must_use]
    pub fn transport(mut self, transport: FakeTransport) -> Self {
        self.transport = transport;
        self
    }

    /// Register a session-store factory a fixture's `global.session_store`
    /// can select by `kind`.
    #[must_use]
    pub fn session_store(mut self, factory: Arc<dyn SessionStoreFactory>) -> Self {
        self.session_stores.push(factory);
        self
    }

    /// Send requests under these base URLs over a real socket instead of
    /// the scripted transport. See [`live`].
    #[must_use]
    pub fn live(mut self, bases: Vec<String>) -> Self {
        self.live_bases = bases;
        self
    }

    /// Load `yaml` and initialize, as `PolicyFilter::new` does.
    ///
    /// The transport answers the JWKS, an honest token exchange and the
    /// CIBA OP, after whatever the builder's transport already scripts.
    /// Vault is registered on the same transport.
    ///
    /// # Errors
    ///
    /// When the document fails to load or the engine fails to initialize.
    pub async fn start(self, yaml: &str) -> Result<RefHost, Box<PluginError>> {
        let ciba = Ciba::new();
        let transport = Arc::new(ciba.install(Exchange::Honest.install(self.transport.json(
            idp::JWKS_URL,
            200,
            &idp::jwks().to_string(),
        ))));
        let engine = engine(self.session_stores);
        let views = Views::default();
        engine.register_factory(PROBE_KIND, Box::new(HeaderProbeFactory(Arc::clone(&views))));
        let egress: Arc<dyn HttpTransport> = if self.live_bases.is_empty() {
            transport.clone()
        } else {
            Arc::new(live::Split::new(self.live_bases, transport.clone()))
        };
        let issued_tokens = IssuedTokens::default();
        let egress = issued_tokens.record(egress);
        engine.set_http_transport(egress.clone());
        engine.set_secret_providers(registry_with_vault(egress));
        engine.load_config_yaml(yaml)?;
        engine.initialize().await?;

        // The engine does not keep the document, so praxis re-reads it.
        let config = parse_config(yaml)?;
        let request_governed = GovernedNames::from_config(&config, Direction::Request);
        let response_governed = GovernedNames::from_config(&config, Direction::Response);
        let response_hook =
            engine.has_hooks_for(HOOK_HTTP_RESPONSE) || !response_governed.is_empty();
        Ok(RefHost {
            issued_tokens,
            engine,
            transport,
            ciba,
            upstream: Upstream::new(),
            views,
            request_governed,
            response_governed,
            response_hook,
            next_id: AtomicU64::new(1),
        })
    }
}

/// A started engine, its scripted dependencies and the upstream, driven one
/// call at a time.
pub struct RefHost {
    issued_tokens: IssuedTokens,
    engine: Arc<PolicyEngine>,
    transport: Arc<FakeTransport>,
    ciba: Ciba,
    upstream: Upstream,
    views: Views,
    request_governed: GovernedNames,
    response_governed: GovernedNames,
    response_hook: bool,
    next_id: AtomicU64,
}

impl std::fmt::Debug for RefHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefHost")
            .field("transport", &self.transport)
            .field("upstream", &self.upstream)
            .finish_non_exhaustive()
    }
}

/// Accumulates one call's pipeline errors.
#[derive(Default)]
struct Trace {
    errors: Vec<PluginErrorRecord>,
}

impl Trace {
    fn keep(&mut self, result: PipelineResult) -> PipelineResult {
        self.errors.extend(result.errors.iter().cloned());
        result
    }
}

/// Complete background plugin work before this call's capture guard closes.
async fn wait_background(tasks: BackgroundTasks) {
    let errors = tasks.wait_for_background_tasks().await;
    assert!(errors.is_empty(), "background plugin task panicked");
}

impl RefHost {
    /// A builder, for a host whose transport or session store a test
    /// scripts.
    #[must_use]
    pub fn builder() -> HostBuilder {
        HostBuilder::default()
    }

    /// A hermetic host running `fixture`.
    ///
    /// # Panics
    ///
    /// When the fixture fails to load or initialize.
    pub async fn hermetic(fixture: Fixture) -> Self {
        Self::builder()
            .start(fixture.hermetic())
            .await
            .unwrap_or_else(|e| panic!("{} fixture fails to start: {e}", fixture.name()))
    }

    /// A host running `fixture` against the live `targets`.
    ///
    /// # Panics
    ///
    /// When the fixture fails to load or initialize.
    pub async fn live(fixture: Fixture, targets: Targets<'_>) -> Self {
        Self::builder()
            .live(targets.bases())
            .start(&fixture.live(targets))
            .await
            .unwrap_or_else(|e| panic!("live {} fixture fails to start: {e}", fixture.name()))
    }

    /// The scripted transport every dependency call went through. In live
    /// mode, calls to a live base bypass it.
    #[must_use]
    pub fn transport(&self) -> &FakeTransport {
        &self.transport
    }

    /// The scripted CIBA OP, for advancing an approval.
    #[must_use]
    pub fn ciba(&self) -> &Ciba {
        &self.ciba
    }

    /// The upstream stand-in and its request log.
    #[must_use]
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// What every header-probe invocation was shown, as `(hook, headers)`.
    #[must_use]
    pub fn header_views(&self) -> Vec<(String, BTreeMap<String, String>)> {
        self.views
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Invoke one identity hook and retain its pipeline diagnostics.
    async fn resolve_identity(
        &self,
        headers: &HashMap<String, String>,
        entity_type: &str,
        entity_name: &str,
        trace: &mut Trace,
    ) -> Result<IdentityPayload, Option<PluginViolation>> {
        let mut ext = Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some(entity_type.to_owned()),
                entity_name: Some(entity_name.to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        };
        ext.http = Some(Arc::new(mcp::http_extension(headers)));
        let payload =
            IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers.clone());
        let (result, bg) = self
            .engine
            .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, ext, None)
            .await;
        wait_background(bg).await;
        let result = trace.keep(result);
        if !result.continue_processing {
            return Err(result.violation);
        }
        IdentityPayload::from_pipeline_result(&result).ok_or(None)
    }

    /// Drive `call` through both phases.
    pub async fn call(&self, call: Call) -> Outcome {
        // A thread-local sink sees a call's spawned plugins only when they
        // share its thread.
        let current_thread = tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread);
        let (events, _guard) = if current_thread {
            let (events, guard) = capture::capturing();
            (events, Some(guard))
        } else {
            (Events::default(), None)
        };
        let mut trace = Trace::default();
        let mut outcome = Outcome {
            issued_tokens: self.issued_tokens.clone(),
            denied_at: None,
            violation: None,
            upstream: None,
            response: None,
            response_headers: BTreeMap::new(),
            errors: Vec::new(),
            events: events.clone(),
        };
        let deny = |mut outcome: Outcome, stage, violation, trace: Trace| {
            outcome.denied_at = Some(stage);
            outcome.violation = violation;
            outcome.errors = trace.errors;
            outcome
        };

        let inbound = call.inbound();
        let tool = call.tool.as_str();

        // Header phase: the early identity gate.
        if let Err(v) = self
            .resolve_identity(&inbound, ENTITY_HTTP, ENTITY_NAME_GLOBAL, &mut trace)
            .await
        {
            return deny(outcome, Stage::Identity, v, trace);
        }

        // Body phase.
        let identity = match self
            .resolve_identity(&inbound, ENTITY_TOOL, tool, &mut trace)
            .await
        {
            Ok(identity) => identity,
            Err(v) => return deny(outcome, Stage::Identity, v, trace),
        };
        let session = inbound.get("x-session-id").map(String::as_str);
        let identity_ext = mcp::tool_extensions(
            identity.apply_to_extensions(Extensions::default()),
            tool,
            &inbound,
            session,
        );

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = mcp::tool_call_body(id, tool, &call.args);
        let call_id = id_string(&body);
        let (pre, bg) = self
            .engine
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                mcp::tool_call(&call_id, tool, &call.args),
                identity_ext.clone(),
                None,
            )
            .await;
        wait_background(bg).await;
        let pre = trace.keep(pre);
        if !pre.continue_processing {
            return deny(outcome, Stage::Request, pre.violation, trace);
        }

        let mut queued = Queued::default();
        attach_delegated_tokens(&mut queued, pre.modified_extensions.as_ref());
        apply_request_assertions(
            &mut queued,
            &inbound,
            pre.modified_extensions.as_ref(),
            &self.request_governed,
        );
        let body = match modified_message(&pre) {
            Some(message) => rewrite_request(body, message),
            None => body,
        };

        // The upstream.
        let forwarded = queued.forwarded(&inbound);
        let (reply, seen) = self.upstream.exchange(&body, &forwarded);
        outcome.upstream = seen;
        outcome.response_headers =
            BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]);

        // Response headers.
        if self.response_hook {
            let mut ext = identity_ext.clone();
            ext.meta = Some(Arc::new(MetaExtension {
                entity_type: Some(ENTITY_HTTP.to_owned()),
                entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
                ..Default::default()
            }));
            let mut http = mcp::http_extension(&inbound);
            http.response_headers = outcome.response_headers.clone().into_iter().collect();
            http.status = Some(200);
            ext.http = Some(Arc::new(http));
            let (result, bg) = self
                .engine
                .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, ext, None)
                .await;
            wait_background(bg).await;
            let result = trace.keep(result);
            if !result.continue_processing {
                return deny(outcome, Stage::Response, result.violation, trace);
            }
            apply_response_assertions(
                &mut outcome.response_headers,
                result.modified_extensions.as_ref(),
                &self.response_governed,
            );
        }

        // Response body.
        let Some(payload) = response_content(&reply, tool, &call_id) else {
            outcome.response = Some(reply);
            outcome.errors = trace.errors;
            return outcome;
        };
        let mut post_ext = identity_ext;
        if let Some(http) = pre
            .modified_extensions
            .as_ref()
            .and_then(|e| e.http.clone())
        {
            post_ext.http = Some(http);
        }
        let (post, bg) = self
            .engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, payload, post_ext, None)
            .await;
        wait_background(bg).await;
        let post = trace.keep(post);
        if !post.continue_processing {
            return deny(outcome, Stage::Response, post.violation, trace);
        }
        outcome.response = Some(match modified_message(&post) {
            Some(message) => rewrite_response(reply, message),
            None => reply,
        });
        outcome.errors = trace.errors;
        outcome
    }
}
