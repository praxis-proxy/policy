// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// CMF -> OCSF mapping, the running-code form of the AID-EMIT-1 field map.
// Each block below names the source slot it implements.
//
// Design choices:
//   * The event is built as a serde_json::Value rather than hand-rolled
//     OCSF structs: OCSF object shapes still move release to release, and
//     a Value keeps the mapping honest about what is proposed vs merged.
//   * Fields with no native OCSF home go under `unmapped` when
//     cfg.include_gap_fields is set. That is correct OCSF practice and it
//     makes the gaps self-documenting in the emitted evidence.
//
// OCSF modeling: `ai_operation` is a profile, not a class. It contributes
// `ai_agent` / `ai_model` / `message_context` to existing base classes in
// the Application category (6). The host class is API Activity (6003), and
// activity ids follow API Activity's own enum (CRUD plus 99 Other), not a
// bespoke one: per the OCSF enum contract a known id carries the normalized
// caption as activity_name, and source-defined names ride with 99.

//! The CMF to OCSF mapping and the decision overlay.

use serde_json::{Map, Value, json};

use praxis_policy_core::cmf::{ContentPart, MessagePayload};
use praxis_policy_core::decision::{DecisionLog, PluginAction, Verdict};
use praxis_policy_core::hooks::payload::Extensions;

use crate::config::OcsfAuditConfig;

// --- OCSF identifiers ---
const SCHEMA_VERSION: &str = "1.9.0";
const CATEGORY_UID_APPLICATION: u32 = 6;
/// API Activity, the Application-category class hosting the
/// `ai_operation` profile.
const CLASS_UID_API_ACTIVITY: u32 = 6003;
const SEVERITY_INFORMATIONAL: u32 = 1;

/// OCSF activity on API Activity (6003): 0 Unknown, 1 Create, 2 Read,
/// 3 Update, 4 Delete, 99 Other.
///
/// Mapping convention:
///
/// * Read Resource / Invoke Prompt: 2 (Read)
/// * Invoke Tool with `readOnlyHint: true`: 2 (Read)
/// * Invoke Tool otherwise: 99 with `activity_name` "Invoke Tool" (the
///   mapping cannot honestly claim Create/Update/Delete without knowing
///   the operation; `destructiveHint` stays context, not a Delete mapping)
/// * Completion: 99 with `activity_name` "Completion"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// 0: no payload, or content this mapping does not classify.
    Unknown,
    /// 2: a resource read, a prompt, or a tool with `readOnlyHint`.
    Read,
    /// 99 (Other) with a source-defined `activity_name`, per the OCSF
    /// enum contract.
    Other(&'static str),
}

impl Activity {
    fn id(self) -> u32 {
        match self {
            Activity::Unknown => 0,
            Activity::Read => 2,
            Activity::Other(_) => 99,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Activity::Unknown => "Unknown",
            // Known id -> normalized enum caption, never a source-defined
            // string.
            Activity::Read => "Read",
            Activity::Other(n) => n,
        }
    }
}

/// True when the MCP tool metadata for this invocation carries
/// `readOnlyHint: true`. When the content part names the tool, the hint
/// only applies if the MCP slot describes that same tool.
fn tool_read_only_hint(ext: &Extensions, call_name: Option<&str>) -> bool {
    let Some(mcp) = ext.mcp.as_ref() else {
        return false;
    };
    let Some(tool) = mcp.tool.as_ref() else {
        return false;
    };
    if let Some(name) = call_name
        && tool.name != name
    {
        return false;
    }
    matches!(
        tool.annotations.get("readOnlyHint"),
        Some(Value::Bool(true))
    )
}

/// Infer the OCSF activity from the message content parts (the typed
/// handler does not receive the hook name, so the classification comes
/// from content, which is also the more robust source) plus the MCP tool
/// annotations.
pub fn activity_of(payload: &MessagePayload, ext: &Extensions) -> Activity {
    for part in &payload.message.content {
        match part {
            ContentPart::ToolCall { content } => {
                return if tool_read_only_hint(ext, Some(&content.name)) {
                    Activity::Read
                } else {
                    Activity::Other("Invoke Tool")
                };
            },
            ContentPart::ToolResult { .. } => {
                // Result side of the same invocation; the result part
                // carries no tool name, so the MCP slot speaks for it.
                return if tool_read_only_hint(ext, None) {
                    Activity::Read
                } else {
                    Activity::Other("Invoke Tool")
                };
            },
            ContentPart::PromptRequest { .. }
            | ContentPart::PromptResult { .. }
            | ContentPart::Resource { .. }
            | ContentPart::ResourceRef { .. } => return Activity::Read,
            _ => {},
        }
    }
    // Plain assistant text / thinking with completion metadata = LLM output.
    if payload
        .message
        .content
        .iter()
        .any(|p| matches!(p, ContentPart::Text { .. } | ContentPart::Thinking { .. }))
    {
        return Activity::Other("Completion");
    }
    Activity::Unknown
}

/// Build the OCSF event (the inner event, pre-attestation).
/// `now_rfc3339` is injected so the caller controls the clock (testable).
pub fn build_ai_operation(
    payload: &MessagePayload,
    ext: &Extensions,
    cfg: &OcsfAuditConfig,
    now_rfc3339: &str,
) -> Value {
    build_event(Some(payload), ext, cfg, now_rfc3339)
}

/// Payload-optional form of [`build_ai_operation`]. The decision-audit
/// sink fires for every hook family, and a non-CMF dispatch (delegation,
/// identity) carries no `MessagePayload`; the event is then built from
/// the extensions alone, with `activity_id` 0 (Unknown) and no
/// tool/status coordinates. The extension-derived blocks (actor,
/// `ai_agent`, `ai_model`, delegation, gap fields) are identical either
/// way.
pub fn build_event(
    payload: Option<&MessagePayload>,
    ext: &Extensions,
    cfg: &OcsfAuditConfig,
    now_rfc3339: &str,
) -> Value {
    let activity = payload
        .map(|p| activity_of(p, ext))
        .unwrap_or(Activity::Unknown);

    let mut ev = Map::new();

    // --- base event ---------------------------------------------------
    ev.insert("activity_id".into(), json!(activity.id()));
    ev.insert("activity_name".into(), json!(activity.name()));
    ev.insert("category_uid".into(), json!(CATEGORY_UID_APPLICATION));
    ev.insert("class_uid".into(), json!(CLASS_UID_API_ACTIVITY));
    ev.insert(
        "type_uid".into(),
        json!(CLASS_UID_API_ACTIVITY * 100 + activity.id()),
    );
    ev.insert("severity_id".into(), json!(SEVERITY_INFORMATIONAL));
    ev.insert("time".into(), json!(now_rfc3339));

    // security_control profile defaults: a passive post-hook observation
    // is action_id 3 (Observed) / disposition_id 17 (Logged). When this
    // event is built by the decision-audit sink, `apply_decision`
    // overwrites these with the pipeline's actual ruling (Denied /
    // Modified / Allowed): a post-hook observer structurally cannot see
    // a denial, which is exactly what the sink path covers.
    ev.insert("action_id".into(), json!(3));
    ev.insert("action".into(), json!("Observed"));
    ev.insert("disposition_id".into(), json!(17));
    ev.insert("disposition".into(), json!("Logged"));

    // metadata + product (field map: `meta`/`request` -> base metadata)
    let mut profiles = vec!["ai_operation", "security_control"];
    if cfg.chain {
        // `attestation_list` is the record_integrity profile, in 1.9.
        profiles.push("record_integrity");
    }
    let mut metadata = json!({
        "version": SCHEMA_VERSION,
        "profiles": profiles,
        "product": { "name": cfg.product_name, "vendor_name": cfg.vendor_name },
    });

    // correlation (field map: AgentExtension.conversation_id ->
    // metadata.correlation_uid). The correlation key must be stable
    // across every event of one run, and conversation_id is the run.
    // Per-event ids (request_id, tool_call_id) correlate nothing;
    // tool_call_id rides at api.request.uid instead (see
    // attach_capability_coords). `correlation_uid` is an attribute of
    // `metadata`, not of base_event.
    if let (Some(cid), Some(m)) = (correlation_uid(ext), metadata.as_object_mut()) {
        m.insert("correlation_uid".into(), json!(cid));
    }
    ev.insert("metadata".into(), metadata);

    // status (field map: ToolResult.is_error -> status)
    if let Some(is_err) = payload.and_then(first_tool_error) {
        ev.insert("status_id".into(), json!(if is_err { 2 } else { 1 })); // 1=Success 2=Failure
    }

    // --- actor / user (field map: SecurityExtension.SubjectExtension) -
    if let Some(sec) = ext.security.as_ref()
        && let Some(s) = &sec.subject
    {
        // roles/teams are HashSets: sort so the emitted event is
        // canonical and the fingerprint is reproducible.
        let mut groups: Vec<&String> = s.teams.iter().collect();
        groups.sort_unstable();
        let mut roles: Vec<&String> = s.roles.iter().collect();
        roles.sort_unstable();
        ev.insert(
            "actor".into(),
            json!({
                "user": {
                    "uid": s.id,
                    "groups": groups,
                },
                // roles/permissions ride along as enrichment.
                "roles": roles,
            }),
        );
    }

    // --- ai_agent (field map: AgentExtension) -------------------------
    if let Some(ag) = ext.agent.as_ref() {
        ev.insert(
            "ai_agent".into(),
            json!({
                "uid": ag.agent_id,
                "instance_uid": ag.session_id,
                // multi-agent lineage
                "parent_uid": ag.parent_agent_id,
                "conversation_uid": ag.conversation_id,
                "turn": ag.turn,
            }),
        );
    }

    // --- ai_model + message_context (field map: LLMExtension /
    //     CompletionExtension; mostly merged) -------------------------
    if let Some(comp) = ext.completion.as_ref() {
        let mut mctx = Map::new();
        if let Some(tok) = &comp.tokens {
            mctx.insert("prompt_tokens".into(), json!(tok.input_tokens));
            mctx.insert("completion_tokens".into(), json!(tok.output_tokens));
            mctx.insert("total_tokens".into(), json!(tok.total_tokens));
        }
        if !mctx.is_empty() {
            ev.insert("message_context".into(), Value::Object(mctx));
        }
        if let Some(model) = &comp.model {
            ev.insert("ai_model".into(), json!({ "name": model }));
        }
        if let Some(ms) = comp.latency_ms {
            ev.insert("duration".into(), json!(ms)); // base `duration` (ms)
        }
    }

    // --- delegation (field map: DelegationExtension) ------------------
    if let Some(del) = ext.delegation.as_ref()
        && (del.delegated || !del.chain.is_empty())
    {
        let chain: Vec<Value> = del
            .chain
            .iter()
            .map(|hop| {
                json!({
                    "subject_uid": hop.subject_id,
                    "audience": hop.audience,
                    "scopes_granted": hop.scopes_granted,
                    "ttl_seconds": hop.ttl_seconds,
                    "timestamp": hop.timestamp.to_rfc3339(),
                })
            })
            .collect();
        ev.insert(
            "delegation".into(),
            json!({
                "depth": del.depth,
                "origin_subject_uid": del.origin_subject_id,
                "actor_subject_uid": del.actor_subject_id,
                "chain": chain,
            }),
        );
    }

    // --- tool/prompt/resource coordinates from content ----------------
    if let Some(p) = payload {
        attach_capability_coords(&mut ev, p);
    }

    // --- the gaps -> unmapped -----------------------------------------
    if cfg.include_gap_fields {
        let unmapped = build_unmapped_gaps(ext);
        if let Value::Object(m) = &unmapped
            && !m.is_empty()
        {
            ev.insert("unmapped".into(), unmapped);
        }
    }

    Value::Object(ev)
}

/// Gap fields with no native OCSF home yet. Emitting them under
/// `unmapped` keeps the evidence complete and documents the gaps.
fn build_unmapped_gaps(ext: &Extensions) -> Value {
    let mut g = Map::new();

    // gap 3: completion.stop_reason
    if let Some(comp) = ext.completion.as_ref()
        && let Some(sr) = &comp.stop_reason
    {
        g.insert(
            "cmf.completion.stop_reason".into(),
            json!(format!("{sr:?}")),
        );
    }

    // gap 1: mcp tool/resource/prompt metadata
    if let Some(mcp) = ext.mcp.as_ref() {
        // MCPExtension = { tool, resource, prompt }. Serialized whole; each
        // sub-object carries server_id/namespace/schemas.
        g.insert("cmf.mcp".into(), json!(mcp));
    }

    // gap 2: framework context
    if let Some(fw) = ext.framework.as_ref() {
        g.insert(
            "cmf.framework".into(),
            json!({
                "framework": fw.framework,
                "framework_version": fw.framework_version,
                "node_id": fw.node_id,
                "graph_id": fw.graph_id,
            }),
        );
    }

    // gap 4: monotonic security labels (taint set)
    if let Some(sec) = ext.security.as_ref() {
        // SecurityExtension.labels: MonotonicSet<String> (add-only taint).
        let labels = security_labels(sec);
        if !labels.is_empty() {
            g.insert("cmf.security.labels".into(), json!(labels));
        }
    }

    // gap 5: workload attestation (SPIFFE), partial OCSF home
    if let Some(wl) = caller_workload(ext) {
        g.insert("cmf.workload_identity".into(), wl);
    }

    // gap 6: per-request id, the join key for a signed mandate draw
    // receipt. A receipt names the request's correlation id; carrying
    // RequestExtension.request_id here lets a receipt-in-hand reconcile
    // against the OCSF stream. Deliberately not metadata.correlation_uid,
    // which is reserved for the conversation-stable key (per-request ids
    // correlate nothing across events). The token's revocation_id needs
    // no event field: the receipt itself names it, and correlation joins
    // the two.
    if let Some(req) = ext.request.as_ref()
        && let Some(rid) = &req.request_id
    {
        g.insert("cmf.request.request_id".into(), json!(rid));
    }

    Value::Object(g)
}

// ---------------------------------------------------------------------
// Decision overlay. Applies the pipeline's ruling (the engine's
// DecisionLog, handed to audit sinks at every verdict) onto an event built
// by `build_event`, replacing the passive Observed/Logged defaults with
// what enforcement actually did.
// ---------------------------------------------------------------------

/// A step's violation as the `detail` member: the machine code and the
/// reason always, the free-text description and structured details only
/// when the plugin set them. The plugin name is not repeated — the step
/// already carries it.
fn violation_detail(v: &praxis_policy_core::error::PluginViolation) -> Value {
    let mut out = Map::new();
    out.insert("code".into(), json!(v.code));
    out.insert("reason".into(), json!(v.reason));
    if let Some(description) = &v.description {
        out.insert("description".into(), json!(description));
    }
    if !v.details.is_empty() {
        out.insert("details".into(), json!(v.details));
    }
    Value::Object(out)
}

/// The stable, queryable rendering of one [`PluginAction`]. Deliberately
/// a fixed `snake_case` vocabulary (not `Debug` formatting) so SIEM
/// queries survive upstream enum renames; `error` carries its message
/// beside the action, not inside it.
fn action_str(a: &PluginAction) -> &'static str {
    match a {
        PluginAction::Allowed => "allowed",
        PluginAction::Denied(_) => "denied",
        PluginAction::ModifiedPayload => "modified_payload",
        PluginAction::ModifiedExtensions => "modified_extensions",
        // Never rendered as an allow: the step reflects the plugin's
        // actual decision (a suppressed Transform-phase block), per the
        // seam's contract on `PluginAction::DenyIgnored`.
        PluginAction::DenyIgnored(_) => "deny_ignored",
        // Intentional cancellation (a concurrent sibling short-circuited
        // the phase) — distinct from `error` so it doesn't read as a crash.
        PluginAction::Aborted => "aborted",
        PluginAction::Error(_) => "error",
    }
}

/// Overlay one finalized [`DecisionLog`] onto an event from
/// [`build_event`], turning a passive observation into a decision record:
///
/// * **Verdict to `security_control`.** Deny: `action_id` 2 (Denied) /
///   `disposition_id` 2 (Blocked), with the violation surfaced at
///   `status_code` / `status_detail` (`status_id` 2), so a fail-closed
///   panic arrives as `status_code: "plugin_panic"`, distinguishable
///   from an ordinary `plugin_error` by code. Allow after a payload or
///   extension modification: `action_id` 4 (Modified) /
///   `disposition_id` 1 (Allowed). Plain allow: 1 / 1. `activity_*` /
///   `type_uid` are untouched: they describe the operation observed, the
///   action describes what the control did about it.
/// * **Everything else to `unmapped.cpex.*`**, inside the hashed bytes
///   when chaining is on, so the decision facts are tamper-evident:
///   the ordered per-plugin steps (full vocabulary including
///   `deny_ignored` and `aborted`), the invocation span, entry-taint
///   labels, content provenance (input/output digests), and the
///   audit-stream stamps (`epoch` / `stream_id` / `stream_seq` /
///   `emission_seq`, the completeness and ordering claims from the seam).
pub fn apply_decision(ev: &mut Value, decisions: &DecisionLog) {
    let Some(map) = ev.as_object_mut() else {
        return;
    };

    let modified = decisions.steps().iter().any(|s| {
        matches!(
            s.action,
            PluginAction::ModifiedPayload | PluginAction::ModifiedExtensions
        )
    });

    let (action_id, action, disposition_id, disposition, verdict_json) = match decisions.verdict() {
        Some(Verdict::Deny(v)) => {
            // The violation is the forensic core of a deny: surface it
            // on the base-event status fields where OCSF consumers
            // already look, not only inside the unmapped block.
            map.insert("status_id".into(), json!(2)); // Failure
            map.insert("status_code".into(), json!(v.code));
            map.insert("status_detail".into(), json!(v.reason));
            (
                2,
                "Denied",
                2,
                "Blocked",
                json!({ "deny": { "code": v.code, "reason": v.reason } }),
            )
        },
        Some(Verdict::Allow) if modified => (4, "Modified", 1, "Allowed", json!("allow")),
        Some(Verdict::Allow) => (1, "Allowed", 1, "Allowed", json!("allow")),
        // The seam finalizes before invoking sinks; `None` would mean a
        // contract break upstream. Keep the Observed/Logged defaults and
        // say so rather than claim a ruling that never happened.
        None => (3, "Observed", 17, "Logged", json!("pending")),
    };
    map.insert("action_id".into(), json!(action_id));
    map.insert("action".into(), json!(action));
    map.insert("disposition_id".into(), json!(disposition_id));
    map.insert("disposition".into(), json!(disposition));

    // --- unmapped.cpex.*, merged into any existing gap fields ---------
    let un = map
        .entry("unmapped")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(un) = un.as_object_mut() else { return };

    let steps: Vec<Value> = decisions
        .steps()
        .iter()
        .map(|s| {
            let mut step = Map::new();
            step.insert("plugin".into(), json!(s.plugin_name));
            step.insert("phase".into(), json!(s.phase.to_string()));
            step.insert("action".into(), json!(action_str(&s.action)));
            if let PluginAction::Error(e) = &s.action {
                step.insert("error".into(), json!(e));
            }
            // The violation behind a `denied` / `deny_ignored` step. For
            // `deny_ignored` this is the only place the objection's code
            // survives, since no verdict names it. Same member shape as the
            // `audit-logger` reference sink.
            if let PluginAction::Denied(v) | PluginAction::DenyIgnored(v) = &s.action {
                step.insert("detail".into(), violation_detail(v));
            }
            Value::Object(step)
        })
        .collect();
    let mut decision = Map::new();
    decision.insert("verdict".into(), verdict_json);
    decision.insert("steps".into(), Value::Array(steps));
    // Flagged at the top level of the block (not only discoverable by
    // scanning the steps array) so "every suppressed deny" is a flat
    // SIEM query: the seam's contract is that this must never read as
    // a plain allow.
    if decisions
        .steps()
        .iter()
        .any(|s| matches!(s.action, PluginAction::DenyIgnored(_)))
    {
        decision.insert("deny_ignored".into(), json!(true));
    }
    un.insert("cpex.decision".into(), Value::Object(decision));

    // The invocation's node identity in the decision graph (W3C ids;
    // child-span model, where the parent is the causal edge).
    if let Some(span) = decisions.span() {
        un.insert(
            "cpex.span".into(),
            json!({
                "trace_id": span.trace_id,
                "span_id": span.span_id,
                "parent_span_id": span.parent_span_id,
            }),
        );
    }

    // Entry-side taint. The final labels already ride at
    // `cmf.security.labels` (gap 4); the difference is what the
    // pipeline added.
    if !decisions.input_labels().is_empty() {
        un.insert(
            "cpex.taint.input_labels".into(),
            json!(decisions.input_labels()),
        );
    }

    // Content provenance, gated on the executor having captured an entry
    // digest (`capture_content_provenance` on). Digests only, and both are
    // the engine's: it takes them at entry and at emission under the
    // deployment's content provenance key and puts them on the log, so
    // this sink never hashes and never holds the key. Each digest names
    // its scheme and key id (`hmac-sha256:<key_id>:<hex>`, or
    // `sha256:<hex>` under `content_provenance_key: unkeyed`) and travels
    // as an opaque string. An explicit null for the output digest, not an
    // absent key, when the engine recorded none, so the record says "not
    // hashed" rather than leaving the reader to guess.
    if let Some(input_hash) = decisions.input_hash() {
        un.insert(
            "cpex.content".into(),
            json!({ "input_hash": input_hash, "output_hash": decisions.output_hash() }),
        );
    }

    // Audit-stream identity + counters, verbatim from the seam:
    // `stream_seq` is the completeness claim (dense within
    // (epoch, stream_id)); `emission_seq` is ordering-only (sparse for a
    // single-stream consumer by design). Inside the hashed bytes, so a
    // post-hoc renumbering breaks the fingerprint chain.
    if decisions.stream_seq().is_some() {
        un.insert(
            "cpex.stream".into(),
            json!({
                "epoch": decisions.epoch(),
                "stream_id": decisions.stream_id(),
                "stream_seq": decisions.stream_seq(),
                "emission_seq": decisions.emission_seq(),
            }),
        );
    }
}

// ---------------------------------------------------------------------
// Helpers: small, content-shape-dependent extractors.
// ---------------------------------------------------------------------

fn correlation_uid(ext: &Extensions) -> Option<String> {
    // correlation_uid must be multi-event-stable, so it mirrors the run
    // id (AgentExtension.conversation_id), not request_id or
    // tool_call_id, which are per-event unique and correlate nothing.
    // Session-grain grouping stays a join on ai_agent.instance_uid
    // (session_id); the run is the primary forensic grain a SIEM keys on.
    ext.agent.as_ref()?.conversation_id.clone()
}

fn first_tool_error(payload: &MessagePayload) -> Option<bool> {
    for part in &payload.message.content {
        if let ContentPart::ToolResult { content } = part {
            return Some(content.is_error);
        }
    }
    None
}

fn attach_capability_coords(ev: &mut Map<String, Value>, payload: &MessagePayload) {
    for part in &payload.message.content {
        match part {
            ContentPart::ToolCall { content } => {
                ev.insert(
                    "tool".into(),
                    json!({
                        "name": content.name,
                        "uid": content.tool_call_id,
                        "namespace": content.namespace,
                    }),
                );
                // The per-call id's home is api.request.uid (one request
                // is one tool call), not correlation_uid.
                ev.insert(
                    "api".into(),
                    json!({ "request": { "uid": content.tool_call_id } }),
                );
                return;
            },
            ContentPart::Resource { content } => {
                ev.insert(
                    "resource".into(),
                    json!({ "uri": content.uri, "type": format!("{:?}", content.resource_type) }),
                );
                return;
            },
            _ => {},
        }
    }
}

// The following two isolate the less-obvious accessor paths to one place
// each.

fn security_labels(sec: &praxis_policy_core::extensions::SecurityExtension) -> Vec<String> {
    // MonotonicSet<String>::iter() -> impl Iterator<Item = &String>.
    // The backing HashSet iterates in randomized, seed-dependent order;
    // sort so the emitted array is canonical and the fingerprint an
    // independent verifier recomputes matches the emitted one.
    let mut labels: Vec<String> = sec.labels.iter().cloned().collect();
    labels.sort_unstable();
    labels
}

fn caller_workload(ext: &Extensions) -> Option<Value> {
    // The resolved inbound workload identity is reachable at
    // Extensions.security.caller_workload (the executor applies
    // IdentityPayload.caller_workload onto the security ext).
    // `this_workload` (the gateway's own attested id) is the signer
    // identity, not a field of the request.
    let sec = ext.security.as_ref()?;
    let wl = sec.caller_workload.as_ref()?;
    Some(json!({
        "spiffe_id": wl.spiffe_id,
        "trust_domain": wl.trust_domain,
        "attestor": wl.attestor,        // e.g. gke-workload-identity, spire-agent, mtls
        "attested_at": wl.attested_at,  // for stale-evidence rejection
    }))
}
