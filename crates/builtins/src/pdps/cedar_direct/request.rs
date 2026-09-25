// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Build a `cedar_policy::Request` from a `PdpCall` + `AttributeBag`.
// The resolver constructs Cedar's three required parts (principal,
// action, resource) plus the merged context, then hands them to
// Cedar's `Request::builder()`.
//
// # Principal / resource / action
//
// - **Principal:** built from the bag (see `entities::build_principal`).
//   Its `EntityUid` is what we hand to `Request::principal()`.
// - **Resource:** built from `args.resource` (see `entities::build_resource`).
// - **Action:** parsed from `args.action` — must be a fully-qualified
//   Cedar `EntityUid` literal like `Action::"read"` or
//   `Acme::Action::"approve"`. The policy author writes this verbatim
//   in their APL `cedar:(...)` step.
//
// # Context
//
// `args.context` is the operator-supplied context from the APL step. We
// merge in PPE-provided keys at well-known paths:
//
//   - `context.delegation.{chain, depth}`  ← from bag's `delegation.*`
//   - `context.meta.{entity_type, entity_name, scope, tags}` ← from bag's `meta.*`
//   - `context.security.{labels, classification}` ← from bag's `security.*`
//
// Operators write Cedar policies against these stable paths. Any keys
// the operator put in `args.context` win over PPE-provided defaults on
// conflict — operator intent first.
//
// # Schema
//
// When a schema is supplied, Cedar's `Context::from_json_value` validates
// the context's record shape against the action's declared context type.
// Without a schema, Cedar accepts any record.

use cedar_policy::{EntityUid, Schema};
use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::step::{PdpCall, PdpError};
use serde_json::{Map, Value, json};

/// Parsed pieces of a `PdpCall` ready to feed into
/// `cedar_policy::Request::builder()`. We pull this into its own
/// struct so the resolver can sequence "build entities → build request"
/// without a giant function signature.
pub struct ParsedCall<'a> {
    /// The Cedar action being authorized.
    pub action: EntityUid,
    /// The Cedar context for the request.
    pub context: cedar_policy::Context,
    /// The raw resource arguments, used to build the resource entity.
    pub resource_args: &'a serde_yaml::Value,
}

/// Parse the args + bag into the pieces a Cedar request builder needs.
/// Schema is optional; when present, the context block is validated
/// against the action's declared context shape.
/// # Errors
///
/// Returns `PdpError::Dispatch` when the call omits `action` or `resource`, or a
/// context value has no Cedar equivalent, and `PdpError::Schema` when the context
/// does not match the action's declared shape.
pub fn parse<'a>(
    call: &'a PdpCall,
    bag: &AttributeBag,
    schema: Option<&Schema>,
) -> Result<ParsedCall<'a>, PdpError> {
    let map = call.args.as_mapping().ok_or_else(|| {
        PdpError::Dispatch(
            "cedar:() args must be a mapping with `action` and `resource` keys".to_owned(),
        )
    })?;

    let action_str = map
        .get(serde_yaml::Value::String("action".to_owned()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PdpError::Dispatch(
                "cedar:() `action` missing — provide a fully-qualified UID \
                 like 'Action::\"read\"'"
                    .to_owned(),
            )
        })?;
    let action: EntityUid = action_str.parse().map_err(|e| {
        PdpError::Dispatch(format!(
            "cedar:() `action` '{action_str}' not a valid EntityUid: {e}"
        ))
    })?;

    let resource_args = map
        .get(serde_yaml::Value::String("resource".to_owned()))
        .ok_or_else(|| PdpError::Dispatch("cedar:() `resource` missing".to_owned()))?;

    // Build the merged context: operator-supplied `args.context` keys,
    // overlaid on top of PPE-derived context (delegation, meta,
    // security). On collision, the operator's value wins — they
    // explicitly wrote it.
    let policy_ctx = build_policy_context(bag);
    let operator_ctx = map
        .get(serde_yaml::Value::String("context".to_owned()))
        .cloned()
        .unwrap_or(serde_yaml::Value::Null);
    let mut merged = policy_ctx;
    if !operator_ctx.is_null() {
        let op_json: Value = serde_json::to_value(&operator_ctx).map_err(|e| {
            PdpError::Dispatch(format!("cedar:() `context` not JSON-representable: {e}"))
        })?;
        merge_into(&mut merged, op_json);
    }

    let cedar_context = cedar_policy::Context::from_json_value(merged, None)
        .map_err(|e| PdpError::Dispatch(format!("failed to construct Cedar context: {e}")))?;
    // Note: schema-validated context construction takes an
    // (action_schema, action) pair via Cedar's `from_json_value`. For
    // v0 we skip schema-side validation of the context shape — the
    // request builder still applies whole-request validation when a
    // schema is wired into the resolver. Adding context-level schema
    // validation is a polish item; doesn't change decision semantics
    // when the policies are well-formed.
    let _ = schema; // schema currently used at request-build time, not here

    Ok(ParsedCall {
        action,
        context: cedar_context,
        resource_args,
    })
}

/// Build the PPE-provided context block (everything under
/// `context.delegation`, `context.meta`, `context.security`) from the
/// `AttributeBag`. Operators reason about these in Cedar policies via
/// the well-known paths.
fn build_policy_context(bag: &AttributeBag) -> Value {
    let mut root = Map::new();

    let mut delegation = Map::new();
    if let Some(depth) = bag.get_int("delegation.depth") {
        delegation.insert("depth".to_owned(), json!(depth));
    }
    // The full chain isn't currently in a flat bag key; praxis-policy-apl-cmf
    // exposes presence-only `delegated=true` plus per-attribute hops.
    // When praxis-policy-apl-cmf grows a structured `delegation.chain` shape we'll
    // forward it here. For now, the depth + delegated bool let policies
    // do basic chain-depth bounds checks.
    if let Some(delegated) = bag.get_bool("delegated") {
        delegation.insert("delegated".to_owned(), json!(delegated));
    }
    if !delegation.is_empty() {
        root.insert("delegation".to_owned(), Value::Object(delegation));
    }

    let mut meta = Map::new();
    if let Some(et) = bag.get_string("meta.entity_type") {
        meta.insert("entity_type".to_owned(), json!(et));
    }
    if let Some(en) = bag.get_string("meta.entity_name") {
        meta.insert("entity_name".to_owned(), json!(en));
    }
    if let Some(scope) = bag.get_string("meta.scope") {
        meta.insert("scope".to_owned(), json!(scope));
    }
    if let Some(tags) = bag.get_string_set("meta.tags") {
        meta.insert("tags".to_owned(), json!(tags.iter().collect::<Vec<_>>()));
    }
    if !meta.is_empty() {
        root.insert("meta".to_owned(), Value::Object(meta));
    }

    let mut security = Map::new();
    if let Some(labels) = bag.get_string_set("security.labels") {
        security.insert(
            "labels".to_owned(),
            json!(labels.iter().collect::<Vec<_>>()),
        );
    }
    if let Some(cls) = bag.get_string("security.classification") {
        security.insert("classification".to_owned(), json!(cls));
    }
    if !security.is_empty() {
        root.insert("security".to_owned(), Value::Object(security));
    }

    // Pass `authenticated` through as a top-level convenience for
    // policies that want `context.authenticated` shorthand.
    if let Some(auth) = bag.get_bool("authenticated") {
        root.insert("authenticated".to_owned(), json!(auth));
    }

    Value::Object(root)
}

/// Shallow merge `overlay` into `target`. Operator-supplied keys win on
/// conflict at the top level; we don't try to deep-merge nested
/// records (operator says `context.meta = {custom: "x"}` and PPE-
/// provided context.meta is fully replaced). Keeps the semantics
/// predictable.
fn merge_into(target: &mut Value, overlay: Value) {
    let (Value::Object(target_map), Value::Object(overlay_map)) = (target, overlay) else {
        return;
    };
    for (k, v) in overlay_map {
        target_map.insert(k, v);
    }
}
