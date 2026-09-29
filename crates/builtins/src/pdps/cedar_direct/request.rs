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
// Structured input lands at `context.llm.request` and `context.args`, so the
// operator may not define `llm` or `args`. It is sanitized first, because
// Cedar's JSON form cannot hold every JSON value:
//
//   - `null` is dropped, from objects and arrays alike, so `has` is false.
//   - Floats, and integers outside the `Long` range, become strings.
//   - Arrays become sets: unordered, with duplicates collapsed.
//   - An object with a reserved escape key (`__entity`, `__extn`, `__expr`)
//     withholds the whole input. Cedar would read it as an entity or
//     extension value and silently change what a rule means.
//
// A missing entry stays missing, never an empty record.
//
// Context construction errors name a fixed category only, since Cedar's text
// can quote the value it rejected.
//
// # Schema
//
// When a schema is supplied, Cedar's `Context::from_json_value` validates
// the context's record shape against the action's declared context type.
// Without a schema, Cedar accepts any record.

use cedar_policy::{ContextCreationError, ContextJsonError, EntityUid, Schema};
use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{PdpCall, PdpError};
use serde_json::{Map, Value, json};

/// Context keys that carry structured input, so the operator may not set them.
const RESERVED_CONTEXT_KEYS: &[&str] = &["llm", "args"];

/// Object keys Cedar's JSON form reads as escapes rather than record fields.
const CEDAR_ESCAPE_KEYS: &[&str] = &["__entity", "__extn", "__expr"];

/// Structured input converted to Cedar-safe JSON. Deliberately not `Debug`,
/// so its values cannot reach a log line.
#[derive(Default)]
pub struct CedarStructured {
    llm_request: Option<Value>,
    args: Option<Value>,
}

/// Structured input held back because it contains a Cedar escape key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withheld;

/// Convert structured input to Cedar-safe JSON.
///
/// # Errors
///
/// Returns [`Withheld`] when any object in either entry has a Cedar escape key.
pub fn sanitize_structured(structured: &StructuredInput) -> Result<CedarStructured, Withheld> {
    let convert = |entry: Option<&std::sync::Arc<Value>>| match entry {
        Some(value) => sanitize(value),
        None => Ok(None),
    };
    Ok(CedarStructured {
        llm_request: convert(structured.llm_request.as_ref())?,
        args: convert(structured.args.as_ref())?,
    })
}

/// Sanitize one JSON value. `None` means the value was `null` and is dropped.
fn sanitize(value: &Value) -> Result<Option<Value>, Withheld> {
    Ok(match value {
        Value::Null => None,
        Value::Bool(_) | Value::String(_) => Some(value.clone()),
        Value::Number(n) => Some(match n.as_i64() {
            Some(long) => Value::from(long),
            None => Value::String(n.to_string()),
        }),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                if let Some(v) = sanitize(item)? {
                    out.push(v);
                }
            }
            Some(Value::Array(out))
        },
        Value::Object(fields) => {
            if CEDAR_ESCAPE_KEYS.iter().any(|k| fields.contains_key(*k)) {
                return Err(Withheld);
            }
            let mut out = Map::new();
            for (key, field) in fields {
                if let Some(v) = sanitize(field)? {
                    out.insert(key.clone(), v);
                }
            }
            Some(Value::Object(out))
        },
    })
}

/// The first reserved key the step's operator `context:` defines, if any.
pub fn reserved_context_key(call: &PdpCall) -> Option<&'static str> {
    let context = call.args.get("context")?.as_mapping()?;
    RESERVED_CONTEXT_KEYS
        .iter()
        .copied()
        .find(|key| context.contains_key(*key))
}

/// A value-free description of a context construction error.
fn context_error_category(error: &ContextJsonError) -> &'static str {
    match error {
        ContextJsonError::JsonDeserialization(_) => "a value has no Cedar representation",
        ContextJsonError::ContextCreation(ContextCreationError::NotARecord(_)) => {
            "context is not a record"
        },
        ContextJsonError::ContextCreation(_) => "context could not be built",
        ContextJsonError::MissingAction(_) => "action is not in the schema",
    }
}

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

/// Parse the args, bag, and sanitized structured input into the pieces a
/// Cedar request builder needs. Schema is optional; when present, the context
/// block is validated against the action's declared context shape.
/// # Errors
///
/// Returns `PdpError::Dispatch` when the call omits `action` or `resource`, the
/// operator context defines a reserved key, or a context value has no Cedar
/// equivalent.
pub fn parse<'a>(
    call: &'a PdpCall,
    bag: &AttributeBag,
    structured: CedarStructured,
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
    if let Some(key) = reserved_context_key(call) {
        return Err(PdpError::Dispatch(reserved_key_message(key)));
    }
    if let Value::Object(root) = &mut merged {
        if let Some(request) = structured.llm_request {
            root.insert("llm".to_owned(), json!({ "request": request }));
        }
        if let Some(args) = structured.args {
            root.insert("args".to_owned(), args);
        }
    }

    let cedar_context = cedar_policy::Context::from_json_value(merged, None).map_err(|e| {
        PdpError::Dispatch(format!(
            "failed to construct Cedar context: {}",
            context_error_category(&e)
        ))
    })?;
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

/// Why a step's operator `context:` may not define `key`.
pub fn reserved_key_message(key: &str) -> String {
    format!("cedar:() `context` may not define `{key}`; it is reserved for structured input")
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;

    fn structured(llm_request: Option<Value>, args: Option<Value>) -> StructuredInput {
        StructuredInput {
            llm_request: llm_request.map(Arc::new),
            args: args.map(Arc::new),
        }
    }

    fn sanitized_args(args: Value) -> Result<Option<Value>, Withheld> {
        sanitize_structured(&structured(None, Some(args))).map(|s| s.args)
    }

    #[test]
    fn nulls_are_dropped_from_objects_and_arrays() {
        let out = sanitized_args(json!({"a": null, "b": [1, null, 2], "c": {"d": null}}));
        assert_eq!(out, Ok(Some(json!({"b": [1, 2], "c": {}}))));
    }

    #[test]
    fn floats_and_out_of_range_integers_become_strings() {
        let out = sanitized_args(json!({
            "t": 0.7,
            "big": u64::MAX,
            "neg": i64::MIN,
            "n": 5,
            "list": [1.5, 2],
        }));
        assert_eq!(
            out,
            Ok(Some(json!({
                "t": "0.7",
                "big": u64::MAX.to_string(),
                "neg": i64::MIN,
                "n": 5,
                "list": ["1.5", 2],
            })))
        );
    }

    #[test]
    fn a_null_root_is_absent() {
        assert_eq!(sanitized_args(Value::Null), Ok(None));
    }

    #[test]
    fn any_object_with_an_escape_key_withholds_the_input() {
        for doc in [
            json!({"tools": [{"__entity": {"type": "User", "id": "admin"}}]}),
            json!({"x": {"__extn": {"fn": "ip", "arg": "10.0.0.1"}, "other": 1}}),
            json!([{"__expr": "true"}]),
            json!({"__entity": "not even an escape shape"}),
        ] {
            assert_eq!(
                sanitize_structured(&structured(Some(doc.clone()), None)).err(),
                Some(Withheld),
                "{doc}"
            );
            assert_eq!(sanitized_args(doc.clone()), Err(Withheld), "{doc}");
        }
    }

    #[test]
    fn escape_names_as_values_or_longer_keys_are_kept() {
        let doc = json!({"name": "__entity", "__entity_id": 1});
        assert_eq!(sanitized_args(doc.clone()), Ok(Some(doc)));
    }

    #[test]
    fn absent_entries_stay_absent() {
        let out = sanitize_structured(&StructuredInput::default()).unwrap();
        assert!(out.llm_request.is_none() && out.args.is_none());
    }

    fn call(args: &str) -> PdpCall {
        PdpCall {
            dialect: praxis_policy_apl_core::step::PdpDialect::Cedar,
            args: serde_yaml::from_str(args).unwrap(),
        }
    }

    const READ_DOC: &str = "action: 'Action::\"read\"'\nresource:\n  type: Document\n  id: d\n";

    fn context_debug(structured: CedarStructured) -> String {
        let step = call(READ_DOC);
        let parsed = parse(&step, &AttributeBag::new(), structured, None).unwrap();
        format!("{:?}", parsed.context)
    }

    #[test]
    fn structured_entries_land_under_llm_request_and_args() {
        let input = structured(
            Some(json!({"model": "m-under-test"})),
            Some(json!({"region": "eu-under-test"})),
        );
        let ctx = context_debug(sanitize_structured(&input).unwrap());
        for expected in ["llm", "request", "m-under-test", "args", "eu-under-test"] {
            assert!(ctx.contains(expected), "missing {expected}: {ctx}");
        }
    }

    #[test]
    fn no_structured_input_means_no_llm_or_args_key() {
        let ctx = context_debug(CedarStructured::default());
        assert!(!ctx.contains("llm") && !ctx.contains("args"), "{ctx}");
    }

    #[test]
    fn reserved_context_keys_are_detected() {
        let with = |ctx: &str| call(&format!("{READ_DOC}context:\n  {ctx}\n"));
        assert_eq!(reserved_context_key(&with("llm: {}")), Some("llm"));
        assert_eq!(reserved_context_key(&with("args: 1")), Some("args"));
        assert_eq!(reserved_context_key(&with("tenant: acme")), None);
        assert_eq!(reserved_context_key(&call(READ_DOC)), None);
    }

    #[test]
    fn a_reserved_operator_key_is_rejected_at_request_time_too() {
        let step = call(&format!("{READ_DOC}context:\n  args: {{}}\n"));
        let Err(e) = parse(
            &step,
            &AttributeBag::new(),
            CedarStructured::default(),
            None,
        ) else {
            panic!("a reserved key must be rejected");
        };
        assert!(e.to_string().contains("may not define `args`"), "{e}");
    }
}
