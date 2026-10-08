// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Bag → Rego `input` mapping.
//
// APL's `AttributeBag` is a flat `HashMap<String, AttributeValue>` with dotted
// keys (`subject.id`, `role.hr`, `delegation.depth`). Rego wants a nested
// document so `input.subject.id` reads as field selection. This module rebuilds
// the flat bag into a nested JSON object that becomes the engine's `input`.
//
// This mirrors the tree-building and type coercions in the `cel` module's
// `activation.rs` so a policy author's mental model of the attribute
// vocabulary is identical across the two backends. It is ported rather than
// shared so the `opa` feature resolves against praxis-policy-apl-core alone,
// with no normal edge to the runtime.
//
// Type mapping (`AttributeValue` → JSON):
//   Bool      → bool
//   Int       → integer
//   Float     → integer when it is a whole number in i64 range, else float
//   String    → string
//   StringSet → array of strings, sorted (so `input.x[0]` is deterministic)
//
// Collision rule: if a key is both a leaf and a namespace prefix (`delegation`
// AND `delegation.depth`), the namespace (object) wins and the scalar leaf is
// dropped with a `tracing::warn!`, matching the CEL resolver.
//
// Structured input is overlaid after the bag tree is built. Structured `args`
// replaces the whole bag-derived `args` subtree, so a field's type never
// depends on whether the flattener could represent it. `llm.request` is added
// beside the bag's other `llm.*` fields. Either entry, when absent, leaves the
// bag-derived input untouched: a missing document stays undefined in Rego.

use std::collections::BTreeMap;

use praxis_policy_apl_core::attributes::{AttributeBag, AttributeValue};
use praxis_policy_apl_core::redact::payload_namespace;
use praxis_policy_apl_core::route::StructuredInput;
use serde_json::{Map, Number, Value};

/// Build the bag-only JSON input used by callers of the original OPA mapping.
pub fn bag_to_input(bag: &AttributeBag) -> Value {
    build_input(bag, &StructuredInput::default())
}

/// Build bag-only input with extra dotted scalar paths and literal-keyed maps.
/// The source bag is unchanged. Kuadrant compatibility uses this path in tests;
/// production uses [`build_rego_input_with_aliases`] to preserve structured JSON.
pub fn bag_to_input_with_aliases(
    bag: &AttributeBag,
    scalar_aliases: &[(String, AttributeValue)],
    header_maps: &[(&str, &[(String, AttributeValue)])],
) -> Value {
    Value::Object(bag_to_map_with_aliases(bag, scalar_aliases, header_maps))
}

/// Build the Rego `input` document from the policy bag and structured input.
///
/// Every dotted bag key becomes a nested field: `subject.id` → `{"subject":
/// {"id": ...}}`. Single-segment keys (`authenticated`) become top-level
/// fields. Structured `args` then replaces `input.args`, and a structured
/// request document becomes `input.llm.request`. The result is always a JSON
/// object (an empty bag with no structured input yields `{}`).
pub fn build_input(bag: &AttributeBag, structured: &StructuredInput) -> Value {
    let mut root = bag_to_map(bag);
    if let Some(document) = structured.llm_request() {
        let llm = root
            .entry("llm")
            .or_insert_with(|| Value::Object(Map::new()));
        if !llm.is_object() {
            tracing::warn!(
                key = "llm",
                "OPA input: scalar key collides with the request document; \
                 keeping the document and dropping the scalar"
            );
            *llm = Value::Object(Map::new());
        }
        if let Value::Object(llm) = llm {
            llm.insert("request".to_owned(), Value::clone(document));
        }
    }
    if let Some(args) = structured.args() {
        root.insert("args".to_owned(), Value::clone(args));
    }
    Value::Object(root)
}

/// Build Regorus input without cloning structured JSON into an intermediate tree.
pub fn build_rego_input(bag: &AttributeBag, structured: &StructuredInput) -> regorus::Value {
    build_rego_input_with_aliases(bag, structured, &[], &[])
}

/// Build Regorus input with Kuadrant aliases while retaining structured input.
pub fn build_rego_input_with_aliases(
    bag: &AttributeBag,
    structured: &StructuredInput,
    scalar_aliases: &[(String, AttributeValue)],
    header_maps: &[(&str, &[(String, AttributeValue)])],
) -> regorus::Value {
    let mut root = bag_to_map_with_aliases(bag, scalar_aliases, header_maps);
    let bag_args = root.remove("args");
    let bag_llm = root.remove("llm");
    let mut output = root
        .iter()
        .map(|(key, value)| (regorus::Value::from(key.as_str()), json_to_rego(value)))
        .collect::<BTreeMap<_, _>>();

    match structured.llm_request() {
        Some(document) => {
            let mut llm = match bag_llm {
                Some(Value::Object(map)) => map
                    .iter()
                    .map(|(key, value)| (regorus::Value::from(key.as_str()), json_to_rego(value)))
                    .collect::<BTreeMap<_, _>>(),
                Some(_) => {
                    tracing::warn!(
                        key = "llm",
                        "OPA input: scalar key collides with the request document; \
                         keeping the document and dropping the scalar"
                    );
                    BTreeMap::new()
                },
                None => BTreeMap::new(),
            };
            llm.insert(regorus::Value::from("request"), json_to_rego(document));
            output.insert(regorus::Value::from("llm"), regorus::Value::from(llm));
        },
        None => {
            if let Some(value) = bag_llm {
                output.insert(regorus::Value::from("llm"), json_to_rego(&value));
            }
        },
    }

    let args = structured
        .args()
        .map(|value| json_to_rego(value))
        .or_else(|| bag_args.as_ref().map(json_to_rego));
    if let Some(args) = args {
        output.insert(regorus::Value::from("args"), args);
    }
    regorus::Value::from(output)
}

fn json_to_rego(value: &Value) -> regorus::Value {
    match value {
        Value::Null => regorus::Value::Null,
        Value::Bool(value) => regorus::Value::from(*value),
        Value::Number(value) => regorus::Value::from_numeric_string(&value.to_string())
            .unwrap_or(regorus::Value::Undefined),
        Value::String(value) => regorus::Value::from(value.as_str()),
        Value::Array(values) => {
            regorus::Value::from(values.iter().map(json_to_rego).collect::<Vec<_>>())
        },
        Value::Object(values) => regorus::Value::from(
            values
                .iter()
                .map(|(key, value)| (regorus::Value::from(key.as_str()), json_to_rego(value)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

/// Rebuild the flat bag into a nested JSON object.
fn bag_to_map(bag: &AttributeBag) -> Map<String, Value> {
    bag_to_map_with_aliases(bag, &[], &[])
}

fn bag_to_map_with_aliases(
    bag: &AttributeBag,
    scalar_aliases: &[(String, AttributeValue)],
    header_maps: &[(&str, &[(String, AttributeValue)])],
) -> Map<String, Value> {
    let mut root: BTreeMap<String, Node> = BTreeMap::new();
    for (key, value) in bag.iter() {
        let segments: Vec<&str> = key.split('.').collect();
        insert(&mut root, key, &segments, attr_to_value(value));
    }
    for (key, value) in scalar_aliases {
        let segments: Vec<&str> = key.split('.').collect();
        insert(&mut root, key, &segments, attr_to_value(value));
    }
    for &(parent, entries) in header_maps {
        for (name, value) in entries {
            let mut segments: Vec<&str> = parent.split('.').collect();
            segments.push(name);
            insert(&mut root, name, &segments, attr_to_value(value));
        }
    }
    node_map_to_map(root)
}

/// A bag key as it may appear in a log line. Keys below a payload namespace
/// are client-chosen, so only the namespace is shown.
fn loggable_key(key: &str) -> &str {
    payload_namespace(key).unwrap_or(key)
}

/// Internal tree node: either a leaf scalar/array or a nested namespace.
enum Node {
    Leaf(Value),
    Branch(BTreeMap<String, Node>),
}

/// Insert a leaf at the dotted path, creating intermediate branches.
/// Namespace-wins on leaf/branch collisions (see module docs).
fn insert(level: &mut BTreeMap<String, Node>, full_key: &str, segments: &[&str], leaf: Value) {
    // `bag.iter()` never yields empty keys today, but return cleanly rather
    // than panic if a future bag implementation emits one.
    let Some((head, rest)) = segments.split_first() else {
        return;
    };
    let head = (*head).to_owned();

    if rest.is_empty() {
        match level.get(&head) {
            Some(Node::Branch(_)) => {
                tracing::warn!(
                    key = %loggable_key(full_key),
                    "OPA input: scalar key collides with an existing namespace; \
                     keeping the namespace and dropping the scalar"
                );
            },
            _ => {
                level.insert(head, Node::Leaf(leaf));
            },
        }
        return;
    }

    let entry = level
        .entry(head)
        .or_insert_with(|| Node::Branch(BTreeMap::new()));
    if let Node::Leaf(_) = entry {
        tracing::warn!(
            key = %loggable_key(full_key),
            "OPA input: namespace prefix collides with an existing scalar; \
             promoting to a namespace and dropping the scalar"
        );
        *entry = Node::Branch(BTreeMap::new());
    }
    if let Node::Branch(child) = entry {
        insert(child, full_key, rest, leaf);
    }
}

/// Recursively convert a tree of nodes into a JSON object.
fn node_map_to_map(children: BTreeMap<String, Node>) -> Map<String, Value> {
    let mut map = Map::new();
    for (k, child) in children {
        map.insert(k, node_to_value(child));
    }
    map
}

fn node_to_value(node: Node) -> Value {
    match node {
        Node::Leaf(v) => v,
        Node::Branch(children) => Value::Object(node_map_to_map(children)),
    }
}

/// Convert one `AttributeValue` to a JSON value.
fn attr_to_value(attr: &AttributeValue) -> Value {
    match attr {
        AttributeValue::Bool(b) => Value::Bool(*b),
        AttributeValue::Int(i) => Value::Number((*i).into()),
        AttributeValue::Float(f) => float_to_value(*f),
        AttributeValue::String(s) => Value::String(s.clone()),
        // StringSet → sorted array. Rego treats the value as a JSON array;
        // sorting makes any index-dependent policy deterministic across runs.
        AttributeValue::StringSet(set) => {
            let mut sorted: Vec<&String> = set.iter().collect();
            sorted.sort();
            Value::Array(
                sorted
                    .into_iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            )
        },
    }
}

/// Yield an `f64` as a JSON integer when it is a whole number in `i64` range,
/// otherwise a JSON float. Keeps parity with CEL's `float_to_value` so a bag
/// value populated as `Float(2.0)` reads as `2` for an author. A non-finite
/// float has no JSON representation and becomes `null`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "the conversion is guarded to finite, integral, in-range values; the \
              bound casts are deliberate and explained below"
)]
fn float_to_value(f: f64) -> Value {
    // The upper bound is strict on purpose, matching the CEL crate. `i64::MAX as
    // f64` cannot represent 2^63 - 1 and rounds up to exactly 2^63, so `<=`
    // against it would admit 2^63, one past the last i64. `i64::MIN as f64` is
    // exact at -2^63, so the lower bound stays inclusive.
    if f.is_finite() && f.fract() == 0.0 && f >= i64::MIN as f64 && f < i64::MAX as f64 {
        Value::Number((f as i64).into())
    } else {
        Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    use serde_json::json;

    use regorus::Engine;

    /// Evaluate a boolean Rego expression against an input built from `bag`.
    /// Wraps the expression in a rule so we exercise the exact input path the
    /// resolver uses (`set_input_json` + `eval_rule`).
    fn rego_eval(expr: &str, bag: &AttributeBag) -> bool {
        rego_eval_structured(expr, bag, &StructuredInput::default())
    }

    fn rego_eval_structured(expr: &str, bag: &AttributeBag, structured: &StructuredInput) -> bool {
        let mut engine = Engine::new();
        engine
            .add_policy(
                "t.rego".to_owned(),
                format!("package t\nresult if {{ {expr} }}\n"),
            )
            .unwrap();
        engine.set_input(build_rego_input(bag, structured));
        engine
            .eval_rule("data.t.result".to_owned())
            .unwrap()
            .as_bool()
            .copied()
            .unwrap_or(false)
    }

    fn with_args(args: Value) -> StructuredInput {
        StructuredInput::new(None, Some(Arc::new(args)))
    }

    /// Read `input` back out of regorus as JSON after the engine has parsed it.
    fn rego_input_roundtrip(bag: &AttributeBag, structured: &StructuredInput) -> Value {
        let mut engine = Engine::new();
        engine
            .add_policy("t.rego".to_owned(), "package t\nv := input\n".to_owned())
            .unwrap();
        engine.set_input(build_rego_input(bag, structured));
        let v = engine.eval_rule("data.t.v".to_owned()).unwrap();
        serde_json::from_str(&v.to_json_str().unwrap()).unwrap()
    }

    #[test]
    fn request_id_alias_merges_with_native_input_and_structured_args() {
        let mut bag = AttributeBag::new();
        bag.set("request.request_id", "req-abc");
        let structured = with_args(json!({"items": [1, 2]}));
        let aliases = vec![(
            "request.id".to_owned(),
            AttributeValue::String("req-abc".into()),
        )];
        let mut engine = Engine::new();
        engine
            .add_policy("t.rego".to_owned(), "package t\nv := input\n".to_owned())
            .unwrap();
        engine.set_input(build_rego_input_with_aliases(
            &bag,
            &structured,
            &aliases,
            &[],
        ));
        let value = engine.eval_rule("data.t.v".to_owned()).unwrap();
        let input: Value = serde_json::from_str(&value.to_json_str().unwrap()).unwrap();
        assert_eq!(input["request"]["request_id"], json!("req-abc"));
        assert_eq!(input["request"]["id"], json!("req-abc"));
        assert_eq!(input["args"]["items"], json!([1, 2]));
        assert_eq!(bag.get_string("request.request_id"), Some("req-abc"));

        let native = rego_input_roundtrip(&bag, &structured);
        assert!(native["request"].get("id").is_none());
        assert_eq!(native["args"]["items"], json!([1, 2]));
    }

    #[test]
    fn dotted_keys_become_nested_fields() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        bag.set("subject.type", "user");
        assert!(rego_eval("input.subject.id == \"alice\"", &bag));
        assert!(rego_eval("input.subject.type == \"user\"", &bag));
    }

    #[test]
    fn single_segment_key_is_top_level_field() {
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        assert!(rego_eval("input.authenticated == true", &bag));
    }

    #[test]
    fn bool_int_float_string_scalars() {
        let mut bag = AttributeBag::new();
        bag.set("role.hr", true);
        bag.set("delegation.depth", 2_i64);
        bag.set("intent.confidence", 0.92_f64);
        bag.set("subject.id", "alice");
        assert!(rego_eval("input.role.hr == true", &bag));
        assert!(rego_eval("input.delegation.depth == 2", &bag));
        assert!(rego_eval("input.intent.confidence > 0.9", &bag));
        assert!(rego_eval("input.subject.id == \"alice\"", &bag));
    }

    #[test]
    fn whole_number_float_reads_as_integer() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2.0_f64);
        // Emitted as the JSON integer 2 (not 2.0), so an author comparing to an
        // integer literal gets the natural result.
        assert_eq!(
            bag_to_input(&bag)["delegation"]["depth"],
            serde_json::json!(2)
        );
        assert!(rego_eval("input.delegation.depth == 2", &bag));
    }

    #[test]
    fn string_set_becomes_sorted_array() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["zeta".to_owned(), "alpha".to_owned(), "mu".to_owned()]),
        );
        assert!(rego_eval("\"alpha\" in input.session.labels", &bag));
        assert!(rego_eval("input.session.labels[0] == \"alpha\"", &bag));
        assert!(rego_eval("input.session.labels[2] == \"zeta\"", &bag));
    }

    #[test]
    fn namespace_wins_on_leaf_collision() {
        let mut bag = AttributeBag::new();
        bag.set("delegation", "scalar-value");
        bag.set("delegation.depth", 3_i64);
        // The namespace must win so `delegation.depth` resolves rather than the
        // scalar shadowing it.
        assert!(rego_eval("input.delegation.depth == 3", &bag));
    }

    #[test]
    fn empty_bag_is_empty_object() {
        let bag = AttributeBag::new();
        assert_eq!(bag_to_input(&bag), serde_json::json!({}));
    }

    #[test]
    fn structured_args_replace_flattened_args() {
        let mut bag = AttributeBag::new();
        bag.set("args.region", "eu");
        bag.set("args.stale", "flattened-only");
        bag.set("subject.id", "alice");
        let structured = with_args(json!({"region": "eu", "items": [{"k": 1}]}));
        let input = rego_input_roundtrip(&bag, &structured);
        assert_eq!(input["args"], json!({"region": "eu", "items": [{"k": 1}]}));
        assert_eq!(input["subject"]["id"], "alice");
        assert!(rego_eval_structured(
            "input.args.region == \"eu\"",
            &bag,
            &structured
        ));
        assert!(!rego_eval_structured("input.args.stale", &bag, &structured));
    }

    #[test]
    fn flattened_args_kept_when_structured_args_absent() {
        let mut bag = AttributeBag::new();
        bag.set("args", "prompt text");
        let input = rego_input_roundtrip(&bag, &StructuredInput::default());
        assert_eq!(input["args"], "prompt text");
    }

    #[test]
    fn request_document_sits_beside_llm_metadata() {
        let mut bag = AttributeBag::new();
        bag.set("llm.model_id", "gpt-4o");
        let structured = StructuredInput::new(
            Some(Arc::new(json!({"model": "gpt-4o", "tools": []}))),
            None,
        );
        let input = rego_input_roundtrip(&bag, &structured);
        assert_eq!(input["llm"]["model_id"], "gpt-4o");
        assert_eq!(
            input["llm"]["request"],
            json!({"model": "gpt-4o", "tools": []})
        );
    }

    #[test]
    fn request_document_replaces_scalar_llm_key() {
        let mut bag = AttributeBag::new();
        bag.set("llm", "scalar");
        let structured = StructuredInput::new(Some(Arc::new(json!({"model": "m"}))), None);
        let input = rego_input_roundtrip(&bag, &structured);
        assert_eq!(input["llm"], json!({"request": {"model": "m"}}));
    }

    #[test]
    fn absent_document_stays_undefined() {
        let mut bag = AttributeBag::new();
        bag.set("llm.model_id", "gpt-4o");
        let input = rego_input_roundtrip(&bag, &StructuredInput::default());
        assert!(input["llm"].get("request").is_none());
        assert!(rego_eval("not input.llm.request", &bag));
    }

    #[test]
    fn json_shapes_round_trip_through_regorus() {
        let args = json!({
            "empty_list": [],
            "empty_map": {},
            "nothing": null,
            "dupes": [1, 1],
            "mixed": [1, "a", true, null, 1.5, {"k": "v"}],
            "nested": [[{"a": 1}, {"b": [2, 3]}], []],
            "float": 0.7,
        });
        let structured = StructuredInput::new(
            Some(Arc::new(json!({"tools": [{"type": "function"}]}))),
            Some(Arc::new(args.clone())),
        );
        let back = rego_input_roundtrip(&AttributeBag::new(), &structured);
        assert_eq!(back["args"], args);
        assert_eq!(
            back["llm"]["request"],
            json!({"tools": [{"type": "function"}]})
        );
    }

    /// Structured `args` arrays keep numbers, client order, and duplicates,
    /// unlike the sorted string set the bag used to supply.
    #[test]
    fn structured_args_arrays_keep_numbers_order_and_duplicates() {
        let bag = AttributeBag::new();
        let structured = with_args(json!({"ids": [2, 1, 1]}));
        assert!(rego_eval_structured(
            "1 in input.args.ids",
            &bag,
            &structured
        ));
        assert!(!rego_eval_structured(
            "\"1\" in input.args.ids",
            &bag,
            &structured
        ));
        assert!(rego_eval_structured(
            "input.args.ids == [2, 1, 1]",
            &bag,
            &structured
        ));
        assert!(rego_eval_structured(
            "count(input.args.ids) == 3",
            &bag,
            &structured
        ));
    }

    /// An explicit `null` is present, so `not input.args.note` no longer holds.
    #[test]
    fn structured_null_is_present_not_absent() {
        let bag = AttributeBag::new();
        let structured = with_args(json!({"note": null}));
        assert!(!rego_eval_structured(
            "not input.args.note",
            &bag,
            &structured
        ));
        assert!(rego_eval_structured(
            "input.args.note == null",
            &bag,
            &structured
        ));
    }
}
