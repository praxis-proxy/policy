// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Bag → CEL activation mapping.
//
// APL's `AttributeBag` is a flat `HashMap<String, AttributeValue>` with
// dotted keys (`subject.id`, `role.hr`, `delegation.depth`). CEL wants
// nested structures so `subject.id` reads as field selection on a
// `subject` map. This module rebuilds the flat bag into a tree of CEL
// maps and registers each top-level namespace as a CEL variable.
//
// Type mapping (`AttributeValue` → `cel::Value`):
//   Bool      → Value::Bool
//   Int       → Value::Int
//   Float     → Value::Float
//   String    → Value::String
//   StringSet → Value::List(of String)   (so `"x" in session.labels` works)
//
// If a key is both a leaf and a namespace prefix, the namespace wins
// and the scalar is dropped with a warning.
//
// Structured input is overlaid on the bag tree. Structured `args` replaces
// the whole bag-derived `args` variable, and `llm.request` is added to the
// `llm` map beside the bag's other `llm.*` fields. An absent entry leaves the
// bag-derived variables untouched, so a missing document stays missing.

use std::collections::{BTreeMap, HashMap};

use cel::{Context, Value};
use praxis_policy_apl_core::attributes::{AttributeBag, AttributeValue};
use praxis_policy_apl_core::redact::payload_namespace;
use praxis_policy_apl_core::route::StructuredInput;

/// Build a CEL evaluation context from the policy bag plus the `cel:`
/// step's extra args.
///
/// - Every dotted bag key becomes nested CEL maps; each top-level segment
///   (`subject`, `role`, `delegation`, `session`, `args`, …) is registered
///   as a CEL variable.
/// - Each top-level key of `extra_args` (everything the author put under
///   `cel:` besides `expr`) is registered as an additional variable —
///   e.g. `resource`, `context` — mirroring how `cedar:` surfaces them.
/// - On a name collision between an `extra_args` key and a bag namespace,
///   the **bag wins** (the bag is the authoritative, framework-populated
///   vocabulary; args can't shadow it by accident).
/// - Structured `args` replaces the bag-derived `args` variable, and a
///   request document becomes `llm.request`.
///
/// The returned context also carries CEL's standard function/macro library
/// (via `Context::default`), so `has()`, `size()`, `all()`, `exists()`,
/// `map()`, `filter()`, string methods, etc. are all available.
pub fn bag_to_context(
    bag: &AttributeBag,
    extra_args: &serde_yaml::Value,
    structured: &StructuredInput,
) -> Context<'static> {
    let mut ctx = Context::default();

    // 1. Author-supplied extra args first (so the bag overrides on
    //    collision). Skip `expr` — that's the program text, not a
    //    variable.
    let mut extra_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(map) = extra_args.as_mapping() {
        for (k, v) in map {
            let Some(name) = k.as_str() else { continue };
            if name == "expr" {
                continue;
            }
            extra_names.insert(name.to_owned());
            ctx.add_variable_from_value(name.to_owned(), yaml_to_value(v));
        }
    }

    // 2. The bag namespaces (authoritative). Build the tree, then register
    //    each top-level node as a variable. Log when a bag namespace
    //    shadows an author-supplied extra arg with the same name — the
    //    bag wins by design, but a silent shadow can mask a typo in the
    //    author's args block.
    let mut root = build_tree(bag);
    overlay_structured(&mut root, structured);
    for (name, node) in root {
        if extra_names.contains(&name) {
            tracing::debug!(
                name = %name,
                "CEL activation: bag namespace shadows an extra-arg of the same name; \
                 bag value wins by design",
            );
        }
        ctx.add_variable_from_value(name, node_to_value(node));
    }

    ctx
}

/// Overlay structured input on the bag tree.
fn overlay_structured(root: &mut BTreeMap<String, Node>, structured: &StructuredInput) {
    if let Some(document) = structured.llm_request() {
        let llm = root
            .entry("llm".to_owned())
            .or_insert_with(|| Node::Branch(BTreeMap::new()));
        if let Node::Leaf(_) = llm {
            tracing::warn!(
                key = "llm",
                "CEL activation: scalar key collides with the request document; \
                 keeping the document and dropping the scalar"
            );
            *llm = Node::Branch(BTreeMap::new());
        }
        if let Node::Branch(children) = llm {
            children.insert("request".to_owned(), Node::Leaf(json_to_value(document)));
        }
    }
    if let Some(args) = structured.args() {
        root.insert("args".to_owned(), Node::Leaf(json_to_value(args)));
    }
}

/// A bag key as it may appear in a log line. Keys below a payload namespace
/// are client-chosen, so only the namespace is shown.
fn loggable_key(key: &str) -> &str {
    payload_namespace(key).unwrap_or(key)
}

/// Internal tree node: either a leaf scalar/list or a nested namespace.
enum Node {
    Leaf(Value),
    Branch(BTreeMap<String, Node>),
}

/// Build the top-level namespace tree from the flat, dotted bag.
fn build_tree(bag: &AttributeBag) -> BTreeMap<String, Node> {
    let mut root: BTreeMap<String, Node> = BTreeMap::new();
    for (key, value) in bag.iter() {
        let segments: Vec<&str> = key.split('.').collect();
        insert(&mut root, key, &segments, attr_to_value(value));
    }
    root
}

/// Insert a leaf at the dotted path, creating intermediate branches.
/// Namespace-wins on leaf/branch collisions (see module docs).
fn insert(level: &mut BTreeMap<String, Node>, full_key: &str, segments: &[&str], leaf: Value) {
    // `bag.iter()` never yields empty keys today, but iterator
    // contracts can drift — return cleanly rather than panic if a
    // future bag implementation emits one. The caller's leaf is just
    // dropped; no name to insert under.
    let Some((head, rest)) = segments.split_first() else {
        return;
    };
    let head = (*head).to_owned();

    if rest.is_empty() {
        // Terminal segment — place the leaf, unless a namespace already
        // claimed this name (namespace wins).
        match level.get(&head) {
            Some(Node::Branch(_)) => {
                tracing::warn!(
                    key = %loggable_key(full_key),
                    "CEL activation: scalar key collides with an existing namespace; \
                     keeping the namespace and dropping the scalar"
                );
            },
            _ => {
                level.insert(head, Node::Leaf(leaf));
            },
        }
        return;
    }

    // Intermediate segment — descend, converting a leaf into a branch if
    // needed (namespace wins).
    let entry = level
        .entry(head)
        .or_insert_with(|| Node::Branch(BTreeMap::new()));
    if let Node::Leaf(_) = entry {
        tracing::warn!(
            key = %loggable_key(full_key),
            "CEL activation: namespace prefix collides with an existing scalar; \
             promoting to a namespace and dropping the scalar"
        );
        *entry = Node::Branch(BTreeMap::new());
    }
    if let Node::Branch(child) = entry {
        insert(child, full_key, rest, leaf);
    }
}

/// Recursively convert a tree node into a `cel::Value`.
fn node_to_value(node: Node) -> Value {
    match node {
        Node::Leaf(v) => v,
        Node::Branch(children) => {
            let map: HashMap<String, Value> = children
                .into_iter()
                .map(|(k, child)| (k, node_to_value(child)))
                .collect();
            Value::from(map)
        },
    }
}

/// Convert one `AttributeValue` to a `cel::Value`.
///
/// An `f64` stays `Value::Float`; narrowing whole-valued floats breaks CEL
/// arithmetic such as `confidence * 100.0`.
fn attr_to_value(attr: &AttributeValue) -> Value {
    match attr {
        AttributeValue::Bool(b) => Value::from(*b),
        AttributeValue::Int(i) => Value::from(*i),
        AttributeValue::Float(f) => Value::from(*f),
        AttributeValue::String(s) => Value::from(s.clone()),
        // StringSet → list(string). Sort before yielding so authors
        // who reach for `session.labels[0]` (or any other
        // index-dependent operation) get a stable answer across runs
        // and rust releases. `in` / `exists` / `all` / `filter` don't
        // care about order, but determinism by construction beats
        // "works on my machine" when the policy ever indexes.
        AttributeValue::StringSet(set) => {
            let mut sorted: Vec<&String> = set.iter().collect();
            sorted.sort();
            let items: Vec<Value> = sorted.into_iter().map(|s| Value::from(s.clone())).collect();
            Value::from(items)
        },
    }
}

/// Convert a JSON value to a `cel::Value`. Integers map to `Int`, an integer
/// above `i64::MAX` to `UInt`, and other numbers to `Float`. Lists keep their
/// order and duplicates.
fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::from(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                Value::UInt(u)
            } else {
                Value::from(n.as_f64().unwrap_or(f64::NAN))
            }
        },
        serde_json::Value::String(s) => Value::from(s.clone()),
        serde_json::Value::Array(items) => {
            let items: Vec<Value> = items.iter().map(json_to_value).collect();
            Value::from(items)
        },
        serde_json::Value::Object(map) => {
            let out: HashMap<String, Value> = map
                .iter()
                .map(|(k, val)| (k.clone(), json_to_value(val)))
                .collect();
            Value::from(out)
        },
    }
}

/// Convert an author-supplied `cel:` argument to a `cel::Value`. Integers map
/// to `Int`, floats to `Float`, and non-string mapping keys are skipped.
fn yaml_to_value(v: &serde_yaml::Value) -> Value {
    match v {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::from(*b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else {
                Value::from(n.as_f64().unwrap_or(f64::NAN))
            }
        },
        serde_yaml::Value::String(s) => Value::from(s.clone()),
        serde_yaml::Value::Sequence(seq) => {
            let items: Vec<Value> = seq.iter().map(yaml_to_value).collect();
            Value::from(items)
        },
        serde_yaml::Value::Mapping(map) => {
            let mut out: HashMap<String, Value> = HashMap::new();
            for (k, val) in map {
                if let Some(name) = k.as_str() {
                    out.insert(name.to_owned(), yaml_to_value(val));
                }
            }
            Value::from(out)
        },
        // serde_yaml's tagged values are not used in APL configs; treat as null.
        _ => Value::Null,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    use serde_json::json;

    fn run_cel(expr: &str, ctx: &Context<'static>) -> Result<Value, String> {
        let program = cel::Program::compile(expr).map_err(|e| e.to_string())?;
        program.execute(ctx).map_err(|e| e.to_string())
    }

    fn truthy(expr: &str, bag: &AttributeBag) -> bool {
        let ctx = bag_to_context(bag, &serde_yaml::Value::Null, &StructuredInput::default());
        matches!(run_cel(expr, &ctx), Ok(Value::Bool(true)))
    }

    fn structured_ctx(bag: &AttributeBag, structured: &StructuredInput) -> Context<'static> {
        bag_to_context(bag, &serde_yaml::Value::Null, structured)
    }

    fn with_args(args: serde_json::Value) -> StructuredInput {
        StructuredInput::new(None, Some(Arc::new(args)))
    }

    fn with_document(document: serde_json::Value) -> StructuredInput {
        StructuredInput::new(Some(Arc::new(document)), None)
    }

    fn holds(expr: &str, ctx: &Context<'static>) -> bool {
        matches!(run_cel(expr, ctx), Ok(Value::Bool(true)))
    }

    fn insert_key(root: &mut BTreeMap<String, Node>, key: &str, leaf: Value) {
        let segments: Vec<&str> = key.split('.').collect();
        insert(root, key, &segments, leaf);
    }

    #[test]
    fn dotted_keys_become_nested_maps() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        bag.set("subject.type", "user");
        assert!(truthy("subject.id == 'alice'", &bag));
        assert!(truthy("subject.type == 'user'", &bag));
    }

    #[test]
    fn bool_int_float_scalars() {
        let mut bag = AttributeBag::new();
        bag.set("role.hr", true);
        bag.set("delegation.depth", 2_i64);
        bag.set("intent.confidence", 0.92_f64);
        assert!(truthy("role.hr", &bag));
        assert!(truthy("delegation.depth <= 2", &bag));
        assert!(truthy("intent.confidence > 0.9", &bag));
    }

    #[test]
    fn single_segment_key_is_top_level_variable() {
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        assert!(truthy("authenticated", &bag));
    }

    #[test]
    fn string_set_becomes_list_for_in_operator() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["PII".to_owned(), "compensation".to_owned()]),
        );
        assert!(truthy("'PII' in session.labels", &bag));
        assert!(truthy("'compensation' in session.labels", &bag));
        assert!(truthy("!('PHI' in session.labels)", &bag));
        // Comprehension macros work over the list too.
        assert!(truthy("session.labels.exists(l, l == 'PII')", &bag));
    }

    #[test]
    fn double_scalar_compares_against_int_literal() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2.0_f64);
        bag.set("intent.confidence", 0.92_f64);
        assert!(truthy("delegation.depth == 2", &bag));
        assert!(truthy("delegation.depth <= 2", &bag));
        // Genuine doubles still compare to double literals.
        assert!(truthy("intent.confidence > 0.9", &bag));
    }

    #[test]
    fn whole_valued_float_keeps_arithmetic() {
        let mut bag = AttributeBag::new();
        bag.set("intent.confidence", 1.0_f64);
        assert!(truthy("intent.confidence * 100.0 >= 90.0", &bag));
        bag.set("intent.confidence", 0.92_f64);
        assert!(truthy("intent.confidence * 100.0 >= 90.0", &bag));
    }

    #[test]
    fn mixed_int_float_comparison_is_order_independent() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2.0_f64);
        assert!(truthy("2 == delegation.depth", &bag));
        assert!(truthy("2 <= delegation.depth", &bag));
        assert!(truthy("2 >= delegation.depth", &bag));
        assert!(truthy("3 > delegation.depth", &bag));
        assert!(truthy("1 < delegation.depth", &bag));
        assert!(truthy("3 != delegation.depth", &bag));
    }

    #[test]
    fn whole_valued_float_in_int_list_matches() {
        let mut bag = AttributeBag::new();
        bag.set("delegation.depth", 2.0_f64);
        assert!(
            truthy("delegation.depth in [1, 2, 3]", &bag),
            "float 2.0 in int list"
        );
        bag.set("intent.confidence", 1.0_f64);
        assert!(
            truthy("intent.confidence in [0.5, 1.0]", &bag),
            "float in float list"
        );
    }

    /// `StringSet` is yielded in sorted order so indexing returns a
    /// stable value across runs. `"compensation" < "PII"` (ASCII;
    /// uppercase letters sort before lowercase, but both labels here
    /// are different cases so ordering is alphanumeric on the first
    /// char). Pinning the order keeps an author who reaches for
    /// `session.labels[0]` from getting different answers between
    /// builds.
    #[test]
    fn string_set_yields_sorted_order_for_stable_indexing() {
        let mut bag = AttributeBag::new();
        bag.set(
            "session.labels",
            HashSet::from(["zeta".to_owned(), "alpha".to_owned(), "mu".to_owned()]),
        );
        assert!(truthy("session.labels[0] == 'alpha'", &bag));
        assert!(truthy("session.labels[1] == 'mu'", &bag));
        assert!(truthy("session.labels[2] == 'zeta'", &bag));
    }

    #[test]
    fn has_macro_guards_optional_fields() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        // `subject` exists but has no `email` field → has() is false.
        assert!(truthy("has(subject.id) && !has(subject.email)", &bag));
    }

    #[test]
    fn extra_args_surface_as_variables_bag_wins_on_collision() {
        let mut bag = AttributeBag::new();
        bag.set("subject.id", "alice");
        let args = serde_yaml::from_str::<serde_yaml::Value>(
            "resource:\n  kind: document\n  sensitivity: 3\nsubject: shadowed\n",
        )
        .unwrap();
        let ctx = bag_to_context(&bag, &args, &StructuredInput::default());
        // Author-supplied `resource` is visible.
        assert!(matches!(
            run_cel(
                "resource.kind == 'document' && resource.sensitivity == 3",
                &ctx
            ),
            Ok(Value::Bool(true))
        ));
        // `subject` from the bag wins over the args' `subject: shadowed`.
        assert!(matches!(
            run_cel("subject.id == 'alice'", &ctx),
            Ok(Value::Bool(true))
        ));
    }

    #[test]
    fn namespace_wins_on_leaf_collision() {
        // Both `delegation` (scalar) and `delegation.depth` (under a
        // namespace) present — the namespace must win so `delegation.depth`
        // resolves rather than erroring on a scalar field access.
        let mut bag = AttributeBag::new();
        bag.set("delegation", "scalar-value");
        bag.set("delegation.depth", 3_i64);
        assert!(truthy("delegation.depth == 3", &bag));
    }

    #[test]
    fn namespace_wins_when_scalar_arrives_after_branch() {
        let mut root = BTreeMap::new();
        insert_key(&mut root, "delegation.depth", Value::from(3_i64));
        insert_key(
            &mut root,
            "delegation",
            Value::from("scalar-value".to_owned()),
        );

        assert!(
            matches!(
                root.get("delegation"),
                Some(Node::Branch(children))
                    if matches!(
                        children.get("depth"),
                        Some(Node::Leaf(Value::Int(3)))
                    )
            ),
            "namespace must retain its child",
        );
    }

    #[test]
    fn namespace_wins_when_branch_arrives_after_scalar() {
        let mut root = BTreeMap::new();
        insert_key(
            &mut root,
            "delegation",
            Value::from("scalar-value".to_owned()),
        );
        insert_key(&mut root, "delegation.depth", Value::from(3_i64));

        assert!(
            matches!(
                root.get("delegation"),
                Some(Node::Branch(children))
                    if matches!(
                        children.get("depth"),
                        Some(Node::Leaf(Value::Int(3)))
                    )
            ),
            "namespace must replace the scalar",
        );
    }

    #[test]
    fn json_types_convert_natively() {
        let structured = with_args(json!({
            "dupes": [1, 1],
            "nothing": null,
            "empty": {},
            "one": 1,
            "half": 0.5,
            "big": u64::MAX,
            "nested": [[{"a": 1}], []],
        }));
        let ctx = structured_ctx(&AttributeBag::new(), &structured);
        assert!(holds("size(args.dupes) == 2 && args.dupes[1] == 1", &ctx));
        assert!(holds("args.nothing == null", &ctx));
        assert!(holds("args.empty == {} && size(args.empty) == 0", &ctx));
        assert!(matches!(run_cel("args.one", &ctx), Ok(Value::Int(1))));
        assert!(
            matches!(run_cel("args.half", &ctx), Ok(Value::Float(f)) if (f - 0.5).abs() < f64::EPSILON)
        );
        assert!(matches!(
            run_cel("args.big", &ctx),
            Ok(Value::UInt(u64::MAX))
        ));
        assert!(matches!(run_cel("args.nothing", &ctx), Ok(Value::Null)));
        assert!(holds(
            "args.nested[0][0].a == 1 && size(args.nested[1]) == 0",
            &ctx
        ));
    }

    #[test]
    fn json_lists_keep_order() {
        let ctx = structured_ctx(&AttributeBag::new(), &with_args(json!({"ids": [3, 1, 2]})));
        assert!(holds("args.ids == [3, 1, 2]", &ctx));
    }

    #[test]
    fn structured_args_replace_bag_args() {
        let mut bag = AttributeBag::new();
        bag.set("args.region", "eu");
        bag.set("args.stale", "flattened-only");
        bag.set("subject.id", "alice");
        let ctx = structured_ctx(&bag, &with_args(json!({"region": "eu", "ids": [13]})));
        assert!(holds("args.region == 'eu' && !has(args.stale)", &ctx));
        assert!(holds("subject.id == 'alice'", &ctx));
    }

    #[test]
    fn bag_args_kept_without_structured_args() {
        let mut bag = AttributeBag::new();
        bag.set("args", "prompt text");
        assert!(truthy("args == 'prompt text'", &bag));
    }

    /// Structured `args` arrays compare as native numbers, and an explicit
    /// `null` is a present field.
    #[test]
    fn structured_args_numbers_and_nulls_are_native() {
        let ctx = structured_ctx(
            &AttributeBag::new(),
            &with_args(json!({"ids": [13], "note": null})),
        );
        assert!(holds("13 in args.ids", &ctx));
        assert!(holds("!('13' in args.ids)", &ctx));
        assert!(holds("has(args.note)", &ctx));
    }

    #[test]
    fn request_document_sits_beside_llm_metadata() {
        let mut bag = AttributeBag::new();
        bag.set("llm.model_id", "gpt-4o");
        let ctx = structured_ctx(
            &bag,
            &with_document(json!({"tools": [{"type": "function"}]})),
        );
        assert!(holds("llm.model_id == 'gpt-4o'", &ctx));
        assert!(holds("llm.request.tools[0].type == 'function'", &ctx));
    }

    #[test]
    fn request_document_replaces_scalar_llm_key() {
        let mut bag = AttributeBag::new();
        bag.set("llm", "scalar");
        let ctx = structured_ctx(&bag, &with_document(json!({"model": "m"})));
        assert!(holds("llm == {'request': {'model': 'm'}}", &ctx));
    }

    #[test]
    fn absent_document_stays_missing() {
        let mut bag = AttributeBag::new();
        bag.set("llm.model_id", "gpt-4o");
        let ctx = structured_ctx(&bag, &StructuredInput::default());
        assert!(holds("!has(llm.request)", &ctx));
        let err = run_cel("size(llm.request.tools) == 0", &ctx).unwrap_err();
        assert!(err.contains("No such key"), "{err}");
    }
}
