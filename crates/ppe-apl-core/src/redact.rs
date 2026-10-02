// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Keeps payload values out of PDP-generated reasons and diagnostics.
//!
//! Values under a payload namespace may contain client data, so a PDP must not
//! echo them. Engines render such values as a [`TypeLabel`] and name payload
//! paths only down to their [`payload_namespace`].

use std::fmt;

use crate::attributes::AttributeValue;

/// Namespaces whose values come from the request or response payload.
const PAYLOAD_NAMESPACES: &[&str] = &[
    "args",
    "result",
    "llm.request",
    "custom",
    "http.request_headers",
    "http.response_headers",
];

/// The payload namespace a dotted path falls under, if any.
///
/// `args.items` yields `Some("args")`, `llm.request.tools` yields
/// `Some("llm.request")`, and `llm.model_id` or `subject.id` yield `None`.
pub fn payload_namespace(path: &str) -> Option<&'static str> {
    PAYLOAD_NAMESPACES.iter().copied().find(|ns| {
        path.strip_prefix(ns)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
    })
}

/// The type of a value, printed without its contents or child keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeLabel {
    /// A null.
    Null,
    /// A boolean.
    Bool,
    /// An integer.
    Int,
    /// A floating-point number.
    Float,
    /// A string.
    String,
    /// An ordered list with this many elements.
    List(usize),
    /// A set with this many elements.
    Set(usize),
    /// A map or object.
    Map,
}

impl TypeLabel {
    /// The label of a JSON value.
    pub fn of_json(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(_) => Self::Bool,
            serde_json::Value::Number(n) if n.is_f64() => Self::Float,
            serde_json::Value::Number(_) => Self::Int,
            serde_json::Value::String(_) => Self::String,
            serde_json::Value::Array(items) => Self::List(items.len()),
            serde_json::Value::Object(_) => Self::Map,
        }
    }
}

impl From<&AttributeValue> for TypeLabel {
    fn from(value: &AttributeValue) -> Self {
        match value {
            AttributeValue::Bool(_) => Self::Bool,
            AttributeValue::Int(_) => Self::Int,
            AttributeValue::Float(_) => Self::Float,
            AttributeValue::String(_) => Self::String,
            AttributeValue::StringSet(set) => Self::Set(set.len()),
        }
    }
}

impl fmt::Display for TypeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool => f.write_str("bool"),
            Self::Int => f.write_str("int"),
            Self::Float => f.write_str("float"),
            Self::String => f.write_str("string"),
            Self::List(n) => write!(f, "list({n})"),
            Self::Set(n) => write!(f, "set({n})"),
            Self::Map => f.write_str("map"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_paths_are_recognized() {
        assert_eq!(payload_namespace("args"), Some("args"));
        assert_eq!(payload_namespace("args.items"), Some("args"));
        assert_eq!(payload_namespace("result.rows"), Some("result"));
        assert_eq!(payload_namespace("llm.request"), Some("llm.request"));
        assert_eq!(payload_namespace("llm.request.tools"), Some("llm.request"));
        assert_eq!(payload_namespace("custom.llm.temperature"), Some("custom"));
        assert_eq!(payload_namespace("custom.anything_else"), Some("custom"));
        assert_eq!(
            payload_namespace("http.request_headers.authorization"),
            Some("http.request_headers")
        );
        assert_eq!(
            payload_namespace("http.response_headers.server"),
            Some("http.response_headers")
        );
    }

    #[test]
    fn identity_meta_and_llm_metadata_are_not_payload() {
        for path in [
            "subject.role",
            "meta.entity_name",
            "llm.model_id",
            "llm.provider",
            "llm",
            "argsx",
            "llm.requests",
            "",
        ] {
            assert_eq!(payload_namespace(path), None, "{path}");
        }
    }

    #[test]
    fn json_values_label_by_type() {
        let labels: Vec<String> = [
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!(1),
            serde_json::json!(u64::MAX),
            serde_json::json!(0.5),
            serde_json::json!("secret"),
            serde_json::json!([1, 1]),
            serde_json::json!({"secret": "x"}),
        ]
        .iter()
        .map(|v| TypeLabel::of_json(v).to_string())
        .collect();
        assert_eq!(
            labels,
            [
                "null", "bool", "int", "int", "float", "string", "list(2)", "map"
            ]
        );
    }

    #[test]
    fn attribute_values_label_by_type() {
        let set = std::collections::HashSet::from(["a".to_owned(), "b".to_owned()]);
        assert_eq!(
            TypeLabel::from(&AttributeValue::StringSet(set)),
            TypeLabel::Set(2)
        );
        assert_eq!(
            TypeLabel::from(&AttributeValue::String("secret".into())),
            TypeLabel::String
        );
    }

    #[test]
    fn labels_carry_only_type_and_size() {
        let rendered: Vec<String> = [
            TypeLabel::Null,
            TypeLabel::Bool,
            TypeLabel::Int,
            TypeLabel::Float,
            TypeLabel::String,
            TypeLabel::List(2),
            TypeLabel::Set(3),
            TypeLabel::Map,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            rendered,
            [
                "null", "bool", "int", "float", "string", "list(2)", "set(3)", "map"
            ]
        );
    }
}
