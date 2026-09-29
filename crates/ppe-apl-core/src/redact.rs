// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Keeps payload values out of PDP-generated reasons and diagnostics.
//!
//! Values under a payload namespace come from the client, so a PDP must not
//! echo them. Engines render such values as a [`TypeLabel`] and name payload
//! paths only down to their [`payload_namespace`].

use std::fmt;

/// Namespaces whose values come from the request or response payload.
const PAYLOAD_NAMESPACES: &[&str] = &["args", "result", "llm.request"];

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
