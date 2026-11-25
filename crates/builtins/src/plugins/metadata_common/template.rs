// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::BTreeSet;

use praxis_policy_apl_core::{AttributeBag, AttributeValue};
use serde_json::{Number, Value};

use super::CalloutFailure;
use praxis_policy_core::metadata_callout::MetadataCalloutErrorCode;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Part {
    Literal(String),
    Reference(String),
}

/// A template compiled once at plugin load.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Template {
    parts: Vec<Part>,
    exact_reference: Option<String>,
}

impl Template {
    pub(crate) fn compile(raw: &str, references: &mut BTreeSet<String>) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut rest = raw;
        while let Some(open) = rest.find('{') {
            let (literal, after_open) = rest.split_at(open);
            if !literal.is_empty() {
                parts.push(Part::Literal(literal.to_owned()));
            }
            let after_open = after_open
                .get(1..)
                .ok_or_else(|| "template ended after an opening brace".to_owned())?;
            let close = after_open
                .find('}')
                .ok_or_else(|| "template has an unmatched opening brace".to_owned())?;
            let reference = after_open
                .get(..close)
                .ok_or_else(|| "template reference is not valid UTF-8".to_owned())?
                .trim();
            if reference.is_empty()
                || reference.contains(['{', '}'])
                || reference.chars().any(char::is_whitespace)
            {
                return Err("template contains an invalid attribute reference".to_owned());
            }
            references.insert(reference.to_owned());
            parts.push(Part::Reference(reference.to_owned()));
            rest = after_open
                .get(close + 1..)
                .ok_or_else(|| "template suffix is not valid UTF-8".to_owned())?;
        }
        if rest.contains('}') {
            return Err("template has an unmatched closing brace".to_owned());
        }
        if !rest.is_empty() {
            parts.push(Part::Literal(rest.to_owned()));
        }
        if parts.is_empty() {
            parts.push(Part::Literal(String::new()));
        }
        let exact_reference = match parts.as_slice() {
            [Part::Reference(reference)] => Some(reference.clone()),
            _ => None,
        };
        Ok(Self {
            parts,
            exact_reference,
        })
    }

    pub(crate) fn render_text(&self, bag: &AttributeBag) -> Result<String, CalloutFailure> {
        let mut rendered = String::new();
        for part in &self.parts {
            match part {
                Part::Literal(literal) => rendered.push_str(literal),
                Part::Reference(reference) => {
                    rendered.push_str(&scalar_text(bag.get(reference)).ok_or_else(bad_response)?);
                },
            }
        }
        Ok(rendered)
    }

    pub(crate) fn references(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|part| match part {
            Part::Reference(reference) => Some(reference.as_str()),
            Part::Literal(_) => None,
        })
    }

    pub(crate) const fn is_exact_reference(&self) -> bool {
        self.exact_reference.is_some()
    }

    pub(crate) fn render_repeated(
        &self,
        bag: &AttributeBag,
    ) -> Result<Vec<String>, CalloutFailure> {
        if let Some(reference) = &self.exact_reference
            && let Some(AttributeValue::StringSet(values)) = bag.get(reference)
        {
            let mut values: Vec<_> = values.iter().cloned().collect();
            values.sort_unstable();
            return Ok(values);
        }
        self.render_text(bag).map(|value| vec![value])
    }

    pub(crate) fn render_json(&self, bag: &AttributeBag) -> Result<Value, CalloutFailure> {
        let Some(reference) = &self.exact_reference else {
            return self.render_text(bag).map(Value::String);
        };
        match bag.get(reference).ok_or_else(bad_response)? {
            AttributeValue::Bool(value) => Ok(Value::Bool(*value)),
            AttributeValue::Int(value) => Ok(Value::Number(Number::from(*value))),
            AttributeValue::Float(value) => Number::from_f64(*value)
                .map(Value::Number)
                .ok_or_else(bad_response),
            AttributeValue::String(value) => Ok(Value::String(value.clone())),
            AttributeValue::StringSet(values) => {
                let mut values: Vec<_> = values.iter().cloned().collect();
                values.sort_unstable();
                Ok(Value::Array(
                    values.into_iter().map(Value::String).collect(),
                ))
            },
            AttributeValue::NonScalar => Err(bad_response()),
        }
    }
}

fn scalar_text(value: Option<&AttributeValue>) -> Option<String> {
    match value? {
        AttributeValue::Bool(value) => Some(value.to_string()),
        AttributeValue::Int(value) => Some(value.to_string()),
        AttributeValue::Float(value) if value.is_finite() => Some(value.to_string()),
        AttributeValue::String(value) => Some(value.clone()),
        AttributeValue::Float(_) | AttributeValue::StringSet(_) | AttributeValue::NonScalar => None,
    }
}

const fn bad_response() -> CalloutFailure {
    CalloutFailure::new(MetadataCalloutErrorCode::BadResponse)
}
