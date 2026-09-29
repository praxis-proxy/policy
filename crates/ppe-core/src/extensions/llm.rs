// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// LLMExtension — model identity and capabilities.

use std::{fmt, sync::Arc};

use serde::{Deserialize, Serialize};

/// Model identity and capabilities.
///
/// Immutable — set by the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LLMExtension {
    /// Model identifier (e.g., "gpt-4o", "claude-sonnet-4-20250514").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,

    /// Provider name (e.g., "openai", "anthropic").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Model capabilities (e.g., "`tool_use`", "vision", "streaming").
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Host-parsed LLM request body, shared without copying.
///
/// `Debug` prints only the JSON kind, so logging extensions never dumps the payload.
#[derive(Clone)]
pub struct LlmRequestDocument(Arc<serde_json::Value>);

impl LlmRequestDocument {
    /// Wraps a parsed request body.
    #[must_use]
    pub fn new(value: serde_json::Value) -> Self {
        Self(Arc::new(value))
    }

    /// The parsed request body.
    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.0
    }

    /// The shared handle, for passing the body on without a copy.
    #[must_use]
    pub fn shared(&self) -> &Arc<serde_json::Value> {
        &self.0
    }
}

impl fmt::Debug for LlmRequestDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.value() {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        };
        write!(f, "LlmRequestDocument(<{kind}>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_hides_request_body() {
        let doc = LlmRequestDocument::new(serde_json::json!({"messages": ["secret-marker"]}));
        let rendered = format!("{doc:?}");
        assert_eq!(rendered, "LlmRequestDocument(<object>)");
        assert!(!rendered.contains("secret-marker"));
    }
}
