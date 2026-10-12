// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! MCP tool-call builders, shaped the way the praxis policy filter builds
//! them (`json_rpc.rs` and `extensions_from_identity` in `filter.rs`).

use std::collections::HashMap;
use std::sync::Arc;

use praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall, ToolResult};
use praxis_policy_core::extensions::{AgentExtension, Extensions, HttpExtension, MetaExtension};
use serde_json::{Value, json};

/// A JSON-RPC `tools/call` request body.
#[must_use]
pub fn tool_call_body(id: u64, tool: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool, "arguments": arguments },
    })
}

/// The CMF request payload for a tool call. A non-object `arguments`
/// becomes an empty map, as in the filter.
#[must_use]
pub fn tool_call(call_id: &str, tool: &str, arguments: &Value) -> MessagePayload {
    let arguments = arguments
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: call_id.to_owned(),
                    name: tool.to_owned(),
                    arguments,
                    namespace: None,
                },
            }],
        ),
    }
}

/// The CMF response payload for a tool result.
#[must_use]
pub fn tool_result(call_id: &str, tool: &str, content: Value, is_error: bool) -> MessagePayload {
    MessagePayload {
        message: Message::with_content(
            Role::Assistant,
            vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: call_id.to_owned(),
                    tool_name: tool.to_owned(),
                    content,
                    is_error,
                },
            }],
        ),
    }
}

/// Route-matching meta for a tool.
fn meta_for_tool(tool: &str) -> MetaExtension {
    MetaExtension {
        entity_type: Some("tool".to_owned()),
        entity_name: Some(tool.to_owned()),
        ..Default::default()
    }
}

/// The HTTP view of a `POST /mcp`, header names lowercased.
pub(crate) fn http_extension(headers: &HashMap<String, String>) -> HttpExtension {
    HttpExtension {
        method: Some("POST".to_owned()),
        path: Some("/mcp".to_owned()),
        host: Some("gateway.test".to_owned()),
        scheme: Some("https".to_owned()),
        request_headers: headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect(),
        ..Default::default()
    }
}

/// Stamp tool meta, HTTP attributes and, when given, the session id onto
/// `ext`, keeping whatever identity it already carries.
#[must_use]
pub fn tool_extensions(
    mut ext: Extensions,
    tool: &str,
    headers: &HashMap<String, String>,
    session_id: Option<&str>,
) -> Extensions {
    let mut meta = ext.meta.as_deref().cloned().unwrap_or_default();
    let tool_meta = meta_for_tool(tool);
    meta.entity_type = tool_meta.entity_type;
    meta.entity_name = tool_meta.entity_name;
    ext.meta = Some(Arc::new(meta));
    ext.http = Some(Arc::new(http_extension(headers)));
    if let Some(id) = session_id.filter(|id| !id.is_empty()) {
        let mut agent = ext
            .agent
            .as_deref()
            .cloned()
            .unwrap_or_else(AgentExtension::default);
        agent.session_id = Some(id.to_owned());
        ext.agent = Some(Arc::new(agent));
    }
    ext
}
