// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// MCPExtension → AttributeBag.
//
// Tool, resource, and prompt metadata each flatten under their own sub-namespace.
//
// `annotations` flattens through the same JSON walker as `custom.*`,
// `framework.metadata.*` and `claim.*`. Being free-form is not what keeps a map
// off the bag, or none of those four would be on it; `readOnlyHint` and
// `destructiveHint` live here and are what a tool-gating rule reads.
//
// The schemas and the prompt's argument list stay off. They describe the shape
// of a call rather than a fact about it, so a rule over them would be asserting
// something about the contract, not about this request. The arguments
// themselves reach policy as `args.*`.
//
// Namespace:
//   mcp.tool.name           : String     (always set if tool present)
//   mcp.tool.title          : String
//   mcp.tool.description    : String
//   mcp.tool.server_id      : String
//   mcp.tool.namespace      : String
//   mcp.tool.annotations.<k>: flattened JSON (JSON walker — same as custom.*)
//   mcp.resource.uri        : String     (always set if resource present)
//   mcp.resource.name       : String
//   mcp.resource.description: String
//   mcp.resource.mime_type  : String
//   mcp.resource.server_id  : String
//   mcp.resource.annotations.<k> : flattened JSON
//   mcp.prompt.name         : String     (always set if prompt present)
//   mcp.prompt.description  : String
//   mcp.prompt.server_id    : String
//   mcp.prompt.annotations.<k>   : flattened JSON

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::MCPExtension;

/// Write tool and resource metadata into the bag.
pub fn extract_mcp(mcp: &MCPExtension, bag: &mut AttributeBag) {
    if let Some(tool) = &mcp.tool {
        bag.set("mcp.tool.name", tool.name.clone());
        if let Some(v) = &tool.title {
            bag.set("mcp.tool.title", v.clone());
        }
        if let Some(v) = &tool.description {
            bag.set("mcp.tool.description", v.clone());
        }
        if let Some(v) = &tool.server_id {
            bag.set("mcp.tool.server_id", v.clone());
        }
        if let Some(v) = &tool.namespace {
            bag.set("mcp.tool.namespace", v.clone());
        }
        for (k, v) in &tool.annotations {
            crate::payload::walk(v, &format!("mcp.tool.annotations.{k}"), bag);
        }
    }
    if let Some(res) = &mcp.resource {
        bag.set("mcp.resource.uri", res.uri.clone());
        if let Some(v) = &res.name {
            bag.set("mcp.resource.name", v.clone());
        }
        if let Some(v) = &res.description {
            bag.set("mcp.resource.description", v.clone());
        }
        if let Some(v) = &res.mime_type {
            bag.set("mcp.resource.mime_type", v.clone());
        }
        if let Some(v) = &res.server_id {
            bag.set("mcp.resource.server_id", v.clone());
        }
        for (k, v) in &res.annotations {
            crate::payload::walk(v, &format!("mcp.resource.annotations.{k}"), bag);
        }
    }
    if let Some(prompt) = &mcp.prompt {
        bag.set("mcp.prompt.name", prompt.name.clone());
        if let Some(v) = &prompt.description {
            bag.set("mcp.prompt.description", v.clone());
        }
        if let Some(v) = &prompt.server_id {
            bag.set("mcp.prompt.server_id", v.clone());
        }
        for (k, v) in &prompt.annotations {
            crate::payload::walk(v, &format!("mcp.prompt.annotations.{k}"), bag);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::extensions::mcp::{PromptMetadata, ResourceMetadata, ToolMetadata};

    #[test]
    fn tool_metadata_flattens() {
        let mcp = MCPExtension {
            tool: Some(ToolMetadata {
                name: "get_compensation".into(),
                description: Some("HR comp lookup".into()),
                server_id: Some("hr-srv".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_mcp(&mcp, &mut bag);
        assert_eq!(bag.get_string("mcp.tool.name"), Some("get_compensation"));
        assert_eq!(
            bag.get_string("mcp.tool.description"),
            Some("HR comp lookup")
        );
        assert_eq!(bag.get_string("mcp.tool.server_id"), Some("hr-srv"));
        // Schemas are deliberately not in the bag.
        assert!(!bag.contains("mcp.tool.input_schema"));
    }

    /// The annotations a tool-gating rule actually wants. `readOnlyHint` and
    /// `destructiveHint` are the reason this map is bridged rather than left
    /// off for being free-form, so a rule can refuse a destructive tool.
    #[test]
    fn tool_annotations_flatten_through_the_json_walker() {
        let mcp = MCPExtension {
            tool: Some(ToolMetadata {
                name: "delete_record".into(),
                annotations: [
                    ("readOnlyHint".to_owned(), serde_json::json!(false)),
                    ("destructiveHint".to_owned(), serde_json::json!(true)),
                    (
                        "audience".to_owned(),
                        serde_json::json!({"tier": "internal"}),
                    ),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_mcp(&mcp, &mut bag);
        assert_eq!(
            bag.get_bool("mcp.tool.annotations.readOnlyHint"),
            Some(false)
        );
        assert_eq!(
            bag.get_bool("mcp.tool.annotations.destructiveHint"),
            Some(true)
        );
        // Nested objects flatten to their leaves, the way `custom.*` does, so
        // no parent key stands for the object itself.
        assert_eq!(
            bag.get_string("mcp.tool.annotations.audience.tier"),
            Some("internal")
        );
        assert!(!bag.contains("mcp.tool.annotations.audience"));
    }

    /// The other two namespaces carry the same map, and a rule written for one
    /// should read the same on the others.
    #[test]
    fn resource_and_prompt_annotations_flatten_too() {
        let annotations: std::collections::HashMap<String, serde_json::Value> =
            [("tier".to_owned(), serde_json::json!("gold"))]
                .into_iter()
                .collect();
        let mcp = MCPExtension {
            resource: Some(ResourceMetadata {
                uri: "file:///x".into(),
                annotations: annotations.clone(),
                ..Default::default()
            }),
            prompt: Some(PromptMetadata {
                name: "summarize".into(),
                annotations,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_mcp(&mcp, &mut bag);
        assert_eq!(
            bag.get_string("mcp.resource.annotations.tier"),
            Some("gold")
        );
        assert_eq!(bag.get_string("mcp.prompt.annotations.tier"), Some("gold"));
    }

    #[test]
    fn resource_uri_is_required_field() {
        let mcp = MCPExtension {
            resource: Some(ResourceMetadata {
                uri: "hr://employees/123".into(),
                mime_type: Some("application/json".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_mcp(&mcp, &mut bag);
        assert_eq!(
            bag.get_string("mcp.resource.uri"),
            Some("hr://employees/123")
        );
        assert_eq!(
            bag.get_string("mcp.resource.mime_type"),
            Some("application/json")
        );
    }
}
