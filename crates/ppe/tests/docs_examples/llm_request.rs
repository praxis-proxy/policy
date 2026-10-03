// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The tool-type allowlist examples in the PDP page, loaded and run.
//
// Loading a config proves it parses, not that its policy does what the page
// says. Each block marked `<!-- evaluate: llm-tool-allowlist -->` is loaded
// with the builtin PDPs and run against inference requests, so the example
// keeps denying a tool type it does not list.

use std::sync::Arc;

use praxis_policy::{PolicyEngine, install_builtins};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::extensions::{
    LlmRequestDocument, MetaExtension, SecurityExtension, SubjectExtension,
};
use praxis_policy_core::hooks::payload::Extensions;
use serde_json::{Value, json};

use super::docs_root;

const MARKER: &str = "<!-- evaluate: llm-tool-allowlist -->";

/// The yaml block after each marker on the PDP page.
fn marked_examples() -> Vec<String> {
    let page =
        std::fs::read_to_string(docs_root().join("content/apl/pdp.md")).expect("read pdp.md");
    let mut examples = Vec::new();
    let mut lines = page.lines();
    while let Some(line) = lines.next() {
        if line.trim() != MARKER {
            continue;
        }
        let fence = lines
            .by_ref()
            .find(|l| !l.trim().is_empty())
            .expect("a fence after the marker");
        assert_eq!(
            fence.trim(),
            "```yaml",
            "the marker must precede a yaml fence"
        );
        let body: Vec<&str> = lines
            .by_ref()
            .take_while(|l| !l.starts_with("```"))
            .collect();
        examples.push(body.join("\n"));
    }
    examples
}

async fn engine(yaml: &str) -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    install_builtins(&mgr);
    mgr.load_config_yaml(yaml).expect("load example");
    mgr.initialize().await.expect("initialize");
    mgr
}

fn extensions(document: Option<Value>) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("llm".to_owned()),
            entity_name: Some("gpt-4o".to_owned()),
            ..Default::default()
        })),
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        llm_request: document.map(LlmRequestDocument::new),
        ..Default::default()
    }
}

async fn allows(mgr: &PolicyEngine, document: Option<Value>) -> bool {
    let payload = MessagePayload {
        message: Message::text(Role::User, "hello"),
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_input", payload, extensions(document), None)
        .await;
    result.continue_processing
}

#[tokio::test]
async fn tool_allowlist_examples_deny_unlisted_types() {
    let examples = marked_examples();
    assert_eq!(examples.len(), 2, "expected the OPA and CEL examples");

    for yaml in &examples {
        let mgr = engine(yaml).await;
        let unlisted = json!({
            "model": "gpt-4o",
            "tools": [{"type": "function", "function": {}}, {"type": "web_search_20250305"}],
        });
        assert!(
            !allows(&mgr, Some(unlisted)).await,
            "unlisted type allowed:\n{yaml}"
        );

        let listed = json!({
            "model": "gpt-4o",
            "tools": [{"type": "function", "function": {}}, {"type": "code_execution_20250522"}],
        });
        assert!(
            allows(&mgr, Some(listed)).await,
            "listed types denied:\n{yaml}"
        );

        let untyped = json!({"tools": [{"function": {}}]});
        assert!(
            !allows(&mgr, Some(untyped)).await,
            "untyped tool allowed:\n{yaml}"
        );

        let no_tools = json!({"model": "gpt-4o", "messages": []});
        assert!(
            allows(&mgr, Some(no_tools)).await,
            "no tools denied:\n{yaml}"
        );

        assert!(
            !allows(&mgr, None).await,
            "absent document allowed:\n{yaml}"
        );
    }
}
