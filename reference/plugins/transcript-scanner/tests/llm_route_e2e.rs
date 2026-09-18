// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The scanner behind a real `llm:` route: config load, the APL route handler,
// and the engine's capability filter between them. The unit tests hand the
// scanner its extensions directly, so they cannot catch the history being
// filtered out on the way in. A deny here can only come from the scanner
// having read the history the host sent.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::sync::Arc;

use praxis_policy_apl_runtime::{AplOptions, DispatchCache, MemorySessionStore, register_apl};
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload, Role};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{AgentExtension, ConversationContext, MetaExtension};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_plugin_transcript_scanner::{KIND, TranscriptScannerFactory};

const YAML: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: transcript-scan
    kind: validator/transcript-scan
    hooks: [cmf.llm_input]
    capabilities: [read_agent]
    config:
      patterns:
        - name: api_key
          regex: "sk-[A-Za-z0-9]{8,}"
routes:
  - llm: gpt-4
    authorization:
      pre_invocation:
        - "run(transcript-scan)"
"#;

async fn engine() -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory(KIND, Box::new(TranscriptScannerFactory));
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

fn llm_request(history: Vec<Message>) -> Extensions {
    let meta = MetaExtension {
        entity_type: Some("llm".to_owned()),
        entity_name: Some("gpt-4".to_owned()),
        ..Default::default()
    };
    Extensions {
        meta: Some(Arc::new(meta)),
        agent: Some(Arc::new(AgentExtension {
            conversation: Some(ConversationContext {
                history,
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "and what should I do next?"),
    }
}

#[tokio::test]
async fn a_secret_in_history_denies_the_llm_call() {
    let mgr = engine().await;
    let ext = llm_request(vec![
        Message::text(Role::User, "here is my key: sk-live0123456789"),
        Message::text(Role::Assistant, "thanks, noted"),
    ]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_input", payload(), ext, None)
        .await;

    assert!(!result.continue_processing, "the route must deny");
    let v = result.violation.expect("a deny carries a violation");
    assert_eq!(v.code, "transcript.detected", "reason: {}", v.reason);
}

/// The same request with clean history goes through, so the deny above is the
/// scanner's verdict on the history and not the route refusing everything.
#[tokio::test]
async fn clean_history_is_allowed() {
    let mgr = engine().await;
    let ext = llm_request(vec![Message::text(Role::User, "hello")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.llm_input", payload(), ext, None)
        .await;

    assert!(
        result.continue_processing,
        "clean history should pass: {:?}",
        result.violation
    );
}
