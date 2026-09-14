// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Decision-cache wiring: YAML opt-in, factory wrap, and the shared contract
// against a counting fake so hit/miss/error behaviour is observable.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::step::{
    PdpCall, PdpDecision, PdpDialect, PdpError, PdpFactory, PdpResolver,
};
use praxis_policy_apl_runtime::{
    AplOptions, CacheContractSamples, DispatchCache, MemorySessionStore, register_apl,
    run_cache_contract,
};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{
    MetaExtension, SecurityExtension, SubjectExtension, SubjectType,
};
use praxis_policy_core::hooks::payload::Extensions;

struct CountingResolver {
    calls: Arc<AtomicU64>,
}

#[async_trait]
impl PdpResolver for CountingResolver {
    fn dialect(&self) -> PdpDialect {
        PdpDialect::Custom("counter".to_owned())
    }

    async fn evaluate(&self, _call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match bag.get_string("subject.id") {
            Some("err") => Err(PdpError::Dispatch("timeout".to_owned())),
            Some("alice") => Ok(PdpDecision {
                decision: Decision::Allow,
                diagnostics: vec!["count".to_owned()],
            }),
            _ => Ok(PdpDecision {
                decision: Decision::Deny {
                    reason: Some("not alice".to_owned()),
                    rule_source: "counter".to_owned(),
                },
                diagnostics: Vec::new(),
            }),
        }
    }
}

struct CountingFactory {
    calls: Arc<AtomicU64>,
}

impl PdpFactory for CountingFactory {
    fn kind(&self) -> &str {
        "counter"
    }

    fn build(
        &self,
        _config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Arc::new(CountingResolver {
            calls: Arc::clone(&self.calls),
        }))
    }
}

fn bag(id: &str) -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", id);
    bag
}

fn call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Custom("counter".to_owned()),
        args: serde_yaml::from_str("x: 1\n").unwrap(),
    }
}

#[tokio::test]
async fn counting_resolver_covers_the_cache_contract() {
    let inner: Arc<dyn PdpResolver> = Arc::new(CountingResolver {
        calls: Arc::new(AtomicU64::new(0)),
    });
    run_cache_contract(
        inner,
        CacheContractSamples {
            allow: (call(), bag("alice")),
            deny: (call(), bag("bob")),
            error: (call(), bag("err")),
            extra_bags: [bag("carol"), bag("dave")],
        },
    )
    .await;
}

const CACHED_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: counter
      cache:
        ttl_seconds: 60
        max_entries: 8
routes:
  - tool: ping
    authorization:
      pre_invocation:
        - pdp(counter):
            x: 1
"#;

const UNCACHED_YAML: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: counter
routes:
  - tool: ping
    authorization:
      pre_invocation:
        - pdp(counter):
            x: 1
"#;

async fn load(yaml: &str, calls: Arc<AtomicU64>) -> Arc<PolicyEngine> {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: vec![Arc::new(CountingFactory { calls })],
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

fn alice_ext() -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some("ping".to_owned()),
            ..Default::default()
        })),
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice".to_owned()),
                subject_type: Some(SubjectType::User),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "ping"),
    }
}

async fn invoke(mgr: &Arc<PolicyEngine>) {
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload(), alice_ext(), None)
        .await;
    assert!(
        result.continue_processing,
        "alice must be allowed, violation={:?}",
        result.violation
    );
}

#[tokio::test]
async fn yaml_cache_reuses_the_backend_on_the_second_call() {
    let calls = Arc::new(AtomicU64::new(0));
    let mgr = load(CACHED_YAML, Arc::clone(&calls)).await;
    invoke(&mgr).await;
    invoke(&mgr).await;
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "the second identical request must be served from the decision cache"
    );
}

#[tokio::test]
async fn omitted_cache_block_evaluates_every_time() {
    let calls = Arc::new(AtomicU64::new(0));
    let mgr = load(UNCACHED_YAML, Arc::clone(&calls)).await;
    invoke(&mgr).await;
    invoke(&mgr).await;
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "without cache: the backend must run per request"
    );
}

#[tokio::test]
async fn zero_ttl_is_rejected_at_load() {
    const BAD: &str = r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: counter
      cache:
        ttl_seconds: 0
        max_entries: 8
routes:
  - tool: ping
    authorization:
      pre_invocation:
        - pdp(counter):
            x: 1
"#;
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: vec![Arc::new(CountingFactory {
                calls: Arc::new(AtomicU64::new(0)),
            })],
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    let err = mgr
        .load_config_yaml(BAD)
        .expect_err("zero TTL must fail load");
    let msg = err.to_string();
    assert!(
        msg.contains("ttl_seconds"),
        "load error must name ttl_seconds, got {msg}"
    );
}
