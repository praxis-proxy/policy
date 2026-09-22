// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Decision-cache contract against a real OPA resolver.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::sync::Arc;

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::step::{PdpCall, PdpDialect, PdpResolver};
use praxis_policy_apl_runtime::{CacheContractSamples, run_cache_contract};
use praxis_policy_pdp_opa::OpaResolver;

fn query_call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Opa,
        args: serde_yaml::from_str("query: data.authz.allow\n").unwrap(),
    }
}

fn error_call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Opa,
        args: serde_yaml::Value::Null,
    }
}

fn bag(id: &str) -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", id);
    bag
}

#[tokio::test]
async fn opa_decision_cache_contract() {
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
kind: opa
modules:
  - |
    package authz
    default allow := false
    allow if input.subject.id == "alice"
"#,
    )
    .unwrap();
    let inner: Arc<dyn PdpResolver> = Arc::new(OpaResolver::from_config(&config).expect("opa"));
    run_cache_contract(
        inner,
        CacheContractSamples {
            allow: (query_call(), bag("alice")),
            deny: (query_call(), bag("bob")),
            error: (error_call(), bag("alice")),
            extra_bags: [bag("carol"), bag("dave")],
        },
    )
    .await;
}
