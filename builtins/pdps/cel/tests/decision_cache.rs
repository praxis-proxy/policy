// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Decision-cache contract against a real CEL resolver.

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
use praxis_policy_pdp_cel::CelResolver;

fn expr_call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Cel,
        args: serde_yaml::from_str("expr: \"subject.id == \\\"alice\\\"\"\n").unwrap(),
    }
}

fn error_call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Cel,
        args: serde_yaml::Value::Null,
    }
}

fn bag(id: &str) -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", id);
    bag
}

#[tokio::test]
async fn cel_decision_cache_contract() {
    let inner: Arc<dyn PdpResolver> = Arc::new(
        CelResolver::from_config(&serde_yaml::from_str("kind: cel\n").unwrap())
            .expect("cel config"),
    );
    run_cache_contract(
        inner,
        CacheContractSamples {
            allow: (expr_call(), bag("alice")),
            deny: (expr_call(), bag("bob")),
            error: (error_call(), bag("alice")),
            extra_bags: [bag("carol"), bag("dave")],
        },
    )
    .await;
}
