// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Decision-cache contract against a real Cedar resolver.

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
use praxis_policy_pdp_cedar_direct::CedarDirectResolver;

fn read_call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Cedar,
        args: serde_yaml::from_str(
            r#"
action: 'Action::"read"'
resource:
  type: Document
  id: doc-1
"#,
        )
        .unwrap(),
    }
}

fn error_call() -> PdpCall {
    PdpCall {
        dialect: PdpDialect::Cedar,
        args: serde_yaml::Value::Null,
    }
}

fn bag(id: &str, reader: bool) -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", id);
    bag.set("subject.type", "User");
    if reader {
        bag.set("role.reader", true);
    }
    bag
}

#[tokio::test]
async fn cedar_decision_cache_contract() {
    const POLICY: &str = r#"
        @id("reader-permit")
        permit(principal, action == Action::"read", resource)
        when { principal.roles.contains("reader") };
    "#;
    let inner: Arc<dyn PdpResolver> =
        Arc::new(CedarDirectResolver::from_policy_text(POLICY).expect("policy"));
    run_cache_contract(
        inner,
        CacheContractSamples {
            allow: (read_call(), bag("alice", true)),
            deny: (read_call(), bag("bob", false)),
            error: (error_call(), bag("alice", true)),
            extra_bags: [bag("carol", true), bag("dave", true)],
        },
    )
    .await;
}
