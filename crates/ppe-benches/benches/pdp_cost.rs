// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Per-PDP evaluation cost (issue #19 — Cedar / CEL / OPA separately).
//!
//! Compiles / loads each resolver **once** in setup. Timed loop is only
//! `PdpResolver::evaluate`.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "benchmark harness — Criterion macros + fixture expects"
)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::evaluator::Decision;
use praxis_policy_apl_core::step::{PdpCall, PdpDialect, PdpResolver as _};
use praxis_policy_pdp_cedar_direct::CedarDirectResolver;
use praxis_policy_pdp_cel::CelResolver;
use praxis_policy_pdp_opa::OpaResolver;
use tokio::runtime::Runtime;

/// Fail loud in setup if a fixture times a deny path (same idea as `invoke_once`).
fn assert_allow(label: &str, d: &praxis_policy_apl_core::step::PdpDecision) {
    assert!(
        matches!(d.decision, Decision::Allow),
        "{label} fixture must allow; got {:?}",
        d.decision
    );
}

fn cedar_call() -> PdpCall {
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
        .expect("cedar args"),
    }
}

fn cel_call(expr: &str) -> PdpCall {
    let mut m = serde_yaml::Mapping::new();
    m.insert(
        serde_yaml::Value::String("expr".into()),
        serde_yaml::Value::String(expr.into()),
    );
    PdpCall {
        dialect: PdpDialect::Cel,
        args: serde_yaml::Value::Mapping(m),
    }
}

fn opa_call(query: &str) -> PdpCall {
    let mut m = serde_yaml::Mapping::new();
    m.insert(
        serde_yaml::Value::String("query".into()),
        serde_yaml::Value::String(query.into()),
    );
    PdpCall {
        dialect: PdpDialect::Opa,
        args: serde_yaml::Value::Mapping(m),
    }
}

fn reader_bag() -> AttributeBag {
    let mut bag = AttributeBag::new();
    bag.set("subject.id", "alice");
    bag.set("subject.type", "User");
    bag.set("role.reader", true);
    bag
}

fn pdp_cost(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("pdp_cost");
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4))
        .sample_size(100);

    const CEDAR_POLICY: &str = r#"
        @id("reader-permit")
        permit(principal, action == Action::"read", resource)
        when { principal.roles.contains("reader") };
    "#;
    let cedar =
        Arc::new(CedarDirectResolver::from_policy_text(CEDAR_POLICY).expect("cedar compile"));
    let cedar_args = cedar_call();
    let bag = reader_bag();
    {
        let d = rt
            .block_on(cedar.evaluate(&cedar_args, &bag))
            .expect("cedar setup");
        assert_allow("cedar_evaluate", &d);
    }
    group.bench_function("cedar_evaluate", |b| {
        b.to_async(&rt).iter(|| async {
            let d = cedar
                .evaluate(black_box(&cedar_args), black_box(&bag))
                .await
                .expect("cedar eval");
            black_box(d);
        });
    });

    let cel = Arc::new(CelResolver::new());
    let cel_args = cel_call("subject.id == 'alice'");
    {
        let d = rt
            .block_on(cel.evaluate(&cel_args, &bag))
            .expect("cel setup");
        assert_allow("cel_evaluate", &d);
    }
    group.bench_function("cel_evaluate", |b| {
        b.to_async(&rt).iter(|| async {
            let d = cel
                .evaluate(black_box(&cel_args), black_box(&bag))
                .await
                .expect("cel eval");
            black_box(d);
        });
    });

    const OPA_MODULE: &str = r#"package authz
default allow := false
allow if input.subject.id == "alice"
"#;
    let mut opa_cfg = serde_yaml::Mapping::new();
    opa_cfg.insert(
        serde_yaml::Value::String("kind".into()),
        serde_yaml::Value::String("opa".into()),
    );
    opa_cfg.insert(
        serde_yaml::Value::String("modules".into()),
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(OPA_MODULE.into())]),
    );
    let opa =
        Arc::new(OpaResolver::from_config(&serde_yaml::Value::Mapping(opa_cfg)).expect("opa load"));
    let opa_args = opa_call("data.authz.allow");
    {
        let d = rt
            .block_on(opa.evaluate(&opa_args, &bag))
            .expect("opa setup");
        assert_allow("opa_evaluate", &d);
    }
    group.bench_function("opa_evaluate", |b| {
        b.to_async(&rt).iter(|| async {
            let d = opa
                .evaluate(black_box(&opa_args), black_box(&bag))
                .await
                .expect("opa eval");
            black_box(d);
        });
    });

    group.finish();
}

criterion_group!(benches, pdp_cost);
criterion_main!(benches);
