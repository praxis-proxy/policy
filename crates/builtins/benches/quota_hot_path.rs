// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Added-latency benchmark for the quota plugin's per-request hooks.
//!
//! The cost that matters is the Limitador round trip each hook adds to the
//! request: the pre-invoke `/check` on TTFT and the post-invoke `/report` on
//! TTLB. A CPU microbenchmark cannot see it, so this drives both handlers
//! against a fake transport that injects a fixed round-trip latency, and
//! Criterion reports the latency each hook adds end to end. Compare the two
//! numbers to `RTT`: `/check` carries the round trip inline, while `/report`
//! dispatches the debit off the response path and should stay well under it.
//!
//! Run with `cargo bench -p praxis-policy-builtins --features experimental-quota`.

#![expect(
    clippy::expect_used,
    reason = "benchmark setup must construct a valid fixture"
)]

use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use praxis_policy_builtins::plugins::quota::handlers::{Quota, QuotaCheck, QuotaReport};
use praxis_policy_core::cmf::{Message, MessagePayload, Role};
use praxis_policy_core::extensions::{
    CompletionExtension, Extensions, SecurityExtension, SubjectExtension, TokenUsage,
};
use praxis_policy_core::hooks::HookHandler as _;
use praxis_policy_core::host::HttpTransportSlot;
use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::plugin::PluginConfig;
use praxis_policy_core::prelude::PluginContext;
use serde_json::json;
use tokio::runtime::Runtime;

/// The round-trip latency the fake Limitador injects, so the added latency
/// Criterion reports is measured against a known backend cost.
const RTT: Duration = Duration::from_millis(2);

fn core() -> Arc<Quota> {
    let cfg = PluginConfig {
        name: "token-quota".into(),
        kind: "quota/limitador".into(),
        config: Some(json!({
            "endpoint": "http://limitador.bench",
            "namespace": "grid-tokens",
            "insecure_http": true,
        })),
        ..Default::default()
    };
    Arc::new(Quota::new(cfg).expect("core builds"))
}

fn transport(path: &str) -> Arc<dyn HttpTransport> {
    Arc::new(FakeTransport::new().with_latency(RTT).json(path, 200, ""))
}

fn extensions(transport: Arc<dyn HttpTransport>, usage: Option<u32>) -> Extensions {
    let mut ext = Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("user-bench".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        http_transport: HttpTransportSlot::installed(transport),
        ..Default::default()
    };
    if let Some(total) = usage {
        ext.completion = Some(Arc::new(CompletionExtension {
            tokens: Some(TokenUsage {
                total_tokens: total,
                ..Default::default()
            }),
            ..Default::default()
        }));
    }
    ext
}

fn payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "hello"),
    }
}

fn quota_hooks(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    // Pre-invoke admission: the /check round trip is on the request's TTFT.
    c.bench_function("quota_check_added_latency", |b| {
        let core = core();
        let t = transport("/check");
        b.to_async(&rt).iter(|| {
            let core = Arc::clone(&core);
            let t = Arc::clone(&t);
            async move {
                let handler = QuotaCheck::new(core);
                let ext = extensions(t, None);
                let mut ctx = PluginContext::new();
                handler.handle(&payload(), &ext, &mut ctx).await
            }
        });
    });

    // Post-invoke debit: the /report round trip should be off the response path.
    c.bench_function("quota_report_added_latency", |b| {
        let core = core();
        let t = transport("/report");
        b.to_async(&rt).iter(|| {
            let core = Arc::clone(&core);
            let t = Arc::clone(&t);
            async move {
                let handler = QuotaReport::new(core);
                let ext = extensions(t, Some(128));
                let mut ctx = PluginContext::new();
                handler.handle(&payload(), &ext, &mut ctx).await
            }
        });
    });
}

criterion_group!(benches, quota_hooks);
criterion_main!(benches);
