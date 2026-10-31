// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Per-request cost of the embedded rate limiter at both rate-limit hooks.
//!
//! Each case drives the engine the way a host does, through `invoke_named` on
//! the pre- or post-identity hook, so the figure includes dispatch, attribute
//! binding and the in-memory Limitador check. Allow and deny take different
//! paths through Limitador, and the limit count scales the per-request work,
//! so each hook is measured for both verdicts with one limit and with eight.
//!
//! Run with `cargo bench -p praxis-policy-builtins --features experimental-ratelimit
//! --bench ratelimit_hot_path`.

#![expect(
    clippy::expect_used,
    reason = "benchmark setup must construct a valid fixture"
)]

use std::fmt::Write as _;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use praxis_policy_builtins::plugins::ratelimit::{CODE_EXCEEDED, KIND, RateLimitFactory};
use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{
    Extensions, HttpExtension, MetaExtension, SecurityExtension, SubjectExtension,
};
use praxis_policy_core::http_hook::{HttpHook, HttpPayload};
use praxis_policy_core::ratelimit_hook::{
    HOOK_RATELIMIT_POST_IDENTITY, HOOK_RATELIMIT_PRE_IDENTITY,
};
use tokio::runtime::Runtime;

/// High enough that no allow case reaches it during a run.
const ALLOW_MAX: u64 = 1_000_000_000_000; // requests per window

/// The deny cases spend this on a warm-up call, so every timed call is denied.
const DENY_MAX: u64 = 1; // requests per window

/// Long enough that a deny window cannot reset mid-run and let a call through.
const WINDOW_SECONDS: u64 = 3_600; // one hour

const MANY_LIMITS: usize = 8; // limits per policy

#[derive(Clone, Copy)]
enum Stage {
    PreIdentity,
    PostIdentity,
}

impl Stage {
    const fn hook(self) -> &'static str {
        match self {
            Self::PreIdentity => HOOK_RATELIMIT_PRE_IDENTITY,
            Self::PostIdentity => HOOK_RATELIMIT_POST_IDENTITY,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::PreIdentity => "pre_identity",
            Self::PostIdentity => "post_identity",
        }
    }
}

/// A policy whose `limits` all apply to the benchmark request. Only the last
/// limit carries `max`, so the deny cases still evaluate every earlier limit.
fn policy(stage: Stage, limits: usize, max: u64) -> String {
    let (hook, capabilities, bindings, selector) = match stage {
        Stage::PreIdentity => (
            "ratelimit.pre_identity",
            "[read_headers]",
            "      bindings:\n        client: http.client_address\n",
            "          variables: [client]\n",
        ),
        Stage::PostIdentity => (
            "ratelimit.post_identity",
            "[read_subject, read_headers]",
            "",
            "          conditions: [\"http_method == 'GET'\"]\n          variables: [subject_id]\n",
        ),
    };
    let mut yaml = format!(
        "plugins:\n  - name: bench-limits\n    kind: ratelimit/limitador\n    \
         hooks: [{hook}]\n    capabilities: {capabilities}\n    config:\n      \
         namespace: bench\n{bindings}      limits:\n"
    );
    for index in 0..limits {
        let limit_max = if index + 1 == limits { max } else { ALLOW_MAX };
        // Distinct windows keep each limit its own counter.
        let seconds = WINDOW_SECONDS + index as u64;
        write!(
            yaml,
            "        - max: {limit_max}\n          seconds: {seconds}\n{selector}"
        )
        .expect("writing to a String cannot fail");
    }
    yaml.push_str("global:\n  rate_limits: [bench-limits]\n");
    yaml
}

fn request() -> Extensions {
    let mut http = HttpExtension {
        method: Some("GET".to_owned()),
        path: Some("/toys".to_owned()),
        ..Default::default()
    };
    http.set_client_address("203.0.113.7");
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some(ENTITY_HTTP.to_owned()),
            entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
            ..Default::default()
        })),
        http: Some(Arc::new(http)),
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("user-bench".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn engine(policy: &str) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(RateLimitFactory));
    engine
        .load_config_yaml(policy)
        .expect("benchmark policy loads");
    engine.initialize().await.expect("rate limiter initializes");
    engine
}

/// The denial code of one call at `hook`, or `None` when it is allowed.
async fn verdict(engine: &PolicyEngine, hook: &str) -> Option<String> {
    let (result, _background) = engine
        .invoke_named::<HttpHook>(hook, HttpPayload, request(), None)
        .await;
    result.violation.map(|violation| violation.code)
}

fn bench_case(c: &mut Criterion, rt: &Runtime, stage: Stage, limits: usize, deny: bool) {
    let max = if deny { DENY_MAX } else { ALLOW_MAX };
    let engine = rt.block_on(engine(&policy(stage, limits, max)));
    let hook = stage.hook();
    if deny {
        rt.block_on(verdict(&engine, hook));
    }
    // A case that measured the other verdict would time the wrong path.
    let expected = deny.then(|| CODE_EXCEEDED.to_owned());
    assert_eq!(
        rt.block_on(verdict(&engine, hook)),
        expected,
        "the {} case must see its intended verdict before timing",
        stage.label(),
    );

    let verdict_label = if deny { "deny" } else { "allow" };
    let name = format!(
        "ratelimit_{}/{verdict_label}/{limits}_limits",
        stage.label()
    );
    c.bench_function(&name, |b| {
        let extensions = request();
        b.to_async(rt).iter(|| {
            let engine = Arc::clone(&engine);
            let extensions = extensions.clone();
            async move {
                engine
                    .invoke_named::<HttpHook>(hook, HttpPayload, extensions, None)
                    .await
            }
        });
    });
}

fn ratelimit_hooks(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    for stage in [Stage::PreIdentity, Stage::PostIdentity] {
        for limits in [1, MANY_LIMITS] {
            for deny in [false, true] {
                bench_case(c, &rt, stage, limits, deny);
            }
        }
    }
}

criterion_group!(benches, ratelimit_hooks);
criterion_main!(benches);
