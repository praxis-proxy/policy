// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Microbenchmark for the per-request CPU the quota plugin adds: resolving
//! the principal from the identity extension, and the response-body usage
//! fallback parse. The Limitador round trip dominates real request latency
//! and is out of scope here. This guards the plugin's own cost and the
//! borrow-not-clone identity path.
//!
//! Run with `cargo bench -p praxis-policy-builtins --features quota,bench`.

use std::sync::Arc;

use praxis_policy_builtins::plugins::quota::handlers::bench::{extract_usage, resolve_identity};
use praxis_policy_core::extensions::{Extensions, SecurityExtension, SubjectExtension};

fn main() {
    divan::main();
}

fn ext_with_sub(sub: &str) -> Extensions {
    Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some(sub.to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// The default `sub` path: borrows the subject id, no allocation.
#[divan::bench]
fn resolve_sub(bencher: divan::Bencher) {
    let ext = ext_with_sub("user-a1b2c3d4-e5f6-7890");
    bencher.bench(|| resolve_identity(divan::black_box(&ext), divan::black_box("sub")));
}

/// A missing subject, the common unauthenticated path that skips metering.
#[divan::bench]
fn resolve_absent(bencher: divan::Bencher) {
    let ext = Extensions::default();
    bencher.bench(|| resolve_identity(divan::black_box(&ext), divan::black_box("sub")));
}

/// The body fallback parse, taken only when the gateway's typed usage is
/// absent. An OpenAI-shaped body with the usage object at the tail.
#[divan::bench]
fn extract_usage_from_body(bencher: divan::Bencher) {
    let body = r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":57,"completion_tokens":71,"total_tokens":128}}"#;
    bencher.bench(|| {
        extract_usage(
            divan::black_box(body),
            divan::black_box("usage.total_tokens"),
        )
    });
}
