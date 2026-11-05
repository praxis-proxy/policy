// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! JWT verification through the resolver, for comparing the `jwt` (AWS-LC)
//! and `jwt-openssl-fips` backends on the same independently signed tokens.
//!
//! Build the FIPS binary with an ordinary OpenSSL config, since Cargo's own
//! TLS fails with FIPS-only defaults, then run it with the FIPS default:
//!
//! ```console
//! cargo bench -p praxis-policy-builtins --features jwt --bench jwt_verify
//! cargo bench -p praxis-policy-builtins --no-default-features \
//!   --features fips,api-key,jwt-openssl-fips --bench jwt_verify --no-run
//! OPENSSL_CONF=.github/fips-default.cnf target/release/deps/jwt_verify-<hash> --bench
//! ```

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "bench"
)]

use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use praxis_policy_builtins::plugins::identity_jwt::{JwtIdentityResolver, KIND};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::HookHandler as _;
use praxis_policy_core::http_testing::{FakeTransport, granting};
use praxis_policy_core::identity::{HOOK_IDENTITY_RESOLVE, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::{Plugin as _, PluginConfig};
use serde_json::{Value, json};

const FIXTURES: &str = include_str!("../tests/jwt_fips/fixtures/oracle.json");
const JWKS_URL: &str = "https://idp.example/certs";

fn verify(c: &mut Criterion) {
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixture JSON");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let backend = if cfg!(feature = "jwt-openssl-fips") {
        "openssl-fips"
    } else {
        "aws-lc"
    };
    for algorithm in ["ES256", "ES384", "RS256", "PS256"] {
        let resolver = runtime.block_on(resolver(&fixtures, algorithm));
        let token = fixtures["tokens"][algorithm]
            .as_str()
            .expect("fixture token");
        let payload = IdentityPayload::new(token, TokenSource::Bearer);
        let handle = || {
            runtime.block_on(resolver.handle(
                &payload,
                &Extensions::default(),
                &mut PluginContext::new(),
            ))
        };
        assert!(
            handle().violation.is_none(),
            "{algorithm} must verify before it is measured"
        );
        c.bench_function(&format!("jwt_verify/{backend}/{algorithm}"), |b| {
            b.iter(handle);
        });
    }
}

async fn resolver(fixtures: &Value, algorithm: &str) -> JwtIdentityResolver {
    let resolver = JwtIdentityResolver::new(PluginConfig {
        name: "jwt".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.to_owned()],
        capabilities: ["perform_http".to_owned()].into(),
        config: Some(json!({
            "trusted_issuers": [{
                "issuer": fixtures["issuer"],
                "audiences": [fixtures["audience"]],
                "algorithms": [algorithm],
                "decoding_key": { "kind": "jwks_url", "url": JWKS_URL },
            }],
            "claim_mapper": "standard",
        })),
        ..Default::default()
    })
    .expect("bench resolver");
    let http = Arc::new(FakeTransport::new().json(JWKS_URL, 200, &fixtures["jwks"].to_string()));
    resolver
        .initialize_with(&granting(http))
        .await
        .expect("JWKS loads");
    resolver
}

criterion_group!(benches, verify);
criterion_main!(benches);
