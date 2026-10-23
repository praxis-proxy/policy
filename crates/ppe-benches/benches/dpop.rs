// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What `DPoP` adds to a request (`identity/jwt`, praxis-proxy/policy#204).
//!
//! A `DPoP` request costs a normal token validation plus two things this target
//! isolates:
//!
//! - `verify_proof`: the proof check (decode, `typ`, `jwk` thumbprint, ES256
//!   signature, `htm`, `htu`, `iat`, `ath`), against a replay store that always
//!   accepts so only the check is measured. Proofs are signed in Criterion's
//!   untimed setup, one per iteration, as a client would send them.
//! - `replay_guard_first_use`: recording a proof id in the in-memory replay
//!   store, in steady state, with entries expiring as fast as they arrive.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "benchmark harness — Criterion macros + fixture expects"
)]

use std::hint::black_box;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use praxis_policy_builtins::plugins::identity_jwt::DpopConfig;
use praxis_policy_builtins::plugins::identity_jwt::dpop::{
    DpopVerifier, InMemoryReplayGuard, PopRequest, ProofOfPossession as _, ReplayGuard,
    ReplayUnavailable, access_token_hash, jwk_thumbprint,
};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

const URL: &str = "https://gateway.test/mcp";
/// Stands in for the access token. The verifier only hashes it for `ath`, so it
/// need not be a JWT.
const TOKEN: &str = "bench-access-token";

/// A replay store that accepts every proof, so `verify_proof` measures only
/// the check.
#[derive(Debug)]
struct AcceptAll;

#[async_trait]
impl ReplayGuard for AcceptAll {
    async fn first_use(&self, _: &str, _: &str, _: i64, _: i64) -> Result<bool, ReplayUnavailable> {
        Ok(true)
    }
}

struct Key {
    encoding: EncodingKey,
    jwk: Value,
}

fn key() -> Key {
    let signing = SigningKey::from_slice(&[0x11; 32]).expect("valid P-256 scalar");
    let pem = signing.to_pkcs8_pem(LineEnding::LF).expect("PEM");
    let point = signing.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    Key {
        encoding: EncodingKey::from_ec_pem(pem.as_bytes()).expect("EncodingKey"),
        jwk: json!({ "kty": "EC", "crv": "P-256", "x": b64(&bytes[1..33]), "y": b64(&bytes[33..65]) }),
    }
}

fn now() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    i64::try_from(secs).expect("seconds fit in i64")
}

fn proof(key: &Key, jti: i64) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(serde_json::from_value(key.jwk.clone()).expect("JWK"));
    let claims = json!({
        "htm": "POST",
        "htu": URL,
        "iat": now(),
        "jti": format!("jti-{jti}"),
        "ath": access_token_hash(TOKEN),
    });
    encode(&header, &claims, &key.encoding).expect("sign proof")
}

fn dpop(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("dpop");
    group
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(100);

    let key = key();
    let thumbprint = jwk_thumbprint(&key.jwk).expect("thumbprint");
    let config = DpopConfig::default();
    let verifier = DpopVerifier::new(&config, &AcceptAll);
    let counter = AtomicI64::new(0);
    // References, so each `async move` iteration copies a borrow rather than
    // taking the verifier.
    let (verifier, thumbprint) = (&verifier, thumbprint.as_str());

    group.bench_function("verify_proof", |b| {
        b.to_async(&rt).iter_batched(
            || proof(&key, counter.fetch_add(1, Ordering::Relaxed)),
            |proof| async move {
                let binding = verifier
                    .verify(&PopRequest {
                        issuer: "https://idp.test",
                        access_token: TOKEN,
                        bound_thumbprint: thumbprint,
                        proof: Some(&proof),
                        method: "POST",
                        url: URL,
                        now: now(),
                    })
                    .await
                    .expect("a valid proof verifies");
                black_box(binding);
            },
            BatchSize::SmallInput,
        );
    });

    let guard = InMemoryReplayGuard::default();
    let tick = AtomicI64::new(0);
    group.bench_function("replay_guard_first_use", |b| {
        b.to_async(&rt).iter(|| async {
            // Each id expires one tick after it is recorded, so every call
            // prunes the previous entry: the steady state of a store whose
            // traffic and window are in balance.
            let t = tick.fetch_add(1, Ordering::Relaxed);
            let first = guard
                .first_use("issuer\u{1f}thumbprint", &t.to_string(), t + 1, t)
                .await
                .expect("store has room");
            black_box(first);
        });
    });

    group.finish();
}

criterion_group!(benches, dpop);
criterion_main!(benches);
