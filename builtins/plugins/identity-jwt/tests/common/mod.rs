// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared harness for the end-to-end suites.
//!
//! An RSA keypair, a token minter, a plugin-config builder, and one call that
//! drives a token through the real handler pipeline. Integration test binaries do
//! not share code by default, so this is a `mod common;` each suite declares.
//!
//! `jwks_url_e2e.rs` deliberately does not use the keypair here: it generates one
//! per test because it exercises key rotation, multiple `kid`s, and an unknown
//! `kid`, none of which a process-global key can express.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test and example code"
)]
#![allow(
    dead_code,
    reason = "shared across integration binaries; each suite uses a subset of the helpers"
)]

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};
use praxis_policy_plugin_identity_jwt::{JwtIdentityResolver, KIND};
use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};

pub(crate) const TEST_ISSUER: &str = "https://idp.test.local";
pub(crate) const TEST_AUDIENCE: &str = "test-api";

pub(crate) struct Keypair {
    pub(crate) private_pem: String,
    pub(crate) public_pem: String,
}

/// Process-global keypair. RSA 2048 is ~50-100ms, which is not worth paying per
/// test.
pub(crate) fn keypair() -> &'static Keypair {
    static KP: OnceLock<Keypair> = OnceLock::new();
    KP.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA");
        let pub_key = RsaPublicKey::from(&priv_key);
        Keypair {
            private_pem: priv_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode private PEM")
                .to_string(),
            public_pem: pub_key
                .to_public_key_pem(LineEnding::LF)
                .expect("encode public PEM"),
        }
    })
}

pub(crate) fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Sign exactly the claims given, for a test that spells out its own registered
/// claims in order to make one of them wrong.
pub(crate) fn mint_exact(claims: Value) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let key = EncodingKey::from_rsa_pem(keypair().private_pem.as_bytes())
        .expect("build EncodingKey from the test private PEM");
    encode(&Header::new(Algorithm::RS256), &claims, &key).expect("sign JWT")
}

/// Sign `extra` plus the registered claims the resolver validates against, for a
/// test whose subject is the claim mapping rather than validation.
pub(crate) fn mint(extra: Value) -> String {
    let mut claims = json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    });
    merge_into(&mut claims, &extra, "claim set");
    mint_exact(claims)
}

/// A plugin config wiring the test key, plus whatever settings the case needs.
/// Mirrors what an operator writes in unified-config YAML.
pub(crate) fn plugin_config(settings: Value) -> PluginConfig {
    let mut config = json!({
        "trusted_issuers": [{
            "issuer": TEST_ISSUER,
            "audiences": [TEST_AUDIENCE],
            "algorithms": ["RS256"],
            "decoding_key": { "kind": "pem", "pem": keypair().public_pem },
            "leeway_seconds": 60,
        }],
    });
    merge_into(&mut config, &settings, "config block");

    PluginConfig {
        name: "jwt-resolver".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(config),
        ..Default::default()
    }
}

fn merge_into(target: &mut Value, source: &Value, what: &str) {
    match (target.as_object_mut(), source.as_object()) {
        (Some(target), Some(source)) => {
            for (key, value) in source {
                target.insert(key.clone(), value.clone());
            }
        },
        _ => panic!("both halves of the {what} must be JSON objects"),
    }
}

/// Drive a token through the real handler pipeline.
pub(crate) async fn invoke(
    cfg: PluginConfig,
    token: String,
    source: TokenSource,
) -> PipelineResult {
    let resolver = JwtIdentityResolver::new(cfg.clone()).expect("the resolver must construct");

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::new(resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .expect("registration");
    mgr.initialize().await.expect("initialize");

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            IdentityPayload::new(token, source),
            Extensions::default(),
            None,
        )
        .await;
    result
}

/// A set's contents in a stable order, for an assertion message worth reading.
pub(crate) fn sorted(values: &HashSet<String>) -> Vec<&str> {
    let mut items: Vec<&str> = values.iter().map(String::as_str).collect();
    items.sort_unstable();
    items
}
