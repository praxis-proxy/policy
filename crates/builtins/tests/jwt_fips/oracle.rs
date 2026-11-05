// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities: fixture tokens and keys.
//!
//! `fixtures/oracle.json` holds the RFC 7515 Appendix A.2 and A.3 and RFC 7520
//! section 4.2 examples, and tokens signed with `RustCrypto` by
//! `fixtures/gen`. Tokens with a live `iat` or `ath` are signed here with the
//! `RustCrypto` `p256` crate.

use std::sync::OnceLock;

use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

pub(crate) fn fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/oracle.json")).expect("fixture JSON")
    })
}

pub(crate) fn issuer() -> &'static str {
    fixtures()["issuer"].as_str().unwrap()
}

pub(crate) fn audience() -> &'static str {
    fixtures()["audience"].as_str().unwrap()
}

pub(crate) fn token(name: &str) -> &'static str {
    fixtures()["tokens"][name]
        .as_str()
        .unwrap_or_else(|| panic!("no fixture token {name}"))
}

pub(crate) fn text(name: &str) -> &'static str {
    fixtures()[name].as_str().unwrap()
}

/// A P-256 key from a fixed scalar.
pub(crate) struct P256 {
    signing: SigningKey,
    pub(crate) jwk: Value,
}

impl P256 {
    pub(crate) fn from_scalar(byte: u8) -> Self {
        let signing = SigningKey::from_slice(&[byte; 32]).expect("valid P-256 scalar");
        let point = signing.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        Self {
            jwk: json!({
                "kty": "EC",
                "crv": "P-256",
                "x": b64(&bytes[1..33]),
                "y": b64(&bytes[33..65]),
            }),
            signing,
        }
    }

    /// A compact ES256 JWS over `header` and `claims`.
    pub(crate) fn sign(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(header).unwrap()),
            b64(&serde_json::to_vec(claims).unwrap())
        );
        let signature: Signature = self.signing.sign(input.as_bytes());
        format!("{input}.{}", b64(&signature.to_bytes()))
    }
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
