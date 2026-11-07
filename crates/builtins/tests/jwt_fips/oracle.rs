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

/// A compact RS256 JWS signed with `RustCrypto` `rsa`.
pub(crate) fn rs256(private_pem: &str, header: &Value, claims: &Value) -> String {
    use rsa::pkcs8::DecodePrivateKey as _;
    // RFC 8017 section 9.2, note 1: the DER prefix of a SHA-256 DigestInfo.
    const SHA256_DIGEST_INFO: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(private_pem).expect("fixture RSA key");
    let input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(header).unwrap()),
        b64(&serde_json::to_vec(claims).unwrap())
    );
    let digest = praxis_policy_core::crypto::sha256(input.as_bytes()).expect("SHA-256");
    let digest_info = [SHA256_DIGEST_INFO.as_slice(), &digest].concat();
    let signature = key
        .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("RSA signature");
    format!("{input}.{}", b64(&signature))
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
