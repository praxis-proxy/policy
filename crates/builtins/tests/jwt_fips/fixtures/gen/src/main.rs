// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Writes the `jwt_fips` fixture tokens and keys, signed with `RustCrypto`.
//!
//! Keeps the `rfc` block of an existing `oracle.json`, since those are
//! published examples rather than generated ones:
//!
//! ```console
//! cargo run --release -- ../oracle.json
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "fixture generator")]

use base64::Engine as _;
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Map, Value, json};
use sha2::{Sha256, Sha384, Sha512};

const ISSUER: &str = "https://idp.example";
const AUDIENCE: &str = "fips-api";
const EXP: i64 = 4_102_444_800; // 2100-01-01
const NBF: i64 = 1_700_000_000;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: jwt-fips-fixtures <oracle.json>");
    let rfc = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("rfc").cloned())
        .expect("an existing oracle.json with an rfc block");

    let claims = json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "exp": EXP, "nbf": NBF });
    let mut tokens: Map<String, Value> = Map::new();
    let mut add = |name: &str, token: String| {
        tokens.insert(name.to_owned(), Value::String(token));
    };
    let mut keys = Vec::new();

    let rsa = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    keys.push(rsa_jwk(&rsa.to_public_key(), "rsa-2048"));
    let rs = |alg: &str| header(alg, Some("rsa-2048"));
    add(
        "RS256",
        jws(&rs("RS256"), &claims, |m| {
            rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa.clone())
                .sign(m)
                .to_vec()
        }),
    );
    add(
        "RS384",
        jws(&rs("RS384"), &claims, |m| {
            rsa::pkcs1v15::SigningKey::<Sha384>::new(rsa.clone())
                .sign(m)
                .to_vec()
        }),
    );
    add(
        "RS512",
        jws(&rs("RS512"), &claims, |m| {
            rsa::pkcs1v15::SigningKey::<Sha512>::new(rsa.clone())
                .sign(m)
                .to_vec()
        }),
    );
    add(
        "PS256",
        jws(&rs("PS256"), &claims, |m| {
            rsa::pss::SigningKey::<Sha256>::new(rsa.clone())
                .sign_with_rng(&mut OsRng, m)
                .to_vec()
        }),
    );
    add(
        "PS384",
        jws(&rs("PS384"), &claims, |m| {
            rsa::pss::SigningKey::<Sha384>::new(rsa.clone())
                .sign_with_rng(&mut OsRng, m)
                .to_vec()
        }),
    );
    add(
        "PS512",
        jws(&rs("PS512"), &claims, |m| {
            rsa::pss::SigningKey::<Sha512>::new(rsa.clone())
                .sign_with_rng(&mut OsRng, m)
                .to_vec()
        }),
    );

    let p256 = p256::ecdsa::SigningKey::random(&mut OsRng);
    let point = p256.verifying_key().to_encoded_point(false);
    keys.push(ec_jwk(
        "ec-P-256",
        "P-256",
        point.x().unwrap(),
        point.y().unwrap(),
    ));
    let es256 = |m: &[u8]| {
        let sig: p256::ecdsa::Signature = p256.sign(m);
        sig.to_bytes().to_vec()
    };
    add(
        "ES256",
        jws(&header("ES256", Some("ec-P-256")), &claims, es256),
    );
    add("ES256_no_kid", jws(&header("ES256", None), &claims, es256));
    let mut expired = claims.clone();
    expired["exp"] = json!(NBF + 100);
    add(
        "ES256_expired",
        jws(&header("ES256", None), &expired, es256),
    );
    let mut wrong_aud = claims.clone();
    wrong_aud["aud"] = json!("other-api");
    add(
        "ES256_wrong_aud",
        jws(&header("ES256", None), &wrong_aud, es256),
    );
    let good = jws(&header("ES256", None), &claims, es256);
    add("ES256_bad_signature", flip_signature_bit(&good));

    let p384 = p384::ecdsa::SigningKey::random(&mut OsRng);
    let point = p384.verifying_key().to_encoded_point(false);
    keys.push(ec_jwk(
        "ec-P-384",
        "P-384",
        point.x().unwrap(),
        point.y().unwrap(),
    ));
    add(
        "ES384",
        jws(&header("ES384", Some("ec-P-384")), &claims, |m| {
            let sig: p384::ecdsa::Signature = p384.sign(m);
            sig.to_bytes().to_vec()
        }),
    );

    let small = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
    let rsa_1024_token = jws(&header("RS256", Some("rsa-1024")), &claims, |m| {
        rsa::pkcs1v15::SigningKey::<Sha256>::new(small.clone())
            .sign(m)
            .to_vec()
    });

    // A 2048-bit key with e=3, which FIPS 186-5 forbids; the DPoP test signs a
    // proof with it at run time.
    let weak = RsaPrivateKey::new_with_exp(&mut OsRng, 2048, &rsa::BigUint::from(3_u8)).unwrap();

    let p521_point = p521_public_point();
    let ed = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let ed_public = ed.verifying_key();

    let fixtures = json!({
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "tokens": tokens,
        "jwks": { "keys": keys },
        "rsa_public_pem": rsa.to_public_key().to_public_key_pem(LineEnding::LF).unwrap(),
        "ec_p256_public_pem": p256::PublicKey::from(p256.verifying_key())
            .to_public_key_pem(LineEnding::LF)
            .unwrap(),
        "rsa_1024_jwk": rsa_jwk(&small.to_public_key(), "rsa-1024"),
        "rsa_1024_token": rsa_1024_token,
        "rsa_e3_private_pem": weak.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        "rsa_e3_jwk": rsa_jwk(&weak.to_public_key(), "rsa-e3"),
        "ec_p521_jwk": ec_jwk("ec-p521", "P-521", &p521_point.0, &p521_point.1),
        "ed25519_public_pem": ed_public.to_public_key_pem(LineEnding::LF).unwrap(),
        "ed25519_jwk": {
            "kty": "OKP", "crv": "Ed25519", "kid": "ed", "use": "sig",
            "x": b64(ed_public.as_bytes()),
        },
        "rfc": rfc,
    });
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&fixtures).unwrap() + "\n",
    )
    .unwrap();
}

fn header(alg: &str, kid: Option<&str>) -> Value {
    let mut header = json!({ "alg": alg, "typ": "JWT" });
    if let Some(kid) = kid {
        header["kid"] = json!(kid);
    }
    header
}

fn jws(header: &Value, claims: &Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(header).unwrap()),
        b64(&serde_json::to_vec(claims).unwrap())
    );
    let signature = sign(input.as_bytes());
    format!("{input}.{}", b64(&signature))
}

fn flip_signature_bit(token: &str) -> String {
    let (input, signature) = token.rsplit_once('.').unwrap();
    let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature)
        .unwrap();
    bytes[5] ^= 1;
    format!("{input}.{}", b64(&bytes))
}

fn rsa_jwk(key: &RsaPublicKey, kid: &str) -> Value {
    json!({
        "kty": "RSA", "kid": kid, "use": "sig",
        "n": b64(&key.n().to_bytes_be()),
        "e": b64(&key.e().to_bytes_be()),
    })
}

fn ec_jwk(kid: &str, crv: &str, x: &[u8], y: &[u8]) -> Value {
    json!({ "kty": "EC", "kid": kid, "use": "sig", "crv": crv, "x": b64(x), "y": b64(y) })
}

/// The P-521 generator point from RFC 5903 section 3.3. A refusal input only:
/// nothing is signed with it, so no P-521 implementation is needed.
fn p521_public_point() -> (Vec<u8>, Vec<u8>) {
    const GX: &str = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
    const GY: &str = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650";
    (hex(GX), hex(GY))
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
