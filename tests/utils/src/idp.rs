// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A scripted identity provider shaped like the demo's Keycloak realm.
//!
//! One fixed-seed RSA key signs every token and is published as a JWKS.
//! Personas carry the claims the `policy-demo` realm issues through the
//! `hr-copilot` client. Two responders stand in for the token endpoint
//! (RFC 8693 exchange) and for CIBA, each on its own host so their traffic
//! never mixes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use base64::Engine as _;
use bytes::Bytes;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use praxis_policy_core::http::{HttpRequest, HttpResponse};
use praxis_policy_core::http_testing::FakeTransport;
use rand::SeedableRng as _;
use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};

use crate::fixtures::CLIENT_SECRET;

/// Issuer every persona token names.
pub const ISSUER: &str = "https://idp.test/realms/policy-demo";

/// Where the issuer publishes its JWKS.
pub const JWKS_URL: &str = "https://idp.test/realms/policy-demo/protocol/openid-connect/certs";

/// Audience the gateway accepts on inbound tokens.
pub const GATEWAY_AUDIENCE: &str = "praxis-gateway";

/// RFC 8693 token endpoint. Its own host, apart from CIBA's.
pub const TOKEN_EXCHANGE_URL: &str =
    "https://sts.idp.test/realms/policy-demo/protocol/openid-connect/token";

/// CIBA backchannel authentication endpoint.
pub const CIBA_BACKCHANNEL_URL: &str =
    "https://ciba.idp.test/realms/policy-demo/protocol/openid-connect/ext/ciba/auth";

/// CIBA token endpoint polled for the approval.
pub const CIBA_TOKEN_URL: &str =
    "https://ciba.idp.test/realms/policy-demo/protocol/openid-connect/token";

/// `kid` the signing key is published under.
const KID: &str = "policy-demo-rs256";

/// The issued token type a well-behaved exchange reports.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

struct Keys {
    private_pem: String,
    public: RsaPublicKey,
}

/// The process-wide key. Seeded, so every run signs with the same key, and
/// generated once because RSA 2048 is slow in a debug build.
fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed_d3e0);
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        Keys {
            private_pem: private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode private PEM")
                .to_string(),
            public: RsaPublicKey::from(&private),
        }
    })
}

/// The JWKS document publishing the signing key.
#[must_use]
pub fn jwks() -> Value {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": b64.encode(keys().public.n().to_bytes_be()),
            "e": b64.encode(keys().public.e().to_bytes_be()),
        }]
    })
}

/// Sign exactly `claims` with the realm key, under the published `kid`.
#[must_use]
pub fn sign(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    let key = EncodingKey::from_rsa_pem(keys().private_pem.as_bytes()).expect("encoding key");
    jsonwebtoken::encode(&header, claims, &key).expect("sign JWT")
}

/// A second fixed-seed key the realm never publishes: an attacker's, or
/// another issuer's.
fn foreign_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x0bad_c0de);
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        Keys {
            private_pem: private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode private PEM")
                .to_string(),
            public: RsaPublicKey::from(&private),
        }
    })
}

/// The public half of the foreign key, as a JWK under `kid`.
#[must_use]
pub fn foreign_jwk(kid: &str) -> Value {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64.encode(foreign_keys().public.n().to_bytes_be()),
        "e": b64.encode(foreign_keys().public.e().to_bytes_be()),
    })
}

/// What signs a [`forge`]d token.
#[derive(Clone, Copy, Debug)]
pub enum Signer<'a> {
    /// The realm key, RS256.
    Realm,
    /// The foreign key, RS256.
    Foreign,
    /// HMAC-SHA256 keyed with these bytes.
    Hs256(&'a [u8]),
    /// No signature: the third segment is empty.
    Unsigned,
}

/// A token carrying exactly `header` and `claims`, signed by `signer`. The
/// header is written verbatim, so its `alg` may disagree with the signature.
#[must_use]
pub fn forge(header: &Value, claims: &Value, signer: Signer<'_>) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let input = format!(
        "{}.{}",
        b64.encode(header.to_string()),
        b64.encode(claims.to_string())
    );
    let rsa = |k: &Keys| EncodingKey::from_rsa_pem(k.private_pem.as_bytes()).expect("encoding key");
    let (key, alg) = match signer {
        Signer::Realm => (rsa(keys()), Algorithm::RS256),
        Signer::Foreign => (rsa(foreign_keys()), Algorithm::RS256),
        Signer::Hs256(secret) => (EncodingKey::from_secret(secret), Algorithm::HS256),
        Signer::Unsigned => return format!("{input}."),
    };
    let signature = jsonwebtoken::crypto::sign(input.as_bytes(), &key, alg).expect("sign JWT");
    format!("{input}.{signature}")
}

/// A JWT's payload, decoded without verification. Accepts a `Bearer ` prefix.
#[must_use]
pub fn claims_of(token: &str) -> Option<Value> {
    let raw = token.strip_prefix("Bearer ").unwrap_or(token);
    let mut parts = raw.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[expect(
    clippy::cast_possible_wrap,
    reason = "seconds since 1970 fit in an i64"
)]
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// A unique `jti`, so two tokens minted in the same second differ.
fn jti() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("jti-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// The demo realm's users, plus the agent's own client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Persona {
    /// HR, with `view_ssn`, `pii_access` and `email_send`. Manager: alice.
    Bob,
    /// HR without `view_ssn`.
    Eve,
    /// Engineer, `repo:read:internal` on GitHub.
    Alice,
    /// The `hr-copilot` agent's service account, sent as `Authorization`.
    HrCopilot,
}

impl Persona {
    /// The `sub` claim, a stable Keycloak-style id.
    #[must_use]
    pub fn sub(self) -> &'static str {
        match self {
            Self::Bob => "b0b5e2a1-7c4d-4e8f-9a01-00000000b0b0",
            Self::Eve => "e7e1c3d2-5b6a-4f90-8c12-00000000e7e0",
            Self::Alice => "a11ce9f0-3e2d-4c1b-a345-00000000a11c",
            Self::HrCopilot => "5e7c1ce0-4c0b-4c0b-b678-00000000c0b1",
        }
    }

    /// The `preferred_username` claim.
    #[must_use]
    pub fn username(self) -> &'static str {
        match self {
            Self::Bob => "bob",
            Self::Eve => "eve",
            Self::Alice => "alice",
            Self::HrCopilot => "service-account-hr-copilot",
        }
    }

    /// The claims the realm issues for this persona, unsigned.
    #[must_use]
    pub fn claims(self) -> Value {
        let now = now();
        let mut claims = json!({
            "iss": ISSUER,
            "aud": GATEWAY_AUDIENCE,
            "sub": self.sub(),
            "azp": "hr-copilot",
            "typ": "Bearer",
            "preferred_username": self.username(),
            "scope": "openid",
            "iat": now,
            "exp": now + 300,
            "jti": jti(),
        });
        let extra = match self {
            Self::Bob => json!({
                "email": "bob@corp.com",
                "roles": ["hr"],
                "teams": ["hr"],
                "groups": ["hr"],
                "permissions": ["tool_execute", "view_ssn", "pii_access", "email_send"],
                "gh_permissions": [],
                "manager": "alice",
            }),
            Self::Eve => json!({
                "email": "eve@corp.com",
                "roles": ["hr"],
                "teams": ["hr"],
                "groups": ["hr"],
                "permissions": ["tool_execute"],
                "gh_permissions": [],
            }),
            Self::Alice => json!({
                "email": "alice@corp.com",
                "roles": ["engineer"],
                "teams": ["engineering"],
                "groups": ["engineering"],
                "permissions": ["tool_execute"],
                "gh_permissions": ["repo:read:internal"],
            }),
            Self::HrCopilot => json!({ "client_id": "hr-copilot" }),
        };
        merge(&mut claims, extra);
        claims
    }

    /// A signed token for this persona.
    #[must_use]
    pub fn token(self) -> String {
        sign(&self.claims())
    }
}

fn merge(target: &mut Value, extra: Value) {
    if let (Some(target), Value::Object(extra)) = (target.as_object_mut(), extra) {
        target.extend(extra);
    }
}

/// The fields of an `application/x-www-form-urlencoded` body.
fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (form_decode(k), form_decode(v))
        })
        .collect()
}

fn form_field(req: &HttpRequest, key: &str) -> Option<String> {
    form_fields(&req.body)
        .into_iter()
        .find_map(|(k, v)| (k == key).then_some(v))
}

fn form_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                if let Some(decoded) = hex {
                    out.push(decoded);
                    i += 2;
                } else {
                    out.push(b);
                }
            },
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn reply(status: u16, body: &Value) -> HttpResponse {
    HttpResponse::new(status, Bytes::from(body.to_string()))
}

fn oauth_error(code: &str) -> HttpResponse {
    reply(400, &json!({ "error": code }))
}

fn authenticated(req: &HttpRequest) -> bool {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("praxis-gateway:{CLIENT_SECRET}"))
    );
    req.headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(expected.as_str())
}

fn field_is(req: &HttpRequest, name: &str, value: &str) -> bool {
    form_field(req, name).as_deref() == Some(value)
}

/// How the token endpoint departs from RFC 8693, for misbehaving-IdP rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Exchange {
    /// Mint for the requested audience and the caller's `sub`.
    #[default]
    Honest,
    /// Grant more scope than was asked for.
    BroaderScope,
    /// Mint for a different subject than the caller.
    DifferentSubject,
    /// Report an `issued_token_type` other than an access token.
    UnexpectedTokenType,
    /// Mint for an audience other than the one requested.
    WrongAudience,
}

impl Exchange {
    /// Answer the token endpoint by minting from the request form.
    #[must_use]
    pub fn install(self, transport: FakeTransport) -> FakeTransport {
        transport.respond_with(TOKEN_EXCHANGE_URL, move |req| Ok(self.mint(req)))
    }

    fn mint(self, req: &HttpRequest) -> HttpResponse {
        if !authenticated(req) {
            return oauth_error("invalid_client");
        }
        if !field_is(
            req,
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ) || !field_is(req, "subject_token_type", ACCESS_TOKEN_TYPE)
        {
            return oauth_error("invalid_request");
        }
        let (Some(subject), Some(audience)) = (
            form_field(req, "subject_token").and_then(|t| claims_of(&t)),
            form_field(req, "audience"),
        ) else {
            return oauth_error("invalid_request");
        };
        let Some(sub) = subject.get("sub").and_then(Value::as_str) else {
            return oauth_error("invalid_grant");
        };
        let requested = form_field(req, "scope");

        let sub = if self == Self::DifferentSubject {
            Persona::Eve.sub().to_owned()
        } else {
            sub.to_owned()
        };
        let aud = if self == Self::WrongAudience {
            format!("not-{audience}")
        } else {
            audience.clone()
        };
        let scope = match (self, requested) {
            (Self::BroaderScope, Some(s)) => Some(format!("{s} admin")),
            (Self::BroaderScope, None) => Some("admin".to_owned()),
            (_, s) => s,
        };
        // The github-api client maps `gh_permissions` into `permissions`;
        // every other audience carries the user's own.
        let permissions = if audience == "github-api" {
            subject.get("gh_permissions").cloned()
        } else {
            subject.get("permissions").cloned()
        };

        let now = now();
        let mut claims = json!({
            "iss": ISSUER,
            "sub": sub,
            "aud": aud,
            "azp": "praxis-gateway",
            "preferred_username": subject.get("preferred_username"),
            "roles": subject.get("roles"),
            "permissions": permissions.unwrap_or_else(|| json!([])),
            "iat": now,
            "exp": now + 300,
            "jti": jti(),
        });
        if let Some(scope) = &scope {
            merge(&mut claims, json!({ "scope": scope }));
        }
        claims["typ"] = json!(if self == Self::UnexpectedTokenType {
            "ID"
        } else {
            "Bearer"
        });
        let issued_token_type = if self == Self::UnexpectedTokenType {
            "urn:ietf:params:oauth:token-type:id_token"
        } else {
            ACCESS_TOKEN_TYPE
        };
        let mut body = json!({
            "access_token": sign(&claims),
            "issued_token_type": issued_token_type,
            "token_type": "Bearer",
            "expires_in": 300,
        });
        if let Some(scope) = scope {
            merge(&mut body, json!({ "scope": scope }));
        }
        reply(200, &body)
    }
}

/// What the CIBA token endpoint answers on the next poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CibaPoll {
    /// `authorization_pending`.
    Pending,
    /// Tokens naming `approver` as `preferred_username`.
    Approved {
        /// Who consented.
        approver: String,
    },
    /// `access_denied`.
    Denied,
    /// `expired_token`.
    Expired,
}

/// A scripted CIBA OP: a backchannel ack, then polls answered from a state
/// the test advances, per `auth_req_id` or for all of them.
#[derive(Clone, Debug)]
pub struct Ciba {
    poll: Arc<Mutex<CibaPoll>>,
    per_id: Arc<Mutex<HashMap<String, CibaPoll>>>,
    issued: Arc<Mutex<Vec<String>>>,
}

impl Default for Ciba {
    fn default() -> Self {
        Self {
            poll: Arc::new(Mutex::new(CibaPoll::Pending)),
            per_id: Arc::default(),
            issued: Arc::default(),
        }
    }
}

impl Ciba {
    /// An OP whose polls answer `authorization_pending` until advanced.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer every later poll with `poll`, except for an id given its own
    /// state by [`Ciba::set_for`].
    pub fn set(&self, poll: CibaPoll) {
        *self.poll.lock().unwrap_or_else(PoisonError::into_inner) = poll;
    }

    /// Answer later polls for `auth_req_id` with `poll`, ahead of
    /// [`Ciba::set`].
    pub fn set_for(&self, auth_req_id: &str, poll: CibaPoll) {
        self.per_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(auth_req_id.to_owned(), poll);
    }

    /// Every `auth_req_id` the backchannel handed out, in order.
    #[must_use]
    pub fn auth_req_ids(&self) -> Vec<String> {
        self.issued
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Answer the backchannel and token endpoints on `transport`.
    #[must_use]
    pub fn install(&self, transport: FakeTransport) -> FakeTransport {
        let issued = Arc::clone(&self.issued);
        let known_ids = Arc::clone(&self.issued);
        let poll = Arc::clone(&self.poll);
        let per_id = Arc::clone(&self.per_id);
        transport
            .respond_with(CIBA_BACKCHANNEL_URL, move |req| {
                if !authenticated(req) {
                    return Ok(oauth_error("invalid_client"));
                }
                if form_field(req, "login_hint").is_none_or(|h| h.is_empty())
                    || !form_field(req, "scope")
                        .is_some_and(|s| s.split_whitespace().any(|s| s == "openid"))
                {
                    return Ok(oauth_error("invalid_request"));
                }
                // Unguessable, because it is a bearer handle on the approval.
                let id = format!("ciba-{:016x}", rand::random::<u64>());
                issued
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(id.clone());
                Ok(reply(
                    200,
                    &json!({ "auth_req_id": id, "expires_in": 120, "interval": 1 }),
                ))
            })
            .respond_with(CIBA_TOKEN_URL, move |req| {
                if !authenticated(req) {
                    return Ok(oauth_error("invalid_client"));
                }
                if !field_is(req, "grant_type", "urn:openid:params:grant-type:ciba") {
                    return Ok(oauth_error("invalid_request"));
                }
                let Some(id) = form_field(req, "auth_req_id") else {
                    return Ok(oauth_error("invalid_request"));
                };
                if !known_ids
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .contains(&id)
                {
                    return Ok(oauth_error("invalid_grant"));
                }
                let own = per_id
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&id)
                    .cloned();
                let default = || poll.lock().unwrap_or_else(PoisonError::into_inner).clone();
                let state = own.unwrap_or_else(default);
                Ok(match state {
                    CibaPoll::Pending => oauth_error("authorization_pending"),
                    CibaPoll::Denied => oauth_error("access_denied"),
                    CibaPoll::Expired => oauth_error("expired_token"),
                    CibaPoll::Approved { approver } => {
                        let now = now();
                        let token = sign(&json!({
                            "iss": ISSUER,
                            "sub": format!("sub-{approver}"),
                            "aud": "praxis-gateway",
                            "preferred_username": approver,
                            "iat": now,
                            "exp": now + 300,
                            "jti": jti(),
                        }));
                        reply(
                            200,
                            &json!({
                                "access_token": token,
                                "id_token": token,
                                "token_type": "Bearer",
                                "expires_in": 300,
                            }),
                        )
                    },
                })
            })
    }
}
