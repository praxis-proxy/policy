// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `DPoP` ([RFC 9449]) proof verification.
//!
//! An issuer that binds a token to a key records the key's [RFC 7638] thumbprint
//! in the token's `cnf.jkt`. With every request the presenter sends a proof: a
//! JWT of type `dpop+jwt` in the `DPoP` header, signed with the private key,
//! carrying the public key in its header and naming the request's method (`htm`)
//! and URL (`htu`), the time (`iat`), a unique id (`jti`) and the SHA-256 of the
//! access token (`ath`). A copied token is useless without the key, and a copied
//! proof is useless for any other request, after its window, or a second time.
//!
//! [`ProofOfPossession`] is the general shape: a credential names a key, the
//! request proves possession of it. `DPoP` is the first implementation; a
//! certificate-bound token ([RFC 8705]) or a WIMSE proof token would be others.
//!
//! [`ReplayGuard`] remembers each accepted proof's `jti` for as long as the
//! proof counts as recent. [`InMemoryReplayGuard`] covers one gateway instance.
//! Several instances need a store they share, so that a proof replayed to a
//! different instance is still caught; that waits on host-injected stores
//! ([praxis-proxy/policy#127]), and the interface here is what such a store
//! would implement.
//!
//! [`ProofOfPossession`]: crate::plugins::identity_jwt::dpop::ProofOfPossession
//! [`ReplayGuard`]: crate::plugins::identity_jwt::dpop::ReplayGuard
//! [`InMemoryReplayGuard`]: crate::plugins::identity_jwt::dpop::InMemoryReplayGuard
//! [RFC 9449]: https://datatracker.ietf.org/doc/html/rfc9449
//! [RFC 7638]: https://datatracker.ietf.org/doc/html/rfc7638
//! [RFC 8705]: https://datatracker.ietf.org/doc/html/rfc8705
//! [praxis-proxy/policy#127]: https://github.com/praxis-proxy/policy/issues/127

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use praxis_policy_core::extensions::KeyBinding;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::plugins::identity_jwt::config::DpopConfig;

/// Stable denial codes for a failed proof of possession.
pub mod codes {
    /// A proof was required and none was presented: a bound token without a
    /// `DPoP` header, a bound token presented as `Bearer`, or an unbound token
    /// where the issuer requires binding.
    pub const DPOP_MISSING: &str = "auth.dpop_missing";
    /// The proof is malformed or fails a check: signature, `typ`, algorithm,
    /// `htm`, `htu`, `iat` or `ath`.
    pub const DPOP_INVALID: &str = "auth.dpop_invalid";
    /// The proof is signed by a key other than the one the token is bound to.
    pub const DPOP_KEY_MISMATCH: &str = "auth.dpop_key_mismatch";
    /// The proof's `jti` was already used within its window.
    pub const DPOP_REPLAY: &str = "auth.dpop_replay";
    /// The replay store could not answer, so the proof cannot be accepted.
    pub const DPOP_REPLAY_UNAVAILABLE: &str = "auth.dpop_replay_unavailable";
}

/// The [`KeyBinding::method`] a verified `DPoP` proof records.
pub const METHOD: &str = "dpop";

/// Why a proof of possession was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopDenial {
    /// One of [`codes`].
    pub code: &'static str,
    /// Operator-readable detail.
    pub reason: String,
}

impl PopDenial {
    fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

/// What a proof-of-possession check needs to know about one request.
#[derive(Debug, Clone, Copy)]
pub struct PopRequest<'a> {
    /// The issuer that minted the token, used to scope replay keys.
    pub issuer: &'a str,
    /// The access token exactly as presented.
    pub access_token: &'a str,
    /// The thumbprint the token is bound to (`cnf.jkt`).
    pub bound_thumbprint: &'a str,
    /// The proof, if the request carried one.
    pub proof: Option<&'a str>,
    /// The request's HTTP method.
    pub method: &'a str,
    /// The request's URL as the client addressed it.
    pub url: &'a str,
    /// The current time, Unix seconds.
    pub now: i64,
}

/// A check that the presenter of a credential holds the key it is bound to.
#[async_trait]
pub trait ProofOfPossession: Send + Sync {
    /// The method name recorded in the resulting [`KeyBinding`].
    fn method(&self) -> &'static str;

    /// Verify the request's proof, returning the binding it establishes.
    ///
    /// # Errors
    ///
    /// A [`PopDenial`] naming why the proof was not accepted.
    async fn verify(&self, request: &PopRequest<'_>) -> Result<KeyBinding, PopDenial>;
}

/// The replay store could not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayUnavailable(pub String);

/// Remembers proof ids for as long as a proof counts as recent.
#[async_trait]
pub trait ReplayGuard: Send + Sync + std::fmt::Debug {
    /// Record proof `id` within `scope` until `expires_at` (Unix seconds).
    ///
    /// `scope` names the key that signed the proof (its issuer and
    /// thumbprint), so a store can bound how much any one key holds. Returns
    /// `true` when this is the first use, `false` when the id was already
    /// recorded in that scope and has not expired. Must be atomic: two
    /// concurrent calls with the same scope and id must not both see `true`.
    ///
    /// # Errors
    ///
    /// [`ReplayUnavailable`] when the store cannot answer, or will not take
    /// more from this scope. The caller denies rather than accepting a proof it
    /// could not check.
    async fn first_use(
        &self,
        scope: &str,
        id: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, ReplayUnavailable>;
}

/// Default bound on [`InMemoryReplayGuard`] entries across all keys.
pub const DEFAULT_REPLAY_CAPACITY: usize = 100_000;

/// Default bound on live entries for one key. Over the default 60-second
/// window this allows about 166 proofs a second per key, and stops one client
/// from filling the store and denying `DPoP` to every other caller.
pub const DEFAULT_REPLAY_CAPACITY_PER_KEY: usize = 10_000;

#[derive(Debug, Default)]
struct ReplayState {
    /// `(scope, id)` to expiry.
    seen: HashMap<(String, String), i64>,
    /// The same entries ordered by expiry, so pruning reads only what expired.
    by_expiry: BTreeSet<(i64, String, String)>,
    /// Live entries per scope.
    per_scope: HashMap<String, usize>,
}

impl ReplayState {
    fn prune(&mut self, now: i64) {
        // Oldest first, stopping at the first entry still live, so a call reads
        // only what has expired. Removing in place avoids building a new tree.
        while self.by_expiry.first().is_some_and(|entry| entry.0 <= now) {
            if let Some((_, scope, id)) = self.by_expiry.pop_first() {
                self.seen.remove(&(scope.clone(), id));
                if let Some(count) = self.per_scope.get_mut(&scope) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.per_scope.remove(&scope);
                    }
                }
            }
        }
    }
}

/// A [`ReplayGuard`] in this process's memory.
///
/// Correct for a single gateway instance; the store starts empty when the
/// resolver is rebuilt, for example on a configuration reload. Expired entries
/// are pruned in expiry order on every call. Bounded twice: per key, so one
/// client cannot crowd out the rest, and overall. A full store reports itself
/// unavailable, so the proof is denied rather than accepted unchecked.
#[derive(Debug)]
pub struct InMemoryReplayGuard {
    state: Mutex<ReplayState>,
    capacity: usize,
    capacity_per_key: usize,
}

impl InMemoryReplayGuard {
    /// A guard holding at most `capacity` live entries, and at most
    /// `capacity_per_key` for any one key.
    pub fn new(capacity: usize, capacity_per_key: usize) -> Self {
        Self {
            state: Mutex::new(ReplayState::default()),
            capacity,
            capacity_per_key,
        }
    }
}

impl Default for InMemoryReplayGuard {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_CAPACITY, DEFAULT_REPLAY_CAPACITY_PER_KEY)
    }
}

#[async_trait]
impl ReplayGuard for InMemoryReplayGuard {
    async fn first_use(
        &self,
        scope: &str,
        id: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, ReplayUnavailable> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune(now);
        let key = (scope.to_owned(), id.to_owned());
        if state.seen.contains_key(&key) {
            return Ok(false);
        }
        if state.per_scope.get(scope).copied().unwrap_or(0) >= self.capacity_per_key {
            return Err(ReplayUnavailable(format!(
                "this key already has {} live proofs in the replay window",
                self.capacity_per_key
            )));
        }
        if state.seen.len() >= self.capacity {
            return Err(ReplayUnavailable(format!(
                "in-memory replay store is full ({} live proofs)",
                self.capacity
            )));
        }
        state
            .by_expiry
            .insert((expires_at, scope.to_owned(), id.to_owned()));
        state.seen.insert(key, expires_at);
        *state.per_scope.entry(scope.to_owned()).or_default() += 1;
        Ok(true)
    }
}

/// The [RFC 7638 Section 3] thumbprint of a public JWK: base64url SHA-256 over
/// its required members in lexicographic order, without whitespace.
///
/// [RFC 7638 Section 3]: https://datatracker.ietf.org/doc/html/rfc7638#section-3
///
/// Returns `None` for a key type this verifier does not accept or a JWK missing
/// a required member. Symmetric (`oct`) keys are not accepted: a proof signed
/// with a shared secret proves nothing about who holds it.
pub fn jwk_thumbprint(jwk: &Value) -> Option<String> {
    let member = |name: &'static str| -> Option<(&'static str, &str)> {
        Some((name, jwk.get(name)?.as_str()?))
    };
    let required: BTreeMap<&str, &str> = match jwk.get("kty")?.as_str()? {
        "EC" => [member("crv")?, member("kty")?, member("x")?, member("y")?].into(),
        "RSA" => [member("e")?, member("kty")?, member("n")?].into(),
        "OKP" => [member("crv")?, member("kty")?, member("x")?].into(),
        _ => return None,
    };
    let canonical = serde_json::to_string(&required).ok()?;
    Some(b64url(&Sha256::digest(canonical.as_bytes())))
}

/// Normalize a URL for `htu` comparison: lowercase scheme and host, drop a
/// default port, the query and the fragment, and give an empty path a `/`.
///
/// Returns `None` for a string that is not an absolute `http` or `https` URL.
pub fn normalize_htu(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => return None,
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let authority = authority.strip_suffix(default_port).unwrap_or(&authority);
    Some(format!("{scheme}://{authority}{path}"))
}

/// The `ath` value for an access token: base64url SHA-256 of its ASCII bytes.
pub fn access_token_hash(token: &str) -> String {
    b64url(&Sha256::digest(token.as_bytes()))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// JWK members that only a private key carries. A proof whose header holds any
/// of them has leaked its private key, and is refused.
const PRIVATE_JWK_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

#[derive(Debug, Deserialize)]
struct ProofClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    ath: Option<String>,
}

/// Upper bound on a proof's `jti`, so a client cannot make the replay store
/// hold arbitrarily large keys.
const MAX_JTI_LEN: usize = 256;

/// How much of a client-supplied value a denial reason repeats.
const MAX_ECHO_CHARS: usize = 120;

/// A client-supplied value, shortened for a denial reason.
fn clip(value: &str) -> String {
    let mut clipped: String = value.chars().take(MAX_ECHO_CHARS).collect();
    if clipped.len() < value.len() {
        clipped.push('…');
    }
    clipped
}

/// `DPoP` proof verification for one issuer's settings.
#[derive(Debug)]
pub struct DpopVerifier<'a> {
    config: &'a DpopConfig,
    replay: &'a dyn ReplayGuard,
}

impl<'a> DpopVerifier<'a> {
    /// A verifier applying `config`, recording proof ids in `replay`.
    pub fn new(config: &'a DpopConfig, replay: &'a dyn ReplayGuard) -> Self {
        Self { config, replay }
    }

    /// Every check except the replay lookup, in an order that touches the
    /// replay store only for a proof that is otherwise valid.
    fn check(&self, request: &PopRequest<'_>) -> Result<(String, ProofClaims), PopDenial> {
        let invalid = |reason: String| PopDenial::new(codes::DPOP_INVALID, reason);
        let Some(proof) = request.proof else {
            return Err(PopDenial::new(
                codes::DPOP_MISSING,
                "the token is bound to a key but the request carries no DPoP proof",
            ));
        };
        if proof.contains(',') {
            return Err(invalid(
                "the request carries more than one DPoP header".into(),
            ));
        }

        let header_json = proof
            .split('.')
            .next()
            .and_then(|h| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(h)
                    .ok()
            })
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .ok_or_else(|| invalid("the DPoP proof is not a well-formed JWT".into()))?;
        let typ = header_json.get("typ").and_then(Value::as_str);
        if !typ.is_some_and(|t| t.eq_ignore_ascii_case("dpop+jwt")) {
            return Err(invalid(format!(
                "the DPoP proof's typ must be dpop+jwt, got {:?}",
                typ.map(clip)
            )));
        }
        // RFC 7515 section 4.1.11: a recipient must reject a JWS naming critical
        // extensions it does not understand, and this verifier understands none.
        // jsonwebtoken does not enforce `crit`, so it is checked here.
        if header_json.get("crit").is_some() {
            return Err(invalid(
                "the DPoP proof's header names critical extensions (crit), which this \
                 verifier does not implement"
                    .into(),
            ));
        }
        let jwk = header_json
            .get("jwk")
            .filter(|j| j.is_object())
            .ok_or_else(|| invalid("the DPoP proof's header carries no public key (jwk)".into()))?;
        if let Some(member) = PRIVATE_JWK_MEMBERS.iter().find(|m| jwk.get(**m).is_some()) {
            return Err(invalid(format!(
                "the DPoP proof's jwk carries the private member '{member}'"
            )));
        }
        let thumbprint = jwk_thumbprint(jwk)
            .ok_or_else(|| invalid("the DPoP proof's jwk is not a supported public key".into()))?;
        if thumbprint != request.bound_thumbprint {
            return Err(PopDenial::new(
                codes::DPOP_KEY_MISMATCH,
                "the DPoP proof is signed by a key other than the one the token is bound to",
            ));
        }

        let header = decode_header(proof)
            .map_err(|e| invalid(format!("the DPoP proof's header is malformed: {e}")))?;
        if !self.config.algorithms.contains(&header.alg) {
            return Err(invalid(format!(
                "the DPoP proof is signed with {:?}, which this issuer does not accept",
                header.alg
            )));
        }
        let parsed_jwk = header
            .jwk
            .as_ref()
            .ok_or_else(|| invalid("the DPoP proof's jwk could not be parsed".into()))?;
        let key = DecodingKey::from_jwk(parsed_jwk)
            .map_err(|e| invalid(format!("the DPoP proof's jwk is unusable: {e}")))?;
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let claims = decode::<ProofClaims>(proof, &key, &validation)
            .map_err(|e| invalid(format!("the DPoP proof did not verify: {e}")))?
            .claims;

        if claims.htm != request.method {
            return Err(invalid(format!(
                "the DPoP proof is for method {}, the request is {}",
                clip(&claims.htm),
                request.method
            )));
        }
        let expected = normalize_htu(request.url)
            .ok_or_else(|| invalid(format!("the request URL '{}' is not usable", request.url)))?;
        if normalize_htu(&claims.htu).as_deref() != Some(expected.as_str()) {
            return Err(invalid(format!(
                "the DPoP proof is for {}, the request is for {expected}",
                clip(&claims.htu)
            )));
        }
        // `abs_diff` cannot overflow, unlike `(iat - now).abs()`, which wraps for
        // an `iat` near `i64::MIN` in a release build and would pass the check.
        let skew = claims.iat.abs_diff(request.now);
        if claims.iat <= 0 || skew > self.config.iat_window_seconds {
            return Err(invalid(format!(
                "the DPoP proof's iat is {skew}s from now, outside the {}s window",
                self.config.iat_window_seconds
            )));
        }
        if claims.ath.as_deref() != Some(access_token_hash(request.access_token).as_str()) {
            return Err(invalid(
                "the DPoP proof's ath does not match the access token presented with it".into(),
            ));
        }
        if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_LEN {
            return Err(invalid(format!(
                "the DPoP proof's jti must be 1 to {MAX_JTI_LEN} characters"
            )));
        }
        Ok((thumbprint, claims))
    }
}

#[async_trait]
impl ProofOfPossession for DpopVerifier<'_> {
    fn method(&self) -> &'static str {
        METHOD
    }

    async fn verify(&self, request: &PopRequest<'_>) -> Result<KeyBinding, PopDenial> {
        let (thumbprint, claims) = self.check(request)?;
        let window = i64::try_from(self.config.iat_window_seconds).unwrap_or(i64::MAX);
        // Remembered until the proof could no longer pass the `iat` check.
        let expires_at = claims.iat.saturating_add(window).saturating_add(1);
        let scope = format!("{}\u{1f}{thumbprint}", request.issuer);
        match self
            .replay
            .first_use(&scope, &claims.jti, expires_at, request.now)
            .await
        {
            Ok(true) => Ok(KeyBinding {
                method: METHOD.to_owned(),
                thumbprint,
            }),
            Ok(false) => Err(PopDenial::new(
                codes::DPOP_REPLAY,
                "the DPoP proof's jti was already used",
            )),
            Err(ReplayUnavailable(reason)) => {
                Err(PopDenial::new(codes::DPOP_REPLAY_UNAVAILABLE, reason))
            },
        }
    }
}

/// Whether `alg` is one a `DPoP` proof may use: asymmetric only.
pub fn is_asymmetric(alg: Algorithm) -> bool {
    !matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    /// The RFC 7638 section 3.1 example key and its published thumbprint.
    #[test]
    fn thumbprint_matches_the_rfc_7638_example() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(
            jwk_thumbprint(&jwk).as_deref(),
            Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        );
    }

    #[test]
    fn thumbprint_ignores_optional_members_and_refuses_symmetric_keys() {
        let ec = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "BB"});
        let mut with_extras = ec.clone();
        let members = with_extras.as_object_mut().unwrap();
        members.insert("kid".into(), "k1".into());
        members.insert("use".into(), "sig".into());
        assert_eq!(jwk_thumbprint(&ec), jwk_thumbprint(&with_extras));
        assert_eq!(
            jwk_thumbprint(&serde_json::json!({"kty": "oct", "k": "c2VjcmV0"})),
            None
        );
        assert_eq!(
            jwk_thumbprint(&serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AA"})),
            None
        );
    }

    #[test]
    fn htu_normalization_ignores_case_default_ports_query_and_fragment() {
        let n = |u: &str| normalize_htu(u);
        assert_eq!(
            n("HTTPS://API.Example.com:443/v1/mcp?x=1#f").as_deref(),
            Some("https://api.example.com/v1/mcp")
        );
        assert_eq!(
            n("http://localhost:80").as_deref(),
            Some("http://localhost/")
        );
        assert_eq!(
            n("http://localhost:8090/mcp").as_deref(),
            Some("http://localhost:8090/mcp")
        );
        assert_eq!(
            n("https://api.example.com/MCP"),
            Some("https://api.example.com/MCP".into()),
            "path case is significant"
        );
        assert_eq!(n("ftp://example.com/"), None);
        assert_eq!(n("/mcp"), None);
        assert_eq!(n("https://user@example.com/"), None);
    }

    #[test]
    fn access_token_hash_is_base64url_sha256() {
        // SHA-256 of "abc", base64url without padding.
        assert_eq!(
            access_token_hash("abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[tokio::test]
    async fn replay_guard_accepts_an_id_once_until_it_expires() {
        let guard = InMemoryReplayGuard::new(10, 10);
        assert_eq!(guard.first_use("k", "j", 100, 50).await, Ok(true));
        assert_eq!(guard.first_use("k", "j", 100, 60).await, Ok(false));
        assert_eq!(
            guard.first_use("other", "j", 100, 60).await,
            Ok(true),
            "ids are per scope"
        );
        assert_eq!(
            guard.first_use("k", "j", 200, 100).await,
            Ok(true),
            "expired entries are forgotten"
        );
    }

    #[tokio::test]
    async fn one_key_cannot_fill_the_store_for_everyone() {
        let guard = InMemoryReplayGuard::new(100, 2);
        assert_eq!(guard.first_use("noisy", "1", 100, 0).await, Ok(true));
        assert_eq!(guard.first_use("noisy", "2", 100, 0).await, Ok(true));
        assert!(matches!(
            guard.first_use("noisy", "3", 100, 0).await,
            Err(ReplayUnavailable(_))
        ));
        assert_eq!(
            guard.first_use("quiet", "1", 100, 0).await,
            Ok(true),
            "other keys still work"
        );
    }

    #[tokio::test]
    async fn expiring_one_of_a_keys_proofs_frees_one_slot_of_its_quota() {
        let guard = InMemoryReplayGuard::new(100, 2);
        assert_eq!(guard.first_use("k", "a", 10, 0).await, Ok(true));
        assert_eq!(guard.first_use("k", "b", 100, 0).await, Ok(true));
        // At now = 20 "a" has expired and "b" has not: the key holds one live
        // proof, so one more fits and the next does not.
        assert_eq!(
            guard.first_use("k", "c", 100, 20).await,
            Ok(true),
            "expiring a proof returns its slot to the key's quota"
        );
        assert!(
            matches!(
                guard.first_use("k", "d", 100, 20).await,
                Err(ReplayUnavailable(_))
            ),
            "the key is back at its quota of two live proofs"
        );
    }

    #[test]
    fn the_dpop_verifier_records_its_method_as_dpop() {
        let config = DpopConfig::default();
        let guard = InMemoryReplayGuard::default();
        assert_eq!(DpopVerifier::new(&config, &guard).method(), METHOD);
        assert_eq!(
            METHOD, "dpop",
            "policy compares key_binding against this name"
        );
    }

    #[tokio::test]
    async fn a_full_replay_guard_prunes_in_expiry_order_then_fails_closed() {
        let guard = InMemoryReplayGuard::new(2, 10);
        assert_eq!(guard.first_use("s", "a", 10, 0).await, Ok(true));
        assert_eq!(guard.first_use("s", "b", 100, 0).await, Ok(true));
        // "a" has expired by now = 20, so pruning makes room.
        assert_eq!(guard.first_use("s", "c", 100, 20).await, Ok(true));
        // Nothing has expired at now = 30: refuse rather than accept unchecked.
        assert!(matches!(
            guard.first_use("s", "d", 100, 30).await,
            Err(ReplayUnavailable(_))
        ));
    }

    #[test]
    fn shared_secret_algorithms_are_not_asymmetric() {
        assert!(!is_asymmetric(Algorithm::HS256));
        assert!(is_asymmetric(Algorithm::ES256));
        assert!(is_asymmetric(Algorithm::EdDSA));
    }
}
