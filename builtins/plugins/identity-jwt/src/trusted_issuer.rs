// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `TrustedIssuer` — config for one OIDC issuer the resolver trusts,
// plus the `KeyStore` that holds its (possibly-multiple) JWKS keys
// indexed by `kid` for token-header-driven key selection.

use std::collections::HashMap;

use jsonwebtoken::{Algorithm, DecodingKey};

/// A bundle of decoding keys for one trust anchor, supporting
/// `kid`-driven selection at verify time.
///
/// JWKS endpoints commonly publish more than one key (rotation grace
/// windows, multi-algo deployments). The standard OIDC pattern is
/// for each token to declare which `kid` it was signed with in its
/// header; verifiers select the matching key from the JWKS rather
/// than picking the first-listed entry and hoping.
///
/// Two slots:
///   - `by_kid`: keys with a JWKS-declared `kid`. The verify path
///     looks here first using the inbound token's header `kid`.
///   - `fallback`: a single key for the kid-less case. Populated
///     for inline sources (`Pem`/`PemFile`/`Jwk`/`Secret`) which
///     have no JWKS context. JWKS-sourced `KeyStores` leave this
///     `None` — every JWKS key carries a `kid` by spec.
///
/// A `KeyStore` with no entries at all (`by_kid.is_empty() && fallback.is_none()`)
/// is a valid runtime state — it represents "JWKS fetch failed,
/// retry pending" in the soft-fail design. Today every
/// construction path populates at least one slot before the store
/// is reachable from the resolver.
///
/// # Update discipline (refresh)
///
/// Refresh does **whole-store replacement** — it fetches a fresh
/// JWKS, builds a new `KeyStore`, and replaces the old one
/// atomically (`*shared.write() = new_store`). Do **not** merge new
/// keys into the existing `by_kid` map: that grows unbounded as
/// the `IdP` rotates kids in and out over the deployment's lifetime
/// (every kid the `IdP` ever published stays in our map forever).
/// Whole-store replacement bounds the live key count to the
/// `IdP`'s current JWKS size and lets dropped `DecodingKeys` release.
/// `RwLock` semantics make this race-free: in-flight verifies
/// holding `&DecodingKey` keep the old store alive until they
/// release, at which point the swap completes and the old store
/// drops.
pub struct KeyStore {
    by_kid: HashMap<String, DecodingKey>,
    fallback: Option<DecodingKey>,
}

impl KeyStore {
    /// Empty store. Only useful for the soft-fail placeholder path;
    /// current code always populates before exposing.
    pub fn empty() -> Self {
        Self {
            by_kid: HashMap::new(),
            fallback: None,
        }
    }

    /// Single-key store with no `kid`. Used by inline sources (Pem,
    /// `PemFile`, Jwk, Secret) — they have no JWKS context to provide
    /// a kid, so the key serves every token regardless of header.
    pub fn single_fallback(key: DecodingKey) -> Self {
        Self {
            by_kid: HashMap::new(),
            fallback: Some(key),
        }
    }

    /// Construct from a JWKS — every key gets indexed by its `kid`.
    /// JWKS entries without a `kid` are silently dropped (the OIDC
    /// spec requires them to carry one; an entry missing `kid` is
    /// an `IdP` misconfiguration we'd rather surface as
    /// `auth.unknown_kid` at verify time than as a silent
    /// fallback-wins behaviour).
    pub fn from_jwks_entries<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (String, DecodingKey)>,
    {
        Self {
            by_kid: entries.into_iter().collect(),
            fallback: None,
        }
    }

    /// Look up the key for a token's header `kid`. Returns:
    ///   - the matching kid'd key if `kid` is Some and present
    ///   - the fallback if `kid` is None and a fallback exists
    ///   - None otherwise (caller surfaces `auth.unknown_kid`)
    ///
    /// Deliberately does NOT silently fall back to `fallback` when
    /// a kid'd lookup misses. With both behaviours mixed, an
    /// attacker who controls JWKS body order could downgrade a
    /// kid'd token to a fallback key. The kid'ed lookup is exact;
    /// only kid-absent tokens may use the fallback.
    pub fn select(&self, kid: Option<&str>) -> Option<&DecodingKey> {
        match kid {
            Some(k) => self.by_kid.get(k),
            None => self.fallback.as_ref(),
        }
    }

    /// Diagnostic: how many keys this store knows about. Used in
    /// log lines and the `Debug` impl below; not for control flow.
    pub fn len(&self) -> usize {
        self.by_kid.len() + usize::from(self.fallback.is_some())
    }

    /// Whether the store has any usable key. False only on the
    /// Slice-B soft-fail placeholder path.
    pub fn is_empty(&self) -> bool {
        self.by_kid.is_empty() && self.fallback.is_none()
    }
}

// `DecodingKey` doesn't derive Debug (it carries key bytes; the lib
// avoids accidental log leakage). We elide every key value; only
// the count and kid set surface.
impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kids: Vec<&str> = self.by_kid.keys().map(String::as_str).collect();
        f.debug_struct("KeyStore")
            .field("kids", &kids)
            .field("has_fallback", &self.fallback.is_some())
            .finish()
    }
}

/// One issuer's trust config — `iss` value to match against,
/// audience to require, decoding key(s), and acceptable algorithms.
///
/// Deployments with multiple `IdPs` construct one of these per `IdP`
/// and hand the list to `JwtIdentityResolver::new`. The resolver
/// picks the matching issuer based on the inbound token's `iss`
/// claim.
#[non_exhaustive]
pub struct TrustedIssuer {
    /// Expected `iss` claim value — the resolver rejects tokens
    /// whose `iss` doesn't match.
    pub issuer: String,

    /// Expected audience(s). Tokens must carry at least one matching
    /// `aud` value. Empty vec disables audience checking only when
    /// [`skip_audience_validation`](Self::skip_audience_validation) is set.
    pub audiences: Vec<String>,

    /// When true, `aud` is not checked. Produced only from config that
    /// set `skip_audience_validation: true`. An empty `audiences` list
    /// without this flag is refused at load, and at verify it rejects
    /// the token rather than treating any audience as acceptable.
    pub skip_audience_validation: bool,

    /// Decoding keys for this issuer, indexed by `kid`. For inline
    /// sources (Pem/Jwk/Secret) this is a single-entry store with
    /// no kid; for JWKS sources every advertised signature key
    /// lands here so the verify path can pick the one matching the
    /// inbound token's header.
    ///
    /// Wrapped in `Arc<RwLock<...>>` so an on-demand JWKS refresh
    /// can atomically swap in a fresh `KeyStore`
    /// without blocking concurrent verifies (read guards are held
    /// for the duration of one `decode()`, which is sync — no
    /// `.await` between acquisition and release, so no deadlock
    /// risk and no contention beyond a few µs per request).
    ///
    /// Empty during the soft-fail boot path (initial JWKS fetch
    /// failed, a later verify will retry). Verify checks for this
    /// and returns `auth.jwks_unavailable` rather than the
    /// `auth.unknown_kid` it would otherwise produce.
    pub keys: std::sync::Arc<std::sync::RwLock<KeyStore>>,

    /// Algorithms accepted for signature verification. Most
    /// deployments stick to one (RS256 most commonly), but
    /// supporting multiple lets the `IdP` rotate to a new algo
    /// without us redeploying.
    pub algorithms: Vec<Algorithm>,

    /// Clock-skew tolerance for `exp` / `nbf` claims, in seconds.
    /// Defaults applied in `JwtIdentityResolver::new`.
    pub leeway_seconds: u64,

    /// Where this issuer's keys came from, so it can re-fetch them.
    ///
    /// The verify path refreshes on demand — an unknown `kid` means the
    /// `IdP` rolled, an empty store means the boot fetch failed — and
    /// both need the source to fetch again. There is no background task
    /// holding a copy any more; see [`RefreshGate`] for why.
    pub source: crate::config::DecodingKeySource,

    /// Coordinates on-demand refresh for this issuer.
    pub refresh: RefreshGate,
}

/// Bounds how often one issuer's keys may be re-fetched, and collapses
/// concurrent attempts into one.
///
/// Refresh is triggered from the verify path rather than a timer,
/// because a timer needs a background task and a background task cannot
/// be relied upon: it binds to whichever runtime spawned it, which for a
/// host that initializes on a short-lived runtime means the task is
/// cancelled before it ever ticks. Triggering from a request needs no
/// runtime of its own, and recovers on the first token that needs the
/// new key rather than at the next tick.
///
/// Two bounds, both load-bearing:
///
///   * **Single-flight.** A rotation makes every in-flight token fail at
///     once. Without this, each would fetch, and the `IdP` would take a
///     stampede at exactly the moment it just rolled its keys.
///   * **A floor between attempts.** An unknown `kid` is reachable with
///     an unauthenticated request, so a stream of invented `kid`s would
///     otherwise be an amplification attack pointed at your own `IdP`.
#[derive(Debug, Default)]
pub struct RefreshGate {
    /// Held for the duration of a fetch. Losers wait, then re-check the
    /// store: the winner has usually already fixed things, so they
    /// proceed rather than fetching again.
    pub(crate) fetching: tokio::sync::Mutex<()>,

    /// When the last attempt *started*, successful or not.
    ///
    /// Recorded before the fetch rather than after, so a burst of
    /// concurrent callers sees the floor immediately instead of all
    /// deciding they are first.
    last_attempt: std::sync::Mutex<Option<std::time::Instant>>,

    /// When a fetch last actually replaced the key set.
    ///
    /// Distinct from `last_attempt`: the floor is about how often we may
    /// *try*, and staleness is about how long ago we last *succeeded*. A
    /// run of failures must not make the keys look fresh.
    last_success: std::sync::Mutex<Option<std::time::Instant>>,

    /// Bumped every time the key set is replaced.
    ///
    /// This is how a caller that queued behind the single-flight lock
    /// learns whether the winner actually refreshed. A timestamp cannot
    /// answer that: "was the last success recent" also says yes when the
    /// boot fetch was recent, which would swallow the very first refresh
    /// after a rotation and leave the caller denying a token the `IdP`
    /// can perfectly well vouch for.
    generation: std::sync::atomic::AtomicU64,

    /// The `ETag` of the document the current `KeyStore` came from, when
    /// the `IdP` sent one.
    ///
    /// Fed back as `If-None-Match`, which turns the common refresh — keys
    /// stale, `IdP` has not rotated — into a `304` with no body. That is
    /// what makes refreshing from a request path affordable at all: the
    /// alternative is re-downloading and re-parsing a document that has
    /// not changed, on a request that already had its answer.
    etag: std::sync::Mutex<Option<String>>,
}

impl RefreshGate {
    /// Whether a refresh may start now, recording the attempt if so.
    ///
    /// `min_interval` is the floor. A store that has never been fetched
    /// is always allowed through, so the first token after a failed boot
    /// fetch recovers immediately rather than waiting out an interval it
    /// did nothing to earn.
    pub(crate) fn claim_attempt(&self, min_interval: std::time::Duration) -> bool {
        let mut last = self
            .last_attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = std::time::Instant::now();
        match *last {
            Some(prev) if now.duration_since(prev) < min_interval => false,
            _ => {
                *last = Some(now);
                true
            },
        }
    }

    /// Record that a fetch replaced the key set.
    pub(crate) fn mark_success(&self) {
        self.mark_current();
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// Record that the key set was confirmed current without changing.
    ///
    /// The `304` case. It resets the staleness clock — the keys really
    /// are current, and without this every later request would try to
    /// refresh again — but must *not* bump the generation, because a
    /// caller queued on the single-flight lock reads that to decide
    /// whether re-validating is worth anything, and nothing changed.
    pub(crate) fn mark_current(&self) {
        *self
            .last_success
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::time::Instant::now());
    }

    /// The validator for the document behind the current key set.
    pub(crate) fn etag(&self) -> Option<String> {
        self.etag
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Record the validator a fetched document arrived with.
    ///
    /// `None` clears it: an `IdP` that stops sending `ETag` must not
    /// leave a stale validator behind, or every later refresh would send
    /// an `If-None-Match` the peer cannot match and might answer `304`
    /// to, freezing the key set.
    pub(crate) fn set_etag(&self, etag: Option<String>) {
        *self
            .etag
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = etag;
    }

    /// The current key-set generation.
    ///
    /// Read *before* queueing on the single-flight lock and compared
    /// after acquiring it: a change means the winner refreshed while
    /// this caller waited, so it should re-validate rather than fetch
    /// again.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether the key set is older than `max_age`, so a verify should
    /// refresh it proactively rather than waiting for a token to fail.
    ///
    /// `None` means the source cannot refresh at all. A store that has
    /// never been successfully fetched is stale by definition — that is
    /// the failed-boot-fetch case, and it is what makes the first
    /// request after an `IdP` recovers try again.
    pub(crate) fn is_stale(&self, max_age: Option<std::time::Duration>) -> bool {
        let Some(max_age) = max_age else {
            return false;
        };
        // Bind before matching: holding the guard as a match scrutinee
        // would keep the lock for the whole expression.
        let last = *self
            .last_success
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match last {
            None => true,
            Some(t) => std::time::Instant::now().duration_since(t) >= max_age,
        }
    }
}

// Manual `Debug` impl — `jsonwebtoken::DecodingKey` doesn't derive
// `Debug` (presumably to avoid leaking key material into logs).
// We elide the key entirely; the issuer URL + algorithms are
// enough for diagnostic output.
impl std::fmt::Debug for TrustedIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedIssuer")
            .field("issuer", &self.issuer)
            .field("audiences", &self.audiences)
            .field("skip_audience_validation", &self.skip_audience_validation)
            .field("algorithms", &self.algorithms)
            .field("leeway_seconds", &self.leeway_seconds)
            .field("keys", &self.keys)
            .field("source", &self.source)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn issuer_with_secret(secret: &str) -> TrustedIssuer {
        TrustedIssuer {
            issuer: "https://idp.example".to_owned(),
            audiences: vec!["praxis".to_owned()],
            skip_audience_validation: false,
            keys: std::sync::Arc::new(std::sync::RwLock::new(KeyStore::single_fallback(
                DecodingKey::from_secret(secret.as_bytes()),
            ))),
            algorithms: vec![Algorithm::HS256],
            leeway_seconds: 60,
            source: crate::config::DecodingKeySource::Secret {
                secret: secret.to_owned(),
            },
            refresh: RefreshGate::default(),
        }
    }

    /// The manual `Debug` impls on this path exist to keep key material out of
    /// logs. A derived impl anywhere in the chain undoes that silently, so the
    /// absence of the secret is asserted rather than assumed.
    #[test]
    fn debug_for_a_trusted_issuer_does_not_leak_key_material() {
        let rendered = format!("{:?}", issuer_with_secret("hunter2-shared-hmac"));
        assert!(
            !rendered.contains("hunter2-shared-hmac"),
            "issuer Debug leaked the signing secret: {rendered}"
        );
        assert!(
            rendered.contains("https://idp.example"),
            "issuer Debug should still name the issuer: {rendered}"
        );
        assert!(
            rendered.contains("HS256"),
            "issuer Debug should still name the algorithms: {rendered}"
        );
    }

    /// The same guarantee one level down, where the material actually lives.
    #[test]
    fn debug_for_a_secret_key_source_is_redacted() {
        let source = crate::config::DecodingKeySource::Secret {
            secret: "hunter2-shared-hmac".to_owned(),
        };
        let rendered = format!("{source:?}");
        assert!(
            !rendered.contains("hunter2-shared-hmac"),
            "key source Debug leaked the secret: {rendered}"
        );
        assert!(rendered.contains("Secret"), "got {rendered}");
    }

    /// A JWKS URL is a locator, not key material, and a log line about the
    /// wrong endpoint is only actionable if it names the endpoint.
    #[test]
    fn debug_for_a_jwks_source_keeps_the_url() {
        let source = crate::config::DecodingKeySource::JwksUrl {
            url: "https://idp.example/jwks".to_owned(),
            insecure_http: false,
            refresh_secs: 600,
            min_refresh_interval_secs: 30,
        };
        assert!(
            format!("{source:?}").contains("https://idp.example/jwks"),
            "a JWKS URL should survive redaction"
        );
    }

    /// `KeyStore` holds `DecodingKey`s, which have no `Debug` of their own
    /// precisely so a key cannot be printed. The store reports the kid set and
    /// whether a fallback exists, and nothing else.
    #[test]
    fn debug_for_a_key_store_reports_kids_without_keys() {
        let store = KeyStore::from_jwks_entries([(
            "kid-1".to_owned(),
            DecodingKey::from_secret(b"key-bytes"),
        )]);
        let rendered = format!("{store:?}");
        assert!(rendered.contains("kid-1"), "got {rendered}");
        assert!(rendered.contains("has_fallback"), "got {rendered}");
        assert!(
            !rendered.contains("key-bytes"),
            "leaked key bytes: {rendered}"
        );
    }

    /// `len` counts the fallback alongside the kid-indexed keys, so a
    /// single-key inline source reports one rather than zero.
    #[test]
    fn key_store_len_counts_the_fallback() {
        assert_eq!(KeyStore::empty().len(), 0);
        assert!(KeyStore::empty().is_empty());

        let fallback = KeyStore::single_fallback(DecodingKey::from_secret(b"k"));
        assert_eq!(fallback.len(), 1);
        assert!(!fallback.is_empty());
    }

    /// A store that has never been fetched successfully is stale by
    /// definition. That is the failed-boot-fetch case, and it is what makes
    /// the first request after an `IdP` recovers try again.
    #[test]
    fn a_store_that_never_succeeded_is_stale() {
        let gate = RefreshGate::default();
        assert!(
            gate.is_stale(Some(std::time::Duration::from_secs(600))),
            "no successful fetch has to read as stale"
        );
        assert!(
            !gate.is_stale(None),
            "a source that cannot refresh is never stale"
        );

        gate.mark_success();
        assert!(
            !gate.is_stale(Some(std::time::Duration::from_secs(600))),
            "a fresh success is not stale"
        );
    }
}
