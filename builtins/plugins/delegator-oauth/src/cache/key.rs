// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Cache-key derivation for delegated tokens.
//
// This module is the security boundary of the cache. Everything else in
// `cache/` is mechanism; if the key is wrong, one caller is served a
// credential minted for another, the downstream service accepts it, and
// the action is attributed to the wrong principal. That failure is
// silent at every layer.
//
// # The rule
//
// A cache key must be derived from things a caller cannot forge. It is
// not enough for the components to be *hard* to guess: they must be
// values the caller either genuinely possesses (a credential) or that an
// operator wrote (configuration).
//
// # Anchored on the credential, not on the identity
//
// The load-bearing component is the credential being exchanged, not
// `security.subject.id`. This is deliberate and it is the opposite of
// what "cache per user" suggests.
//
// A derived identity is only as good as the mapping that produced it,
// and that mapping is operator-editable. A key built on it inherits
// whatever the claim map becomes, including a remap onto a claim that is
// not unique. The credential has no such indirection: two principals
// cannot present the same one unless one of them holds the other's
// token, at which point the cache is not what went wrong.
//
// This is not a theoretical preference. `fast-jwt` shipped exactly this
// choice as a configurable and it became GHSA-rp9m-7r4c-75qg, CVSS 9.1:
// a key builder that derived from claims collided two users' tokens and
// returned one user's claims for the other's token. Its *default* key,
// the token itself, was never affected. `curl` CVE-2022-22576 is the
// same shape at the connection layer, and FastMCP CVE-2025-69196 is the
// same shape with the target audience omitted.
//
// Consequently `security.subject.id` must not enter this key even as an
// *additional* component alongside the credential. It buys no isolation
// the credential does not already provide, and its presence is an
// invitation to later drop the credential and keep the identity, which
// is precisely the patch note above in reverse.
//
// # Unvalidated input is safe here, for a specific reason
//
// `bearer_token` reaches us straight off the wire, before validation
// (see `Capability::ReadInboundTokens` in praxis-policy-core, which says so
// explicitly). Keying on unvalidated input would normally be alarming.
//
// It is sound because the cache only ever stores a *confirmed* mint. A
// confirmed mint means the `IdP` accepted that exact credential during
// the exchange, so every anchor of every stored entry is a credential
// the `IdP` validated — even though the key was computed before anyone
// had checked it. Garbage in the anchor produces a failed exchange,
// which produces no entry.
//
// That argument covers isolation only. It does *not* cover rate
// limiting: a caller holding no valid credential at all can still emit a
// stream of invented tokens, each a distinct anchor, and drive one `IdP`
// round trip per request. A limiter keyed on the anchor is defeated by
// varying the anchor. See the module docs in `cache/mod.rs`.
//
// # Keyed, not bare
//
// The hash is an HMAC under a per-process secret rather than a plain
// digest, which buys two things. A key is safe to log, put in a metric
// label, or leave in a heap dump without becoming an oracle for "is this
// token live" — the property kubelet's token manager states as "keys
// should be nonconfidential and safe to log". And because the secret
// never leaves the process, an attacker who controls the anchor bytes
// still cannot steer the output: landing on a victim's key would require
// a second preimage under an unknown 256-bit key, with only a
// chosen-message oracle to work from.

use hmac::{Hmac, Mac as _};
use praxis_policy_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, DelegationSubject, TargetType,
};
use praxis_policy_core::extensions::raw_credentials::TokenRole;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain separator, versioned.
///
/// Bump the suffix whenever the component list or its ordering changes.
/// A derivation change then produces entirely different keys, so old and
/// new entries cannot collide during a rolling restart; the old ones age
/// out untouched instead.
const DOMAIN: &[u8] = b"ppe.delegation.cache.v1";

/// Per-process cache-key secret: 32 bytes from the OS CSPRNG, never
/// serialized and never logged.
///
/// Per *process*, which is what makes a key meaningless outside the
/// process that made it. A shared cache across several proxies would
/// need a configured secret instead, since two processes must agree on
/// the key for a shared entry to be found at all.
///
/// Holds the *keyed* HMAC state rather than the raw bytes, so the
/// fallible part of setting it up happens once at construction where an
/// error is natural, and each derivation is an infallible clone of an
/// already-keyed instance. Cloning a keyed MAC to reuse it is the
/// standard pattern and it is what keeps the hot path free of a
/// can't-happen error branch.
///
/// The consequence is that the raw secret is zeroized as soon as it has
/// been absorbed, while the derived HMAC state lives for the process
/// lifetime and is not zeroized on drop. That state is not the key, but
/// it is equivalent to it for producing tags, so it is worth being
/// accurate about: this is protection against the secret lingering in a
/// buffer, not against an attacker who can already read our heap. An
/// attacker at that level has the cached tokens themselves.
pub(crate) struct KeySecret(Hmac<Sha256>);

impl KeySecret {
    /// Draw a fresh secret from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns a message describing the failure. A host that cannot
    /// produce 32 random bytes cannot be given a working cache, and that
    /// is a construction-time failure rather than a silent fallback to
    /// something weaker.
    pub(crate) fn random() -> Result<Self, String> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|e| format!("could not draw a cache-key secret from the OS CSPRNG: {e}"))?;
        // `Hmac` accepts a key of any length, so this cannot fail for a
        // 32-byte array. Handled rather than asserted because a panic
        // here would take down a host over something recoverable.
        let keyed = Hmac::<Sha256>::new_from_slice(bytes.as_ref())
            .map_err(|e| format!("could not initialize the cache-key HMAC: {e}"))?;
        Ok(Self(keyed))
    }
}

impl std::fmt::Debug for KeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySecret(<elided>)")
    }
}

/// A derived cache key.
///
/// Safe to log by construction: it is an HMAC tag under a secret that
/// never leaves the process, so it reveals nothing about the credential
/// it was derived from.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey([u8; 32]);

impl CacheKey {
    /// A byte for decorrelating this entry's retirement from its
    /// neighbours'. See `CacheConfig::serve_window` for why the jitter
    /// comes from the key rather than from an RNG.
    pub(crate) fn jitter_byte(&self) -> u8 {
        self.0[0]
    }

    /// A key with chosen bytes, for tests that need to call an expiry
    /// policy directly rather than through a derivation.
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Truncated: the full tag is safe to print, but 16 hex characters
        // are enough to correlate two log lines and short enough to sit
        // in a message without swamping it.
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The delegator's own identity, as far as the key is concerned.
///
/// Load-bearing beyond mere narrowing. For `subject: this_workload`
/// there *is* no inbound credential — the anchor is empty by design and
/// contributes no isolation — so these fields are the only thing keeping
/// two differently-configured delegators from sharing an entry for a
/// token that speaks for two different clients.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DelegatorIdentity<'a> {
    /// The plugin instance name, which distinguishes two configured
    /// delegators.
    pub(crate) instance: &'a str,
    /// The `IdP` token endpoint.
    pub(crate) token_endpoint: &'a str,
    /// The OAuth client this delegator authenticates as.
    pub(crate) client_id: &'a str,
}

/// Length-prefixed encoder feeding an HMAC.
///
/// Length prefixes rather than delimiters. A delimiter raises the
/// question of what happens when a component contains it; `("ab", "c")`
/// and `("a", "bc")` must not agree, and with a prefix they cannot,
/// whatever the component holds. SPIRE achieves the same with nul
/// separators and a note about ambiguity; prefixing costs the same and
/// removes the question.
struct KeyEncoder(Hmac<Sha256>);

impl KeyEncoder {
    fn new(secret: &KeySecret) -> Self {
        Self(secret.0.clone())
    }

    /// A length-prefixed byte string.
    fn bytes(&mut self, value: &[u8]) -> &mut Self {
        // `u32` rather than `usize` so the encoding does not change
        // meaning between a 32-bit and a 64-bit build. A component
        // longer than 4GiB is not reachable from a token or a YAML
        // scalar; saturating keeps the encoding total rather than
        // panicking on an input that cannot occur.
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.0.update(&len.to_le_bytes());
        self.0.update(value);
        self
    }

    fn str(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    /// A single discriminant byte, for enum variants.
    fn tag(&mut self, value: u8) -> &mut Self {
        self.0.update(&[value]);
        self
    }

    /// An optional string, with an explicit presence tag.
    ///
    /// The tag is the point. Without it `None` and `Some("")` encode
    /// identically, which silently merges "no audience configured" with
    /// "audience configured as empty" — a collision between two
    /// genuinely different delegations that no test written against
    /// realistic values would ever catch.
    fn opt_str(&mut self, value: Option<&str>) -> &mut Self {
        match value {
            None => self.tag(0x00),
            Some(s) => self.tag(0x01).str(s),
        }
    }

    /// A list whose order and duplicates must not matter.
    ///
    /// Sorted and deduplicated before encoding, so a route author
    /// reordering `permissions:` in YAML does not split the cache into
    /// two entries holding identical tokens. SPIRE sorts audiences for
    /// the same reason.
    fn set(&mut self, values: &[String]) -> &mut Self {
        let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.dedup();
        self.0.update(
            &u32::try_from(sorted.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for value in sorted {
            self.str(value);
        }
        self
    }

    fn finish(self) -> CacheKey {
        CacheKey(self.0.finalize().into_bytes().into())
    }
}

/// Discriminant for a subject mode, or `None` for a variant this build
/// does not know.
///
/// `DelegationSubject` is `#[non_exhaustive]`, so a variant added
/// upstream would otherwise fall into a catch-all arm and silently share
/// a key space with an existing mode. Refusing to cache an unrecognized
/// subject costs a cache miss; guessing costs a credential mix-up.
fn subject_tag(subject: &DelegationSubject) -> Option<u8> {
    match subject {
        DelegationSubject::User => Some(1),
        DelegationSubject::Client => Some(2),
        DelegationSubject::CallerWorkload => Some(3),
        DelegationSubject::ThisWorkload => Some(4),
        _ => None,
    }
}

/// Discriminant for a target type. Same `#[non_exhaustive]` reasoning as
/// [`subject_tag`].
fn target_type_tag(target: &TargetType) -> Option<(u8, Option<&str>)> {
    match target {
        TargetType::Tool => Some((1, None)),
        TargetType::Agent => Some((2, None)),
        TargetType::Resource => Some((3, None)),
        TargetType::Service => Some((4, None)),
        TargetType::Custom(name) => Some((5, Some(name.as_str()))),
        _ => None,
    }
}

/// Discriminant for an enforcement point. Same reasoning as
/// [`subject_tag`].
fn auth_enforced_by_tag(value: AuthEnforcedBy) -> Option<u8> {
    match value {
        AuthEnforcedBy::Caller => Some(1),
        AuthEnforcedBy::Target => Some(2),
        AuthEnforcedBy::Both => Some(3),
        _ => None,
    }
}

/// Discriminant for a token role. Same reasoning as [`subject_tag`].
fn token_role_tag(role: &TokenRole) -> Option<(u8, Option<&str>)> {
    match role {
        TokenRole::User => Some((1, None)),
        TokenRole::Client => Some((2, None)),
        TokenRole::CallerWorkload => Some((3, None)),
        TokenRole::Custom(name) => Some((4, Some(name.as_str()))),
        _ => None,
    }
}

/// Why a delegation was not cacheable.
///
/// Carried rather than folded into a bare `None` so the caller can say
/// which one happened. Two of these are configuration problems an
/// operator wants to hear about once; the others are ordinary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotCacheable {
    /// The credential being exchanged was empty, and the subject is not
    /// `this_workload` (where an empty anchor is correct).
    ///
    /// Two callers who both arrive without the relevant token would
    /// otherwise compute the same anchor. In practice the `IdP` rejects
    /// an exchange with an empty `subject_token`, so no entry would be
    /// stored anyway — but that leaves a security property enforced by
    /// someone else's input validation, which is not where it belongs.
    EmptyAnchor,

    /// The route carries `route_attenuation.resource_template`.
    ///
    /// The template is an *unrendered* URI with `{{ args.* }}`
    /// placeholders that handlers substitute from request context. Every
    /// other component of this key is an operator-authored literal, and
    /// that is what makes them safe. A rendered template is not: it
    /// carries request data, so two requests differing only in their
    /// arguments would produce differently-scoped tokens under one key,
    /// and the second caller would be served a token minted for the
    /// first one's resource.
    ///
    /// This delegator does not render the template today — it reads only
    /// `capabilities` and `ttl_seconds`. But RFC 8693 has a `resource`
    /// parameter, and wiring the rendered template into it looks like a
    /// one-line feature. Refusing to cache while the field is set means
    /// that change degrades the hit rate instead of leaking a
    /// credential.
    ResourceTemplate,

    /// A variant this build does not recognize appeared in one of the
    /// `#[non_exhaustive]` enums that make up the key.
    UnknownVariant,
}

/// Derive the cache key for a delegation, or explain why there isn't
/// one.
///
/// Ordering is fixed and must not be rearranged without bumping
/// [`DOMAIN`]: two deployments disagreeing about the order would agree
/// about nothing, and one deployment changing it mid-rollout would have
/// old and new entries in the same map.
pub(crate) fn derive(
    secret: &KeySecret,
    delegator: DelegatorIdentity<'_>,
    payload: &DelegationPayload,
) -> Result<CacheKey, NotCacheable> {
    let subject = payload.subject();
    let subject_tag = subject_tag(subject).ok_or(NotCacheable::UnknownVariant)?;

    // `this_workload` has no inbound credential to exchange: the
    // delegator proves who it is with its own client credentials, so an
    // empty anchor is correct there and only there.
    let anchor = payload.bearer_token();
    if anchor.is_empty() && *subject != DelegationSubject::ThisWorkload {
        return Err(NotCacheable::EmptyAnchor);
    }

    if payload
        .route_attenuation()
        .is_some_and(|att| att.resource_template.is_some())
    {
        return Err(NotCacheable::ResourceTemplate);
    }

    let (target_type_tag, target_type_name) =
        target_type_tag(payload.target_type()).ok_or(NotCacheable::UnknownVariant)?;
    let auth_tag =
        auth_enforced_by_tag(payload.auth_enforced_by()).ok_or(NotCacheable::UnknownVariant)?;

    let mut enc = KeyEncoder::new(secret);

    // 0. Domain separation and version.
    enc.bytes(DOMAIN);

    // 1-2. Which delegator, and which IdP identity it mints under. Two
    //      instances pointed at different IdPs, or authenticating as
    //      different clients, must never share an entry.
    enc.str(delegator.instance)
        .str(delegator.token_endpoint)
        .str(delegator.client_id);

    // 3. The subject mode. Not *who* — which credential slot is being
    //    exchanged, and therefore what kind of token comes back. This is
    //    the analogue of MSAL's `credential_type`, and a key resting on
    //    it alone would collide every user in `user` mode.
    enc.tag(subject_tag);

    // 4. The credential anchor. The load-bearing component; see the
    //    module docs.
    enc.str(anchor);

    // 5-6. The RFC 8693 actor, when the step opted into one. Both the
    //      role and the token: the bytes alone do not say whose they
    //      are, and varying only the actor must miss.
    match payload.actor_role() {
        None => {
            enc.tag(0x00);
        },
        Some(role) => {
            let (tag, custom) = token_role_tag(role).ok_or(NotCacheable::UnknownVariant)?;
            enc.tag(0x01).tag(tag).opt_str(custom);
        },
    }
    enc.str(payload.actor_token());

    // 7-9. What the token is minted *for*. `target_audience` is the
    //      component whose omission is FastMCP CVE-2025-69196.
    enc.str(payload.target_name())
        .tag(target_type_tag)
        .opt_str(target_type_name)
        .opt_str(payload.target_audience());

    // 10-12. The remaining narrowing an operator wrote.
    enc.set(payload.required_permissions())
        .opt_str(payload.trust_domain())
        .tag(auth_tag);

    // 13. Route attenuation. Only ever shortens or narrows, so a route
    //     that attenuates produces a different token and must not share
    //     an entry with one that does not.
    encode_attenuation(&mut enc, payload.route_attenuation());

    Ok(enc.finish())
}

/// Encode the attenuation block, or its absence.
///
/// `resource_template` is deliberately not encoded: [`derive`] refuses
/// to produce a key at all when it is set, so there is nothing to
/// encode. If that ever changes, the *rendered* value belongs here, not
/// the template, and the flooding analysis has to be revisited because a
/// rendered value carries request data.
fn encode_attenuation(enc: &mut KeyEncoder, attenuation: Option<&AttenuationConfig>) {
    match attenuation {
        None => {
            enc.tag(0x00);
        },
        Some(att) => {
            enc.tag(0x01).set(&att.capabilities).set(&att.actions);
            match att.ttl_seconds {
                None => enc.tag(0x00),
                Some(ttl) => enc.tag(0x01).bytes(&ttl.to_le_bytes()),
            };
        },
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests assert on known-good values"
)]
mod tests {
    use super::*;

    fn secret() -> KeySecret {
        KeySecret::random().expect("the test host can produce random bytes")
    }

    fn delegator() -> DelegatorIdentity<'static> {
        DelegatorIdentity {
            instance: "delegator-a",
            token_endpoint: "https://idp.example.com/token",
            client_id: "gateway",
        }
    }

    /// A payload that is cacheable, so each test can vary exactly one
    /// component away from it.
    fn base() -> DelegationPayload {
        DelegationPayload::new("user-token-alice", "billing-api")
            .with_target_audience("https://billing.example.com")
    }

    fn key_of(payload: &DelegationPayload, secret: &KeySecret) -> CacheKey {
        derive(secret, delegator(), payload).expect("base payload is cacheable")
    }

    /// Vary one thing, assert the key moves. The point of the whole
    /// module: every component that changes what gets minted must change
    /// the key, or one caller is served another's credential.
    fn assert_differs(mutate: impl FnOnce(DelegationPayload) -> DelegationPayload) {
        let secret = secret();
        let before = key_of(&base(), &secret);
        let after = key_of(&mutate(base()), &secret);
        assert_ne!(
            before, after,
            "varying this component alone must miss the cache"
        );
    }

    #[test]
    fn identical_payloads_agree() {
        let secret = secret();
        assert_eq!(key_of(&base(), &secret), key_of(&base(), &secret));
    }

    #[test]
    fn two_bearer_tokens_never_share_an_entry() {
        assert_differs(|_| {
            DelegationPayload::new("user-token-bob", "billing-api")
                .with_target_audience("https://billing.example.com")
        });
    }

    #[test]
    fn varying_only_the_actor_token_misses() {
        let secret = secret();
        let a = base().with_actor(TokenRole::CallerWorkload, "svid-one");
        let b = base().with_actor(TokenRole::CallerWorkload, "svid-two");
        assert_ne!(key_of(&a, &secret), key_of(&b, &secret));
    }

    #[test]
    fn varying_only_the_actor_role_misses() {
        let secret = secret();
        let a = base().with_actor(TokenRole::CallerWorkload, "same-token");
        let b = base().with_actor(TokenRole::Client, "same-token");
        assert_ne!(key_of(&a, &secret), key_of(&b, &secret));
    }

    #[test]
    fn an_absent_actor_differs_from_an_empty_one() {
        let secret = secret();
        let absent = key_of(&base(), &secret);
        let empty = key_of(&base().with_actor(TokenRole::Client, ""), &secret);
        assert_ne!(
            absent, empty,
            "no actor and an empty actor are different delegations"
        );
    }

    #[test]
    fn varying_the_subject_mode_misses() {
        assert_differs(|p| p.with_subject(DelegationSubject::Client));
    }

    #[test]
    fn varying_the_target_name_misses() {
        assert_differs(|_| {
            DelegationPayload::new("user-token-alice", "invoicing-api")
                .with_target_audience("https://billing.example.com")
        });
    }

    #[test]
    fn varying_the_target_audience_misses() {
        assert_differs(|p| p.with_target_audience("https://payroll.example.com"));
    }

    #[test]
    fn varying_the_target_type_misses() {
        assert_differs(|p| p.with_target_type(TargetType::Service));
    }

    #[test]
    fn varying_required_permissions_misses() {
        assert_differs(|p| p.with_required_permissions(vec!["invoices:write".to_owned()]));
    }

    #[test]
    fn varying_the_trust_domain_misses() {
        assert_differs(|p| p.with_trust_domain("spiffe://other.example.com"));
    }

    #[test]
    fn varying_the_enforcement_point_misses() {
        assert_differs(|p| p.with_auth_enforced_by(AuthEnforcedBy::Target));
    }

    #[test]
    fn varying_the_delegator_instance_misses() {
        let secret = secret();
        let payload = base();
        let a = derive(&secret, delegator(), &payload).unwrap();
        let b = derive(
            &secret,
            DelegatorIdentity {
                instance: "delegator-b",
                ..delegator()
            },
            &payload,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    /// The `this_workload` case, where the credential anchor is empty by
    /// design and the delegator identity is the only thing isolating two
    /// deployments. Without this the two would share an entry, and a
    /// token minted for one client would be handed to the other.
    #[test]
    fn two_delegators_as_this_workload_do_not_share_an_entry() {
        let secret = secret();
        let payload = DelegationPayload::new("", "billing-api")
            .with_subject(DelegationSubject::ThisWorkload)
            .with_target_audience("https://billing.example.com");

        let a = derive(&secret, delegator(), &payload).expect("this_workload is cacheable");
        let b = derive(
            &secret,
            DelegatorIdentity {
                client_id: "other-gateway",
                ..delegator()
            },
            &payload,
        )
        .expect("this_workload is cacheable");

        assert_ne!(
            a, b,
            "with an empty anchor the delegator identity is the only isolation there is"
        );
    }

    #[test]
    fn a_different_idp_endpoint_misses() {
        let secret = secret();
        let payload = base();
        let a = derive(&secret, delegator(), &payload).unwrap();
        let b = derive(
            &secret,
            DelegatorIdentity {
                token_endpoint: "https://other-idp.example.com/token",
                ..delegator()
            },
            &payload,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    /// `agent_id` is client-settable session state, explicitly "NOT a
    /// credential". It has no accessor on `DelegationPayload` and must
    /// never acquire one for this purpose: it would let a caller pick
    /// its own cache partition, and worse, invite someone to treat it as
    /// naming the acting agent. The actor is the actor *token*.
    #[test]
    fn agent_id_is_absent_from_the_key() {
        // `include_str!` resolves relative to this source file at compile
        // time, so the check does not depend on the working directory the
        // test harness happens to run in.
        let derivation = include_str!("key.rs")
            .split("mod tests")
            .next()
            .expect("the module has a body before its tests");
        assert!(
            !derivation.contains("agent_id"),
            "AgentExtension.agent_id is caller-controlled and must not enter the cache key"
        );
    }

    /// Reordering a YAML sequence must not split the cache into two
    /// entries holding identical tokens.
    #[test]
    fn permission_order_does_not_matter() {
        let secret = secret();
        let a = base().with_required_permissions(vec![
            "invoices:read".to_owned(),
            "invoices:write".to_owned(),
        ]);
        let b = base().with_required_permissions(vec![
            "invoices:write".to_owned(),
            "invoices:read".to_owned(),
        ]);
        assert_eq!(key_of(&a, &secret), key_of(&b, &secret));
    }

    #[test]
    fn duplicate_permissions_do_not_matter() {
        let secret = secret();
        let a = base().with_required_permissions(vec!["invoices:read".to_owned()]);
        let b = base().with_required_permissions(vec![
            "invoices:read".to_owned(),
            "invoices:read".to_owned(),
        ]);
        assert_eq!(key_of(&a, &secret), key_of(&b, &secret));
    }

    /// The classic `Option` collision. Without a presence tag these two
    /// encode identically, silently merging two different delegations.
    #[test]
    fn absent_and_empty_encode_differently() {
        let secret = secret();
        let absent = DelegationPayload::new("user-token-alice", "billing-api");
        let empty =
            DelegationPayload::new("user-token-alice", "billing-api").with_target_audience("");
        assert_ne!(key_of(&absent, &secret), key_of(&empty, &secret));
    }

    /// The component-boundary shift. With length prefixes these cannot
    /// agree; with a naive concatenation they would.
    #[test]
    fn a_boundary_shift_between_components_misses() {
        let secret = secret();
        let a = DelegationPayload::new("ab", "c-api").with_target_audience("aud");
        let b = DelegationPayload::new("a", "bc-api").with_target_audience("aud");
        assert_ne!(key_of(&a, &secret), key_of(&b, &secret));
    }

    #[test]
    fn attenuation_changes_the_key() {
        assert_differs(|p| {
            p.with_route_attenuation(AttenuationConfig {
                capabilities: vec!["read".to_owned()],
                resource_template: None,
                actions: Vec::new(),
                ttl_seconds: None,
            })
        });
    }

    /// A route shortening the TTL produces a materially different token
    /// and must not be served one that was not shortened.
    #[test]
    fn attenuation_ttl_changes_the_key() {
        let secret = secret();
        let with_ttl = |ttl| {
            base().with_route_attenuation(AttenuationConfig {
                capabilities: Vec::new(),
                resource_template: None,
                actions: Vec::new(),
                ttl_seconds: ttl,
            })
        };
        assert_ne!(
            key_of(&with_ttl(Some(60)), &secret),
            key_of(&with_ttl(Some(120)), &secret)
        );
        assert_ne!(
            key_of(&with_ttl(None), &secret),
            key_of(&with_ttl(Some(60)), &secret)
        );
    }

    #[test]
    fn an_empty_anchor_is_not_cacheable() {
        let secret = secret();
        let payload = DelegationPayload::new("", "billing-api");
        assert_eq!(
            derive(&secret, delegator(), &payload),
            Err(NotCacheable::EmptyAnchor)
        );
    }

    #[test]
    fn an_empty_anchor_is_fine_for_this_workload() {
        let secret = secret();
        let payload =
            DelegationPayload::new("", "billing-api").with_subject(DelegationSubject::ThisWorkload);
        derive(&secret, delegator(), &payload)
            .expect("this_workload has no inbound credential by design");
    }

    #[test]
    fn a_resource_template_is_not_cacheable() {
        let secret = secret();
        let payload = base().with_route_attenuation(AttenuationConfig {
            capabilities: Vec::new(),
            resource_template: Some("https://billing.example.com/{{ args.invoice_id }}".to_owned()),
            actions: Vec::new(),
            ttl_seconds: None,
        });
        assert_eq!(
            derive(&secret, delegator(), &payload),
            Err(NotCacheable::ResourceTemplate),
            "a template rendered from request arguments would scope the token per-request"
        );
    }

    /// Two processes must not agree on a key. This is what makes a key
    /// meaningless if it escapes in a log line, and it is the property a
    /// shared cache would have to give up by configuring the secret.
    #[test]
    fn keys_do_not_survive_a_change_of_secret() {
        let payload = base();
        let a = derive(&secret(), delegator(), &payload).unwrap();
        let b = derive(&secret(), delegator(), &payload).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn debug_does_not_print_the_secret() {
        let rendered = format!("{:?}", secret());
        assert_eq!(rendered, "KeySecret(<elided>)");
    }
}
