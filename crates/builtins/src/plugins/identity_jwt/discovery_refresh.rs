// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// One refresh of an `oidc_discovery` issuer: re-read the provider
// configuration when it is due, fetch the JWKS it names, and commit both as
// one change. Driven by the verify path and by `initialize_with`, under the
// issuer's `RefreshGate`, so there is no task, timer or thread of its own.

use std::time::{Duration, Instant};

use jsonwebtoken::Algorithm;

use praxis_policy_core::host::HostServices;

use crate::plugins::identity_jwt::config::{
    JwksFetch, JwksFetchBudget, KeySourceError, fetch_jwks,
};
use crate::plugins::identity_jwt::discovery::{
    DiscoveryError, Document, DocumentFetch, Expectations, OidcDiscoveryConfig, authority,
    fetch_document,
};
use crate::plugins::identity_jwt::trusted_issuer::{TrustedIssuer, older_than};

/// What the last accepted discovery document said, for one issuer.
///
/// Held in the issuer's `RefreshGate` and written only by the refresh that
/// holds its single-flight lock. Bounded: one URL, at most nine algorithms,
/// one validator.
#[derive(Clone, Default)]
pub(super) struct DiscoveryState {
    /// The JWKS the current keys came from. `None` until a document has been
    /// accepted and its JWKS fetched.
    jwks_uri: Option<String>,
    /// The algorithms derived from that document.
    algorithms: Vec<Algorithm>,
    /// The document's `ETag`, for a conditional re-read.
    etag: Option<String>,
    /// When the document was last accepted or confirmed unchanged.
    pub(super) discovered_at: Option<Instant>,
    /// Re-read the document on the next attempt even if it is fresh, because
    /// the JWKS it named failed: the key set may have moved.
    rediscover: bool,
}

// Manual so a validator never reaches a log line through `Debug`.
impl std::fmt::Debug for DiscoveryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryState")
            .field("jwks_uri", &self.jwks_uri)
            .field("algorithms", &self.algorithms)
            .field("has_etag", &self.etag.is_some())
            .field("discovered_at", &self.discovered_at)
            .field("rediscover", &self.rediscover)
            .finish()
    }
}

impl DiscoveryState {
    /// Whether this attempt has to read the document.
    fn needs_discovery(&self, max_age: Duration) -> bool {
        self.jwks_uri.is_none() || self.rediscover || older_than(self.discovered_at, max_age)
    }

    /// Take on an accepted document.
    fn adopt(&mut self, document: Document, etag: Option<String>, now: Instant) {
        self.jwks_uri = Some(document.jwks_uri);
        self.algorithms = document.algorithms;
        self.etag = etag;
        self.discovered_at = Some(now);
    }
}

/// What the discovery hop of one attempt produced.
enum Hop {
    /// Not due: the held document is fresh.
    Skipped,
    /// The peer confirmed the held document with a `304`.
    Confirmed,
    /// A new accepted document.
    Fresh(Document, Option<String>),
    /// The fetch failed and a last-good document is kept.
    Failed,
}

/// Refresh `issuer` from its provider configuration.
///
/// Call with the issuer's single-flight lock held and, on the request path,
/// its floor claimed. At most one document fetch and one JWKS fetch. A
/// document is re-read only when none was accepted yet, when it is older than
/// `refresh_secs`, or after a JWKS failure; the JWKS is always fetched,
/// conditionally when the URL is unchanged.
///
/// Returns whether what a verify checks against changed (keys or
/// algorithms), so the caller knows whether re-validating is worth anything.
/// Recoverable failures are logged here and keep the last good state; they
/// return `Ok`, as the caller has nothing more to do about them.
///
/// A failed document fetch does not advance the document's age, so during a
/// lasting discovery outage the issuer stays stale: one request per
/// `min_refresh_interval_secs` runs this inline and waits out the failing
/// fetch (up to two request-path hops, 4 s), while held keys keep verifying.
/// The same holds for a `jwks_url` issuer whose endpoint is down.
///
/// # Errors
///
/// Only a [`KeySourceError::Fatal`], when no transport is available to the
/// plugin: no later attempt fixes that.
pub(super) async fn refresh(
    issuer: &TrustedIssuer,
    source: &OidcDiscoveryConfig,
    svc: &dyn HostServices,
    budget: JwksFetchBudget,
    plugin: &str,
) -> Result<bool, KeySourceError> {
    let max_age = Duration::from_secs(source.refresh_secs);
    let discovery_url = source.discovery_url(&issuer.issuer);
    let bounds = budget.hop_bounds();
    let held = issuer.refresh.discovery();
    let log = Log {
        plugin,
        issuer: &issuer.issuer,
        discovery_url: &discovery_url,
    };

    let hop = if held.needs_discovery(max_age) {
        let expected = Expectations {
            issuer: source.expected_issuer(&issuer.issuer),
            insecure_http: source.insecure_http,
            configured: &issuer.algorithms,
        };
        match fetch_document(&discovery_url, &expected, svc, bounds, held.etag.as_deref()).await {
            Ok(DocumentFetch::Accepted { document, etag }) => {
                log.document_notes(&document);
                Hop::Fresh(document, etag)
            },
            Ok(DocumentFetch::NotModified) => Hop::Confirmed,
            Err(DiscoveryError::Fetch(e)) if e.is_fatal() => return Err(e),
            Err(e) if held.jwks_uri.is_none() => {
                log.unresolved(&e, budget);
                return Ok(false);
            },
            Err(e) => {
                log.kept_last_good(&e);
                Hop::Failed
            },
        }
    } else {
        Hop::Skipped
    };

    let (target, moved) = match (&hop, held.jwks_uri.as_deref()) {
        (Hop::Fresh(document, _), held_uri) => (
            document.jwks_uri.clone(),
            held_uri != Some(document.jwks_uri.as_str()),
        ),
        (_, Some(held_uri)) => (held_uri.to_owned(), false),
        // Every way of reaching here with nothing held went through a fresh
        // document; a confirmation needs a validator, which needs a commit.
        (_, None) => return Ok(false),
    };

    // A moved key set starts over: its predecessor's validator means nothing
    // to the new URL, and a `304` from it would vouch for the wrong keys.
    let validator = if moved { None } else { issuer.refresh.etag() };
    let fetched = fetch_jwks(
        &target,
        source.insecure_http,
        true,
        svc,
        bounds,
        validator.as_deref(),
    )
    .await;

    let mut next = held.clone();
    let now = Instant::now();
    let discovered = !matches!(hop, Hop::Skipped | Hop::Failed);
    match fetched {
        Ok(JwksFetch::Fetched { keys, etag }) => {
            commit_hop(&mut next, hop, now);
            next.rediscover = false;
            let count = keys.len();
            // Keys first, discovery state last, each under its own lock. A
            // verify in between sees new keys with an old `discovered_at` and
            // at worst re-checks staleness, which the floor and the
            // single-flight lock held here turn into no extra fetch.
            *issuer
                .keys
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                keys.with_algorithms(next.algorithms.clone());
            issuer.refresh.set_etag(etag);
            issuer.refresh.mark_success();
            log.progress(&held, &next, discovered, Some(count));
            if held.jwks_uri.is_some() {
                log.keys_refreshed(&target, count);
            }
            issuer.refresh.set_discovery(next);
            Ok(true)
        },
        Ok(JwksFetch::NotModified) if validator.is_some() => {
            commit_hop(&mut next, hop, now);
            next.rediscover = false;
            let changed = next.algorithms != held.algorithms;
            if changed {
                set_algorithms(issuer, &next.algorithms);
                issuer.refresh.mark_success();
            } else {
                issuer.refresh.mark_current();
            }
            log.progress(&held, &next, discovered, None);
            issuer.refresh.set_discovery(next);
            Ok(changed)
        },
        other => {
            let error = match other {
                Err(e) => e,
                Ok(_) => KeySourceError::Recoverable(format!(
                    "JWKS GET {target} answered 304 to a request carrying no If-None-Match"
                )),
            };
            if error.is_fatal() {
                return Err(error);
            }
            // A moved key set is adopted only with keys from it; a document
            // that kept the URL is committed either way, so a narrowed
            // algorithm list takes effect while the JWKS endpoint is down.
            if !moved {
                commit_hop(&mut next, hop, now);
            }
            next.rediscover = true;
            let changed = next.algorithms != held.algorithms;
            if changed {
                set_algorithms(issuer, &next.algorithms);
                issuer.refresh.bump_generation();
                log.progress(&held, &next, discovered, None);
            }
            log.jwks_failed(&target, &error, budget);
            issuer.refresh.set_discovery(next);
            Ok(changed)
        },
    }
}

/// Record what the discovery hop learned.
fn commit_hop(state: &mut DiscoveryState, hop: Hop, now: Instant) {
    match hop {
        Hop::Fresh(document, etag) => state.adopt(document, etag, now),
        Hop::Confirmed => state.discovered_at = Some(now),
        Hop::Skipped | Hop::Failed => {},
    }
}

/// Rebind the held keys to `algorithms`.
fn set_algorithms(issuer: &TrustedIssuer, algorithms: &[Algorithm]) {
    issuer
        .keys
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_algorithms(algorithms.to_vec());
}

/// The fields every discovery event carries.
struct Log<'a> {
    plugin: &'a str,
    issuer: &'a str,
    discovery_url: &'a str,
}

impl Log<'_> {
    /// What an accepted document left out or fell back on.
    fn document_notes(&self, document: &Document) {
        if !document.ignored.is_empty() {
            tracing::debug!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                ignored = ?document.ignored,
                "ignoring advertised algorithms that are symmetric, unsigned or unsupported"
            );
        }
        if document.algorithms_omitted {
            tracing::warn!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                algorithms = ?document.algorithms,
                "discovery document omits id_token_signing_alg_values_supported; using the \
                 configured algorithms, or RS256 when none are configured"
            );
        }
    }

    /// The state a successful attempt settled on, against what it replaced.
    fn progress(
        &self,
        held: &DiscoveryState,
        next: &DiscoveryState,
        discovered: bool,
        keys: Option<usize>,
    ) {
        let (Some(old_uri), Some(new_uri)) = (held.jwks_uri.as_deref(), next.jwks_uri.as_deref())
        else {
            tracing::info!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                jwks_uri = next.jwks_uri.as_deref().unwrap_or_default(),
                algorithms = ?next.algorithms,
                keys = keys.unwrap_or_default(),
                "OIDC discovery resolved"
            );
            return;
        };
        if old_uri == new_uri && held.algorithms == next.algorithms {
            if discovered {
                tracing::debug!(
                    plugin = %self.plugin,
                    issuer = %self.issuer,
                    discovery_url = %self.discovery_url,
                    "OIDC discovery unchanged"
                );
            }
            return;
        }
        let host_changed = match (authority(old_uri), authority(new_uri)) {
            (Some(old), Some(new)) => !old.eq_ignore_ascii_case(new),
            _ => true,
        };
        if host_changed {
            tracing::warn!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                old_jwks_uri = %old_uri,
                new_jwks_uri = %new_uri,
                old_algorithms = ?held.algorithms,
                new_algorithms = ?next.algorithms,
                "OIDC discovery changed; the key set moved to another host"
            );
        } else {
            tracing::info!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                old_jwks_uri = %old_uri,
                new_jwks_uri = %new_uri,
                old_algorithms = ?held.algorithms,
                new_algorithms = ?next.algorithms,
                "OIDC discovery changed"
            );
        }
    }

    /// A refresh after the first resolution replaced the key set, the event a
    /// `jwks_url` issuer logs for the same thing.
    fn keys_refreshed(&self, jwks_uri: &str, keys: usize) {
        tracing::info!(
            plugin = %self.plugin,
            issuer = %self.issuer,
            jwks_uri = %jwks_uri,
            keys,
            "refreshed JWKS on demand"
        );
    }

    /// A document fetch failed with nothing to fall back on.
    fn unresolved(&self, error: &DiscoveryError, budget: JwksFetchBudget) {
        let outcome = match budget {
            JwksFetchBudget::Startup => {
                "initial OIDC discovery failed; soft-fail. Tokens from this issuer deny \
                 auth.jwks_unavailable until a refresh succeeds"
            },
            JwksFetchBudget::RequestPath => {
                "OIDC discovery failed; tokens from this issuer deny auth.jwks_unavailable \
                 until a refresh succeeds"
            },
        };
        if error.is_config_fault() {
            tracing::error!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                error = %error,
                "{outcome}"
            );
        } else {
            tracing::warn!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                error = %error,
                "{outcome}"
            );
        }
    }

    /// A document fetch failed and the last good one stays in force.
    fn kept_last_good(&self, error: &DiscoveryError) {
        if error.is_config_fault() {
            tracing::error!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                error = %error,
                "OIDC discovery refresh failed; keeping the last known configuration"
            );
        } else {
            tracing::warn!(
                plugin = %self.plugin,
                issuer = %self.issuer,
                discovery_url = %self.discovery_url,
                error = %error,
                "OIDC discovery refresh failed; keeping the last known configuration"
            );
        }
    }

    /// The JWKS fetch failed; whatever keys are held stay.
    fn jwks_failed(&self, jwks_uri: &str, error: &KeySourceError, budget: JwksFetchBudget) {
        let outcome = match budget {
            JwksFetchBudget::Startup => {
                "initial JWKS fetch for a discovered issuer failed; soft-fail. Tokens from this \
                 issuer deny auth.jwks_unavailable until a refresh succeeds"
            },
            JwksFetchBudget::RequestPath => {
                "JWKS refresh for a discovered issuer failed; keeping the existing keys"
            },
        };
        tracing::warn!(
            plugin = %self.plugin,
            issuer = %self.issuer,
            discovery_url = %self.discovery_url,
            jwks_uri = %jwks_uri,
            error = %error,
            "{outcome}"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use praxis_policy_core::host::InitExtensions;
    use praxis_policy_core::http::{HeaderMap, HttpResponse, HttpTransportError};
    use praxis_policy_core::http_testing::{FakeTransport, granting};
    use serde_json::{Value, json};

    use crate::plugins::identity_jwt::config::{
        DecodingKeySource, DpopConfig, TrustedIssuerConfig,
    };
    use crate::plugins::identity_jwt::trusted_issuer::KeyStore;

    #[tokio::test]
    async fn boot_fetches_the_document_then_the_jwks_it_names() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256"])))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let changed = run(&issuer, &http, JwksFetchBudget::Startup).await;

        assert!(changed, "the first resolution installs keys");
        let requests = http.requests();
        assert_eq!(requests.len(), 2, "one document fetch, one JWKS fetch");
        assert_eq!(
            requests[0].url,
            format!("{ISSUER}/.well-known/openid-configuration")
        );
        assert_eq!(
            requests[0].max_response_bytes, 65_536,
            "discovery body ceiling"
        );
        assert_eq!(requests[1].url, format!("https://keys.example{KEYS_ONE}"));
        assert_eq!(requests[1].max_response_bytes, 262_144, "JWKS body ceiling");
        assert!(holds(&issuer, "k1"), "the advertised key set is installed");
        assert_eq!(algorithms(&issuer), Some(vec![Algorithm::RS256]));
        assert_eq!(issuer.refresh.generation(), 1, "one change, one generation");
    }

    #[tokio::test]
    async fn a_fresh_document_is_not_re_read() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .respond(KEYS_ONE, 200, &jwks(&[rsa("k1")]), etag("\"jwks-1\"")),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;

        run(&issuer, &http, JwksFetchBudget::RequestPath).await;

        assert_eq!(
            http.call_count_for(WELL_KNOWN),
            1,
            "the document is still fresh"
        );
        assert_eq!(http.call_count_for(KEYS_ONE), 2, "the JWKS hop always runs");
        assert_eq!(
            if_none_match(&http.last_request().unwrap()),
            Some("\"jwks-1\"".to_owned()),
            "the JWKS re-fetch is conditional"
        );
    }

    #[tokio::test]
    async fn after_the_ttl_both_fetches_are_conditional_and_304s_change_nothing() {
        let http = Arc::new(
            FakeTransport::new()
                .respond(WELL_KNOWN, 200, &doc(KEYS_ONE, None), etag("\"doc-1\""))
                .respond(WELL_KNOWN, 304, "", HeaderMap::new())
                .respond(KEYS_ONE, 200, &jwks(&[rsa("k1")]), etag("\"jwks-1\""))
                .respond(KEYS_ONE, 304, "", HeaderMap::new()),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        age_document(&issuer);

        let changed = run(&issuer, &http, JwksFetchBudget::RequestPath).await;

        assert!(!changed, "two 304s change nothing a verify checks");
        let requests = http.requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(if_none_match(&requests[2]), Some("\"doc-1\"".to_owned()));
        assert_eq!(if_none_match(&requests[3]), Some("\"jwks-1\"".to_owned()));
        assert_eq!(issuer.refresh.generation(), 1, "no generation bump on 304");
        assert!(
            !issuer
                .refresh
                .discovery()
                .needs_discovery(Duration::from_secs(600)),
            "a 304 resets the document's staleness"
        );
        assert!(!issuer.is_stale(), "a 304 resets the key set's staleness");
    }

    #[tokio::test]
    async fn a_moved_jwks_is_fetched_unconditionally_and_replaces_the_keys() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .json(WELL_KNOWN, 200, &doc(KEYS_TWO, None))
                .respond(KEYS_ONE, 200, &jwks(&[rsa("k1")]), etag("\"jwks-1\""))
                .json(KEYS_TWO, 200, &jwks(&[rsa("k2")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        age_document(&issuer);

        let changed = run(&issuer, &http, JwksFetchBudget::RequestPath).await;

        assert!(changed);
        assert!(
            holds(&issuer, "k2") && !holds(&issuer, "k1"),
            "whole-store swap"
        );
        assert_eq!(
            if_none_match(&http.last_request().unwrap()),
            None,
            "the old URL's validator is not sent to the new one"
        );
        age_document(&issuer);
        run(&issuer, &http, JwksFetchBudget::RequestPath).await;
        assert_eq!(
            http.call_count_for(KEYS_ONE),
            1,
            "the old URL is never contacted again"
        );
    }

    #[tokio::test]
    async fn a_moved_jwks_that_fails_keeps_everything_and_rediscovers_next_time() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .json(WELL_KNOWN, 200, &doc(KEYS_TWO, None))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")]))
                .json(KEYS_TWO, 503, "{}"),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        age_document(&issuer);

        let changed = run(&issuer, &http, JwksFetchBudget::RequestPath).await;

        assert!(!changed, "nothing from the candidate is committed");
        assert!(holds(&issuer, "k1"), "the old keys keep verifying");
        let state = issuer.refresh.discovery();
        assert!(
            state
                .jwks_uri
                .as_deref()
                .is_some_and(|u| u.ends_with(KEYS_ONE))
        );
        assert!(state.rediscover, "the next attempt re-reads the document");

        run(&issuer, &http, JwksFetchBudget::RequestPath).await;
        assert_eq!(
            http.call_count_for(WELL_KNOWN),
            3,
            "re-discovered without waiting a TTL"
        );
    }

    #[tokio::test]
    async fn a_changed_algorithm_set_rebinds_the_held_keys() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256", "ES256"])))
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["ES256"])))
                .respond(KEYS_ONE, 200, &jwks(&[rsa("k1")]), etag("\"jwks-1\""))
                .respond(KEYS_ONE, 304, "", HeaderMap::new()),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        assert_eq!(
            algorithms(&issuer),
            Some(vec![Algorithm::RS256, Algorithm::ES256])
        );
        age_document(&issuer);

        let changed = run(&issuer, &http, JwksFetchBudget::RequestPath).await;

        assert!(
            changed,
            "a narrowed algorithm set must trigger re-validation"
        );
        assert_eq!(algorithms(&issuer), Some(vec![Algorithm::ES256]));
        assert!(holds(&issuer, "k1"), "the keys themselves are untouched");
        assert_eq!(issuer.refresh.generation(), 2);
    }

    #[tokio::test]
    async fn a_narrowed_algorithm_set_applies_while_the_jwks_is_down() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256", "ES256"])))
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["ES256"])))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")]))
                .fail(KEYS_ONE, HttpTransportError::Timeout),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        age_document(&issuer);

        let changed = run(&issuer, &http, JwksFetchBudget::RequestPath).await;

        assert!(changed);
        assert_eq!(algorithms(&issuer), Some(vec![Algorithm::ES256]));
        assert!(issuer.refresh.discovery().rediscover);
    }

    #[tokio::test]
    async fn discovery_down_keeps_the_last_document_and_still_refreshes_the_jwks() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .fail(WELL_KNOWN, HttpTransportError::Connect("refused".into()))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")]))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1"), rsa("k2")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        age_document(&issuer);

        let (changed, events) = captured(run(&issuer, &http, JwksFetchBudget::RequestPath)).await;

        assert!(changed, "rotation keeps working while discovery is down");
        assert!(holds(&issuer, "k2"));
        assert_eq!(http.call_count_for(KEYS_ONE), 2);
        assert_eq!(
            events
                .matching("keeping the last known configuration")
                .len(),
            1,
            "{:?}",
            events.recorded()
        );
    }

    #[tokio::test]
    async fn an_issuer_mismatch_never_reaches_the_jwks_and_says_why() {
        let wrong = json!({ "issuer": "https://other.example", "jwks_uri": format!("https://keys.example{KEYS_ONE}") });
        let http = Arc::new(FakeTransport::new().json(WELL_KNOWN, 200, &wrong.to_string()));
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (changed, events) = captured(run(&issuer, &http, JwksFetchBudget::Startup)).await;

        assert!(!changed);
        assert_eq!(http.call_count(), 1, "the JWKS is never fetched");
        assert!(issuer.keys.read().unwrap().is_empty());
        let errors = events.matching("[ERROR]");
        assert_eq!(errors.len(), 1, "{:?}", events.recorded());
        assert!(
            errors[0].contains("https://other.example"),
            "actual issuer: {errors:?}"
        );
        assert!(errors[0].contains(ISSUER), "expected issuer: {errors:?}");
    }

    #[tokio::test]
    async fn a_discovery_issuer_is_compared_instead_of_the_token_issuer() {
        let source = OidcDiscoveryConfig {
            discovery_url: Some(format!("http://idp.svc:8080/realms/a{WELL_KNOWN}?tenant=x")),
            discovery_issuer: Some("http://idp.svc:8080/realms/a".to_owned()),
            insecure_http: true,
            ..OidcDiscoveryConfig::default()
        };
        let internal = json!({ "issuer": "http://idp.svc:8080/realms/a", "jwks_uri": "http://idp.svc:8080/realms/a/certs" });
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &internal.to_string())
                .json("/realms/a/certs", 200, &jwks(&[rsa("k1")])),
        );
        let issuer = issuer(source, &[]);

        assert!(run(&issuer, &http, JwksFetchBudget::Startup).await);
        assert!(
            http.requests()[0].url.ends_with("?tenant=x"),
            "discovery_url is used verbatim"
        );
    }

    #[tokio::test]
    async fn a_plaintext_jwks_uri_is_refused_without_insecure_http() {
        let plaintext = json!({ "issuer": ISSUER, "jwks_uri": "http://keys.example/k" });
        let http = Arc::new(FakeTransport::new().json(WELL_KNOWN, 200, &plaintext.to_string()));
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        assert!(!run(&issuer, &http, JwksFetchBudget::Startup).await);
        assert_eq!(http.call_count(), 1, "the plaintext JWKS is never fetched");
    }

    #[tokio::test]
    async fn insecure_http_permits_plaintext_for_both_fetches() {
        let source = OidcDiscoveryConfig {
            insecure_http: true,
            ..OidcDiscoveryConfig::default()
        };
        let plaintext_issuer = "http://idp.local/realms/a";
        let document =
            json!({ "issuer": plaintext_issuer, "jwks_uri": "http://idp.local/realms/a/certs" });
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &document.to_string())
                .json("/certs", 200, &jwks(&[rsa("k1")])),
        );
        let issuer = TrustedIssuerConfig {
            issuer: plaintext_issuer.to_owned(),
            ..issuer_config(source)
        }
        .into_trusted_issuer(KeyStore::empty());

        assert!(run(&issuer, &http, JwksFetchBudget::Startup).await);
        assert!(holds(&issuer, "k1"));
    }

    #[tokio::test]
    async fn the_first_resolution_logs_a_cross_origin_jwks_uri() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256"])))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (_, events) = captured(run(&issuer, &http, JwksFetchBudget::Startup)).await;

        let resolved = events.matching("OIDC discovery resolved");
        assert_eq!(resolved.len(), 1, "{:?}", events.recorded());
        assert!(resolved[0].starts_with("[INFO]"), "{resolved:?}");
        assert!(resolved[0].contains("https://keys.example"), "{resolved:?}");
        assert!(resolved[0].contains("plugin=test-plugin"), "{resolved:?}");
        assert!(
            resolved[0].contains(&format!("issuer={ISSUER}")),
            "{resolved:?}"
        );
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed_and_names_discovery_url() {
        let mut location = HeaderMap::new();
        location.insert("location", "https://elsewhere.example/".parse().unwrap());
        let http = Arc::new(FakeTransport::new().respond(WELL_KNOWN, 302, "", location));
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (changed, events) = captured(run(&issuer, &http, JwksFetchBudget::Startup)).await;

        assert!(!changed);
        assert_eq!(http.call_count(), 1, "nothing follows the Location");
        let logged = events.recorded().join("\n");
        assert!(logged.contains("redirect"), "{logged}");
        assert!(logged.contains("discovery_url"), "{logged}");
    }

    #[tokio::test]
    async fn an_oversized_document_is_a_recoverable_rejection() {
        let http = Arc::new(FakeTransport::new().fail(
            WELL_KNOWN,
            HttpTransportError::ResponseTooLarge {
                actual: 70_000,
                limit: 65_536,
            },
        ));
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let outcome = refresh(
            &issuer,
            &OidcDiscoveryConfig::default(),
            &granting(Arc::clone(&http)),
            JwksFetchBudget::Startup,
            "test-plugin",
        )
        .await;

        assert!(matches!(outcome, Ok(false)), "soft-fail, not fatal");
    }

    #[tokio::test]
    async fn no_transport_is_fatal() {
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        let outcome = refresh(
            &issuer,
            &OidcDiscoveryConfig::default(),
            &InitExtensions::new(),
            JwksFetchBudget::Startup,
            "test-plugin",
        )
        .await;
        assert!(
            matches!(outcome, Err(ref e) if e.is_fatal()),
            "a missing transport is a configuration fault: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn an_unconditional_304_is_not_a_document() {
        let http = Arc::new(FakeTransport::new().respond(WELL_KNOWN, 304, "", HeaderMap::new()));
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        assert!(!run(&issuer, &http, JwksFetchBudget::Startup).await);
        assert_eq!(http.call_count(), 1);
    }

    #[tokio::test]
    async fn an_empty_intersection_keeps_the_last_good_algorithms() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256", "ES256"])))
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256"])))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[Algorithm::ES256]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        assert_eq!(algorithms(&issuer), Some(vec![Algorithm::ES256]));
        age_document(&issuer);

        let (_, events) = captured(run(&issuer, &http, JwksFetchBudget::RequestPath)).await;

        assert_eq!(
            algorithms(&issuer),
            Some(vec![Algorithm::ES256]),
            "last good kept"
        );
        let errors = events.matching("[ERROR]");
        assert_eq!(errors.len(), 1, "{:?}", events.recorded());
        assert!(
            errors[0].contains("RS256") && errors[0].contains("ES256"),
            "{errors:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_intersection_with_nothing_held_leaves_no_keys() {
        let http =
            Arc::new(FakeTransport::new().json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256"]))));
        let issuer = issuer(OidcDiscoveryConfig::default(), &[Algorithm::ES256]);
        assert!(!run(&issuer, &http, JwksFetchBudget::Startup).await);
        assert!(issuer.keys.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn only_symmetric_advertised_algorithms_are_rejected() {
        let http =
            Arc::new(FakeTransport::new().json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["HS256"]))));
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        assert!(!run(&issuer, &http, JwksFetchBudget::Startup).await);
        assert_eq!(http.call_count(), 1);
    }

    #[tokio::test]
    async fn omitted_algorithms_warn_and_fall_back_to_rs256() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (_, events) = captured(run(&issuer, &http, JwksFetchBudget::Startup)).await;

        assert_eq!(algorithms(&issuer), Some(vec![Algorithm::RS256]));
        let warned = events.matching("omits id_token_signing_alg_values_supported");
        assert_eq!(warned.len(), 1, "{:?}", events.recorded());
        assert!(warned[0].starts_with("[WARN]"), "{warned:?}");
    }

    #[tokio::test]
    async fn ignored_algorithms_are_logged_at_debug() {
        let http = Arc::new(
            FakeTransport::new()
                .json(
                    WELL_KNOWN,
                    200,
                    &doc(KEYS_ONE, Some(&["HS256", "RS256", "none"])),
                )
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (_, events) = captured(run(&issuer, &http, JwksFetchBudget::Startup)).await;

        assert_eq!(algorithms(&issuer), Some(vec![Algorithm::RS256]));
        let ignored = events.matching("ignoring advertised algorithms");
        assert_eq!(ignored.len(), 1, "{:?}", events.recorded());
        assert!(ignored[0].starts_with("[DEBUG]"), "{ignored:?}");
        assert!(
            ignored[0].contains("HS256") && ignored[0].contains("none"),
            "{ignored:?}"
        );
    }

    #[tokio::test]
    async fn symmetric_keys_in_a_discovered_jwks_are_dropped() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .json(KEYS_ONE, 200, &jwks(&[oct("shared"), rsa("k1")]))
                .json(KEYS_ONE, 200, &jwks(&[oct("shared")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        run(&issuer, &http, JwksFetchBudget::Startup).await;
        assert!(
            holds(&issuer, "k1") && !holds(&issuer, "shared"),
            "oct key dropped"
        );

        let (changed, events) = captured(run(&issuer, &http, JwksFetchBudget::RequestPath)).await;

        assert!(!changed, "a JWKS of only oct keys has nothing to install");
        assert!(holds(&issuer, "k1"), "the previous keys stay");
        let logged = events.recorded().join("\n");
        assert!(logged.contains("no usable signature keys"), "{logged}");
        assert!(logged.contains("1 symmetric"), "{logged}");
    }

    #[tokio::test]
    async fn discovery_down_at_start_leaves_no_keys_and_warns() {
        let http = Arc::new(
            FakeTransport::new().fail(WELL_KNOWN, HttpTransportError::Connect("refused".into())),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (changed, events) = captured(run(&issuer, &http, JwksFetchBudget::Startup)).await;

        assert!(!changed);
        let warned = events.matching("soft-fail");
        assert_eq!(warned.len(), 1, "{:?}", events.recorded());
        assert!(warned[0].starts_with("[WARN]"), "{warned:?}");
    }

    #[tokio::test]
    async fn alternating_documents_retain_constant_state() {
        let served = Arc::new(AtomicUsize::new(0));
        let doc_counter = Arc::clone(&served);
        let http = Arc::new(
            FakeTransport::new()
                .respond_with(WELL_KNOWN, move |_| {
                    let n = doc_counter.fetch_add(1, Ordering::SeqCst);
                    let (uri, algs): (&str, &[&str]) = if n.is_multiple_of(2) {
                        (KEYS_ONE, &["RS256"])
                    } else {
                        (KEYS_TWO, &["RS256", "ES256"])
                    };
                    Ok(HttpResponse::new(200, Bytes::from(doc(uri, Some(algs)))))
                })
                .respond_with(KEYS_ONE, |_| {
                    Ok(HttpResponse::new(200, Bytes::from(jwks(&[rsa("k1")]))))
                })
                .respond_with(KEYS_TWO, |_| {
                    Ok(HttpResponse::new(200, Bytes::from(jwks(&[rsa("k2")]))))
                }),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        for cycle in 0..1_000 {
            age_document(&issuer);
            assert!(
                run(&issuer, &http, JwksFetchBudget::RequestPath).await,
                "cycle {cycle}"
            );
            let state = issuer.refresh.discovery();
            assert_eq!(
                issuer.keys.read().unwrap().len(),
                1,
                "keys never accumulate"
            );
            assert!(state.algorithms.len() <= 2, "algorithms never accumulate");
            assert!(state.jwks_uri.as_deref().is_some_and(|u| u.len() < 64));
        }
        assert_eq!(served.load(Ordering::SeqCst), 1_000);
    }

    #[tokio::test]
    async fn failure_logs_carry_no_body_validator_or_key_material() {
        let marker_doc = json!({
            "issuer": "https://other.example",
            "jwks_uri": format!("https://keys.example{KEYS_ONE}"),
            "body_marker": "BODY-MARKER-7f3a",
        });
        let key = rsa("k1");
        let modulus = key["n"].as_str().unwrap().to_owned();
        let http = Arc::new(
            FakeTransport::new()
                .respond(
                    WELL_KNOWN,
                    200,
                    &doc(KEYS_ONE, None),
                    etag("\"ETAG-MARKER-doc\""),
                )
                .respond(
                    WELL_KNOWN,
                    200,
                    &marker_doc.to_string(),
                    etag("\"ETAG-MARKER-bad\""),
                )
                .respond(KEYS_ONE, 200, &jwks(&[key]), etag("\"ETAG-MARKER-jwks\""))
                .json(KEYS_ONE, 500, "JWKS-BODY-MARKER"),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (_, events) = captured(async {
            run(&issuer, &http, JwksFetchBudget::Startup).await;
            age_document(&issuer);
            run(&issuer, &http, JwksFetchBudget::RequestPath).await;
        })
        .await;

        let logged = events.recorded().join("\n");
        assert!(!logged.is_empty(), "the scenario logs something");
        for secret in ["ETAG-MARKER", "BODY-MARKER", modulus.as_str()] {
            assert!(!logged.contains(secret), "{secret} leaked into: {logged}");
        }
        assert!(
            !format!("{:?}", issuer.refresh.discovery()).contains("ETAG-MARKER"),
            "Debug elides the validator"
        );
    }

    #[tokio::test]
    async fn a_rotated_key_set_is_logged_at_info() {
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, Some(&["RS256"])))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1")]))
                .json(KEYS_ONE, 200, &jwks(&[rsa("k1"), rsa("k2")])),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);
        let (_, boot) = captured(run(&issuer, &http, JwksFetchBudget::Startup)).await;
        assert!(
            boot.matching("refreshed JWKS").is_empty(),
            "the first resolution has its own event: {:?}",
            boot.recorded()
        );

        let (changed, events) = captured(run(&issuer, &http, JwksFetchBudget::RequestPath)).await;

        assert!(
            changed && holds(&issuer, "k2"),
            "the rotated key is installed"
        );
        let refreshed = events.matching("refreshed JWKS on demand");
        assert_eq!(refreshed.len(), 1, "{:?}", events.recorded());
        assert!(refreshed[0].starts_with("[INFO]"), "{refreshed:?}");
        assert!(
            refreshed[0].contains("keys=2") && refreshed[0].contains("issuer="),
            "{refreshed:?}"
        );
    }

    #[tokio::test]
    async fn hostile_jwks_bodies_reach_no_log() {
        let long_kid = |i: usize| format!("KID-MARKER-{i}-{}", "x".repeat(1_000));
        let unusable: Vec<Value> = (0..40)
            .map(
                |i| json!({ "kty": "RSA", "use": "sig", "kid": long_kid(i), "n": "!!", "e": "!!" }),
            )
            .collect();
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .json(
                    KEYS_ONE,
                    200,
                    r#"{"keys":"BODY-MARKER-aws_secret_access_key=AKIAEXAMPLE"}"#,
                )
                .json(KEYS_ONE, 200, &jwks(&unusable)),
        );
        let issuer = issuer(OidcDiscoveryConfig::default(), &[]);

        let (_, events) = captured(async {
            run(&issuer, &http, JwksFetchBudget::Startup).await;
            run(&issuer, &http, JwksFetchBudget::RequestPath).await;
        })
        .await;

        let logged = events.recorded();
        assert_eq!(
            http.call_count_for(KEYS_ONE),
            2,
            "both hostile bodies were served"
        );
        let all = logged.join("\n");
        assert!(!all.contains("BODY-MARKER"), "body content leaked: {all}");
        assert!(all.contains("not a JWKSet"), "{all}");
        assert!(all.contains("and 24 more"), "the list is capped: {all}");
        assert!(
            !all.contains(&long_kid(0)),
            "every echoed kid is clipped: {all}"
        );
        assert!(
            logged.iter().all(|line| line.len() < 16 * 1_024),
            "no log line grows with the body"
        );
    }

    #[tokio::test]
    async fn remote_strings_cannot_forge_log_lines() {
        let forged_issuer = json!({
            "issuer": format!("{ISSUER}\n2026-11-26T00:00:00Z  INFO praxis: FORGED-ISSUER"),
            "jwks_uri": format!("https://keys.example{KEYS_ONE}"),
        });
        let forged_algorithm = doc(KEYS_ONE, Some(&["RS256\n\u{1b}[2J FORGED-ALG"]));
        let forged_kid = jwks(&[
            json!({ "kty": "RSA", "use": "sig", "kid": "k\nFORGED-KID", "n": "!!", "e": "AQAB" }),
        ]);
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &forged_issuer.to_string())
                .json(WELL_KNOWN, 200, &forged_algorithm)
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .json(KEYS_ONE, 200, &forged_kid),
        );

        let (_, events) = captured(async {
            let plain = issuer(OidcDiscoveryConfig::default(), &[]);
            run(&plain, &http, JwksFetchBudget::Startup).await;
            let narrowed = issuer(OidcDiscoveryConfig::default(), &[Algorithm::ES256]);
            run(&narrowed, &http, JwksFetchBudget::Startup).await;
            run(&plain, &http, JwksFetchBudget::Startup).await;
        })
        .await;

        let logged = events.recorded();
        let all = logged.join("\n");
        assert_eq!(http.call_count(), 4, "every hostile string was served");
        for escaped in [
            r"\n2026-11-26T00:00:00Z  INFO praxis: FORGED-ISSUER",
            r"RS256\n\u{1b}[2J FORGED-ALG",
            r"k\nFORGED-KID",
        ] {
            assert!(
                all.contains(escaped),
                "echoed escaped: {escaped} in {logged:?}"
            );
        }
        assert!(
            logged
                .iter()
                .all(|l| !l.contains('\n') && !l.contains('\u{1b}')),
            "no raw newline or escape reaches a log event: {logged:?}"
        );
    }

    #[tokio::test]
    async fn bodies_over_the_ceiling_are_refused_even_when_the_transport_ignores_it() {
        // `FakeTransport` does not enforce `max_response_bytes`, like a host
        // transport that ignores it.
        let mut big_doc: Value = serde_json::from_str(&doc(KEYS_ONE, None)).unwrap();
        big_doc["padding"] = json!("p".repeat(70_000));
        let http = Arc::new(FakeTransport::new().json(WELL_KNOWN, 200, &big_doc.to_string()));
        let issuer_a = issuer(OidcDiscoveryConfig::default(), &[]);
        assert!(!run(&issuer_a, &http, JwksFetchBudget::RequestPath).await);
        assert_eq!(http.call_count(), 1, "an oversized document names no keys");

        let mut big_jwks: Value = serde_json::from_str(&jwks(&[rsa("k1")])).unwrap();
        big_jwks["padding"] = json!("p".repeat(300_000));
        let http = Arc::new(
            FakeTransport::new()
                .json(WELL_KNOWN, 200, &doc(KEYS_ONE, None))
                .json(KEYS_ONE, 200, &big_jwks.to_string()),
        );
        let issuer_b = issuer(OidcDiscoveryConfig::default(), &[]);

        let (changed, events) = captured(run(&issuer_b, &http, JwksFetchBudget::RequestPath)).await;

        assert!(!changed);
        assert!(
            issuer_b.keys.read().unwrap().is_empty(),
            "an oversized JWKS installs nothing"
        );
        assert!(
            events.recorded().join("\n").contains("ceiling"),
            "{:?}",
            events.recorded()
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    const ISSUER: &str = "https://idp.example/realms/a";
    const WELL_KNOWN: &str = "/.well-known/openid-configuration";
    const KEYS_ONE: &str = "/keys-one";
    const KEYS_TWO: &str = "/keys-two";

    fn issuer_config(source: OidcDiscoveryConfig) -> TrustedIssuerConfig {
        TrustedIssuerConfig {
            issuer: ISSUER.to_owned(),
            audiences: vec!["api".to_owned()],
            skip_audience_validation: false,
            algorithms: Vec::new(),
            decoding_key: DecodingKeySource::OidcDiscovery(source),
            leeway_seconds: 0,
            dpop: DpopConfig::default(),
        }
    }

    fn issuer(source: OidcDiscoveryConfig, configured: &[Algorithm]) -> TrustedIssuer {
        TrustedIssuerConfig {
            algorithms: configured.to_vec(),
            ..issuer_config(source)
        }
        .into_trusted_issuer(KeyStore::empty())
    }

    /// One refresh with the issuer's own settings, reporting whether it
    /// changed anything and panicking on a fatal error.
    async fn run(
        issuer: &TrustedIssuer,
        http: &Arc<FakeTransport>,
        budget: JwksFetchBudget,
    ) -> bool {
        let DecodingKeySource::OidcDiscovery(source) = &issuer.source else {
            panic!("a discovered issuer")
        };
        refresh(
            issuer,
            source,
            &granting(Arc::clone(http)),
            budget,
            "test-plugin",
        )
        .await
        .expect("no fatal error")
    }

    /// Make the held document look older than any TTL.
    fn age_document(issuer: &TrustedIssuer) {
        let mut state = issuer.refresh.discovery();
        state.discovered_at = Instant::now().checked_sub(Duration::from_secs(3_600));
        issuer.refresh.set_discovery(state);
    }

    fn holds(issuer: &TrustedIssuer, kid: &str) -> bool {
        issuer.keys.read().unwrap().select(Some(kid)).is_some()
    }

    fn algorithms(issuer: &TrustedIssuer) -> Option<Vec<Algorithm>> {
        issuer
            .keys
            .read()
            .unwrap()
            .algorithms()
            .map(<[Algorithm]>::to_vec)
    }

    fn doc(jwks_path: &str, algorithms: Option<&[&str]>) -> String {
        let mut document = json!({
            "issuer": ISSUER,
            "jwks_uri": format!("https://keys.example{jwks_path}"),
            "token_endpoint": format!("{ISSUER}/token"),
        });
        if let Some(algorithms) = algorithms {
            document["id_token_signing_alg_values_supported"] = json!(algorithms);
        }
        document.to_string()
    }

    fn jwks(keys: &[Value]) -> String {
        json!({ "keys": keys }).to_string()
    }

    /// A well-formed RSA public key under `kid`. These tests never verify a
    /// signature, so one modulus serves every key.
    fn rsa(kid: &str) -> Value {
        json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        })
    }

    fn oct(kid: &str) -> Value {
        json!({ "kty": "oct", "kid": kid, "k": "c2hhcmVkLXNlY3JldA", "alg": "HS256" })
    }

    fn etag(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("etag", value.parse().unwrap());
        headers
    }

    fn if_none_match(req: &praxis_policy_core::http::HttpRequest) -> Option<String> {
        req.headers
            .get("if-none-match")
            .map(|v| v.to_str().unwrap().to_owned())
    }

    /// Events one test emitted, captured on its own thread.
    #[derive(Clone, Default)]
    struct Events(Arc<std::sync::Mutex<Vec<String>>>);

    impl Events {
        fn recorded(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }

        fn matching(&self, needle: &str) -> Vec<String> {
            self.recorded()
                .into_iter()
                .filter(|e| e.contains(needle))
                .collect()
        }
    }

    thread_local! {
        static SINK: std::cell::RefCell<Option<Events>> = const { std::cell::RefCell::new(None) };
    }

    /// Always interested, so a callsite cached by a parallel test cannot be
    /// disabled under this one; the thread-local sink keeps tests apart.
    struct Capture;

    struct Render(String);

    impl tracing::field::Visit for Render {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }

    impl tracing::Subscriber for Capture {
        fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            SINK.with_borrow(|sink| {
                if let Some(events) = sink {
                    let mut render = Render(format!("[{}]", event.metadata().level()));
                    event.record(&mut render);
                    events.0.lock().unwrap().push(render.0);
                }
            });
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Run `body` on this thread, capturing what it logs.
    async fn captured<T>(body: impl std::future::Future<Output = T>) -> (T, Events) {
        static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INSTALLED.get_or_init(|| {
            tracing::subscriber::set_global_default(Capture)
                .expect("no other subscriber is installed in this test binary");
        });
        let events = Events::default();
        SINK.with_borrow_mut(|sink| *sink = Some(events.clone()));
        let out = body.await;
        SINK.with_borrow_mut(|sink| *sink = None);
        (out, events)
    }
}
