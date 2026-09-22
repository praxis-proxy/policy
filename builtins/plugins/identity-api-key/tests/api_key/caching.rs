// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Reusing a directory's answers, and the things that must not be reused.

use std::sync::Arc;

use praxis_policy_core::host::InitExtensions;
use praxis_policy_core::http_testing::{FakeTransport, granting};
use praxis_policy_plugin_identity_api_key::{
    CacheConfig, CachingDirectory, DirectoryError, HttpDirectory, HttpDirectoryConfig,
    KeyDirectory as _, PresentedKey,
};

const URL: &str = "https://maas-api.example/internal/v1/api-keys/validate";
const KEY: &[u8] = b"sk-oai-abc123_secret";
const OTHER: &[u8] = b"sk-oai-zzz999_other";

const VALID: &str = r#"{"valid": true, "username": "alice", "groups": ["reader"], "tenant": "t"}"#;
const MISS: &str = r#"{"valid": false, "reason": "key not found", "tenant": ""}"#;

fn backend() -> Arc<HttpDirectory> {
    let config: HttpDirectoryConfig =
        serde_yaml::from_str(&format!("url: {URL}")).expect("the backend config parses");
    Arc::new(HttpDirectory::new(config).expect("the config builds"))
}

fn cached(block: &str) -> CachingDirectory {
    let config: CacheConfig = serde_yaml::from_str(block).expect("the cache config parses");
    CachingDirectory::new(backend(), config).expect("the cache builds")
}

fn serving(status: u16, body: &str) -> (InitExtensions, Arc<FakeTransport>) {
    let transport = Arc::new(FakeTransport::new().json("api-keys/validate", status, body));
    (granting(Arc::clone(&transport)), transport)
}

#[tokio::test]
async fn a_second_lookup_of_the_same_credential_costs_no_request() {
    let (services, transport) = serving(200, VALID);
    let directory = cached("ttl_secs: 60");

    for _ in 0..5 {
        let record = directory
            .lookup(&PresentedKey::new(KEY), &services)
            .await
            .expect("the directory answers");
        assert!(record.is_some(), "every lookup resolves");
    }

    assert_eq!(transport.call_count(), 1, "one request served five lookups");
}

/// The whole point of a negative entry: a caller working through guesses must
/// not turn into one directory request per guess.
#[tokio::test]
async fn a_repeated_unknown_credential_costs_one_request() {
    let (services, transport) = serving(200, MISS);
    let directory = cached("ttl_secs: 60\nnegative_ttl_secs: 30");

    for _ in 0..5 {
        let outcome = directory
            .lookup(&PresentedKey::new(KEY), &services)
            .await
            .expect("the directory answers");
        assert!(outcome.is_none(), "an unknown credential stays unknown");
    }

    assert_eq!(transport.call_count(), 1, "one request served five guesses");
}

/// Negative caching off means every miss reaches the directory, which is a
/// choice an operator can make and should get if they made it.
#[tokio::test]
async fn without_a_negative_ttl_every_miss_reaches_the_directory() {
    let (services, transport) = serving(200, MISS);
    let directory = cached("ttl_secs: 60");

    for _ in 0..3 {
        let _ = directory.lookup(&PresentedKey::new(KEY), &services).await;
    }

    assert_eq!(transport.call_count(), 3);
}

/// A failure is asked again. Caching it would turn a blip into an outage
/// lasting the TTL, at exactly the moment someone is recovering the directory.
#[tokio::test]
async fn a_directory_failure_is_never_cached() {
    let (services, transport) = serving(500, r#"{"error": "down"}"#);
    let directory = cached("ttl_secs: 60\nnegative_ttl_secs: 30");

    for _ in 0..3 {
        let error = directory
            .lookup(&PresentedKey::new(KEY), &services)
            .await
            .expect_err("the directory is down");
        assert!(matches!(error, DirectoryError::Unavailable(_)));
    }

    assert_eq!(
        transport.call_count(),
        3,
        "each attempt must reach the directory"
    );
}

/// An entry expires. With a zero TTL rejected at config load, the smallest
/// window this can test with is one second.
#[tokio::test]
async fn an_entry_stops_being_reused_once_it_expires() {
    let (services, transport) = serving(200, VALID);
    let directory = cached("ttl_secs: 1");

    let _ = directory.lookup(&PresentedKey::new(KEY), &services).await;
    let _ = directory.lookup(&PresentedKey::new(KEY), &services).await;
    assert_eq!(
        transport.call_count(),
        1,
        "the second lookup was served from cache"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let _ = directory.lookup(&PresentedKey::new(KEY), &services).await;
    assert_eq!(
        transport.call_count(),
        2,
        "past the TTL the directory is asked again"
    );
}

/// Different credentials are different entries. A cache that collapsed them
/// would hand one caller another's identity.
#[tokio::test]
async fn two_credentials_do_not_share_an_entry() {
    let (services, transport) = serving(200, VALID);
    let directory = cached("ttl_secs: 60");

    let _ = directory.lookup(&PresentedKey::new(KEY), &services).await;
    let _ = directory.lookup(&PresentedKey::new(OTHER), &services).await;

    assert_eq!(
        transport.call_count(),
        2,
        "each credential is asked about once"
    );
    assert_eq!(directory.len(), 2);
}

/// Caching misses without a ceiling turns a guessing flood into memory growth
/// instead of directory load.
#[tokio::test]
async fn misses_are_bounded() {
    let (services, _transport) = serving(200, MISS);
    let directory = cached("ttl_secs: 60\nnegative_ttl_secs: 60\nmax_negative_entries: 4");

    for n in 0..50_u32 {
        let guess = format!("sk-oai-guess{n}_x");
        let _ = directory
            .lookup(&PresentedKey::new(guess.as_bytes()), &services)
            .await;
    }

    assert!(
        directory.negative_len() <= 4,
        "held {} entries against a ceiling of 4",
        directory.negative_len()
    );
}

/// The ceilings are separate, so a flood of guesses cannot displace the
/// credentials that are actually in use.
#[tokio::test]
async fn a_flood_of_guesses_does_not_evict_a_resolved_record() {
    let hit = Arc::new(FakeTransport::new().json("api-keys/validate", 200, VALID));
    let directory = cached("ttl_secs: 60\nnegative_ttl_secs: 60\nmax_negative_entries: 2");

    // One real credential, cached.
    let services = granting(Arc::clone(&hit));
    let _ = directory.lookup(&PresentedKey::new(KEY), &services).await;
    assert_eq!(directory.len(), 1);

    // Then a flood of misses, which land in their own map.
    let (miss_services, _miss) = serving(200, MISS);
    for n in 0..50_u32 {
        let guess = format!("sk-oai-guess{n}_x");
        let _ = directory
            .lookup(&PresentedKey::new(guess.as_bytes()), &miss_services)
            .await;
    }

    assert_eq!(directory.len(), 1, "the resolved record is still held");
    let _ = directory.lookup(&PresentedKey::new(KEY), &services).await;
    assert_eq!(hit.call_count(), 1, "and is still served without a request");
}

#[test]
fn a_zero_ttl_fails_at_config_load() {
    let config: CacheConfig = serde_yaml::from_str("ttl_secs: 0").expect("the block parses");

    let error = CachingDirectory::new(backend(), config).expect_err("a zero TTL must not build");

    assert!(error.contains("caches nothing"), "got: {error}");
}

/// The file backend is already an index. A cache over it adds a second
/// revocation window for one property, so an operator who wrote one believing
/// they configured a single window is told rather than quietly given two.
#[test]
fn a_cache_over_a_file_directory_fails_at_config_load() {
    let file = crate::support::RecordFile::write("keys: []\n");
    let mut config = crate::support::file_config(file.path(), None);
    config["cache"] = serde_json::json!({ "ttl_secs": 60 });

    let error =
        crate::support::resolver(config).expect_err("a cache over a file backend must not build");

    assert!(
        error.contains("two revocation windows"),
        "the error must explain why: {error}"
    );
}

#[test]
fn a_zero_capacity_fails_at_config_load() {
    let config: CacheConfig =
        serde_yaml::from_str("ttl_secs: 60\nmax_entries: 0").expect("the block parses");

    let error =
        CachingDirectory::new(backend(), config).expect_err("a zero capacity must not build");

    assert!(error.contains("caches nothing"), "got: {error}");
}

/// The cache reports the backend it wraps, not itself. A diagnostic naming
/// "cache" would say nothing about which directory could not answer.
#[tokio::test]
async fn the_cache_names_the_backend_it_wraps() {
    let directory = cached("ttl_secs: 60");

    assert_eq!(directory.kind(), "http");
    assert!(
        directory.is_empty(),
        "nothing is held before the first lookup"
    );
}
