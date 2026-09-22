// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The hash indexed file backend: what it accepts, what it refuses, and what
//! a reload does to the running index.

use crate::support::{RecordFile, denial_code, file_config, hash, resolve_with_header, resolver};

use praxis_policy_plugin_identity_api_key::{
    DirectoryError, FileDirectory, FileDirectoryConfig, KeyDirectory as _, PresentedKey,
};

/// The file backend reads no host services, so an empty carrier is honest
/// about what it needs: nothing here should make a deployment declare
/// `perform_http`.
fn no_services() -> praxis_policy_core::host::InitExtensions {
    praxis_policy_core::host::InitExtensions::new()
}

fn config_for(path: &str) -> FileDirectoryConfig {
    serde_yaml::from_str(&format!("path: {path}")).expect("the backend config parses")
}

#[tokio::test]
async fn a_known_credential_resolves_and_an_unknown_one_denies() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n    groups: [reader]\n",
        hash("sk-oai-secret")
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let known = resolve_with_header(&resolver, "sk-oai-secret").await;
    assert!(
        denial_code(&known).is_none(),
        "a credential in the file must resolve"
    );

    let unknown = resolve_with_header(&resolver, "sk-oai-nope").await;
    assert_eq!(denial_code(&unknown).as_deref(), Some("auth.key_unknown"));
}

/// The file holds digests. A file that leaks must not hand over credentials,
/// so a record carrying the key itself has to be refused rather than hashed
/// on the operator's behalf.
#[test]
fn a_record_whose_hash_is_not_a_digest_fails_at_load() {
    let file = RecordFile::write("keys:\n  - hash: \"sk-oai-secret\"\n    user: alice\n");

    let error =
        resolver(file_config(file.path(), None)).expect_err("a plaintext key must not load");

    assert!(
        error.contains("no `<algorithm>:` prefix"),
        "the error must name the problem: {error}"
    );
}

#[test]
fn a_digest_of_the_wrong_length_fails_at_load() {
    let file = RecordFile::write("keys:\n  - hash: \"sha256:abcd\"\n    user: alice\n");

    let error = resolver(file_config(file.path(), None)).expect_err("a short digest must not load");

    assert!(
        error.contains("64 hex characters"),
        "the error must say what is wrong: {error}"
    );
}

/// Two records for one credential have no coherent answer, and picking either
/// silently would hand one caller the other's identity.
#[test]
fn two_records_sharing_a_hash_fail_at_load() {
    let digest = hash("sk-oai-secret");
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{digest}\"\n    user: alice\n  - hash: \"{digest}\"\n    user: bob\n"
    ));

    let error = resolver(file_config(file.path(), None)).expect_err("a duplicate must not load");

    assert!(
        error.contains("same hash"),
        "the error must name the duplicate: {error}"
    );
}

/// An authored digest in upper case matches a credential hashed at runtime.
#[tokio::test]
async fn an_uppercase_digest_matches() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret").to_uppercase()
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    assert!(
        denial_code(&result).is_none(),
        "digest comparison must not be case sensitive"
    );
}

/// A reload that fails leaves the running records serving. Emptying the index
/// on a transient read error turns a blip into an authentication outage.
#[tokio::test]
async fn a_failed_reload_keeps_the_previous_records() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let directory = FileDirectory::new(config_for(file.path())).expect("the file loads");
    assert_eq!(directory.len(), 1);

    file.rewrite("keys: [ this is not a record list");
    let error = directory
        .reload()
        .expect_err("a malformed file must fail the reload");

    assert!(
        error.contains("parsing"),
        "the error must name the parse: {error}"
    );
    assert_eq!(
        directory.len(),
        1,
        "the previous index must still be serving"
    );
    let found = directory
        .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
        .await
        .expect("a lookup against the kept index still answers");
    assert!(
        found.is_some(),
        "the credential loaded before the failed reload still resolves"
    );
}

/// A successful reload publishes the new set, which is what makes the refresh
/// interval the revocation window.
#[tokio::test]
async fn a_successful_reload_replaces_the_records() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let directory = FileDirectory::new(config_for(file.path())).expect("the file loads");

    file.rewrite("keys: []\n");
    directory.reload().expect("an empty record list is valid");

    assert!(directory.is_empty(), "the revoked record must be gone");
    let found = directory
        .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
        .await
        .expect("the lookup answers");
    assert!(found.is_none(), "a revoked credential must stop resolving");
}

/// The revocation window in action. Reloading is driven by a lookup finding
/// the set due, not by a timer, because a spawned ticker binds to whichever
/// runtime called `initialize` and a host that drives async init on a
/// short-lived runtime has it cancelled before it ticks once.
#[tokio::test]
async fn a_lookup_past_the_interval_reloads_and_a_revoked_record_stops_resolving() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    // Zero seconds: every lookup finds the set due, which is the reload path
    // under test without a sleep in it.
    let directory = FileDirectory::new(
        serde_yaml::from_str(&format!("path: {}\nrefresh_secs: 0", file.path()))
            .expect("the backend config parses"),
    )
    .expect("the file loads");

    assert!(
        directory
            .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
            .await
            .expect("the lookup answers")
            .is_some(),
        "the credential resolves before it is revoked"
    );

    file.rewrite("keys: []\n");

    assert!(
        directory
            .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
            .await
            .expect("the lookup answers")
            .is_none(),
        "a lookup past the interval must pick up the revocation without a restart"
    );
}

/// With no interval the set is read once. An operator who configured no window
/// gets none, rather than one that happens to be however often requests arrive.
#[tokio::test]
async fn without_an_interval_a_lookup_does_not_reload() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let directory = FileDirectory::new(config_for(file.path())).expect("the file loads");

    file.rewrite("keys: []\n");

    assert!(
        directory
            .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
            .await
            .expect("the lookup answers")
            .is_some(),
        "with no refresh configured the startup records keep serving"
    );
}

/// Serving stale records is right for a blip and wrong forever. Past the
/// ceiling the backend says it cannot answer, so requests deny as a directory
/// failure rather than as unknown credentials.
#[tokio::test]
async fn past_the_staleness_ceiling_a_lookup_reports_a_directory_failure() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let directory = FileDirectory::new(
        serde_yaml::from_str(&format!(
            "path: {}\nrefresh_secs: 0\nmax_staleness_secs: 0",
            file.path()
        ))
        .expect("the backend config parses"),
    )
    .expect("the file loads");

    // The reload this lookup triggers fails, so the records stay as loaded and
    // keep ageing past a ceiling of zero. Long enough only to put the clock
    // past that ceiling: the check is `staleness > 0s`, so a sub-millisecond
    // test would be reading its own timing.
    file.rewrite("keys: [ not a record list");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let error = directory
        .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
        .await
        .expect_err("past the ceiling the backend must not answer");

    assert!(
        matches!(error, DirectoryError::Unavailable(_)),
        "staleness is an availability failure, not a malformed answer: {error:?}"
    );
}

/// A ceiling below the interval would deny before the first reload was due.
#[test]
fn a_ceiling_below_the_interval_fails_at_config_load() {
    let file = RecordFile::write("keys: []\n");
    let mut config = file_config(file.path(), None);
    config["directory"]["refresh_secs"] = serde_json::json!(60);
    config["directory"]["max_staleness_secs"] = serde_json::json!(30);

    let error = resolver(config).expect_err("an incoherent pair must not build");

    assert!(
        error.contains("below `refresh_secs`"),
        "the error must name the pair: {error}"
    );
}

/// A ceiling with nothing reloading would deny every request once it passed.
#[test]
fn a_ceiling_without_an_interval_fails_at_config_load() {
    let file = RecordFile::write("keys: []\n");
    let mut config = file_config(file.path(), None);
    config["directory"]["max_staleness_secs"] = serde_json::json!(30);

    let error = resolver(config).expect_err("a ceiling with no interval must not build");

    assert!(
        error.contains("needs `refresh_secs`"),
        "the error must say what is missing: {error}"
    );
}

/// Readers see one index or the next, never a half-built one.
///
/// The index is published by swapping a whole `Arc`, so this is an invariant of
/// the design rather than of the timing. Exercised under real parallelism
/// anyway, because "no reader can observe a partial map" is the kind of claim
/// that is easy to argue from the code and easy to break in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readers_never_observe_a_partial_index_during_a_reload() {
    // `stable` is in every version of the file, so a lookup that ever misses it
    // saw a state neither version contained. `churned` is added and removed to
    // keep each reload doing real work.
    let stable = hash("sk-oai-stable");
    let churned = hash("sk-oai-churned");
    let with_both = format!(
        "keys:\n  - hash: \"{stable}\"\n    user: alice\n  - hash: \"{churned}\"\n    user: bob\n"
    );
    let stable_only = format!("keys:\n  - hash: \"{stable}\"\n    user: alice\n");

    let file = std::sync::Arc::new(RecordFile::write(&with_both));
    let directory =
        std::sync::Arc::new(FileDirectory::new(config_for(file.path())).expect("the file loads"));

    let writer = {
        let file = std::sync::Arc::clone(&file);
        let directory = std::sync::Arc::clone(&directory);
        tokio::spawn(async move {
            for round in 0..200 {
                let contents = if round % 2 == 0 {
                    &stable_only
                } else {
                    &with_both
                };
                file.rewrite(contents);
                directory.reload().expect("both versions are valid records");
                tokio::task::yield_now().await;
            }
        })
    };

    let readers: Vec<_> = std::iter::repeat_with(|| {
        let directory = std::sync::Arc::clone(&directory);
        tokio::spawn(async move {
            for _ in 0..500 {
                let found = directory
                    .lookup(&PresentedKey::new(&b"sk-oai-stable"[..]), &no_services())
                    .await
                    .expect("the lookup answers");
                assert!(
                    found.is_some(),
                    "a record present in every version must never be missed"
                );

                let absent = directory
                    .lookup(
                        &PresentedKey::new(&b"sk-oai-never-issued"[..]),
                        &no_services(),
                    )
                    .await
                    .expect("the lookup answers");
                assert!(
                    absent.is_none(),
                    "a record in no version must never be found"
                );
                tokio::task::yield_now().await;
            }
        })
    })
    .take(4)
    .collect();

    writer.await.expect("the writer finishes");
    for reader in readers {
        reader.await.expect("the readers finish");
    }
}

/// The backend's own storage fields are not subject attributes. `hash` in
/// particular is what a hash indexed directory matches on, and
/// `subject.claim.<name>` is a legal assertion source, so a record leaving it
/// in the bag would let an operator render a credential equivalent upstream.
#[tokio::test]
async fn the_hash_and_expiry_never_reach_the_record_fields() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    expires_at: 2099-01-01T00:00:00Z\n    user: alice\n    tenant: acme\n",
        hash("sk-oai-secret")
    ));
    let directory = FileDirectory::new(config_for(file.path())).expect("the file loads");

    let record = directory
        .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
        .await
        .expect("the lookup answers")
        .expect("the credential is known");

    assert!(
        !record.fields.contains_key("hash"),
        "the digest must not be projectable"
    );
    assert!(
        !record.fields.contains_key("expires_at"),
        "expiry is lifecycle, not an attribute"
    );
    assert!(
        record.fields.contains_key("tenant"),
        "an authored attribute must survive"
    );
}

/// The index names one algorithm, so a digest computed with another cannot be
/// matched and is a config fault rather than a credential that never resolves.
#[test]
fn a_digest_from_another_algorithm_fails_at_load() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"sha512:{}\"\n    user: alice\n",
        "a".repeat(64)
    ));

    let error =
        resolver(file_config(file.path(), None)).expect_err("a sha512 digest must not load");

    assert!(
        error.contains("where the index is 'sha256'"),
        "the error must name both algorithms: {error}"
    );
}

/// Before the interval elapses the file is not re-read, so the revocation
/// window is the interval rather than however often requests arrive.
#[tokio::test]
async fn a_lookup_inside_the_interval_does_not_reload() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let directory = FileDirectory::new(
        serde_yaml::from_str(&format!("path: {}\nrefresh_secs: 3600", file.path()))
            .expect("the backend config parses"),
    )
    .expect("the file loads");

    file.rewrite("keys: []\n");

    assert!(
        directory
            .lookup(&PresentedKey::new(&b"sk-oai-secret"[..]), &no_services())
            .await
            .expect("the lookup answers")
            .is_some(),
        "inside the interval the startup records keep serving"
    );
}

#[test]
fn the_backend_names_itself() {
    let file = RecordFile::write("keys: []\n");
    let directory = FileDirectory::new(config_for(file.path())).expect("the file loads");

    assert_eq!(directory.kind(), "file");
}
