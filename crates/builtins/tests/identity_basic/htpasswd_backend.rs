// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The `.htpasswd` backend: parsing, the index, the refresh window, the
//! staleness ceiling, and the properties that keep a miss from being cheaper
//! than a hit.

use praxis_policy_builtins::plugins::identity_basic::directory::CredentialDirectory as _;
use praxis_policy_builtins::plugins::identity_basic::{HtpasswdConfig, HtpasswdDirectory};

use crate::support::{HtpasswdFile, bcrypt_line, config_for, services};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// An argon2 record, for the uniformity cases.
const ARGON2_RECORD: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
                             MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn a_known_user_authenticates_and_a_wrong_password_does_not() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    let record = dir.lookup("alice", &svc).await.expect("the lookup answers");
    let record = record.expect("alice is in the file");
    assert!(
        dir.verify(
            Some(&record),
            &crate::support::password("correct horse"),
            &svc
        )
        .await
        .expect("the verify answers"),
        "the right password must authenticate"
    );
    assert!(
        !dir.verify(
            Some(&record),
            &crate::support::password("wrong horse"),
            &svc
        )
        .await
        .expect("the verify answers"),
        "a wrong password must not authenticate"
    );
}

#[tokio::test]
async fn an_unknown_user_runs_a_dummy_verification() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    assert_eq!(
        dir.dummy_runs(),
        0,
        "no dummy has run before the first lookup"
    );
    let missing = dir
        .lookup("nobody", &svc)
        .await
        .expect("the lookup answers");
    assert!(missing.is_none(), "there is no such user");
    let verdict = dir
        .verify(None, &crate::support::password("anything"), &svc)
        .await
        .expect("the verify answers");
    assert!(!verdict, "a miss never authenticates");
    assert_eq!(
        dir.dummy_runs(),
        1,
        "the miss path must do the work a hit does"
    );
}

#[test]
fn a_duplicate_user_id_fails_at_load() {
    let file = HtpasswdFile::write(&format!(
        "{}\n{}\n",
        bcrypt_line("alice", "one", 4),
        bcrypt_line("alice", "two", 4),
    ));
    let err = directory(&file).expect_err("a duplicate user-id must fail the load");
    assert!(
        err.contains("same user-id"),
        "the error should name the collision: {err}"
    );
}

#[test]
fn two_encodings_of_one_user_id_are_caught_as_duplicates() {
    let file = HtpasswdFile::write(&format!(
        "{}\n{}\n",
        bcrypt_line("José", "one", 4),
        bcrypt_line("Jose\u{0301}", "two", 4),
    ));
    let err = directory(&file).expect_err("normalised duplicates must fail the load");
    assert!(
        err.contains("normalisation"),
        "the error should say why: {err}"
    );
}

#[tokio::test]
async fn a_non_nfc_stored_user_id_is_reachable_by_either_encoding() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("Jose\u{0301}", "pw", 4)));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    for spelling in ["José", "Jose\u{0301}"] {
        let normalised: String = {
            use unicode_normalization::UnicodeNormalization as _;
            spelling.nfc().collect()
        };
        assert!(
            dir.lookup(&normalised, &svc)
                .await
                .expect("the lookup answers")
                .is_some(),
            "{spelling:?} must reach the stored record"
        );
    }
}

#[test]
fn comments_blank_lines_and_trailing_whitespace_parse() {
    let file = HtpasswdFile::write(&format!(
        "# a comment\n\n   \n{}   \n# trailing comment\n",
        bcrypt_line("alice", "pw", 4),
    ));
    let dir = directory(&file).expect("the format's own noise must parse");
    assert_eq!(
        dir.len(),
        1,
        "comments and blank lines must not become records"
    );
}

#[test]
fn a_malformed_line_and_an_unreadable_path_both_fail_at_construction() {
    let no_separator = HtpasswdFile::write("alicenohash\n");
    let err = directory(&no_separator).expect_err("a line with no separator must fail");
    assert!(err.contains("separator"), "{err}");

    let empty_half = HtpasswdFile::write("alice:\n");
    let err = directory(&empty_half).expect_err("an empty hash must fail");
    assert!(err.contains("empty"), "{err}");

    let gone = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    gone.unlink();
    let err = directory(&gone).expect_err("an unreadable path must fail");
    assert!(err.contains("reading"), "{err}");
}

#[test]
fn a_refused_scheme_fails_at_load_naming_the_line() {
    let file = HtpasswdFile::write(&format!(
        "{}\nlegacy:$apr1$abcdefgh$1234567890123456789012\n",
        bcrypt_line("alice", "pw", 4),
    ));
    let err = directory(&file).expect_err("an MD5-grade record must fail the load");
    assert!(
        err.contains("line 2"),
        "the error should name the line: {err}"
    );
    assert!(
        err.contains("re-hash"),
        "the error should name the fix: {err}"
    );
}

#[test]
fn a_cost_above_the_ceiling_fails_at_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 12)));
    let mut config = config_for(file.path());
    config.limits.max_bcrypt_cost = 10;
    let err = HtpasswdDirectory::new(config).expect_err("an over-ceiling cost must fail the load");
    assert!(err.contains("ceiling"), "{err}");
}

#[test]
fn a_config_omitting_the_staleness_ceiling_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let yaml = format!("path: {}\nrefresh_secs: 30\n", file.path());
    let err = serde_yaml::from_str::<HtpasswdConfig>(&yaml)
        .expect_err("a config with no `max_staleness_secs` must not deserialize");
    assert!(
        err.to_string().contains("max_staleness_secs"),
        "the error should name the missing field: {err}"
    );
}

#[test]
fn a_ceiling_below_the_refresh_interval_fails_validation() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    config.refresh_secs = 60;
    config.max_staleness_secs = 30;
    let err = HtpasswdDirectory::new(config).expect_err("an incoherent ceiling must fail");
    assert!(err.contains("below"), "{err}");
}

#[tokio::test]
async fn a_revoked_user_stops_authenticating_after_a_reload() {
    let file = HtpasswdFile::write(&format!(
        "{}\n{}\n",
        bcrypt_line("alice", "pw", 4),
        bcrypt_line("bob", "pw", 4),
    ));
    let dir = directory(&file).expect("the file loads");
    let svc = services();
    assert!(
        dir.lookup("bob", &svc).await.expect("answers").is_some(),
        "bob is in the file before the revocation"
    );

    file.rewrite(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    dir.reload().expect("the rewritten file loads");

    assert!(
        dir.lookup("bob", &svc).await.expect("answers").is_none(),
        "a record removed from the file must stop authenticating once reloaded"
    );
    assert!(
        dir.lookup("alice", &svc).await.expect("answers").is_some(),
        "and a record left in the file keeps authenticating"
    );
}

#[tokio::test]
async fn a_failed_reload_keeps_the_previous_index_serving() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    file.rewrite("this is not a htpasswd file at all\n");
    let err = dir.reload().expect_err("a malformed file fails the reload");
    assert!(err.contains("separator"), "{err}");

    assert!(
        dir.lookup("alice", &svc).await.expect("answers").is_some(),
        "the previous index must still serve after a failed reload"
    );
}

#[tokio::test]
async fn past_the_staleness_ceiling_lookups_report_unavailable_not_unknown() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    config.refresh_secs = 0;
    config.max_staleness_secs = 0;
    let dir = HtpasswdDirectory::new(config).expect("the file loads");
    let svc = services();

    file.unlink();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let outcome = dir.lookup("alice", &svc).await;
    assert!(
        matches!(
            outcome,
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Stale)
        ),
        "past the ceiling a lookup must fail closed as unavailable, got {outcome:?}"
    );
}

#[tokio::test]
async fn concurrent_verifications_beyond_the_cap_deny_rather_than_queue() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 10)));
    let mut config = config_for(file.path());
    config.max_concurrent_verifications = 1;
    let dir = std::sync::Arc::new(HtpasswdDirectory::new(config).expect("the file loads"));
    let svc = services();
    let record = dir
        .lookup("alice", &svc)
        .await
        .expect("answers")
        .expect("alice exists");

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8_u32 {
        let dir = std::sync::Arc::clone(&dir);
        let encoded = record.verifier.clone();
        set.spawn(async move {
            let svc = services();
            let rec =
                praxis_policy_builtins::plugins::identity_basic::UserRecord::verifier_only(encoded);
            dir.verify(Some(&rec), &crate::support::password("pw"), &svc)
                .await
        });
    }

    let mut saturated = 0_u32;
    while let Some(joined) = set.join_next().await {
        if matches!(
            joined.expect("the task completes"),
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Saturated)
        ) {
            saturated = saturated.saturating_add(1);
        }
    }
    assert!(
        saturated > 0,
        "a cap of 1 under 8 concurrent verifies must refuse at least one"
    );
}

#[tokio::test]
async fn a_burst_of_lookups_triggers_one_file_read() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    config.refresh_secs = 1;
    config.max_staleness_secs = 3600;
    let dir = std::sync::Arc::new(HtpasswdDirectory::new(config).expect("the file loads"));

    assert_eq!(
        dir.reload_attempts(),
        0,
        "no read happens before the first due time"
    );

    file.rewrite(&format!(
        "{}\n{}\n",
        bcrypt_line("alice", "pw", 4),
        bcrypt_line("bob", "pw", 4),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..16_u32 {
        let dir = std::sync::Arc::clone(&dir);
        set.spawn(async move {
            let svc = services();
            dir.lookup("alice", &svc).await.map(|found| found.is_some())
        });
    }
    while let Some(joined) = set.join_next().await {
        assert!(
            joined.expect("the task completes").expect("answers"),
            "every lookup in the burst must see the record"
        );
    }

    assert_eq!(
        dir.reload_attempts(),
        1,
        "16 concurrent lookups past the due time must cost exactly one file read"
    );
    assert_eq!(
        dir.len(),
        2,
        "and that one read must have picked up the rewritten file"
    );
}

#[tokio::test]
async fn the_stored_hash_never_reaches_the_projected_fields() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    let record = dir
        .lookup("alice", &svc)
        .await
        .expect("answers")
        .expect("alice exists");
    assert!(
        record.fields.is_empty(),
        "a .htpasswd record has nothing to project, and must not project its hash: {:?}",
        record.fields.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn lookup_cost_does_not_grow_with_the_record_count() {
    let mut lines = String::new();
    for n in 0..500_u32 {
        lines.push_str(&bcrypt_line(&format!("user{n}"), "pw", 4));
        lines.push('\n');
    }
    let file = HtpasswdFile::write(&lines);
    let dir = directory(&file).expect("a large file loads");
    let svc = services();

    assert_eq!(dir.len(), 500, "every record in a large file is indexed");
    assert!(
        dir.lookup("user0", &svc).await.expect("answers").is_some(),
        "the first record is reachable"
    );
    assert!(
        dir.lookup("user499", &svc)
            .await
            .expect("answers")
            .is_some(),
        "so is the last, without a scan"
    );
    assert!(
        dir.lookup("nobody", &svc).await.expect("answers").is_none(),
        "and a miss in a large file is still a miss"
    );
}

#[test]
fn loading_an_argon2_record_does_not_mint_an_expensive_dummy() {
    let phc = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
               MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";
    let file = HtpasswdFile::write(&format!("alice:{phc}\n"));

    let start = std::time::Instant::now();
    let dir = directory(&file).expect("an argon2 file loads");
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "loading one argon2 record took {elapsed:?}; the miss-path hash must be \
         reused from the file rather than minted from a scaled cost"
    );
    assert_eq!(dir.len(), 1, "the record is indexed");
}

#[test]
fn reloading_a_populated_directory_does_no_hashing_work() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 5)));
    let dir = directory(&file).expect("the file loads");

    let start = std::time::Instant::now();
    for _ in 0..20_u32 {
        dir.reload().expect("the reload succeeds");
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "20 reloads took {elapsed:?}; a reload must reuse a record from the file \
         as its miss-path hash rather than minting one, because reload runs on \
         the request path where a bcrypt mint would block an executor worker"
    );
    assert_eq!(
        dir.len(),
        1,
        "the record is still indexed after the reloads"
    );
}

#[test]
fn a_concurrency_cap_above_the_semaphore_maximum_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    config.max_concurrent_verifications = usize::MAX;

    let err = HtpasswdDirectory::new(config)
        .expect_err("a cap above the semaphore maximum must fail the load");
    assert!(
        err.contains("max_concurrent_verifications"),
        "the error should name the field, got: {err}"
    );
    assert!(
        !err.is_empty(),
        "and it must be an error rather than a panic"
    );
}

#[test]
fn a_file_whose_records_cost_different_amounts_fails_at_load() {
    for (label, body) in [
        (
            "two bcrypt costs",
            format!(
                "{}\n{}\n",
                bcrypt_line("cheap", "pw", 4),
                bcrypt_line("dear", "pw", 12)
            ),
        ),
        (
            "bcrypt and argon2",
            format!("{}\nmixed:{ARGON2_RECORD}\n", bcrypt_line("a", "pw", 10)),
        ),
        (
            "two argon2 tunings",
            format!(
                "a:{ARGON2_RECORD}\nb:{}\n",
                ARGON2_RECORD.replace("m=19456", "m=8192")
            ),
        ),
    ] {
        let file = HtpasswdFile::write(&body);
        let err =
            directory(&file).expect_err("a file with non-uniform verification cost must not load");
        assert!(
            err.contains("One cost profile per file"),
            "{label}: differing cost within a directory is a user-enumeration \
             oracle whichever record serves the miss path, because the hits \
             differ from each other -- a wrong password for a cost-4 record \
             returns in 0.7ms against 160ms for a cost-12 miss. The error must \
             name the constraint, got: {err}"
        );
        assert!(
            err.contains("Re-hash"),
            "{label}: and name the fix, got: {err}"
        );
    }
}

#[test]
fn a_uniform_file_loads_under_either_scheme() {
    let bcrypt = HtpasswdFile::write(&format!(
        "{}\n{}\n",
        bcrypt_line("a", "pw", 6),
        bcrypt_line("b", "other", 6),
    ));
    let dir = directory(&bcrypt).expect("a uniform bcrypt file loads");
    assert_eq!(dir.len(), 2, "both bcrypt records are indexed");

    let argon2 = HtpasswdFile::write(&format!("a:{ARGON2_RECORD}\nb:{ARGON2_RECORD}\n"));
    let dir = directory(&argon2).expect("a uniform argon2 file loads");
    assert_eq!(
        dir.len(),
        2,
        "both argon2 records are indexed: the rule is uniformity, not \
         bcrypt-only, so a single-tuning argon2 directory is supported"
    );
}

#[tokio::test]
async fn a_miss_runs_the_same_cost_profile_as_every_hit() {
    let file = HtpasswdFile::write(&format!(
        "{}\n{}\n",
        bcrypt_line("alice", "pw", 6),
        bcrypt_line("bob", "pw", 6),
    ));
    let dir = directory(&file).expect("the file loads");

    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&bcrypt_line("alice", "pw", 6)),
        "the miss path must share the directory's single cost profile: with \
         uniformity enforced there is exactly one cost present, so a miss \
         necessarily costs what any hit costs"
    );
}

#[tokio::test]
async fn a_reload_onto_a_new_uniform_cost_is_accepted_and_tracked() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 5)));
    let dir = directory(&file).expect("the file loads");
    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&bcrypt_line("alice", "pw", 5)),
        "the miss path starts at the file's cost"
    );

    file.rewrite(&format!("{}\n", bcrypt_line("alice", "pw", 7)));
    dir.reload().expect("a uniformly re-hashed file reloads");

    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&bcrypt_line("alice", "pw", 7)),
        "and tracks the new cost after the re-hash: re-hashing a whole file \
         onto a new cost is legitimate, so the miss path must follow it rather \
         than keep the old one"
    );
}

#[test]
fn an_argon2_record_argon2_cannot_verify_fails_at_load() {
    for (label, record) in [
        ("zero parallelism", ARGON2_RECORD.replace("p=1", "p=0")),
        ("zero passes", ARGON2_RECORD.replace("t=2", "t=0")),
        (
            "unknown variant",
            ARGON2_RECORD.replace("argon2id", "argon2x"),
        ),
        (
            "memory below the parallelism floor",
            ARGON2_RECORD.replace("m=19456", "m=1"),
        ),
    ] {
        let file = HtpasswdFile::write(&format!("alice:{record}\n"));
        let err = match directory(&file) {
            Ok(_) => panic!("{label}: this record must not load"),
            Err(e) => e,
        };
        assert!(
            err.contains("line 1"),
            "{label}: PHC parsing is not admission -- this record parses but \
             fails before the KDF, so without a load-time check that user-id \
             would be measurably faster to probe than an unknown one. The \
             error must name the line, got: {err}"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a directory over a fixture file, with the default ceilings.
fn directory(file: &HtpasswdFile) -> Result<HtpasswdDirectory, String> {
    HtpasswdDirectory::new(config_for(file.path()))
}
