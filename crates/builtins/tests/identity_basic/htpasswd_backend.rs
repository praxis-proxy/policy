// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The `.htpasswd` backend: parsing, the index, the refresh window, the
//! staleness ceiling, and the properties that keep a miss from being cheaper
//! than a hit.

use praxis_policy_builtins::plugins::identity_basic::directory::CredentialDirectory as _;
use praxis_policy_builtins::plugins::identity_basic::file_backend::FileBackend;
use praxis_policy_builtins::plugins::identity_basic::verifier::EMPTY_DIRECTORY_COST;
use praxis_policy_builtins::plugins::identity_basic::{
    CostProfile, DirectoryError, HtpasswdConfig, HtpasswdDirectory,
};

use praxis_policy_builtins::plugins::identity_basic::ShaCryptVariant;

use crate::support::{
    HtpasswdFile, ScriptedSource, argon2_line, bcrypt_line, config_for, services, sha_crypt_line,
    sha_crypt_salted,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// An argon2 record, for the uniformity cases.
const ARGON2_RECORD: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
                             MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";

/// How long a held task is watched for, to show it is waiting rather than done.
///
/// Bounded observation, not a deadline the work races: the task cannot finish
/// until the test releases what it is held on, so the probe need only be long
/// enough for the other tasks to run, and every passing run waits it out.
const PENDING_PROBE: std::time::Duration = std::time::Duration::from_millis(200); // 200 ms

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
async fn an_argon2_user_authenticates_and_a_wrong_password_does_not() {
    let file = HtpasswdFile::write(&format!(
        "{}\n",
        crate::support::argon2_line("alice", "correct horse", 19_456, 2)
    ));
    let dir = directory(&file).expect("an argon2 file loads");
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
        "the right password must authenticate against an argon2 record, so the \
         argon2 arm runs a real KDF comparison rather than returning a constant"
    );
    assert!(
        !dir.verify(
            Some(&record),
            &crate::support::password("wrong horse"),
            &svc
        )
        .await
        .expect("the verify answers"),
        "and a wrong password must not: an arm returning a constant would pass \
         one of these two assertions and fail the other"
    );
}

#[tokio::test]
async fn a_sha_crypt_user_authenticates_and_a_wrong_password_does_not() {
    for variant in [ShaCryptVariant::Sha256, ShaCryptVariant::Sha512] {
        let file = HtpasswdFile::write(&format!(
            "{}\n",
            sha_crypt_line("alice", "correct horse", variant, 1_000)
        ));
        let dir = directory(&file).expect("the file loads");
        let svc = services();

        let record = dir
            .lookup("alice", &svc)
            .await
            .expect("the lookup succeeds")
            .expect("alice is in the file");

        assert!(
            dir.verify(
                Some(&record),
                &crate::support::password("correct horse"),
                &svc
            )
            .await
            .expect("the verify completes"),
            "{} must authenticate the password its record was minted from",
            variant.ident()
        );
        assert!(
            !dir.verify(Some(&record), &crate::support::password("wrong"), &svc)
                .await
                .expect("the verify completes"),
            "{} must reject a wrong password",
            variant.ident()
        );
    }
}

#[tokio::test]
async fn a_sha_crypt_directory_runs_a_sha_crypt_dummy_for_an_unknown_user() {
    let line = sha_crypt_line("alice", "pw", ShaCryptVariant::Sha512, 1_000);
    let file = HtpasswdFile::write(&format!("{line}\n"));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&line),
        "the miss path must reuse one of the file's own sha-crypt records: a \
         bcrypt dummy over a sha-crypt directory would cost a different amount \
         than every hit, which is the user-enumeration oracle the uniformity \
         rule exists to close"
    );

    let before = dir.dummy_runs();
    assert!(
        dir.lookup("nobody", &svc)
            .await
            .expect("the lookup succeeds")
            .is_none(),
        "an unknown user must not resolve to a record"
    );
    assert!(
        !dir.verify(None, &crate::support::password("pw"), &svc)
            .await
            .expect("the verify completes"),
        "and the dummy's verdict must be discarded, even when its throwaway \
         password happens to match"
    );
    assert_eq!(
        dir.dummy_runs(),
        before.saturating_add(1),
        "the miss must have run the dummy rather than returning early"
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

#[test]
fn a_zero_staleness_ceiling_fails_validation() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    config.refresh_secs = 1;
    config.max_staleness_secs = 0;
    let err = HtpasswdDirectory::new(config)
        .expect_err("a zero staleness ceiling denies every lookup and must not load");
    assert!(
        err.contains("max_staleness_secs"),
        "the error should name the field an operator has to change: {err}"
    );
}

#[test]
fn a_zero_refresh_interval_fails_validation() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    config.refresh_secs = 0;
    config.max_staleness_secs = 30;
    let err = HtpasswdDirectory::new(config)
        .expect_err("a zero refresh interval reloads on every lookup and must not load");
    assert!(
        err.contains("refresh_secs"),
        "the error should name the field an operator has to change: {err}"
    );
}

#[tokio::test]
async fn the_smallest_legal_refresh_interval_still_merges_a_burst_into_one_read() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    config.refresh_secs = 1;
    config.max_staleness_secs = 3600;
    let dir = std::sync::Arc::new(HtpasswdDirectory::new(config).expect("the file loads"));

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
        "at the one-second floor a burst past the due time costs one read, so 15 \
         of these 16 lookups never dispatch a reload at all. A zero interval \
         would re-arm the slot at the same instant and queue one file read and \
         full parse per lookup onto the blocking pool, serialized on the \
         publishing mutex and unbounded by the verification semaphore"
    );
}

#[test]
fn a_due_reload_runs_on_the_blocking_pool_not_the_async_worker() {
    let runtime = single_blocking_thread_runtime();

    runtime.block_on(async {
        let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
        let mut config = config_for(file.path());
        config.refresh_secs = 1;
        config.max_staleness_secs = 3600;
        let dir = HtpasswdDirectory::new(config).expect("the file loads");
        let svc = services();

        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

        let (squatter, release) = occupy_the_blocking_pool();

        let mut due = Box::pin(dir.lookup("alice", &svc));
        let first_poll = futures::poll!(&mut due);
        assert!(
            first_poll.is_pending(),
            "the lookup that claims the due refresh must suspend on a queued \
             blocking task. Reading and parsing the file inline would let this \
             first poll run to completion on the async worker, stalling every \
             other task on it for the whole read -- outside the verification \
             semaphore, which bounds only the verify step"
        );

        drop(release);
        squatter.await.expect("the squatting task completes");

        let found = due.await.expect("the lookup answers");

        assert!(
            found.is_some(),
            "moving the reload off the worker must not change the answer: the \
             last-good index serves throughout, so alice resolves either way"
        );
        assert_eq!(
            dir.reload_attempts(),
            1,
            "the slot claim stays on the async side, so a due lookup still \
             records exactly one reload attempt"
        );
    });
}

/// A reload must hold the publication lock across its read, not only across
/// the publish.
///
/// The first reload is held after it has captured the pre-revocation records,
/// the source is then revoked, and a second reload is started. A lock that
/// covered only the publish would let the second read while the first is
/// held; it must instead wait for the first to publish, then read and publish
/// the revoked records last.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_reloads_across_a_revocation_cannot_republish_the_revoked_record() {
    let source = ScriptedSource::new(&["alice", "bob"], 3600, 7200);
    let control = source.control();
    let backend =
        std::sync::Arc::new(FileBackend::new(Box::new(source), None).expect("the source loads"));

    let (captured, release) = control.hold_next_read();
    let first = {
        let backend = std::sync::Arc::clone(&backend);
        tokio::task::spawn_blocking(move || backend.reload())
    };
    tokio::task::spawn_blocking(move || captured.recv())
        .await
        .expect("the capture wait completes")
        .expect("the first reload captures the pre-revocation records");

    control.set_users(&["alice"]);
    let reads_while_held = control.reads();
    let second = {
        let backend = std::sync::Arc::clone(&backend);
        tokio::task::spawn_blocking(move || backend.reload())
    };
    tokio::time::sleep(PENDING_PROBE).await;
    assert_eq!(
        control.reads(),
        reads_while_held,
        "the second reload must not read while the first holds the publication lock: a lock \
         over the publish alone lets it read the revoked file and publish before the held \
         reload republishes bob"
    );

    release.send(()).expect("the held reload is waiting");
    first
        .await
        .expect("the first reload task completes")
        .expect("the pre-revocation records are valid");
    second
        .await
        .expect("the second reload task completes")
        .expect("the revoked records are valid");

    assert_eq!(
        backend.peak_concurrent_reloads(),
        1,
        "reloads straddling a revocation must read, parse and publish one at a time"
    );
    assert!(
        backend.lookup("bob").await.expect("answers").is_none(),
        "the reload that read after the revocation publishes last, so bob stays revoked"
    );
}

/// A stalled read must not hold lookups past the staleness ceiling.
///
/// The defect: the lookup that started a reload awaited it unbounded, and
/// every later lookup queued on the refresh slot before the staleness check.
/// A hung read therefore hung every request instead of denying as `Stale`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_reload_past_the_ceiling_denies_as_stale_rather_than_hanging() {
    let source = ScriptedSource::new(&["alice"], 1, 1);
    let control = source.control();
    let backend =
        std::sync::Arc::new(FileBackend::new(Box::new(source), None).expect("the source loads"));

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    control.set_users(&["alice", "bob"]);
    let (captured, release) = control.hold_next_read();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..4_u32 {
        let backend = std::sync::Arc::clone(&backend);
        set.spawn(async move { backend.lookup("bob").await.map(|found| found.is_some()) });
    }
    tokio::task::spawn_blocking(move || captured.recv())
        .await
        .expect("the capture wait completes")
        .expect("the request-path reload reaches the stalled read");

    let outcomes = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut outcomes = Vec::new();
        while let Some(joined) = set.join_next().await {
            outcomes.push(joined.expect("the lookup task completes"));
        }
        outcomes
    })
    .await
    .expect("every lookup must answer within its bound rather than queue on the stalled read");
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome, Err(DirectoryError::Stale))),
        "past the ceiling with no replacement published, each lookup denies as stale: \
         {outcomes:?}"
    );
    assert_eq!(
        backend.reload_attempts(),
        1,
        "the stalled reload keeps the refresh slot, so the lookups that gave up started no \
         duplicate read"
    );

    release.send(()).expect("the stalled read is waiting");
    let mut served = false;
    for _ in 0..50_u32 {
        if matches!(backend.lookup("bob").await, Ok(Some(_))) {
            served = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        served,
        "once the stalled read finishes, its index publishes and lookups answer from it"
    );
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
    config.refresh_secs = 1;
    config.max_staleness_secs = 1;
    let dir = HtpasswdDirectory::new(config).expect("the file loads");
    let svc = services();

    file.unlink();
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let outcome = dir.lookup("alice", &svc).await;
    assert!(
        matches!(
            outcome,
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Stale)
        ),
        "past the ceiling a lookup must fail closed as unavailable, got {outcome:?}"
    );
}

#[test]
fn a_burst_after_an_idle_period_past_the_ceiling_waits_for_the_reload() {
    let runtime = single_blocking_thread_runtime();

    runtime.block_on(async {
        let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
        let mut config = config_for(file.path());
        config.refresh_secs = 1;
        config.max_staleness_secs = 2;
        let dir = std::sync::Arc::new(HtpasswdDirectory::new(config).expect("the file loads"));

        tokio::time::sleep(std::time::Duration::from_millis(2_200)).await;
        file.rewrite(&format!(
            "{}\n{}\n",
            bcrypt_line("alice", "pw", 4),
            bcrypt_line("bob", "pw", 4)
        ));

        let (squatter, release) = occupy_the_blocking_pool();

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16_u32 {
            let dir = std::sync::Arc::clone(&dir);
            set.spawn(async move {
                dir.lookup("bob", &services())
                    .await
                    .map(|found| found.is_some())
            });
        }

        let while_held = tokio::time::timeout(PENDING_PROBE, set.join_next()).await;
        let reloads_while_held = dir.reload_attempts();

        drop(release);
        squatter.await.expect("the squatting task completes");

        assert!(
            matches!(while_held, Err(tokio::time::error::Elapsed { .. })),
            "with the reload held off the blocking pool, no lookup in the burst may answer: past \
             the ceiling each one waits for the in-flight reload rather than denying as `Stale`, \
             got {while_held:?}"
        );
        assert_eq!(
            reloads_while_held, 1,
            "the first lookup claims the slot and queues the one reload, and the rest wait on it \
             rather than start their own"
        );

        let mut outcomes = Vec::new();
        while let Some(joined) = set.join_next().await {
            outcomes.push(joined.expect("the lookup task completes"));
        }
        assert!(
            outcomes.len() == 16 && outcomes.iter().all(|outcome| matches!(outcome, Ok(true))),
            "once the reload publishes, every waiting lookup must answer from it: bob exists only \
             in the rewritten file, so a lookup answering from the old index would miss: \
             {outcomes:?}"
        );
        assert_eq!(
            dir.reload_attempts(),
            1,
            "the waiting lookups must share the one reload rather than each run their own"
        );
    });
}

#[test]
fn concurrent_verifications_beyond_the_cap_deny_rather_than_queue() {
    let runtime = single_blocking_thread_runtime();

    runtime.block_on(async {
        let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
        let mut config = config_for(file.path());
        config.max_concurrent_verifications = 1;
        let dir = HtpasswdDirectory::new(config).expect("the file loads");
        let svc = services();
        let record = dir
            .lookup("alice", &svc)
            .await
            .expect("the lookup answers")
            .expect("alice is in the file");
        let credential = crate::support::password("pw");

        let (squatter, release) = occupy_the_blocking_pool();

        let mut admitted = Box::pin(dir.verify(Some(&record), &credential, &svc));
        let took_the_permit = futures::poll!(&mut admitted).is_pending();

        let mut contenders = Vec::new();
        for _ in 0..7_u32 {
            contenders.push(
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    dir.verify(Some(&record), &credential, &svc),
                )
                .await,
            );
        }

        drop(release);
        squatter.await.expect("the squatting task completes");
        let verdict = admitted.await;

        assert!(
            took_the_permit,
            "the first verify must take the only permit and queue its blocking work"
        );
        assert!(
            contenders.iter().all(|contender| matches!(
                contender,
                Ok(Err(
                    praxis_policy_builtins::plugins::identity_basic::DirectoryError::Saturated
                ))
            )),
            "with the only permit held, every contender must be refused at once as `Saturated` \
             rather than queue behind it: {contenders:?}"
        );
        assert!(
            matches!(verdict, Ok(true)),
            "and the verification holding the permit must authenticate once it runs: the cap \
             refuses excess work, not the request it admitted, got {verdict:?}"
        );
    });
}

#[test]
fn dropping_a_verify_future_does_not_release_its_permit_early() {
    let runtime = single_blocking_thread_runtime();

    runtime.block_on(async {
        let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
        let mut config = config_for(file.path());
        config.max_concurrent_verifications = 1;
        let dir = HtpasswdDirectory::new(config).expect("the file loads");
        let svc = services();
        let record = dir
            .lookup("alice", &svc)
            .await
            .expect("the lookup answers")
            .expect("alice is in the file");
        let credential = crate::support::password("pw");

        let (squatter, release) = occupy_the_blocking_pool();

        let mut in_flight = Box::pin(dir.verify(Some(&record), &credential, &svc));
        assert!(
            futures::poll!(&mut in_flight).is_pending(),
            "the first poll must take the only permit and queue the blocking \
             verification without completing it"
        );
        assert!(
            saturated(&dir, &record, &credential, &svc).await,
            "with the pool's only thread occupied by the test, the queued \
             verification cannot have run, so its permit must still be held"
        );

        drop(in_flight);

        let still_held = saturated(&dir, &record, &credential, &svc).await;

        drop(release);
        squatter.await.expect("the squatting task completes");

        assert!(
            still_held,
            "a permit held in the async body rather than inside the blocking \
             closure would be released the instant that future dropped, while \
             the hashing it bounded ran on -- the unauthenticated \
             CPU-exhaustion path where a caller that connects and disconnects \
             starts as many concurrent verifies as the Tokio blocking pool \
             allows, whatever the cap. The blocking task still has not run \
             here, so this cannot be satisfied by a verification that merely \
             has not finished yet"
        );
    });
}

#[test]
fn a_burst_of_lookups_triggers_one_file_read() {
    let runtime = single_blocking_thread_runtime();

    runtime.block_on(async {
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

        let (squatter, release) = occupy_the_blocking_pool();

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16_u32 {
            let dir = std::sync::Arc::clone(&dir);
            set.spawn(async move {
                dir.lookup("alice", &services())
                    .await
                    .map(|found| found.is_some())
            });
        }

        let mut served = Vec::new();
        let losers = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while served.len() < 15
                && let Some(joined) = set.join_next().await
            {
                served.push(joined.expect("the lookup task completes"));
            }
        })
        .await;
        let while_held = tokio::time::timeout(PENDING_PROBE, set.join_next()).await;
        let reloads_while_held = dir.reload_attempts();

        drop(release);
        squatter.await.expect("the squatting task completes");

        assert!(
            matches!(losers, Ok(())) && served.iter().all(|outcome| matches!(outcome, Ok(true))),
            "within the ceiling, the 15 lookups that lose the refresh slot must answer from the \
             running index while the reload is held, rather than wait for it: {served:?}"
        );
        assert!(
            matches!(while_held, Err(tokio::time::error::Elapsed { .. })),
            "the lookup that claimed the slot must still be waiting on the held reload, or the \
             burst did not overlap it, got {while_held:?}"
        );
        assert_eq!(
            reloads_while_held, 1,
            "16 concurrent lookups past the due time must cost exactly one file read"
        );

        let reloader = set
            .join_next()
            .await
            .expect("the reloading lookup is still in the set")
            .expect("the lookup task completes");
        assert!(
            matches!(reloader, Ok(true)),
            "the lookup that ran the reload must answer once it publishes, got {reloader:?}"
        );
        assert_eq!(
            dir.len(),
            2,
            "and that one read must have picked up the rewritten file"
        );
    });
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
async fn every_record_in_a_large_file_is_reachable() {
    let shared = bcrypt_line("user", "pw", 4);
    let (_, stored) = shared
        .split_once(':')
        .expect("the fixture line has a separator");
    let lines: String = (0..500_u32)
        .map(|n| format!("user{n}:{stored}\n"))
        .collect();
    let file = HtpasswdFile::write(&lines);
    let dir = directory(&file).expect("a large file loads");
    let svc = services();

    assert_eq!(dir.len(), 500, "every record in a large file is indexed");
    for n in 0..500_u32 {
        let user_id = format!("user{n}");
        assert!(
            dir.lookup(&user_id, &svc).await.expect("answers").is_some(),
            "{user_id} must be reachable, not only the first and last records"
        );
    }
    assert!(
        dir.lookup("nobody", &svc).await.expect("answers").is_none(),
        "and a miss in a large file is still a miss"
    );
}

#[test]
fn loading_an_argon2_record_does_not_mint_an_expensive_dummy() {
    let phc = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
               MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";
    let line = format!("alice:{phc}");
    let file = HtpasswdFile::write(&format!("{line}\n"));

    let dir = directory(&file).expect("an argon2 file loads");

    assert_eq!(
        dir.floor_mints(),
        0,
        "a populated file must take its miss-path hash from a stored record; \
         minting the bcrypt floor hash instead is work this load never needs"
    );
    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&line),
        "and the miss path must cost what the stored argon2 record costs, \
         which is the property the absent mint leaves intact"
    );
    assert_eq!(dir.len(), 1, "the record is indexed");
}

#[test]
fn an_empty_file_mints_one_floor_hash_and_reuses_it_across_reloads() {
    let file = HtpasswdFile::write("# every record commented out\n");
    let dir = directory(&file).expect("a file with no records loads");

    assert_eq!(
        dir.floor_mints(),
        1,
        "a file with no records has no stored hash to borrow, so the floor hash \
         is the only thing that keeps an empty directory from answering a miss \
         in nanoseconds"
    );
    assert_eq!(
        dir.miss_cost_profile(),
        CostProfile::Bcrypt {
            cost: EMPTY_DIRECTORY_COST
        },
        "and it runs at the documented floor cost"
    );

    for _ in 0..5_u32 {
        dir.reload().expect("the reload succeeds");
    }

    assert_eq!(
        dir.floor_mints(),
        1,
        "a reload that finds the file still empty reuses the first floor hash: \
         reload runs on the request path, where a second bcrypt mint would \
         block an executor worker"
    );
}

#[test]
fn reloading_a_populated_directory_does_no_hashing_work() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 5)));
    let dir = directory(&file).expect("the file loads");

    for _ in 0..20_u32 {
        dir.reload().expect("the reload succeeds");
    }

    assert_eq!(
        dir.floor_mints(),
        0,
        "a reload must reuse a record from the file as its miss-path hash rather \
         than minting one, because reload runs on the request path where a \
         bcrypt mint would block an executor worker"
    );
    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&bcrypt_line("alice", "pw", 5)),
        "and the miss path must still cost what the stored record costs"
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
        (
            "the two sha-crypt variants",
            format!(
                "{}\n{}\n",
                sha_crypt_line("a", "pw", ShaCryptVariant::Sha256, 1_000),
                sha_crypt_line("b", "pw", ShaCryptVariant::Sha512, 1_000)
            ),
        ),
        (
            "two sha-crypt round counts",
            format!(
                "{}\n{}\n",
                sha_crypt_line("a", "pw", ShaCryptVariant::Sha512, 1_000),
                sha_crypt_line("b", "pw", ShaCryptVariant::Sha512, 2_000)
            ),
        ),
        (
            "two sha-crypt salt lengths",
            format!(
                "a:{}\nb:{}\n",
                sha_crypt_salted(ShaCryptVariant::Sha256, 1_000, "pw", b"saltsalt0000"),
                sha_crypt_salted(ShaCryptVariant::Sha256, 1_000, "pw", b"salt00"),
            ),
        ),
        (
            "sha-crypt and bcrypt",
            format!(
                "{}\n{}\n",
                sha_crypt_line("a", "pw", ShaCryptVariant::Sha512, 1_000),
                bcrypt_line("b", "pw", 10)
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

    let sha_crypt = HtpasswdFile::write(&format!(
        "{}\n{}\n",
        sha_crypt_line("a", "pw", ShaCryptVariant::Sha512, 1_000),
        sha_crypt_line("b", "other", ShaCryptVariant::Sha512, 1_000),
    ));
    let dir = directory(&sha_crypt).expect("a uniform sha512crypt file loads");
    assert_eq!(
        dir.len(),
        2,
        "both sha512crypt records are indexed, so a deployment restricted to \
         SHA-2 has a directory it can actually use"
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

#[tokio::test]
async fn a_reload_onto_mixed_costs_is_refused_and_the_uniform_index_keeps_serving() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 5)));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    file.rewrite(&format!(
        "{}\n{}\n",
        bcrypt_line("alice", "pw", 5),
        bcrypt_line("bob", "pw", 12),
    ));
    let err = dir
        .reload()
        .expect_err("a rewrite mixing two bcrypt costs must fail the reload");
    assert!(
        err.contains("One cost profile per file"),
        "the refresh path must refuse mixed costs for the same reason the load path does, and \
         say so: uniformity is a property of whatever is being served, so a rewrite accepted \
         here would reintroduce the enumeration oracle at runtime on a file that loaded clean, \
         got: {err}"
    );

    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&bcrypt_line("alice", "pw", 5)),
        "the refused reload must leave the uniform index in place rather than \
         publish a half-applied one"
    );
    assert!(
        dir.lookup("bob", &svc).await.expect("answers").is_none(),
        "and the record from the refused file must not be reachable"
    );

    let retained = dir
        .lookup("alice", &svc)
        .await
        .expect("answers")
        .expect("the user from the accepted file must still be indexed");
    assert!(
        dir.verify(Some(&retained), &crate::support::password("pw"), &svc)
            .await
            .expect("the verify answers"),
        "and must still authenticate: keeping the previous miss profile while \
         dropping the user index would pass every other assertion here and \
         still have locked out everyone in the file"
    );
}

#[tokio::test]
async fn a_file_backend_refuses_a_delegated_verdict() {
    use praxis_policy_builtins::plugins::identity_basic::{StoredVerifier, UserRecord};

    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let dir = directory(&file).expect("the file loads");
    let svc = services();
    let record = UserRecord::verifier_only(StoredVerifier::Delegated { valid: true });

    assert!(
        matches!(
            dir.verify(Some(&record), &crate::support::password("pw"), &svc)
                .await,
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Malformed(_))
        ),
        "a verdict this backend cannot have produced must fail closed rather \
         than authenticate on someone else's `valid: true`"
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

#[tokio::test]
async fn a_reload_onto_bcrypt_is_refused_under_a_ceiling_bcrypt_cannot_honour() {
    let argon2 = argon2_line("alice", "correct horse", 19_456, 2);
    let file = HtpasswdFile::write(&format!("{argon2}\n"));
    let dir = HtpasswdDirectory::with_password_ceiling(config_for(file.path()), 128)
        .expect("an argon2 file loads under a ceiling above bcrypt's truncation point");
    let svc = services();

    file.rewrite(&format!("{}\n", bcrypt_line("alice", "pw", 5)));
    let err = dir
        .reload()
        .expect_err("a rewrite onto bcrypt must fail the reload while the ceiling exceeds 72");
    assert!(
        err.contains("max_password_bytes") && err.contains("72"),
        "the refresh path must refuse the incoherent pairing for the same reason the load path \
         does, and name both the setting and the truncation point, got: {err}"
    );

    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&argon2),
        "the refused reload must leave the argon2 index serving rather than publish a bcrypt \
         one that would deny every password over 72 bytes as though it were simply wrong"
    );

    let retained = dir
        .lookup("alice", &svc)
        .await
        .expect("answers")
        .expect("the user from the accepted file must still be indexed");
    assert!(
        dir.verify(
            Some(&retained),
            &crate::support::password("correct horse"),
            &svc
        )
        .await
        .expect("the verify answers"),
        "and must still authenticate against the argon2 record the refused reload left in place"
    );
}

#[test]
fn an_empty_file_loads_under_a_ceiling_bcrypt_could_not_honour() {
    let file = HtpasswdFile::write("# every user revoked\n");

    HtpasswdDirectory::with_password_ceiling(config_for(file.path()), 128).expect(
        "a file with no records must not be read as a bcrypt directory: its miss-path hash is a \
         synthesized bcrypt one, but with no stored hash there is no long password to truncate, \
         so an empty file constrains the ceiling not at all",
    );
}

#[tokio::test]
async fn revoking_every_user_publishes_the_empty_index_under_a_large_ceiling() {
    let argon2 = argon2_line("alice", "correct horse", 19_456, 2);
    let file = HtpasswdFile::write(&format!("{argon2}\n"));
    let dir = HtpasswdDirectory::with_password_ceiling(config_for(file.path()), 128)
        .expect("an argon2 file loads under a ceiling above bcrypt's truncation point");
    let svc = services();

    file.rewrite("");
    dir.reload().expect(
        "emptying the file is how an operator revokes everyone, so it must publish the empty \
         index rather than refuse the reload",
    );

    assert!(
        dir.lookup("alice", &svc).await.expect("answers").is_none(),
        "the revoked user must be gone from the published index: a refused reload left the \
         previous one serving, so every revoked user kept authenticating until the staleness \
         ceiling elapsed -- a failure the caller sees as success"
    );
}

#[tokio::test]
async fn a_reload_onto_bcrypt_is_accepted_under_a_ceiling_bcrypt_can_honour() {
    let argon2 = argon2_line("alice", "correct horse", 19_456, 2);
    let file = HtpasswdFile::write(&format!("{argon2}\n"));
    let dir = HtpasswdDirectory::with_password_ceiling(config_for(file.path()), 72)
        .expect("an argon2 file loads at bcrypt's truncation point");

    let bcrypt = bcrypt_line("alice", "pw", 5);
    file.rewrite(&format!("{bcrypt}\n"));
    dir.reload()
        .expect("a ceiling bcrypt can honour must not block a scheme change");

    assert_eq!(
        dir.miss_cost_profile(),
        crate::support::cost_profile_of(&bcrypt),
        "the ceiling is refused for the pairing it breaks, not for every reload onto bcrypt"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a directory over a fixture file, with the default ceilings.
/// A current-thread runtime with one blocking thread, which
/// [`occupy_the_blocking_pool`] can hold so blocking work queued after it is
/// provably unstarted.
fn single_blocking_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .build()
        .expect("the test runtime builds")
}

fn directory(file: &HtpasswdFile) -> Result<HtpasswdDirectory, String> {
    HtpasswdDirectory::new(config_for(file.path()))
}

/// Hold the runtime's only blocking thread until the returned sender drops.
///
/// Returns once the thread is occupied, so a `spawn_blocking` queued after
/// this call is provably unstarted rather than merely unfinished.
///
/// The release is a channel rather than a barrier because a failing assertion
/// unwinds out of `block_on`, and dropping the runtime then waits for the
/// blocking pool to drain. A barrier would still be waiting for a partner that
/// is never coming, so the test would hang instead of reporting its failure.
/// Unwinding drops the sender, which ends the `recv` and lets the thread go.
fn occupy_the_blocking_pool() -> (tokio::task::JoinHandle<()>, std::sync::mpsc::Sender<()>) {
    let occupied = std::sync::Arc::new(std::sync::Barrier::new(2));
    let (release, released) = std::sync::mpsc::channel::<()>();
    let squatter = {
        let occupied = std::sync::Arc::clone(&occupied);
        tokio::task::spawn_blocking(move || {
            occupied.wait();
            let _ = released.recv();
        })
    };
    occupied.wait();

    (squatter, release)
}

/// Whether a `verify` is refused for capacity right now.
///
/// Bounded, because the answer is only meaningful when it comes back
/// immediately. `verify` refuses at capacity through a non-blocking
/// `try_acquire`, so a held permit answers at once; if the permit is instead
/// free, the call takes it and queues blocking work that a parked pool may
/// never run. Without the bound that case hangs rather than reporting, and a
/// hang says far less than a failed assertion.
async fn saturated(
    dir: &HtpasswdDirectory,
    record: &praxis_policy_builtins::plugins::identity_basic::UserRecord,
    credential: &praxis_policy_builtins::plugins::identity_basic::credential::BasicCredential,
    svc: &praxis_policy_core::host::InitExtensions,
) -> bool {
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dir.verify(Some(record), credential, svc),
        )
        .await,
        Ok(Err(
            praxis_policy_builtins::plugins::identity_basic::DirectoryError::Saturated
        ))
    )
}
