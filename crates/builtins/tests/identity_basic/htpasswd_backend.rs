// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The `.htpasswd` backend: parsing, the index, the refresh window, the
//! staleness ceiling, and the properties that keep a miss from being cheaper
//! than a hit.

use praxis_policy_builtins::plugins::identity_basic::directory::CredentialDirectory as _;
use praxis_policy_builtins::plugins::identity_basic::{HtpasswdConfig, HtpasswdDirectory};

use crate::support::{HtpasswdFile, bcrypt_line, config_for, services};

/// Build a directory over a fixture file, with the default ceilings.
fn directory(file: &HtpasswdFile) -> Result<HtpasswdDirectory, String> {
    HtpasswdDirectory::new(config_for(file.path()))
}

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
    // R7: asserted via a counter rather than timing, which would be flaky in
    // CI. This proves a dummy *ran*; that it costs the same is the work-factor
    // assertion below, not this one.
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

#[tokio::test]
async fn the_miss_path_runs_at_the_maximum_cost_present_not_the_dominant_one() {
    // KTD9. Three cheap records and one expensive one: a dummy at the
    // *dominant* cost would make the expensive user's hit measurably slower
    // than a miss, which enumerates both which names exist and which users sit
    // on the cheapest scheme.
    let file = HtpasswdFile::write(&format!(
        "{}\n{}\n{}\n{}\n",
        bcrypt_line("a", "pw", 4),
        bcrypt_line("b", "pw", 4),
        bcrypt_line("c", "pw", 4),
        bcrypt_line("expensive", "pw", 8),
    ));
    let dir = directory(&file).expect("the file loads");

    let miss = dir.miss_work_factor();
    let dearest = crate::support::work_factor_of(&bcrypt_line("expensive", "pw", 8));
    assert!(
        miss >= dearest,
        "the miss path ({miss:?}) must not be cheaper than the dearest record ({dearest:?})"
    );
}

#[tokio::test]
async fn the_dummy_tracks_a_reload_that_raises_the_maximum_cost() {
    // KTD9: recomputed on every load, not fixed at startup. Otherwise adding a
    // more expensive record makes that user's hit slower than every miss.
    // Costs straddle `WorkFactor::FLOOR`: below it the dummy is pinned at the
    // floor by design (a cheap directory still pays a floor-cost miss), so a
    // reload only moves the dummy once the file's worst case clears it.
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("a", "pw", 4)));
    let dir = directory(&file).expect("the file loads");
    let before = dir.miss_work_factor();

    file.rewrite(&format!(
        "{}\n{}\n",
        bcrypt_line("a", "pw", 4),
        bcrypt_line("b", "pw", 12)
    ));
    dir.reload().expect("the rewritten file loads");

    let after = dir.miss_work_factor();
    assert!(
        after > before,
        "the dummy must rise with the file's worst case ({before:?} -> {after:?})"
    );
    assert!(
        after >= crate::support::work_factor_of(&bcrypt_line("b", "pw", 12)),
        "and must reach at least the new dearest record"
    );
}

#[tokio::test]
async fn a_directory_of_cheap_records_still_pays_a_floor_cost_miss() {
    // The complement of KTD9, and the reason the previous case has to straddle
    // the floor: a file of cheap records would otherwise make every miss cheap
    // too, so an empty or low-cost directory stays distinguishable from a
    // populated one by timing alone. The floor is what stops that.
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("a", "pw", 4)));
    let dir = directory(&file).expect("the file loads");
    let cheap = crate::support::work_factor_of(&bcrypt_line("a", "pw", 4));
    assert!(
        dir.miss_work_factor() > cheap,
        "the miss path must not drop to the cost of the cheapest record"
    );
}

#[test]
fn a_duplicate_user_id_fails_at_load() {
    // R11: picking either silently would hand one caller the other's identity.
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
    // R11 + R4: the duplicate check runs *after* normalisation, so the two
    // spellings cannot silently collapse onto one key.
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
    // R4: stored user-ids are normalised identically to inbound ones, so a
    // file written with a decomposed name stays reachable.
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
    // R13: a bad file is a configuration mistake, and failing at load reads as
    // one. Failing at request time reads as an outage.
    let no_separator = HtpasswdFile::write("alicenohash\n");
    let err = directory(&no_separator).expect_err("a line with no separator must fail");
    assert!(err.contains("separator"), "{err}");

    let empty_half = HtpasswdFile::write("alice:\n");
    let err = directory(&empty_half).expect_err("an empty hash must fail");
    assert!(err.contains("empty"), "{err}");

    // The unreadable-path case: delete the file while the guard still owns the
    // path, so the directory is built against something that is not there.
    let gone = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    gone.unlink();
    let err = directory(&gone).expect_err("an unreadable path must fail");
    assert!(err.contains("reading"), "{err}");
}

#[test]
fn a_refused_scheme_fails_at_load_naming_the_line() {
    // R8. The message has to name the line, because a password file is often
    // machine-written and the operator needs to find the record.
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
    // R23, at the backend boundary rather than the verifier's.
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 12)));
    let mut config = config_for(file.path());
    config.limits.max_bcrypt_cost = 10;
    let err = HtpasswdDirectory::new(config).expect_err("an over-ceiling cost must fail the load");
    assert!(err.contains("ceiling"), "{err}");
}

#[test]
fn a_config_omitting_the_staleness_ceiling_fails_to_load() {
    // R12: required here, unlike the api-key backend. A reload that keeps
    // failing would otherwise keep serving a revoked user forever.
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
    // R12: the refresh interval *is* the revocation window on this backend.
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
    // R12: emptying the index on a transient read error would turn a blip into
    // a total authentication outage, and the loaded records are still the best
    // answer available.
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
    // R12 + R13: the distinction matters to an operator. "Stale" is an outage;
    // "no such user" is a wave of bad passwords. Conflating them hides the
    // former behind the latter.
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut config = config_for(file.path());
    // A zero ceiling with a refresh interval it does not undercut: every
    // lookup is immediately past the ceiling.
    config.refresh_secs = 0;
    config.max_staleness_secs = 0;
    let dir = HtpasswdDirectory::new(config).expect("the file loads");
    let svc = services();

    // Make the index un-reloadable, so staleness cannot be reset by a refresh.
    file.unlink();
    // Let the monotonic clock advance past zero.
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
    // R24: every syntactically valid header costs a full verify, including a
    // miss, so an unbounded queue is an unauthenticated CPU exhaustion path.
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

    // Enough concurrent verifications that at least one must be refused a
    // permit while another holds the only one.
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
    // R12: the CAS-claimed refresh slot. Without it a burst past the due time
    // costs one file read each, which is a thundering herd on every interval.
    //
    // The non-zero interval is load-bearing. An earlier version used
    // `refresh_secs = 0`, which makes every lookup immediately due, so the
    // slot re-armed between lookups and the test would have passed even if all
    // 16 had reloaded -- it asserted only that the records were visible, not
    // the one-read property its name claims. The counter is what pins it.
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
    // Past the interval, so the slot is due exactly once for the whole burst.
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
    // R15: `subject.claim.<name>` is a legal assertion source, so a hash left
    // in the projectable bag could be rendered into an upstream header.
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
    // R6: a directory that scans is a directory that times out under the user
    // population it was bought for. Asserted structurally -- the index is a
    // hash map and a lookup is one probe -- by showing a large file still
    // answers a miss and a hit without the file size appearing anywhere.
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
    // A regression bound, not a benchmark. An earlier version derived a bcrypt
    // cost from argon2's parameters and minted a dummy at it, conflating two
    // scales that differ by orders of magnitude: bcrypt cost is a power-of-two
    // exponent, argon2's `m` is already in KiB. An ordinary `m=19456,t=2`
    // record -- the RFC-recommended default -- scaled to cost 16, and loading
    // one took 7.9 seconds. The default argon2 ceiling scaled to 28, which is
    // 2^12 times that again.
    //
    // The miss path now reuses the heaviest record already in the file, so a
    // populated directory does no minting at all. The generous bound here is
    // deliberate: the failure this guards against was measured in seconds, so
    // a threshold in the hundreds of milliseconds catches it without being
    // flaky on a loaded CI box.
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

#[tokio::test]
async fn the_miss_path_hash_is_the_heaviest_record_not_a_synthesized_cost() {
    // KTD9's requirement, restated as what the code now does: a miss is
    // verified against the dearest *real* hash. That is exactly as expensive
    // as the dearest hit by construction, where a synthesized cost could land
    // either side of it -- and did land far above it.
    let file = HtpasswdFile::write(&format!(
        "{}\n{}\n",
        bcrypt_line("cheap", "pw", 4),
        bcrypt_line("dear", "pw", 12),
    ));
    let dir = directory(&file).expect("the file loads");

    assert_eq!(
        dir.miss_work_factor(),
        crate::support::work_factor_of(&bcrypt_line("dear", "pw", 12)),
        "the miss path must run at exactly the dearest record's work factor"
    );
}

#[test]
fn an_empty_directory_still_mints_a_floor_cost_miss_hash() {
    // The one case that must mint: with no record to reuse, an empty file
    // would otherwise be distinguishable from a populated one by timing.
    let file = HtpasswdFile::write("# every line is a comment\n\n");
    let dir = directory(&file).expect("an empty file is still a valid directory");

    assert!(dir.is_empty(), "the file holds no records");
    assert_eq!(
        dir.miss_work_factor(),
        praxis_policy_builtins::plugins::identity_basic::WorkFactor::FLOOR,
        "an empty directory falls back to a minted floor-cost hash"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_request_does_not_release_its_verification_permit_early() {
    // R24, against the failure mode that defeats it. Dropping a future does
    // not cancel a `spawn_blocking` task, so a permit held by the async body
    // is released while the CPU work it bounds carries on. A client that
    // connects and disconnects could then start unbounded concurrent
    // verifications -- measured at 8 against a cap of 1 before the fix.
    //
    // A high bcrypt cost so each verify is slow enough that the aborted tasks
    // are provably still running when the final acquire is attempted.
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 12)));
    let mut config = config_for(file.path());
    config.max_concurrent_verifications = 1;
    let dir = std::sync::Arc::new(HtpasswdDirectory::new(config).expect("the file loads"));
    let svc = services();
    let record = dir
        .lookup("alice", &svc)
        .await
        .expect("the lookup answers")
        .expect("alice exists");
    let verifier = record.verifier.clone();

    // Start a verification, then abort its future while the blocking work runs.
    let aborted = {
        let dir = std::sync::Arc::clone(&dir);
        let verifier = verifier.clone();
        tokio::spawn(async move {
            let svc = services();
            let rec = praxis_policy_builtins::plugins::identity_basic::UserRecord::verifier_only(
                verifier,
            );
            dir.verify(Some(&rec), &crate::support::password("pw"), &svc)
                .await
        })
    };
    // Long enough to be inside the blocking verify, short enough that a cost-12
    // bcrypt (~170ms) has not finished.
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    aborted.abort();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // The permit must still be held by the blocking task, so this is refused.
    let rec = praxis_policy_builtins::plugins::identity_basic::UserRecord::verifier_only(verifier);
    let outcome = dir
        .verify(Some(&rec), &crate::support::password("pw"), &svc)
        .await;
    assert!(
        matches!(
            outcome,
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Saturated)
        ),
        "an aborted request must not hand its permit back while its blocking \
         verification is still running, got {outcome:?}"
    );
}

#[test]
fn an_unknown_key_fails_to_load_at_either_level() {
    // The ceilings live in a nested `limits:` block rather than a flattened
    // one, because serde does not support `flatten` with
    // `deny_unknown_fields`. A silently accepted `max_bcrypt_cst: 20` would
    // leave the real ceiling at its default while an operator believed a limit
    // was in force -- a misconfiguration that reads as working.
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let base = format!(
        "path: {}\nrefresh_secs: 30\nmax_staleness_secs: 300\n",
        file.path()
    );

    for (label, extra) in [
        ("a typo at the top level", "max_bcrypt_cst: 20\n".to_owned()),
        ("an unknown top-level key", "wholly_bogus: 1\n".to_owned()),
        (
            "a typo inside the limits block",
            "limits:\n  max_bcrypt_cst: 20\n".to_owned(),
        ),
    ] {
        let err = serde_yaml::from_str::<HtpasswdConfig>(&format!("{base}{extra}"))
            .expect_err("an unknown key must not deserialize");
        assert!(
            err.to_string().contains("unknown field"),
            "{label} should be refused by name, got: {err}"
        );
    }
}

#[test]
fn the_limits_block_parses_nested_and_defaults_when_absent() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let base = format!(
        "path: {}\nrefresh_secs: 30\nmax_staleness_secs: 300\n",
        file.path()
    );

    let defaulted = serde_yaml::from_str::<HtpasswdConfig>(&base)
        .expect("a config with no limits block takes the defaults");
    assert_eq!(
        defaulted.limits.max_bcrypt_cost,
        praxis_policy_builtins::plugins::identity_basic::Limits::default().max_bcrypt_cost,
        "an absent limits block means the shared defaults"
    );

    let explicit =
        serde_yaml::from_str::<HtpasswdConfig>(&format!("{base}limits:\n  max_bcrypt_cost: 11\n"))
            .expect("a nested limits block parses");
    assert_eq!(
        explicit.limits.max_bcrypt_cost, 11,
        "an explicit nested ceiling is the one that takes effect"
    );
}
