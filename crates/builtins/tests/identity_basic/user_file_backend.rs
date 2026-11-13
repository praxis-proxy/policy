// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The YAML user-file backend: the record shape, the fields it projects that
//! `.htpasswd` cannot express, its native expiry, and the load-time rules it
//! shares with the `.htpasswd` backend.

use praxis_policy_builtins::plugins::identity_basic::directory::CredentialDirectory as _;
use praxis_policy_builtins::plugins::identity_basic::{UserFileConfig, UserFileDirectory};

use crate::support::{
    UserYamlFile, argon2_at, bcrypt_line, cost_profile_of, denial_code, resolve_with_header,
    resolver, services, user_file_block, user_file_config_for,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// A directory over a fixture file.
fn directory(file: &UserYamlFile) -> Result<UserFileDirectory, String> {
    UserFileDirectory::new(user_file_config_for(file.path()))
}

/// A directory over a fixture file under an explicit password ceiling.
fn directory_with_ceiling(
    file: &UserYamlFile,
    ceiling: usize,
) -> Result<UserFileDirectory, String> {
    UserFileDirectory::with_password_ceiling(user_file_config_for(file.path()), ceiling)
}

/// A bcrypt hash at the given cost, for a record body.
fn bcrypt_hash(password: &str, cost: u32) -> String {
    let line = bcrypt_line("u", password, cost);
    line.split_once(':')
        .expect("the fixture line has a separator")
        .1
        .to_owned()
}

/// A one-user file whose record carries roles and teams.
fn alice_with_fields(password: &str) -> String {
    format!(
        "users:\n  \
         - username: alice\n    \
           password_hash: {}\n    \
           roles: [admin, auditor]\n    \
           teams: [platform]\n",
        bcrypt_hash(password, 4)
    )
}

// -----------------------------------------------------------------------------
// Projection (R9, R15)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn a_records_roles_and_teams_project_into_the_identity() {
    let file = UserYamlFile::write(&alice_with_fields("correct horse"));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    let record = dir
        .lookup("alice", &svc)
        .await
        .expect("the lookup answers")
        .expect("alice is in the file");

    assert_eq!(
        record.fields.get("roles"),
        Some(&serde_json::json!(["admin", "auditor"])),
        "a record's roles must be projectable, which is what this backend exists for"
    );
    assert_eq!(
        record.fields.get("teams"),
        Some(&serde_json::json!(["platform"])),
        "a record's teams must be projectable too"
    );
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
async fn neither_the_hash_nor_the_username_reaches_the_projected_fields() {
    let file = UserYamlFile::write(&alice_with_fields("correct horse"));
    let dir = directory(&file).expect("the file loads");

    let record = dir
        .lookup("alice", &services())
        .await
        .expect("the lookup answers")
        .expect("alice is in the file");

    // R15. The three storage fields are typed on the record, so `flatten`
    // never collects them -- this asserts the structural stripping holds
    // rather than that a drop list ran.
    for reserved in ["password_hash", "username", "expires_at"] {
        assert!(
            !record.fields.contains_key(reserved),
            "`{reserved}` is a storage field and must not reach the projected claims, where \
             `subject.claim.{reserved}` could render it into an upstream header"
        );
    }
    // And nothing hash-shaped arrived under another name.
    let rendered = format!("{:?}", record.fields);
    assert!(
        !rendered.contains("$2"),
        "no stored hash material may appear in the projected fields: {rendered}"
    );
}

#[tokio::test]
async fn a_record_projects_through_the_resolver_into_subject_claims() {
    let file = UserYamlFile::write(&alice_with_fields("correct horse"));
    let mut block = user_file_block(file.path());
    block["record_map"] = serde_json::json!({
        "subject": { "id": "user_id", "roles": "roles" },
    });
    let resolver = resolver(block).expect("the resolver loads");

    let result = resolve_with_header(
        &resolver,
        &crate::support::basic_header("alice", "correct horse"),
    )
    .await;

    assert_eq!(
        denial_code(&result),
        None,
        "a correct password against a YAML record must authenticate"
    );
    let subject = result
        .modified_payload
        .expect("a verified credential resolves")
        .subject
        .expect("the subject slot is filled");
    assert_eq!(
        subject.id.as_deref(),
        Some("alice"),
        "`subject.id` anchors on the verified user-id"
    );
    // A set, so membership rather than order is what the mapper promises.
    for role in ["admin", "auditor"] {
        assert!(
            subject.roles.contains(role),
            "the record's roles must reach `subject.roles`, which is the capability \
             `.htpasswd` cannot express; got {:?}",
            subject.roles
        );
    }
}

// -----------------------------------------------------------------------------
// Expiry (R25)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn a_record_past_its_expiry_denies_as_expired() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n    expires_at: \
         2020-01-01T00:00:00Z\n",
        bcrypt_hash("correct horse", 4)
    ));
    let resolver = resolver(user_file_block(file.path())).expect("the resolver loads");

    let result = resolve_with_header(
        &resolver,
        &crate::support::basic_header("alice", "correct horse"),
    )
    .await;

    assert_eq!(
        denial_code(&result),
        Some("auth.credential_expired".to_owned()),
        "a record past `expires_at` must deny as expired, distinctly from a wrong password: \
         the credential is right and the record is over"
    );
}

#[tokio::test]
async fn a_record_inside_its_expiry_still_authenticates() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n    expires_at: \
         2999-01-01T00:00:00Z\n",
        bcrypt_hash("correct horse", 4)
    ));
    let resolver = resolver(user_file_block(file.path())).expect("the resolver loads");

    let result = resolve_with_header(
        &resolver,
        &crate::support::basic_header("alice", "correct horse"),
    )
    .await;

    assert_eq!(
        denial_code(&result),
        None,
        "a future expiry must not deny: enforcement is mandatory, not eager"
    );
}

#[test]
fn an_unparseable_expiry_fails_at_load_rather_than_meaning_no_expiry() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n    expires_at: \
         not-a-timestamp\n",
        bcrypt_hash("correct horse", 4)
    ));

    let error = directory(&file).expect_err("an unparseable expiry must fail at load");
    assert!(
        error.contains("parsing"),
        "the error must name the parse rather than the password: {error}"
    );
    // R25's specific failure mode: a `String`-typed field would have
    // deserialized this and then silently meant "never expires".
    assert!(
        !error.contains("never"),
        "an unparseable expiry must not be reported as an absent one: {error}"
    );
}

#[test]
fn a_present_but_empty_expiry_fails_at_load() {
    for (spelling, value) in [("an explicit null", "~"), ("nothing at all", "")] {
        let file = UserYamlFile::write(&format!(
            "users:\n  - username: alice\n    password_hash: {}\n    expires_at: {value}\n",
            bcrypt_hash("correct horse", 4)
        ));

        let Err(error) = directory(&file) else {
            panic!(
                "`expires_at` written as {spelling} must fail at load: it reads to a human as \
                 an expiry that is set and to serde as absent, which is the silent \
                 never-expires outcome R25 exists to prevent"
            );
        };
        assert!(
            error.contains("expires_at"),
            "the error must name the field so an operator knows which key to fix: {error}"
        );
    }
}

#[tokio::test]
async fn a_record_with_no_expiry_key_never_expires() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));
    let dir = directory(&file).expect("a record with no expiry key loads");

    let record = dir
        .lookup("alice", &services())
        .await
        .expect("the lookup answers")
        .expect("alice is in the file");
    assert!(
        record.expires_at.is_none(),
        "omitting the key is the one way to say a record does not expire, and it must keep \
         working now that an empty value is refused"
    );
}

#[test]
fn an_expiry_that_is_a_date_without_a_time_fails_at_load() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n    expires_at: 2020-01-01\n",
        bcrypt_hash("correct horse", 4)
    ));

    // A bare date has no instant and no zone. Accepting one would have to
    // invent both, and the record it invented them for is a credential
    // lifetime.
    let error = directory(&file).expect_err("a zoneless date must fail at load");
    assert!(
        error.contains("parsing"),
        "the error must name the parse: {error}"
    );
}

// -----------------------------------------------------------------------------
// Duplicates and normalisation (R11, R4)
// -----------------------------------------------------------------------------

#[test]
fn a_duplicate_username_fails_at_load() {
    let hash = bcrypt_hash("correct horse", 4);
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {hash}\n  - username: alice\n    \
         password_hash: {hash}\n"
    ));

    let error = directory(&file).expect_err("a duplicate username must fail at load");
    assert!(
        error.contains("same username"),
        "the error must say the username collided, not merely that the file is invalid: {error}"
    );
    assert!(
        error.contains("alice"),
        "the error must name the colliding record so an operator can find it: {error}"
    );
}

#[test]
fn two_encodings_of_one_username_are_caught_as_duplicates() {
    let hash = bcrypt_hash("correct horse", 4);
    // Precomposed e-acute, then the decomposed spelling of the same name.
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: \"ren\u{00e9}\"\n    password_hash: {hash}\n  - username: \
         \"rene\u{0301}\"\n    password_hash: {hash}\n"
    ));

    let error = directory(&file)
        .expect_err("two spellings of one username must collide after normalisation");
    assert!(
        error.contains("same username"),
        "normalising before the duplicate check is what makes this a collision rather than a \
         silent overwrite that hands one caller the other's identity: {error}"
    );
}

#[tokio::test]
async fn a_non_nfc_stored_username_is_reachable_by_either_encoding() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: \"rene\u{0301}\"\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));
    let dir = directory(&file).expect("a decomposed username loads");
    let svc = services();

    // The resolver normalises an inbound user-id to NFC, so a stored name in
    // any other form has to be normalised identically at load or it is
    // unreachable.
    for spelling in ["ren\u{00e9}", "rene\u{0301}"] {
        let normalised: String = {
            use unicode_normalization::UnicodeNormalization as _;
            spelling.nfc().collect()
        };
        assert!(
            dir.lookup(&normalised, &svc)
                .await
                .expect("the lookup answers")
                .is_some(),
            "a stored non-NFC username must be reachable by the {spelling:?} spelling"
        );
    }
}

#[test]
fn an_empty_username_fails_at_load() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: \"\"\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));

    let error = directory(&file).expect_err("an empty username must fail at load");
    assert!(
        error.contains("empty username"),
        "the error must name the empty username: {error}"
    );
}

// -----------------------------------------------------------------------------
// The record shape (R13)
// -----------------------------------------------------------------------------

#[test]
fn malformed_yaml_fails_at_load() {
    let file = UserYamlFile::write("users:\n  - username: alice\n   password_hash: oops\n");
    let error = directory(&file).expect_err("malformed YAML must fail at load");
    assert!(
        error.contains("parsing"),
        "the error must name the parse: {error}"
    );
}

#[test]
fn an_unknown_top_level_key_fails_at_load() {
    let file = UserYamlFile::write(&format!(
        "user:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));

    // A misspelled envelope would otherwise load as an empty directory that
    // denies every request, which reads as an outage rather than the typo it
    // is.
    let error = directory(&file).expect_err("an unknown top-level key must fail at load");
    assert!(
        error.contains("parsing"),
        "the error must name the parse: {error}"
    );
}

#[test]
fn a_missing_required_storage_field_fails_at_load() {
    for (missing, body) in [
        ("password_hash", "users:\n  - username: alice\n".to_owned()),
        (
            "username",
            format!(
                "users:\n  - password_hash: {}\n",
                bcrypt_hash("correct horse", 4)
            ),
        ),
    ] {
        let file = UserYamlFile::write(&body);
        let Err(error) = directory(&file) else {
            panic!(
                "a record missing `{missing}` must fail at load: the record accepts arbitrary \
                 field names, so the required storage fields are the only thing still \
                 checkable about its shape"
            );
        };
        assert!(
            error.contains(missing),
            "the error must name the missing field so an operator can add it: {error}"
        );
    }
}

#[tokio::test]
async fn arbitrary_projectable_record_fields_are_accepted() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n    cost_centre: \"R-12\"\n    \
         clearance: 3\n    on_call: true\n",
        bcrypt_hash("correct horse", 4)
    ));
    let dir = directory(&file).expect("arbitrary record fields must load");

    let record = dir
        .lookup("alice", &services())
        .await
        .expect("the lookup answers")
        .expect("alice is in the file");

    // The record cannot use `deny_unknown_fields`: the names a policy is
    // written against are the operator's to choose, and a record rejecting
    // unknown keys would be `.htpasswd` with extra syntax.
    assert_eq!(
        record.fields.get("cost_centre"),
        Some(&serde_json::json!("R-12"))
    );
    assert_eq!(record.fields.get("clearance"), Some(&serde_json::json!(3)));
    assert_eq!(record.fields.get("on_call"), Some(&serde_json::json!(true)));
}

#[test]
fn no_load_error_carries_stored_hash_material() {
    let real = bcrypt_hash("correct horse", 4);

    for (shape, body) in [
        (
            "a record pasted as a bare `.htpasswd` line",
            format!("users:\n  - username: alice\n    password_hash: {real}\n  - bob:{real}\n"),
        ),
        (
            "a record list written as a map",
            format!("users:\n  alice: {real}\n"),
        ),
        (
            "a hash where a record was expected",
            format!("users:\n  - {real}\n"),
        ),
    ] {
        let file = UserYamlFile::write(&body);
        let Err(error) = directory(&file) else {
            panic!("{shape} must fail at load");
        };
        assert!(
            !error.contains(&real) && !error.contains("$2"),
            "a load error must carry no stored hash material: it is logged on every refresh \
             interval while the previous index keeps serving, so a verifier in it reaches \
             operator logs repeatedly and quietly. {shape} produced: {error}"
        );
        assert!(
            error.contains("parsing"),
            "the error must still name the parse so an operator can act on it: {error}"
        );
    }
}

#[tokio::test]
async fn no_reload_error_carries_stored_hash_material() {
    let real = bcrypt_hash("correct horse", 4);
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {real}\n"
    ));
    let dir = directory(&file).expect("the file loads");

    file.rewrite(&format!(
        "users:\n  - username: alice\n    password_hash: {real}\n  - bob:{real}\n"
    ));
    let Err(error) = dir.reload() else {
        panic!("a reload onto a malformed file must fail");
    };

    assert!(
        !error.contains(&real) && !error.contains("$2"),
        "the reload path is the one that matters: this string goes to `tracing::warn!` once \
         per refresh interval, forever, while authentication keeps working, so nothing \
         prompts an operator to notice. Got: {error}"
    );
    assert!(
        dir.lookup("alice", &services())
            .await
            .expect("the lookup answers")
            .is_some(),
        "the previous index must keep serving, which is what makes the leak quiet"
    );
}

#[test]
fn an_unreadable_path_fails_at_load() {
    let file = UserYamlFile::write(&alice_with_fields("correct horse"));
    file.unlink();

    let error = directory(&file).expect_err("an unreadable path must fail at load");
    assert!(
        error.contains("reading"),
        "the error must name the read: {error}"
    );
}

#[test]
fn an_empty_record_list_loads() {
    let file = UserYamlFile::write("users: []\n");
    let dir = directory(&file).expect("an empty record list loads");
    assert!(
        dir.is_empty(),
        "a file with no records is an empty directory, not a load error: it is what a \
         revocation that removed the last user leaves behind"
    );
}

// -----------------------------------------------------------------------------
// Uniform cost (R7)
// -----------------------------------------------------------------------------

#[test]
fn a_file_whose_records_cost_different_amounts_fails_at_load() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: cheap\n    password_hash: {}\n  - username: dear\n    \
         password_hash: {}\n",
        bcrypt_hash("correct horse", 4),
        bcrypt_hash("correct horse", 6),
    ));

    let error = directory(&file).expect_err("mixed bcrypt costs must fail at load");
    assert!(
        error.contains("One cost profile per file"),
        "the error must explain that mixed costs are an enumeration oracle: {error}"
    );
    assert!(
        error.contains("cost 4") && error.contains("cost 6"),
        "the error must name both costs so an operator can reconcile them: {error}"
    );
}

#[test]
fn a_file_mixing_schemes_fails_at_load() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: a\n    password_hash: {}\n  - username: b\n    password_hash: \
         {}\n",
        bcrypt_hash("correct horse", 4),
        argon2_at(19_456, 2, "correct horse"),
    ));

    let error = directory(&file).expect_err("mixing bcrypt with argon2 must fail at load");
    assert!(
        error.contains("One cost profile per file"),
        "work factors across schemes cannot be compared, so the file is refused: {error}"
    );
}

#[test]
fn a_uniform_file_loads_and_names_no_cost_conflict() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: a\n    password_hash: {}\n  - username: b\n    password_hash: \
         {}\n",
        bcrypt_hash("one", 4),
        bcrypt_hash("two", 4),
    ));

    let dir = directory(&file).expect("records at one cost load");
    assert_eq!(dir.len(), 2, "both records must be indexed");
}

#[tokio::test]
async fn a_miss_runs_the_same_cost_profile_as_every_hit() {
    let record = bcrypt_line("alice", "correct horse", 4);
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        record
            .split_once(':')
            .expect("the fixture line has a separator")
            .1
    ));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    assert_eq!(
        dir.miss_cost_profile(),
        cost_profile_of(&record),
        "the miss path must run one of the file's own records, so a miss costs exactly what a \
         hit costs rather than approximately"
    );

    let missing = dir
        .lookup("nobody", &svc)
        .await
        .expect("the lookup answers");
    assert!(missing.is_none(), "`nobody` is not in the file");
    assert!(
        !dir.verify(None, &crate::support::password("anything"), &svc)
            .await
            .expect("the verify answers"),
        "an unknown user must not authenticate"
    );
    assert_eq!(
        dir.dummy_runs(),
        1,
        "a miss must perform a dummy verification, asserted by counter rather than by timing"
    );
}

#[tokio::test]
async fn an_empty_directory_still_runs_a_dummy_on_a_miss() {
    let file = UserYamlFile::write("users: []\n");
    let dir = directory(&file).expect("an empty file loads");
    let svc = services();

    assert!(
        dir.lookup("alice", &svc)
            .await
            .expect("the lookup answers")
            .is_none(),
        "an empty directory knows nobody"
    );
    assert!(
        !dir.verify(None, &crate::support::password("anything"), &svc)
            .await
            .expect("the verify answers"),
        "an unknown user must not authenticate"
    );
    assert_eq!(
        dir.dummy_runs(),
        1,
        "a file with no records has no record to reuse, so it mints a floor hash and still \
         pays a full verify: answering in nanoseconds would make an empty directory \
         distinguishable from a populated one by timing alone"
    );
    assert!(
        matches!(
            dir.miss_cost_profile(),
            praxis_policy_builtins::plugins::identity_basic::CostProfile::Bcrypt { .. }
        ),
        "the synthesized floor hash is the one case where a cost is chosen rather than taken \
         from the file, got {:?}",
        dir.miss_cost_profile()
    );
}

#[tokio::test]
async fn a_reload_onto_mixed_costs_is_refused_and_the_uniform_index_keeps_serving() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));
    let dir = directory(&file).expect("the file loads");

    file.rewrite(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n  - username: bob\n    \
         password_hash: {}\n",
        bcrypt_hash("correct horse", 4),
        bcrypt_hash("hunter2", 6),
    ));

    let error = dir
        .reload()
        .expect_err("a reload onto mixed costs must fail");
    assert!(
        error.contains("One cost profile per file"),
        "the refusal must be the uniformity rule, on refresh as at load: {error}"
    );
    assert_eq!(
        dir.len(),
        1,
        "the previous uniform index must keep serving rather than being emptied by a failed \
         reload"
    );
    assert!(
        dir.lookup("bob", &services())
            .await
            .expect("the lookup answers")
            .is_none(),
        "the record from the refused file must not be reachable"
    );
}

// -----------------------------------------------------------------------------
// Parameter ceilings (R23) and the password ceiling (R26)
// -----------------------------------------------------------------------------

#[test]
fn a_cost_above_the_ceiling_fails_at_load() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 6)
    ));
    let config: UserFileConfig = serde_yaml::from_str(&format!(
        "path: {}\nrefresh_secs: 30\nmax_staleness_secs: 300\nlimits:\n  max_bcrypt_cost: 5\n",
        file.path()
    ))
    .expect("the backend config parses");

    let error =
        UserFileDirectory::new(config).expect_err("a cost above the ceiling must fail at load");
    assert!(
        !error.is_empty(),
        "a well-formed but over-parameterised record must be refused at load, where one login \
         cannot be turned into a denial of service"
    );
}

#[test]
fn a_bcrypt_file_is_refused_under_a_ceiling_bcrypt_cannot_honour() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));

    let error = directory_with_ceiling(&file, 200)
        .expect_err("a bcrypt file above the truncation point must be refused");
    assert!(
        error.contains("truncation"),
        "the error must name bcrypt's truncation point, which is why the ceiling cannot be \
         honoured: {error}"
    );
}

#[test]
fn an_argon2_file_loads_under_a_ceiling_bcrypt_could_not_honour() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        argon2_at(19_456, 2, "correct horse")
    ));

    directory_with_ceiling(&file, 200)
        .expect("argon2 consumes the whole password, so a large ceiling is coherent with it");
}

#[tokio::test]
async fn a_reload_onto_bcrypt_is_refused_under_a_ceiling_bcrypt_cannot_honour() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        argon2_at(19_456, 2, "correct horse")
    ));
    let dir = directory_with_ceiling(&file, 200).expect("an argon2 file loads under the ceiling");

    file.rewrite(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));

    let error = dir
        .reload()
        .expect_err("a reload that changes the scheme must re-check the ceiling");
    assert!(
        error.contains("truncation"),
        "the ceiling is re-checked on every load, so a file swapped to bcrypt is refused \
         rather than published under a ceiling the verifier would then always reject: {error}"
    );
}

// -----------------------------------------------------------------------------
// Refresh, staleness and capacity (R12)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn a_revoked_user_stops_authenticating_after_a_reload() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n  - username: bob\n    \
         password_hash: {}\n",
        bcrypt_hash("correct horse", 4),
        bcrypt_hash("hunter2", 4),
    ));
    let dir = directory(&file).expect("the file loads");
    let svc = services();

    assert!(
        dir.lookup("bob", &svc)
            .await
            .expect("the lookup answers")
            .is_some(),
        "bob authenticates before the revocation"
    );

    file.rewrite(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));
    dir.reload().expect("the reload lands");

    assert!(
        dir.lookup("bob", &svc)
            .await
            .expect("the lookup answers")
            .is_none(),
        "a record removed from the file must stop authenticating once the reload lands: the \
         refresh interval is this backend's revocation window"
    );
}

#[tokio::test]
async fn a_failed_reload_keeps_the_previous_index_serving() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));
    let dir = directory(&file).expect("the file loads");

    file.unlink();
    dir.reload()
        .expect_err("a reload of a deleted file must fail");

    assert!(
        dir.lookup("alice", &services())
            .await
            .expect("the lookup answers")
            .is_some(),
        "a failed reload must leave the running index serving: emptying it would turn a blip \
         into a total authentication outage"
    );
}

#[tokio::test]
async fn past_the_staleness_ceiling_lookups_report_unavailable_not_unknown() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));
    let config: UserFileConfig = serde_yaml::from_str(&format!(
        "path: {}\nrefresh_secs: 1\nmax_staleness_secs: 1\n",
        file.path()
    ))
    .expect("the backend config parses");
    let dir = UserFileDirectory::new(config).expect("the file loads");

    file.unlink();
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let outcome = dir.lookup("alice", &services()).await;
    assert!(
        matches!(
            outcome,
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Stale)
        ),
        "past the ceiling a lookup must report that it cannot answer, not that the user does \
         not exist: an operator needs to see an outage rather than a wave of bad passwords, \
         got {outcome:?}"
    );
}

#[test]
fn a_config_omitting_the_staleness_ceiling_fails_to_load() {
    let file = UserYamlFile::write("users: []\n");
    let parsed: Result<UserFileConfig, _> =
        serde_yaml::from_str(&format!("path: {}\nrefresh_secs: 30\n", file.path()));
    assert!(
        parsed.is_err(),
        "the staleness ceiling is required on this backend: there is no value meaning `no \
         ceiling`, so omitting it cannot silently mean one"
    );
}

#[test]
fn a_ceiling_below_the_refresh_interval_fails_validation() {
    let file = UserYamlFile::write("users: []\n");
    let config: UserFileConfig = serde_yaml::from_str(&format!(
        "path: {}\nrefresh_secs: 60\nmax_staleness_secs: 30\n",
        file.path()
    ))
    .expect("the backend config parses");

    let error = UserFileDirectory::new(config)
        .expect_err("a ceiling below the refresh interval must fail validation");
    assert!(
        error.contains("below `refresh_secs`"),
        "such a config would fail closed before the first reload is even due: {error}"
    );
}

#[test]
fn a_zero_concurrency_cap_fails_validation() {
    let file = UserYamlFile::write("users: []\n");
    let config: UserFileConfig = serde_yaml::from_str(&format!(
        "path: {}\nrefresh_secs: 30\nmax_staleness_secs: 300\nmax_concurrent_verifications: 0\n",
        file.path()
    ))
    .expect("the backend config parses");

    let error = UserFileDirectory::new(config).expect_err("a zero cap must fail validation");
    assert!(
        error.contains("at least 1"),
        "a zero cap denies every request: {error}"
    );
}

#[tokio::test]
async fn a_burst_of_lookups_triggers_one_file_read() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 4)
    ));
    let config: UserFileConfig = serde_yaml::from_str(&format!(
        "path: {}\nrefresh_secs: 1\nmax_staleness_secs: 300\n",
        file.path()
    ))
    .expect("the backend config parses");
    let dir = std::sync::Arc::new(UserFileDirectory::new(config).expect("the file loads"));

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let mut handles = Vec::new();
    for _ in 0..16 {
        let dir = std::sync::Arc::clone(&dir);
        handles.push(tokio::spawn(async move {
            let _ = dir.lookup("alice", &services()).await;
        }));
    }
    for handle in handles {
        handle.await.expect("the lookup task completes");
    }

    assert_eq!(
        dir.reload_attempts(),
        1,
        "the refresh slot is claimed by one lookup at a time, so a burst costs one file read \
         rather than one each"
    );
}

#[tokio::test]
async fn concurrent_verifications_beyond_the_cap_deny_rather_than_queue() {
    let file = UserYamlFile::write(&format!(
        "users:\n  - username: alice\n    password_hash: {}\n",
        bcrypt_hash("correct horse", 10)
    ));
    let config: UserFileConfig = serde_yaml::from_str(&format!(
        "path: {}\nrefresh_secs: 30\nmax_staleness_secs: 300\nmax_concurrent_verifications: 1\n",
        file.path()
    ))
    .expect("the backend config parses");
    let dir = std::sync::Arc::new(UserFileDirectory::new(config).expect("the file loads"));
    let svc = services();

    let record = dir
        .lookup("alice", &svc)
        .await
        .expect("the lookup answers")
        .expect("alice is in the file");
    let record = std::sync::Arc::new(record);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let dir = std::sync::Arc::clone(&dir);
        let record = std::sync::Arc::clone(&record);
        handles.push(tokio::spawn(async move {
            dir.verify(
                Some(&record),
                &crate::support::password("correct horse"),
                &services(),
            )
            .await
        }));
    }

    let mut saturated = 0_usize;
    for handle in handles {
        if matches!(
            handle.await.expect("the verify task completes"),
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Saturated)
        ) {
            saturated = saturated.saturating_add(1);
        }
    }

    assert!(
        saturated > 0,
        "beyond the cap a verification must deny rather than queue: a queue here is an \
         unauthenticated CPU exhaustion path"
    );
}

// -----------------------------------------------------------------------------
// The directory contract
// -----------------------------------------------------------------------------

#[test]
fn the_kind_string_is_the_documented_one() {
    let file = UserYamlFile::write("users: []\n");
    let dir = directory(&file).expect("an empty file loads");
    assert_eq!(
        dir.kind(),
        "user_file",
        "the `kind:` string is part of this crate's public API"
    );
}

#[tokio::test]
async fn a_file_backend_refuses_a_delegated_verdict() {
    use praxis_policy_builtins::plugins::identity_basic::{StoredVerifier, UserRecord};

    let file = UserYamlFile::write("users: []\n");
    let dir = directory(&file).expect("an empty file loads");
    let record = UserRecord::verifier_only(StoredVerifier::Delegated { valid: true });

    let outcome = dir
        .verify(
            Some(&record),
            &crate::support::password("anything"),
            &services(),
        )
        .await;
    assert!(
        matches!(
            outcome,
            Err(praxis_policy_builtins::plugins::identity_basic::DirectoryError::Malformed(_))
        ),
        "a delegated verdict cannot arrive from a file backend, and must not be honoured as \
         one: got {outcome:?}"
    );
}
