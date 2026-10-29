// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hash-scheme admission, the parameter ceiling, and the properties that keep
//! a verify from leaking which users exist.

use praxis_policy_builtins::plugins::identity_basic::verifier::{
    BCRYPT_TRUNCATION_BYTES, HashError, Limits, Scheme, WorkFactor, floor_hash, parse_hash,
};

/// A bcrypt record at a given cost, minted rather than checked in.
fn bcrypt_at(cost: u32, password: &str) -> String {
    bcrypt::hash(password, cost).expect("bcrypt mints at a legal cost")
}

#[test]
fn bcrypt_records_load_in_every_spelling() {
    // R8: `.htpasswd` in the wild carries all three variant markers, and they
    // differ only in which historical bug the writer was avoiding.
    let minted = bcrypt_at(4, "pw");
    for variant in ["$2a$", "$2b$", "$2y$"] {
        let tail = minted
            .get(4..)
            .expect("a bcrypt record is longer than its variant marker");
        let swapped = format!("{variant}{tail}");
        let parsed = parse_hash(&swapped, &Limits::default())
            .unwrap_or_else(|e| panic!("{variant} should load: {e}"));
        assert_eq!(
            parsed.scheme(),
            Scheme::Bcrypt,
            "{variant} is a bcrypt spelling and must be read as one"
        );
    }
}

#[test]
fn an_argon2_record_loads() {
    // R8. A PHC string with explicit parameters, which is how argon2 is stored.
    let phc = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
               MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";
    let parsed = parse_hash(phc, &Limits::default()).expect("an argon2 record loads");
    assert_eq!(
        parsed.scheme(),
        Scheme::Argon2,
        "a PHC argon2 record reads as argon2"
    );
}

#[test]
fn des_crypt_and_plaintext_are_refused() {
    // R8: refused outright, not gated behind an opt-in. A 13-character DES
    // record has a keyspace a laptop exhausts, and a plaintext "hash" is not a
    // verifier at all.
    for stored in ["abJnggxhB/yWI", "hunter2", ""] {
        assert_eq!(
            parse_hash(stored, &Limits::default()).err(),
            Some(HashError::RefusedScheme),
            "{stored:?} must be refused"
        );
    }
}

#[test]
fn md5_and_sha1_grade_schemes_are_refused_with_an_actionable_reason() {
    // R8. These are recognised rather than lumped in with corruption, so the
    // load error can tell an operator to re-hash rather than suggesting the
    // file is damaged.
    for stored in [
        "$apr1$abcdefgh$1234567890123456789012",
        "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=",
    ] {
        let err = parse_hash(stored, &Limits::default())
            .expect_err("an MD5/SHA-1 grade scheme is not verified here");
        assert_eq!(
            err,
            HashError::WeakSchemeUnsupported,
            "an MD5/SHA-1 grade scheme is refused as weak, not as corrupt"
        );
        let message = err.to_string();
        assert!(
            message.contains("re-hash"),
            "the error should name the fix, got: {message}"
        );
    }
}

#[test]
fn a_malformed_bcrypt_record_fails_at_load() {
    // R8. The prefix says bcrypt, so this is corruption rather than another
    // scheme, and it must not reach a request.
    for stored in [
        "$2y$ZZ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // cost not a number
        "$2y$04$tooshort",                                               // wrong length
        "$2y$04$aaaaaaaaaaaaaaaaaaaaa£aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",   // non-ASCII
    ] {
        assert_eq!(
            parse_hash(stored, &Limits::default()).err(),
            Some(HashError::Malformed),
            "{stored:?} must fail at load"
        );
    }
}

#[test]
fn a_bcrypt_cost_above_the_ceiling_fails_at_load() {
    // R23: well-formed but extreme. One login at cost 20 is seconds of CPU the
    // caller does not have to authenticate to spend, so this is an availability
    // control, not a hygiene one.
    let limits = Limits {
        max_bcrypt_cost: 10,
        ..Limits::default()
    };
    let hot = bcrypt_at(12, "pw");
    assert_eq!(
        parse_hash(&hot, &limits).err(),
        Some(HashError::ParametersTooHigh),
        "a well-formed cost above the ceiling is an availability risk, not a \
         parse problem, so it must be refused at load rather than at verify"
    );
    parse_hash(&hot, &Limits::default()).expect("the same record loads once the ceiling admits it");
}

#[test]
fn argon2_parameters_above_the_ceiling_fail_at_load() {
    // R23, the other scheme's axes: memory and passes.
    let phc = "$argon2id$v=19$m=1048576,t=8,p=1$c2FsdHNhbHRzYWx0$\
               MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";
    let tight = Limits {
        max_argon2_memory_kib: 65536,
        ..Limits::default()
    };
    assert_eq!(
        parse_hash(phc, &tight).err(),
        Some(HashError::ParametersTooHigh),
        "argon2 memory above the ceiling is refused at load"
    );

    let tight_time = Limits {
        max_argon2_time_cost: 2,
        ..Limits::default()
    };
    assert_eq!(
        parse_hash(phc, &tight_time).err(),
        Some(HashError::ParametersTooHigh),
        "and so is an argon2 time cost above the ceiling"
    );
}

#[test]
fn the_work_factor_orders_records_so_a_directory_has_one_worst_case() {
    // KTD9: the miss path must run at the maximum present, not the dominant
    // one, so a `WorkFactor` from either scheme has to be comparable.
    let cheap = parse_hash(&bcrypt_at(4, "pw"), &Limits::default()).expect("loads");
    let dear = parse_hash(&bcrypt_at(8, "pw"), &Limits::default()).expect("loads");
    assert!(
        dear.work_factor() > cheap.work_factor(),
        "a higher bcrypt cost must order above a lower one"
    );

    let argon = parse_hash(
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
         MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI",
        &Limits::default(),
    )
    .expect("loads");
    // The point is only that they are on one axis, so a max() across a mixed
    // directory is meaningful. Which is larger is not a guarantee this makes.
    let worst = [cheap.work_factor(), dear.work_factor(), argon.work_factor()]
        .into_iter()
        .max()
        .expect("three factors");
    assert!(
        worst >= dear.work_factor() && worst >= argon.work_factor(),
        "a max() across a mixed directory must dominate every record in it"
    );
}

#[test]
fn the_floor_hash_is_a_real_record_that_verifies_in_full() {
    // KTD9: a malformed miss-path hash would be rejected early and cost
    // nothing, which is exactly the leak it exists to close. So the fallback
    // minted for an empty directory must be a valid record.
    let dummy = floor_hash(WorkFactor::FLOOR).expect("the floor hash mints");
    assert_eq!(
        dummy.scheme(),
        Scheme::Bcrypt,
        "the dummy is a real bcrypt record the verifier runs in full"
    );
    assert_eq!(
        dummy.work_factor(),
        WorkFactor::FLOOR,
        "and it carries the work factor it was asked for"
    );
}

#[test]
fn a_password_past_bcrypts_truncation_point_is_rejected() {
    // R26, and this is a real vulnerability rather than a hygiene rule: bcrypt
    // feeds at most 72 bytes to the KDF, so without this guard a 92-byte
    // password authenticates against a hash minted from its first 72 -- two
    // different passwords, one accepted.
    let seventy_two = "A".repeat(BCRYPT_TRUNCATION_BYTES);
    let longer = format!("{seventy_two}COMPLETELY-DIFFERENT-TAIL");

    // Proof the underlying library really does collide, so this test is
    // guarding something that happens rather than something theoretical.
    let stored = bcrypt_at(4, &seventy_two);
    assert_eq!(
        bcrypt::verify(&longer, &stored).ok(),
        Some(true),
        "precondition: bcrypt itself accepts the over-length password"
    );

    // And the plugin refuses it.
    let parsed = parse_hash(&stored, &Limits::default()).expect("loads");
    assert!(
        !crate::support::verify_password(&parsed, longer.as_bytes()),
        "an over-length password must not authenticate on a 72-byte prefix match"
    );
    assert!(
        crate::support::verify_password(&parsed, seventy_two.as_bytes()),
        "the password that was actually hashed still verifies"
    );
}

#[test]
fn a_correct_password_verifies_and_a_wrong_one_does_not() {
    let parsed = parse_hash(&bcrypt_at(4, "correct horse"), &Limits::default()).expect("loads");
    assert!(
        crate::support::verify_password(&parsed, b"correct horse"),
        "the password the hash was minted from must verify"
    );
    assert!(
        !crate::support::verify_password(&parsed, b"wrong horse"),
        "and any other password must not"
    );
}

#[test]
fn a_debug_formatted_record_redacts_the_stored_hash() {
    // A stored hash is an offline-crackable verifier, and `UserRecord` derives
    // `Debug` over its verifier, so a derived `Debug` here would write the
    // scheme, cost and salt into the log at the first `debug!("{record:?}")`
    // or failed `unwrap()`. The field doc claims "never logged"; this is what
    // keeps that claim true.
    use praxis_policy_builtins::plugins::identity_basic::{StoredVerifier, UserRecord};

    let stored = "$2y$04$UNIQUE.SALT.AND.DIGEST.MATERIAL.THAT.MUST.NOT.PRINT";
    let record = UserRecord::verifier_only(StoredVerifier::Hash(stored.to_owned()));

    let printed = format!("{record:?}");
    assert!(
        !printed.contains("UNIQUE.SALT"),
        "a Debug-formatted record must not carry the stored hash, got: {printed}"
    );
    assert!(
        !printed.contains("$2y$"),
        "nor the scheme prefix, which narrows an offline attack, got: {printed}"
    );
    assert!(
        printed.contains("redacted"),
        "and it should say the value was withheld rather than look absent, got: {printed}"
    );

    // The delegated verdict is a boolean and stays readable: a diagnostic that
    // cannot show whether a service said yes or no is not worth having.
    let delegated = UserRecord::verifier_only(StoredVerifier::Delegated { valid: true });
    assert!(
        format!("{delegated:?}").contains("true"),
        "a delegated verdict carries nothing crackable and should stay visible"
    );
}

/// An out-of-tree backend, implemented from outside the plugin's module tree.
///
/// This type exists to pin the trait's usability rather than to test behaviour:
/// `CredentialDirectory` is public, so a host adapter — the Kubernetes `Secret`
/// backend the plan defers, for one — must be able to implement it using only
/// public API. An earlier draft took the plugin-private password type, which
/// made that impossible; this is what stops that regressing.
#[derive(Debug)]
struct OutOfTreeDirectory {
    expected_user: String,
    expected_password: Vec<u8>,
}

#[async_trait::async_trait]
impl praxis_policy_builtins::plugins::identity_basic::CredentialDirectory for OutOfTreeDirectory {
    async fn lookup(
        &self,
        user_id: &str,
        _services: &dyn praxis_policy_core::host::HostServices,
    ) -> Result<
        Option<praxis_policy_builtins::plugins::identity_basic::UserRecord>,
        praxis_policy_builtins::plugins::identity_basic::DirectoryError,
    > {
        use praxis_policy_builtins::plugins::identity_basic::{StoredVerifier, UserRecord};
        Ok((user_id == self.expected_user)
            .then(|| UserRecord::verifier_only(StoredVerifier::Delegated { valid: true })))
    }

    async fn verify(
        &self,
        record: Option<&praxis_policy_builtins::plugins::identity_basic::UserRecord>,
        credential: &praxis_policy_builtins::plugins::identity_basic::BasicCredential,
        _services: &dyn praxis_policy_core::host::HostServices,
    ) -> Result<bool, praxis_policy_builtins::plugins::identity_basic::DirectoryError> {
        // Reaches the password through public API only. The owned copy is
        // zeroizing, which is the contract the plugin's own backends use.
        let presented = credential.to_zeroized_password();
        Ok(record.is_some() && presented.as_slice() == self.expected_password.as_slice())
    }

    fn kind(&self) -> &'static str {
        "out-of-tree-test"
    }
}

#[tokio::test]
async fn the_directory_trait_is_implementable_from_outside_the_plugin() {
    use praxis_policy_builtins::plugins::identity_basic::CredentialDirectory as _;

    let dir = OutOfTreeDirectory {
        expected_user: "alice".to_owned(),
        expected_password: b"pw".to_vec(),
    };
    let svc = crate::support::services();

    let found = dir.lookup("alice", &svc).await.expect("the lookup answers");
    assert!(found.is_some(), "a public-API backend can return a record");
    assert!(
        dir.verify(found.as_ref(), &crate::support::password("pw"), &svc)
            .await
            .expect("the verify answers"),
        "and can verify a credential using only public API"
    );
    assert!(
        !dir.verify(found.as_ref(), &crate::support::password("wrong"), &svc)
            .await
            .expect("the verify answers"),
        "and rejects a wrong password"
    );
}
