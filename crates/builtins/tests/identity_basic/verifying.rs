// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hash-scheme admission, the parameter ceiling, and the properties that keep
//! a verify from leaking which users exist.

use praxis_policy_builtins::plugins::identity_basic::verifier::{
    BCRYPT_TRUNCATION_BYTES, CostProfile, HashError, Limits, Scheme, empty_directory_hash,
    parse_hash,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn bcrypt_records_load_in_every_spelling() {
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
    for (stored, reason) in [
        (
            "$2y$ZZ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "nonnumeric cost",
        ),
        ("$2y$04$tooshort", "incorrect length"),
        (
            "$2y$04$aaaaaaaaaaaaaaaaaaaaa£aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "non-ASCII bytes",
        ),
    ] {
        assert_eq!(
            parse_hash(stored, &Limits::default()).err(),
            Some(HashError::Malformed),
            "a bcrypt record with {reason} must fail at load"
        );
    }
}

#[test]
fn a_bcrypt_record_the_verifier_cannot_decode_fails_at_load() {
    let minted = bcrypt_at(4, "pw");
    let prefix = minted
        .get(..7)
        .expect("a bcrypt record is longer than its cost prefix");
    let salt = minted.get(7..29).expect("a bcrypt salt is 22 characters");
    let digest = minted.get(29..).expect("a bcrypt digest is 31 characters");
    let salt_head = salt
        .get(..21)
        .expect("the salt is longer than one character");
    let digest_head = digest
        .get(..30)
        .expect("the digest is longer than one character");

    for (forged, reason) in [
        (
            format!("{prefix}{}", "!".repeat(53)),
            "a character in no base alphabet",
        ),
        (
            format!("{prefix}{}", "+".repeat(53)),
            "a standard-base64 character bcrypt does not use",
        ),
        (
            format!("{prefix}{}", "=".repeat(53)),
            "base64 padding, which bcrypt never emits",
        ),
        (
            format!("{prefix}{salt_head}z{digest}"),
            "an in-alphabet salt character whose spare bits are not zero",
        ),
        (
            format!("{prefix}{salt}{digest_head}z"),
            "an in-alphabet digest character whose spare bits are not zero",
        ),
    ] {
        assert_eq!(
            forged.len(),
            60,
            "the forged record carrying {reason} must be the right length, so \
             only the encoding check can reject it"
        );
        assert!(
            bcrypt::verify("pw", &forged).is_err(),
            "precondition: bcrypt itself refuses {reason} before running the KDF"
        );
        assert_eq!(
            parse_hash(&forged, &Limits::default()).err(),
            Some(HashError::Malformed),
            "a bcrypt record carrying {reason} must fail at load: the verifier \
             rejects it before the KDF, so admitting it would answer in \
             nanoseconds where a real record takes milliseconds and reveal \
             that the user-id exists"
        );
    }
}

#[test]
fn a_bcrypt_cost_above_the_ceiling_fails_at_load() {
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
fn the_empty_directory_hash_is_a_real_record_that_verifies_in_full() {
    let dummy = empty_directory_hash().expect("the empty-directory hash mints");
    assert_eq!(
        dummy.scheme(),
        Scheme::Bcrypt,
        "the dummy is a real bcrypt record the verifier runs in full"
    );
    assert_eq!(
        dummy.profile(),
        CostProfile::Bcrypt { cost: 10 },
        "and it carries the work factor it was asked for"
    );
}

#[test]
fn a_password_past_bcrypts_truncation_point_is_rejected() {
    let seventy_two = "A".repeat(BCRYPT_TRUNCATION_BYTES);
    let longer = format!("{seventy_two}COMPLETELY-DIFFERENT-TAIL");

    let stored = bcrypt_at(4, &seventy_two);
    assert_eq!(
        bcrypt::verify(&longer, &stored).ok(),
        Some(true),
        "precondition: bcrypt itself accepts the over-length password"
    );

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

    let delegated = UserRecord::verifier_only(StoredVerifier::Delegated { valid: true });
    assert!(
        format!("{delegated:?}").contains("true"),
        "a delegated verdict carries nothing crackable and should stay visible"
    );
}

/// An out-of-tree backend, implemented from outside the plugin's module tree.
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

#[test]
fn a_debug_formatted_parsed_hash_redacts_the_stored_record() {
    let stored = bcrypt_at(4, "pw");
    let parsed = parse_hash(&stored, &Limits::default()).expect("loads");

    let printed = format!("{parsed:?}");
    assert!(
        !printed.contains(&stored),
        "the stored record must not appear in Debug output, got: {printed}"
    );
    assert!(
        !printed.contains("$2"),
        "nor any part of the modular-crypt record, got: {printed}"
    );
    assert!(
        printed.contains("redacted"),
        "and the field should read as withheld rather than absent, got: {printed}"
    );
    assert!(
        printed.contains("Bcrypt"),
        "the scheme stays visible for diagnostics, got: {printed}"
    );
}

#[test]
fn a_cost_profile_compares_by_equality_not_by_order() {
    let four = parse_hash(&bcrypt_at(4, "pw"), &Limits::default()).expect("loads");
    let four_again = parse_hash(&bcrypt_at(4, "pw"), &Limits::default()).expect("loads");
    let twelve = parse_hash(&bcrypt_at(12, "pw"), &Limits::default()).expect("loads");

    assert_eq!(
        four.profile(),
        four_again.profile(),
        "two records minted at the same cost share a profile"
    );
    assert_ne!(
        four.profile(),
        twelve.profile(),
        "records at different costs must not share a profile, since that is \
         what the load-time uniformity check compares; CostProfile offers no \
         ordering because argon2 trades memory against passes, so m=4096,t=10 \
         (14ms) would rank above m=65536,t=2 (37ms) on any single number"
    );
}

#[test]
fn argon2_records_differing_in_any_parameter_have_different_profiles() {
    let base = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
                MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";
    let reference = parse_hash(base, &Limits::default()).expect("the base record loads");

    for (label, variant) in [
        ("memory", base.replace("m=19456", "m=8192")),
        ("passes", base.replace("t=2", "t=3")),
        ("parallelism", base.replace("p=1", "p=2")),
        ("variant", base.replace("argon2id", "argon2i")),
    ] {
        let other = parse_hash(&variant, &Limits::default())
            .unwrap_or_else(|e| panic!("the {label} variant should load: {e}"));
        assert_ne!(
            reference.profile(),
            other.profile(),
            "a record differing in {label} must not share the base profile: \
             every parameter affects verify cost, and the variant and version \
             change the function rather than only its tuning"
        );
    }
}

#[test]
fn a_hash_exactly_at_the_parameter_ceiling_is_accepted() {
    let at_limit = Limits {
        max_bcrypt_cost: 6,
        ..Limits::default()
    };
    parse_hash(&bcrypt_at(6, "pw"), &at_limit)
        .expect("a cost equal to the ceiling is within it, not over");

    assert_eq!(
        parse_hash(&bcrypt_at(7, "pw"), &at_limit).err(),
        Some(HashError::ParametersTooHigh),
        "one above the ceiling is refused, so the boundary is inclusive"
    );
}

#[test]
fn argon2_parameters_exactly_at_each_ceiling_are_accepted() {
    let base = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
                MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI";
    let at_limit = Limits {
        max_argon2_memory_kib: 19_456,
        max_argon2_time_cost: 2,
        ..Limits::default()
    };
    parse_hash(base, &at_limit).expect("memory and passes equal to their ceilings are within them");

    let over_memory = Limits {
        max_argon2_memory_kib: 19_455,
        ..at_limit
    };
    assert_eq!(
        parse_hash(base, &over_memory).err(),
        Some(HashError::ParametersTooHigh),
        "one KiB above the memory ceiling is refused"
    );

    let over_time = Limits {
        max_argon2_time_cost: 1,
        ..at_limit
    };
    assert_eq!(
        parse_hash(base, &over_time).err(),
        Some(HashError::ParametersTooHigh),
        "and one pass above the time ceiling is refused, so each dimension is \
         checked against its own limit rather than the pair being conflated"
    );
}

#[test]
fn a_bcrypt_cost_outside_the_library_range_fails_at_load() {
    let minted = bcrypt_at(4, "pw");
    let tail = minted
        .get(7..)
        .expect("a bcrypt record is longer than its cost prefix");

    for (label, cost) in [("below the minimum", "03"), ("above the maximum", "32")] {
        let record = format!("$2b${cost}${tail}");
        assert_eq!(
            parse_hash(&record, &Limits::default()).err(),
            Some(HashError::Malformed),
            "a cost {label} of the library's accepted range must fail at load, \
             since the verifier would otherwise reject it before the KDF and \
             make that user-id faster to probe"
        );
    }
}

#[test]
fn an_argon2_record_missing_its_salt_or_digest_fails_at_load() {
    for (label, record) in [
        (
            "no digest",
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0".to_owned(),
        ),
        (
            "no salt or digest",
            "$argon2id$v=19$m=19456,t=2,p=1".to_owned(),
        ),
    ] {
        assert_eq!(
            parse_hash(&record, &Limits::default()).err(),
            Some(HashError::Malformed),
            "a record with {label} must fail at load: argon2 errors out before \
             the KDF without them, which is the same timing signal as any other \
             early rejection"
        );
    }
}

#[test]
fn a_cost_profile_describes_its_own_parameters() {
    let bcrypt = parse_hash(&bcrypt_at(9, "pw"), &Limits::default()).expect("loads");
    let described = bcrypt.profile().describe();
    assert!(
        described.contains('9'),
        "a bcrypt description names its cost, which an operator reconciling two \
         records needs to see: {described}"
    );
    assert!(
        described.contains("bcrypt"),
        "and names the scheme: {described}"
    );

    let argon2 = parse_hash(
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$\
         MOUsGI8r0i0dSn9k0rLmvL2mNj8D0nQ0jQX1QmXKjQI",
        &Limits::default(),
    )
    .expect("loads");
    let described = argon2.profile().describe();
    for expected in ["19456", "t=2", "p=1", "argon2id"] {
        assert!(
            described.contains(expected),
            "an argon2 description names {expected}, since every parameter is \
             part of what the uniformity check compares: {described}"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A bcrypt record at a given cost, minted rather than checked in.
fn bcrypt_at(cost: u32, password: &str) -> String {
    bcrypt::hash(password, cost).expect("bcrypt mints at a legal cost")
}
