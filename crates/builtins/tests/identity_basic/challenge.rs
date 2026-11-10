// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The 401 challenge on a denial this resolver raises, the single denial code
//! an unknown user and a wrong password share, the wrong-scheme decline, and
//! the failure limiter.

use praxis_policy_builtins::plugins::identity_basic::codes;

use crate::support::{
    HtpasswdFile, basic_header, bcrypt_line, challenge_of, denial_code, htpasswd_block,
    resolve_with_header, resolver,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// A denial carries 401 and the `WWW-Authenticate: Basic` challenge per
/// [RFC 7617 Section 2] and the [RFC 7235 Section 4.1] framework.
///
/// [RFC 7617 Section 2]: https://datatracker.ietf.org/doc/html/rfc7617#section-2
/// [RFC 7235 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
#[tokio::test]
async fn a_denial_carries_401_and_the_realm_challenge() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;

    let violation = result.violation.as_ref().expect("a wrong password denies");
    assert_eq!(
        violation.proto_error_code,
        Some(401),
        "a denial this resolver raises is a 401, so the caller knows to retry with a credential"
    );
    assert_eq!(
        challenge_of(&result).as_deref(),
        Some("Basic realm=\"ops\""),
        "the challenge rides the violation's `http.headers` details key for the host to render"
    );
}

#[tokio::test]
async fn the_configured_charset_reaches_the_challenge_on_a_denial() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["charset_utf8"] = serde_json::json!(true);
    let resolver = resolver(block).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;

    assert_eq!(
        challenge_of(&result).as_deref(),
        Some("Basic realm=\"ops\", charset=\"UTF-8\""),
        "the charset parameter must reach the header value, not just the config"
    );
}

#[tokio::test]
async fn an_unknown_user_and_a_bad_password_deny_identically() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let unknown = resolve_with_header(&resolver, &basic_header("nobody", "correct horse")).await;
    let wrong = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;

    let unknown = unknown.violation.expect("an unknown user denies");
    let wrong = wrong.violation.expect("a wrong password denies");
    assert_eq!(
        unknown.code,
        codes::INVALID_CREDENTIALS,
        "both must carry the shared code"
    );
    assert_eq!(
        (&unknown.code, &unknown.reason, unknown.proto_error_code),
        (&wrong.code, &wrong.reason, wrong.proto_error_code),
        "a client able to tell these apart could enumerate user-ids without guessing a password"
    );
    assert_eq!(
        unknown.details, wrong.details,
        "the details must not distinguish them either"
    );
}

#[tokio::test]
async fn a_missing_header_denies_with_the_challenge() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = crate::support::resolve(&resolver, std::collections::HashMap::new()).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::MISSING_CREDENTIAL),
        "a missing header is a denial this resolver raises, not a decline"
    );
    assert_eq!(
        challenge_of(&result).as_deref(),
        Some("Basic realm=\"ops\""),
        "a denial this resolver raises always carries the challenge"
    );
}

#[tokio::test]
async fn a_bearer_credential_declines_without_denying() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, "Bearer some.jwt.value").await;

    assert!(
        result.violation.is_none(),
        "a wrong scheme must decline so a Bearer resolver on the same header can serve it"
    );
    let payload = result
        .modified_payload
        .expect("the decline carries the payload through");
    assert!(
        payload.subject.is_none() && payload.client.is_none(),
        "a declining resolver must leave every identity slot untouched"
    );
}

#[tokio::test]
async fn a_wrong_scheme_decline_carries_no_challenge() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, "Bearer some.jwt.value").await;

    assert!(
        challenge_of(&result).is_none() && result.violation.is_none(),
        "a declining plugin has no channel to contribute a challenge: when every resolver \
         declines, the engine synthesizes `auth.unrecognized_credential` with no details and no \
         proto_error_code. Asserted so the gap cannot regress into a false belief it is covered"
    );
}

#[tokio::test]
async fn a_malformed_credential_denies_with_a_reason_naming_no_value() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, "Basic not-base64!!").await;

    let violation = result.violation.expect("a non-base64 payload denies");
    assert_eq!(
        violation.code,
        codes::MALFORMED_CREDENTIAL,
        "the extraction-phase code is reused verbatim from the sibling plugins"
    );
    assert!(
        !violation.reason.contains("not-base64"),
        "the reason must name the location and the shape, never the value: {}",
        violation.reason
    );
}

#[tokio::test]
async fn an_overlong_password_denies_before_verification() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");
    let overlong = "x".repeat(200);

    let result = resolve_with_header(&resolver, &basic_header("alice", &overlong)).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::MALFORMED_CREDENTIAL),
        "a password past bcrypt's truncation point must be rejected, not verified on its prefix"
    );
}

#[tokio::test]
async fn repeated_failures_for_one_user_id_are_bounded() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["failure_limit"] = serde_json::json!({ "max_failures": 3, "window_secs": 60 });
    let resolver = resolver(block).expect("the config loads");

    for attempt in 1..=3_u32 {
        let result = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
        assert_eq!(
            denial_code(&result).as_deref(),
            Some(codes::INVALID_CREDENTIALS),
            "attempt {attempt} is within budget, so it must deny as an invalid credential"
        );
    }

    let blocked = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
    assert_eq!(
        denial_code(&blocked).as_deref(),
        Some(codes::TOO_MANY_FAILURES),
        "past the budget the limiter must deny before any verification runs"
    );
    assert_eq!(
        challenge_of(&blocked).as_deref(),
        Some("Basic realm=\"ops\""),
        "a limiter denial is still one this resolver raises, so it carries the challenge"
    );
}

#[tokio::test]
async fn the_limiter_keys_on_the_normalised_user_id() {
    let decomposed = "jose\u{301}";
    let precomposed = "jos\u{e9}";
    let file = HtpasswdFile::write(&format!(
        "{}\n",
        bcrypt_line(precomposed, "correct horse", 4)
    ));
    let mut block = htpasswd_block(file.path());
    block["failure_limit"] = serde_json::json!({ "max_failures": 2, "window_secs": 60 });
    let resolver = resolver(block).expect("the config loads");

    resolve_with_header(&resolver, &basic_header(decomposed, "wrong")).await;
    resolve_with_header(&resolver, &basic_header(precomposed, "wrong")).await;

    let blocked = resolve_with_header(&resolver, &basic_header(decomposed, "wrong")).await;
    assert_eq!(
        denial_code(&blocked).as_deref(),
        Some(codes::TOO_MANY_FAILURES),
        "two encodings of one name must share a bucket rather than getting a budget each"
    );
}

#[tokio::test]
async fn a_success_clears_the_failure_counter() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["failure_limit"] = serde_json::json!({ "max_failures": 3, "window_secs": 60 });
    let resolver = resolver(block).expect("the config loads");

    resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
    resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
    resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    for attempt in 1..=3_u32 {
        let result = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
        assert_eq!(
            denial_code(&result).as_deref(),
            Some(codes::INVALID_CREDENTIALS),
            "the budget must have been restored, so attempt {attempt} is within it again"
        );
    }
}

#[tokio::test]
async fn limiter_capacity_does_not_evict_a_blocked_user_id() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["failure_limit"] =
        serde_json::json!({ "capacity": 1, "max_failures": 1, "window_secs": 60 });
    let resolver = resolver(block).expect("the config loads");

    resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;

    let fresh = resolve_with_header(&resolver, &basic_header("bob", "whatever")).await;
    assert_eq!(
        denial_code(&fresh).as_deref(),
        Some(codes::INVALID_CREDENTIALS),
        "a full limiter must judge bob on his credential, not refuse him for want of a slot"
    );
    assert_eq!(
        resolver.limiter_saturations(),
        1,
        "the untracked attempt is still counted, so saturation is observable without logging a \
         user-id"
    );

    let blocked = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
    assert_eq!(
        denial_code(&blocked).as_deref(),
        Some(codes::TOO_MANY_FAILURES),
        "the blocked counter must survive the flood that tried to displace it"
    );
}

#[tokio::test]
async fn a_user_id_spray_does_not_lock_out_a_legitimate_caller() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["failure_limit"] =
        serde_json::json!({ "capacity": 8, "max_failures": 3, "window_secs": 300 });
    let resolver = resolver(block).expect("the config loads");

    // Alice is well-behaved, so she holds no counter -- which is exactly what
    // made her a victim when a full map denied untracked user-ids.
    for n in 0..16 {
        resolve_with_header(&resolver, &basic_header(&format!("junk{n}"), "whatever")).await;
    }
    assert!(
        resolver.limiter_saturations() > 0,
        "the spray must have filled the map, or this test is not exercising saturation"
    );

    let accepted = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;
    assert_eq!(
        denial_code(&accepted).as_deref(),
        None,
        "a spray of junk user-ids must not deny a caller presenting the correct password: \
         refusing untracked user-ids at capacity was a global-outage primitive costing the \
         attacker nothing but cheap, hash-free requests"
    );
}

#[tokio::test]
async fn an_expired_limiter_entry_frees_capacity() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["failure_limit"] =
        serde_json::json!({ "capacity": 1, "max_failures": 1, "window_secs": 1 });
    let resolver = resolver(block).expect("the config loads");

    resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
    assert_eq!(
        resolver.limiter_tracked(),
        1,
        "the failure must be counted before the window can expire it"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let fresh = resolve_with_header(&resolver, &basic_header("bob", "whatever")).await;
    assert_eq!(
        denial_code(&fresh).as_deref(),
        Some(codes::INVALID_CREDENTIALS),
        "once alice's counter expires its slot is reclaimed, so bob is tracked rather than \
         refused for want of capacity"
    );
}

#[tokio::test]
async fn a_route_response_block_does_not_override_the_challenge() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;

    let violation = result.violation.as_ref().expect("a wrong password denies");
    assert_eq!(
        violation.proto_error_code,
        Some(401),
        "an identity denial never reaches the route handler's denial decoration, because that \
         handler binds only the CMF and HTTP hook families. So the plugin's 401 and challenge \
         win unconditionally and a route's `response:` block does not apply here"
    );
    assert_eq!(
        challenge_of(&result).as_deref(),
        Some("Basic realm=\"ops\""),
        "the plugin's own challenge is the one that survives"
    );
}

#[tokio::test]
async fn a_scheme_only_header_denies_as_empty() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, "Basic ").await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::EMPTY_CREDENTIAL),
        "a header holding only the scheme is an empty credential, not a malformed one"
    );
    assert_eq!(
        challenge_of(&result).as_deref(),
        Some("Basic realm=\"ops\""),
        "an extraction-phase denial still carries the challenge"
    );
}

#[tokio::test]
async fn a_duplicated_authorization_header_denies_as_ambiguous() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");
    let header = basic_header("alice", "correct horse");

    let result = crate::support::resolve(
        &resolver,
        std::collections::HashMap::from([
            ("authorization".to_owned(), header.clone()),
            ("Authorization".to_owned(), header),
        ]),
    )
    .await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::AMBIGUOUS_CREDENTIAL),
        "two credentials in one header must not resolve either of them"
    );
}

#[tokio::test]
async fn a_credential_with_an_empty_half_denies_as_empty() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    for raw in ["alice:", ":correct horse"] {
        let result = resolve_with_header(
            &resolver,
            &format!("Basic {}", crate::support::b64(raw.as_bytes())),
        )
        .await;

        assert_eq!(
            denial_code(&result).as_deref(),
            Some(codes::EMPTY_CREDENTIAL),
            "an empty user-id or password is an empty credential, not a malformed one"
        );
    }
}

#[tokio::test]
async fn a_credential_with_no_separator_denies_as_malformed() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(
        &resolver,
        &format!("Basic {}", crate::support::b64(b"nocolonhere")),
    )
    .await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::MALFORMED_CREDENTIAL),
        "without a colon there is no user-id / password boundary"
    );
}

#[tokio::test]
async fn a_stale_directory_denies_distinctly_from_a_bad_password() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["provider"]["refresh_secs"] = serde_json::json!(1);
    block["provider"]["max_staleness_secs"] = serde_json::json!(1);
    let resolver = resolver(block).expect("the config loads");
    file.unlink();

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::DIRECTORY_UNAVAILABLE),
        "an operator watching a denial spike cannot act until they know whether the passwords \
         are wrong or the directory is down, so this code stays distinct"
    );
    assert_eq!(
        challenge_of(&result).as_deref(),
        Some("Basic realm=\"ops\""),
        "a directory denial is still one this resolver raises"
    );
}

#[tokio::test]
async fn a_record_map_that_cannot_project_the_client_slot_denies() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["role"] = serde_json::json!("client");
    block["record_map"] = serde_json::json!({ "client": { "client_id": "absent_field" } });
    let resolver = resolver(block).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::MAPPING_FAILED),
        "an anchor no record field satisfies must deny rather than authenticate an empty client"
    );
}

/// The log budget must never cost a denial.
///
/// Past the budget `may_log_failure` drops the line, and this pins that it
/// drops only the line: all forty attempts are still denied and still counted.
/// It deliberately asserts nothing about the log output itself -- that would
/// need a capturing subscriber, and `tracing-subscriber` is not a
/// dev-dependency of this crate. The budget's arithmetic is covered by the
/// unit tests beside it in `resolver.rs`, which is where the defect that
/// broke it lived.
#[tokio::test]
async fn every_failure_in_a_burst_is_denied_whether_or_not_it_is_logged() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["failure_limit"] = serde_json::json!({ "max_failures": 1_000, "window_secs": 60 });
    let resolver = resolver(block).expect("the config loads");

    for _ in 0..40_u32 {
        let result = resolve_with_header(&resolver, &basic_header("alice", "wrong horse")).await;
        assert_eq!(
            denial_code(&result).as_deref(),
            Some(codes::INVALID_CREDENTIALS),
            "every attempt in the burst must still be denied, whether or not it was logged"
        );
    }
}

#[tokio::test]
async fn a_record_map_that_cannot_project_the_subject_slot_denies() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["record_map"] = serde_json::json!({ "subject": { "id": "absent_field" } });
    let resolver = resolver(block).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::MAPPING_FAILED),
        "an anchor no record field satisfies must deny rather than authenticate an empty subject"
    );
    assert_eq!(
        challenge_of(&result).as_deref(),
        Some("Basic realm=\"ops\""),
        "a mapping denial is still one this resolver raises"
    );
}

#[tokio::test]
async fn a_directory_that_cannot_answer_does_not_spend_the_user_ids_budget() {
    // A stale index is the cheapest way to make every answer a
    // `DirectoryError` without racing a concurrency cap.
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["provider"]["refresh_secs"] = serde_json::json!(1);
    block["provider"]["max_staleness_secs"] = serde_json::json!(1);
    block["failure_limit"] =
        serde_json::json!({ "capacity": 16, "max_failures": 2, "window_secs": 300 });
    let resolver = resolver(block).expect("the config loads");
    file.unlink();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Far more attempts than the budget of two, every one naming alice.
    for _ in 0..8 {
        let denied = resolve_with_header(&resolver, &basic_header("alice", "whatever")).await;
        assert_eq!(
            denial_code(&denied).as_deref(),
            Some(codes::DIRECTORY_UNAVAILABLE),
            "while the index is stale the directory cannot answer"
        );
    }

    assert_eq!(
        resolver.limiter_tracked(),
        0,
        "a guess the directory never evaluated must not be counted against the user-id: \
         otherwise anyone able to stale or saturate the directory could spend a named victim's \
         budget to zero without ever guessing a password"
    );
}
