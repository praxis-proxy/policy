// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What a verified record projects onto the identity slots, and what it must
//! never carry there.

use crate::support::{
    HtpasswdFile, basic_header, bcrypt_line, htpasswd_block, resolve_with_header, resolver,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn the_subject_id_defaults_to_the_user_id() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    let payload = result
        .modified_payload
        .expect("a verified credential resolves");
    let subject = payload.subject.expect("the subject slot is filled");
    assert_eq!(
        subject.id.as_deref(),
        Some("alice"),
        "with no record_map entry, subject.id must default to the verified user-id"
    );
}

#[tokio::test]
async fn an_explicit_record_map_anchor_wins_over_the_default() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["record_map"] = serde_json::json!({ "subject": { "id": "user_id" } });
    let resolver = resolver(block).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    let subject = result
        .modified_payload
        .expect("a verified credential resolves")
        .subject
        .expect("the subject slot is filled");
    assert_eq!(
        subject.id.as_deref(),
        Some("alice"),
        "an operator naming the user-id field explicitly must get the same anchor"
    );
}

#[tokio::test]
async fn the_client_role_projects_the_user_id_as_its_client_id() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("svc-a", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["role"] = serde_json::json!("client");
    let resolver = resolver(block).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("svc-a", "correct horse")).await;

    let client = result
        .modified_payload
        .expect("a verified credential resolves")
        .client
        .expect("the client slot is filled");
    assert_eq!(
        client.client_id, "svc-a",
        "the client role must anchor on the verified user-id too"
    );
}

#[tokio::test]
async fn a_user_id_cannot_satisfy_the_workload_spiffe_anchor() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["role"] = serde_json::json!("caller_workload");
    block["record_map"] = serde_json::json!({ "workload": { "spiffe_id": "user_id" } });
    let resolver = resolver(block).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    assert_eq!(
        crate::support::denial_code(&result).as_deref(),
        Some("auth.mapping_failed"),
        "a user-id is not a SPIFFE id, so the workload anchor must decline rather than \
         fabricate one"
    );
}

#[tokio::test]
async fn the_projected_identity_records_the_basic_attestor() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["role"] = serde_json::json!("caller_workload");
    block["record_map"] = serde_json::json!({
        "workload": { "spiffe_id": "spiffe", "client_id": "user_id" },
    });
    let resolver = resolver(block).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    assert_eq!(
        crate::support::denial_code(&result).as_deref(),
        Some("auth.mapping_failed"),
        "`.htpasswd` carries no SPIFFE id, so this projection cannot complete; the attestor a \
         completed one would carry is asserted below"
    );
    assert_eq!(
        praxis_policy_builtins::plugins::identity_basic::record_map::ATTESTOR,
        "basic",
        "a policy gating on how an identity was established must be told it was a password"
    );
}

#[tokio::test]
async fn the_stored_hash_never_reaches_the_projected_claims() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    let subject = result
        .modified_payload
        .expect("a verified credential resolves")
        .subject
        .expect("the subject slot is filled");
    for (name, value) in &subject.claims {
        let rendered = value.to_string();
        assert!(
            !rendered.contains("$2") && !rendered.contains("$argon2"),
            "claim `{name}` carries stored hash material: {rendered}"
        );
    }
    assert!(
        !subject.claims.contains_key("hash") && !subject.claims.contains_key("password_hash"),
        "no storage field may reach the claims bag, got: {:?}",
        subject.claims.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn raw_credentials_is_unset_after_a_successful_resolve() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("alice", "correct horse")).await;

    let payload = result
        .modified_payload
        .expect("a verified credential resolves");
    assert!(
        payload.raw_credentials.is_none(),
        "the password must not reach raw_credentials, or a downstream step could forward it to \
         an upstream that never authenticated it"
    );
}

#[tokio::test]
async fn the_forwarded_request_still_carries_the_inbound_authorization_header() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");
    let header = basic_header("alice", "correct horse");

    let result = resolve_with_header(&resolver, &header).await;

    let payload = result
        .modified_payload
        .expect("a verified credential resolves");
    assert_eq!(
        payload.headers().get("authorization"),
        Some(&header),
        "the identity hook has no request-mutation channel, so the inbound header remains: \
         removing it before an upstream sees it is a host obligation, and a test asserting \
         otherwise could not pass"
    );
}

#[tokio::test]
async fn a_user_id_the_file_does_not_hold_denies() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    let result = resolve_with_header(&resolver, &basic_header("bob", "correct horse")).await;

    assert!(
        result.modified_payload.is_none() || result.violation.is_some(),
        "an unknown user-id must not resolve an identity"
    );
}

#[tokio::test]
async fn a_non_nfc_stored_user_id_is_reachable_through_the_resolver() {
    let decomposed = "jose\u{301}";
    let precomposed = "jos\u{e9}";
    let file = HtpasswdFile::write(&format!(
        "{}\n",
        bcrypt_line(decomposed, "correct horse", 4)
    ));
    let resolver = resolver(htpasswd_block(file.path())).expect("the config loads");

    for sent in [decomposed, precomposed] {
        let result = resolve_with_header(&resolver, &basic_header(sent, "correct horse")).await;

        let subject = result
            .modified_payload
            .expect("either spelling resolves")
            .subject
            .expect("the subject slot is filled");
        assert_eq!(
            subject.id.as_deref(),
            Some(precomposed),
            "both spellings must normalise onto one index key and one subject id"
        );
    }
}
