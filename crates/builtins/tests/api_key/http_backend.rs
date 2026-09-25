// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The directory behind an HTTP API, against the `maas-api` validate contract.
//!
//! Response bodies here are copied from `ValidationResult` in
//! `maas-api/internal/api_keys/types.go`, read 2026-09-22, including the parts
//! that are easy to get wrong: an invalid key answers 200, and `userId` is the
//! key's row id rather than the user's.

use std::sync::Arc;

use praxis_policy_builtins::plugins::identity_api_key::{
    DirectoryError, HttpDirectory, HttpDirectoryConfig, KeyDirectory as _, PresentedKey,
};
use praxis_policy_core::host::InitExtensions;
use praxis_policy_core::http_testing::{FakeTransport, granting};

const URL: &str = "https://maas-api.example/internal/v1/api-keys/validate";
const KEY: &[u8] = b"sk-oai-abc123_secret";

/// A valid answer, shaped as upstream shapes it.
const VALID: &str = r#"{
  "valid": true,
  "userId": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
  "keyId": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
  "username": "alice",
  "keyName": "laptop",
  "groups": ["reader", "writer"],
  "subscription": "premium",
  "tenant": "default"
}"#;

fn directory() -> HttpDirectory {
    let config: HttpDirectoryConfig =
        serde_yaml::from_str(&format!("url: {URL}")).expect("the backend config parses");
    HttpDirectory::new(config).expect("the config builds")
}

fn serving(status: u16, body: &str) -> (InitExtensions, Arc<FakeTransport>) {
    let transport = Arc::new(FakeTransport::new().json("api-keys/validate", status, body));
    (granting(Arc::clone(&transport)), transport)
}

#[tokio::test]
async fn a_valid_answer_becomes_a_record() {
    let (services, _transport) = serving(200, VALID);

    let record = directory()
        .lookup(&PresentedKey::new(KEY), &services)
        .await
        .expect("the directory answers")
        .expect("a valid answer is a record");

    assert_eq!(
        record.fields.get("username").and_then(|v| v.as_str()),
        Some("alice")
    );
    assert_eq!(
        record.fields.get("tenant").and_then(|v| v.as_str()),
        Some("default")
    );
}

/// The envelope describes the answer, not the subject. Leaving `valid` in the
/// bag means an operator can project `subject.claim.valid` and render it
/// upstream as though the identity carried it.
#[tokio::test]
async fn the_envelope_fields_never_reach_the_record() {
    let (services, _transport) = serving(200, VALID);

    let record = directory()
        .lookup(&PresentedKey::new(KEY), &services)
        .await
        .expect("the directory answers")
        .expect("a valid answer is a record");

    assert!(
        !record.fields.contains_key("valid"),
        "the verdict is not an attribute"
    );
    assert!(
        !record.fields.contains_key("reason"),
        "nor is a refusal's reason"
    );
}

/// `userId` is `metadata.ID`, the key's row id, and `keyId` is the same value.
/// A map wanting a stable subject reads `username`; this pins that the two are
/// distinguishable in what reaches the mapper.
#[tokio::test]
async fn the_record_carries_the_key_id_and_the_username_separately() {
    let (services, _transport) = serving(200, VALID);

    let record = directory()
        .lookup(&PresentedKey::new(KEY), &services)
        .await
        .expect("the directory answers")
        .expect("a valid answer is a record");

    assert_eq!(
        record.fields.get("userId"),
        record.fields.get("keyId"),
        "upstream fills both from metadata.ID"
    );
    assert_ne!(
        record.fields.get("userId").and_then(|v| v.as_str()),
        Some("alice"),
        "`userId` is the key's row id, not the person"
    );
}

/// An invalid key is HTTP 200 with `valid: false`, per their design doc
/// section 7.7. Treating a 200 as success regardless would authenticate a
/// refused credential.
#[tokio::test]
async fn an_invalid_answer_on_200_is_a_miss_not_a_record() {
    for reason in [
        "invalid key format",
        "key not found",
        "key revoked or expired",
        "key has no subscription bound",
    ] {
        let body = format!(r#"{{"valid": false, "reason": "{reason}", "tenant": ""}}"#);
        let (services, _transport) = serving(200, &body);

        let outcome = directory()
            .lookup(&PresentedKey::new(KEY), &services)
            .await
            .expect("the directory answered, it just said no");

        assert!(outcome.is_none(), "'{reason}' must be a miss, not a record");
    }
}

/// A miss and a failure are different denials. 500 is upstream's own
/// validation error and 400 is a request this client built wrong; neither is
/// an answer about the credential.
#[tokio::test]
async fn a_non_200_is_a_directory_failure_rather_than_a_miss() {
    for status in [400, 401, 404, 500, 502, 503] {
        let (services, _transport) = serving(status, r#"{"error": "nope"}"#);

        let error = directory()
            .lookup(&PresentedKey::new(KEY), &services)
            .await
            .expect_err("a non-200 must not read as an unknown key");

        assert!(
            matches!(error, DirectoryError::Unavailable(_)),
            "{status} must be unavailable, got {error:?}"
        );
    }
}

/// A response this backend cannot read is not a refusal. Defaulting a missing
/// verdict to `false` denies a caller the directory may have accepted, and to
/// `true` admits one it may not.
#[tokio::test]
async fn an_unreadable_answer_is_malformed_rather_than_a_miss() {
    for body in [
        r#"{"username": "alice"}"#, // no verdict field at all
        r#"{"valid": "yes"}"#,      // present, wrong type
        r#"["valid"]"#,             // not an object
        "not json at all",
    ] {
        let (services, _transport) = serving(200, body);

        let error = directory()
            .lookup(&PresentedKey::new(KEY), &services)
            .await
            .unwrap_err();

        assert!(
            matches!(error, DirectoryError::Malformed(_)),
            "{body} must be malformed, got {error:?}"
        );
    }
}

/// The credential is sent as JSON built by a serializer, so one containing a
/// quote cannot alter the shape of the request around it.
#[tokio::test]
async fn the_credential_is_encoded_rather_than_interpolated() {
    let (services, transport) = serving(200, VALID);
    let awkward = br#"sk-oai-a"b\c_secret"#;

    let _ = directory()
        .lookup(&PresentedKey::new(&awkward[..]), &services)
        .await;

    let request = transport.last_request().expect("a request was made");
    let body: serde_json::Value =
        serde_json::from_slice(&request.body).expect("the body is valid JSON");
    assert_eq!(
        body.get("key").and_then(|v| v.as_str()),
        Some(r#"sk-oai-a"b\c_secret"#),
        "the credential must survive encoding intact"
    );
}

/// A host that wired no transport, or withheld it, is a deployment fault. It
/// denies as a directory failure so an operator is sent to the host rather
/// than to their key store.
#[tokio::test]
async fn no_transport_is_a_directory_failure() {
    let error = directory()
        .lookup(&PresentedKey::new(KEY), &InitExtensions::new())
        .await
        .expect_err("a lookup with no transport cannot succeed");

    assert!(
        matches!(error, DirectoryError::Unavailable(detail) if detail.contains("transport")),
        "the denial must name the missing transport"
    );
}

/// An empty credential is answered without a round trip: a directory should
/// not be asked about a key that was never presented.
#[tokio::test]
async fn an_empty_credential_costs_no_request() {
    let (services, transport) = serving(200, VALID);

    let outcome = directory()
        .lookup(&PresentedKey::new(&b""[..]), &services)
        .await
        .expect("an empty credential answers locally");

    assert!(outcome.is_none());
    assert_eq!(
        transport.call_count(),
        0,
        "no request should have been sent"
    );
}

#[test]
fn a_url_that_is_not_absolute_http_fails_at_config_load() {
    for url in ["maas-api.example/validate", "ftp://host/validate", ""] {
        let config: HttpDirectoryConfig =
            serde_yaml::from_str(&format!("url: \"{url}\"")).expect("the block parses");
        let error = HttpDirectory::new(config).expect_err("'{url}' must not build");
        assert!(
            error.contains("absolute http"),
            "the error must say what is wrong with '{url}': {error}"
        );
    }
}

#[test]
fn a_zero_timeout_fails_at_config_load() {
    let config: HttpDirectoryConfig =
        serde_yaml::from_str(&format!("url: {URL}\ntimeout_secs: 0")).expect("the block parses");

    let error = HttpDirectory::new(config).expect_err("a zero timeout must not build");

    assert!(
        error.contains("every lookup would time out"),
        "got: {error}"
    );
}

/// Through the resolver, not just the backend: a credential off a request
/// reaches the directory, and the answer becomes a subject.
#[tokio::test]
async fn the_resolver_projects_an_http_answer_onto_the_subject() {
    let transport = Arc::new(FakeTransport::new().json("api-keys/validate", 200, VALID));
    let resolver = crate::support::resolver(serde_json::json!({
        "credential": { "kind": "header", "name": "Authorization" },
        "prefix": "Bearer sk-oai-",
        "provider": { "kind": "http", "url": URL },
        "record_map": { "subject": { "id": "username", "roles": "groups" } },
        "claims": { "include": ["subscription", "tenant"] },
    }))
    .expect("the config builds");

    let result = crate::support::resolve_over_http(
        &resolver,
        "Bearer sk-oai-abc123_secret",
        Arc::clone(&transport),
    )
    .await;

    let subject = result
        .modified_payload
        .expect("a resolved credential modifies the payload")
        .subject
        .expect("the subject slot is filled");
    assert_eq!(subject.id.as_deref(), Some("alice"));
    let mut roles: Vec<&str> = subject.roles.iter().map(String::as_str).collect();
    roles.sort_unstable();
    assert_eq!(roles, vec!["reader", "writer"]);
    assert_eq!(transport.call_count(), 1, "one lookup, one request");

    // The prefix's leader is part of the key, so the directory is asked about
    // the whole `sk-oai-...` string rather than what follows it.
    let body: serde_json::Value =
        serde_json::from_slice(&transport.last_request().expect("a request").body)
            .expect("the body is JSON");
    assert_eq!(
        body.get("key").and_then(|v| v.as_str()),
        Some("sk-oai-abc123_secret")
    );
}

/// A directory that cannot answer denies as a directory failure, which is a
/// different code from an unknown key and a different operator problem.
#[tokio::test]
async fn a_directory_failure_denies_differently_from_an_unknown_key() {
    let resolver = crate::support::resolver(serde_json::json!({
        "credential": { "kind": "header", "name": "Authorization" },
        "provider": { "kind": "http", "url": URL },
        "record_map": { "subject": { "id": "username" } },
    }))
    .expect("the config builds");

    let down = Arc::new(FakeTransport::new().json("api-keys/validate", 500, r#"{"error":"x"}"#));
    let failed = crate::support::resolve_over_http(&resolver, "sk-oai-a_b", down).await;

    let refusing = Arc::new(FakeTransport::new().json(
        "api-keys/validate",
        200,
        r#"{"valid": false, "reason": "key not found", "tenant": ""}"#,
    ));
    let missed = crate::support::resolve_over_http(&resolver, "sk-oai-a_b", refusing).await;

    assert_eq!(
        crate::support::denial_code(&failed).as_deref(),
        Some("auth.directory_unavailable")
    );
    assert_eq!(
        crate::support::denial_code(&missed).as_deref(),
        Some("auth.key_unknown")
    );
}

/// A credential that is not UTF-8 cannot be asked about over a JSON contract.
/// Refused rather than lossily converted: a replacement character would be a
/// lookup for a different key, and would answer "unknown" about a credential
/// nobody ever issued.
#[tokio::test]
async fn a_non_utf8_credential_is_refused_without_a_request() {
    let (services, transport) = serving(200, VALID);

    let error = directory()
        .lookup(
            &PresentedKey::new(&b"sk-oai-\xff\xfe_secret"[..]),
            &services,
        )
        .await
        .expect_err("a credential that cannot be encoded must not be sent");

    assert!(
        matches!(error, DirectoryError::Malformed(detail) if detail.contains("not UTF-8")),
        "the refusal must say why"
    );
    assert_eq!(transport.call_count(), 0, "nothing should have been sent");
}

/// `connect_timeout_secs` reaches the request rather than being parsed and
/// dropped.
#[tokio::test]
async fn the_connect_timeout_reaches_the_request() {
    let (services, transport) = serving(200, VALID);
    let config: HttpDirectoryConfig = serde_yaml::from_str(&format!(
        "url: {URL}\ntimeout_secs: 9\nconnect_timeout_secs: 2"
    ))
    .expect("the backend config parses");

    let _ = HttpDirectory::new(config)
        .expect("the config builds")
        .lookup(&PresentedKey::new(KEY), &services)
        .await;

    let request = transport.last_request().expect("a request was made");
    assert_eq!(request.timeout, std::time::Duration::from_secs(9));
    assert_eq!(
        request.connect_timeout,
        Some(std::time::Duration::from_secs(2))
    );
}

/// A field name that is empty addresses nothing, so it fails at load rather
/// than making every answer unreadable.
#[test]
fn an_empty_field_name_fails_at_config_load() {
    for (block, expected) in [
        (
            format!("url: {URL}\nkey_field: \"\""),
            "`key_field` is empty",
        ),
        (
            format!("url: {URL}\nvalid_field: \"  \""),
            "`valid_field` is empty",
        ),
    ] {
        let config: HttpDirectoryConfig = serde_yaml::from_str(&block).expect("the block parses");
        let error = HttpDirectory::new(config).expect_err("an empty field name must not build");
        assert!(error.contains(expected), "got: {error}");
    }
}

#[test]
fn the_backend_names_itself() {
    assert_eq!(directory().kind(), "http");
}

// Deployment capture from 2026-09-24 with identifying values replaced.
const CAPTURED_RESPONSE: &str = include_str!("fixtures/maas-validate-response.json");

#[tokio::test]
async fn a_captured_deployment_response_projects_as_documented() {
    let transport =
        Arc::new(FakeTransport::new().json("api-keys/validate", 200, CAPTURED_RESPONSE));
    let resolver = crate::support::resolver(serde_json::json!({
        "credential": { "kind": "header", "name": "Authorization" },
        "prefix": "Bearer sk-oai-",
        "provider": { "kind": "http", "url": URL },
        "record_map": { "subject": { "id": "username", "roles": "groups" } },
        "claims": { "exclude": ["userId", "keyId", "keyName"] },
    }))
    .expect("the config builds");

    let result =
        crate::support::resolve_over_http(&resolver, "Bearer sk-oai-abc123_secret", transport)
            .await;
    let subject = result
        .modified_payload
        .expect("the payload is modified")
        .subject
        .expect("the subject slot is filled");
    assert_eq!(
        subject.id.as_deref(),
        Some("system:serviceaccount:example-tenant:example-consumer")
    );
    let mut roles: Vec<&str> = subject.roles.iter().map(String::as_str).collect();
    roles.sort_unstable();
    assert_eq!(
        roles,
        vec![
            "system:authenticated",
            "system:serviceaccounts",
            "system:serviceaccounts:example-tenant"
        ]
    );
}
