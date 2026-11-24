// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The `TokenReview` backend on its own: what it sends, and how each answer
//! becomes a record, a miss, or a failure.

use std::sync::Arc;

use praxis_policy_builtins::plugins::identity_kubernetes::{
    ApiServerConfig, DirectoryError, KeyDirectory as _, PresentedKey, TokenReviewDirectory,
};
use praxis_policy_core::http_testing::{FakeTransport, granting};

use crate::support::{
    API_SERVER, AUTHENTICATED, FORBIDDEN, GARBAGE, LEGACY, LEGACY_CUSTOM_AUDIENCE, REVIEW_PATH,
    REVIEWER, TokenFile, UNAUTHENTICATED, api_server, jwt_expiring_at,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn an_authenticated_review_becomes_the_user_record() {
    let (_file, directory) = directory(&["praxis-gateway"]);
    let services = granting(api_server(201, AUTHENTICATED));

    let record = directory
        .lookup(&PresentedKey::new("caller-token"), &services)
        .await
        .expect("the API server answers")
        .expect("an authenticated review is a record");

    assert_eq!(
        record.fields["username"], "system:serviceaccount:team-a:agent-bot",
        "the username comes from status.user"
    );
    assert_eq!(
        record.fields["groups"][1], "system:serviceaccounts:team-a",
        "groups are carried as the API server gave them"
    );
    assert!(
        record.fields.contains_key("extra"),
        "extra reaches the record"
    );
    assert!(
        record.expires_at.is_none(),
        "a token that is not a JWT has no expiry to read"
    );
}

#[tokio::test]
async fn the_review_carries_the_token_the_audiences_and_the_reviewer_credential() {
    let (_file, directory) = directory(&["praxis-gateway"]);
    let transport = api_server(201, AUTHENTICATED);
    let services = granting(Arc::clone(&transport));

    directory
        .lookup(&PresentedKey::new("caller-token"), &services)
        .await
        .expect("the API server answers");

    let request = transport.last_request().expect("a review was sent");
    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("the body is JSON");
    assert_eq!(
        request.url,
        format!("{API_SERVER}{REVIEW_PATH}"),
        "the review goes to the v1 endpoint"
    );
    assert_eq!(request.method.as_str(), "POST", "a review is a create");
    assert_eq!(
        request.headers["authorization"],
        format!("Bearer {REVIEWER}").as_str(),
        "PPE authenticates with its own token, not the caller's"
    );
    assert_eq!(body["kind"], "TokenReview");
    assert_eq!(
        body["spec"]["token"], "caller-token",
        "the caller's token is under review"
    );
    assert_eq!(body["spec"]["audiences"][0], "praxis-gateway");
}

#[tokio::test]
async fn no_configured_audiences_sends_none() {
    let (_file, directory) = directory(&[]);
    let transport = api_server(201, AUTHENTICATED);
    let services = granting(Arc::clone(&transport));

    directory
        .lookup(&PresentedKey::new("caller-token"), &services)
        .await
        .expect("the API server answers");

    let request = transport.last_request().expect("a review was sent");
    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("the body is JSON");
    assert!(
        body["spec"].get("audiences").is_none(),
        "omitting audiences asks for the API server's default"
    );
}

#[tokio::test]
async fn an_omitted_authenticated_field_is_a_miss() {
    let (_file, directory) = directory(&["praxis-gateway"]);
    let services = granting(api_server(201, UNAUTHENTICATED));

    let outcome = directory
        .lookup(&PresentedKey::new("revoked-token"), &services)
        .await
        .expect("a refusal is an answer, not a failure");

    assert!(
        outcome.is_none(),
        "the API server omits `authenticated` when false"
    );
}

#[tokio::test]
async fn an_audience_the_answer_does_not_grant_is_a_miss() {
    let (_file, directory) = directory(&["some-other-gateway"]);
    let services = granting(api_server(201, AUTHENTICATED));

    let outcome = directory
        .lookup(&PresentedKey::new("caller-token"), &services)
        .await
        .expect("the API server answers");

    assert!(
        outcome.is_none(),
        "an answer granting none of the configured audiences must not authenticate"
    );
}

#[tokio::test]
async fn a_refused_reviewer_credential_is_a_failure_not_a_miss() {
    for status in [401, 403] {
        let (_file, directory) = directory(&[]);
        let services = granting(api_server(status, FORBIDDEN));

        let error = directory
            .lookup(&PresentedKey::new("caller-token"), &services)
            .await
            .expect_err("a refused reviewer cannot answer about the caller");

        assert!(
            matches!(&error, DirectoryError::Unavailable(message) if message.contains("reviewer")),
            "{status} must point at the reviewer credential, got {error}"
        );
    }
}

#[tokio::test]
async fn a_legacy_token_resolves_without_audiences_and_carries_no_expiry() {
    let (_file, directory) = directory(&[]);
    let services = granting(api_server(201, LEGACY));

    let record = directory
        .lookup(&PresentedKey::new("legacy-token"), &services)
        .await
        .expect("the API server answers")
        .expect("a legacy token authenticates for the API server's own audience");

    assert_eq!(
        record.fields["username"],
        "system:serviceaccount:team-a:agent-bot"
    );
    assert!(record.expires_at.is_none(), "a legacy token never expires");
}

#[tokio::test]
async fn refusals_the_api_server_gives_are_misses() {
    let cases = [
        (
            LEGACY_CUSTOM_AUDIENCE,
            "a legacy token reviewed for a custom audience",
        ),
        (UNAUTHENTICATED, "a legacy token whose Secret was deleted"),
        (GARBAGE, "a token no authenticator recognises"),
    ];
    for (answer, case) in cases {
        let (_file, directory) = directory(&[]);
        let services = granting(api_server(201, answer));

        let outcome = directory
            .lookup(&PresentedKey::new("caller-token"), &services)
            .await
            .expect(case);

        assert!(outcome.is_none(), "{case} must not authenticate");
    }
}

#[tokio::test]
async fn a_server_error_is_a_failure() {
    let (_file, directory) = directory(&[]);
    let services = granting(api_server(503, "unavailable"));

    let error = directory
        .lookup(&PresentedKey::new("caller-token"), &services)
        .await
        .expect_err("a 503 is not an answer");

    assert!(
        matches!(error, DirectoryError::Unavailable(_)),
        "got {error}"
    );
}

#[tokio::test]
async fn unreadable_answers_are_malformed() {
    let cases = [
        ("not json", "the body is not JSON"),
        (r#"{"kind":"TokenReview"}"#, "no status object"),
        (
            r#"{"status":{"authenticated":"yes"}}"#,
            "a non-boolean verdict",
        ),
        (
            r#"{"status":{"authenticated":true,"user":{}}}"#,
            "no username",
        ),
    ];
    for (body, case) in cases {
        let (_file, directory) = directory(&[]);
        let services = granting(api_server(201, body));

        let error = directory
            .lookup(&PresentedKey::new("caller-token"), &services)
            .await
            .expect_err(case);

        assert!(
            matches!(error, DirectoryError::Malformed(_)),
            "{case}: got {error}"
        );
    }
}

#[tokio::test]
async fn a_jwt_answer_expires_with_the_token() {
    let (_file, directory) = directory(&["praxis-gateway"]);
    let services = granting(api_server(201, AUTHENTICATED));

    let record = directory
        .lookup(
            &PresentedKey::new(jwt_expiring_at(4_102_444_800_i64)),
            &services,
        )
        .await
        .expect("the API server answers")
        .expect("an authenticated review is a record");

    assert_eq!(
        record.expires_at.map(|at| at.timestamp()),
        Some(4_102_444_800),
        "the record carries the token's own exp"
    );
}

#[tokio::test]
async fn a_decimal_exp_is_floored_rather_than_dropped() {
    let (_file, directory) = directory(&["praxis-gateway"]);
    let services = granting(api_server(201, AUTHENTICATED));

    let record = directory
        .lookup(
            &PresentedKey::new(jwt_expiring_at(4_102_444_800.9)),
            &services,
        )
        .await
        .expect("the API server answers")
        .expect("an authenticated review is a record");

    assert_eq!(
        record.expires_at.map(|at| at.timestamp()),
        Some(4_102_444_800),
        "RFC 7519 allows a fractional NumericDate; flooring keeps the bound"
    );
}

#[tokio::test]
async fn a_rotated_reviewer_token_is_picked_up_after_the_refresh_interval() {
    let file = TokenFile::write(REVIEWER);
    let config: ApiServerConfig = serde_json::from_value(serde_json::json!({
        "url": API_SERVER,
        "reviewer_token": { "kind": "file", "path": file.path(), "refresh_secs": 1 },
    }))
    .expect("the config parses");
    let directory = TokenReviewDirectory::new(&config, Vec::new()).expect("the token reads");
    let transport = Arc::new(
        FakeTransport::new()
            .json(REVIEW_PATH, 201, AUTHENTICATED)
            .json(REVIEW_PATH, 201, AUTHENTICATED),
    );
    let services = granting(Arc::clone(&transport));

    file.rotate("rotated-reviewer-token\n");
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    directory
        .lookup(&PresentedKey::new("caller-token"), &services)
        .await
        .expect("the API server answers");

    let request = transport.last_request().expect("a review was sent");
    assert_eq!(
        request.headers["authorization"], "Bearer rotated-reviewer-token",
        "the re-read token is sent, trimmed of the trailing newline"
    );
}

#[test]
fn an_unreadable_or_empty_reviewer_token_fails_the_build() {
    let empty = TokenFile::write("  \n");
    for path in [empty.path(), "/nonexistent/ppe-reviewer-token"] {
        let config: ApiServerConfig = serde_json::from_value(serde_json::json!({
            "url": API_SERVER,
            "reviewer_token": { "kind": "file", "path": path },
        }))
        .expect("the config parses");

        let error = TokenReviewDirectory::new(&config, Vec::new())
            .expect_err("a reviewer token that cannot be read stops the load");

        assert!(
            error.contains("reviewer_token"),
            "the error names the setting: {error}"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A backend with a fresh reviewer token file, kept alive alongside it.
fn directory(audiences: &[&str]) -> (TokenFile, TokenReviewDirectory) {
    let file = TokenFile::write(REVIEWER);
    let config: ApiServerConfig = serde_json::from_value(serde_json::json!({
        "url": API_SERVER,
        "reviewer_token": { "kind": "file", "path": file.path() },
    }))
    .expect("the config parses");
    let audiences = audiences.iter().map(|a| (*a).to_owned()).collect();
    let directory = TokenReviewDirectory::new(&config, audiences).expect("the token reads");
    (file, directory)
}
