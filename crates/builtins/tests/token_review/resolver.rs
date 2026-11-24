// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The resolver end to end: config load, the denial codes, the cache, and the
//! identity a review produces.

use std::sync::Arc;

use praxis_policy_builtins::plugins::identity_kubernetes::codes;

use crate::support::{
    AUTHENTICATED, REVIEW_PATH, REVIEWER, TokenFile, UNAUTHENTICATED, api_server, config,
    denial_code, jwt_expiring_at, resolve, resolver, resolver_with,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn an_authenticated_token_fills_the_subject() {
    let file = TokenFile::write(REVIEWER);
    let resolver = resolver(config(file.path())).expect("the config builds");

    let result = resolve(&resolver, "caller-token", api_server(201, AUTHENTICATED)).await;

    assert_eq!(
        denial_code(&result),
        None,
        "an authenticated token resolves"
    );
    let subject = result
        .modified_payload
        .and_then(|payload| payload.subject)
        .expect("the subject slot is filled");
    assert_eq!(
        subject.id.as_deref(),
        Some("system:serviceaccount:team-a:agent-bot")
    );
    assert!(
        subject.roles.contains("system:serviceaccounts:team-a"),
        "groups become roles: {:?}",
        subject.roles
    );
}

#[tokio::test]
async fn an_unauthenticated_token_is_denied_as_such() {
    let file = TokenFile::write(REVIEWER);
    let resolver = resolver(config(file.path())).expect("the config builds");

    let result = resolve(&resolver, "revoked-token", api_server(201, UNAUTHENTICATED)).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::TOKEN_UNAUTHENTICATED)
    );
}

#[tokio::test]
async fn a_refused_reviewer_is_denied_as_unavailable() {
    let file = TokenFile::write(REVIEWER);
    let resolver = resolver(config(file.path())).expect("the config builds");

    let result = resolve(&resolver, "caller-token", api_server(403, "{}")).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::DIRECTORY_UNAVAILABLE),
        "a reviewer the API server refuses is an outage, not a bad caller"
    );
}

#[tokio::test]
async fn an_authenticated_jwt_past_its_exp_is_denied_as_expired() {
    let file = TokenFile::write(REVIEWER);
    let resolver = resolver(config(file.path())).expect("the config builds");

    let result = resolve(
        &resolver,
        &jwt_expiring_at(1),
        api_server(201, AUTHENTICATED),
    )
    .await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::TOKEN_EXPIRED),
        "a record never outlives the token's own exp"
    );
}

#[tokio::test]
async fn an_authenticated_jwt_past_a_decimal_exp_is_denied_as_expired() {
    let file = TokenFile::write(REVIEWER);
    let resolver = resolver(config(file.path())).expect("the config builds");

    let result = resolve(
        &resolver,
        &jwt_expiring_at(1.5),
        api_server(201, AUTHENTICATED),
    )
    .await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::TOKEN_EXPIRED),
        "a decimal exp bounds the record as an integer one does"
    );
}

#[tokio::test]
async fn a_cached_answer_is_not_asked_for_again() {
    let file = TokenFile::write(REVIEWER);
    let mut block = config(file.path());
    block["cache"] = serde_json::json!({ "ttl_secs": 30 });
    let resolver = resolver(block).expect("the config builds");
    let transport = api_server(201, AUTHENTICATED);

    let first = resolve(&resolver, "caller-token", Arc::clone(&transport)).await;
    let second = resolve(&resolver, "caller-token", Arc::clone(&transport)).await;

    assert_eq!(denial_code(&first), None);
    assert_eq!(denial_code(&second), None);
    assert_eq!(
        transport.call_count_for(REVIEW_PATH),
        1,
        "the second request is served from the cache"
    );
}

#[test]
fn a_plugin_without_perform_http_fails_the_build() {
    let file = TokenFile::write(REVIEWER);

    let error = resolver_with(config(file.path()), &[]).expect_err("every review needs egress");

    assert!(
        error.contains("perform_http"),
        "the error names the capability: {error}"
    );
}

#[test]
fn settings_that_cannot_work_fail_the_build() {
    let file = TokenFile::write(REVIEWER);
    let cases: [(&str, serde_json::Value); 4] = [
        (
            "api_server",
            serde_json::json!("http://kube-api.example:6443"),
        ),
        ("timeout_secs", serde_json::json!(0)),
        ("audiences", serde_json::json!([""])),
        (
            "record_map",
            serde_json::json!({ "client": { "client_id": "username" } }),
        ),
    ];
    for (setting, value) in cases {
        let mut block = config(file.path());
        match setting {
            "api_server" => block["api_server"]["url"] = value,
            "timeout_secs" => block["api_server"]["timeout_secs"] = value,
            other => block[other] = value,
        }

        let error = resolver(block).expect_err(setting);

        assert!(
            error.contains(setting) || error.contains("url"),
            "{setting}: the error names what is wrong: {error}"
        );
    }
}

#[test]
fn the_documented_recipe_builds() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/content/identity-delegation.md"
    ))
    .expect("the identity docs are readable");
    let yaml = doc
        .split("A Kubernetes token, reviewed by the API server")
        .nth(1)
        .and_then(|recipe| recipe.split("```yaml\n").nth(1))
        .and_then(|block| block.split("```").next())
        .expect("the recipe has a YAML block");
    let document: serde_yaml::Value = serde_yaml::from_str(yaml).expect("the recipe parses");
    let mut block =
        serde_json::to_value(&document["plugins"][0]["config"]).expect("the block converts");
    let file = TokenFile::write(REVIEWER);
    block["api_server"]["reviewer_token"]["path"] = file.path().into();

    resolver(block).expect("the documented config builds");
}
