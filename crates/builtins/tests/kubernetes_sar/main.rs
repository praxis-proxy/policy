// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End to end behaviour of the Kubernetes `SubjectAccessReview` decision point,
//! from a `global.pdp` block and a route step through a scripted API server to
//! the route's allow or deny.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use praxis_policy_apl_runtime::{AplOptions, register_apl};
use praxis_policy_builtins::pdps::kubernetes_sar::SubjectAccessReviewPdpFactory;
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, ToolCall};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::extensions::{
    MetaExtension, SecurityExtension, SubjectExtension, SubjectType,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::http::HttpResponse;
use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::http_testing::FakeTransport;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const API_SERVER: &str = "https://kube-api.example:6443";

const REVIEW_PATH: &str = "/apis/authorization.k8s.io/v1/subjectaccessreviews";

const REVIEWER: &str = "reviewer-sa-token";

const ALLOWED: &str = r#"{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{"allowed":true,"reason":"RBAC: allowed by ClusterRoleBinding \"agents\""}}"#;

const NO_OPINION: &str =
    r#"{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{}}"#;

const AGENT: &str = "system:serviceaccount:team-a:agent";

const NON_RESOURCE_STEP: &str = "
            non_resource_attributes:
              path: \"'/tools/' + meta.entity_name\"
              verb: \"'post'\"";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn an_allowed_review_allows_and_sends_only_the_projected_fields() {
    let token = TokenFile::write(REVIEWER);
    let api = Arc::new(FakeTransport::new().json(REVIEW_PATH, 201, ALLOWED));
    let engine = engine(&policy(&token, "", "search", NON_RESOURCE_STEP), Some(&api))
        .await
        .expect("the policy loads");

    let result = call(
        &engine,
        "search",
        serde_json::json!({"q": "secret"}),
        Some(agent()),
    )
    .await;

    assert!(
        result.continue_processing,
        "an allowed review allows: {:?}",
        result.violation
    );
    let request = api.last_request().expect("one review was sent");
    assert_eq!(request.url, format!("{API_SERVER}{REVIEW_PATH}"));
    assert_eq!(
        request
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some(format!("Bearer {REVIEWER}").as_str()),
        "PPE authenticates with the reviewer token"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body).expect("the body is JSON"),
        serde_json::json!({
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {
                "user": AGENT,
                "groups": ["system:serviceaccounts", "system:serviceaccounts:team-a"],
                "nonResourceAttributes": { "path": "/tools/search", "verb": "post" }
            }
        }),
        "only the subject and the projected attributes leave PPE, not the tool arguments"
    );
}

#[tokio::test]
async fn no_opinion_from_the_api_server_denies() {
    let token = TokenFile::write(REVIEWER);
    let api = Arc::new(FakeTransport::new().json(REVIEW_PATH, 201, NO_OPINION));
    let engine = engine(&policy(&token, "", "search", NON_RESOURCE_STEP), Some(&api))
        .await
        .expect("the policy loads");

    let result = call(&engine, "search", serde_json::json!({}), Some(agent())).await;

    assert!(
        !result.continue_processing,
        "no authorizer allowed, so the request is denied"
    );
    assert!(
        format!("{:?}", result.violation).contains("not allowed by Kubernetes authorization"),
        "{:?}",
        result.violation
    );
}

#[tokio::test]
async fn resource_attributes_follow_the_tool_arguments() {
    let token = TokenFile::write(REVIEWER);
    let api = Arc::new(FakeTransport::new().respond_with(REVIEW_PATH, |request| {
        let review: serde_json::Value =
            serde_json::from_slice(&request.body).expect("the body is JSON");
        let attributes = &review["spec"]["resourceAttributes"];
        let allowed = attributes["namespace"] == "staging"
            && ["get", "invoke"].contains(&attributes["verb"].as_str().unwrap_or_default());
        Ok(HttpResponse::new(
            201,
            serde_json::json!({"status": {"allowed": allowed}})
                .to_string()
                .into(),
        ))
    }));
    let step = "
            resource_attributes:
              group: \"'mcp.example.com'\"
              resource: \"'tools'\"
              name: meta.entity_name
              namespace: args.environment
              verb: \"args.dry_run == true ? 'get' : 'invoke'\"";
    let engine = engine(&policy(&token, "", "deploy", step), Some(&api))
        .await
        .expect("the policy loads");

    let staging = call(
        &engine,
        "deploy",
        serde_json::json!({"environment": "staging", "dry_run": true}),
        Some(agent()),
    )
    .await;
    let production = call(
        &engine,
        "deploy",
        serde_json::json!({"environment": "production", "dry_run": false}),
        Some(agent()),
    )
    .await;

    assert!(
        staging.continue_processing,
        "staging is bound: {:?}",
        staging.violation
    );
    assert!(!production.continue_processing, "production has no binding");
    let sent = serde_json::from_slice::<serde_json::Value>(&api.requests()[0].body)
        .expect("the body is JSON");
    assert_eq!(
        sent["spec"]["resourceAttributes"],
        serde_json::json!({
            "group": "mcp.example.com",
            "resource": "tools",
            "name": "deploy",
            "namespace": "staging",
            "verb": "get"
        }),
        "a dry run asks only for `get`"
    );
}

#[tokio::test]
async fn a_step_can_review_a_different_subject() {
    let token = TokenFile::write(REVIEWER);
    let api = Arc::new(FakeTransport::new().json(REVIEW_PATH, 201, ALLOWED));
    let step = "
            subject:
              user: \"'system:serviceaccount:agents:' + meta.entity_name + '-bot'\"
              groups: \"[]\"
              extra: \"{'scopes.example.com/tier': ['gold']}\"
            non_resource_attributes:
              path: \"'/admin'\"
              verb: \"'get'\"";
    let engine = engine(&policy(&token, "", "search", step), Some(&api))
        .await
        .expect("the policy loads");

    let result = call(&engine, "search", serde_json::json!({}), Some(agent())).await;

    assert!(result.continue_processing, "{:?}", result.violation);
    let sent: serde_json::Value =
        serde_json::from_slice(&api.last_request().expect("a review").body).expect("JSON");
    assert_eq!(
        sent["spec"]["user"],
        "system:serviceaccount:agents:search-bot"
    );
    assert_eq!(
        sent["spec"].get("groups"),
        None,
        "an empty group list is omitted rather than sent"
    );
    assert_eq!(
        sent["spec"]["extra"],
        serde_json::json!({"scopes.example.com/tier": ["gold"]})
    );
}

#[tokio::test]
async fn no_answer_from_the_api_server_follows_on_error() {
    for (on_error, status, allowed) in [
        ("deny", 503, false),
        ("allow", 503, true),
        ("allow", 403, true),
    ] {
        let token = TokenFile::write(REVIEWER);
        let api = Arc::new(FakeTransport::new().json(REVIEW_PATH, status, "{}"));
        let block = format!("      on_error: {on_error}\n");
        let engine = engine(
            &policy(&token, &block, "search", NON_RESOURCE_STEP),
            Some(&api),
        )
        .await
        .expect("the policy loads");

        let result = call(&engine, "search", serde_json::json!({}), Some(agent())).await;

        assert_eq!(
            result.continue_processing, allowed,
            "on_error: {on_error} with a {status} answer: {:?}",
            result.violation
        );
    }
}

#[tokio::test]
async fn a_request_with_no_subject_denies_without_asking_even_under_on_error_allow() {
    let token = TokenFile::write(REVIEWER);
    let api = Arc::new(FakeTransport::new().json(REVIEW_PATH, 201, ALLOWED));
    let engine = engine(
        &policy(
            &token,
            "      on_error: allow\n",
            "search",
            NON_RESOURCE_STEP,
        ),
        Some(&api),
    )
    .await
    .expect("the policy loads");

    let result = call(&engine, "search", serde_json::json!({}), None).await;

    assert!(
        !result.continue_processing,
        "with no one to review, the step must deny rather than ask about nobody"
    );
    assert_eq!(api.call_count(), 0, "no review is sent without a subject");
}

#[tokio::test]
async fn the_superuser_group_is_never_sent_even_under_on_error_allow() {
    let token = TokenFile::write(REVIEWER);
    let api = Arc::new(FakeTransport::new().json(REVIEW_PATH, 201, ALLOWED));
    let engine = engine(
        &policy(
            &token,
            "      on_error: allow\n",
            "search",
            NON_RESOURCE_STEP,
        ),
        Some(&api),
    )
    .await
    .expect("the policy loads");
    let mut caller = agent();
    let subject = caller.subject.as_mut().expect("the agent has a subject");
    subject.roles.insert("system:masters".to_owned());

    let result = call(&engine, "search", serde_json::json!({}), Some(caller)).await;

    assert!(
        !result.continue_processing,
        "a review claiming system:masters would allow anything, so the step denies"
    );
    assert_eq!(api.call_count(), 0, "the superuser group never leaves PPE");
}

#[tokio::test]
async fn a_policy_the_resolver_cannot_run_fails_the_load() {
    let token = TokenFile::write(REVIEWER);
    let api = Arc::new(FakeTransport::new());
    let both = "
            resource_attributes:
              verb: \"'get'\"
            non_resource_attributes:
              path: \"'/x'\"
              verb: \"'get'\"";
    let bad_cel = "
            non_resource_attributes:
              path: \"'/tools/' +\"
              verb: \"'post'\"";
    let unknown_key = "
            non_resource_attributes:
              path: \"'/x'\"
              verb: \"'get'\"
            namespace: \"'team-a'\"";

    for (step, expected) in [
        (both, "exactly one of"),
        (bad_cel, "is not valid CEL"),
        (unknown_key, "unknown field"),
    ] {
        let error = engine(&policy(&token, "", "search", step), Some(&api))
            .await
            .err()
            .expect("the policy must not load");
        assert!(
            error.contains(expected),
            "expected '{expected}' in: {error}"
        );
    }

    let error = engine(&policy(&token, "", "search", NON_RESOURCE_STEP), None)
        .await
        .err()
        .expect("a SAR block without a transport must not load");
    assert!(error.contains("set_http_transport"), "{error}");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A reviewer token written to a temporary path, removed when the guard drops.
struct TokenFile {
    path: PathBuf,
}

impl TokenFile {
    fn write(contents: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("ppe-k8s-sar-{}-{n}", std::process::id()));
        std::fs::write(&path, contents).expect("the token file is writable");
        Self { path }
    }
}

impl Drop for TokenFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A policy with one `kubernetes-sar` block, extended by `block`, and one
/// route for `tool` whose only step has the body `step`.
fn policy(token: &TokenFile, block: &str, tool: &str, step: &str) -> String {
    format!(
        "
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: kubernetes-sar
      api_server:
        url: {API_SERVER}
        reviewer_token:
          kind: file
          path: {path}
{block}
routes:
  - tool: {tool}
    authorization:
      pre_invocation:
        - pdp(kubernetes-sar):{step}
",
        path = token.path.display(),
    )
}

/// An engine with `api` as its transport, if any, loaded with `yaml`.
async fn engine(yaml: &str, api: Option<&Arc<FakeTransport>>) -> Result<Arc<PolicyEngine>, String> {
    let engine = Arc::new(PolicyEngine::default());
    if let Some(api) = api {
        let transport: Arc<dyn HttpTransport> = Arc::<FakeTransport>::clone(api);
        engine.set_http_transport(transport);
    }
    let mut options = AplOptions::in_process();
    options.pdp_factories = vec![Arc::new(SubjectAccessReviewPdpFactory::new())];
    register_apl(&engine, options);
    engine.load_config_yaml(yaml).map_err(|e| format!("{e}"))?;
    engine.initialize().await.map_err(|e| format!("{e}"))?;
    Ok(engine)
}

/// The `ServiceAccount` a `TokenReview` would have resolved.
fn agent() -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some(AGENT.to_owned()),
            subject_type: Some(SubjectType::Service),
            roles: HashSet::from([
                "system:serviceaccounts".to_owned(),
                "system:serviceaccounts:team-a".to_owned(),
            ]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Call `tool` with `arguments`, as `subject` when one is given.
async fn call(
    engine: &PolicyEngine,
    tool: &str,
    arguments: serde_json::Value,
    subject: Option<SecurityExtension>,
) -> PipelineResult {
    let serde_json::Value::Object(arguments) = arguments else {
        panic!("tool-call arguments must be an object");
    };
    let payload = MessagePayload {
        message: Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".to_owned(),
                    name: tool.to_owned(),
                    arguments: arguments.into_iter().collect(),
                    namespace: None,
                },
            }],
        ),
    };
    let extensions = Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some(tool.to_owned()),
            ..Default::default()
        })),
        security: subject.map(Arc::new),
        ..Default::default()
    };
    let (result, _background) = engine
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, extensions, None)
        .await;
    result
}
