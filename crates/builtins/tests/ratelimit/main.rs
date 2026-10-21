// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! In-process proof that an APL route runs the embedded Limitador plugin.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests inspect the rate-limit decision"
)]

use std::collections::HashMap;
use std::sync::Arc;

use praxis_policy_apl_runtime::{AplOptions, register_apl};
use praxis_policy_builtins::plugins::ratelimit::{KIND, RateLimitFactory};
use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::extensions::{
    Extensions, HttpExtension, MetaExtension, SecurityExtension, SubjectExtension,
};
use praxis_policy_core::factory::PluginFactory as _;
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HttpHook, HttpPayload};
use praxis_policy_core::plugin::PluginConfig;

const POLICY: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_subject, read_headers]
    config:
      namespace: toystore
      counter_capacity: 1000
      limits:
        - max: 5
          seconds: 60
          conditions: ["subject_id == 'alice'", "http_method == 'GET'"]
        - max: 2
          seconds: 60
          conditions: ["subject_id == 'bob'", "http_method == 'GET'"]
global:
  authorization:
    pre_invocation:
      - "run(app-ratelimit)"
"#;

const CLAIM_POLICY: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_subject, read_claims, read_headers]
    config:
      namespace: claim-demo
      bindings:
        subject_id: subject.id
        http_method: http.method
        plan: claim.plan
      limits:
        - max: 1
          seconds: 60
          conditions: ["subject_id == 'alice'", "http_method == 'GET'", "plan == 'free'"]
global:
  authorization:
    pre_invocation:
      - "run(app-ratelimit)"
"#;

const GLOBAL_AND_ROUTE_POLICY: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: global-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_subject, read_headers]
    config:
      namespace: global-demo
      limits:
        - max: 5
          seconds: 60
          conditions: ["subject_id == 'alice'", "http_method == 'GET'"]
  - name: toys-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_subject, read_headers]
    config:
      namespace: toys-demo
      limits:
        - max: 2
          seconds: 60
          conditions: ["subject_id == 'bob'", "http_method == 'GET'"]
global:
  authorization:
    pre_invocation:
      - "run(global-ratelimit)"
routes:
  - http: /toys
    authorization:
      pre_invocation:
        - "run(toys-ratelimit)"
  - http:
      path_prefix: /
"#;

const HEADER_POLICY: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: global-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_headers]
    config:
      namespace: header-global-test
      bindings:
        demo_user: http.request_headers.x-demo-user
        http_method: http.method
      limits:
        - max: 5
          seconds: 300
          conditions: ["demo_user == 'alice'", "http_method == 'GET'"]
  - name: toys-ratelimit
    kind: ratelimit/limitador
    hooks: [http.request]
    mode: sequential
    capabilities: [read_headers]
    config:
      namespace: header-toys-test
      bindings:
        demo_user: http.request_headers.x-demo-user
        http_method: http.method
      limits:
        - max: 2
          seconds: 300
          conditions: ["demo_user == 'bob'", "http_method == 'GET'"]
global:
  authorization:
    pre_invocation:
      - "run(global-ratelimit)"
routes:
  - http: /toys
    authorization:
      pre_invocation:
        - "run(toys-ratelimit)"
  - http:
      path_prefix: /
"#;

async fn engine_with(policy: &str) -> Arc<PolicyEngine> {
    let manager = Arc::new(PolicyEngine::default());
    manager.register_factory(KIND, Box::new(RateLimitFactory));
    register_apl(&manager, AplOptions::in_process());
    manager
        .load_config_yaml(policy)
        .expect("rate-limit config loads");
    manager
        .initialize()
        .await
        .expect("rate limiter initializes");
    manager
}

async fn engine() -> Arc<PolicyEngine> {
    engine_with(POLICY).await
}

fn request_with_plan(
    subject_id: Option<&str>,
    method: Option<&str>,
    plan: Option<&str>,
) -> Extensions {
    request_with_plan_at_path(subject_id, method, plan, "/toys")
}

fn request_with_plan_at_path(
    subject_id: Option<&str>,
    method: Option<&str>,
    plan: Option<&str>,
    path: &str,
) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some(ENTITY_HTTP.to_owned()),
            entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
            ..Default::default()
        })),
        http: Some(Arc::new(HttpExtension {
            method: method.map(str::to_owned),
            path: Some(path.to_owned()),
            ..Default::default()
        })),
        security: Some(Arc::new(SecurityExtension {
            subject: subject_id.map(|id| SubjectExtension {
                id: Some(id.to_owned()),
                claims: plan.map_or_else(HashMap::new, |value| {
                    HashMap::from([("plan".to_owned(), serde_json::json!(value))])
                }),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn request(subject_id: Option<&str>, method: Option<&str>) -> Extensions {
    request_with_plan(subject_id, method, None)
}

fn request_at_path(subject_id: &str, method: &str, path: &str) -> Extensions {
    request_with_plan_at_path(Some(subject_id), Some(method), None, path)
}

fn gateway_request(user: &str, path: &str) -> Extensions {
    let mut extensions = request_with_plan_at_path(None, Some("GET"), None, path);
    Arc::make_mut(extensions.http.as_mut().expect("HTTP request fixture"))
        .request_headers
        .insert("x-demo-user".to_owned(), user.to_owned());
    extensions
}

async fn verdict_request(
    manager: &PolicyEngine,
    extensions: Extensions,
) -> (bool, Option<(String, Option<i64>)>) {
    let (result, _background) = manager
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, extensions, None)
        .await;
    (
        result.continue_processing,
        result.violation.map(|v| (v.code, v.proto_error_code)),
    )
}

async fn verdict(
    manager: &PolicyEngine,
    subject_id: Option<&str>,
    method: Option<&str>,
) -> (bool, Option<(String, Option<i64>)>) {
    verdict_request(manager, request(subject_id, method)).await
}

#[allow(clippy::print_stdout, reason = "show decisions in the in-process demo")]
fn show_verdict(label: &str, (allowed, violation): &(bool, Option<(String, Option<i64>)>)) {
    if *allowed {
        println!("{label}: ALLOW");
    } else if let Some((code, Some(status))) = violation {
        println!("{label}: DENY {code} (proto_error_code={status})");
    } else {
        println!("{label}: DENY {violation:?}");
    }
}

#[tokio::test]
async fn counts_alice_and_bob_independently_and_returns_429() {
    let manager = engine().await;

    // POST does not match either GET limit and must leave Alice's balance alone.
    let post = verdict(&manager, Some("alice"), Some("POST")).await;
    show_verdict("alice POST", &post);
    assert!(post.0);
    for number in 1..=5 {
        let result = verdict(&manager, Some("alice"), Some("GET")).await;
        show_verdict(&format!("alice GET #{number}"), &result);
        assert!(result.0);
    }
    for number in 1..=2 {
        let result = verdict(&manager, Some("bob"), Some("GET")).await;
        show_verdict(&format!("bob GET #{number}"), &result);
        assert!(result.0);
    }

    let alice_denied = verdict(&manager, Some("alice"), Some("GET")).await;
    show_verdict("alice GET #6", &alice_denied);
    assert_eq!(
        alice_denied,
        (false, Some(("ratelimit.exceeded".to_owned(), Some(429))))
    );
    let bob_denied = verdict(&manager, Some("bob"), Some("GET")).await;
    show_verdict("bob GET #3", &bob_denied);
    assert_eq!(
        bob_denied,
        (false, Some(("ratelimit.exceeded".to_owned(), Some(429))))
    );
}

#[tokio::test]
async fn a_string_claim_from_the_ppe_bag_selects_a_limit() {
    let manager = engine_with(CLAIM_POLICY).await;
    let free = || request_with_plan(Some("alice"), Some("GET"), Some("free"));
    let paid = || request_with_plan(Some("alice"), Some("GET"), Some("paid"));

    assert!(verdict_request(&manager, free()).await.0);
    assert_eq!(
        verdict_request(&manager, free()).await,
        (false, Some(("ratelimit.exceeded".to_owned(), Some(429))))
    );
    assert!(verdict_request(&manager, paid()).await.0);
    assert_eq!(
        verdict_request(&manager, request(Some("alice"), Some("GET")))
            .await
            .1,
        Some(("ratelimit.missing_attribute".to_owned(), None))
    );
}

#[tokio::test]
async fn demo_global_and_route_scoped_rate_limits() {
    let manager = engine_with(GLOBAL_AND_ROUTE_POLICY).await;

    for number in 1..=5 {
        let result = verdict_request(&manager, request_at_path("alice", "GET", "/other")).await;
        show_verdict(&format!("global alice /other GET #{number}"), &result);
        assert!(result.0);
    }
    let global_denied = verdict_request(&manager, request_at_path("alice", "GET", "/other")).await;
    show_verdict("global alice /other GET #6", &global_denied);
    assert_eq!(
        global_denied,
        (false, Some(("ratelimit.exceeded".to_owned(), Some(429))))
    );

    for number in 1..=2 {
        let result = verdict_request(&manager, request_at_path("bob", "GET", "/toys")).await;
        show_verdict(&format!("route bob /toys GET #{number}"), &result);
        assert!(result.0);
    }
    let route_denied = verdict_request(&manager, request_at_path("bob", "GET", "/toys")).await;
    show_verdict("route bob /toys GET #3", &route_denied);
    assert_eq!(
        route_denied,
        (false, Some(("ratelimit.exceeded".to_owned(), Some(429))))
    );

    let outside_route = verdict_request(&manager, request_at_path("bob", "GET", "/other")).await;
    show_verdict("bob /other GET outside route", &outside_route);
    assert!(outside_route.0);
}

#[tokio::test]
async fn header_binding_sets_http_429() {
    let manager = engine_with(HEADER_POLICY).await;

    for _ in 0..5 {
        assert!(
            verdict_request(&manager, gateway_request("alice", "/other"))
                .await
                .0
        );
    }
    let (result, _) = manager
        .invoke_named::<HttpHook>(
            HOOK_HTTP_REQUEST,
            HttpPayload,
            gateway_request("alice", "/other"),
            None,
        )
        .await;
    assert!(!result.continue_processing);
    let violation = result
        .violation
        .expect("Alice exceeds the global rate limit");
    assert_eq!(violation.code, "ratelimit.exceeded");
    assert_eq!(violation.proto_error_code, Some(429));
    assert_eq!(
        violation.details.get("http.status"),
        Some(&serde_json::json!(429))
    );

    for _ in 0..2 {
        assert!(
            verdict_request(&manager, gateway_request("bob", "/toys"))
                .await
                .0
        );
    }
    assert_eq!(
        verdict_request(&manager, gateway_request("bob", "/toys"))
            .await
            .1,
        Some(("ratelimit.exceeded".to_owned(), Some(429)))
    );
    assert!(
        verdict_request(&manager, gateway_request("bob", "/other"))
            .await
            .0
    );
}

#[tokio::test]
async fn missing_identity_or_http_method_denies_before_the_counter() {
    let manager = engine().await;
    assert_eq!(
        verdict(&manager, None, Some("GET")).await.1,
        Some(("ratelimit.no_identity".to_owned(), None))
    );
    assert_eq!(
        verdict(&manager, Some("alice"), None).await.1,
        Some(("ratelimit.no_http_method".to_owned(), None))
    );
    assert!(verdict(&manager, Some("alice"), Some("GET")).await.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_do_not_exceed_the_in_memory_limit() {
    let manager = engine().await;
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let manager = Arc::clone(&manager);
        tasks.push(tokio::spawn(async move {
            verdict(&manager, Some("alice"), Some("GET")).await.0
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        admitted += usize::from(task.await.expect("request task completes"));
    }
    assert_eq!(admitted, 5);
}

#[test]
fn malformed_condition_fails_during_plugin_construction() {
    let config = PluginConfig {
        name: "app-ratelimit".to_owned(),
        kind: KIND.to_owned(),
        config: Some(serde_json::json!({
            "namespace": "toystore",
            "limits": [{
                "max": 5,
                "seconds": 60,
                "conditions": ["subject_id =="],
            }],
        })),
        ..Default::default()
    };
    let error = RateLimitFactory
        .create(&config)
        .err()
        .expect("malformed CEL must fail at construction");
    assert!(matches!(*error, PluginError::Config { .. }));
}

#[test]
fn unbound_cel_variable_fails_during_plugin_construction() {
    let config = PluginConfig {
        name: "app-ratelimit".to_owned(),
        kind: KIND.to_owned(),
        config: Some(serde_json::json!({
            "namespace": "toystore",
            "limits": [{
                "max": 5,
                "seconds": 60,
                "conditions": ["plan == 'free'"],
            }],
        })),
        ..Default::default()
    };
    let error = RateLimitFactory
        .create(&config)
        .err()
        .expect("unbound CEL variable must fail at construction");
    assert!(matches!(*error, PluginError::Config { .. }));
    assert!(error.to_string().contains("unbound CEL variable 'plan'"));
}

#[test]
fn http_only_global_limiter_rejects_entity_routes_at_startup() {
    for (route, route_key) in [
        ("tool: get_toys", "tool:get_toys"),
        ("llm: demo-model", "llm:demo-model"),
    ] {
        let manager = Arc::new(PolicyEngine::default());
        manager.register_factory(KIND, Box::new(RateLimitFactory));
        register_apl(&manager, AplOptions::in_process());
        let policy = format!("{HEADER_POLICY}  - {route}\n");
        let error = manager
            .load_config_yaml(&policy)
            .expect_err("HTTP-only limiter cannot run in an entity route")
            .to_string();
        assert!(error.contains(route_key), "{error}");
        assert!(error.contains("global-ratelimit"), "{error}");
        assert!(error.contains("http.request"), "{error}");
        assert!(error.contains("no matching registered handler"), "{error}");
    }
}
