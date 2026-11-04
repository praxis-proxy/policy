// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The embedded Limitador plugin, dispatched from `rate_limits:` on the
//! pre- and post-identity rate-limit hooks.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests inspect the rate-limit decision"
)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use praxis_policy_apl_cmf::constants::DETAIL_HTTP_STATUS;
use praxis_policy_builtins::plugins::ratelimit::{
    CODE_CHECK_FAILED, CODE_EXCEEDED, CODE_MISSING_ATTRIBUTE, CODE_NO_HTTP_METHOD,
    CODE_NO_IDENTITY, CODE_UNSUPPORTED_ATTRIBUTE, DETAIL_LIMIT, DETAIL_REMAINING,
    DETAIL_RETRY_AFTER_SECONDS, DETAIL_WINDOW_SECONDS, KIND, RateLimitFactory,
};
use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL, ENTITY_TOOL};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::{PluginError, PluginViolation};
#[cfg(feature = "fips")]
use praxis_policy_core::extensions::llm::{
    LlmInstruction, LlmInstructionRole, LlmRequest, LlmRequestParts,
};
use praxis_policy_core::extensions::{
    Extensions, HttpExtension, MetaExtension, SecurityExtension, SubjectExtension,
};
use praxis_policy_core::factory::PluginFactory as _;
use praxis_policy_core::http_hook::{HttpHook, HttpPayload};
use praxis_policy_core::plugin::PluginConfig;
use praxis_policy_core::ratelimit_hook::{
    HOOK_RATELIMIT_POST_IDENTITY, HOOK_RATELIMIT_PRE_IDENTITY,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

#[cfg(feature = "fips")]
const CRYPTO_FAILURE_INSTRUCTION: &str = "private instruction for crypto failure coverage";

const POLICY: &str = r#"
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
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
  rate_limits: [app-ratelimit]
"#;

const CLAIM_POLICY: &str = r#"
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
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
  rate_limits: [app-ratelimit]
"#;

const GLOBAL_AND_ROUTE_POLICY: &str = r#"
plugins:
  - name: global-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: global-demo
      limits:
        - max: 5
          seconds: 60
          conditions: ["subject_id == 'alice'", "http_method == 'GET'"]
  - name: toys-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: toys-demo
      limits:
        - max: 2
          seconds: 60
          conditions: ["subject_id == 'bob'", "http_method == 'GET'"]
global:
  rate_limits: [global-ratelimit]
routes:
  - http: /toys
    rate_limits: [toys-ratelimit]
  - http:
      path_prefix: /
"#;

const ROUTE_OVERRIDE_POLICY: &str = r#"
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: toystore
      limits:
        - max: 5
          seconds: 60
          conditions: ["subject_id == 'alice'", "http_method == 'GET'"]
global:
  rate_limits: [app-ratelimit]
routes:
  - http: /toys
    rate_limits:
      replace_inherited: true
      steps:
        - name: app-ratelimit
          config:
            namespace: route-override
            limits:
              - max: 1
                seconds: 60
"#;

const MACRO_POLICY: &str = r#"
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: macro-demo
      bindings:
        path: http.path
        subject_id: subject.id
      limits:
        - max: 1
          seconds: 60
          conditions: ["['/api/'].exists(prefix, [prefix].all(prefix, path.startsWith(prefix)))"]
          variables: ["['alice', 'bob'].filter(id, id == subject_id).map(id, id)[0]"]
global:
  rate_limits: [app-ratelimit]
"#;

const HEADER_POLICY: &str = r#"
plugins:
  - name: global-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
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
    hooks: [ratelimit.post_identity]
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
  rate_limits: [global-ratelimit]
routes:
  - http: /toys
    rate_limits: [toys-ratelimit]
  - http:
      path_prefix: /
"#;

const PER_USER_POLICY: &str = r#"
plugins:
  - name: per-user-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_claims, read_headers]
    config:
      namespace: per-user
      bindings:
        subject_id: subject.id
        http_method: http.method
        plan: claim.plan
      limits:
        - max: 2
          seconds: 60
          variables: [subject_id]
        - max: 1
          seconds: 60
          conditions: ["plan == 'free'", "http_method == 'POST'"]
          variables: [subject_id]
global:
  rate_limits: [per-user-limits]
"#;

const EDGE_POLICY: &str = "
plugins:
  - name: edge-limits
    kind: ratelimit/limitador
    hooks: [ratelimit.pre_identity]
    capabilities: [read_headers]
    config:
      namespace: edge
      bindings:
        client: http.client_address
      limits:
        - max: 5
          seconds: 60
          variables: [client]
        - max: 2
          seconds: 60
global:
  rate_limits: [edge-limits]
";

const FIRST_CLIENT: &str = "203.0.113.7";

const SECOND_CLIENT: &str = "198.51.100.4";

type Verdict = (bool, Option<(String, Option<i64>)>);

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn counts_alice_and_bob_independently_and_returns_429() {
    let manager = engine().await;

    let post = verdict(&manager, Some("alice"), Some("POST")).await;
    assert!(
        post.0,
        "POST does not match either GET limit and must leave Alice's balance alone"
    );
    for number in 1..=5 {
        let result = verdict(&manager, Some("alice"), Some("GET")).await;
        assert!(result.0, "Alice's GET #{number} is within her limit of 5");
    }
    for number in 1..=2 {
        let result = verdict(&manager, Some("bob"), Some("GET")).await;
        assert!(result.0, "Bob's GET #{number} is within his limit of 2");
    }

    let alice_denied = verdict(&manager, Some("alice"), Some("GET")).await;
    assert_eq!(
        alice_denied,
        (false, Some((CODE_EXCEEDED.to_owned(), Some(429)))),
        "Alice's sixth GET exceeds her limit with a 429"
    );
    let bob_denied = verdict(&manager, Some("bob"), Some("GET")).await;
    assert_eq!(
        bob_denied,
        (false, Some((CODE_EXCEEDED.to_owned(), Some(429)))),
        "Bob's third GET exceeds his limit with a 429"
    );
}

#[tokio::test]
async fn a_string_claim_from_the_ppe_bag_selects_a_limit() {
    let manager = engine_with(CLAIM_POLICY).await;
    let free = || request_with_plan(Some("alice"), Some("GET"), Some("free"));
    let paid = || request_with_plan(Some("alice"), Some("GET"), Some("paid"));

    assert!(
        verdict_request(&manager, free()).await.0,
        "the first free-plan GET is within the limit"
    );
    assert_eq!(
        verdict_request(&manager, free()).await,
        (false, Some((CODE_EXCEEDED.to_owned(), Some(429)))),
        "the second free-plan GET exceeds the limit of 1"
    );
    assert!(
        verdict_request(&manager, paid()).await.0,
        "a paid-plan GET matches no limit"
    );
    assert_eq!(
        verdict_request(&manager, request(Some("alice"), Some("GET")))
            .await
            .1,
        Some((CODE_MISSING_ATTRIBUTE.to_owned(), Some(400))),
        "a request without the bound claim denies"
    );
}

#[tokio::test]
async fn demo_global_and_route_scoped_rate_limits() {
    let manager = engine_with(GLOBAL_AND_ROUTE_POLICY).await;

    for number in 1..=5 {
        let result = verdict_request(&manager, request_at_path("alice", "GET", "/other")).await;
        assert!(result.0, "Alice's global GET #{number} is within the limit");
    }
    let global_denied = verdict_request(&manager, request_at_path("alice", "GET", "/other")).await;
    assert_eq!(
        global_denied,
        (false, Some((CODE_EXCEEDED.to_owned(), Some(429)))),
        "Alice's sixth GET exceeds the global limit"
    );

    for number in 1..=2 {
        let result = verdict_request(&manager, request_at_path("bob", "GET", "/toys")).await;
        assert!(
            result.0,
            "Bob's /toys GET #{number} is within the route limit"
        );
    }
    let route_denied = verdict_request(&manager, request_at_path("bob", "GET", "/toys")).await;
    assert_eq!(
        route_denied,
        (false, Some((CODE_EXCEEDED.to_owned(), Some(429)))),
        "Bob's third /toys GET exceeds the route limit"
    );

    let outside_route = verdict_request(&manager, request_at_path("bob", "GET", "/other")).await;
    assert!(
        outside_route.0,
        "the route limit does not apply outside /toys"
    );
}

#[tokio::test]
async fn header_binding_sets_http_429() {
    let manager = engine_with(HEADER_POLICY).await;

    for _ in 0..5 {
        assert!(
            verdict_request(&manager, gateway_request("alice", "/other"))
                .await
                .0,
            "Alice is within the global header-selected limit"
        );
    }
    let (result, _) = manager
        .invoke_named::<HttpHook>(
            HOOK_RATELIMIT_POST_IDENTITY,
            HttpPayload,
            gateway_request("alice", "/other"),
            None,
        )
        .await;
    assert!(
        !result.continue_processing,
        "Alice's sixth request is denied"
    );
    let violation = result
        .violation
        .expect("Alice exceeds the global rate limit");
    assert_eq!(
        violation.code, CODE_EXCEEDED,
        "the denial is a rate-limit excess"
    );
    assert_eq!(
        violation.proto_error_code,
        Some(429),
        "the denial carries HTTP 429"
    );
    assert_eq!(
        violation.details.get(DETAIL_HTTP_STATUS),
        Some(&serde_json::json!(429)),
        "the details carry the HTTP status"
    );

    for _ in 0..2 {
        assert!(
            verdict_request(&manager, gateway_request("bob", "/toys"))
                .await
                .0,
            "Bob is within the /toys header-selected limit"
        );
    }
    assert_eq!(
        verdict_request(&manager, gateway_request("bob", "/toys"))
            .await
            .1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "Bob's third /toys request exceeds the route limit"
    );
    assert!(
        verdict_request(&manager, gateway_request("bob", "/other"))
            .await
            .0,
        "the route limit does not apply outside /toys"
    );
}

#[tokio::test]
async fn missing_identity_or_http_method_denies_before_the_counter() {
    let manager = engine().await;
    assert_eq!(
        verdict(&manager, None, Some("GET")).await.1,
        Some((CODE_NO_IDENTITY.to_owned(), Some(401))),
        "a request without a subject denies"
    );
    assert_eq!(
        verdict(&manager, Some("alice"), None).await.1,
        Some((CODE_NO_HTTP_METHOD.to_owned(), Some(400))),
        "a request without a method denies"
    );
    assert!(
        verdict(&manager, Some("alice"), Some("GET")).await.0,
        "denied requests leave Alice's counter untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_do_not_exceed_the_in_memory_limit() {
    let manager = engine().await;
    let barrier = Arc::new(tokio::sync::Barrier::new(20));
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let manager = Arc::clone(&manager);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            verdict(&manager, Some("alice"), Some("GET")).await.0
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        admitted += usize::from(task.await.expect("request task completes"));
    }
    assert_eq!(admitted, 5, "concurrent requests admit exactly the limit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_requests_share_the_route_override_counter() {
    let manager = engine_with(ROUTE_OVERRIDE_POLICY).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(20));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let manager = Arc::clone(&manager);
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            verdict(&manager, Some("alice"), Some("GET")).await
        });
    }
    let mut admitted = 0;
    while let Some(result) = tasks.join_next().await {
        let verdict = result.expect("request task completes");
        if verdict.0 {
            admitted += 1;
        } else {
            assert_eq!(
                verdict.1,
                Some((CODE_EXCEEDED.to_owned(), Some(429))),
                "every refused first request is a rate-limit excess"
            );
        }
    }
    assert_eq!(
        admitted, 1,
        "all first requests must share the same counter"
    );
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "later requests must retain the installed counter"
    );
}

#[tokio::test]
async fn cel_macros_select_limits_and_partition_counters() {
    let manager = engine_with(MACRO_POLICY).await;
    for subject in ["alice", "bob"] {
        for _ in 0..2 {
            assert!(
                verdict_request(&manager, request_at_path(subject, "GET", "/public"))
                    .await
                    .0,
                "nonmatching paths must leave counters unchanged"
            );
        }
        assert!(
            verdict_request(&manager, request_at_path(subject, "GET", "/api/toys"))
                .await
                .0,
            "each subject must get an independent counter"
        );
        assert_eq!(
            verdict_request(&manager, request_at_path(subject, "GET", "/api/toys"))
                .await
                .1,
            Some((CODE_EXCEEDED.to_owned(), Some(429))),
            "matching macro conditions must enforce the counter for {subject}"
        );
    }
}

#[tokio::test]
async fn limit_metadata_conditions_select_and_enforce_a_limit() {
    let policy = POLICY.replace("max: 5", "max: 1").replace(
        "subject_id == 'alice'",
        "limit.name == null && limit.id == null && subject_id == 'alice'",
    );
    let manager = engine_with(&policy).await;
    assert!(
        verdict(&manager, Some("alice"), Some("GET")).await.0,
        "the first GET is within the limit"
    );
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the limit metadata condition selects the limit of 1"
    );
    assert!(
        verdict(&manager, Some("alice"), Some("POST")).await.0,
        "a POST matches no limit"
    );
}

#[tokio::test]
async fn a_global_limiter_applies_after_identity_on_a_tool_route() {
    let manager = engine_with(&format!("{HEADER_POLICY}  - tool: get_toys\n")).await;
    let tool_request = || {
        let mut extensions = gateway_request("alice", "/mcp");
        extensions.meta = Some(Arc::new(MetaExtension {
            entity_type: Some(ENTITY_TOOL.to_owned()),
            entity_name: Some("get_toys".to_owned()),
            ..Default::default()
        }));
        extensions
    };

    for number in 1..=5 {
        assert!(
            verdict_request(&manager, tool_request()).await.0,
            "Alice's tool call #{number} is within the inherited global limit"
        );
    }
    assert_eq!(
        verdict_request(&manager, tool_request()).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the inherited global limit counts tool calls"
    );

    let mut without_http = tool_request();
    without_http.http = None;
    assert_eq!(
        verdict_request(&manager, without_http).await.1,
        Some((CODE_MISSING_ATTRIBUTE.to_owned(), Some(400))),
        "a tool call without its HTTP request fails closed"
    );
}

#[tokio::test]
async fn a_condition_evaluation_error_denies_as_check_failed() {
    let policy = POLICY.replace("subject_id == 'alice'", "int(subject_id) > 1");
    let manager = engine_with(&policy).await;
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await,
        (false, Some((CODE_CHECK_FAILED.to_owned(), Some(503)))),
        "a non-numeric subject must deny"
    );
    assert!(
        verdict(&manager, Some("7"), Some("GET")).await.0,
        "the limiter must keep serving after a condition evaluation error"
    );

    let with_metadata = POLICY.replace(
        "subject_id == 'alice'",
        "limit.name == null && int(subject_id) > 1",
    );
    let manager = engine_with(&with_metadata).await;
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await,
        (false, Some((CODE_CHECK_FAILED.to_owned(), Some(503)))),
        "a condition using limit metadata must fail before Limitador unwraps the error"
    );
}

#[tokio::test]
async fn an_unresolved_computed_key_denies_before_other_counters_change() {
    let policy = r#"
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: computed-key
      bindings:
        subject_id: subject.id
        http_method: http.method
      limits:
        - max: 1
          seconds: 60
          variables: [subject_id]
        - max: 1
          seconds: 60
          conditions: ["http_method == 'GET'"]
          variables: [subject_id, "{'alice': 'known'}[subject_id]"]
global:
  rate_limits: [app-ratelimit]
"#;
    let manager = engine_with(policy).await;

    start_capture();
    let violation = violation_at(
        &manager,
        HOOK_RATELIMIT_POST_IDENTITY,
        request(Some("charlie"), Some("GET")),
    )
    .await
    .expect("a matching rule with no computed key denies");
    let errors = finish_capture(tracing::Level::ERROR);
    assert_eq!(
        (violation.code.as_str(), violation.proto_error_code),
        (CODE_CHECK_FAILED, Some(503)),
        "a missing computed key denies even when another rule has a counter"
    );
    assert_eq!(
        violation.details.len(),
        1,
        "the client sees only the status, not the rule or expression"
    );
    assert!(
        errors.iter().any(|event| {
            event.contains("limits[1]") && event.contains("{'alice': 'known'}[subject_id]")
        }),
        "the operator log names the unresolved expression: {errors:?}"
    );
    assert!(
        verdict(&manager, Some("charlie"), Some("POST")).await.0,
        "the failed GET must leave the other rule's counter untouched"
    );
    assert_eq!(
        verdict(&manager, Some("charlie"), Some("POST")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the other rule must still enforce its own counter"
    );
    assert!(
        verdict(&manager, Some("alice"), Some("GET")).await.0,
        "a computed key that resolves must count normally"
    );
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "resolved computed keys must enforce their limit"
    );
}

#[tokio::test]
async fn a_computed_key_that_fails_to_evaluate_denies_as_check_failed() {
    let policy = r#"
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: computed-key-error
      bindings:
        subject_id: subject.id
      limits:
        - max: 5
          seconds: 60
          variables: ["[subject_id]"]
global:
  rate_limits: [app-ratelimit]
"#;
    let manager = engine_with(policy).await;

    start_capture();
    let violation = violation_at(
        &manager,
        HOOK_RATELIMIT_POST_IDENTITY,
        request(Some("alice"), Some("GET")),
    )
    .await
    .expect("a counter expression that cannot form a key denies");
    let errors = finish_capture(tracing::Level::ERROR);
    assert_eq!(
        (violation.code.as_str(), violation.proto_error_code),
        (CODE_CHECK_FAILED, Some(503)),
        "an expression evaluating to a list cannot key a counter"
    );
    assert!(
        errors
            .iter()
            .any(|event| event.contains("limits[0]") && event.contains("failed")),
        "the operator log names the failing expression: {errors:?}"
    );
}

#[tokio::test]
async fn a_panicking_condition_on_a_computed_key_rule_denies_as_check_failed() {
    let policy = r#"
plugins:
  - name: app-ratelimit
    kind: ratelimit/limitador
    hooks: [ratelimit.post_identity]
    capabilities: [read_subject, read_headers]
    config:
      namespace: computed-key-panic
      bindings:
        subject_id: subject.id
      limits:
        - max: 5
          seconds: 60
          conditions: ["int(subject_id) > 1"]
          variables: ["{'7': 'known'}[subject_id]"]
global:
  rate_limits: [app-ratelimit]
"#;
    let manager = engine_with(policy).await;

    assert_eq!(
        verdict_at(
            &manager,
            HOOK_RATELIMIT_POST_IDENTITY,
            request(Some("alice"), Some("GET")),
        )
        .await,
        (false, Some((CODE_CHECK_FAILED.to_owned(), Some(503)))),
        "a condition that panics while checking computed keys denies"
    );
    assert!(
        verdict_at(
            &manager,
            HOOK_RATELIMIT_POST_IDENTITY,
            request(Some("7"), Some("GET")),
        )
        .await
        .0,
        "the limiter keeps serving requests whose condition evaluates"
    );
}

#[tokio::test]
async fn an_unreferenced_binding_does_not_require_its_attribute() {
    let manager = engine_with(&CLAIM_POLICY.replace(", \"plan == 'free'\"", "")).await;
    assert!(
        verdict(&manager, Some("alice"), Some("GET")).await.0,
        "no limit references `plan`, so a request without the claim must pass"
    );
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the referenced bindings must still select the limit"
    );
}

#[tokio::test]
async fn a_numeric_claim_is_an_unsupported_attribute() {
    let manager = engine_with(CLAIM_POLICY).await;
    let mut extensions = request(Some("alice"), Some("GET"));
    let security = Arc::make_mut(extensions.security.as_mut().expect("security fixture"));
    security
        .subject
        .as_mut()
        .expect("subject fixture")
        .claims
        .insert("plan".to_owned(), serde_json::json!(3));
    assert_eq!(
        verdict_request(&manager, extensions).await.1,
        Some((CODE_UNSUPPORTED_ATTRIBUTE.to_owned(), Some(400))),
        "a bound attribute present with a non-string value must deny"
    );
}

#[tokio::test]
async fn a_per_user_limit_counts_each_subject_and_a_free_post_counts_twice() {
    let manager = engine_with(PER_USER_POLICY).await;
    let alice = |method| request_with_plan(Some("alice"), Some(method), Some("free"));
    let bob = || request_with_plan(Some("bob"), Some("GET"), Some("paid"));

    assert!(
        verdict_request(&manager, alice("POST")).await.0,
        "Alice's first POST is within both limits"
    );
    assert_eq!(
        verdict_request(&manager, alice("POST")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the free-plan POST limit of 1 is spent"
    );
    assert!(
        verdict_request(&manager, alice("GET")).await.0,
        "the refused POST did not spend Alice's per-user balance"
    );
    assert_eq!(
        verdict_request(&manager, alice("GET")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the first POST and one GET spent Alice's per-user limit of 2"
    );
    for number in 1..=2 {
        assert!(
            verdict_request(&manager, bob()).await.0,
            "Bob's GET #{number} counts on his own per-user counter"
        );
    }
    assert_eq!(
        verdict_request(&manager, bob()).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "Bob's third GET exceeds his own per-user limit"
    );
}

#[tokio::test]
async fn a_pre_identity_limit_counts_each_client_address() {
    let manager = engine_with(&EDGE_POLICY.replace("max: 2", "max: 100")).await;
    for number in 1..=5 {
        assert!(
            pre_identity_verdict(&manager, edge_request(Some(FIRST_CLIENT)))
                .await
                .0,
            "request #{number} from the first address is within its limit"
        );
    }
    assert_eq!(
        pre_identity_verdict(&manager, edge_request(Some(FIRST_CLIENT)))
            .await
            .1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the first address exceeds its limit of 5"
    );
    assert!(
        pre_identity_verdict(&manager, edge_request(Some(SECOND_CLIENT)))
            .await
            .0,
        "the second address counts on its own counter"
    );
    assert_eq!(
        pre_identity_verdict(&manager, edge_request(Some("[::ffff:203.0.113.7]:4431")))
            .await
            .1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "a mapped, port-bearing form of the first address shares its counter"
    );
}

#[tokio::test]
async fn the_client_address_needs_read_headers() {
    let manager = engine_with(&EDGE_POLICY.replace("[read_headers]", "[read_query]")).await;
    assert_eq!(
        pre_identity_verdict(&manager, edge_request(Some(FIRST_CLIENT)))
            .await
            .1,
        Some((CODE_MISSING_ATTRIBUTE.to_owned(), Some(400))),
        "without read_headers the address is filtered out and the limiter fails closed"
    );
}

#[tokio::test]
async fn a_missing_client_address_denies_before_any_counter_changes() {
    let manager = engine_with(EDGE_POLICY).await;
    for _ in 0..3 {
        assert_eq!(
            pre_identity_verdict(&manager, edge_request(None)).await.1,
            Some((CODE_MISSING_ATTRIBUTE.to_owned(), Some(400))),
            "a request without a client address denies"
        );
    }
    for number in 1..=2 {
        assert!(
            pre_identity_verdict(&manager, edge_request(Some(FIRST_CLIENT)))
                .await
                .0,
            "request #{number} is within the shared limit, so the denials spent none of it"
        );
    }
    assert_eq!(
        pre_identity_verdict(&manager, edge_request(Some(SECOND_CLIENT)))
            .await
            .1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "the shared limit of 2 is spent by addressed requests only"
    );
}

#[tokio::test]
async fn a_post_identity_limiter_does_not_run_at_pre_identity() {
    let manager = engine().await;
    for _ in 0..10 {
        assert!(
            pre_identity_verdict(&manager, request(Some("alice"), Some("GET")))
                .await
                .0,
            "a post-identity limiter registers on its own hook only"
        );
    }
    assert!(
        verdict(&manager, Some("alice"), Some("GET")).await.0,
        "the pre-identity calls spent none of the post-identity balance"
    );
}

#[tokio::test]
async fn a_429_carries_only_client_safe_details() {
    let manager = engine_with(&POLICY.replace("max: 5", "max: 1")).await;
    assert!(
        verdict(&manager, Some("alice"), Some("GET")).await.0,
        "the first GET is within the limit of 1"
    );

    let violation = violation_at(
        &manager,
        HOOK_RATELIMIT_POST_IDENTITY,
        request(Some("alice"), Some("GET")),
    )
    .await
    .expect("the second GET exceeds the limit");

    assert_eq!(violation.code, CODE_EXCEEDED, "the denial is an excess");
    assert_eq!(violation.proto_error_code, Some(429), "the status is 429");
    let mut keys: Vec<&str> = violation.details.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            DETAIL_HTTP_STATUS,
            DETAIL_LIMIT,
            DETAIL_REMAINING,
            DETAIL_RETRY_AFTER_SECONDS,
            DETAIL_WINDOW_SECONDS,
        ],
        "the details hold the client-safe fields and nothing else"
    );
    assert_eq!(
        violation.details[DETAIL_HTTP_STATUS],
        serde_json::json!(429),
        "the details carry the HTTP status"
    );
    assert_eq!(
        violation.details[DETAIL_REMAINING],
        serde_json::json!(0),
        "nothing remains"
    );
    assert_eq!(
        violation.details[DETAIL_LIMIT],
        serde_json::json!(1),
        "the limit is the configured max"
    );
    assert_eq!(
        violation.details[DETAIL_WINDOW_SECONDS],
        serde_json::json!(60),
        "the window is the configured seconds"
    );
    let retry_after = violation.details[DETAIL_RETRY_AFTER_SECONDS]
        .as_u64()
        .expect("retry_after_seconds is a whole number");
    assert!(
        (1..=60).contains(&retry_after),
        "retry_after_seconds is positive and within the window: {retry_after}"
    );
    let rendered = format!("{} {:?}", violation.reason, violation.details);
    for leaked in ["toystore", "subject_id", "read_subject", "read_headers"] {
        assert!(
            !rendered.contains(leaked),
            "the response must not reveal `{leaked}`: {rendered}"
        );
    }
}

#[tokio::test]
async fn a_429_describes_the_most_restrictive_matched_counter() {
    let manager = engine_with(PER_USER_POLICY).await;
    let alice_post = || request_with_plan(Some("alice"), Some("POST"), Some("free"));
    assert!(
        verdict_request(&manager, alice_post()).await.0,
        "the first POST is within both limits"
    );

    let violation = violation_at(&manager, HOOK_RATELIMIT_POST_IDENTITY, alice_post())
        .await
        .expect("the second POST exceeds the free-plan limit");

    assert_eq!(
        violation.details[DETAIL_LIMIT],
        serde_json::json!(1),
        "the free-plan limit of 1 has less left than the per-user limit of 2"
    );
    assert_eq!(
        violation.details[DETAIL_REMAINING],
        serde_json::json!(0),
        "the most restrictive counter has nothing left"
    );
}

#[tokio::test]
async fn a_429_on_two_exhausted_counters_waits_for_the_longer_window() {
    let policy = PER_USER_POLICY
        .replace(
            "- max: 2\n          seconds: 60",
            "- max: 1\n          seconds: 3600",
        )
        .replace(
            "- max: 1\n          seconds: 60\n          conditions: [\"plan == 'free'\", \
             \"http_method == 'POST'\"]",
            "- max: 1\n          seconds: 1",
        );
    let manager = engine_with(&policy).await;
    let alice = || request_with_plan(Some("alice"), Some("GET"), Some("free"));
    assert!(
        verdict_request(&manager, alice()).await.0,
        "the first request is within both limits"
    );

    let violation = violation_at(&manager, HOOK_RATELIMIT_POST_IDENTITY, alice())
        .await
        .expect("the second request exhausts both counters");

    assert_eq!(
        violation.details[DETAIL_WINDOW_SECONDS],
        serde_json::json!(3600),
        "the hour counter is the one a client waits on: {:?}",
        violation.details
    );
    let retry_after = violation.details[DETAIL_RETRY_AFTER_SECONDS]
        .as_u64()
        .expect("retry_after_seconds is a whole number");
    assert!(
        retry_after > 1,
        "retrying after the one-second window would be denied again: {retry_after}"
    );
}

#[tokio::test]
async fn a_lowercase_method_matches_an_uppercase_limit() {
    let manager = engine_with(&POLICY.replace("max: 5", "max: 1")).await;
    assert!(
        verdict(&manager, Some("alice"), Some("get")).await.0,
        "the first lowercase GET is within the limit"
    );
    assert_eq!(
        verdict(&manager, Some("alice"), Some("get")).await,
        (false, Some((CODE_EXCEEDED.to_owned(), Some(429)))),
        "a lowercase `get` counts against the `http_method == 'GET'` limit"
    );
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await.1,
        Some((CODE_EXCEEDED.to_owned(), Some(429))),
        "both spellings share one counter"
    );
}

#[tokio::test]
async fn a_missing_binding_logs_its_hint_and_keeps_it_out_of_the_response() {
    let manager = engine_with(&EDGE_POLICY.replace("[read_headers]", "[read_query]")).await;

    start_capture();
    let violation = violation_at(
        &manager,
        HOOK_RATELIMIT_PRE_IDENTITY,
        edge_request(Some(FIRST_CLIENT)),
    )
    .await
    .expect("an unreadable client address denies");
    for _ in 0..5 {
        assert_eq!(
            pre_identity_verdict(&manager, edge_request(Some(FIRST_CLIENT)))
                .await
                .1,
            Some((CODE_MISSING_ATTRIBUTE.to_owned(), Some(400))),
            "every request lacking the attribute is denied"
        );
    }
    let logged = finish_capture(tracing::Level::WARN);

    assert_eq!(
        violation.code, CODE_MISSING_ATTRIBUTE,
        "the denial is a missing attribute"
    );
    assert_eq!(
        violation.proto_error_code,
        Some(400),
        "a request lacking what the limit needs is a bad request"
    );
    assert_eq!(
        violation.details.get(DETAIL_HTTP_STATUS),
        Some(&serde_json::json!(400)),
        "the details carry the HTTP status"
    );
    let rendered = format!("{} {:?}", violation.reason, violation.details);
    for leaked in ["client", "http.client_address", "read_headers", "edge"] {
        assert!(
            !rendered.contains(leaked),
            "the response must not reveal `{leaked}`: {rendered}"
        );
    }
    let hints: Vec<&String> = logged
        .iter()
        .filter(|event| event.contains(CODE_MISSING_ATTRIBUTE))
        .collect();
    assert_eq!(
        hints.len(),
        1,
        "six denials inside one interval warn once, so a host fault is visible at default \
         levels without flooding: {logged:?}"
    );
    for needle in [
        "edge-limits",
        "\"client\"",
        "http.client_address",
        "read_headers",
        "capabilities",
        "suppressed",
    ] {
        assert!(
            hints[0].contains(needle),
            "the operator hint names `{needle}`: {hints:?}"
        );
    }
}

#[cfg(feature = "fips")]
#[tokio::test]
async fn a_crypto_failure_denies_and_logs_once_per_interval() {
    let policy = POLICY
        .replace(
            "[read_subject, read_headers]",
            "[read_subject, read_headers, read_llm_request]",
        )
        .replace("subject_id == 'alice'", "int(subject_id) > 1");
    let manager = engine_with(&policy).await;

    start_capture();
    assert_eq!(
        verdict(&manager, Some("alice"), Some("GET")).await.1,
        Some((CODE_CHECK_FAILED.to_owned(), Some(503))),
        "a generic evaluation error must not suppress the first crypto alarm"
    );
    for number in 1..=20 {
        let mut extensions = request(Some("alice"), Some("GET"));
        extensions.llm_request = Some(LlmRequest::from_parts(LlmRequestParts {
            instructions: vec![LlmInstruction {
                role: LlmInstructionRole::System,
                text: CRYPTO_FAILURE_INSTRUCTION.to_owned(),
            }],
            ..Default::default()
        }));
        let violation = violation_at(&manager, HOOK_RATELIMIT_POST_IDENTITY, extensions)
            .await
            .expect("missing-provider hashing denies the request");

        assert_eq!(
            violation.code, CODE_CHECK_FAILED,
            "request #{number} denies"
        );
        assert_eq!(violation.proto_error_code, Some(503));
        assert_eq!(
            violation.details.get(DETAIL_HTTP_STATUS),
            Some(&serde_json::json!(503))
        );
        let rendered = format!("{} {:?}", violation.reason, violation.details);
        for leaked in [
            "OpenSSL",
            "fips=yes",
            CRYPTO_FAILURE_INSTRUCTION,
            "app-ratelimit",
        ] {
            assert!(
                !rendered.contains(leaked),
                "request #{number} must not expose {leaked}: {rendered}"
            );
        }
    }
    let errors = finish_capture(tracing::Level::ERROR);
    let crypto_failures: Vec<&String> = errors
        .iter()
        .filter(|event| event.contains("policy_crypto_failure"))
        .collect();
    assert_eq!(
        crypto_failures.len(),
        1,
        "twenty hashing failures log one crypto alarm despite a prior generic failure: {errors:?}"
    );
    for field in [
        "attribute_bag",
        "app-ratelimit",
        "suppressed=0",
        "interval_seconds=60",
    ] {
        assert!(
            crypto_failures[0].contains(field),
            "the crypto alarm includes {field}: {crypto_failures:?}"
        );
    }
}

#[tokio::test]
async fn a_check_failure_is_a_503_without_the_raw_error() {
    let policy = POLICY.replace("subject_id == 'alice'", "int(subject_id) > 1");
    let manager = engine_with(&policy).await;

    let violation = violation_at(
        &manager,
        HOOK_RATELIMIT_POST_IDENTITY,
        request(Some("alice"), Some("GET")),
    )
    .await
    .expect("a condition evaluation error denies");

    assert_eq!(violation.code, CODE_CHECK_FAILED, "the check failed");
    assert_eq!(
        violation.proto_error_code,
        Some(503),
        "a limiter that cannot check is unavailable"
    );
    let rendered = format!("{} {:?}", violation.reason, violation.details);
    for leaked in ["int(", "subject_id", "panic", "Limitador", "toystore"] {
        assert!(
            !rendered.contains(leaked),
            "the response must not reveal `{leaked}`: {rendered}"
        );
    }
}

#[tokio::test]
async fn a_persistent_check_failure_logs_once_per_interval() {
    let policy = POLICY.replace("subject_id == 'alice'", "int(subject_id) > 1");
    let manager = engine_with(&policy).await;

    start_capture();
    for number in 1..=20 {
        assert_eq!(
            verdict(&manager, Some("alice"), Some("GET")).await.1,
            Some((CODE_CHECK_FAILED.to_owned(), Some(503))),
            "request #{number} fails closed"
        );
    }
    let errors = finish_capture(tracing::Level::ERROR);

    assert!(
        errors
            .iter()
            .all(|event| !event.contains("policy_crypto_failure")),
        "generic evaluation errors are not crypto failures: {errors:?}"
    );
    let failures: Vec<&String> = errors
        .iter()
        .filter(|event| event.contains("rate limit check failed"))
        .collect();
    assert_eq!(
        failures.len(),
        1,
        "twenty failures inside one interval log once: {errors:?}"
    );
    assert!(
        failures[0].contains("app-ratelimit")
            && failures[0].contains("condition failed")
            && !failures[0].contains("panicked"),
        "the one log names the plugin and the cause: {failures:?}"
    );
}

#[test]
fn a_small_capacity_for_a_client_address_counter_warns_at_load() {
    let config = |capacity: u64| {
        plugin_config(
            &[HOOK_RATELIMIT_PRE_IDENTITY],
            serde_json::json!({
                "namespace": "edge",
                "counter_capacity": capacity,
                "bindings": {"client": "http.client_address"},
                "limits": [{"max": 5, "seconds": 60, "variables": ["client"]}],
            }),
        )
    };

    let (built, warnings) = warnings_while(|| RateLimitFactory.create(&config(100)).is_ok());

    assert!(built, "a small capacity still loads");
    assert_eq!(
        warnings.len(),
        1,
        "one unbounded counter key warns once: {warnings:?}"
    );
    for needle in [
        "app-ratelimit",
        "client",
        "http.client_address",
        "counter_capacity=100",
    ] {
        assert!(
            warnings[0].contains(needle),
            "the warning names `{needle}`: {warnings:?}"
        );
    }
    let (built, warnings) = warnings_while(|| RateLimitFactory.create(&config(10_000)).is_ok());
    assert!(built, "the default capacity loads");
    assert!(
        warnings.is_empty(),
        "the default capacity does not warn: {warnings:?}"
    );
}

#[test]
fn a_pre_identity_binding_to_an_identity_attribute_fails_to_load() {
    for attribute in ["subject.id", "claim.plan", "delegation.origin_subject_id"] {
        let policy = EDGE_POLICY.replace("http.client_address", attribute);
        let error = load_error(&policy);
        for needle in [
            "edge-limits",
            "binding 'client'",
            attribute,
            "ratelimit.pre_identity",
            "ratelimit.post_identity",
        ] {
            assert!(
                error.contains(needle),
                "the error for {attribute} must name `{needle}`: {error}"
            );
        }
    }
}

#[test]
fn an_unreferenced_identity_binding_loads_at_pre_identity() {
    let config = plugin_config(
        &[HOOK_RATELIMIT_PRE_IDENTITY],
        serde_json::json!({
            "namespace": "edge",
            "limits": [{"max": 1, "seconds": 60}],
        }),
    );
    assert!(
        RateLimitFactory.create(&config).is_ok_and(|instance| {
            instance.handlers.len() == 1 && instance.handlers[0].0 == HOOK_RATELIMIT_PRE_IDENTITY
        }),
        "the default subject binding is never resolved when no limit references it"
    );
}

#[test]
fn a_factory_registers_only_on_its_declared_stage() {
    for hook in [HOOK_RATELIMIT_PRE_IDENTITY, HOOK_RATELIMIT_POST_IDENTITY] {
        let config = plugin_config(&[hook], minimal_config());
        let instance = RateLimitFactory
            .create(&config)
            .expect("a single-stage config builds");
        let hooks: Vec<&str> = instance.handlers.iter().map(|(name, _)| *name).collect();
        assert_eq!(hooks, vec![hook], "the instance serves {hook} alone");
    }
}

#[test]
fn hooks_other_than_one_rate_limit_hook_fail_to_load() {
    for (hooks, expected) in [
        (
            &[HOOK_RATELIMIT_PRE_IDENTITY, HOOK_RATELIMIT_POST_IDENTITY][..],
            "an instance runs at one stage",
        ),
        (&["http.request"][..], "hook `http.request` is not served"),
        (
            &[HOOK_RATELIMIT_POST_IDENTITY, "http.request"][..],
            "hook `http.request` is not served",
        ),
        (&[][..], "no rate-limit hook is declared"),
    ] {
        let error = construction_error(&plugin_config(hooks, minimal_config()));
        assert!(
            error.contains("plugin 'app-ratelimit':") && error.contains(expected),
            "{hooks:?}: {error}"
        );
    }
}

#[test]
fn on_error_other_than_fail_and_non_sequential_modes_fail_to_load() {
    for (key, value, expected) in [
        ("on_error", "ignore", "`on_error: ignore`"),
        ("on_error", "disable", "`on_error: disable`"),
        ("mode", "concurrent", "`mode: concurrent`"),
        ("mode", "audit", "`mode: audit`"),
    ] {
        let policy = POLICY.replace(
            "    hooks: [ratelimit.post_identity]",
            &format!("    hooks: [ratelimit.post_identity]\n    {key}: {value}"),
        );
        let error = load_error(&policy);
        assert!(
            error.contains("app-ratelimit") && error.contains(expected),
            "{key}: {value} must be refused: {error}"
        );
    }
}

#[test]
fn a_pre_identity_counter_keyed_on_a_caller_header_fails_to_load() {
    for attribute in [
        "http.request_headers.x-user",
        "http.query",
        "http.path",
        "http.host",
        "agent.session_id",
        "custom.tenant",
        "meta.properties.owner",
        "request.trace_id",
    ] {
        let policy = EDGE_POLICY.replace("http.client_address", attribute);
        let error = load_error(&policy);
        for needle in [
            "edge-limits",
            "binding 'client'",
            attribute,
            "ratelimit.pre_identity",
            "http.client_address",
        ] {
            assert!(
                error.contains(needle),
                "the error for {attribute} must name `{needle}`: {error}"
            );
        }
    }
}

#[test]
fn a_pre_identity_condition_on_a_caller_header_loads() {
    let config = plugin_config(
        &[HOOK_RATELIMIT_PRE_IDENTITY],
        serde_json::json!({
            "namespace": "edge",
            "bindings": {"user": "http.request_headers.x-user"},
            "limits": [{"max": 1, "seconds": 60, "conditions": ["user == 'alice'"]}],
        }),
    );
    assert!(
        RateLimitFactory.create(&config).is_ok(),
        "a caller header may select a limit, since it cannot mint a counter"
    );
}

#[test]
fn a_post_identity_counter_keyed_on_a_caller_header_loads_with_one_warning() {
    for attribute in [
        "http.request_headers.x-user",
        "agent.session_id",
        "request.request_id",
    ] {
        let config = plugin_config(
            &[HOOK_RATELIMIT_POST_IDENTITY],
            serde_json::json!({
                "namespace": "user",
                "bindings": {"user": attribute},
                "limits": [{"max": 1, "seconds": 60, "variables": ["user"]}],
            }),
        );
        let (built, warnings) = warnings_while(|| RateLimitFactory.create(&config).is_ok());
        assert!(built, "a post-identity counter on {attribute} still loads");
        assert_eq!(
            warnings.len(),
            1,
            "construction warns exactly once for {attribute}: {warnings:?}"
        );
        for needle in ["app-ratelimit", "user", attribute] {
            assert!(
                warnings[0].contains(needle),
                "the warning must name `{needle}`: {warnings:?}"
            );
        }
    }
}

#[test]
fn malformed_condition_fails_during_plugin_construction() {
    let config = plugin_config(
        &[HOOK_RATELIMIT_POST_IDENTITY],
        serde_json::json!({
            "namespace": "toystore",
            "limits": [{
                "max": 5,
                "seconds": 60,
                "conditions": ["subject_id =="],
            }],
        }),
    );
    let error = RateLimitFactory
        .create(&config)
        .err()
        .expect("malformed CEL must fail at construction");
    assert!(
        matches!(*error, PluginError::Config { .. }),
        "malformed CEL is a config error: {error}"
    );
}

#[test]
fn unbound_cel_variable_fails_during_plugin_construction() {
    let config = plugin_config(
        &[HOOK_RATELIMIT_POST_IDENTITY],
        serde_json::json!({
            "namespace": "toystore",
            "limits": [{
                "max": 5,
                "seconds": 60,
                "conditions": ["plan == 'free'"],
            }],
        }),
    );
    let error = RateLimitFactory
        .create(&config)
        .err()
        .expect("unbound CEL variable must fail at construction");
    assert!(
        matches!(*error, PluginError::Config { .. }),
        "an unbound variable is a config error: {error}"
    );
    assert!(
        error.to_string().contains("unbound CEL variable 'plan'"),
        "the error names the unbound variable: {error}"
    );
}

#[test]
fn cel_macro_locals_do_not_hide_unbound_free_variables() {
    for (field, source, missing) in [
        (
            "conditions",
            "['/api/'].exists(prefix, missing.startsWith(prefix))",
            "missing",
        ),
        (
            "conditions",
            "['/api/'].exists(prefix, path.startsWith(prefix)) && prefix == ''",
            "prefix",
        ),
        ("variables", "[prefix].map(prefix, prefix)[0]", "prefix"),
        ("variables", "['a'].map(item, item + missing)[0]", "missing"),
    ] {
        let config = plugin_config(
            &[HOOK_RATELIMIT_POST_IDENTITY],
            serde_json::json!({
                "namespace": "toystore",
                "bindings": {"path": "http.path"},
                "limits": [{"max": 1, "seconds": 60, (field): [source]}],
            }),
        );
        let error = RateLimitFactory
            .create(&config)
            .err()
            .expect("free names must be bound");
        assert!(
            error
                .to_string()
                .contains(&format!("unbound CEL variable '{missing}'")),
            "{source}: {error}"
        );
    }
}

#[test]
fn limit_metadata_in_counter_expressions_fails_during_plugin_construction() {
    for expression in ["limit.name", "limit.id", "string(limit.name)"] {
        let config = plugin_config(
            &[HOOK_RATELIMIT_POST_IDENTITY],
            serde_json::json!({
                "namespace": "toystore",
                "limits": [{
                    "max": 1,
                    "seconds": 60,
                    "variables": [expression],
                }],
            }),
        );
        let error = RateLimitFactory
            .create(&config)
            .err()
            .expect("unsupported limit metadata must fail at construction");
        assert!(
            matches!(*error, PluginError::Config { .. }),
            "{expression}: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("'limit' is supported only in conditions"),
            "{expression}: {error}"
        );
    }
}

#[test]
fn invalid_configs_fail_during_plugin_construction() {
    for (label, config, expected) in [
        ("missing config", None, "ratelimit config is required"),
        (
            "unknown field",
            Some(serde_json::json!({
                "namespace": "toystore",
                "limits": [{"max": 1, "seconds": 60}],
                "store": "redis",
            })),
            "unknown field `store`",
        ),
        (
            "duplicate limits",
            Some(serde_json::json!({
                "namespace": "toystore",
                "limits": [
                    {"max": 1, "seconds": 60, "conditions": ["subject_id == 'alice'"]},
                    {"max": 1, "seconds": 60, "conditions": ["subject_id == 'alice'"]},
                ],
            })),
            "limits[1] duplicates an earlier limit",
        ),
    ] {
        let config = PluginConfig {
            config,
            ..plugin_config(&[HOOK_RATELIMIT_POST_IDENTITY], minimal_config())
        };
        let error = RateLimitFactory
            .create(&config)
            .err()
            .expect("invalid config must fail at construction");
        assert!(
            matches!(*error, PluginError::Config { .. }),
            "{label}: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("plugin 'app-ratelimit':"),
            "{label}: {message}"
        );
        assert!(message.contains(expected), "{label}: {message}");
    }
}

#[tokio::test]
async fn maximum_safe_window_loads_and_checks_a_request() {
    let policy = POLICY.replace("seconds: 60", "seconds: 9223372036854");
    let manager = engine_with(&policy).await;

    let result = verdict_request(&manager, request_at_path("alice", "GET", "/other")).await;
    assert!(
        result.0,
        "the maximum safe window must count a matching request: {result:?}"
    );
}

#[test]
fn oversized_windows_fail_to_load_in_base_and_route_override_configs() {
    let base = POLICY.replacen("seconds: 60", "seconds: 9223372036855", 1);
    let override_policy = ROUTE_OVERRIDE_POLICY.replacen(
        "                seconds: 60",
        "                seconds: 9223372036855",
        1,
    );

    for (label, policy) in [("base", base), ("route override", override_policy)] {
        let error = load_error(&policy);
        assert!(
            error.contains("limits[0] seconds must be at most 9223372036854"),
            "{label} config must fail at load: {error}"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

async fn engine_with(policy: &str) -> Arc<PolicyEngine> {
    let manager = Arc::new(PolicyEngine::default());
    manager.register_factory(KIND, Box::new(RateLimitFactory));
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

fn load_error(policy: &str) -> String {
    let manager = Arc::new(PolicyEngine::default());
    manager.register_factory(KIND, Box::new(RateLimitFactory));
    manager
        .load_config_yaml(policy)
        .expect_err("the config must fail to load")
        .to_string()
}

fn construction_error(config: &PluginConfig) -> String {
    RateLimitFactory
        .create(config)
        .err()
        .expect("the config must fail at construction")
        .to_string()
}

fn plugin_config(hooks: &[&str], config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        name: "app-ratelimit".to_owned(),
        kind: KIND.to_owned(),
        hooks: hooks.iter().map(|hook| (*hook).to_owned()).collect(),
        config: Some(config),
        ..Default::default()
    }
}

fn minimal_config() -> serde_json::Value {
    serde_json::json!({
        "namespace": "toystore",
        "limits": [{"max": 1, "seconds": 60}],
    })
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

fn edge_request(client_address: Option<&str>) -> Extensions {
    let mut extensions = request_with_plan_at_path(None, Some("GET"), None, "/toys");
    if let Some(address) = client_address {
        Arc::make_mut(extensions.http.as_mut().expect("HTTP request fixture"))
            .set_client_address(address);
    }
    extensions
}

async fn verdict_at(manager: &PolicyEngine, hook: &str, extensions: Extensions) -> Verdict {
    let (result, _background) = manager
        .invoke_named::<HttpHook>(hook, HttpPayload, extensions, None)
        .await;
    (
        result.continue_processing,
        result.violation.map(|v| (v.code, v.proto_error_code)),
    )
}

async fn violation_at(
    manager: &PolicyEngine,
    hook: &str,
    extensions: Extensions,
) -> Option<PluginViolation> {
    let (result, _background) = manager
        .invoke_named::<HttpHook>(hook, HttpPayload, extensions, None)
        .await;
    result.violation
}

async fn verdict_request(manager: &PolicyEngine, extensions: Extensions) -> Verdict {
    verdict_at(manager, HOOK_RATELIMIT_POST_IDENTITY, extensions).await
}

async fn pre_identity_verdict(manager: &PolicyEngine, extensions: Extensions) -> Verdict {
    verdict_at(manager, HOOK_RATELIMIT_PRE_IDENTITY, extensions).await
}

async fn verdict(
    manager: &PolicyEngine,
    subject_id: Option<&str>,
    method: Option<&str>,
) -> Verdict {
    verdict_request(manager, request(subject_id, method)).await
}

thread_local! {
    static EVENTS: RefCell<Option<Vec<(tracing::Level, String)>>> = const { RefCell::new(None) };
}

/// Installed once for the whole binary, because callsite interest is cached
/// process-wide; the thread-local sink keeps each test's events its own.
struct EventCapture;

struct Render(String);

impl tracing::field::Visit for Render {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}

impl tracing::Subscriber for EventCapture {
    fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut render = Render(String::new());
        event.record(&mut render);
        EVENTS.with_borrow_mut(|sink| {
            if let Some(events) = sink.as_mut() {
                events.push((*event.metadata().level(), render.0));
            }
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Start collecting this thread's events, dropping any left from before.
fn start_capture() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(EventCapture)
            .expect("no other subscriber is installed in this test binary");
    });
    EVENTS.with_borrow_mut(|sink| *sink = Some(Vec::new()));
}

/// Stop collecting and return the events at `level` since capture began.
fn finish_capture(level: tracing::Level) -> Vec<String> {
    EVENTS
        .with_borrow_mut(Option::take)
        .unwrap_or_default()
        .into_iter()
        .filter(|(event_level, _)| *event_level == level)
        .map(|(_, event)| event)
        .collect()
}

fn warnings_while<T>(body: impl FnOnce() -> T) -> (T, Vec<String>) {
    start_capture();
    let value = body();
    (value, finish_capture(tracing::Level::WARN))
}
