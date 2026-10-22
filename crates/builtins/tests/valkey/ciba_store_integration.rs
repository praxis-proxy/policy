// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// CIBA correlations against a real Valkey. `#[ignore]`d and gated the same way
// as the session store tests in `valkey_store_integration.rs`.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::Utc;
use praxis_policy_builtins::plugins::elicitation_ciba::{
    CibaApprover, Correlation, CorrelationStore as _, TakeResult, ValkeyCorrelationStore,
};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::elicitation::{ElicitationOp, ElicitationPayload};
use praxis_policy_core::factory::FactoryContext;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::HookHandler as _;
use praxis_policy_core::host::HttpTransportSlot;
use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::plugin::PluginConfig;

use crate::valkey_store_integration::{Target, valkey_target};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn a_correlation_round_trips_and_redeems_once() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target);
    store.put("rt", pending(60)).await.unwrap();

    let got = store.get("rt").await.unwrap().expect("stored");
    assert_eq!(got.expected_approver, "alice");
    assert!(got.resolved_approver.is_none());
    assert!(matches!(
        store
            .take_if_ready("rt", ROUTE, "adjust", "bob")
            .await
            .unwrap(),
        TakeResult::Pending
    ));

    store
        .set_resolved_approver("rt", "alice".into())
        .await
        .unwrap();
    let TakeResult::Ready(c) = store
        .take_if_ready("rt", ROUTE, "adjust", "bob")
        .await
        .unwrap()
    else {
        panic!("a resolved approval is ready");
    };
    assert_eq!(c.resolved_approver.as_deref(), Some("alice"));
    assert!(matches!(
        store
            .take_if_ready("rt", ROUTE, "adjust", "bob")
            .await
            .unwrap(),
        TakeResult::Missing
    ));
}

#[tokio::test]
#[ignore]
async fn a_mismatched_redeem_does_not_consume_the_approval() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target);
    store.put("mm", pending(60)).await.unwrap();
    store
        .set_resolved_approver("mm", "alice".into())
        .await
        .unwrap();

    for (route, tool, requester) in [
        ("tool:adjust@prod", "adjust", "bob"),
        (ROUTE, "bonus", "bob"),
        (ROUTE, "adjust", "eve"),
    ] {
        assert!(
            matches!(
                store
                    .take_if_ready("mm", route, tool, requester)
                    .await
                    .unwrap(),
                TakeResult::BindingMismatch
            ),
            "{route} {tool} {requester}"
        );
    }
    assert!(matches!(
        store
            .take_if_ready("mm", ROUTE, "adjust", "bob")
            .await
            .unwrap(),
        TakeResult::Ready(_)
    ));
}

#[tokio::test]
#[ignore]
async fn two_replicas_racing_to_redeem_get_exactly_one_approval() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let a = Arc::new(store_for(&target));
    let b = Arc::new(store_for(&target));
    a.put("race", pending(60)).await.unwrap();
    a.set_resolved_approver("race", "alice".into())
        .await
        .unwrap();

    let (ra, rb) = tokio::join!(
        a.take_if_ready("race", ROUTE, "adjust", "bob"),
        b.take_if_ready("race", ROUTE, "adjust", "bob"),
    );
    let ready = [ra.unwrap(), rb.unwrap()]
        .iter()
        .filter(|r| matches!(r, TakeResult::Ready(_)))
        .count();
    assert_eq!(ready, 1, "one replica redeems, the other sees it missing");
}

#[tokio::test]
#[ignore]
async fn a_correlation_expires_server_side() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target);
    let mut c = pending(0);
    c.expires_at = Utc::now() + chrono::Duration::milliseconds(300);
    store.put("exp", c).await.unwrap();
    assert!(store.get("exp").await.unwrap().is_some());

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        store.get("exp").await.unwrap().is_none(),
        "expired by Valkey"
    );
    store
        .set_resolved_approver("exp", "alice".into())
        .await
        .unwrap();
    assert!(
        store.get("exp").await.unwrap().is_none(),
        "a late poll does not recreate an expired entry"
    );
}

#[tokio::test]
#[ignore]
async fn an_unreachable_store_is_an_error_not_a_miss() {
    let settings = serde_json::json!({
        "endpoint": "localhost:1",
        "connect_timeout_ms": 300,
        "command_timeout_ms": 300,
    });
    let store = ValkeyCorrelationStore::from_settings(settings.as_object().unwrap(), None)
        .expect("a lazy pool builds");
    store
        .get("x")
        .await
        .expect_err("a dead endpoint must fail closed");
}

#[tokio::test]
#[ignore]
async fn an_approval_dispatched_on_one_replica_redeems_on_another() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let global: serde_yaml::Value = serde_yaml::from_str(&format!(
        "kind: valkey\nendpoint: {}\nconnect_timeout_ms: 5000\ncommand_timeout_ms: 5000\n",
        target.url
    ))
    .unwrap();
    let context = FactoryContext::with_session_store(Some(global));
    let prefix = format!("ciba:test:{}", uuid::Uuid::new_v4());
    let replica = || {
        CibaApprover::with_context(approver_config(&prefix), &context).expect("reference builds")
    };
    let (first, second) = (replica(), replica());
    let token = format!(
        "h.{}.s",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "preferred_username": "alice" }).to_string())
    );
    let http = Arc::new(
        FakeTransport::new()
            .json(
                "/ciba/auth",
                200,
                r#"{"auth_req_id":"X-1","expires_in":60}"#,
            )
            .json(
                "/token",
                200,
                &serde_json::json!({ "id_token": token }).to_string(),
            ),
    );

    let dispatched = handle(
        &first,
        &http,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice"),
    )
    .await;
    assert_eq!(dispatched.id.as_deref(), Some("X-1"));
    handle(
        &second,
        &http,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id("X-1"),
    )
    .await;
    let validated = handle(
        &first,
        &http,
        ElicitationPayload::new(ElicitationOp::Validate, "approval", "").with_elicitation_id("X-1"),
    )
    .await;
    assert_eq!(
        validated.valid,
        Some(true),
        "the other replica's poll counts"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

const ROUTE: &str = "tool:adjust@sandbox";

fn store_for(target: &Target) -> ValkeyCorrelationStore {
    let settings = serde_json::json!({
        "endpoint": target.url,
        "key_prefix": format!("ciba:test:{}", uuid::Uuid::new_v4()),
        "connect_timeout_ms": 5000,
        "command_timeout_ms": 5000,
    });
    ValkeyCorrelationStore::from_settings(settings.as_object().unwrap(), None).expect("store")
}

fn pending(ttl_secs: i64) -> Correlation {
    Correlation {
        expected_approver: "alice".into(),
        resolved_approver: None,
        route_key: ROUTE.into(),
        tool: "adjust".into(),
        requester: "bob".into(),
        expires_at: Utc::now() + chrono::Duration::seconds(ttl_secs),
    }
}

fn approver_config(key_prefix: &str) -> PluginConfig {
    PluginConfig {
        name: "manager-approver".into(),
        kind: "elicitation/ciba".into(),
        hooks: vec!["elicit".into()],
        config: Some(serde_json::json!({
            "backchannel_endpoint": "https://op.example.test/ciba/auth",
            "token_endpoint": "https://op.example.test/token",
            "client_id": "praxis-policy-gateway",
            "client_secret_source": { "kind": "literal", "secret": "shh" },
            "store": { "kind": "valkey", "connection": "session_store", "key_prefix": key_prefix },
        })),
        ..Default::default()
    }
}

async fn handle(
    approver: &CibaApprover,
    http: &Arc<FakeTransport>,
    payload: ElicitationPayload,
) -> ElicitationPayload {
    let transport: Arc<dyn HttpTransport> = http.clone();
    let ext = Extensions {
        http_transport: HttpTransportSlot::installed(transport),
        ..Default::default()
    };
    let result = approver
        .handle(
            &payload.with_binding(ROUTE, "adjust", "bob"),
            &ext,
            &mut PluginContext::new(),
        )
        .await;
    assert!(result.continue_processing, "denied: {:?}", result.violation);
    result.modified_payload.expect("a payload")
}
