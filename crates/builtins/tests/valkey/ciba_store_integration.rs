// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// CIBA correlations against a real Valkey. `#[ignore]`d and gated the same way
// as the session store tests in `valkey_store_integration.rs`.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::Utc;
use praxis_policy_builtins::plugins::elicitation_ciba::{
    CibaApprover, Correlation, CorrelationStore as _, PollClaim, TakeResult, ValkeyCorrelationStore,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn two_replicas_racing_to_redeem_get_exactly_one_approval() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let prefix = format!("ciba:test:{}", uuid::Uuid::new_v4());
    let a = Arc::new(store_with_prefix(&target, &prefix));
    let b = Arc::new(store_with_prefix(&target, &prefix));
    a.put("race", pending(60)).await.unwrap();
    a.set_resolved_approver("race", "alice".into())
        .await
        .unwrap();

    let take = |s: Arc<ValkeyCorrelationStore>| {
        tokio::spawn(async move { s.take_if_ready("race", ROUTE, "adjust", "bob").await })
    };
    let (ra, rb) = tokio::join!(take(a), take(b));
    let results = [ra.unwrap().unwrap(), rb.unwrap().unwrap()];
    let ready = results
        .iter()
        .filter(|r| matches!(r, TakeResult::Ready(_)))
        .count();
    let missing = results
        .iter()
        .filter(|r| matches!(r, TakeResult::Missing))
        .count();
    assert_eq!(
        (ready, missing),
        (1, 1),
        "one replica redeems, the other sees it missing"
    );
}

#[tokio::test]
#[ignore]
async fn two_replicas_claim_one_op_poll() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let prefix = format!("ciba:test:{}", uuid::Uuid::new_v4());
    let a = store_with_prefix(&target, &prefix);
    let b = store_with_prefix(&target, &prefix);
    a.put("poll-race", pending(60)).await.unwrap();
    assert_eq!(
        a.claim_poll(
            "poll-race",
            "a",
            Duration::from_secs(10),
            ROUTE,
            "adjust",
            "bob"
        )
        .await
        .unwrap(),
        PollClaim::Acquired
    );
    assert_eq!(
        b.claim_poll(
            "poll-race",
            "b",
            Duration::from_secs(10),
            ROUTE,
            "adjust",
            "bob"
        )
        .await
        .unwrap(),
        PollClaim::Busy
    );
    a.complete_poll("poll-race", "a", "alice".into())
        .await
        .unwrap();
    assert_eq!(
        b.claim_poll(
            "poll-race",
            "b",
            Duration::from_secs(10),
            ROUTE,
            "adjust",
            "bob"
        )
        .await
        .unwrap(),
        PollClaim::Resolved
    );

    a.put("expired-poll", pending(60)).await.unwrap();
    a.claim_poll(
        "expired-poll",
        "a",
        Duration::from_millis(1),
        ROUTE,
        "adjust",
        "bob",
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        b.claim_poll(
            "expired-poll",
            "b",
            Duration::from_secs(10),
            ROUTE,
            "adjust",
            "bob"
        )
        .await
        .unwrap(),
        PollClaim::Uncertain
    );
}

#[tokio::test]
#[ignore]
async fn two_approvers_on_one_server_cannot_redeem_each_others_approvals() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let settings = serde_json::json!({
        "endpoint": target.url,
        "key_prefix": format!("ciba:test:{}", uuid::Uuid::new_v4()),
    });
    let settings = settings.as_object().unwrap();
    let manager = ValkeyCorrelationStore::from_settings("manager", settings, None).unwrap();
    let security = ValkeyCorrelationStore::from_settings("security", settings, None).unwrap();
    manager.put("shared-id", pending(60)).await.unwrap();
    manager
        .set_resolved_approver("shared-id", "alice".into())
        .await
        .unwrap();

    assert!(security.get("shared-id").await.unwrap().is_none());
    assert!(matches!(
        security
            .take_if_ready("shared-id", ROUTE, "adjust", "bob")
            .await
            .unwrap(),
        TakeResult::Missing
    ));
    assert!(matches!(
        manager
            .take_if_ready("shared-id", ROUTE, "adjust", "bob")
            .await
            .unwrap(),
        TakeResult::Ready(_)
    ));
}

#[tokio::test]
#[ignore]
async fn a_put_replaces_rather_than_merges_an_existing_correlation() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target);
    store.put("reput", pending(60)).await.unwrap();
    store
        .set_resolved_approver("reput", "alice".into())
        .await
        .unwrap();
    store.put("reput", pending(60)).await.unwrap();

    assert!(
        store
            .get("reput")
            .await
            .unwrap()
            .unwrap()
            .resolved_approver
            .is_none(),
        "a fresh dispatch must not inherit an earlier approval"
    );
    assert!(matches!(
        store
            .take_if_ready("reput", ROUTE, "adjust", "bob")
            .await
            .unwrap(),
        TakeResult::Pending
    ));
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
async fn a_server_that_never_replies_times_out_as_an_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _hold = tokio::spawn(async move {
        let accepted = listener.accept().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(accepted);
    });
    let settings = serde_json::json!({
        "endpoint": addr.to_string(),
        "connect_timeout_ms": 200,
        "command_timeout_ms": 200,
    });
    let store = ValkeyCorrelationStore::from_settings("p", settings.as_object().unwrap(), None)
        .expect("a lazy pool builds");
    let err = store
        .get("x")
        .await
        .expect_err("a silent server must fail closed");
    assert!(err.message().contains("timed out"), "got {err}");
}

#[tokio::test]
async fn an_unreachable_store_is_an_error_not_a_miss() {
    let settings = serde_json::json!({
        "endpoint": "localhost:1",
        "connect_timeout_ms": 300,
        "command_timeout_ms": 300,
    });
    let store = ValkeyCorrelationStore::from_settings("p", settings.as_object().unwrap(), None)
        .expect("a lazy pool builds");
    store
        .get("x")
        .await
        .expect_err("a dead endpoint must fail closed");
}

#[tokio::test]
#[ignore]
async fn scripts_reload_after_cache_flush() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target);
    let mut admin = redis::Client::open(target.url.clone())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    store.put("reload", pending(60)).await.unwrap();
    flush_scripts(&mut admin).await;
    assert_eq!(
        store
            .claim_poll(
                "reload",
                "owner",
                Duration::from_secs(5),
                ROUTE,
                "adjust",
                "bob"
            )
            .await
            .unwrap(),
        PollClaim::Acquired
    );
    flush_scripts(&mut admin).await;
    store.release_poll("reload", "owner").await.unwrap();
    store
        .claim_poll(
            "reload",
            "owner2",
            Duration::from_secs(5),
            ROUTE,
            "adjust",
            "bob",
        )
        .await
        .unwrap();
    flush_scripts(&mut admin).await;
    store
        .complete_poll("reload", "owner2", "alice".into())
        .await
        .unwrap();
    flush_scripts(&mut admin).await;
    assert!(matches!(
        store
            .take_if_ready("reload", ROUTE, "adjust", "bob")
            .await
            .unwrap(),
        TakeResult::Ready(_)
    ));
    store.put("resolve", pending(60)).await.unwrap();
    flush_scripts(&mut admin).await;
    store
        .set_resolved_approver("resolve", "alice".into())
        .await
        .unwrap();
    store.put("abandon", pending(60)).await.unwrap();
    store
        .claim_poll(
            "abandon",
            "owner",
            Duration::from_secs(5),
            ROUTE,
            "adjust",
            "bob",
        )
        .await
        .unwrap();
    flush_scripts(&mut admin).await;
    store.abandon_poll("abandon", "owner").await.unwrap();
}

#[tokio::test]
#[ignore]
async fn an_approval_dispatched_on_one_replica_redeems_on_another() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let prefix = format!("ciba:test:{}", uuid::Uuid::new_v4());
    let replica = || {
        CibaApprover::with_context(
            approver_config(&prefix, &target.url),
            &FactoryContext::default(),
        )
        .expect("standalone store builds")
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

#[tokio::test]
#[ignore = "needs PPE_ACL_VALKEY and the ACL users from docs/content/testing.md"]
async fn documented_acl_users_compartmentalize_the_two_stores() {
    use praxis_policy_apl_runtime::SessionStore as _;
    use praxis_policy_builtins::session::valkey::{ValkeyConfig, ValkeySessionStore};

    let vars = ["PPE_ACL_VALKEY", "PPE_TAINT_PW", "PPE_CIBA_PW"].map(|v| std::env::var(v).ok());
    let [Some(endpoint), Some(taint_pw), Some(ciba_pw)] = vars else {
        assert!(
            std::env::var("VALKEY_TESTS_OPTIONAL").as_deref() == Ok("1"),
            "set PPE_ACL_VALKEY, PPE_TAINT_PW and PPE_CIBA_PW, or VALKEY_TESTS_OPTIONAL=1"
        );
        eprintln!("SKIPPED documented_acl_users: set PPE_ACL_VALKEY, PPE_TAINT_PW, PPE_CIBA_PW");
        return;
    };
    let global: serde_yaml::Value = serde_yaml::from_str(&format!(
        "kind: valkey\nendpoint: {endpoint}\nusername: ppe-taint\n\
         password: {{ env: PPE_TAINT_PW }}\nttl_seconds: 60\n"
    ))
    .unwrap();
    let taint =
        ValkeySessionStore::from_config(&ValkeyConfig::from_value(&global).unwrap()).unwrap();
    taint
        .append_labels("sess", &["secret".to_owned()])
        .await
        .expect("ppe-taint appends with a TTL");
    assert_eq!(
        taint
            .load_labels("sess")
            .await
            .expect("ppe-taint loads and refreshes"),
        vec!["secret".to_owned()]
    );

    let pw = std::env::temp_dir().join(format!("ppe-ciba-acl-pw-{}", uuid::Uuid::new_v4()));
    std::fs::write(&pw, format!("{ciba_pw}\n")).unwrap();
    let reference = serde_json::json!({
        "connection": "session_store",
        "username": "ppe-ciba",
        "password": { "file": pw },
    });
    let ciba = ValkeyCorrelationStore::from_settings(
        "manager-approver",
        reference.as_object().unwrap(),
        FactoryContext::with_session_store(Some(global)).session_store(),
    )
    .unwrap();
    ciba.put("acl", pending(60))
        .await
        .expect("ppe-ciba writes ciba:v1:*");
    assert!(ciba.get("acl").await.expect("ppe-ciba reads").is_some());
    assert_eq!(
        ciba.claim_poll(
            "acl",
            "owner",
            Duration::from_secs(5),
            ROUTE,
            "adjust",
            "bob"
        )
        .await
        .expect("ppe-ciba may claim"),
        PollClaim::Acquired
    );
    ciba.release_poll("acl", "owner")
        .await
        .expect("ppe-ciba may release");
    assert!(matches!(
        ciba.take_if_ready("acl", ROUTE, "adjust", "bob")
            .await
            .expect("take"),
        TakeResult::Pending
    ));
    ciba.set_resolved_approver("acl", "alice".into())
        .await
        .expect("ppe-ciba may run a cached script");
    ciba.set_resolved_approver("absent", "alice".into())
        .await
        .expect("resolving a missing id is a no-op");
    assert!(matches!(
        ciba.take_if_ready("acl", ROUTE, "adjust", "eve")
            .await
            .expect("take"),
        TakeResult::BindingMismatch
    ));
    assert!(matches!(
        ciba.take_if_ready("absent", ROUTE, "adjust", "bob")
            .await
            .expect("take"),
        TakeResult::Missing
    ));
    assert!(matches!(
        ciba.take_if_ready("acl", ROUTE, "adjust", "bob")
            .await
            .expect("take"),
        TakeResult::Ready(_)
    ));
    std::fs::remove_file(&pw).unwrap();

    let raw = |user: &str, pass: &str| {
        redis::Client::open(format!("redis://{user}:{pass}@{endpoint}")).unwrap()
    };
    let mut as_taint = raw("ppe-taint", &taint_pw)
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let mut as_ciba = raw("ppe-ciba", &ciba_pw)
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let forge: redis::RedisResult<()> = redis::cmd("HSET")
        .arg("ciba:v1:manager-approver:x")
        .arg("resolved")
        .arg("mallory")
        .query_async(&mut as_taint)
        .await;
    let forge = forge.unwrap_err();
    assert_eq!(
        forge.code(),
        Some("NOPERM"),
        "taint credentials cannot forge an approval: {forge:?}"
    );
    let clear: redis::RedisResult<()> = redis::cmd("DEL")
        .arg("taint:v1:anything")
        .query_async(&mut as_ciba)
        .await;
    let clear = clear.unwrap_err();
    assert_eq!(
        clear.code(),
        Some("NOPERM"),
        "CIBA credentials cannot clear taint: {clear:?}"
    );
    let read: redis::RedisResult<Vec<String>> = redis::cmd("HGETALL")
        .arg("taint:v1:anything")
        .query_async(&mut as_ciba)
        .await;
    assert_eq!(read.unwrap_err().code(), Some("NOPERM"));
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

const ROUTE: &str = "tool:adjust@sandbox";

fn store_for(target: &Target) -> ValkeyCorrelationStore {
    store_with_prefix(target, &format!("ciba:test:{}", uuid::Uuid::new_v4()))
}

fn store_with_prefix(target: &Target, prefix: &str) -> ValkeyCorrelationStore {
    let settings = serde_json::json!({
        "endpoint": target.url,
        "key_prefix": prefix,
        "connect_timeout_ms": 5000,
        "command_timeout_ms": 5000,
    });
    ValkeyCorrelationStore::from_settings("manager-approver", settings.as_object().unwrap(), None)
        .expect("store")
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

fn approver_config(key_prefix: &str, endpoint: &str) -> PluginConfig {
    PluginConfig {
        name: "manager-approver".into(),
        kind: "elicitation/ciba".into(),
        hooks: vec!["elicit".into()],
        config: Some(serde_json::json!({
            "backchannel_endpoint": "https://op.example.test/ciba/auth",
            "token_endpoint": "https://op.example.test/token",
            "client_id": "praxis-policy-gateway",
            "client_secret_source": { "kind": "literal", "secret": "shh" },
            "store": { "kind": "valkey", "endpoint": endpoint, "key_prefix": key_prefix },
        })),
        ..Default::default()
    }
}

async fn flush_scripts(admin: &mut redis::aio::MultiplexedConnection) {
    redis::cmd("SCRIPT")
        .arg("FLUSH")
        .query_async::<()>(admin)
        .await
        .unwrap();
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
