// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Runs the automatable half of the CIBA flow (dispatch, then check-pending)
// against a real Keycloak, so the parts that do not need a human are a
// repeatable test rather than a manual runbook.
//
// The approval itself is human-driven and cannot be asserted here. Dispatch and
// the first poll still exercise the realm, client and auth config end to end,
// which is what usually breaks.
//
// `#[ignore]` by default. To run against a Keycloak configured per the
// runbook:
//
//   CIBA_BACKCHANNEL_ENDPOINT=http://localhost:8080/realms/corp/protocol/openid-connect/ext/ciba/auth \
//   CIBA_TOKEN_ENDPOINT=http://localhost:8080/realms/corp/protocol/openid-connect/token \
//   CIBA_CLIENT_ID=praxis-policy-gateway \
//   CIBA_CLIENT_SECRET=<secret> \
//   CIBA_LOGIN_HINT=alice \
//   cargo nextest run -p praxis-policy-builtins --test live_keycloak -- --ignored --nocapture

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::collections::HashSet;

use serde_json::json;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::elicitation::{ElicitationOp, ElicitationPayload, ElicitationStatusKind};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::HookHandler as _;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_builtins::plugins::elicitation_ciba::CibaApprover;

/// Read a required env var, or `None` (so the test skips cleanly).
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "requires a live Keycloak"]
async fn live_dispatch_then_pending() {
    let (Some(backchannel), Some(token), Some(client_id), Some(secret), Some(login_hint)) = (
        env("CIBA_BACKCHANNEL_ENDPOINT"),
        env("CIBA_TOKEN_ENDPOINT"),
        env("CIBA_CLIENT_ID"),
        env("CIBA_CLIENT_SECRET"),
        env("CIBA_LOGIN_HINT"),
    ) else {
        eprintln!(
            "SKIP: set CIBA_BACKCHANNEL_ENDPOINT / _TOKEN_ENDPOINT / _CLIENT_ID / _CLIENT_SECRET / _LOGIN_HINT"
        );
        return;
    };

    let insecure = backchannel.starts_with("http://") || token.starts_with("http://");
    let cfg = PluginConfig {
        name: "manager-approver".to_owned(),
        kind: "elicitation/ciba".to_owned(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["elicit".to_owned()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(json!({
            "backchannel_endpoint": backchannel,
            "token_endpoint": token,
            "client_id": client_id,
            "client_secret_source": { "kind": "literal", "secret": secret },
            "insecure_http": insecure,
        })),
    };
    let approver = CibaApprover::new(cfg).expect("construct approver");
    let ext = Extensions::default();

    // 1. dispatch → backchannel auth request.
    let dispatch = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", &login_hint)
        .with_purpose("live CIBA config check — please ignore");
    let mut ctx = PluginContext::new();
    let out = approver.handle(&dispatch, &ext, &mut ctx).await;
    assert!(
        out.continue_processing,
        "dispatch denied: {:?}",
        out.violation
    );
    let dispatched = out.modified_payload.expect("dispatch payload");
    let id = dispatched
        .id
        .clone()
        .expect("Keycloak returned an auth_req_id");
    assert_eq!(dispatched.status, Some(ElicitationStatusKind::Pending));
    assert_eq!(dispatched.approver.as_deref(), Some(login_hint.as_str()));
    eprintln!("dispatch OK — auth_req_id = {id}");

    // 2. check → token poll before approval. Without a
    //    completed decoupled approval this must report Pending.
    let check =
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id(&id);
    let mut ctx = PluginContext::new();
    let out = approver.handle(&check, &ext, &mut ctx).await;
    assert!(out.continue_processing, "check denied: {:?}", out.violation);
    let checked = out.modified_payload.expect("check payload");
    assert_eq!(
        checked.status,
        Some(ElicitationStatusKind::Pending),
        "expected authorization_pending before approval; got {:?}",
        checked.status
    );
    eprintln!("check OK — status = Pending (no approval yet, as expected)");
}
