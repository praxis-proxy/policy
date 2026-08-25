// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Integration tests for the CIBA elicitation handler against a mock OP
// (a scripted transport). Exercises the real request shapes and the
// lifecycle mapping
// for dispatch → check → validate without a live Keycloak.

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
use std::sync::Arc;

use base64::Engine as _;
use serde_json::json;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::elicitation::{
    ElicitationOp, ElicitationOutcomeKind, ElicitationPayload, ElicitationStatusKind,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::HookHandler as _;
use praxis_policy_core::host::HttpTransportSlot;
use praxis_policy_core::http::{HttpTransport, HttpTransportError};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_elicitation_ciba::CibaApprover;

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

fn approver() -> CibaApprover {
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
        // A CIBA backchannel is an outbound call, so the plugin declares
        // `perform_http`.
        capabilities: ["perform_http".to_owned()].into(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(json!({
            "backchannel_endpoint": format!("{OP_URL}{AUTH_PATH}"),
            "token_endpoint": format!("{OP_URL}{TOKEN_PATH}"),
            "client_id": "praxis-policy-gateway",
            "client_secret_source": { "kind": "literal", "secret": "shh" },
            "insecure_http": true,
        })),
    };
    CibaApprover::new(cfg).expect("construct approver")
}

/// Endpoint paths the scripted `OP` answers on.
const AUTH_PATH: &str = "/ciba/auth";
const TOKEN_PATH: &str = "/token";

/// Base URL for the scripted transport. Never resolved — the transport
/// is programmed, not dialled.
const OP_URL: &str = "https://op.example.test";

/// `Extensions` carrying the host transport, as the executor would build
/// them for a plugin holding `perform_http`.
fn ext_with(http: &Arc<FakeTransport>) -> Extensions {
    let transport: Arc<dyn HttpTransport> = http.clone();
    Extensions {
        http_transport: HttpTransportSlot::installed(transport),
        ..Default::default()
    }
}

async fn run(
    approver: &CibaApprover,
    http: &Arc<FakeTransport>,
    payload: ElicitationPayload,
) -> ElicitationPayload {
    let ext = ext_with(http);
    let mut ctx = PluginContext::new();
    let result = approver.handle(&payload, &ext, &mut ctx).await;
    assert!(
        result.continue_processing,
        "handler denied: {:?}",
        result.violation
    );
    result
        .modified_payload
        .expect("handler returned an ElicitationPayload")
}

/// Decode one `application/x-www-form-urlencoded` value.
fn form_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => out.push(b),
                    Err(_) => out.push(bytes[i]),
                }
                i += 3;
            },
            b => {
                out.push(b);
                i += 1;
            },
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One field from the form body the approver actually sent.
///
/// Asserting on the recorded request rather than a server-side matcher
/// means a failure names the value that was wrong, instead of reporting
/// an unmatched mock.
fn sent_field(http: &FakeTransport, key: &str) -> Option<String> {
    let req = http.last_request()?;
    let body = String::from_utf8_lossy(&req.body).into_owned();
    body.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (form_decode(k) == key).then(|| form_decode(v))
    })
}

/// Build a fake `id_token` whose payload carries `preferred_username`.
fn fake_id_token(username: &str) -> String {
    let payload = json!({ "preferred_username": username, "sub": "u-1" });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    format!("aaa.{b64}.sig")
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatch_posts_backchannel_and_returns_auth_req_id() {
    let http = Arc::new(FakeTransport::new().json(
        AUTH_PATH,
        200,
        &json!({ "auth_req_id": "REQ-123", "expires_in": 300, "interval": 5 }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    let out = run(&app, &http, payload).await;

    // The CIBA request shape, asserted on what was actually sent. The
    // purpose "Approve raise" is sanitized to a Keycloak-valid,
    // space-free correlation code before it goes on the wire — a space
    // here would be rejected by the OP, so the sanitizer is load-bearing.
    assert_eq!(
        sent_field(&http, "login_hint").as_deref(),
        Some("alice@corp.com")
    );
    assert_eq!(
        sent_field(&http, "binding_message").as_deref(),
        Some("Approve-raise")
    );
    assert_eq!(sent_field(&http, "scope").as_deref(), Some("openid"));

    assert_eq!(out.id.as_deref(), Some("REQ-123"));
    assert_eq!(out.status, Some(ElicitationStatusKind::Pending));
    assert_eq!(out.approver.as_deref(), Some("alice@corp.com"));
    assert!(out.expires_at.is_some());
}

#[tokio::test]
async fn check_authorization_pending_maps_to_pending() {
    let http = Arc::new(FakeTransport::new().json(
        TOKEN_PATH,
        400,
        &json!({ "error": "authorization_pending" }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, &http, payload).await;

    assert_eq!(http.call_count_for(TOKEN_PATH), 1);
    assert_eq!(out.status, Some(ElicitationStatusKind::Pending));
    assert!(out.outcome.is_none());
}

#[tokio::test]
async fn check_success_maps_to_resolved_approved() {
    let http = Arc::new(FakeTransport::new().json(
        TOKEN_PATH,
        200,
        &json!({ "access_token": "at", "id_token": fake_id_token("alice@corp.com") }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, &http, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Resolved));
    assert_eq!(out.outcome, Some(ElicitationOutcomeKind::Approved));
}

#[tokio::test]
async fn check_access_denied_maps_to_resolved_denied() {
    let http = Arc::new(FakeTransport::new().json(
        TOKEN_PATH,
        400,
        &json!({ "error": "access_denied" }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, &http, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Resolved));
    assert_eq!(out.outcome, Some(ElicitationOutcomeKind::Denied));
}

#[tokio::test]
async fn check_expired_token_maps_to_expired() {
    let http = Arc::new(FakeTransport::new().json(
        TOKEN_PATH,
        400,
        &json!({ "error": "expired_token" }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, &http, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Expired));
}

#[tokio::test]
async fn full_flow_dispatch_check_validate_approves() {
    // One approver instance across all three ops, so the in-memory
    // correlation store carries the expected approver + cached token.
    let http = Arc::new(
        FakeTransport::new()
            .json(
                AUTH_PATH,
                200,
                &json!({ "auth_req_id": "REQ-9", "expires_in": 300 }).to_string(),
            )
            .json(
                TOKEN_PATH,
                200,
                &json!({ "id_token": fake_id_token("alice@corp.com") }).to_string(),
            ),
    );

    let app = approver();

    // 1. dispatch — login_hint = the resolved approver.
    let d = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
            .with_purpose("Approve raise"),
    )
    .await;
    let id = d.id.clone().expect("dispatch id");

    // 2. check — approved.
    let c = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id(&id),
    )
    .await;
    assert_eq!(c.outcome, Some(ElicitationOutcomeKind::Approved));

    // 3. validate — token's preferred_username matches the login_hint.
    let v = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Validate, "approval", "").with_elicitation_id(&id),
    )
    .await;
    assert_eq!(v.valid, Some(true));
    assert_eq!(v.approver.as_deref(), Some("alice@corp.com"));
}

#[tokio::test]
async fn validate_rejects_approver_mismatch() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_PATH, 200, &json!({ "auth_req_id": "REQ-x", "expires_in": 300 }).to_string())
            // The token comes back naming a DIFFERENT user than the
            // login_hint — the impersonation case `validate` exists to catch.
            .json(
                TOKEN_PATH,
                200,
                &json!({ "id_token": fake_id_token("mallory@corp.com") }).to_string(),
            ),
    );

    let app = approver();
    let d = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com"),
    )
    .await;
    let id = d.id.unwrap();
    let _ = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id(&id),
    )
    .await;
    let v = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Validate, "approval", "").with_elicitation_id(&id),
    )
    .await;

    assert_eq!(v.valid, Some(false));
    assert!(v.reason.unwrap().contains("approver mismatch"));
}

// ---------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------

/// Run a payload and require a denial, returning the violation.
async fn deny_for(
    app: &CibaApprover,
    http: &Arc<FakeTransport>,
    payload: ElicitationPayload,
) -> praxis_policy_core::error::PluginViolation {
    let ext = ext_with(http);
    let mut ctx = PluginContext::new();
    let result = app.handle(&payload, &ext, &mut ctx).await;
    assert!(
        !result.continue_processing,
        "this case must deny rather than report a lifecycle state"
    );
    result.violation.expect("a deny carries a violation")
}

/// A transport that refuses every connection.
///
/// Scripted rather than dialled: `Connect` specifically, not `Timeout`,
/// because it proves nothing was sent. That distinction decides whether
/// a failed dispatch merely never happened or may have already asked a
/// human.
fn unreachable_op() -> Arc<FakeTransport> {
    Arc::new(
        FakeTransport::new()
            .fail(AUTH_PATH, HttpTransportError::Connect("refused".into()))
            .fail(TOKEN_PATH, HttpTransportError::Connect("refused".into())),
    )
}

/// An unreachable OP on dispatch must deny, not report pending. Reporting
/// pending would leave the caller polling an approval request that was never
/// created, so the request would sit until it expired with nobody notified.
#[tokio::test]
async fn a_dispatch_that_cannot_reach_the_op_denies_rather_than_reporting_pending() {
    let http = unreachable_op();
    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    let violation = deny_for(&app, &http, payload).await;
    assert_eq!(violation.code, "elicitation.op_unreachable");
    assert!(
        violation.reason.contains("backchannel"),
        "the reason must name the leg that failed, since dispatch and check \
         talk to different endpoints: {}",
        violation.reason
    );
}

/// The same for the token poll: an unreachable OP is a transport failure, not
/// an approval outcome. Treating it as either approved or denied would invent a
/// human decision that nobody made.
#[tokio::test]
async fn a_check_that_cannot_reach_the_op_denies_rather_than_inventing_an_outcome() {
    let http = unreachable_op();
    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let violation = deny_for(&app, &http, payload).await;
    assert_eq!(violation.code, "elicitation.op_unreachable");
    assert!(
        violation.reason.contains("token poll"),
        "the reason must name the token poll: {}",
        violation.reason
    );
}

/// A backchannel rejection is reported with its status, because the request was
/// never registered and the caller has to stop rather than poll.
#[tokio::test]
async fn a_rejected_backchannel_request_denies_with_its_status() {
    let http = Arc::new(FakeTransport::new().json(
        AUTH_PATH,
        400,
        &json!({ "error": "invalid_request" }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    let violation = deny_for(&app, &http, payload).await;
    assert_eq!(violation.code, "elicitation.op_rejected");
    assert!(
        violation.reason.contains("400"),
        "the status must appear so an operator can tell a bad request from an \
         outage: {}",
        violation.reason
    );
}

/// A 200 from the backchannel carrying no `auth_req_id` cannot be treated as a
/// dispatched request: there would be no id for the agent to poll with.
#[tokio::test]
async fn a_backchannel_success_with_no_auth_req_id_denies() {
    let http = Arc::new(FakeTransport::new().json(
        AUTH_PATH,
        200,
        &json!({ "expires_in": 300 }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    assert_eq!(
        deny_for(&app, &http, payload).await.code,
        "elicitation.bad_response"
    );
}

/// A successful poll whose body is not JSON denies rather than being read as an
/// approval. This is the dangerous direction: a 200 means the OP issued tokens,
/// so a parse failure here must not be allowed to resolve as approved with no
/// approver recorded.
#[tokio::test]
async fn a_successful_poll_with_an_unparseable_body_denies() {
    let http = Arc::new(FakeTransport::new().json(TOKEN_PATH, 200, "not json at all"));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    assert_eq!(
        deny_for(&app, &http, payload).await.code,
        "elicitation.bad_response"
    );
}

/// An OAuth error the lifecycle mapping does not recognize is a genuine
/// failure, not a state. `authorization_pending`, `expired_token` and
/// `access_denied` each map to a lifecycle outcome; anything else, such as the
/// `invalid_grant` a spent request id produces, has to deny. Mapping an unknown
/// error to pending would make the caller poll forever.
#[tokio::test]
async fn an_unrecognized_poll_error_denies_instead_of_becoming_a_lifecycle_state() {
    let http = Arc::new(FakeTransport::new().json(
        TOKEN_PATH,
        400,
        &json!({ "error": "invalid_grant" }).to_string(),
    ));

    let app = approver();
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let violation = deny_for(&app, &http, payload).await;
    assert_eq!(violation.code, "elicitation.op_rejected");
    assert!(
        violation.reason.contains("invalid_grant"),
        "the unrecognized error must be quoted so it can be diagnosed: {}",
        violation.reason
    );
}

/// A second check after approval must replay the cached result rather than poll
/// again.
///
/// A CIBA `auth_req_id` is spent by the exchange that consumes it, so a re-poll
/// comes back `invalid_grant`, which the case above shows is a denial. The
/// confirm-then-apply retry does exactly this second check, so without the
/// replay an approval the user actually granted would turn into a denial on the
/// call that depends on it.
///
/// The replay depends on the dispatch having registered the correlation in this
/// same process: caching the resolved approver is a no-op for an id the store
/// does not already know, so the sequence has to start at dispatch. The token
/// mock expects exactly one hit, so a re-poll fails the assertion rather than
/// quietly succeeding against a still-live mock.
#[tokio::test]
async fn a_second_check_after_approval_replays_instead_of_repolling() {
    let http = Arc::new(
        FakeTransport::new()
            .json(
                AUTH_PATH,
                200,
                &json!({ "auth_req_id": "REQ-123", "expires_in": 300 }).to_string(),
            )
            .json(
                TOKEN_PATH,
                200,
                &json!({ "access_token": "at", "id_token": fake_id_token("alice@corp.com") })
                    .to_string(),
            ),
    );

    let app = approver();
    let dispatched = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
            .with_purpose("Approve raise"),
    )
    .await;
    assert_eq!(dispatched.id.as_deref(), Some("REQ-123"));

    let check = || {
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id("REQ-123")
    };

    let first = run(&app, &http, check()).await;
    assert_eq!(first.outcome, Some(ElicitationOutcomeKind::Approved));

    let second = run(&app, &http, check()).await;
    assert_eq!(
        second.outcome,
        Some(ElicitationOutcomeKind::Approved),
        "the cached approval must be replayed"
    );
    assert_eq!(second.status, Some(ElicitationStatusKind::Resolved));

    // Exactly one poll reached the OP across both checks. The
    // `auth_req_id` is single-use, so a second poll would come back
    // `invalid_grant` and turn an approval the human already gave into a
    // denial.
    assert_eq!(http.call_count_for(TOKEN_PATH), 1);
}

// ---------------------------------------------------------------------
// Configuration the approver has to refuse
// ---------------------------------------------------------------------

fn config_err(config: serde_json::Value) -> String {
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
        capabilities: std::collections::HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(config),
    };
    match CibaApprover::new(cfg) {
        Ok(_) => panic!("this config must not load"),
        Err(e) => e.to_string(),
    }
}

/// Both endpoints and the client id are required, and plaintext is refused
/// unless the operator opted in.
///
/// The plaintext check is the one that matters most: this plugin sends the
/// client secret as Basic auth on every call, so an `http://` endpoint puts it
/// on the wire in the clear.
#[tokio::test]
async fn each_incomplete_ciba_config_is_refused_at_load() {
    let base = json!({
        "backchannel_endpoint": "https://op.example/ciba/auth",
        "token_endpoint": "https://op.example/token",
        "client_id": "praxis-policy-gateway",
        "client_secret_source": { "kind": "literal", "secret": "shh" },
    });

    // The control: the baseline loads, so each failure below is attributable to
    // the single field it changes.
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
        capabilities: std::collections::HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(base.clone()),
    };
    assert!(
        CibaApprover::new(cfg).is_ok(),
        "the baseline config must load"
    );

    let with = |field: &str, value: serde_json::Value| {
        let mut c = base.clone();
        c.as_object_mut().unwrap().insert(field.to_owned(), value);
        c
    };

    for (field, value, expected) in [
        ("backchannel_endpoint", json!(""), "must be non-empty"),
        ("token_endpoint", json!("  "), "must be non-empty"),
        ("client_id", json!(""), "client_id must be non-empty"),
        (
            "backchannel_endpoint",
            json!("http://op.example/ciba/auth"),
            "https://",
        ),
        (
            "token_endpoint",
            json!("http://op.example/token"),
            "https://",
        ),
    ] {
        let err = config_err(with(field, value.clone()));
        assert!(
            err.contains(expected),
            "{field} = {value}: the message must contain {expected:?}, got: {err}"
        );
    }
}

// ---------------------------------------------------------------------
// the non-idempotency rule
// ---------------------------------------------------------------------

/// A timed-out dispatch is never repeated.
///
/// Registering a CIBA request asks a human to approve something. Repeat
/// one that already landed and the same policy decision produces two
/// approval prompts — confusing at best, and at worst two people
/// approving what one action needed.
#[tokio::test]
async fn a_timed_out_dispatch_is_not_retried() {
    let http = Arc::new(FakeTransport::new().fail(AUTH_PATH, HttpTransportError::Timeout));
    let app = approver();
    let violation = deny_for(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com"),
    )
    .await;

    assert_eq!(violation.code, "elicitation.op_timeout");
    assert_eq!(
        http.call_count_for(AUTH_PATH),
        1,
        "exactly one attempt: a repeat could ask a human twice"
    );
}

/// A timed-out poll is never repeated either.
///
/// This one looks idempotent and is not. A successful poll spends the
/// single-use `auth_req_id`; repeat a timed-out one and the spent id
/// comes back `invalid_grant`, turning an approval the human already
/// gave into a denial.
#[tokio::test]
async fn a_timed_out_poll_is_not_retried() {
    let http = Arc::new(FakeTransport::new().fail(TOKEN_PATH, HttpTransportError::Timeout));
    let app = approver();
    let violation = deny_for(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "")
            .with_elicitation_id("REQ-123"),
    )
    .await;

    assert_eq!(violation.code, "elicitation.op_timeout");
    assert_eq!(
        http.call_count_for(TOKEN_PATH),
        1,
        "a repeat would spend an auth_req_id whose result may already exist"
    );
}

/// A refused connection *is* retried, because nothing was sent.
#[tokio::test]
async fn a_refused_dispatch_is_retried() {
    let http = Arc::new(
        FakeTransport::new()
            .fail(AUTH_PATH, HttpTransportError::Connect("refused".into()))
            .json(
                AUTH_PATH,
                200,
                &json!({ "auth_req_id": "REQ-9", "expires_in": 300 }).to_string(),
            ),
    );
    let app = approver();
    let out = run(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com"),
    )
    .await;

    assert_eq!(out.id.as_deref(), Some("REQ-9"));
    assert_eq!(http.call_count_for(AUTH_PATH), 2);
}

/// Without `perform_http`, dispatch denies and issues no request.
#[tokio::test]
async fn without_a_transport_dispatch_denies_without_calling_out() {
    let http = Arc::new(FakeTransport::new().json(AUTH_PATH, 200, "{}"));
    let app = approver();
    // No transport on the extensions at all, as a host that installed
    // none would produce.
    let mut ctx = PluginContext::new();
    let result = app
        .handle(
            &ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com"),
            &Extensions::default(),
            &mut ctx,
        )
        .await;

    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.expect("a deny carries a violation").code,
        "elicitation.no_transport"
    );
    assert_eq!(
        http.call_count(),
        0,
        "nothing may reach the OP without a transport"
    );
}

/// A malformed payload is rejected on its own terms, not blamed on a
/// missing capability.
///
/// Ordering: resolving the transport before checking arguments would
/// answer a payload with no `login_hint` by complaining about
/// `perform_http`, sending an operator to fix the wrong file.
#[tokio::test]
async fn a_bad_request_is_reported_as_such_even_with_no_transport() {
    let app = approver();
    let mut ctx = PluginContext::new();
    let result = app
        .handle(
            // Dispatch with an empty login hint.
            &ElicitationPayload::new(ElicitationOp::Dispatch, "approval", ""),
            &Extensions::default(),
            &mut ctx,
        )
        .await;

    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.expect("a deny carries a violation").code,
        "elicitation.bad_request",
        "argument validation must run before the transport is required"
    );
}

/// Same for CIBA: a refusal by the host is its own outcome.
///
/// It matters more here than elsewhere, because the alternative reading
/// — "the OP is unreachable" — invites an operator to wait for an outage
/// to pass, when nothing was ever sent and nothing will be until their
/// egress config changes.
#[tokio::test]
async fn a_host_refusal_is_reported_as_egress_denied() {
    let http = Arc::new(FakeTransport::new().fail(
        AUTH_PATH,
        HttpTransportError::Rejected("egress policy".into()),
    ));
    let app = approver();
    let violation = deny_for(
        &app,
        &http,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com"),
    )
    .await;

    assert_eq!(violation.code, "elicitation.egress_denied");
    assert!(
        violation.reason.contains("egress policy"),
        "the host's reason must survive: {}",
        violation.reason
    );
    assert_eq!(
        http.call_count_for(AUTH_PATH),
        1,
        "a refusal is not retried"
    );
}
