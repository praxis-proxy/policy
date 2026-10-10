// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for `VaultDelegator` against a `FakeTransport`-backed
// scripted Vault. Exercises the full handler path:
// `mgr.invoke_named::<TokenDelegateHook>(...)` → delegator authenticates
// to Vault → reads KV v2 secret → translates into a `RawDelegatedToken`
// → host extracts via `from_pipeline_result`.
//
// Scenarios:
//   * user subject happy path — JWT login, KV read, correct outbound header
//   * caller_workload subject — JWT login with actor_token
//   * client subject — JWT login with bearer_token, identity from client_id
//   * this_workload subject — AppRole login
//   * missing secret (404) — surfaces `delegation.vault_secret_not_found`
//   * Vault auth failure (401) — surfaces `delegation.vault_auth_failed`
//   * Vault unreachable — surfaces `delegation.vault_unreachable`
//   * missing field in secret — surfaces `delegation.vault_field_missing`
//   * cache isolation — two callers get distinct credentials
//   * secret rotation — after TTL, new value fetched (unit-level; moka
//     uses monotonic time, so wall-clock advancement requires moka's
//     test-clock feature, which is exercised in cache.rs unit tests)
//   * path traversal — identity with `..` rejected

use std::sync::Arc;

use praxis_policy_core::delegation::{
    DelegationPayload, DelegationSubject, HOOK_TOKEN_DELEGATE, TokenDelegateHook,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::raw_credentials::{DelegationMode, TokenRole};
use praxis_policy_core::extensions::security::{
    ClientExtension, SecurityExtension, SubjectExtension, WorkloadIdentity,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::http::{HttpTransport, HttpTransportError};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_builtins::plugins::delegator_vault::VaultDelegator;

use serde_json::json;

// =====================================================================
// Fixtures
// =====================================================================

const AUTH_JWT_PATH: &str = "/v1/auth/jwt/login";
const AUTH_APPROLE_PATH: &str = "/v1/auth/approle/login";
const KV_PATH_USER123: &str = "/v1/secret/data/agents/user-123/github";
const KV_PATH_MYAPP: &str = "/v1/secret/data/agents/my-app/github";
const KV_PATH_AGENT: &str = "/v1/secret/data/agents/spiffe://example.com/agent/github";
const KV_PATH_SHARED: &str = "/v1/secret/data/shared/api-key";

fn vault_addr() -> String {
    "https://vault.example.test".to_owned()
}

fn plugin_config_for(auth: serde_json::Value) -> PluginConfig {
    PluginConfig {
        name: "vault-delegator".into(),
        kind: "test".into(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: [
            "perform_http".to_owned(),
            "read_subject".to_owned(),
            "read_claims".to_owned(),
            "read_client".to_owned(),
            "read_workload".to_owned(),
        ]
        .into(),
        config: Some(json!({
            "vault_addr": vault_addr(),
            "kv_mount": "secret",
            "secret_path_template": "agents/{{sub}}/github",
            "secret_field": "token",
            "identity_claim": "sub",
            "outbound_header": "X-API-Key",
            "insecure_http": true,
            "auth": auth,
        })),
        ..Default::default()
    }
}

fn user_auth() -> serde_json::Value {
    json!({
        "user": { "method": "jwt", "mount": "jwt", "role": "ppe-user" }
    })
}

fn all_auth() -> serde_json::Value {
    json!({
        "user": { "method": "jwt", "mount": "jwt", "role": "ppe-user" },
        "client": { "method": "jwt", "mount": "jwt", "role": "ppe-client" },
        "caller_workload": { "method": "jwt", "mount": "jwt", "role": "ppe-workload" },
        "this_workload": {
            "method": "approle",
            "mount": "approle",
            "role_id_source": { "kind": "literal", "secret": "test-role-id" },
            "secret_id_source": { "kind": "literal", "secret": "test-secret-id" },
        }
    })
}

fn vault_login_response() -> String {
    json!({ "auth": { "client_token": "s.fake-vault-token", "lease_duration": 3600 } }).to_string()
}

fn kv_response(field: &str, value: &str) -> String {
    json!({
        "data": {
            "data": { field: value },
            "metadata": { "version": 1 }
        }
    })
    .to_string()
}

fn ext_with_user_sub(sub: &str) -> Extensions {
    let mut claims = std::collections::HashMap::new();
    claims.insert("sub".into(), json!(sub));
    Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some(sub.into()),
                claims,
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn ext_with_client(client_id: &str) -> Extensions {
    Extensions {
        security: Some(Arc::new(SecurityExtension {
            client: Some(ClientExtension {
                client_id: client_id.into(),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn ext_with_caller_workload(spiffe_id: &str) -> Extensions {
    Extensions {
        security: Some(Arc::new(SecurityExtension {
            caller_workload: Some(WorkloadIdentity {
                spiffe_id: Some(spiffe_id.into()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn ext_with_this_workload(spiffe_id: &str) -> Extensions {
    Extensions {
        security: Some(Arc::new(SecurityExtension {
            this_workload: Some(WorkloadIdentity {
                spiffe_id: Some(spiffe_id.into()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn build_manager(cfg: PluginConfig, http: &Arc<FakeTransport>) -> Arc<PolicyEngine> {
    let delegator = VaultDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    let transport: Arc<dyn HttpTransport> = http.clone();
    mgr.set_http_transport(transport);
    mgr.initialize().await.unwrap();
    mgr
}

async fn invoke(
    mgr: &Arc<PolicyEngine>,
    payload: DelegationPayload,
    ext: Extensions,
) -> praxis_policy_core::executor::PipelineResult {
    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(HOOK_TOKEN_DELEGATE, payload, ext, None)
        .await;
    result
}

// =====================================================================
// Scenarios
// =====================================================================

// User subject happy path: JWT login with bearer_token, KV read,
// token returned with correct outbound_header.
#[tokio::test]
async fn user_subject_happy_path() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_USER123, 200, &kv_response("token", "ghp_user123")),
    );

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("user-jwt-bytes", "github-api")
        .with_target_audience("https://api.github.com");
    let ext = ext_with_user_sub("user-123");

    let result = invoke(&mgr, payload, ext).await;
    assert!(
        result.continue_processing,
        "user happy path should succeed: {:?}",
        result.violation,
    );

    let final_payload =
        DelegationPayload::from_pipeline_result(&result).expect("delegation payload present");
    let token = final_payload
        .delegated_token
        .as_ref()
        .expect("token populated");

    assert_eq!(&*token.token, "ghp_user123");
    assert_eq!(token.outbound_header, "X-API-Key");
    assert_eq!(token.audience, "https://api.github.com");
    assert!(token.scopes.is_empty());
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    assert_eq!(http.call_count_for(AUTH_JWT_PATH), 1);
    assert_eq!(http.call_count_for(KV_PATH_USER123), 1);
}

// CallerWorkload subject: JWT login with bearer_token (the inbound SVID).
#[tokio::test]
async fn caller_workload_uses_bearer_token() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_AGENT, 200, &kv_response("token", "ghp_agent")),
    );

    let mut cfg = plugin_config_for(all_auth());
    cfg.config.as_mut().unwrap()["identity_claim"] = json!("spiffe_id");
    cfg.config.as_mut().unwrap()["secret_path_template"] = json!("agents/{{spiffe_id}}/github");

    let mgr = build_manager(cfg, &http).await;
    let payload = DelegationPayload::new("svid-jwt-bytes", "github-api")
        .with_subject(DelegationSubject::CallerWorkload)
        .with_target_audience("https://api.github.com");
    let ext = ext_with_caller_workload("spiffe://example.com/agent");

    let result = invoke(&mgr, payload, ext).await;
    assert!(result.continue_processing, "{:?}", result.violation);

    let final_payload = DelegationPayload::from_pipeline_result(&result).unwrap();
    let token = final_payload.delegated_token.as_ref().unwrap();
    assert_eq!(&*token.token, "ghp_agent");

    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::AsCallerWorkload),
    ));

    // Verify the JWT login used the bearer_token (the workload's SVID)
    let login_req = http
        .requests()
        .into_iter()
        .find(|r| r.url.contains("auth/jwt/login"))
        .expect("jwt login request");
    let body = String::from_utf8_lossy(&login_req.body).into_owned();
    assert!(body.contains("svid-jwt-bytes"), "should use bearer_token");
}

// Client subject: JWT login with bearer_token, identity from client_id.
#[tokio::test]
async fn client_subject_uses_client_id() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_MYAPP, 200, &kv_response("token", "ghp_client")),
    );

    let mut cfg = plugin_config_for(all_auth());
    cfg.config.as_mut().unwrap()["identity_claim"] = json!("client_id");
    cfg.config.as_mut().unwrap()["secret_path_template"] = json!("agents/{{client_id}}/github");

    let mgr = build_manager(cfg, &http).await;
    let payload = DelegationPayload::new("client-cred-jwt", "github-api")
        .with_subject(DelegationSubject::Client)
        .with_target_audience("https://api.github.com");
    let ext = ext_with_client("my-app");

    let result = invoke(&mgr, payload, ext).await;
    assert!(result.continue_processing, "{:?}", result.violation);

    let final_payload = DelegationPayload::from_pipeline_result(&result).unwrap();
    assert_eq!(
        &*final_payload.delegated_token.as_ref().unwrap().token,
        "ghp_client"
    );
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::AsClient),
    ));
}

// ThisWorkload subject: AppRole login (no JWT).
#[tokio::test]
async fn this_workload_uses_approle() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_APPROLE_PATH, 200, &vault_login_response())
            .json(KV_PATH_SHARED, 200, &kv_response("token", "shared-key")),
    );

    let this_workload_auth = json!({
        "this_workload": {
            "method": "approle",
            "mount": "approle",
            "role_id_source": { "kind": "literal", "secret": "test-role-id" },
            "secret_id_source": { "kind": "literal", "secret": "test-secret-id" },
        }
    });
    let mut cfg = plugin_config_for(this_workload_auth);
    cfg.config.as_mut().unwrap()["identity_claim"] = json!("spiffe_id");
    cfg.config.as_mut().unwrap()["secret_path_template"] = json!("shared/api-key");

    let mgr = build_manager(cfg, &http).await;
    let payload = DelegationPayload::new("", "legacy-api")
        .with_subject(DelegationSubject::ThisWorkload)
        .with_target_audience("https://legacy.example.com");
    let ext = ext_with_this_workload("spiffe://example.com/ppe");

    let result = invoke(&mgr, payload, ext).await;
    assert!(result.continue_processing, "{:?}", result.violation);

    let final_payload = DelegationPayload::from_pipeline_result(&result).unwrap();
    assert_eq!(
        &*final_payload.delegated_token.as_ref().unwrap().token,
        "shared-key"
    );
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::AsThisWorkload),
    ));

    assert_eq!(http.call_count_for(AUTH_APPROLE_PATH), 1);
    assert_eq!(http.call_count_for(AUTH_JWT_PATH), 0);
}

// Missing secret (404) returns a distinguishable violation.
#[tokio::test]
async fn missing_secret_returns_enrollment_error() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_USER123, 404, r#"{"errors":[]}"#),
    );

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let ext = ext_with_user_sub("user-123");

    let result = invoke(&mgr, payload, ext).await;
    assert!(!result.continue_processing);
    let v = result.violation.as_ref().unwrap();
    assert_eq!(v.code, "delegation.vault_secret_not_found");
    assert!(v.reason.contains("enrolled"));
}

// Vault auth failure (401) returns a specific violation.
#[tokio::test]
async fn vault_auth_failure() {
    let http = Arc::new(FakeTransport::new().json(
        AUTH_JWT_PATH,
        401,
        r#"{"errors":["permission denied"]}"#,
    ));

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("bad-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let ext = ext_with_user_sub("user-123");

    let result = invoke(&mgr, payload, ext).await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.as_ref().unwrap().code,
        "delegation.vault_auth_failed"
    );
}

// Vault unreachable: transport connect failure.
#[tokio::test]
async fn vault_unreachable() {
    let http = Arc::new(
        FakeTransport::new().fail(AUTH_JWT_PATH, HttpTransportError::Connect("refused".into())),
    );

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let ext = ext_with_user_sub("user-123");

    let result = invoke(&mgr, payload, ext).await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.as_ref().unwrap().code,
        "delegation.vault_unreachable"
    );
}

// Missing field in secret returns a specific violation.
#[tokio::test]
async fn missing_field_in_secret() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_USER123, 200, &kv_response("wrong_field", "value")),
    );

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let ext = ext_with_user_sub("user-123");

    let result = invoke(&mgr, payload, ext).await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.as_ref().unwrap().code,
        "delegation.vault_field_missing"
    );
}

// Unconfigured subject is denied.
#[tokio::test]
async fn unconfigured_subject_denied() {
    let http = Arc::new(FakeTransport::new());

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("client-jwt", "github-api")
        .with_subject(DelegationSubject::Client)
        .with_target_audience("https://api.github.com");
    let ext = ext_with_client("my-app");

    let result = invoke(&mgr, payload, ext).await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.as_ref().unwrap().code,
        "delegation.vault_auth_unconfigured"
    );
}

// Cache isolation: two different users get different credentials.
#[tokio::test]
async fn cache_isolates_callers() {
    let kv_path_alice = "/v1/secret/data/agents/alice/github";
    let kv_path_bob = "/v1/secret/data/agents/bob/github";

    let http = Arc::new(
        FakeTransport::new()
            // Two login calls, two KV reads
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(kv_path_alice, 200, &kv_response("token", "alice-token"))
            .json(kv_path_bob, 200, &kv_response("token", "bob-token")),
    );

    let mut cfg = plugin_config_for(user_auth());
    cfg.config.as_mut().unwrap()["cache"] = json!({
        "enabled": true,
        "ttl_seconds": 60,
        "max_entries": 100,
    });

    let mgr = build_manager(cfg, &http).await;

    // Alice
    let alice_payload = DelegationPayload::new("alice-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let alice_ext = ext_with_user_sub("alice");
    let alice_result = invoke(&mgr, alice_payload, alice_ext).await;
    assert!(
        alice_result.continue_processing,
        "{:?}",
        alice_result.violation
    );

    // Bob
    let bob_payload = DelegationPayload::new("bob-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let bob_ext = ext_with_user_sub("bob");
    let bob_result = invoke(&mgr, bob_payload, bob_ext).await;
    assert!(bob_result.continue_processing, "{:?}", bob_result.violation);

    let alice_token = DelegationPayload::from_pipeline_result(&alice_result)
        .unwrap()
        .delegated_token
        .unwrap();
    let bob_token = DelegationPayload::from_pipeline_result(&bob_result)
        .unwrap()
        .delegated_token
        .unwrap();

    assert_eq!(&*alice_token.token, "alice-token");
    assert_eq!(&*bob_token.token, "bob-token");
    assert_ne!(&*alice_token.token, &*bob_token.token);

    // Alice again — should hit cache, no new Vault calls
    let alice_payload2 = DelegationPayload::new("alice-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let alice_ext2 = ext_with_user_sub("alice");
    let alice_result2 = invoke(&mgr, alice_payload2, alice_ext2).await;
    assert!(
        alice_result2.continue_processing,
        "{:?}",
        alice_result2.violation
    );
    let fp2 = DelegationPayload::from_pipeline_result(&alice_result2).unwrap();
    assert_eq!(&*fp2.delegated_token.as_ref().unwrap().token, "alice-token");
    assert_eq!(&fp2.metadata["delegated_token_source"], "cache");
    assert_eq!(http.call_count_for(AUTH_JWT_PATH), 2, "no new login call");
}

// Different JWTs for the same identity must NOT share a cache entry.
// A JWT that Vault would reject must not reuse another JWT's credential.
#[tokio::test]
async fn cache_rejects_different_jwt_for_same_identity() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_USER123, 200, &kv_response("token", "ghp_jwt1"))
            .json(KV_PATH_USER123, 200, &kv_response("token", "ghp_jwt2")),
    );

    let mut cfg = plugin_config_for(user_auth());
    cfg.config.as_mut().unwrap()["cache"] = json!({
        "enabled": true,
        "ttl_seconds": 60,
        "max_entries": 100,
    });

    let mgr = build_manager(cfg, &http).await;

    // First call with jwt-A
    let r1 = invoke(
        &mgr,
        DelegationPayload::new("jwt-A", "github-api")
            .with_target_audience("https://api.github.com"),
        ext_with_user_sub("user-123"),
    )
    .await;
    assert!(r1.continue_processing, "{:?}", r1.violation);

    // Second call with a DIFFERENT jwt-B — must NOT reuse jwt-A's cache
    let r2 = invoke(
        &mgr,
        DelegationPayload::new("jwt-B", "github-api")
            .with_target_audience("https://api.github.com"),
        ext_with_user_sub("user-123"),
    )
    .await;
    assert!(r2.continue_processing, "{:?}", r2.violation);

    let t1 = DelegationPayload::from_pipeline_result(&r1)
        .unwrap()
        .delegated_token
        .unwrap();
    let t2 = DelegationPayload::from_pipeline_result(&r2)
        .unwrap()
        .delegated_token
        .unwrap();

    assert_eq!(&*t1.token, "ghp_jwt1");
    assert_eq!(&*t2.token, "ghp_jwt2");
    assert_eq!(
        http.call_count_for(AUTH_JWT_PATH),
        2,
        "different JWTs must trigger separate Vault logins"
    );
}

// Metadata includes secret_source and vault_secret_version.
#[tokio::test]
async fn metadata_populated() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_USER123, 200, &kv_response("token", "ghp_xxx")),
    );

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let ext = ext_with_user_sub("user-123");

    let result = invoke(&mgr, payload, ext).await;
    assert!(result.continue_processing);

    let fp = DelegationPayload::from_pipeline_result(&result).unwrap();
    assert_eq!(&fp.metadata["secret_source"], "vault");
    assert_eq!(&fp.metadata["vault_secret_version"], 1);
    assert_eq!(&fp.metadata["delegated_token_source"], "mint");
}

// Path traversal in identity claim is rejected before Vault call.
#[tokio::test]
async fn path_traversal_identity_rejected() {
    let http = Arc::new(FakeTransport::new());

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;
    let payload = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let ext = ext_with_user_sub("../../admin");

    let result = invoke(&mgr, payload, ext).await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.as_ref().unwrap().code,
        "delegation.identity_invalid"
    );
    // No HTTP calls should have been made
    assert_eq!(http.call_count_for(AUTH_JWT_PATH), 0);
}

// Actor role is rejected — Vault pre-stored credentials cannot record
// the acting party.
#[tokio::test]
async fn actor_role_rejected() {
    let http = Arc::new(FakeTransport::new());

    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;

    let payload = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com")
        .with_actor(TokenRole::Client, "client-jwt");
    let ext = ext_with_user_sub("user-123");

    let result = invoke(&mgr, payload, ext).await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.as_ref().unwrap().code,
        "delegation.actor_unsupported"
    );
    assert_eq!(http.call_count_for(AUTH_JWT_PATH), 0, "no Vault calls");
}

// ThisWorkload with the default identity_claim (sub) and a fixed path
// succeeds — the handler skips the claim lookup when the path has no
// placeholder.
#[tokio::test]
async fn this_workload_fixed_path_default_claim() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_APPROLE_PATH, 200, &vault_login_response())
            .json(KV_PATH_SHARED, 200, &kv_response("token", "shared-key")),
    );

    let cfg = PluginConfig {
        name: "vault-delegator".into(),
        kind: "test".into(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: ["perform_http".to_owned(), "read_workload".to_owned()].into(),
        config: Some(json!({
            "vault_addr": vault_addr(),
            "secret_path_template": "shared/api-key",
            "insecure_http": true,
            "auth": {
                "this_workload": {
                    "method": "approle",
                    "mount": "approle",
                    "role_id_source": { "kind": "literal", "secret": "test-role-id" },
                    "secret_id_source": { "kind": "literal", "secret": "test-secret-id" },
                }
            }
        })),
        ..Default::default()
    };

    let mgr = build_manager(cfg, &http).await;
    let payload = DelegationPayload::new("", "legacy-api")
        .with_subject(DelegationSubject::ThisWorkload)
        .with_target_audience("https://legacy.example.com");
    let ext = ext_with_this_workload("spiffe://example.com/ppe");

    let result = invoke(&mgr, payload, ext).await;
    assert!(
        result.continue_processing,
        "this_workload with default claim + fixed path should succeed: {:?}",
        result.violation
    );
    assert_eq!(
        &*DelegationPayload::from_pipeline_result(&result)
            .unwrap()
            .delegated_token
            .as_ref()
            .unwrap()
            .token,
        "shared-key"
    );
}

// Secret rotation: without cache, successive calls fetch fresh values.
#[tokio::test]
async fn uncached_fetches_fresh_each_time() {
    let http = Arc::new(
        FakeTransport::new()
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(AUTH_JWT_PATH, 200, &vault_login_response())
            .json(KV_PATH_USER123, 200, &kv_response("token", "ghp_v1"))
            .json(KV_PATH_USER123, 200, &kv_response("token", "ghp_v2")),
    );

    // No cache configured (default)
    let mgr = build_manager(plugin_config_for(user_auth()), &http).await;

    let payload1 = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let r1 = invoke(&mgr, payload1, ext_with_user_sub("user-123")).await;
    assert!(r1.continue_processing, "{:?}", r1.violation);

    let payload2 = DelegationPayload::new("user-jwt", "github-api")
        .with_target_audience("https://api.github.com");
    let r2 = invoke(&mgr, payload2, ext_with_user_sub("user-123")).await;
    assert!(r2.continue_processing, "{:?}", r2.violation);

    let t1 = DelegationPayload::from_pipeline_result(&r1)
        .unwrap()
        .delegated_token
        .unwrap();
    let t2 = DelegationPayload::from_pipeline_result(&r2)
        .unwrap()
        .delegated_token
        .unwrap();
    assert_eq!(&*t1.token, "ghp_v1");
    assert_eq!(&*t2.token, "ghp_v2");

    assert_eq!(http.call_count_for(AUTH_JWT_PATH), 2);
    assert_eq!(http.call_count_for(KV_PATH_USER123), 2);
}
