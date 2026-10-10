// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use serde::Deserialize;
use zeroize::Zeroizing;

use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::host::{HostServices, HttpRequestError};
use praxis_policy_core::http::{HttpRequest, HttpTransportError};
use praxis_policy_core::http_retry::RetryPolicy;

/// A Vault token obtained from login. Zeroized on drop.
pub(crate) struct VaultToken {
    pub client_token: Zeroizing<String>,
}

/// Login to Vault using JWT auth.
///
/// `POST /v1/auth/{mount}/login` with `{"jwt": "…", "role": "…"}`.
pub(crate) async fn jwt_login(
    svc: &dyn HostServices,
    vault_addr: &str,
    mount: &str,
    role: &str,
    jwt: &str,
    timeout: Duration,
) -> Result<VaultToken, PluginViolation> {
    let body = serde_json::json!({ "jwt": jwt, "role": role }).to_string();
    vault_login(svc, vault_addr, mount, body, "JWT", timeout).await
}

/// Login to Vault using `AppRole` auth.
///
/// `POST /v1/auth/{mount}/login` with `{"role_id": "…", "secret_id": "…"}`.
pub(crate) async fn approle_login(
    svc: &dyn HostServices,
    vault_addr: &str,
    mount: &str,
    role_id: &str,
    secret_id: &str,
    timeout: Duration,
) -> Result<VaultToken, PluginViolation> {
    let body = serde_json::json!({
        "role_id": role_id,
        "secret_id": secret_id
    })
    .to_string();
    vault_login(svc, vault_addr, mount, body, "AppRole", timeout).await
}

async fn vault_login(
    svc: &dyn HostServices,
    vault_addr: &str,
    mount: &str,
    body: String,
    method_label: &str,
    timeout: Duration,
) -> Result<VaultToken, PluginViolation> {
    let url = format!("{vault_addr}/v1/auth/{mount}/login");

    let request = HttpRequest::post(&url, Bytes::from(body))
        .timeout(timeout)
        .max_response_bytes(64 * 1024);
    let request = request
        .header("content-type", "application/json")
        .map_err(|e| violation_for_invalid_request(&format!("{method_label} login"), &e))?;
    let request = request
        .header("x-vault-request", "true")
        .map_err(|e| violation_for_invalid_request(&format!("{method_label} login"), &e))?;

    let response = svc
        .http_request(
            request,
            RetryPolicy::undelivered_only().with_total_budget(timeout),
        )
        .await
        .map_err(|e| violation_for_transport(&format!("{method_label} login"), &e))?;

    if !response.is_success() {
        return if response.status >= 500 {
            Err(PluginViolation::new(
                "delegation.vault_error",
                format!(
                    "Vault {method_label} login failed — server error (HTTP {})",
                    response.status
                ),
            ))
        } else {
            Err(auth_failure_violation(response.status, method_label))
        };
    }

    let parsed: VaultAuthResponse = serde_json::from_slice(&response.body).map_err(|_e| {
        PluginViolation::new(
            "delegation.vault_error",
            format!("Vault {method_label} login returned unparseable response"),
        )
    })?;

    Ok(VaultToken {
        client_token: Zeroizing::new(parsed.auth.client_token),
    })
}

/// Read a KV v2 secret from Vault.
///
/// `GET /v1/{mount}/data/{path}` with `X-Vault-Token` header.
pub(crate) async fn kv_read(
    svc: &dyn HostServices,
    vault_addr: &str,
    mount: &str,
    path: &str,
    vault_token: &str,
    timeout: Duration,
) -> Result<KvReadResult, PluginViolation> {
    let url = format!("{vault_addr}/v1/{mount}/data/{path}");

    let request = HttpRequest::get(&url)
        .timeout(timeout)
        .max_response_bytes(256 * 1024);
    let request = request
        .header("x-vault-token", vault_token)
        .map_err(|e| violation_for_invalid_request("KV read", &e))?;
    let request = request
        .header("x-vault-request", "true")
        .map_err(|e| violation_for_invalid_request("KV read", &e))?;

    let response = svc
        .http_request(
            request,
            RetryPolicy::idempotent().with_total_budget(timeout),
        )
        .await
        .map_err(|e| violation_for_transport("KV read", &e))?;

    match response.status {
        404 => {
            return Err(PluginViolation::new(
                "delegation.vault_secret_not_found",
                "no secret at the resolved path — the principal has not \
                 enrolled a credential for this target",
            ));
        },
        403 => {
            return Err(PluginViolation::new(
                "delegation.vault_forbidden",
                "Vault policy denied access to the secret path",
            ));
        },
        s if !((200..300).contains(&s)) => {
            return Err(PluginViolation::new(
                "delegation.vault_error",
                format!("Vault KV read failed (HTTP {s})"),
            ));
        },
        _ => {},
    }

    let parsed: KvV2Response = serde_json::from_slice(&response.body).map_err(|_e| {
        PluginViolation::new(
            "delegation.vault_error",
            "Vault KV response was not valid JSON",
        )
    })?;

    Ok(KvReadResult {
        data: parsed.data.data,
        version: parsed.data.metadata.version,
    })
}

/// Parsed result of a KV v2 read.
pub(crate) struct KvReadResult {
    pub data: HashMap<String, serde_json::Value>,
    pub version: u64,
}

// -- Vault response types (private, deserialization only) --

#[derive(Deserialize)]
struct VaultAuthResponse {
    auth: VaultAuth,
}

#[derive(Deserialize)]
struct VaultAuth {
    client_token: String,
}

#[derive(Deserialize)]
struct KvV2Response {
    data: KvV2Envelope,
}

#[derive(Deserialize)]
struct KvV2Envelope {
    data: HashMap<String, serde_json::Value>,
    metadata: KvV2Metadata,
}

#[derive(Deserialize)]
struct KvV2Metadata {
    version: u64,
}

// -- Error mapping --

fn auth_failure_violation(status: u16, method: &str) -> PluginViolation {
    PluginViolation::new(
        "delegation.vault_auth_failed",
        format!("Vault {method} auth rejected (HTTP {status})"),
    )
}

fn violation_for_transport(operation: &str, err: &HttpRequestError) -> PluginViolation {
    match err {
        HttpRequestError::Unavailable(_) => PluginViolation::new(
            "delegation.no_transport",
            format!(
                "no HTTP transport available for Vault {operation} — \
                 host has not installed one, or this plugin lacks perform_http"
            ),
        ),
        HttpRequestError::Transport(te) => match te {
            HttpTransportError::Timeout => PluginViolation::new(
                "delegation.vault_timeout",
                format!("Vault {operation} timed out"),
            ),
            HttpTransportError::Connect(_) => PluginViolation::new(
                "delegation.vault_unreachable",
                format!("Vault {operation} failed — could not connect"),
            ),
            HttpTransportError::Rejected(_) => PluginViolation::new(
                "delegation.vault_unreachable",
                format!("Vault {operation} rejected by transport"),
            ),
            _ => PluginViolation::new(
                "delegation.vault_error",
                format!("Vault {operation} failed — transport error"),
            ),
        },
    }
}

fn violation_for_invalid_request(operation: &str, err: &HttpTransportError) -> PluginViolation {
    PluginViolation::new(
        "delegation.bad_request",
        format!("could not build Vault {operation} request: {err}"),
    )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn vault_auth_response_parses() {
        let json = r#"{"auth":{"client_token":"s.abc123","lease_duration":3600}}"#;
        let parsed: VaultAuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.auth.client_token, "s.abc123");
    }

    #[test]
    fn kv_v2_response_parses() {
        let json = r#"{
            "data": {
                "data": {"token": "ghp_xxx", "scope": "repo"},
                "metadata": {"version": 3}
            }
        }"#;
        let parsed: KvV2Response = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.data.metadata.version, 3);
        assert_eq!(
            parsed.data.data.get("token").and_then(|v| v.as_str()),
            Some("ghp_xxx")
        );
    }

    #[test]
    fn auth_failure_uses_correct_code() {
        let v = auth_failure_violation(401, "JWT");
        assert_eq!(v.code, "delegation.vault_auth_failed");
        assert!(!v.reason.contains("eyJ"));
    }

    /// RFC 9110 §15.6.4: 503 is a server-side availability failure.
    /// `vault_login` maps status >= 500 to `vault_error`, reserving
    /// `vault_auth_failed` for client-side rejections (4xx). This test
    /// pins the helper used for the 4xx branch.
    #[test]
    fn auth_failure_is_reserved_for_client_rejections() {
        for status in [400, 401, 403, 404] {
            let v = auth_failure_violation(status, "JWT");
            assert_eq!(
                v.code, "delegation.vault_auth_failed",
                "HTTP {status} must map to vault_auth_failed, not vault_error"
            );
        }
    }
}
