// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Live Vault KV v2 coverage. See `docs/content/testing.md` for provisioning.

#![cfg(all(feature = "secrets-vault", feature = "http-hyper"))]
#![expect(clippy::expect_used, reason = "test code")]

use std::env;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use praxis_policy::{HyperTransport, SecretProviderFactory as _, VaultSecretProviderFactory};
use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
use praxis_policy_core::secrets::SecretProviderConfig;

#[derive(Debug)]
struct RecordingTransport {
    inner: HyperTransport,
    deleted_response: Mutex<Option<HttpResponse>>,
}

#[async_trait]
impl HttpTransport for RecordingTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let deleted_read = request.url.ends_with("/v1/secret/data/live-deleted");
        let response = self.inner.execute(request).await?;
        if deleted_read {
            *self.deleted_response.lock().expect("recording lock") = Some(response.clone());
        }
        Ok(response)
    }
}

#[tokio::test]
#[ignore = "requires a provisioned Vault server; see docs/content/testing.md"]
async fn vault_kv_v2_reads_live_and_maps_soft_deleted_versions() {
    let (Ok(address), Ok(role_id), Ok(secret_id)) = (
        env::var("VAULT_ADDR"),
        env::var("VAULT_ROLE_ID"),
        env::var("VAULT_SECRET_ID"),
    ) else {
        return;
    };
    let transport = Arc::new(RecordingTransport {
        inner: HyperTransport::new().with_allow_private_destinations(),
        deleted_response: Mutex::new(None),
    });
    let factory = VaultSecretProviderFactory::new(transport.clone());
    let settings = serde_yaml::from_str(&format!(
        "address: {address}\ninsecure_http: {}\nauth:\n  method: approle\n  role_id: {role_id}\n  secret_id:\n    literal: {secret_id}\nallow_insecure_literal: true\n",
        address.starts_with("http://")
    ))
    .expect("settings");
    let provider = factory
        .build(&SecretProviderConfig {
            kind: "vault".to_owned(),
            settings,
        })
        .expect("provider");

    assert_eq!(
        provider
            .get_secret("secret/live#password")
            .await
            .expect("live read")
            .as_str(),
        "live-value"
    );
    let deleted = provider
        .get_secret("secret/live-deleted#password")
        .await
        .expect_err("soft-deleted version must be absent");
    assert!(
        matches!(deleted, praxis_policy::SecretError::NotFound { .. }),
        "{deleted}"
    );
    let response = transport
        .deleted_response
        .lock()
        .expect("recording lock")
        .take()
        .expect("soft-deleted KV response");
    assert_eq!(response.status, 404);
    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("KV JSON");
    assert!(
        body.pointer("/data/data")
            .is_some_and(serde_json::Value::is_null),
        "{body}"
    );
    assert!(
        body.pointer("/data/metadata/deletion_time")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|time| !time.is_empty()),
        "{body}"
    );
}
