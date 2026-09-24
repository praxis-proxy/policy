// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Vault KV v2 `SecretProvider`.
//
// The factory captures a host `HttpTransport` and builds a provider that
// logs in lazily, renews on the next read, and never spawns a task.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
use praxis_policy_core::http_retry::{RetryPolicy, execute_with_retry};
use praxis_policy_core::secrets::{
    SecretError, SecretProvider, SecretProviderConfig, SecretProviderFactory,
};

use crate::KIND;
use crate::config::{ValidatedSettings, VaultAuth, read_service_account_token};
use crate::reference::KvRef;

/// Process-wide counter so concurrent providers do not share a renew
/// deadline. Same trick as HTTP retry jitter, no extra dependency.
static RENEW_JITTER: AtomicU64 = AtomicU64::new(0);

/// Identity of the session currently held by a provider. A generation is
/// distinct even when Vault renews a token to the same token value.
static SESSION_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Renew when this fraction of `lease_duration` has elapsed.
const RENEW_AFTER_NUM: u32 = 2;
const RENEW_AFTER_DEN: u32 = 3;
/// Downward jitter as a fraction of the renew-after interval.
const RENEW_JITTER_NUM: u32 = 1;
const RENEW_JITTER_DEN: u32 = 10;

/// Builds a Vault KV v2 [`SecretProvider`].
pub struct VaultSecretProviderFactory {
    transport: Arc<dyn HttpTransport>,
}

impl VaultSecretProviderFactory {
    /// Capture the host transport. Does not dial.
    #[must_use]
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self { transport }
    }
}

impl SecretProviderFactory for VaultSecretProviderFactory {
    fn kind(&self) -> &str {
        KIND
    }

    fn build(&self, config: &SecretProviderConfig) -> Result<Arc<dyn SecretProvider>, SecretError> {
        let settings = crate::config::VaultSettings::from_config(&config.settings)?;
        Ok(Arc::new(VaultSecretProvider {
            transport: Arc::clone(&self.transport),
            settings,
            session: Mutex::new(None),
        }))
    }
}

/// One Vault instance, one auth method, one captured transport.
struct VaultSecretProvider {
    transport: Arc<dyn HttpTransport>,
    settings: ValidatedSettings,
    session: Mutex<Option<VaultSession>>,
}

struct VaultSession {
    token: Zeroizing<String>,
    generation: u64,
    renewable: bool,
    renew_at: Option<Instant>,
}

impl fmt::Debug for VaultSecretProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSecretProvider")
            .field("address", &self.settings.address)
            .field("auth", &self.settings.auth.kind_name())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSession")
            .field("renewable", &self.renewable)
            .finish_non_exhaustive()
    }
}

impl VaultSession {
    fn from_auth(auth: &Value, now: Instant, operation: &str) -> Result<Self, SecretError> {
        let token = auth
            .get("client_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SecretError::backend(format!("Vault {operation} returned no client token"))
            })?;
        let lease = auth
            .get("lease_duration")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let renewable = auth
            .get("renewable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(Self {
            token: Zeroizing::new(token.to_owned()),
            generation: SESSION_GENERATION.fetch_add(1, Ordering::Relaxed),
            renewable,
            renew_at: (lease > 0).then(|| now + renew_after(Duration::from_secs(lease))),
        })
    }

    fn needs_renewal(&self, now: Instant) -> bool {
        self.renew_at.is_some_and(|renew_at| now >= renew_at)
    }
}

fn renew_after(lease: Duration) -> Duration {
    let after = lease.saturating_mul(RENEW_AFTER_NUM) / RENEW_AFTER_DEN;
    let band = after.saturating_mul(RENEW_JITTER_NUM) / RENEW_JITTER_DEN;
    let ceiling = u64::try_from(band.as_millis()).unwrap_or(0);
    let jitter = if ceiling == 0 {
        Duration::ZERO
    } else {
        let seq = RENEW_JITTER.fetch_add(1, Ordering::Relaxed);
        let spread = seq.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32;
        Duration::from_millis(spread % (ceiling + 1))
    };
    after.saturating_sub(jitter)
}

#[async_trait]
impl SecretProvider for VaultSecretProvider {
    async fn get_secret(&self, reference: &str) -> Result<Zeroizing<String>, SecretError> {
        let kv = KvRef::parse(reference)?;
        let (token, generation) = self.session_token().await?;
        match self.kv_read(token.as_str(), &kv).await {
            Ok(value) => Ok(value),
            Err(ReadFault::Forbidden) => {
                let token = {
                    let mut session = self.session.lock().await;
                    if session
                        .as_ref()
                        .is_some_and(|current| current.generation == generation)
                    {
                        *session = None;
                    }
                    self.ensure_token(&mut session).await?;
                    session
                        .as_ref()
                        .map(|s| s.token.clone())
                        .ok_or_else(|| SecretError::backend("no Vault token after login"))?
                };
                match self.kv_read(token.as_str(), &kv).await {
                    Ok(value) => Ok(value),
                    Err(ReadFault::Forbidden) => Err(SecretError::backend(
                        "Vault returned 403 after reauthentication; this is a permission error, \
                         not a missing secret",
                    )),
                    Err(ReadFault::Failed(err)) => Err(err),
                }
            },
            Err(ReadFault::Failed(err)) => Err(err),
        }
    }
}

enum ReadFault {
    Forbidden,
    Failed(SecretError),
}

impl VaultSecretProvider {
    async fn session_token(&self) -> Result<(Zeroizing<String>, u64), SecretError> {
        let mut session = self.session.lock().await;
        self.ensure_token(&mut session).await?;
        session
            .as_ref()
            .map(|s| (s.token.clone(), s.generation))
            .ok_or_else(|| SecretError::backend("no Vault token after login"))
    }

    async fn ensure_token(&self, session: &mut Option<VaultSession>) -> Result<(), SecretError> {
        let now = Instant::now();
        match session.as_ref() {
            Some(s) if !s.needs_renewal(now) => Ok(()),
            Some(s) if s.renewable => {
                let token = s.token.clone();
                if let Ok(next) = self.renew_self(token.as_str()).await {
                    *session = Some(next);
                    Ok(())
                } else {
                    *session = Some(self.login().await?);
                    Ok(())
                }
            },
            _ => {
                *session = Some(self.login().await?);
                Ok(())
            },
        }
    }

    async fn login(&self) -> Result<VaultSession, SecretError> {
        let (mount, body) = match &self.settings.auth {
            VaultAuth::Kubernetes {
                role,
                mount,
                token_path,
            } => {
                let jwt = read_service_account_token(token_path)?;
                let body = json_login_body(&KubernetesLogin {
                    role: role.as_str(),
                    jwt: jwt.as_str(),
                })?;
                (mount.as_str(), body)
            },
            VaultAuth::Approle {
                role_id,
                mount,
                secret_id,
            } => {
                let secret_id = secret_id.read()?;
                let body = json_login_body(&AppRoleLogin {
                    role_id: role_id.as_str(),
                    secret_id: secret_id.as_str(),
                })?;
                (mount.as_str(), body)
            },
        };
        let operation = format!("login via auth mount `{mount}`");
        let bytes = Bytes::copy_from_slice(&body);
        drop(body);
        let path = format!("v1/auth/{mount}/login");
        let response = self
            .send(
                HttpRequest::post(self.url(&path), bytes)
                    .header("content-type", "application/json")
                    .map_err(|err| transport_err(&operation, err))?,
                RetryPolicy::undelivered_only(),
                &operation,
            )
            .await?;
        let auth = parse_auth_payload(&response, &operation)?;
        VaultSession::from_auth(&auth, Instant::now(), &operation)
    }

    async fn renew_self(&self, token: &str) -> Result<VaultSession, SecretError> {
        let operation = "renew-self";
        let req = HttpRequest::post(self.url("v1/auth/token/renew-self"), Bytes::new())
            .header("content-type", "application/json")
            .and_then(|r| r.header("X-Vault-Token", token))
            .map_err(|err| transport_err(operation, err))?;
        let response = self.send(req, RetryPolicy::idempotent(), operation).await?;
        let auth = parse_auth_payload(&response, operation)?;
        VaultSession::from_auth(&auth, Instant::now(), operation)
    }

    async fn kv_read(&self, token: &str, kv: &KvRef) -> Result<Zeroizing<String>, ReadFault> {
        let operation = format!("KV read `{}`", kv_ref_display(kv));
        let req = HttpRequest::get(self.url(&kv.kv_url_path()))
            .header("X-Vault-Token", token)
            .map_err(|e| ReadFault::Failed(transport_err(&operation, e)))?;
        let req = self
            .with_namespace(req, &operation)
            .map_err(ReadFault::Failed)?;
        let response =
            match execute_with_retry(self.transport.as_ref(), req, RetryPolicy::idempotent()).await
            {
                Ok(resp) => resp,
                Err(err) => return Err(ReadFault::Failed(transport_err(&operation, err))),
            };
        match response.status {
            200 => extract_field(&response.body, kv).map_err(ReadFault::Failed),
            403 => Err(ReadFault::Forbidden),
            404 => Err(ReadFault::Failed(SecretError::not_found(format!(
                "{}/{}#{}",
                kv.mount, kv.path, kv.field
            )))),
            other => Err(ReadFault::Failed(vault_status_error(
                &operation,
                other,
                &response.body,
            ))),
        }
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.settings.address.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn with_namespace(
        &self,
        req: HttpRequest,
        operation: &str,
    ) -> Result<HttpRequest, SecretError> {
        match self.settings.namespace.as_deref() {
            Some(ns) => req
                .header("X-Vault-Namespace", ns)
                .map_err(|err| transport_err(operation, err)),
            None => Ok(req),
        }
    }

    async fn send(
        &self,
        req: HttpRequest,
        policy: RetryPolicy,
        operation: &str,
    ) -> Result<HttpResponse, SecretError> {
        let req = self.with_namespace(req, operation)?;
        execute_with_retry(self.transport.as_ref(), req, policy)
            .await
            .map_err(|err| transport_err(operation, err))
            .and_then(|resp| {
                if resp.status == 200 {
                    Ok(resp)
                } else {
                    Err(vault_status_error(operation, resp.status, &resp.body))
                }
            })
    }
}

#[derive(Serialize)]
struct KubernetesLogin<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Serialize)]
struct AppRoleLogin<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

fn json_login_body<T: Serialize>(payload: &T) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let mut out = Zeroizing::new(Vec::with_capacity(128));
    serde_json::to_writer(&mut *out, payload)
        .map_err(|err| SecretError::backend(format!("Vault login JSON encoding failed: {err}")))?;
    Ok(out)
}

fn parse_auth_payload(response: &HttpResponse, operation: &str) -> Result<Value, SecretError> {
    let root: Value = serde_json::from_slice(&response.body).map_err(|_json| {
        SecretError::backend(format!("Vault {operation} response was not JSON"))
    })?;
    root.get("auth")
        .cloned()
        .filter(Value::is_object)
        .ok_or_else(|| {
            SecretError::backend(format!("Vault {operation} response had no auth object"))
        })
}

fn extract_field(body: &Bytes, kv: &KvRef) -> Result<Zeroizing<String>, SecretError> {
    let root: Value = serde_json::from_slice(body).map_err(|_json| {
        SecretError::malformed(kv_ref_display(kv), "Vault KV response was not JSON")
    })?;
    let data_value = root.pointer("/data/data").ok_or_else(|| {
        SecretError::malformed(kv_ref_display(kv), "Vault KV response had no data.data map")
    })?;
    if data_value.is_null() {
        return Err(SecretError::not_found(kv_ref_display(kv)));
    }
    let data = data_value.as_object().ok_or_else(|| {
        SecretError::malformed(
            kv_ref_display(kv),
            "Vault KV response data.data was not a map",
        )
    })?;
    match data.get(&kv.field) {
        None => Err(SecretError::malformed(
            kv_ref_display(kv),
            format!("field `{}` is absent", kv.field),
        )),
        Some(Value::String(s)) if s.is_empty() => Err(SecretError::malformed(
            kv_ref_display(kv),
            format!("field `{}` is empty", kv.field),
        )),
        Some(Value::String(s)) => Ok(Zeroizing::new(s.clone())),
        Some(_) => Err(SecretError::malformed(
            kv_ref_display(kv),
            format!("field `{}` is not a string", kv.field),
        )),
    }
}

fn kv_ref_display(kv: &KvRef) -> String {
    format!("{}/{}#{}", kv.mount, kv.path, kv.field)
}

fn vault_errors(body: &Bytes) -> Option<String> {
    let root: Value = serde_json::from_slice(body).ok()?;
    let errors = root.get("errors")?.as_array()?;
    let joined: Vec<&str> = errors.iter().filter_map(Value::as_str).collect();
    if joined.is_empty() {
        None
    } else {
        Some(joined.join("; "))
    }
}

fn vault_status_error(operation: &str, status: u16, body: &Bytes) -> SecretError {
    match vault_errors(body) {
        Some(errors) => SecretError::backend(format!("Vault {operation} HTTP {status}: {errors}")),
        None => SecretError::backend(format!("Vault {operation} HTTP {status}")),
    }
}

fn transport_err(operation: &str, err: HttpTransportError) -> SecretError {
    SecretError::backend(format!("Vault {operation} transport: {err}"))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::http_testing::FakeTransport;

    fn provider(http: FakeTransport, yaml: &str) -> Arc<dyn SecretProvider> {
        let factory = VaultSecretProviderFactory::new(Arc::new(http));
        let settings: serde_yaml::Value = serde_yaml::from_str(yaml).expect("yaml");
        factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings,
            })
            .expect("build")
    }

    fn approle_yaml() -> &'static str {
        "
address: https://vault.example.com
allow_insecure_literal: true
auth:
  method: approle
  role_id: role-id
  secret_id:
    literal: secret-id
"
    }

    fn login_body() -> &'static str {
        r#"{"auth":{"client_token":"hvs.token","lease_duration":3600,"renewable":true}}"#
    }

    fn kv_body(field: &str, value: &str) -> String {
        format!(r#"{{"data":{{"data":{{"{field}":"{value}"}}}}}}"#)
    }

    #[tokio::test]
    async fn approle_reads_a_string_field() {
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/app", 200, &kv_body("password", "hunter2"));
        let p = provider(http, approle_yaml());
        let value = p.get_secret("secret/app#password").await.expect("read");
        assert_eq!(value.as_str(), "hunter2");
    }

    #[tokio::test]
    async fn a_missing_path_is_not_found_and_a_missing_field_is_malformed() {
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/missing", 404, r#"{"errors":["no secret"]}"#)
            .json("/data/app", 200, &kv_body("other", "x"));
        let p = provider(http, approle_yaml());
        let missing = p
            .get_secret("secret/missing#password")
            .await
            .expect_err("404");
        assert!(matches!(missing, SecretError::NotFound { .. }), "{missing}");
        let field = p
            .get_secret("secret/app#password")
            .await
            .expect_err("absent field");
        assert!(matches!(field, SecretError::Malformed { .. }), "{field}");
    }

    #[tokio::test]
    async fn empty_and_non_string_fields_are_malformed() {
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/empty", 200, r#"{"data":{"data":{"k":""}}}"#)
            .json("/data/num", 200, r#"{"data":{"data":{"k":1}}}"#);
        let p = provider(http, approle_yaml());
        let empty = p.get_secret("secret/empty#k").await.expect_err("empty");
        assert!(matches!(empty, SecretError::Malformed { .. }), "{empty}");
        let numbered = p.get_secret("secret/num#k").await.expect_err("number");
        assert!(
            matches!(numbered, SecretError::Malformed { .. }),
            "{numbered}"
        );
    }

    #[tokio::test]
    async fn a_soft_deleted_kv_version_is_not_found() {
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/deleted", 200, r#"{"data":{"data":null}}"#);
        let p = provider(http, approle_yaml());
        let err = p
            .get_secret("secret/deleted#password")
            .await
            .expect_err("soft-deleted value");
        assert!(matches!(err, SecretError::NotFound { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_403_reauthenticates_once_and_retries() {
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/app", 403, r#"{"errors":["permission denied"]}"#)
            .json("/data/app", 200, &kv_body("password", "rotated"));
        let p = provider(http, approle_yaml());
        let value = p.get_secret("secret/app#password").await.expect("retried");
        assert_eq!(value.as_str(), "rotated");
    }

    #[tokio::test]
    async fn a_second_403_is_a_permission_error_not_not_found() {
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/app", 403, r#"{"errors":["permission denied"]}"#);
        let p = provider(http, approle_yaml());
        let err = p
            .get_secret("secret/app#password")
            .await
            .expect_err("still forbidden");
        assert!(matches!(err, SecretError::Backend { .. }), "{err}");
        assert!(format!("{err}").contains("permission"), "{err}");
        assert!(!format!("{err}").contains("hvs.token"), "{err}");
    }

    #[tokio::test]
    async fn concurrent_403s_reauthenticate_only_once_for_the_stale_session() {
        let http = FakeTransport::new()
            .with_latency(Duration::from_millis(10))
            .json("/auth/approle/login", 200, login_body())
            .json(
                "/auth/approle/login",
                200,
                &login_body().replace("hvs.token", "hvs.new"),
            )
            .json("/data/app", 403, r#"{"errors":["permission denied"]}"#)
            .json("/data/app", 403, r#"{"errors":["permission denied"]}"#)
            .json("/data/app", 200, &kv_body("password", "rotated"))
            .json("/data/app", 200, &kv_body("password", "rotated"));
        let transport = Arc::new(http);
        let factory = VaultSecretProviderFactory::new(transport.clone());
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(approle_yaml()).expect("yaml"),
            })
            .expect("build");
        let (first, second) = tokio::join!(
            p.get_secret("secret/app#password"),
            p.get_secret("secret/app#password"),
        );
        assert_eq!(first.expect("first").as_str(), "rotated");
        assert_eq!(second.expect("second").as_str(), "rotated");
        assert_eq!(
            transport.call_count_for("/auth/approle/login"),
            2,
            "one initial login and one reauthentication for both stale reads"
        );
    }

    #[tokio::test]
    async fn vault_errors_are_distinct_from_transport_failures() {
        let envelope = FakeTransport::new().json(
            "/auth/approle/login",
            500,
            r#"{"errors":["storage sealed"]}"#,
        );
        let p = provider(envelope, approle_yaml());
        let sealed = p
            .get_secret("secret/app#password")
            .await
            .expect_err("vault envelope");
        assert!(format!("{sealed}").contains("storage sealed"), "{sealed}");
        assert!(
            format!("{sealed}").contains("login via auth mount `approle`"),
            "{sealed}"
        );

        let transport = FakeTransport::new().fail(
            "/auth/approle/login",
            HttpTransportError::Connect("refused".into()),
        );
        let p = provider(transport, approle_yaml());
        let refused = p
            .get_secret("secret/app#password")
            .await
            .expect_err("connect");
        assert!(format!("{refused}").contains("transport"), "{refused}");
        assert!(
            format!("{refused}").contains("login via auth mount `approle`"),
            "{refused}"
        );
    }

    #[tokio::test]
    async fn a_short_lease_renewable_token_renews_on_the_next_read() {
        let login = r#"{"auth":{"client_token":"hvs.token","lease_duration":1,"renewable":true}}"#;
        let renew =
            r#"{"auth":{"client_token":"hvs.renewed","lease_duration":3600,"renewable":true}}"#;
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login)
            .json("/auth/token/renew-self", 200, renew)
            .json("/data/app", 200, &kv_body("password", "one"))
            .json("/data/app", 200, &kv_body("password", "two"));
        let p = provider(http, approle_yaml());
        let first = p.get_secret("secret/app#password").await.expect("first");
        assert_eq!(first.as_str(), "one");
        let second = p.get_secret("secret/app#password").await.expect("second");
        assert_eq!(second.as_str(), "two");
    }

    #[tokio::test]
    async fn a_zero_lease_is_treated_as_non_expiring() {
        let login = r#"{"auth":{"client_token":"hvs.token","lease_duration":0,"renewable":true}}"#;
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login)
            .json("/data/app", 200, &kv_body("password", "one"))
            .json("/data/app", 200, &kv_body("password", "two"));
        let transport = Arc::new(http);
        let factory = VaultSecretProviderFactory::new(transport.clone());
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(approle_yaml()).expect("yaml"),
            })
            .expect("build");
        let first = p.get_secret("secret/app#password").await.expect("first");
        let second = p.get_secret("secret/app#password").await.expect("second");
        assert_eq!(first.as_str(), "one");
        assert_eq!(second.as_str(), "two");
        assert_eq!(transport.call_count_for("/auth/approle/login"), 1);
    }

    #[tokio::test]
    async fn a_non_renewable_token_logs_in_again_instead_of_renewing() {
        let first = r#"{"auth":{"client_token":"hvs.one","lease_duration":1,"renewable":false}}"#;
        let second =
            r#"{"auth":{"client_token":"hvs.two","lease_duration":3600,"renewable":false}}"#;
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, first)
            .json("/auth/approle/login", 200, second)
            .json("/data/app", 200, &kv_body("password", "one"))
            .json("/data/app", 200, &kv_body("password", "two"));
        let p = provider(http, approle_yaml());
        p.get_secret("secret/app#password").await.expect("first");
        p.get_secret("secret/app#password").await.expect("second");
    }

    #[tokio::test]
    async fn concurrent_reads_share_one_login() {
        let http = FakeTransport::new()
            .with_latency(Duration::from_millis(20))
            .json("/auth/approle/login", 200, login_body())
            .json("/data/app", 200, &kv_body("password", "hunter2"));
        let transport = Arc::new(http);
        let cloned = Arc::clone(&transport);
        let factory = VaultSecretProviderFactory::new(cloned);
        let settings: serde_yaml::Value = serde_yaml::from_str(approle_yaml()).expect("yaml");
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings,
            })
            .expect("build");
        let (a, b) = tokio::join!(
            p.get_secret("secret/app#password"),
            p.get_secret("secret/app#password"),
        );
        assert_eq!(a.expect("a").as_str(), "hunter2");
        assert_eq!(b.expect("b").as_str(), "hunter2");
        assert_eq!(
            transport.call_count_for("/auth/approle/login"),
            1,
            "the session mutex serializes login"
        );
    }

    #[tokio::test]
    async fn kubernetes_rereads_the_service_account_token_on_every_login() {
        let dir = std::env::temp_dir().join(format!("ppe-vault-sa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let token_path = dir.join("token");
        std::fs::write(&token_path, "jwt-one\n").expect("write");
        let yaml = format!(
            "
address: https://vault.example.com
auth:
  method: kubernetes
  role: ppe
  token_path: {}
",
            token_path.display()
        );
        let http = FakeTransport::new()
            .json(
                "/auth/kubernetes/login",
                200,
                r#"{"auth":{"client_token":"hvs.one","lease_duration":1,"renewable":false}}"#,
            )
            .json(
                "/auth/kubernetes/login",
                200,
                r#"{"auth":{"client_token":"hvs.two","lease_duration":3600,"renewable":false}}"#,
            )
            .json("/data/app", 200, &kv_body("password", "one"))
            .json("/data/app", 200, &kv_body("password", "two"));
        let transport = Arc::new(http);
        let cloned = Arc::clone(&transport);
        let factory = VaultSecretProviderFactory::new(cloned);
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(&yaml).expect("yaml"),
            })
            .expect("build");
        p.get_secret("secret/app#password").await.expect("first");
        std::fs::write(&token_path, "jwt-two\n").expect("rotate");
        tokio::time::sleep(Duration::from_millis(700)).await;
        p.get_secret("secret/app#password").await.expect("second");
        let logins: Vec<String> = transport
            .requests()
            .into_iter()
            .filter(|r| r.url.contains("/auth/kubernetes/login"))
            .map(|r| String::from_utf8(r.body.to_vec()).expect("utf8"))
            .collect();
        assert_eq!(logins.len(), 2, "{logins:?}");
        assert!(logins[0].contains("jwt-one"), "{}", logins[0]);
        assert!(!logins[0].contains("jwt-two"), "{}", logins[0]);
        assert!(logins[1].contains("jwt-two"), "{}", logins[1]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_does_not_print_tokens_or_secret_ids() {
        let settings = crate::config::VaultSettings::from_config(
            &serde_yaml::from_str(approle_yaml()).expect("yaml"),
        )
        .expect("settings");
        let p = VaultSecretProvider {
            transport: Arc::new(FakeTransport::new()),
            settings,
            session: Mutex::new(None),
        };
        let rendered = format!("{p:?}");
        assert!(!rendered.contains("secret-id"), "{rendered}");
        assert!(!rendered.contains("hvs."), "{rendered}");
        assert!(rendered.contains("approle"), "{rendered}");
    }

    #[tokio::test]
    async fn a_login_is_not_retried() {
        let http = FakeTransport::new()
            .fail("/auth/approle/login", HttpTransportError::Timeout)
            .json("/auth/approle/login", 200, login_body());
        let transport = Arc::new(http);
        let cloned = Arc::clone(&transport);
        let factory = VaultSecretProviderFactory::new(cloned);
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(approle_yaml()).expect("yaml"),
            })
            .expect("build");
        let err = p
            .get_secret("secret/app#password")
            .await
            .expect_err("timeout stands");
        assert!(format!("{err}").contains("transport"), "{err}");
        assert_eq!(
            transport.call_count_for("/auth/approle/login"),
            1,
            "a timed-out login must not mint a second token"
        );
    }

    #[tokio::test]
    async fn a_login_connect_failure_is_retried() {
        let http = FakeTransport::new()
            .fail(
                "/auth/approle/login",
                HttpTransportError::Connect("refused".into()),
            )
            .json("/auth/approle/login", 200, login_body())
            .json("/data/app", 200, &kv_body("password", "hunter2"));
        let transport = Arc::new(http);
        let cloned = Arc::clone(&transport);
        let factory = VaultSecretProviderFactory::new(cloned);
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(approle_yaml()).expect("yaml"),
            })
            .expect("build");
        let value = p
            .get_secret("secret/app#password")
            .await
            .expect("connect is retried");
        assert_eq!(value.as_str(), "hunter2");
        assert_eq!(
            transport.call_count_for("/auth/approle/login"),
            2,
            "a connect failure is safe to retry because no request reached Vault"
        );
    }

    #[tokio::test]
    async fn a_kv_get_is_retried_on_timeout() {
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .fail("/data/app", HttpTransportError::Timeout)
            .json("/data/app", 200, &kv_body("password", "hunter2"));
        let transport = Arc::new(http);
        let cloned = Arc::clone(&transport);
        let factory = VaultSecretProviderFactory::new(cloned);
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(approle_yaml()).expect("yaml"),
            })
            .expect("build");
        let value = p.get_secret("secret/app#password").await.expect("retried");
        assert_eq!(value.as_str(), "hunter2");
        assert_eq!(
            transport.call_count_for("/data/app"),
            2,
            "an idempotent KV GET is retried once the first attempt times out"
        );
    }

    #[tokio::test]
    async fn namespace_is_sent_on_login_and_kv() {
        let yaml = "
address: https://vault.example.com
namespace: team-a
allow_insecure_literal: true
auth:
  method: approle
  role_id: role-id
  secret_id:
    literal: secret-id
";
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/app", 200, &kv_body("password", "hunter2"));
        let transport = Arc::new(http);
        let cloned = Arc::clone(&transport);
        let factory = VaultSecretProviderFactory::new(cloned);
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(yaml).expect("yaml"),
            })
            .expect("build");
        p.get_secret("secret/app#password").await.expect("read");
        let requests = transport.requests();
        assert!(requests.len() >= 2, "login then KV, got {}", requests.len());
        for req in &requests {
            let ns = req
                .headers
                .get("x-vault-namespace")
                .expect("X-Vault-Namespace");
            assert_eq!(ns.as_bytes(), b"team-a", "{}: {ns:?}", req.url);
        }
    }

    #[tokio::test]
    async fn approle_reads_secret_id_from_a_file() {
        let dir = std::env::temp_dir().join(format!("ppe-vault-sid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("secret_id");
        std::fs::write(&path, "from-file\n").expect("write");
        let yaml = format!(
            "
address: https://vault.example.com
auth:
  method: approle
  role_id: role-id
  secret_id:
    file: {}
",
            path.display()
        );
        let http = FakeTransport::new()
            .json("/auth/approle/login", 200, login_body())
            .json("/data/app", 200, &kv_body("password", "hunter2"));
        let transport = Arc::new(http);
        let cloned = Arc::clone(&transport);
        let factory = VaultSecretProviderFactory::new(cloned);
        let p = factory
            .build(&SecretProviderConfig {
                kind: KIND.to_owned(),
                settings: serde_yaml::from_str(&yaml).expect("yaml"),
            })
            .expect("build");
        p.get_secret("secret/app#password").await.expect("read");
        let login = transport
            .requests()
            .into_iter()
            .find(|r| r.url.contains("/auth/approle/login"))
            .expect("login");
        let body = String::from_utf8(login.body.to_vec()).expect("utf8");
        assert!(body.contains("from-file"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_missing_env_secret_id_is_a_config_error() {
        let yaml = "
address: https://vault.example.com
auth:
  method: approle
  role_id: role-id
  secret_id:
    env: PPE_VAULT_TEST_UNSET_SECRET_ID_9f3c
";
        let p = provider(FakeTransport::new(), yaml);
        let err = p
            .get_secret("secret/app#password")
            .await
            .expect_err("unset");
        assert!(matches!(err, SecretError::Config { .. }), "{err}");
        assert!(format!("{err}").contains("not set"), "{err}");
    }

    #[test]
    fn login_json_round_trips_and_escapes() {
        let encoded = json_login_body(&KubernetesLogin {
            role: "ppe",
            jwt: "a\"b\\c\n\r\t\u{0008}\u{000c}\u{0001}",
        })
        .expect("json");
        let parsed: serde_json::Value = serde_json::from_slice(&encoded).expect("json");
        assert_eq!(parsed["role"], "ppe");
        assert_eq!(parsed["jwt"], "a\"b\\c\n\r\t\u{0008}\u{000c}\u{0001}");
    }
}
