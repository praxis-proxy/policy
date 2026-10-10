// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use zeroize::Zeroizing;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::delegation::{DelegationPayload, DelegationSubject, TokenDelegateHook};
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::extensions::raw_credentials::RawDelegatedToken;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use super::cache::{CredentialCache, Mint, Served, Source};
use super::config::{VaultAuthMethod, VaultDelegatorConfig};
use super::identity;
use super::vault;

struct ResolvedAppRole {
    role_id: Zeroizing<String>,
    secret_id: Zeroizing<String>,
}

/// PPE delegation handler that resolves downstream credentials from
/// `HashiCorp` Vault KV v2, scoped to the caller's identity.
pub struct VaultDelegator {
    cfg: PluginConfig,
    typed: VaultDelegatorConfig,
    approle_creds: HashMap<String, ResolvedAppRole>,
    timeout: Duration,
    ttl: chrono::TimeDelta,
    cache: Option<CredentialCache>,
}

impl std::fmt::Debug for VaultDelegator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultDelegator")
            .field("name", &self.cfg.name)
            .field("vault_addr", &self.typed.vault_addr)
            .field("kv_mount", &self.typed.kv_mount)
            .field(
                "approle_subjects",
                &self.approle_creds.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl VaultDelegator {
    /// Construct from a `PluginConfig` whose `config:` block deserializes
    /// to [`VaultDelegatorConfig`].
    ///
    /// # Errors
    ///
    /// Returns `Err` when the config block is missing, malformed, or fails
    /// validation (e.g. empty `vault_addr`, `http://` without opt-in,
    /// unknown auth subject keys, or unresolvable `AppRole` credentials).
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg
            .config
            .as_ref()
            .ok_or_else(|| PluginError::Config {
                message: "delegator/vault requires a `config:` block".into(),
            })?
            .clone();

        let mut typed: VaultDelegatorConfig =
            serde_json::from_value(raw).map_err(|e| PluginError::Config {
                message: format!("invalid delegator/vault config: {e}"),
            })?;

        typed.vault_addr = typed.vault_addr.trim().to_owned();
        if typed.vault_addr.is_empty() {
            return Err(PluginError::Config {
                message: "vault_addr must not be empty".into(),
            }
            .boxed());
        }
        if !typed.insecure_http
            && !typed
                .vault_addr
                .to_ascii_lowercase()
                .starts_with("https://")
        {
            return Err(PluginError::Config {
                message: format!(
                    "vault_addr must use https (got {}); set insecure_http: true for dev",
                    typed.vault_addr
                ),
            }
            .boxed());
        }
        if typed.secret_path_template.is_empty() {
            return Err(PluginError::Config {
                message: "secret_path_template must not be empty".into(),
            }
            .boxed());
        }
        if typed.auth.is_empty() {
            return Err(PluginError::Config {
                message: "auth map must not be empty — configure at least one subject".into(),
            }
            .boxed());
        }

        const CANONICAL_SUBJECTS: [&str; 4] =
            ["user", "client", "caller_workload", "this_workload"];

        for (key, method) in &typed.auth {
            if !CANONICAL_SUBJECTS.contains(&key.as_str()) {
                return Err(PluginError::Config {
                    message: format!(
                        "unknown auth subject '{key}' — expected one of: \
                         user, client, caller_workload, this_workload"
                    ),
                }
                .boxed());
            }
            match (key.as_str(), method) {
                ("this_workload", VaultAuthMethod::Jwt { .. }) => {
                    return Err(PluginError::Config {
                        message: "this_workload must use approle, not jwt \
                                  — there is no inbound token to forward"
                            .into(),
                    }
                    .boxed());
                },
                ("user" | "client" | "caller_workload", VaultAuthMethod::AppRole { .. }) => {
                    return Err(PluginError::Config {
                        message: format!(
                            "subject '{key}' must use jwt, not approle \
                             — per-caller identity requires forwarding \
                             the caller's own token"
                        ),
                    }
                    .boxed());
                },
                _ => {},
            }
        }

        let placeholder = format!("{{{{{}}}}}", typed.identity_claim);
        let has_jwt_subject = typed
            .auth
            .iter()
            .any(|(key, _)| matches!(key.as_str(), "user" | "client" | "caller_workload"));
        if has_jwt_subject && !typed.secret_path_template.contains(&placeholder) {
            return Err(PluginError::Config {
                message: format!(
                    "secret_path_template must contain '{placeholder}' when a per-caller \
                     subject (user/client/caller_workload) is configured — \
                     without it every caller reads the same secret"
                ),
            }
            .boxed());
        }

        // Eagerly resolve AppRole credentials (per subject)
        let approle_creds = resolve_approle_creds(&typed)?;

        // Zeroize literal secrets in the stored config now that they are resolved
        for auth in typed.auth.values_mut() {
            auth.redact_sources();
        }

        typed.cache.validate().map_err(|e| PluginError::Config {
            message: format!("cache config invalid: {e}"),
        })?;

        let cache = CredentialCache::new(&typed.cache).map_err(|e| PluginError::Config {
            message: format!("cache config invalid: {e}"),
        })?;

        let timeout = typed.timeout();

        // Safe: CacheConfig::validate already proved the conversion succeeds.
        let ttl_secs = i64::try_from(typed.cache.ttl_seconds)
            .ok()
            .and_then(chrono::TimeDelta::try_seconds)
            .ok_or_else(|| PluginError::Config {
                message: "cache.ttl_seconds is not representable as a TimeDelta".into(),
            })?;

        Ok(Self {
            cfg,
            typed,
            approle_creds,
            timeout,
            ttl: ttl_secs,
            cache,
        })
    }

    fn auth_for(
        &self,
        subject: &DelegationSubject,
    ) -> Result<&VaultAuthMethod, Box<PluginViolation>> {
        let key = subject_config_key(subject);
        self.typed.auth.get(key).ok_or_else(|| {
            Box::new(PluginViolation::new(
                "delegation.vault_auth_unconfigured",
                format!(
                    "no Vault auth method configured for subject '{key}' — \
                     add it to the auth map in plugin config"
                ),
            ))
        })
    }

    /// Fetch a credential from Vault: login, then KV read.
    async fn fetch_from_vault(
        &self,
        subject: &DelegationSubject,
        payload: &DelegationPayload,
        ext: &Extensions,
        resolved_path: &str,
    ) -> Result<Mint, PluginViolation> {
        let auth_method = self.auth_for(subject).map_err(|e| *e)?;

        // Login to Vault with the principal's token
        let vault_token = match auth_method {
            VaultAuthMethod::Jwt { mount, role } => {
                let jwt = identity::resolve_auth_token(subject, payload).map_err(|e| *e)?;
                vault::jwt_login(ext, &self.typed.vault_addr, mount, role, jwt, self.timeout)
                    .await?
            },
            VaultAuthMethod::AppRole { mount, .. } => {
                let key = subject_config_key(subject);
                let creds = self.approle_creds.get(key).ok_or_else(|| {
                    PluginViolation::new(
                        "delegation.vault_auth_failed",
                        format!("AppRole credentials not resolved for subject '{key}'"),
                    )
                })?;
                vault::approle_login(
                    ext,
                    &self.typed.vault_addr,
                    mount,
                    &creds.role_id,
                    &creds.secret_id,
                    self.timeout,
                )
                .await?
            },
        };

        // Read the KV secret (vault_token is zeroized when dropped)
        let kv_result = vault::kv_read(
            ext,
            &self.typed.vault_addr,
            &self.typed.kv_mount,
            resolved_path,
            &vault_token.client_token,
            self.timeout,
        )
        .await?;

        // Extract the configured field
        let secret_value = kv_result
            .data
            .get(&self.typed.secret_field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PluginViolation::new(
                    "delegation.vault_field_missing",
                    format!(
                        "secret at the resolved path does not contain field '{}'",
                        self.typed.secret_field
                    ),
                )
            })?;

        let token_value = secret_value.to_owned();

        let expires_at = Utc::now() + self.ttl;
        let token = RawDelegatedToken::new(
            token_value,
            &self.typed.outbound_header,
            payload.target_audience().unwrap_or(""),
            Vec::new(),
            expires_at,
        );

        Ok(Mint {
            token,
            secret_version: kv_result.version,
        })
    }
}

#[async_trait]
impl Plugin for VaultDelegator {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<TokenDelegateHook> for VaultDelegator {
    async fn handle(
        &self,
        payload: &DelegationPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<DelegationPayload> {
        let subject = payload.subject();

        // Validate auth is configured for this subject
        if let Err(v) = self.auth_for(subject) {
            return PluginResult::deny(*v);
        }

        // Resolve identity claim for path templating — skip when the
        // path has no placeholder (e.g. `shared/api-key` with
        // `this_workload`), since no identity value is needed.
        let resolved_path = if identity::path_has_placeholder(
            &self.typed.secret_path_template,
            &self.typed.identity_claim,
        ) {
            let identity_value = match identity::resolve_identity(subject, ext, &self.typed) {
                Ok(id) => id,
                Err(v) => return PluginResult::deny(*v),
            };
            if let Err(v) = identity::validate_identity_value(&identity_value) {
                return PluginResult::deny(*v);
            }
            identity::resolve_path(
                &self.typed.secret_path_template,
                &self.typed.identity_claim,
                &identity_value,
            )
        } else {
            self.typed.secret_path_template.clone()
        };

        if payload.actor_role().is_some() {
            return PluginResult::deny(PluginViolation::new(
                "delegation.actor_unsupported",
                "delegator/vault resolves static credentials — \
                 actors cannot be recorded in a pre-stored secret",
            ));
        }

        if payload.route_attenuation().is_some() {
            return PluginResult::deny(PluginViolation::new(
                "delegation.attenuation_unsupported",
                "delegator/vault resolves static credentials — \
                 route attenuation cannot be honored",
            ));
        }

        if !payload.required_permissions().is_empty() {
            return PluginResult::deny(PluginViolation::new(
                "delegation.permissions_unsupported",
                "delegator/vault resolves static credentials — \
                 required_permissions cannot be enforced",
            ));
        }

        // Resolve credential — cached or fresh.
        //
        // When caching, the key includes a SHA-256 prefix of the
        // bearer token so a different JWT with the same subject claim
        // cannot reuse another caller's cached credential. For
        // `this_workload` (AppRole, no inbound token) the credential
        // component is empty — safe because AppRole auth is this
        // instance's own identity and never varies per caller.
        let served = if let Some(ref cache) = self.cache {
            let audience = payload.target_audience().unwrap_or("");
            let credential = payload.bearer_token();
            if subject.inbound_role().is_some() && credential.is_empty() {
                return PluginResult::deny(PluginViolation::new(
                    "delegation.bad_request",
                    "bearer token is required for cache lookup — \
                     cannot delegate without an authenticated credential",
                ));
            }
            let key = CredentialCache::cache_key(subject, &resolved_path, audience, credential);
            match cache
                .get_or_mint(
                    key,
                    self.fetch_from_vault(subject, payload, ext, &resolved_path),
                )
                .await
            {
                Ok(served) => served,
                Err(violation) => return PluginResult::deny((*violation).clone()),
            }
        } else {
            match self
                .fetch_from_vault(subject, payload, ext, &resolved_path)
                .await
            {
                Ok(mint) => Served {
                    mint,
                    source: Source::Mint,
                    minted_at: Utc::now(),
                },
                Err(violation) => return PluginResult::deny(violation),
            }
        };

        // Build updated payload
        let mut updated = payload.clone();
        updated.delegated_token = Some(served.mint.token);
        updated.delegation_mode = Some(payload.subject().default_mode());
        updated.minted_at = Some(served.minted_at);
        updated.metadata.insert(
            "secret_source".into(),
            serde_json::Value::String("vault".into()),
        );
        updated.metadata.insert(
            "delegated_token_source".into(),
            serde_json::Value::String(
                match served.source {
                    Source::Cache => "cache",
                    Source::Mint => "mint",
                }
                .to_owned(),
            ),
        );
        updated.metadata.insert(
            "vault_secret_version".into(),
            serde_json::json!(served.mint.secret_version),
        );

        PluginResult::modify_payload(updated)
    }
}

fn subject_config_key(subject: &DelegationSubject) -> &'static str {
    match subject {
        DelegationSubject::User => "user",
        DelegationSubject::Client => "client",
        DelegationSubject::CallerWorkload => "caller_workload",
        DelegationSubject::ThisWorkload => "this_workload",
        _ => "unknown",
    }
}

fn resolve_approle_creds(
    typed: &VaultDelegatorConfig,
) -> Result<HashMap<String, ResolvedAppRole>, Box<PluginError>> {
    let mut creds = HashMap::new();
    for (key, auth) in &typed.auth {
        if let VaultAuthMethod::AppRole {
            role_id_source,
            secret_id_source,
            ..
        } = auth
        {
            let role_id = role_id_source.resolve().map_err(|e| PluginError::Config {
                message: format!("AppRole role_id for '{key}': {e}"),
            })?;
            let secret_id = secret_id_source
                .resolve()
                .map_err(|e| PluginError::Config {
                    message: format!("AppRole secret_id for '{key}': {e}"),
                })?;
            creds.insert(
                key.clone(),
                ResolvedAppRole {
                    role_id: Zeroizing::new(role_id),
                    secret_id: Zeroizing::new(secret_id),
                },
            );
        }
    }
    Ok(creds)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::assertions_on_result_states,
    clippy::indexing_slicing,
    reason = "tests"
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_config() -> PluginConfig {
        PluginConfig {
            name: "vault-test".into(),
            kind: "test".into(),
            config: Some(json!({
                "vault_addr": "https://vault.test:8200",
                "secret_path_template": "agents/{{sub}}/github",
                "auth": {
                    "user": {
                        "method": "jwt",
                        "role": "ppe-user"
                    }
                }
            })),
            ..Default::default()
        }
    }

    #[test]
    fn constructs_with_valid_config() {
        let d = VaultDelegator::new(base_config());
        assert!(d.is_ok());
    }

    #[test]
    fn rejects_missing_config_block() {
        let cfg = PluginConfig {
            name: "test".into(),
            kind: "test".into(),
            config: None,
            ..Default::default()
        };
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(err.to_string().contains("config:"));
    }

    #[test]
    fn rejects_empty_vault_addr() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["vault_addr"] = json!("");
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(err.to_string().contains("vault_addr"));
    }

    #[test]
    fn rejects_http_without_opt_in() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["vault_addr"] = json!("http://vault.test:8200");
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn allows_http_with_insecure_opt_in() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["vault_addr"] = json!("http://vault.test:8200");
        cfg.config.as_mut().unwrap()["insecure_http"] = json!(true);
        assert!(VaultDelegator::new(cfg).is_ok());
    }

    #[test]
    fn rejects_empty_auth_map() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["auth"] = json!({});
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(err.to_string().contains("auth map must not be empty"));
    }

    #[test]
    fn rejects_unknown_auth_subject() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["auth"] = json!({
            "invalid_subject": { "method": "jwt", "role": "r" }
        });
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(err.to_string().contains("unknown auth subject"));
    }

    #[test]
    fn rejects_alias_auth_subject() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["auth"] = json!({
            "gateway": { "method": "approle",
                "role_id_source": { "kind": "literal", "secret": "r" },
                "secret_id_source": { "kind": "literal", "secret": "s" } }
        });
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(
            err.to_string().contains("unknown auth subject"),
            "alias 'gateway' should be rejected: {err}"
        );
    }

    #[test]
    fn rejects_this_workload_with_jwt() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["auth"]["this_workload"] = json!({
            "method": "jwt", "role": "bad"
        });
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(
            err.to_string().contains("this_workload must use approle"),
            "expected method mismatch error: {err}"
        );
    }

    #[test]
    fn rejects_user_with_approle() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["auth"] = json!({
            "user": {
                "method": "approle",
                "role_id_source": { "kind": "literal", "secret": "r" },
                "secret_id_source": { "kind": "literal", "secret": "s" }
            }
        });
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(
            err.to_string().contains("must use jwt"),
            "expected method mismatch error: {err}"
        );
    }

    #[test]
    fn debug_redacts_approle_values() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["auth"]["this_workload"] = json!({
            "method": "approle",
            "role_id_source": { "kind": "literal", "secret": "SENSITIVE_ROLE_ID" },
            "secret_id_source": { "kind": "literal", "secret": "SENSITIVE_SECRET_ID" },
        });
        let d = VaultDelegator::new(cfg).unwrap();
        let debug = format!("{d:?}");
        assert!(!debug.contains("SENSITIVE_ROLE_ID"));
        assert!(!debug.contains("SENSITIVE_SECRET_ID"));
        assert!(debug.contains("approle_subjects"));
    }

    #[test]
    fn accepts_https_case_insensitive() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["vault_addr"] = json!("HTTPS://vault.test:8200");
        assert!(VaultDelegator::new(cfg).is_ok());
    }

    #[test]
    fn trims_vault_addr_whitespace() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["vault_addr"] = json!("  https://vault.test:8200  ");
        assert!(VaultDelegator::new(cfg).is_ok());
    }

    #[test]
    fn rejects_jwt_subject_without_template_placeholder() {
        let cfg = PluginConfig {
            name: "vault-test".into(),
            kind: "test".into(),
            config: Some(json!({
                "vault_addr": "https://vault.test:8200",
                "secret_path_template": "shared/api-key",
                "auth": {
                    "user": { "method": "jwt", "role": "r" }
                }
            })),
            ..Default::default()
        };
        let err = VaultDelegator::new(cfg).unwrap_err();
        assert!(
            err.to_string().contains("secret_path_template"),
            "expected placeholder error: {err}"
        );
    }

    #[test]
    fn allows_this_workload_only_with_fixed_path() {
        let cfg = PluginConfig {
            name: "vault-test".into(),
            kind: "test".into(),
            config: Some(json!({
                "vault_addr": "https://vault.test:8200",
                "secret_path_template": "shared/api-key",
                "auth": {
                    "this_workload": {
                        "method": "approle",
                        "role_id_source": { "kind": "literal", "secret": "r" },
                        "secret_id_source": { "kind": "literal", "secret": "s" }
                    }
                }
            })),
            ..Default::default()
        };
        assert!(VaultDelegator::new(cfg).is_ok());
    }

    #[test]
    fn literal_secrets_redacted_in_stored_config() {
        let mut cfg = base_config();
        cfg.config.as_mut().unwrap()["auth"]["this_workload"] = json!({
            "method": "approle",
            "role_id_source": { "kind": "literal", "secret": "SENSITIVE" },
            "secret_id_source": { "kind": "literal", "secret": "ALSO_SENSITIVE" },
        });
        let d = VaultDelegator::new(cfg).unwrap();
        let config_debug = format!("{:?}", d.typed);
        assert!(!config_debug.contains("SENSITIVE"));
        assert!(!config_debug.contains("ALSO_SENSITIVE"));
    }
}
