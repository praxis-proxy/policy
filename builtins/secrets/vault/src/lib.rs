// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Vault KV v2 backend for [`praxis_policy_core::secrets::SecretProvider`].
//!
//! Registered as provider kind [`KIND`] (`vault`). The host constructs
//! [`VaultSecretProviderFactory`] with the same
//! [`praxis_policy_core::http::HttpTransport`] it installed on the engine;
//! the factory does not dial.
//!
//! # Token renewal
//!
//! There is no spawned ticker. A task binds to whichever runtime called
//! `initialize()`, and a host that initializes on a short-lived runtime
//! has it cancelled before it ticks once — issue #29, which is why
//! `identity-jwt` refreshes from the verify path rather than a background
//! loop. Token renewal has no request path to hang off after startup:
//! nothing calls Vault until the next `refresh_secrets()`. So renewal is
//! lazy, on the next `get_secret`:
//!
//! * A renewable token is renewed when two thirds of `lease_duration`
//!   has elapsed, minus up to 10% jitter so replicas do not stampede.
//!   A failed `renew-self` falls through to a full login on that same
//!   read; the host's refresh interval is the backoff before the next
//!   attempt.
//! * A non-renewable token is obtained again on that same schedule.
//! * A `403` on a KV read triggers one reauthentication and one retry,
//!   distinct from a missing path (`404` →
//!   [`praxis_policy_core::secrets::SecretError::NotFound`]).
//!
//! A host that never calls `refresh_secrets()` keeps its startup values
//! and never talks to Vault again, which is documented behaviour rather
//! than a renewal that stopped without saying so.
//!
//! Written against the Vault **1.19** KV v2 HTTP API. CI covers that
//! contract with `FakeTransport`. This crate has no HTTP stack of its
//! own, so a live run belongs to a host that installs `HttpTransport`.

use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::secrets::SecretProviderRegistry;
use std::sync::Arc;

mod config;
mod provider;
mod reference;

pub use provider::VaultSecretProviderFactory;

/// The `kind:` this factory registers as.
pub const KIND: &str = "vault";

/// Register this backend on `registry`.
///
/// The factory captures `transport` and uses it for every Vault call.
/// Construction does not dial; the first login happens on the first
/// `get_secret`, which is `PolicyEngine::initialize()`.
///
/// In-cluster Vault (Kubernetes service DNS, RFC 1918) is refused by
/// the facade's `HyperTransport` unless the host builds it with
/// `with_allow_private_destinations`. A proxy injecting its own
/// transport already chose an egress policy.
///
/// This is not folded into `install_builtins`. The factory needs a
/// transport, so the host calls this (or [`registry_with_vault`])
/// explicitly.
pub fn register(registry: &mut SecretProviderRegistry, transport: Arc<dyn HttpTransport>) {
    registry.register(Box::new(VaultSecretProviderFactory::new(transport)));
}

/// A registry with `env`, `file`, and `vault`.
#[must_use]
pub fn registry_with_vault(transport: Arc<dyn HttpTransport>) -> SecretProviderRegistry {
    let mut registry = SecretProviderRegistry::with_builtin_backends();
    register(&mut registry, transport);
    registry
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
    use praxis_policy_core::secrets::{
        SecretProviderConfig, SecretProviderFactory as _, SecretStore, SecretsConfig,
    };

    #[test]
    fn the_kind_is_vault() {
        let factory = VaultSecretProviderFactory::new(Arc::new(FakeTransport::new()));
        assert_eq!(factory.kind(), KIND);
        assert_eq!(KIND, "vault");
    }

    #[test]
    fn register_puts_vault_among_the_builtins() {
        let registry = registry_with_vault(Arc::new(FakeTransport::new()));
        let cfg = SecretProviderConfig {
            kind: KIND.to_owned(),
            settings: serde_yaml::from_str(
                "
address: https://vault.example.com
auth:
  method: kubernetes
  role: ppe
",
            )
            .expect("settings"),
        };
        registry
            .build("vault-prod", &cfg)
            .expect("vault is registered");
    }

    #[tokio::test]
    async fn store_resolve_reads_through_vault() {
        let http = FakeTransport::new()
            .json(
                "/auth/approle/login",
                200,
                r#"{"auth":{"client_token":"hvs.token","lease_duration":3600,"renewable":true}}"#,
            )
            .json(
                "/data/app",
                200,
                r#"{"data":{"data":{"password":"hunter2"}}}"#,
            );
        let registry = registry_with_vault(Arc::new(http));
        let config: SecretsConfig = serde_yaml::from_str(
            "
providers:
  vault-prod:
    kind: vault
    address: https://vault.example.com
    allow_insecure_literal: true
    auth:
      method: approle
      role_id: role-id
      secret_id:
        literal: secret-id
values:
  session_password:
    provider: vault-prod
    ref: secret/app#password
",
        )
        .expect("config");
        let store = SecretStore::resolve(&config, &registry)
            .await
            .expect("resolve");
        assert_eq!(
            store.value("session_password").expect("bound").as_str(),
            "hunter2"
        );
    }
}
