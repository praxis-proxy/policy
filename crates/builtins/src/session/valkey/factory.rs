// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `ValkeySessionStoreFactory` — the `SessionStoreFactory` that lets the
// praxis-policy-apl-runtime visitor build a `ValkeySessionStore` from a
// `global.session_store: { kind: valkey, ... }` block. Mirrors the
// PDP factories (CelPdpFactory, CedarDirectPdpFactory).

use std::sync::Arc;

use praxis_policy_apl_runtime::{SessionStore, SessionStoreFactory};

use crate::session::valkey::config::ValkeyConfig;
use crate::session::valkey::store::ValkeySessionStore;

/// The `kind:` discriminator this factory builds. Part of the public
/// surface — it is the string operators write in their config.
pub const KIND: &str = "valkey";

/// Factory the host registers via `AplOptions.session_store_factories`.
#[derive(Default)]
pub struct ValkeySessionStoreFactory;

impl ValkeySessionStoreFactory {
    /// A new instance with nothing registered or stored yet.
    pub fn new() -> Self {
        Self
    }
}

impl SessionStoreFactory for ValkeySessionStoreFactory {
    fn kind(&self) -> &str {
        KIND
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn SessionStore>, Box<dyn std::error::Error + Send + Sync>> {
        let cfg = ValkeyConfig::from_value(config)?;
        let store = ValkeySessionStore::from_config(&cfg)?;
        Ok(Arc::new(store))
    }
}
