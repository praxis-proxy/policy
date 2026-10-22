// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Valkey-backed `CorrelationStore`. One hash per correlation, expiring
// server-side when the approval does. The resolve and redeem steps
// are Lua scripts so a check-then-write cannot race across replicas.
//
// Connection settings and validation are the session store's: a standalone
// block is a `ValkeyConfig`, and a `connection: session_store` reference is
// the global block with this store's overrides applied.
//
// Keys carry the plugin name. Memory stores are per plugin, so two approvers
// on one route never see each other's approvals; a shared keyspace must keep
// that, or one approver's id would satisfy the other's step.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;

use crate::plugins::elicitation_ciba::store::{
    Correlation, CorrelationStore, StoreError, TakeResult,
};
use crate::session::valkey::connection::Valkey;
use crate::session::valkey::{BuildError, ValkeyConfig};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const DEFAULT_KEY_PREFIX: &str = "ciba:v1";

const REFERENCE_OVERRIDES: [&str; 5] = [
    "command_timeout_ms",
    "connect_timeout_ms",
    "key_prefix",
    "password",
    "username",
];

// `ValkeyConfig` accepts extra keys for the session store. CIBA must reject
// misspelled settings instead of silently ignoring them.
const STANDALONE_KEYS: [&str; 7] = [
    "command_timeout_ms",
    "connect_timeout_ms",
    "endpoint",
    "key_prefix",
    "password",
    "tls",
    "username",
];

// A late poll must not recreate an expired or redeemed entry.
const SET_RESOLVED: &str = "
if redis.call('EXISTS', KEYS[1]) == 1 then
  redis.call('HSET', KEYS[1], 'resolved', ARGV[1])
end
return 0
";

// A mismatch or pending approval must remain available for a later request.
const TAKE_IF_READY: &str = "
local f = redis.call('HGETALL', KEYS[1])
if #f == 0 then return 0 end
local h = {}
for i = 1, #f, 2 do h[f[i]] = f[i + 1] end
if h.route ~= ARGV[1] or h.tool ~= ARGV[2] or h.requester ~= ARGV[3] then return 1 end
if not h.resolved then return 2 end
redis.call('DEL', KEYS[1])
return f
";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Why a plugin's Valkey `store` settings were refused at load.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettingsError {
    /// A standalone block names a key it does not take.
    #[error("unknown setting `{key}`; expected one of {expected}")]
    UnknownSetting {
        /// The offending key.
        key: String,
        /// The keys a standalone block takes.
        expected: String,
    },
    /// A reference sets a key that only a standalone block may set.
    #[error(
        "`{0}` cannot be set on a `connection: session_store` reference; \
         use a standalone block (no `connection`) for a different server"
    )]
    NotOverridable(String),
    /// A reference overrides one of `username` and `password` but not both.
    #[error("a reference overrides `username` and `password` together, or neither")]
    PartialCredentials,
    /// A reference has no Valkey global session store to point at.
    #[error(
        "`connection: session_store` needs `global.session_store` of kind valkey, \
         loaded with `load_config_yaml`"
    )]
    NoSessionStore,
    /// `connection` names something other than `session_store`.
    #[error("unknown connection {0}; the only one is `session_store`")]
    UnknownConnection(String),
    /// The merged settings fail the session store's validation.
    #[error(transparent)]
    Invalid(#[from] BuildError),
}

// -----------------------------------------------------------------------------
// Store
// -----------------------------------------------------------------------------

/// Correlations shared across replicas through Valkey.
pub struct ValkeyCorrelationStore {
    valkey: Valkey,
}

impl ValkeyCorrelationStore {
    /// Build a store from the plugin's settings and optional session store
    /// connection. Validation does not connect to Valkey.
    ///
    /// # Errors
    ///
    /// Returns a [`SettingsError`] when the settings are malformed, a
    /// reference has no Valkey global store or overrides `endpoint` or `tls`,
    /// or the merged settings fail the session store's validation.
    ///
    /// [`SettingsError`]: crate::plugins::elicitation_ciba::valkey_store::SettingsError
    pub fn from_settings(
        plugin: &str,
        settings: &serde_json::Map<String, serde_json::Value>,
        session_store: Option<&serde_yaml::Value>,
    ) -> Result<Self, SettingsError> {
        let block = merge(settings, session_store)?;
        let cfg = ValkeyConfig::from_value(&block)?;
        Ok(Self {
            valkey: Valkey::new(&cfg, format!("{}:{plugin}:", cfg.key_prefix))?,
        })
    }

    fn key(&self, id: &str) -> String {
        self.valkey.key(id)
    }

    async fn conn(&self) -> Result<deadpool_redis::Connection, StoreError> {
        self.valkey.conn().await.map_err(StoreError::new)
    }

    async fn timed<T>(
        &self,
        what: &str,
        fut: impl Future<Output = redis::RedisResult<T>>,
    ) -> Result<T, StoreError> {
        self.valkey.timed(what, fut).await.map_err(StoreError::new)
    }
}

#[async_trait]
impl CorrelationStore for ValkeyCorrelationStore {
    async fn put(&self, id: &str, correlation: Correlation) -> Result<(), StoreError> {
        let key = self.key(id);
        let fields = to_fields(&correlation);
        // Relative, so a Valkey clock that disagrees with ours cannot stretch
        // or shorten the approval window.
        let ttl_ms = (correlation.expires_at - Utc::now())
            .num_milliseconds()
            .max(1);
        let mut conn = self.conn().await?;
        let mut pipe = redis::pipe();
        // DEL first so a put replaces the entry, as the memory store does,
        // rather than inheriting a stale `resolved` from an earlier one.
        pipe.atomic()
            .del(&key)
            .ignore()
            .hset_multiple(&key, &fields)
            .ignore()
            .pexpire(&key, ttl_ms)
            .ignore();
        self.timed("put", pipe.query_async::<()>(&mut conn)).await
    }

    async fn get(&self, id: &str) -> Result<Option<Correlation>, StoreError> {
        let key = self.key(id);
        let mut conn = self.conn().await?;
        let fields: HashMap<String, String> = self.timed("get", conn.hgetall(&key)).await?;
        if fields.is_empty() {
            return Ok(None);
        }
        from_fields(&fields).map(Some)
    }

    async fn set_resolved_approver(&self, id: &str, approver: String) -> Result<(), StoreError> {
        let key = self.key(id);
        let mut conn = self.conn().await?;
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(SET_RESOLVED).arg(1).arg(&key).arg(approver);
        self.timed("resolve", cmd.query_async::<()>(&mut conn))
            .await
    }

    async fn take_if_ready(
        &self,
        id: &str,
        route_key: &str,
        tool: &str,
        requester: &str,
    ) -> Result<TakeResult, StoreError> {
        let key = self.key(id);
        let mut conn = self.conn().await?;
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(TAKE_IF_READY)
            .arg(1)
            .arg(&key)
            .arg(route_key)
            .arg(tool)
            .arg(requester);
        let reply: redis::Value = self.timed("take", cmd.query_async(&mut conn)).await?;
        match reply {
            redis::Value::Int(0) => Ok(TakeResult::Missing),
            redis::Value::Int(1) => Ok(TakeResult::BindingMismatch),
            redis::Value::Int(2) => Ok(TakeResult::Pending),
            other => {
                let fields: HashMap<String, String> = redis::from_redis_value(other)
                    .map_err(|e| StoreError::new(format!("undecodable take reply: {e}")))?;
                from_fields(&fields).map(TakeResult::Ready)
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn merge(
    settings: &serde_json::Map<String, serde_json::Value>,
    session_store: Option<&serde_yaml::Value>,
) -> Result<serde_yaml::Value, SettingsError> {
    let mut own = settings.clone();
    own.remove("kind");
    let reference = own.remove("connection");
    let mut block = match reference {
        None => {
            if let Some(key) = own.keys().find(|k| !STANDALONE_KEYS.contains(&k.as_str())) {
                return Err(SettingsError::UnknownSetting {
                    key: key.clone(),
                    expected: STANDALONE_KEYS.join(", "),
                });
            }
            own.clone()
        },
        Some(serde_json::Value::String(name)) if name == "session_store" => {
            if let Some(key) = own
                .keys()
                .find(|k| !REFERENCE_OVERRIDES.contains(&k.as_str()))
            {
                return Err(SettingsError::NotOverridable(key.clone()));
            }
            if own.contains_key("username") != own.contains_key("password") {
                return Err(SettingsError::PartialCredentials);
            }
            let global = session_store
                .filter(|g| g.get("kind").and_then(serde_yaml::Value::as_str) == Some("valkey"))
                .ok_or(SettingsError::NoSessionStore)?;
            let mut base: serde_json::Map<String, serde_json::Value> = serde_json::to_value(global)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .ok_or(SettingsError::NoSessionStore)?;
            base.remove("key_prefix");
            base.extend(own);
            base
        },
        Some(other) => {
            return Err(SettingsError::UnknownConnection(other.to_string()));
        },
    };
    block.remove("kind");
    block
        .entry("key_prefix")
        .or_insert_with(|| DEFAULT_KEY_PREFIX.into());
    serde_yaml::to_value(block).map_err(|e| BuildError::Config(e.to_string()).into())
}

fn to_fields(c: &Correlation) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("expected", c.expected_approver.clone()),
        ("route", c.route_key.clone()),
        ("tool", c.tool.clone()),
        ("requester", c.requester.clone()),
        ("expires_at", c.expires_at.to_rfc3339()),
    ];
    if let Some(resolved) = &c.resolved_approver {
        fields.push(("resolved", resolved.clone()));
    }
    fields
}

// A missing field means the stored approval is corrupt, not absent.
fn from_fields(f: &HashMap<String, String>) -> Result<Correlation, StoreError> {
    let field = |name: &str| {
        f.get(name)
            .cloned()
            .ok_or_else(|| StoreError::new(format!("stored correlation lacks `{name}`")))
    };
    let expires_at = DateTime::parse_from_rfc3339(&field("expires_at")?)
        .map_err(|e| StoreError::new(format!("stored expiry: {e}")))?
        .with_timezone(&Utc);
    Ok(Correlation {
        expected_approver: field("expected")?,
        resolved_approver: f.get("resolved").cloned(),
        route_key: field("route")?,
        tool: field("tool")?,
        requester: field("requester")?,
        expires_at,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn a_standalone_block_gets_the_ciba_prefix() {
        let block = merge(&settings(json!({ "endpoint": "localhost:6379" })), None).unwrap();
        assert_eq!(block["key_prefix"], "ciba:v1");
        assert_eq!(block["endpoint"], "localhost:6379");
    }

    #[test]
    fn a_reference_takes_the_global_connection_with_overrides() {
        let global = global(
            "kind: valkey\nendpoint: v.internal:6380\ntls: true\n\
                             username: ppe-taint\npassword: t\nkey_prefix: taint:v1\n",
        );
        let block = merge(
            &settings(json!({
                "connection": "session_store",
                "username": "ppe-ciba",
                "password": { "env": "CIBA_PW" },
            })),
            Some(&global),
        )
        .unwrap();
        assert_eq!(block["endpoint"], "v.internal:6380");
        assert_eq!(block["tls"], true);
        assert_eq!(block["username"], "ppe-ciba", "credentials are overridden");
        assert_eq!(block["password"]["env"], "CIBA_PW");
        assert_eq!(
            block["key_prefix"], "ciba:v1",
            "never the session store's prefix"
        );
        assert!(block.get("kind").is_none());
    }

    #[test]
    fn a_reference_without_overrides_keeps_the_global_user() {
        let global = global("kind: valkey\nendpoint: localhost:6379\nusername: u\npassword: p\n");
        let block = merge(
            &settings(json!({ "connection": "session_store" })),
            Some(&global),
        )
        .unwrap();
        assert_eq!(block["username"], "u");
    }

    #[test]
    fn a_reference_without_a_valkey_global_store_is_refused() {
        for global in [None, Some(global("kind: memory\n"))] {
            let err = merge(
                &settings(json!({ "connection": "session_store" })),
                global.as_ref(),
            )
            .unwrap_err();
            assert!(matches!(err, SettingsError::NoSessionStore), "got {err}");
        }
    }

    #[test]
    fn a_reference_cannot_change_the_server() {
        let global = global("kind: valkey\nendpoint: localhost:6379\n");
        for key in ["endpoint", "tls"] {
            let mut s = settings(json!({ "connection": "session_store" }));
            s.insert(key.to_owned(), json!("x"));
            let err = merge(&s, Some(&global)).unwrap_err();
            assert!(
                matches!(&err, SettingsError::NotOverridable(k) if k == key),
                "got {err}"
            );
        }
    }

    #[test]
    fn a_misspelled_standalone_setting_is_refused() {
        for key in ["pasword", "ttl_seconds"] {
            let mut s = settings(json!({ "endpoint": "localhost:6379" }));
            s.insert(key.to_owned(), json!("x"));
            let err = merge(&s, None).unwrap_err();
            assert!(
                matches!(&err, SettingsError::UnknownSetting { key: k, .. } if k == key),
                "got {err}"
            );
        }
    }

    #[test]
    fn a_reference_overrides_credentials_as_a_pair() {
        let global = global("kind: valkey\nendpoint: localhost:6379\nusername: u\npassword: p\n");
        for half in ["username", "password"] {
            let mut s = settings(json!({ "connection": "session_store" }));
            s.insert(half.to_owned(), json!("x"));
            let err = merge(&s, Some(&global)).unwrap_err();
            assert!(
                matches!(err, SettingsError::PartialCredentials),
                "{half}: {err}"
            );
        }
    }

    #[test]
    fn an_unknown_connection_name_is_refused() {
        let err = merge(&settings(json!({ "connection": "other" })), None).unwrap_err();
        assert!(
            matches!(err, SettingsError::UnknownConnection(_)),
            "got {err}"
        );
    }

    #[test]
    fn merged_settings_are_validated_like_the_session_store() {
        let global = global("kind: valkey\nendpoint: redis://localhost:6379\n");
        let err = ValkeyCorrelationStore::from_settings(
            "p",
            &settings(json!({
                "connection": "session_store",
                "username": "ppe-ciba",
                "password": "p",
            })),
            Some(&global),
        )
        .err()
        .expect("a URL endpoint cannot also take separate credentials");
        assert!(
            matches!(err, SettingsError::Invalid(BuildError::Config(_))),
            "got {err}"
        );
    }

    #[test]
    fn a_standalone_remote_endpoint_without_tls_is_refused() {
        let err = ValkeyCorrelationStore::from_settings(
            "p",
            &settings(json!({ "endpoint": "valkey.prod.internal:6379" })),
            None,
        )
        .err()
        .expect("TLS is required off localhost");
        assert!(
            matches!(err, SettingsError::Invalid(BuildError::TlsRequired(_))),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn keys_are_scoped_to_the_plugin_instance() {
        let s = settings(json!({ "endpoint": "localhost:6379" }));
        let manager = ValkeyCorrelationStore::from_settings("manager", &s, None).unwrap();
        let security = ValkeyCorrelationStore::from_settings("security", &s, None).unwrap();
        assert!(manager.key("id").starts_with("ciba:v1:manager:"));
        assert_ne!(
            manager.key("id"),
            security.key("id"),
            "one approver's id must not address another's correlation"
        );
    }

    #[test]
    fn fields_round_trip_and_carry_no_token() {
        let c = Correlation {
            expected_approver: "alice".into(),
            resolved_approver: Some("alice".into()),
            route_key: "tool:adjust@sandbox".into(),
            tool: "adjust".into(),
            requester: "bob".into(),
            expires_at: Utc::now(),
        };
        let fields: HashMap<String, String> = to_fields(&c)
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        assert!(!fields.keys().any(|k| k.contains("token")));
        let back = from_fields(&fields).unwrap();
        assert_eq!(back.resolved_approver.as_deref(), Some("alice"));
        assert_eq!(
            back.expires_at.timestamp_millis(),
            c.expires_at.timestamp_millis()
        );
    }

    #[test]
    fn a_hash_missing_a_field_is_an_error_not_a_miss() {
        let fields = HashMap::from([("expected".to_owned(), "alice".to_owned())]);
        let err = from_fields(&fields).unwrap_err();
        assert!(err.message().contains("lacks"), "got {err}");
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn settings(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().cloned().unwrap()
    }

    fn global(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }
}
