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
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;

use crate::plugins::elicitation_ciba::store::{
    Correlation, CorrelationStore, PollClaim, StoreError, TakeResult,
};
use crate::session::valkey::connection::Valkey;
use crate::session::valkey::{BuildError, ValkeyConfig};
use praxis_policy_core::factory::SessionStoreConnection;

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

// Redis TIME keeps claim leases consistent when the gateways' clocks differ.
// An expired owner is uncertain: the OP may have spent the single-use id.
const CLAIM_POLL: &str = "
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('HGET', KEYS[1], 'route') ~= ARGV[3] or
   redis.call('HGET', KEYS[1], 'tool') ~= ARGV[4] or
   redis.call('HGET', KEYS[1], 'requester') ~= ARGV[5] then return 5 end
if redis.call('HEXISTS', KEYS[1], 'resolved') == 1 then return 2 end
if redis.call('HGET', KEYS[1], 'poll_unknown') == '1' then return 3 end
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local current = redis.call('HGET', KEYS[1], 'poll_owner')
if current then
  local deadline = tonumber(redis.call('HGET', KEYS[1], 'poll_deadline')) or 0
  if now >= deadline then
    redis.call('HSET', KEYS[1], 'poll_unknown', '1')
    redis.call('HDEL', KEYS[1], 'poll_owner', 'poll_deadline')
    return 3
  end
  return 1
end
redis.call('HSET', KEYS[1], 'poll_owner', ARGV[1], 'poll_deadline', now + tonumber(ARGV[2]))
return 4
";

const RELEASE_POLL: &str = "
if redis.call('HGET', KEYS[1], 'poll_owner') ~= ARGV[1] then return 0 end
redis.call('HDEL', KEYS[1], 'poll_owner', 'poll_deadline')
return 1
";

const COMPLETE_POLL: &str = "
if redis.call('HGET', KEYS[1], 'poll_owner') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'resolved', ARGV[2])
redis.call('HDEL', KEYS[1], 'poll_owner', 'poll_deadline')
return 1
";

const ABANDON_POLL: &str = "
if redis.call('HGET', KEYS[1], 'poll_owner') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'poll_unknown', '1')
redis.call('HDEL', KEYS[1], 'poll_owner', 'poll_deadline')
return 1
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
    /// A reference needs its own password, separate from session taint.
    #[error(
        "a `connection: session_store` reference requires its own `password`; `username` is optional for default-user AUTH"
    )]
    MissingPassword,
    /// A full URL cannot accept separately scoped CIBA credentials.
    #[error(
        "a `connection: session_store` reference needs a bare global Valkey endpoint; move the global URL to host:port with separate credentials"
    )]
    UrlEndpoint,
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
    scripts: Scripts,
}

// `Script::new` hashes its source, so each script is hashed once per store
// rather than on every call.
struct Scripts {
    set_resolved: redis::Script,
    claim_poll: redis::Script,
    release_poll: redis::Script,
    complete_poll: redis::Script,
    abandon_poll: redis::Script,
    take_if_ready: redis::Script,
}

impl Scripts {
    fn new() -> Self {
        Self {
            set_resolved: redis::Script::new(SET_RESOLVED),
            claim_poll: redis::Script::new(CLAIM_POLL),
            release_poll: redis::Script::new(RELEASE_POLL),
            complete_poll: redis::Script::new(COMPLETE_POLL),
            abandon_poll: redis::Script::new(ABANDON_POLL),
            take_if_ready: redis::Script::new(TAKE_IF_READY),
        }
    }
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
        session_store: Option<&SessionStoreConnection>,
    ) -> Result<Self, SettingsError> {
        let block = merge(settings, session_store)?;
        let cfg = ValkeyConfig::from_value(&block)?;
        Ok(Self {
            valkey: Valkey::new(&cfg, format!("{}:{plugin}:", cfg.key_prefix))?,
            scripts: Scripts::new(),
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

    async fn run_owner_script(
        &self,
        what: &str,
        script: &redis::Script,
        id: &str,
        owner: &str,
        approver: Option<&str>,
    ) -> Result<(), StoreError> {
        let key = self.key(id);
        let mut conn = self.conn().await?;
        let mut invocation = script.key(&key);
        invocation.arg(owner);
        if let Some(approver) = approver {
            invocation.arg(approver);
        }
        let updated: i64 = self.timed(what, invocation.invoke_async(&mut conn)).await?;
        if updated == 1 {
            Ok(())
        } else {
            Err(StoreError::new("poll claim is no longer owned"))
        }
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

    async fn claim_poll(
        &self,
        id: &str,
        owner: &str,
        lease: Duration,
        route_key: &str,
        tool: &str,
        requester: &str,
    ) -> Result<PollClaim, StoreError> {
        let key = self.key(id);
        let lease_ms = i64::try_from(lease.as_millis()).map_err(|error| {
            StoreError::new(format!(
                "poll lease exceeds Valkey's integer range: {error}"
            ))
        })?;
        let mut conn = self.conn().await?;
        let mut invocation = self.scripts.claim_poll.key(&key);
        invocation
            .arg(owner)
            .arg(lease_ms)
            .arg(route_key)
            .arg(tool)
            .arg(requester);
        let result: i64 = self
            .timed("claim poll", invocation.invoke_async(&mut conn))
            .await?;
        match result {
            0 => Ok(PollClaim::Missing),
            1 => Ok(PollClaim::Busy),
            2 => Ok(PollClaim::Resolved),
            3 => Ok(PollClaim::Uncertain),
            4 => Ok(PollClaim::Acquired),
            5 => Ok(PollClaim::BindingMismatch),
            _ => Err(StoreError::new("undecodable poll claim reply")),
        }
    }

    async fn release_poll(&self, id: &str, owner: &str) -> Result<(), StoreError> {
        self.run_owner_script("release poll", &self.scripts.release_poll, id, owner, None)
            .await
    }

    async fn complete_poll(
        &self,
        id: &str,
        owner: &str,
        approver: String,
    ) -> Result<(), StoreError> {
        self.run_owner_script(
            "complete poll",
            &self.scripts.complete_poll,
            id,
            owner,
            Some(&approver),
        )
        .await
    }

    async fn abandon_poll(&self, id: &str, owner: &str) -> Result<(), StoreError> {
        self.run_owner_script("abandon poll", &self.scripts.abandon_poll, id, owner, None)
            .await
    }

    async fn set_resolved_approver(&self, id: &str, approver: String) -> Result<(), StoreError> {
        let key = self.key(id);
        let mut conn = self.conn().await?;
        self.timed(
            "resolve",
            self.scripts
                .set_resolved
                .key(&key)
                .arg(approver)
                .invoke_async::<()>(&mut conn),
        )
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
        let mut invocation = self.scripts.take_if_ready.key(&key);
        invocation.arg(route_key).arg(tool).arg(requester);
        let reply: redis::Value = self
            .timed("take", invocation.invoke_async(&mut conn))
            .await?;
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
    session_store: Option<&SessionStoreConnection>,
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
            own
        },
        Some(serde_json::Value::String(name)) if name == "session_store" => {
            if let Some(key) = own
                .keys()
                .find(|k| !REFERENCE_OVERRIDES.contains(&k.as_str()))
            {
                return Err(SettingsError::NotOverridable(key.clone()));
            }
            let global = session_store
                .filter(|g| {
                    g.settings().get("kind").and_then(serde_yaml::Value::as_str) == Some("valkey")
                })
                .ok_or(SettingsError::NoSessionStore)?;
            if global.has_url_endpoint() {
                return Err(SettingsError::UrlEndpoint);
            }
            if own.get("password").is_none_or(serde_json::Value::is_null) {
                return Err(SettingsError::MissingPassword);
            }
            let mut base: serde_json::Map<String, serde_json::Value> =
                serde_json::to_value(global.settings())
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
    fn a_reference_without_its_own_password_is_refused() {
        let global = global("kind: valkey\nendpoint: localhost:6379\nusername: u\npassword: p\n");
        let err = merge(
            &settings(json!({ "connection": "session_store" })),
            Some(&global),
        )
        .unwrap_err();
        assert!(matches!(err, SettingsError::MissingPassword));
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
    fn a_reference_uses_only_its_own_password() {
        let global = global("kind: valkey\nendpoint: localhost:6379\nusername: u\npassword: p\n");
        let block = merge(
            &settings(json!({ "connection": "session_store", "password": "ciba" })),
            Some(&global),
        )
        .unwrap();
        assert_eq!(block["password"], "ciba");
        assert!(
            block.get("username").is_none(),
            "default-user AUTH is supported"
        );
        let err = merge(
            &settings(json!({ "connection": "session_store", "username": "ciba" })),
            Some(&global),
        )
        .unwrap_err();
        assert!(matches!(err, SettingsError::MissingPassword));
        let err = merge(
            &settings(json!({ "connection": "session_store", "password": null })),
            Some(&global),
        )
        .unwrap_err();
        assert!(matches!(err, SettingsError::MissingPassword));
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
        let global = global("kind: valkey\nendpoint: redis://user:secret@localhost:6379\n");
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
        assert!(matches!(err, SettingsError::UrlEndpoint), "got {err}");
        assert!(!format!("{global:?}").contains("secret"));
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

    fn global(yaml: &str) -> SessionStoreConnection {
        let value = serde_yaml::from_str(yaml).unwrap();
        praxis_policy_core::factory::FactoryContext::with_session_store(Some(value))
            .session_store()
            .unwrap()
            .clone()
    }
}
