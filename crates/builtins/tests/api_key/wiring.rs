// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What a host gets when it registers this plugin.
//!
//! The factory is the only path a real deployment takes, and it is the one a
//! unit test of the resolver skips.

use praxis_policy_builtins::plugins::identity_api_key::{ApiKeyIdentityFactory, KIND};
use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::PluginFactory as _;
use praxis_policy_core::identity::HOOK_IDENTITY_RESOLVE;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use crate::support::{RecordFile, file_config, hash};

fn plugin_config(block: serde_json::Value) -> PluginConfig {
    PluginConfig {
        name: "api-keys".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.to_owned()],
        config: Some(block),
        ..Default::default()
    }
}

/// The hook name is fixed in code rather than read from `config.hooks`, so this
/// pins the registration point an operator's `hooks:` list has to match.
#[test]
fn the_factory_registers_one_handler_on_the_identity_resolve_hook() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));

    let instance = ApiKeyIdentityFactory
        .create(&plugin_config(file_config(file.path(), None)))
        .expect("a valid config must build through the factory");

    assert_eq!(instance.handlers.len(), 1, "one resolver, one handler");
    assert_eq!(
        instance.handlers[0].0, HOOK_IDENTITY_RESOLVE,
        "the resolver must land on the identity.resolve hook"
    );
}

/// A config fault fails the factory rather than the first request. The
/// alternative is a registered resolver that denies everything, which reads as
/// an outage rather than as the configuration mistake it is.
#[test]
fn a_config_fault_fails_the_factory_rather_than_the_first_request() {
    let file = RecordFile::write("keys: []\n");

    let mut no_such_file = file_config("/nonexistent/keys.yaml", None);
    no_such_file["record_map"] = serde_json::json!({ "subject": { "id": "user" } });

    let mut bad_role = file_config(file.path(), None);
    bad_role["role"] = serde_json::Value::String("client".to_owned());

    let mut bad_url = file_config(file.path(), None);
    bad_url["provider"] = serde_json::json!({ "kind": "http", "url": "not-a-url" });

    for faulty in [
        serde_json::json!({}),
        no_such_file,
        bad_role,
        bad_url,
        // An unknown key in a backend block, which `deny_unknown_fields`
        // catches only because the variant is its own struct.
        serde_json::json!({
            "credential": { "kind": "header", "name": "Authorization" },
            "provider": { "kind": "file", "path": "/tmp/x", "timeout_secs": 5 },
        }),
    ] {
        // `.err()`: `PluginInstance` is not `Debug`.
        let error = ApiKeyIdentityFactory
            .create(&plugin_config(faulty.clone()))
            .err()
            .unwrap_or_else(|| panic!("{faulty} must not build"));
        assert!(
            matches!(*error, PluginError::Config { .. }),
            "{faulty}: expected a config error, got {error:?}"
        );
    }
}

/// Authentication decisions must not run in a mode that suppresses denials,
/// or with an error policy that turns a failed resolver into an allow.
#[test]
fn a_non_blocking_mode_or_ignored_error_fails_at_config_load() {
    let file = RecordFile::write("keys: []\n");
    let block = file_config(file.path(), None);
    for (mode, on_error) in [
        (PluginMode::Transform, OnError::Fail),
        (PluginMode::Sequential, OnError::Ignore),
    ] {
        let mut config = plugin_config(block.clone());
        config.mode = mode;
        config.on_error = on_error;
        let error = ApiKeyIdentityFactory
            .create(&config)
            .err()
            .expect("unsafe execution settings must fail at load");
        assert!(matches!(*error, PluginError::Config { .. }));
    }
}
