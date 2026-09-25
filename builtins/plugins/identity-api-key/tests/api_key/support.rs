// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Fixtures the cases share: a record file on disk, a built resolver, and a
//! request carrying a credential.

use std::collections::HashMap;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::identity::{IdentityHook, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;
use praxis_policy_plugin_identity_api_key::{ApiKeyIdentityResolver, KIND};
use sha2::{Digest as _, Sha256};

/// A record file written to a temporary path, removed when the guard drops.
pub struct RecordFile {
    path: std::path::PathBuf,
}

impl RecordFile {
    /// Write `contents` to a uniquely named file.
    pub fn write(contents: &str) -> Self {
        // A counter rather than a temp-file crate: one dependency for four
        // tests is not worth it, and the name only has to be unique in-process.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ppe-api-key-{}-{n}.yaml", std::process::id()));
        std::fs::write(&path, contents).expect("the fixture file is writable");
        Self { path }
    }

    /// The path, as the `directory.path` config value wants it.
    pub fn path(&self) -> &str {
        self.path.to_str().expect("the temp path is utf-8")
    }

    /// Replace the contents, which is what a reload reads.
    ///
    /// Written to a sibling and renamed over the target, so a reader never sees
    /// a half-written file. `std::fs::write` truncates first, which leaves a
    /// window where a concurrent reload parses a prefix, and a test that raced
    /// that window would be measuring the fixture rather than the code. It is
    /// also how anything writing these records in production should do it.
    pub fn rewrite(&self, contents: &str) {
        let staging = self.path.with_extension("staging");
        std::fs::write(&staging, contents).expect("the fixture file is writable");
        std::fs::rename(&staging, &self.path).expect("the rename lands");
    }
}

impl Drop for RecordFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The digest of a credential, in the form a record file carries.
pub fn hash(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build a resolver from a `config:` block.
pub fn resolver(block: serde_json::Value) -> Result<ApiKeyIdentityResolver, String> {
    let config = PluginConfig {
        name: "api-keys".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        config: Some(block),
        ..Default::default()
    };
    ApiKeyIdentityResolver::new(config).map_err(|e| e.to_string())
}

/// A config block naming `file` at `path`, with the usual subject map.
pub fn file_config(path: &str, prefix: Option<&str>) -> serde_json::Value {
    let mut block = serde_json::json!({
        "credential": { "kind": "header", "name": "Authorization" },
        "provider": { "kind": "file", "path": path },
        "record_map": { "subject": { "id": "user", "roles": "groups" } },
    });
    if let Some(prefix) = prefix {
        block["prefix"] = serde_json::Value::String(prefix.to_owned());
    }
    block
}

/// Run the resolver against a request carrying `value` in `Authorization`.
pub async fn resolve_with_header(
    resolver: &ApiKeyIdentityResolver,
    value: &str,
) -> PluginResult<IdentityPayload> {
    let mut headers = HashMap::new();
    headers.insert("authorization".to_owned(), value.to_owned());
    resolve(resolver, headers).await
}

/// Run the resolver against a request carrying `headers`.
pub async fn resolve(
    resolver: &ApiKeyIdentityResolver,
    headers: HashMap<String, String>,
) -> PluginResult<IdentityPayload> {
    let payload = IdentityPayload::new("", TokenSource::ApiKey).with_headers(headers);
    resolve_with_payload(resolver, &payload).await
}

/// Run the resolver against a request whose `Extensions` carry `transport`,
/// which is how a backend needing egress reaches the host.
pub async fn resolve_over_http(
    resolver: &ApiKeyIdentityResolver,
    value: &str,
    transport: std::sync::Arc<praxis_policy_core::http_testing::FakeTransport>,
) -> PluginResult<IdentityPayload> {
    let mut headers = HashMap::new();
    headers.insert("authorization".to_owned(), value.to_owned());
    let payload = IdentityPayload::new("", TokenSource::ApiKey).with_headers(headers);
    let ext = Extensions {
        http_transport: praxis_policy_core::host::HttpTransportSlot::installed(transport),
        ..Default::default()
    };
    let mut ctx = PluginContext::default();
    <ApiKeyIdentityResolver as HookHandler<IdentityHook>>::handle(
        resolver, &payload, &ext, &mut ctx,
    )
    .await
}

/// Run the resolver against a payload another handler already contributed to,
/// which is how the executor threads a chain.
pub async fn resolve_with_payload(
    resolver: &ApiKeyIdentityResolver,
    payload: &IdentityPayload,
) -> PluginResult<IdentityPayload> {
    let ext = Extensions::default();
    let mut ctx = PluginContext::default();
    <ApiKeyIdentityResolver as HookHandler<IdentityHook>>::handle(resolver, payload, &ext, &mut ctx)
        .await
}

/// The denial code on a result, or `None` when it allowed.
pub fn denial_code(result: &PluginResult<IdentityPayload>) -> Option<String> {
    result
        .violation
        .as_ref()
        .map(|violation| violation.code.clone())
}
