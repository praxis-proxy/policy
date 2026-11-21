// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities the cases share: a reviewer token on disk, scripted API
//! server answers, a built resolver, and a request carrying a token.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use praxis_policy_builtins::plugins::identity_kubernetes::{KIND, TokenReviewIdentityResolver};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::host::HttpTransportSlot;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::identity::{IdentityHook, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;

/// The API server base URL every case uses.
pub const API_SERVER: &str = "https://kube-api.example:6443";

/// The fragment the review endpoint matches on.
pub const REVIEW_PATH: &str = "/apis/authentication.k8s.io/v1/tokenreviews";

/// PPE's own token, as the reviewer token file holds it.
pub const REVIEWER: &str = "reviewer-sa-token";

// The fixtures are answers from a Kubernetes v1.35.0 API server (kind),
// captured 2026-11-20, with the echoed `spec.token` redacted.

/// A projected `ServiceAccount` token reviewed for the audience it was minted for.
pub const AUTHENTICATED: &str = include_str!("fixtures/gateway-token-gateway-aud.json");

/// A legacy Secret-based token reviewed after its Secret was deleted.
pub const UNAUTHENTICATED: &str = include_str!("fixtures/legacy-token-secret-deleted.json");

/// A legacy Secret-based token reviewed for the API server's own audience.
pub const LEGACY: &str = include_str!("fixtures/legacy-token-no-aud.json");

/// A legacy Secret-based token reviewed for a custom audience.
pub const LEGACY_CUSTOM_AUDIENCE: &str = include_str!("fixtures/legacy-token-gateway-aud.json");

/// A token no authenticator recognises.
pub const GARBAGE: &str = include_str!("fixtures/garbage-token.json");

/// The API server refusing a reviewer that lacks `create` on `tokenreviews`.
pub const FORBIDDEN: &str = include_str!("fixtures/reviewer-without-rbac.json");

/// A reviewer token written to a temporary path, removed when the guard drops.
pub struct TokenFile {
    path: std::path::PathBuf,
}

impl TokenFile {
    /// Write `contents` to a uniquely named file.
    pub fn write(contents: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("ppe-k8s-token-{}-{n}", std::process::id()));
        std::fs::write(&path, contents).expect("the token file is writable");
        Self { path }
    }

    /// The path, as `reviewer_token.path` wants it.
    pub fn path(&self) -> &str {
        self.path.to_str().expect("the temp path is utf-8")
    }

    /// Replace the contents the way the kubelet does, by renaming over it.
    pub fn rotate(&self, contents: &str) {
        let staging = self.path.with_extension("staging");
        std::fs::write(&staging, contents).expect("the token file is writable");
        std::fs::rename(&staging, &self.path).expect("the rename lands");
    }
}

impl Drop for TokenFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A config block reviewing against [`API_SERVER`] with the reviewer token at
/// `token_path`, mapping `username` and `groups` onto the subject.
pub fn config(token_path: &str) -> serde_json::Value {
    serde_json::json!({
        "credential": { "kind": "header", "name": "Authorization" },
        "prefix": "Bearer ",
        "api_server": {
            "url": API_SERVER,
            "reviewer_token": { "kind": "file", "path": token_path },
        },
        "audiences": ["praxis-gateway"],
        "record_map": { "subject": { "id": "username", "roles": "groups" } },
    })
}

/// Build a resolver from a `config:` block, granted `perform_http`.
pub fn resolver(block: serde_json::Value) -> Result<TokenReviewIdentityResolver, String> {
    resolver_with(block, &["perform_http"])
}

/// Build a resolver from a `config:` block with exactly `capabilities`.
pub fn resolver_with(
    block: serde_json::Value,
    capabilities: &[&str],
) -> Result<TokenReviewIdentityResolver, String> {
    let config = PluginConfig {
        name: "k8s-identity".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        config: Some(block),
        capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
        ..Default::default()
    };
    TokenReviewIdentityResolver::new(config).map_err(|e| e.to_string())
}

/// A transport answering every review with `status` and `body`.
pub fn api_server(status: u16, body: &str) -> Arc<FakeTransport> {
    Arc::new(FakeTransport::new().json(REVIEW_PATH, status, body))
}

/// Run the resolver against a request carrying `Bearer <token>`, with the
/// API server reached through `transport`.
pub async fn resolve(
    resolver: &TokenReviewIdentityResolver,
    token: &str,
    transport: Arc<FakeTransport>,
) -> PluginResult<IdentityPayload> {
    let mut headers = HashMap::new();
    headers.insert("authorization".to_owned(), format!("Bearer {token}"));
    let payload = IdentityPayload::new("", TokenSource::ApiKey).with_headers(headers);
    let ext = Extensions {
        http_transport: HttpTransportSlot::installed(transport),
        ..Default::default()
    };
    let mut ctx = PluginContext::default();
    <TokenReviewIdentityResolver as HookHandler<IdentityHook>>::handle(
        resolver, &payload, &ext, &mut ctx,
    )
    .await
}

/// The denial code on a result, or `None` when it allowed.
pub fn denial_code(result: &PluginResult<IdentityPayload>) -> Option<String> {
    result
        .violation
        .as_ref()
        .map(|violation| violation.code.clone())
}

/// An unsigned JWT whose payload carries `exp`. Signature is never checked
/// here: the API server is the verifier.
pub fn jwt_expiring_at(exp: i64) -> String {
    let encode = |value: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    format!(
        "{}.{}.signature",
        encode(serde_json::json!({"alg": "RS256"})),
        encode(serde_json::json!({"exp": exp, "sub": "system:serviceaccount:team-a:agent-bot"}))
    )
}
