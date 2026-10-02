// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Fixtures the cases share: a built resolver, a request carrying headers, and a
//! scripted endpoint that answers the auth sub-request.

use std::collections::HashMap;
use std::sync::Arc;

use praxis_policy_builtins::plugins::identity_forward_auth::{ForwardAuthResolver, KIND};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, PluginResult};
use praxis_policy_core::host::HttpTransportSlot;
use praxis_policy_core::http::HeaderMap;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::identity::{IdentityHook, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;

/// The endpoint the default config points at; `FakeTransport` matches on the
/// path fragment.
pub const ENDPOINT: &str = "http://127.0.0.1:4180/oauth2/auth";

/// The fragment a rule matches against.
pub const FRAGMENT: &str = "/oauth2/auth";

/// Build a resolver from a `config:` block.
pub fn resolver(block: serde_json::Value) -> Result<ForwardAuthResolver, String> {
    let config = PluginConfig {
        name: "dashboard-session".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        config: Some(block),
        ..Default::default()
    };
    ForwardAuthResolver::new(config).map_err(|e| e.to_string())
}

/// The usual config: the default endpoint, a subject anchored on the user
/// header, groups onto teams, and email kept in the claims bag.
pub fn config() -> serde_json::Value {
    serde_json::json!({
        "endpoint": ENDPOINT,
        "claim_map": {
            "subject": {
                "id": "x-auth-request-user",
                "teams": "x-auth-request-groups",
            },
        },
        "claims": { "include": ["x-auth-request-email"] },
    })
}

/// A response with the given status and identity headers, each `(name, value)`
/// appended so a repeated name becomes multiple values.
pub fn response(status: u16, headers: &[(&'static str, &str)]) -> Arc<FakeTransport> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(*name, value.parse().expect("a legal header value"));
    }
    Arc::new(FakeTransport::new().respond(FRAGMENT, status, "", map))
}

/// A request carrying a single `Cookie` header.
pub fn with_cookie(cookie: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("cookie".to_owned(), cookie.to_owned());
    headers
}

/// Run the resolver against `headers`, with `transport` installed as the host's
/// egress.
pub async fn resolve(
    resolver: &ForwardAuthResolver,
    headers: HashMap<String, String>,
    transport: Arc<FakeTransport>,
) -> PluginResult<IdentityPayload> {
    let payload =
        IdentityPayload::new("", TokenSource::Custom("cookie".to_owned())).with_headers(headers);
    let ext = Extensions {
        http_transport: HttpTransportSlot::installed(transport),
        ..Default::default()
    };
    let mut ctx = PluginContext::default();
    <ForwardAuthResolver as HookHandler<IdentityHook>>::handle(resolver, &payload, &ext, &mut ctx)
        .await
}

/// Run the resolver with no transport installed, which is how a deployment that
/// withheld egress reaches the handler.
pub async fn resolve_without_transport(
    resolver: &ForwardAuthResolver,
    headers: HashMap<String, String>,
) -> PluginResult<IdentityPayload> {
    let payload =
        IdentityPayload::new("", TokenSource::Custom("cookie".to_owned())).with_headers(headers);
    let ext = Extensions::default();
    let mut ctx = PluginContext::default();
    <ForwardAuthResolver as HookHandler<IdentityHook>>::handle(resolver, &payload, &ext, &mut ctx)
        .await
}

/// The denial code on a result, or `None` when it did not deny.
pub fn denial_code(result: &PluginResult<IdentityPayload>) -> Option<String> {
    result
        .violation
        .as_ref()
        .map(|violation| violation.code.clone())
}

/// The subject a result resolved, or `None` when it stayed unauthenticated.
pub fn subject_of(
    result: &PluginResult<IdentityPayload>,
) -> Option<praxis_policy_core::extensions::SubjectExtension> {
    result
        .modified_payload
        .as_ref()
        .and_then(|payload| payload.subject.clone())
}
