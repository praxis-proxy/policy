// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Fixtures the plugin's test modules share.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use praxis_policy_core::extensions::raw_credentials::{
    Credential, RawCredentialsExtension, RawInboundToken, TokenKind,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::host::HttpTransportSlot;
use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::plugin::PluginConfig;
use praxis_policy_core::revocation::IdentitySlot;
use serde_json::json;

use crate::plugins::oauth_introspection::{IntrospectionPlugin, KIND};

/// The issuer the fixture plugin is configured for.
pub(crate) const ISSUER: &str = "https://idp.example/realms/demo";

/// A plugin for [`ISSUER`] with client `ppe` and secret `s3cret`, with
/// `overrides` laid over that config.
#[expect(clippy::expect_used, reason = "tests")]
pub(crate) fn plugin(overrides: serde_json::Value) -> IntrospectionPlugin {
    let mut config = json!({
        "issuer": ISSUER,
        "introspection_endpoint": "https://idp.example/introspect",
        "client_id": "ppe",
        "client_secret_source": { "kind": "literal", "secret": "s3cret" },
    });
    for (key, value) in overrides.as_object().into_iter().flatten() {
        if let Some(config) = config.as_object_mut() {
            config.insert(key.clone(), value.clone());
        }
    }
    IntrospectionPlugin::new(PluginConfig {
        name: "introspect".into(),
        kind: KIND.into(),
        config: Some(config),
        ..Default::default()
    })
    .expect("the fixture config builds")
}

/// An unsigned JWT naming `iss`.
pub(crate) fn jwt(iss: &str) -> String {
    let encode = |value: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    format!(
        "{}.{}.signature",
        encode(json!({ "alg": "RS256" })),
        encode(json!({ "iss": iss, "sub": "alice" }))
    )
}

/// Extensions carrying `transport` and one raw inbound token per slot.
pub(crate) fn ext(transport: &Arc<FakeTransport>, tokens: &[(IdentitySlot, String)]) -> Extensions {
    let http: Arc<dyn HttpTransport> = transport.clone();
    let inbound_tokens: HashMap<_, _> = tokens
        .iter()
        .map(|(slot, token)| {
            (
                slot.token_role(),
                RawInboundToken::new(
                    token.clone(),
                    Credential::Header {
                        name: "authorization".into(),
                    },
                    TokenKind::Jwt,
                ),
            )
        })
        .collect();
    Extensions {
        http_transport: HttpTransportSlot::installed(http),
        raw_credentials: Some(Arc::new(RawCredentialsExtension {
            inbound_tokens,
            ..Default::default()
        })),
        ..Default::default()
    }
}
