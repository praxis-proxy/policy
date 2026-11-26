// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `oidc_discovery` examples in the user docs, loaded into a real
// `identity/jwt` plugin. The docs-examples suite only parses the policy
// document, where plugin config is opaque, so a typo inside `decoding_key`
// would pass it. Here every YAML block that names `oidc_discovery` goes
// through the plugin factory, which refuses unknown kinds and fields.

use std::sync::Arc;

use praxis_policy_builtins::plugins::identity_jwt::{JwtIdentityFactory, KIND};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::http::HttpTransport;
use praxis_policy_core::http_testing::FakeTransport;
use serde_json::json;

/// The pages that document `oidc_discovery`, relative to `docs/content`, and
/// how many of their YAML examples use it. The count catches an example whose
/// `kind` was mistyped, which a search for `oidc_discovery` would skip over.
const PAGES: [(&str, usize); 3] = [
    ("apl/identity.md", 1),
    ("reference/builtins.md", 3),
    ("reference/configuration.md", 1),
];

#[test]
fn every_documented_oidc_discovery_example_builds() {
    for (page, examples) in PAGES {
        let path = format!("{}/../../docs/content/{page}", env!("CARGO_MANIFEST_DIR"));
        let doc = std::fs::read_to_string(&path).expect("the docs page is readable");
        let blocks: Vec<&str> = doc
            .split("```yaml\n")
            .skip(1)
            .filter_map(|rest| rest.split("```").next())
            .filter(|block| block.contains("kind: oidc_discovery"))
            .collect();
        assert_eq!(blocks.len(), examples, "{page}: oidc_discovery examples");

        for block in blocks {
            let http = Arc::new(FakeTransport::new());
            let engine = Arc::new(PolicyEngine::default());
            engine.register_factory(KIND, Box::new(JwtIdentityFactory));
            let transport: Arc<dyn HttpTransport> = http.clone();
            engine.set_http_transport(transport);

            engine
                .load_config_yaml(&plugins_only(block))
                .unwrap_or_else(|e| panic!("{page}: the example builds: {e}\n{block}"));

            assert_eq!(http.call_count(), 0, "{page}: loading fetches nothing");
        }
    }
}

/// A policy holding only the plugins of `block`, fired at their own hooks. A
/// `trusted_issuers:` or `decoding_key:` fragment becomes the smallest
/// `identity/jwt` plugin that holds it. The rest of a full document is the
/// docs-examples suite's to check.
fn plugins_only(block: &str) -> String {
    let example: serde_yaml::Value = serde_yaml::from_str(block).expect("the example is YAML");
    let example = serde_json::to_value(example).expect("the example converts");
    let plugins = if let Some(plugins) = example.get("plugins") {
        plugins.clone()
    } else {
        let config = if let Some(decoding_key) = example.get("decoding_key") {
            json!({ "trusted_issuers": [{
                "issuer": "https://idp.example.com/realms/agents",
                "audiences": ["ppe-gateway"],
                "decoding_key": decoding_key,
            }] })
        } else {
            example
        };
        json!([{
            "name": "jwt-user",
            "kind": KIND,
            "hooks": ["identity.resolve"],
            "capabilities": ["read_headers", "perform_http"],
            "config": config,
        }])
    };
    // JSON is a subset of YAML.
    json!({ "engine_settings": { "dispatch": "hooks" }, "plugins": plugins }).to_string()
}
