// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Config-supplied PDP resolvers must be rebuilt on every `load_config_yaml`.
//
// The router keeps code-owned and config-owned resolvers separately. Replacing
// the config-owned set applies changed blocks while preserving the first
// code-supplied registration per dialect. Rejected duplicate registrations must
// be released rather than retained by another ownership list.
//
// A config-supplied `cel` resolver reads its verdict from `decision:`, allowing
// requests before a reload and denying them after the block changes to `deny`.

#![allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    reason = "test code"
)]

use std::sync::Arc;

use async_trait::async_trait;

use praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::{Extensions, HttpExtension, MetaExtension};
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HttpHook, HttpPayload};

use praxis_policy_apl_core::step::{PdpFactory, PdpResolver};
use praxis_policy_apl_core::{AttributeBag, Decision, PdpCall, PdpDecision, PdpDialect, PdpError};
use praxis_policy_apl_runtime::{AplOptions, register_apl};

/// A `cel`-dialect resolver whose verdict is fixed at build time from its
/// `decision:` config value. Ignores the expression — the point is that its
/// behaviour is baked in at construction, so a reload must rebuild it to change.
struct Configurable {
    allow: bool,
}

#[async_trait]
impl PdpResolver for Configurable {
    fn dialect(&self) -> PdpDialect {
        PdpDialect::Cel
    }
    async fn evaluate(
        &self,
        _call: &PdpCall,
        _bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        let decision = if self.allow {
            Decision::Allow
        } else {
            Decision::Deny {
                reason: Some("configured deny".to_owned()),
                rule_source: "test/configurable".to_owned(),
            }
        };
        Ok(PdpDecision {
            decision,
            diagnostics: vec![],
        })
    }
}

struct ConfigurableFactory;

impl PdpFactory for ConfigurableFactory {
    fn kind(&self) -> &str {
        "cel"
    }
    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn PdpResolver>, Box<dyn std::error::Error + Send + Sync>> {
        // `decision: allow | deny` in the `global.pdp[]` block; default allow
        // (anything that is not exactly `deny`).
        let allow = config
            .get(serde_yaml::Value::String("decision".to_owned()))
            .and_then(|v| v.as_str())
            != Some("deny");
        Ok(Arc::new(Configurable { allow }))
    }
}

fn config(decision: &str) -> String {
    format!(
        r#"
engine_settings:
  dispatch: policy
global:
  pdp:
    - kind: cel
      decision: {decision}
routes:
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - cel: {{ expr: "true" }}
"#
    )
}

fn request() -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(ENTITY_HTTP.to_owned());
    meta.entity_name = Some(ENTITY_NAME_GLOBAL.to_owned());
    Extensions {
        meta: Some(Arc::new(meta)),
        http: Some(Arc::new(HttpExtension {
            method: Some("GET".to_owned()),
            path: Some("/x".to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn allows(mgr: &PolicyEngine) -> bool {
    let (result, _bg) = mgr
        .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, request(), None)
        .await;
    result.continue_processing
}

/// A changed `global.pdp[]` block takes effect on reload: the config resolver is
/// rebuilt rather than frozen at the first load.
#[tokio::test]
async fn config_pdp_resolver_is_rebuilt_on_reload() {
    let mgr = Arc::new(PolicyEngine::default());
    register_apl(
        &mgr,
        AplOptions {
            pdp_factories: vec![Arc::new(ConfigurableFactory)],
            ..AplOptions::in_process()
        },
    );

    mgr.load_config_yaml(&config("allow")).expect("load allow");
    mgr.initialize().await.expect("initialize");
    assert!(
        allows(&mgr).await,
        "first load: configured allow must allow"
    );

    // Reload with the block changed to deny; the config-owned set must change.
    mgr.load_config_yaml(&config("deny")).expect("reload deny");
    mgr.initialize().await.expect("initialize");
    assert!(
        !allows(&mgr).await,
        "after reload: the rebuilt resolver must apply the new decision (deny)"
    );

    // And back again, to prove it is not a one-way flip.
    mgr.load_config_yaml(&config("allow"))
        .expect("reload allow");
    mgr.initialize().await.expect("initialize");
    assert!(allows(&mgr).await, "reload back to allow must allow again");
}

/// Rejected duplicates must be released, while the first code-owned resolver
/// continues to take precedence over config-owned resolvers across reloads.
#[tokio::test]
async fn duplicate_code_pdp_is_released_and_first_survives_reload() {
    let mgr = Arc::new(PolicyEngine::default());
    let visitor = register_apl(
        &mgr,
        AplOptions {
            pdp_factories: vec![Arc::new(ConfigurableFactory)],
            ..AplOptions::in_process()
        },
    );
    visitor.register_pdp(Arc::new(Configurable { allow: true }));

    let duplicate = Arc::new(Configurable { allow: false });
    let rejected = Arc::downgrade(&duplicate);
    visitor.register_pdp(duplicate);
    assert!(
        rejected.upgrade().is_none(),
        "a rejected resolver must be released"
    );

    for decision in ["deny", "allow", "deny"] {
        mgr.load_config_yaml(&config(decision))
            .expect("load config");
        mgr.initialize().await.expect("initialize");
        assert!(
            allows(&mgr).await,
            "the first code-owned resolver must still win"
        );
        assert!(
            rejected.upgrade().is_none(),
            "reload must not retain a rejected resolver"
        );
    }
}
