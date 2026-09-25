// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` impl for the quota plugin. Operators declare it in PPE
// YAML as:
//
//     plugins:
//       - name: token-quota
//         kind: quota
//         hooks: [cmf.llm_input, cmf.llm_output]
//         # All three are required. read_subject/read_claims: without them the
//         # identity is filtered to None, which now denies (see
//         # allow_unauthenticated). perform_http: the check and debit are
//         # outbound calls through the host transport; withholding it denies
//         # every metered request, regardless of on_error.
//         capabilities: [read_subject, read_claims, perform_http]
//         config:
//           endpoint: http://limitador.grid-system.svc:8080
//           namespace: grid-tokens
//           identity_claim: sub      # must be a verified, always-present claim
//           on_error: deny           # transport failures fail closed (the default)
//           usage_json_path: usage.total_tokens
//           allow_unauthenticated: false  # a request with no identity denies (the default)
//
// The two hook points are registered from code, so the operator's `hooks:`
// list is documentation, not a lever.
//
// Deployment note: the check and debit run through the host HTTP transport,
// which enforces the host's egress policy. Limitador is usually an in-cluster
// Service on a private (RFC 1918) ClusterIP, and a transport that blocks
// private destinations by default refuses every call, which denies with
// `quota.egress_denied`. Ensure the host transport permits the Limitador
// address.

use std::sync::Arc;

use praxis_policy_core::cmf::CmfHook;
use praxis_policy_core::cmf::constants::{HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT};
use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::TypedHandlerAdapter;
use praxis_policy_core::plugin::PluginConfig;
use praxis_policy_core::registry::AnyHookHandler;

use super::handlers::{Quota, QuotaCheck, QuotaReport};

/// The `kind:` string operators write in PPE YAML.
pub const KIND: &str = "quota";

/// Factory for `kind: quota`. Builds one shared [`Quota`] core and registers
/// the check on `cmf.llm_input` and the debit on `cmf.llm_output`.
pub struct QuotaFactory;

impl PluginFactory for QuotaFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let core = Arc::new(Quota::new(config.clone())?);

        let check: Arc<dyn AnyHookHandler> = Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(
            Arc::new(QuotaCheck::new(Arc::clone(&core))),
        ));
        let report: Arc<dyn AnyHookHandler> = Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(
            Arc::new(QuotaReport::new(Arc::clone(&core))),
        ));

        Ok(PluginInstance {
            plugin: core,
            handlers: vec![(HOOK_CMF_LLM_INPUT, check), (HOOK_CMF_LLM_OUTPUT, report)],
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn cfg(config: serde_json::Value) -> PluginConfig {
        PluginConfig {
            name: "token-quota".into(),
            kind: KIND.into(),
            hooks: vec![
                HOOK_CMF_LLM_INPUT.to_owned(),
                HOOK_CMF_LLM_OUTPUT.to_owned(),
            ],
            config: Some(config),
            ..Default::default()
        }
    }

    fn valid_config() -> serde_json::Value {
        serde_json::json!({
            "endpoint": "http://limitador.grid-system.svc:8080",
            "namespace": "grid-tokens",
        })
    }

    /// The two hook points are fixed in code, so this pins that a valid
    /// config lands exactly one handler on each of `cmf.llm_input` and
    /// `cmf.llm_output`.
    #[test]
    fn registers_the_check_on_input_and_the_report_on_output() {
        let inst = QuotaFactory
            .create(&cfg(valid_config()))
            .expect("a valid config must build");
        assert_eq!(inst.handlers.len(), 2, "one check, one report");
        assert_eq!(inst.handlers[0].0, HOOK_CMF_LLM_INPUT);
        assert_eq!(inst.handlers[1].0, HOOK_CMF_LLM_OUTPUT);
    }

    /// A config missing the required `endpoint` must fail the factory
    /// rather than load a plugin that cannot key a budget.
    #[test]
    fn a_config_without_an_endpoint_fails_the_factory() {
        let err = QuotaFactory
            .create(&cfg(serde_json::json!({ "namespace": "grid-tokens" })))
            .err()
            .expect("a config with no endpoint must not build");
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a config error, got {err:?}"
        );
    }

    /// An absent `config:` block is a config error, not a panic.
    #[test]
    fn an_absent_config_block_fails_the_factory() {
        let bare = PluginConfig {
            name: "token-quota".into(),
            kind: KIND.into(),
            hooks: vec![HOOK_CMF_LLM_INPUT.to_owned()],
            config: None,
            ..Default::default()
        };
        let err = QuotaFactory
            .create(&bare)
            .err()
            .expect("no config block must not build");
        assert!(matches!(*err, PluginError::Config { .. }));
    }
}
