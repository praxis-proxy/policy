// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// QuotaCheck (cmf.llm_input, pre-invoke admission) and QuotaReport
// (cmf.llm_output, post-invoke debit), sharing one Quota core.

use std::sync::Arc;

use async_trait::async_trait;
use praxis_policy_core::cmf::{CmfHook, MessagePayload};
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::{Extensions, HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::prelude::PluginContext;

use super::backend::{BackendErrorKind, CheckOutcome, QuotaBackend};
use super::client::LimitadorClient;
use super::config::{OnErrorMode, QuotaConfig};

/// Over-budget denial. Mapped to HTTP 429.
pub const CODE_QUOTA_EXHAUSTED: &str = "quota.exhausted";

/// Fail-closed denial when the backend is unreachable under `on_error: deny`.
pub const CODE_QUOTA_BACKEND_UNAVAILABLE: &str = "quota.backend_unavailable";

/// Fail-closed denial when the host refused to send the Limitador call (egress
/// policy, SSRF guard, open circuit). Distinct from `backend_unavailable` so
/// the operator looks at egress config, not at a healthy Limitador.
pub const CODE_QUOTA_EGRESS_DENIED: &str = "quota.egress_denied";

/// Fail-closed denial when a request carries no resolved identity to meter and
/// `allow_unauthenticated` is not set.
pub const CODE_QUOTA_NO_IDENTITY: &str = "quota.no_identity";

/// HTTP 429, set as the violation's `proto_error_code` for an over-budget denial.
const HTTP_TOO_MANY_REQUESTS: i64 = 429;

/// Shared runtime state for both handlers: the parsed config, the quota
/// backend (a trait object), and the declared `PluginConfig`.
#[derive(Debug)]
pub struct Quota {
    cfg: PluginConfig,
    typed: QuotaConfig,
    backend: Box<dyn QuotaBackend>,
}

impl Quota {
    /// Build the core from the declared `PluginConfig`, validating the
    /// `config:` block and constructing the backend once.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when the `config:` block is absent, invalid, or
    /// the backend cannot be built.
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg.config.clone().ok_or_else(|| {
            PluginError::Config {
                message: format!(
                    "plugin '{}' (quota): a `config:` block with `endpoint` \
                     and `namespace` is required",
                    cfg.name
                ),
            }
            .boxed()
        })?;

        let typed: QuotaConfig = serde_json::from_value(raw).map_err(|e| {
            PluginError::Config {
                message: format!("plugin '{}' (quota) config invalid: {e}", cfg.name),
            }
            .boxed()
        })?;

        typed.validate().map_err(|e| {
            PluginError::Config {
                message: format!("plugin '{}' (quota): {e}", cfg.name),
            }
            .boxed()
        })?;

        let backend: Box<dyn QuotaBackend> = Box::new(LimitadorClient::new(
            &typed.endpoint,
            &typed.namespace,
            typed.timeout(),
        ));

        Ok(Self {
            cfg,
            typed,
            backend,
        })
    }
}

#[async_trait]
impl Plugin for Quota {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

/// Pre-invoke handler on `cmf.llm_input`. Asks the backend whether the
/// resolved consumer is within budget, charging nothing.
#[derive(Debug)]
pub struct QuotaCheck {
    core: Arc<Quota>,
}

impl QuotaCheck {
    /// Wrap the shared core for the pre-invoke hook.
    pub fn new(core: Arc<Quota>) -> Self {
        Self { core }
    }
}

#[async_trait]
impl Plugin for QuotaCheck {
    fn config(&self) -> &PluginConfig {
        &self.core.cfg
    }
}

impl HookHandler<CmfHook> for QuotaCheck {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let claim = &self.core.typed.identity_claim;
        let Some(sub) = resolve_identity(extensions, claim) else {
            // Nothing to meter. Failing open here would let a dropped identity
            // claim dodge the budget, so deny by default and match the
            // never-serve-unmetered posture. An operator that gates auth
            // upstream opts into serving with `allow_unauthenticated`.
            if self.core.typed.allow_unauthenticated {
                tracing::warn!(
                    claim = claim.as_str(),
                    "quota: no resolved identity on llm_input; allow_unauthenticated is set, \
                     serving UNMETERED"
                );
                return PluginResult::allow();
            }
            tracing::error!(
                claim = claim.as_str(),
                "quota: no resolved identity on llm_input; denying (set allow_unauthenticated \
                 to serve unmetered when auth is gated upstream)"
            );
            return PluginResult::deny(PluginViolation::new(
                CODE_QUOTA_NO_IDENTITY,
                "no resolved identity to meter",
            ));
        };

        match self.core.backend.check(extensions, claim, &sub).await {
            Ok(CheckOutcome::WithinLimit) => PluginResult::allow(),
            Ok(CheckOutcome::OverLimit) => PluginResult::deny(
                PluginViolation::new(CODE_QUOTA_EXHAUSTED, "token budget exhausted")
                    // Exhausted budget is HTTP 429.
                    .with_proto_error_code(HTTP_TOO_MANY_REQUESTS),
            ),
            Err(e) => match e.kind {
                // A misconfigured plugin (no transport, or `perform_http`
                // withheld) is not an unreachable Limitador, so `on_error`
                // does not apply: never serve unmetered on a wiring fault.
                BackendErrorKind::Unavailable => {
                    tracing::error!(
                        error = %e,
                        "quota: check cannot run (transport unavailable or \
                         perform_http withheld); denying regardless of on_error"
                    );
                    PluginResult::deny(PluginViolation::new(
                        CODE_QUOTA_BACKEND_UNAVAILABLE,
                        "token budget backend unavailable",
                    ))
                },
                // The host refused to send the call. Also permanent, and
                // named distinctly so the operator checks egress, not a
                // Limitador that is actually healthy.
                BackendErrorKind::EgressDenied => {
                    tracing::error!(
                        error = %e,
                        "quota: check refused by host egress before reaching Limitador; \
                         denying regardless of on_error"
                    );
                    PluginResult::deny(PluginViolation::new(
                        CODE_QUOTA_EGRESS_DENIED,
                        "token budget check refused by host egress policy",
                    ))
                },
                BackendErrorKind::Transport => {
                    tracing::warn!(
                        error = %e,
                        on_error = ?self.core.typed.on_error,
                        "quota: check call failed; applying on_error posture"
                    );
                    match self.core.typed.on_error {
                        OnErrorMode::Allow => PluginResult::allow(),
                        OnErrorMode::Deny => PluginResult::deny(PluginViolation::new(
                            CODE_QUOTA_BACKEND_UNAVAILABLE,
                            "token budget backend unavailable",
                        )),
                    }
                },
            },
        }
    }
}

/// Post-invoke handler on `cmf.llm_output`. Debits the token usage (typed
/// first, response body as a fallback). Never denies.
#[derive(Debug)]
pub struct QuotaReport {
    core: Arc<Quota>,
}

impl QuotaReport {
    /// Wrap the shared core for the post-invoke hook.
    pub fn new(core: Arc<Quota>) -> Self {
        Self { core }
    }
}

#[async_trait]
impl Plugin for QuotaReport {
    fn config(&self) -> &PluginConfig {
        &self.core.cfg
    }
}

impl HookHandler<CmfHook> for QuotaReport {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let claim = &self.core.typed.identity_claim;
        let Some(sub) = resolve_identity(extensions, claim) else {
            // Cannot attribute the cost to a consumer, so debit nothing.
            return PluginResult::allow();
        };

        // Prefer the gateway's typed usage; fall back to the response body.
        let total = extensions
            .completion
            .as_ref()
            .and_then(|c| c.tokens.as_ref())
            .map(|t| u64::from(t.total_tokens))
            .or_else(|| {
                extract_usage(
                    &payload.message.get_text_content(),
                    &self.core.typed.usage_json_path,
                )
            });
        let Some(total) = total else {
            return PluginResult::allow();
        };
        if total == 0 {
            return PluginResult::allow();
        }

        if let Err(e) = self
            .core
            .backend
            .report(extensions, claim, &sub, total)
            .await
        {
            // A report failure never denies. The response is already out.
            tracing::warn!(
                error = %e,
                delta = total,
                "quota: token debit failed; balance may lag"
            );
        }
        PluginResult::allow()
    }
}

/// The value that keys the budget. `sub` reads `security.subject.id`, any
/// other `identity_claim` reads that scalar claim. Absent or empty yields `None`.
fn resolve_identity<'a>(
    ext: &'a Extensions,
    identity_claim: &str,
) -> Option<std::borrow::Cow<'a, str>> {
    let subject = ext.security.as_ref()?.subject.as_ref()?;
    let value = if identity_claim == "sub" {
        subject.id.as_deref().map(std::borrow::Cow::Borrowed)
    } else {
        subject.claim_str(identity_claim)
    };
    value.filter(|v| !v.is_empty())
}

/// Read a non-negative integer token total at `path` (split on `.` or `/`)
/// in `body` parsed as JSON. `None` if absent or not such an integer.
fn extract_usage(body: &str, path: &str) -> Option<u64> {
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    let mut cursor = &root;
    for segment in path.split(['.', '/']).filter(|s| !s.is_empty()) {
        cursor = cursor.get(segment)?;
    }
    number_as_u64(cursor)
}

/// A `serde_json::Value` as a non-negative integer (number or numeric
/// string). Floats are refused, not truncated.
fn number_as_u64(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    value.as_str().and_then(|s| s.trim().parse::<u64>().ok())
}

/// The per-request hot-path functions, exposed for the microbenchmark under
/// the `bench` feature. Not part of the plugin API in a normal build.
#[cfg(feature = "bench")]
pub mod bench {
    use super::Extensions;
    use std::borrow::Cow;

    /// Benchmark wrapper over the crate-private `resolve_identity`.
    pub fn resolve_identity<'a>(ext: &'a Extensions, identity_claim: &str) -> Option<Cow<'a, str>> {
        super::resolve_identity(ext, identity_claim)
    }

    /// Benchmark wrapper over the crate-private `extract_usage`.
    pub fn extract_usage(body: &str, path: &str) -> Option<u64> {
        super::extract_usage(body, path)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::extensions::{SecurityExtension, SubjectExtension};

    fn security_with_sub(id: &str) -> Extensions {
        Extensions {
            security: Some(Arc::new(SecurityExtension {
                subject: Some(SubjectExtension {
                    id: Some(id.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn resolve_identity_reads_sub_from_subject_id() {
        let ext = security_with_sub("bob");
        assert_eq!(resolve_identity(&ext, "sub").as_deref(), Some("bob"));
    }

    #[test]
    fn resolve_identity_reads_a_custom_claim_from_claims() {
        let mut ext = security_with_sub("bob");
        Arc::get_mut(ext.security.as_mut().unwrap())
            .unwrap()
            .subject
            .as_mut()
            .unwrap()
            .claims
            .insert("tenant".to_owned(), serde_json::json!("acme"));
        assert_eq!(resolve_identity(&ext, "tenant").as_deref(), Some("acme"));
    }

    #[test]
    fn resolve_identity_is_none_without_a_subject() {
        assert_eq!(resolve_identity(&Extensions::default(), "sub"), None);
    }

    #[test]
    fn resolve_identity_treats_empty_as_absent() {
        let ext = security_with_sub("");
        assert_eq!(resolve_identity(&ext, "sub"), None);
    }

    #[test]
    fn extract_usage_reads_the_default_path() {
        let body = r#"{"choices":[],"usage":{"prompt_tokens":5,"total_tokens":11}}"#;
        assert_eq!(extract_usage(body, "usage.total_tokens"), Some(11));
    }

    #[test]
    fn extract_usage_accepts_slash_separators() {
        let body = r#"{"usage":{"total_tokens":11}}"#;
        assert_eq!(extract_usage(body, "usage/total_tokens"), Some(11));
    }

    #[test]
    fn extract_usage_is_none_when_absent() {
        // Streaming chunk without include_usage, no usage object at all.
        let body = r#"{"choices":[{"delta":{"content":"hi"}}]}"#;
        assert_eq!(extract_usage(body, "usage.total_tokens"), None);
    }

    #[test]
    fn extract_usage_is_none_for_non_json() {
        assert_eq!(extract_usage("not json", "usage.total_tokens"), None);
    }

    #[test]
    fn extract_usage_reads_a_numeric_string() {
        let body = r#"{"usage":{"total_tokens":"11"}}"#;
        assert_eq!(extract_usage(body, "usage.total_tokens"), Some(11));
    }

    #[test]
    fn extract_usage_refuses_a_float() {
        let body = r#"{"usage":{"total_tokens":11.5}}"#;
        assert_eq!(extract_usage(body, "usage.total_tokens"), None);
    }
}
