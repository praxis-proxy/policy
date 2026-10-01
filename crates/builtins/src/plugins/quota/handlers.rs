// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// QuotaCheck (cmf.llm_input, pre-invoke admission) and QuotaReport
// (cmf.llm_output, post-invoke debit), sharing one Quota core.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use praxis_policy_core::cmf::{CmfHook, MessagePayload};
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::{Extensions, HookHandler, PluginResult};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::prelude::PluginContext;
use tokio_util::task::TaskTracker;
use tracing::Instrument as _;

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

/// Fail-closed denial while a prior debit for this principal has not landed in
/// Limitador. The next admission re-reports it; a retry clears it once it lands.
pub const CODE_QUOTA_UNSETTLED_DEBIT: &str = "quota.unsettled_debit";

/// Slack past `timeout_seconds` for the shutdown drain of in-flight debits.
const DRAIN_SLACK: std::time::Duration = std::time::Duration::from_secs(1);

/// HTTP 429, set as the violation's `proto_error_code` for an over-budget denial.
const HTTP_TOO_MANY_REQUESTS: i64 = 429;

/// A token debit that failed to reach Limitador, held until a later `/report`
/// confirms it landed. Never expires on a timer: clearing without a confirmed
/// report is a silent under-charge, the fail-open bug this state exists to close.
#[derive(Debug, Default)]
struct PendingDebit {
    /// Accumulated unreported tokens for this principal.
    delta: u64,
    /// A flush is in flight, so a concurrent check must not re-report the same
    /// accumulated delta (a deterministic double-charge, distinct from the
    /// unavoidable ambiguous-loss one).
    flushing: bool,
}

/// Whether a pending-debit flush leaves admission able to proceed.
enum FlushOutcome {
    /// No pending debit, or it flushed successfully: run the normal probe.
    Proceed,
    /// A debit is unsettled (flush failed, or another flush is in flight):
    /// deny, fail-closed, until it lands.
    Deny,
}

/// Resets `flushing` on drop unless the settle committed, so a flush future
/// cancelled at the await does not wedge the principal in permanent deny.
struct FlushClaim<'a> {
    pending: &'a Mutex<HashMap<String, PendingDebit>>,
    principal: &'a str,
    committed: bool,
}

impl Drop for FlushClaim<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut map = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(p) = map.get_mut(self.principal) {
            p.flushing = false;
        }
    }
}

/// Shared runtime state for both handlers: the parsed config, the quota
/// backend (a trait object), the declared `PluginConfig`, and the per-principal
/// pending debits a failed `/report` accumulates for the next admission to flush.
#[derive(Debug)]
pub struct Quota {
    cfg: PluginConfig,
    typed: QuotaConfig,
    backend: Box<dyn QuotaBackend>,
    pending: Mutex<HashMap<String, PendingDebit>>,
    /// Tracks in-flight debits so `shutdown` can drain them instead of
    /// dropping them mid-flight on a restart.
    debits: TaskTracker,
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
            pending: Mutex::new(HashMap::new()),
            debits: TaskTracker::new(),
        })
    }

    /// Lock the pending map, recovering a poisoned guard.
    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingDebit>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record a debit that failed to land, for the next admission to re-report.
    fn record_failed_debit(&self, principal: &str, delta: u64) {
        let mut map = self.pending();
        let entry = map.entry(principal.to_owned()).or_default();
        entry.delta = entry.delta.saturating_add(delta);
    }

    /// Report `total` tokens for `principal`, recording a pending debit on
    /// failure for the next admission to re-report. Spawned off the response
    /// path by the post-invoke handler, so a slow `/report` never adds its
    /// round trip to the response tail.
    async fn debit(&self, ext: &Extensions, principal: &str, total: u64) {
        if let Err(e) = self
            .backend
            .report(ext, &self.typed.identity_claim, principal, total)
            .await
        {
            tracing::warn!(
                error = %e,
                delta = total,
                "quota: token debit failed; recorded for retry, principal denied until it settles"
            );
            self.record_failed_debit(principal, total);
        }
    }

    /// Flush a principal's pending debit before admitting. The lock is dropped
    /// across the `/report` await; a concurrent flush is denied, not re-reported.
    async fn flush_pending(&self, ext: &Extensions, claim: &str, principal: &str) -> FlushOutcome {
        let attempted = {
            let mut map = self.pending();
            match map.get_mut(principal) {
                None => return FlushOutcome::Proceed,
                Some(p) if p.delta == 0 => return FlushOutcome::Proceed,
                Some(p) if p.flushing => return FlushOutcome::Deny,
                Some(p) => {
                    p.flushing = true;
                    p.delta
                },
            }
        };

        // Resets `flushing` if the await is cancelled; the settle sets `committed`.
        let mut flush_claim = FlushClaim {
            pending: &self.pending,
            principal,
            committed: false,
        };

        let result = self.backend.report(ext, claim, principal, attempted).await;
        flush_claim.committed = true;

        let mut map = self.pending();
        let outcome = match map.get_mut(principal) {
            Some(p) => {
                p.flushing = false;
                match result {
                    Ok(()) => {
                        p.delta = p.delta.saturating_sub(attempted);
                        if p.delta == 0 {
                            FlushOutcome::Proceed
                        } else {
                            // Another debit failed while this report was in
                            // flight. It still needs to land before admission.
                            FlushOutcome::Deny
                        }
                    },
                    Err(_) => FlushOutcome::Deny,
                }
            },
            None => match result {
                Ok(()) => FlushOutcome::Proceed,
                Err(_) => FlushOutcome::Deny,
            },
        };
        if map
            .get(principal)
            .is_some_and(|p| p.delta == 0 && !p.flushing)
        {
            map.remove(principal);
        }
        outcome
    }
}

#[async_trait]
impl Plugin for Quota {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }

    /// Drain in-flight debits so a shutdown or rolling restart lets them land
    /// (or record as pending) instead of dropping them. Bounded: each debit is
    /// one call capped at `timeout_seconds`, and they run concurrently.
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        self.debits.close();
        let bound = self.typed.timeout() + DRAIN_SLACK;
        if tokio::time::timeout(bound, self.debits.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                in_flight = self.debits.len(),
                "quota: shutdown drain timed out; in-flight token debits dropped"
            );
        }
        Ok(())
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

        // Settle any prior debit that failed to land before admitting again.
        if let FlushOutcome::Deny = self.core.flush_pending(extensions, claim, &sub).await {
            tracing::warn!(
                claim = claim.as_str(),
                "quota: denying; a prior token debit is unsettled and must re-report first"
            );
            return PluginResult::deny(PluginViolation::new(
                CODE_QUOTA_UNSETTLED_DEBIT,
                "a prior token debit is unsettled",
            ));
        }

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

/// Post-invoke handler on `cmf.llm_output`. Debits the gateway's typed token
/// usage, or a conservative fallback when it is absent. Never denies.
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
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let claim = &self.core.typed.identity_claim;
        let Some(sub) = resolve_identity(extensions, claim) else {
            // Cannot attribute the cost to a consumer, so debit nothing.
            return PluginResult::allow();
        };

        // The gateway's typed usage is the only trusted source. Absent it (a
        // streamed response, or a provider without typed usage) debit the
        // conservative fallback, never zero. The response body is not parsed:
        // the CMF output carries the model's generated text, not the provider's
        // usage block, so a body total would meter on model output.
        let total = extensions
            .completion
            .as_ref()
            .and_then(|c| c.tokens.as_ref())
            .map(|t| u64::from(t.total_tokens))
            .filter(|total| *total > 0)
            .unwrap_or(self.core.typed.missing_usage_charge);

        // Debit off the response path so a slow /report does not hold the
        // response. The response is released before the debit lands, so the
        // principal's next request can be admitted against the pre-debit
        // counter. A failed debit is recorded as pending on this replica and
        // denies until it re-reports; that state is in-process, so a restart
        // loses it. Tracked so shutdown drains in-flight debits.
        let core = Arc::clone(&self.core);
        let report_ext = Extensions {
            http_transport: extensions.http_transport.clone(),
            ..Default::default()
        };
        let principal = sub.into_owned();
        self.core.debits.spawn(
            async move {
                core.debit(&report_ext, &principal, total).await;
            }
            .instrument(tracing::Span::current()),
        );
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests assert pending debit and identity state"
)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use praxis_policy_core::extensions::{SecurityExtension, SubjectExtension};
    use praxis_policy_core::host::HttpTransportSlot;
    use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
    use tokio::sync::Notify;

    #[derive(Debug, Default)]
    struct PausedReport {
        entered: Notify,
        resume: Notify,
    }

    #[async_trait]
    impl HttpTransport for PausedReport {
        async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            if req.url.ends_with("/report") {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            Ok(HttpResponse::new(200, Bytes::new()))
        }
    }

    #[tokio::test]
    async fn a_new_failed_debit_during_a_flush_still_blocks_admission() {
        let cfg = PluginConfig {
            name: "token-quota".into(),
            config: Some(serde_json::json!({
                "endpoint": "http://limitador.test",
                "namespace": "grid-tokens",
                "insecure_http": true,
            })),
            ..Default::default()
        };
        let core = Arc::new(Quota::new(cfg).unwrap());
        core.record_failed_debit("bob", 11);

        let paused = Arc::new(PausedReport::default());
        let transport: Arc<dyn HttpTransport> = paused.clone();
        let ext = Extensions {
            http_transport: HttpTransportSlot::installed(transport),
            ..Default::default()
        };
        let flushing = tokio::spawn({
            let core = Arc::clone(&core);
            async move { core.flush_pending(&ext, "sub", "bob").await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), paused.entered.notified())
            .await
            .expect("the first debit reaches the transport");

        core.record_failed_debit("bob", 20);
        paused.resume.notify_one();

        assert!(matches!(flushing.await.unwrap(), FlushOutcome::Deny));
        assert_eq!(core.pending().get("bob").unwrap().delta, 20);
    }

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
}
