// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end behavior of the two hook handlers against a scripted Limitador.
//!
//! The rows the plugin exists to get right: over budget denies, under budget
//! allows, an unreachable or ungranted Limitador honors `on_error`, and an
//! output with no usage debits a fallback and never denies. Limitador is scripted
//! through the host transport rather than a mock server, so the same
//! `perform_http` seam the plugin uses in production is what the tests drive.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "integration tests assert quota outcomes"
)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use praxis_policy_core::cmf::{Message, MessagePayload, Role};
use praxis_policy_core::extensions::{
    CompletionExtension, Extensions, SecurityExtension, SubjectExtension, TokenUsage,
};
use praxis_policy_core::hooks::HookHandler as _;
use praxis_policy_core::host::HttpTransportSlot;
use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::plugin::{Plugin as _, PluginConfig};
use praxis_policy_core::prelude::PluginContext;
use serde_json::json;

use praxis_policy_builtins::plugins::quota::factory::KIND;
use praxis_policy_builtins::plugins::quota::handlers::{Quota, QuotaCheck, QuotaReport};

/// Build a core with an optional `on_error` override. The endpoint is a fixed
/// placeholder: the transport matches on the `/check` and `/report` path, not
/// on the host.
fn core(on_error: &str) -> Arc<Quota> {
    let cfg = PluginConfig {
        name: "token-quota".into(),
        kind: KIND.into(),
        config: Some(json!({
            "endpoint": "http://limitador.test",
            "namespace": "grid-tokens",
            "on_error": on_error,
            "timeout_seconds": 1,
            "insecure_http": true,
        })),
        ..Default::default()
    };
    Arc::new(Quota::new(cfg).expect("core builds"))
}

/// Identity extensions for `sub`, with `transport` wired into the
/// `perform_http` slot the plugin reaches for its Limitador calls.
fn ext_with_sub(sub: &str, transport: Arc<dyn HttpTransport>) -> Extensions {
    Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some(sub.to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        http_transport: HttpTransportSlot::installed(transport),
        ..Default::default()
    }
}

/// The typed completion usage alongside identity, with the transport wired in.
fn ext_with_sub_and_usage(sub: &str, total: u32, transport: Arc<dyn HttpTransport>) -> Extensions {
    let mut ext = ext_with_sub(sub, transport);
    ext.completion = Some(Arc::new(CompletionExtension {
        tokens: Some(TokenUsage {
            total_tokens: total,
            ..Default::default()
        }),
        ..Default::default()
    }));
    ext
}

/// Coerce a scripted `FakeTransport` handle to the trait object the plugin
/// sees, keeping the concrete handle for post-call assertions.
fn as_transport(t: &Arc<FakeTransport>) -> Arc<dyn HttpTransport> {
    t.clone()
}

fn input_payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "hello"),
    }
}

fn output_payload(body: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::Assistant, body),
    }
}

/// Poll `cond` until it holds, yielding so the spawned debit task can run. The
/// post-invoke debit is fire-and-forget, so a test asserting on its /report
/// call waits for it rather than racing it. Panics if it never holds, so a real
/// regression fails instead of hanging.
async fn eventually(mut cond: impl FnMut() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    panic!("condition never became true");
}

#[tokio::test]
async fn under_budget_check_allows() {
    let t = Arc::new(FakeTransport::new().json("/check", 200, ""));
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(
        !result.is_denied(),
        "a within-limit consumer must be allowed"
    );
}

#[tokio::test]
async fn over_budget_check_denies_with_quota_exhausted() {
    let t = Arc::new(FakeTransport::new().json("/check", 429, ""));
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(result.is_denied(), "an over-budget consumer must be denied");
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.exhausted");
}

#[tokio::test]
async fn unreachable_limitador_fails_open_when_on_error_allow() {
    // The transport reports a connect failure — the check call fails at
    // transport, exactly as an unreachable Limitador would.
    let t = Arc::new(
        FakeTransport::new().fail("/check", HttpTransportError::Connect("refused".to_owned())),
    );
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(
        !result.is_denied(),
        "on_error: allow must serve the request when Limitador is unreachable"
    );
}

#[tokio::test]
async fn unreachable_limitador_fails_closed_when_on_error_deny() {
    let t = Arc::new(
        FakeTransport::new().fail("/check", HttpTransportError::Connect("refused".to_owned())),
    );
    let handler = QuotaCheck::new(core("deny"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(
        result.is_denied(),
        "on_error: deny must refuse the request when Limitador is unreachable"
    );
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.backend_unavailable");
}

#[tokio::test]
async fn withheld_perform_http_fails_closed_when_on_error_deny() {
    // No `perform_http` grant. The check call cannot be made, and under the
    // default posture that must refuse rather than serve unmetered.
    let ext = Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("bob".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        http_transport: HttpTransportSlot::withheld(),
        ..Default::default()
    };
    let handler = QuotaCheck::new(core("deny"));
    let mut ctx = PluginContext::new();
    let result = handler.handle(&input_payload(), &ext, &mut ctx).await;
    assert!(
        result.is_denied(),
        "a withheld perform_http under on_error: deny must refuse"
    );
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.backend_unavailable");
}

#[tokio::test]
async fn withheld_perform_http_fails_closed_even_when_on_error_allow() {
    // A forgotten `perform_http` grant is a misconfiguration, not an
    // unreachable Limitador, so it must NOT fall through `on_error: allow` and
    // silently serve unmetered. This is the fail-open-on-misconfig guard.
    let ext = Extensions {
        security: Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("bob".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        http_transport: HttpTransportSlot::withheld(),
        ..Default::default()
    };
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler.handle(&input_payload(), &ext, &mut ctx).await;
    assert!(
        result.is_denied(),
        "a withheld perform_http must deny even under on_error: allow"
    );
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.backend_unavailable");
}

#[tokio::test]
async fn egress_denied_fails_closed_even_when_on_error_allow() {
    // The host refusing the call (egress policy for the in-cluster Limitador
    // ClusterIP) never reached the peer, so it must NOT fall through
    // on_error: allow and serve unmetered. It denies with its own code.
    let t = Arc::new(
        FakeTransport::new().fail("/check", HttpTransportError::Rejected("egress".to_owned())),
    );
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(
        result.is_denied(),
        "an egress-denied call must deny even under on_error: allow"
    );
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.egress_denied");
}

#[tokio::test]
async fn report_debits_the_fallback_when_typed_usage_absent() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    // No typed usage on the completion extension (a streamed response, or a
    // provider without typed usage): the debit falls to the conservative
    // fallback (missing_usage_charge, default 1000), never nothing. The response
    // body is not parsed for a total.
    let result = handler
        .handle(
            &output_payload("streamed text with no typed usage"),
            &ext_with_sub("bob", as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied(), "an absent total must never deny");
    eventually(|| t.call_count_for("/report") == 1).await;
    let sent =
        String::from_utf8_lossy(&t.last_request().expect("a fallback debit").body).into_owned();
    assert!(sent.contains(r#""delta":1000"#), "{sent}");
}

#[tokio::test]
async fn report_debits_the_fallback_when_typed_usage_is_zero() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("deny"));
    let result = handler
        .handle(
            &output_payload("done"),
            &ext_with_sub_and_usage("bob", 0, as_transport(&t)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(!result.is_denied());
    eventually(|| t.call_count_for("/report") == 1).await;
    let sent =
        String::from_utf8_lossy(&t.last_request().expect("a fallback debit").body).into_owned();
    assert!(sent.contains(r#""delta":1000"#), "{sent}");
}

#[tokio::test]
async fn report_never_denies_even_when_the_debit_fails() {
    // Limitador answers the debit with a 500. The debit is best-effort, so this
    // must be swallowed, not turned into a denial.
    let t = Arc::new(FakeTransport::new().json("/report", 500, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(
            &output_payload("done"),
            &ext_with_sub_and_usage("bob", 11, as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied(), "a failed debit must never deny");
}

#[tokio::test]
async fn a_failed_debit_denies_until_it_settles() {
    // Shared core, so the report's failure is visible to the check.
    let core = core("deny");

    // A debit of 11 fails to reach Limitador and is recorded as pending.
    let t_fail = Arc::new(FakeTransport::new().json("/report", 500, ""));
    let report = QuotaReport::new(Arc::clone(&core));
    let out = report
        .handle(
            &output_payload("done"),
            &ext_with_sub_and_usage("bob", 11, as_transport(&t_fail)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(!out.is_denied(), "the report hook never denies");
    // The debit is spawned; wait for the failed /report to land and be recorded.
    eventually(|| t_fail.call_count_for("/report") == 1).await;

    // Next admission: the flush still fails, so deny (fail-closed) without even
    // running the check probe.
    let check = QuotaCheck::new(Arc::clone(&core));
    let t_still = Arc::new(
        FakeTransport::new()
            .json("/report", 500, "")
            .json("/check", 200, ""),
    );
    let denied = check
        .handle(
            &input_payload(),
            &ext_with_sub("bob", as_transport(&t_still)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(denied.is_denied(), "an unsettled debit must fail closed");
    assert_eq!(
        t_still.call_count_for("/check"),
        0,
        "the probe is skipped while the debit is unsettled"
    );

    // Next admission: the flush succeeds, re-reporting the accumulated 11, then
    // the probe admits.
    let t_ok = Arc::new(
        FakeTransport::new()
            .json("/report", 200, "")
            .json("/check", 200, ""),
    );
    let allowed = check
        .handle(
            &input_payload(),
            &ext_with_sub("bob", as_transport(&t_ok)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(
        !allowed.is_denied(),
        "admission resumes once the debit settles"
    );
    assert_eq!(
        t_ok.call_count_for("/check"),
        1,
        "the probe runs after the flush"
    );
    let re_reported = t_ok
        .requests()
        .iter()
        .any(|r| String::from_utf8_lossy(&r.body).contains(r#""delta":11"#));
    assert!(re_reported, "the accumulated debit is re-reported in full");
}

#[tokio::test]
async fn a_cancelled_flush_does_not_wedge_the_principal() {
    let core = core("deny");

    // Record a pending debit.
    let t_fail = Arc::new(FakeTransport::new().json("/report", 500, ""));
    let out = QuotaReport::new(Arc::clone(&core))
        .handle(
            &output_payload("done"),
            &ext_with_sub_and_usage("bob", 7, as_transport(&t_fail)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(!out.is_denied());
    // The debit is spawned; wait for the failed /report to land and be recorded.
    eventually(|| t_fail.call_count_for("/report") == 1).await;

    // Start a flush whose report hangs, then cancel it by dropping the future.
    let check = QuotaCheck::new(Arc::clone(&core));
    let t_slow = Arc::new(
        FakeTransport::new()
            .with_latency(std::time::Duration::from_secs(30))
            .json("/report", 200, "")
            .json("/check", 200, ""),
    );
    let payload = input_payload();
    let ext = ext_with_sub("bob", as_transport(&t_slow));
    let mut ctx = PluginContext::new();
    let fut = check.handle(&payload, &ext, &mut ctx);
    let cancelled = tokio::time::timeout(std::time::Duration::from_millis(50), fut).await;
    assert!(
        cancelled.is_err(),
        "the flush should still be hanging at the report await"
    );
    // fut dropped here; FlushClaim::drop must reset `flushing`.

    // A fresh admission must flush and proceed, not be wedged in permanent deny.
    let t_ok = Arc::new(
        FakeTransport::new()
            .json("/report", 200, "")
            .json("/check", 200, ""),
    );
    let allowed = check
        .handle(
            &input_payload(),
            &ext_with_sub("bob", as_transport(&t_ok)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(
        !allowed.is_denied(),
        "a cancelled flush must not wedge the principal into permanent deny"
    );
}

#[tokio::test]
async fn report_debits_the_typed_completion_usage() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    // Body carries no usage; the total must come from the typed slot.
    let result = handler
        .handle(
            &output_payload("done"),
            &ext_with_sub_and_usage("alice", 25, as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied());
    eventually(|| t.call_count_for("/report") == 1).await;
    let sent = String::from_utf8_lossy(&t.last_request().expect("a debit").body).into_owned();
    assert!(sent.contains(r#""delta":25"#), "{sent}");
    assert!(sent.contains(r#""sub":"alice""#), "{sent}");
}

#[tokio::test]
async fn report_ignores_the_response_body_and_uses_typed_usage() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    // A body claiming a tiny cost must not be parsed or win over the typed slot.
    let body = r#"{"usage":{"total_tokens":1}}"#;
    let result = handler
        .handle(
            &output_payload(body),
            &ext_with_sub_and_usage("alice", 25, as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied());
    eventually(|| t.call_count_for("/report") == 1).await;
    let sent = String::from_utf8_lossy(&t.last_request().expect("a debit").body).into_owned();
    assert!(sent.contains(r#""delta":25"#), "{sent}");
}

#[tokio::test]
async fn check_denies_without_a_resolved_identity_by_default() {
    // Nothing to meter, and fail-open would let a dropped identity claim dodge
    // the budget, so the default denies before probing Limitador.
    let t = Arc::new(FakeTransport::new().json("/check", 200, ""));
    let ext = Extensions {
        http_transport: HttpTransportSlot::installed(as_transport(&t)),
        ..Default::default()
    };
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler.handle(&input_payload(), &ext, &mut ctx).await;
    assert!(result.is_denied(), "no identity must deny by default");
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.no_identity");
    assert_eq!(t.call_count_for("/check"), 0, "no identity means no probe");
}

#[tokio::test]
async fn check_allows_without_identity_when_allow_unauthenticated() {
    // The explicit opt-in for deployments that gate auth upstream: no identity
    // then serves unmetered, and still never probes Limitador.
    let t = Arc::new(FakeTransport::new().json("/check", 200, ""));
    let ext = Extensions {
        http_transport: HttpTransportSlot::installed(as_transport(&t)),
        ..Default::default()
    };
    let cfg = PluginConfig {
        name: "token-quota".into(),
        kind: KIND.into(),
        config: Some(json!({
            "endpoint": "http://limitador.test",
            "namespace": "grid-tokens",
            "allow_unauthenticated": true,
            "insecure_http": true,
        })),
        ..Default::default()
    };
    let handler = QuotaCheck::new(Arc::new(Quota::new(cfg).expect("core builds")));
    let mut ctx = PluginContext::new();
    let result = handler.handle(&input_payload(), &ext, &mut ctx).await;
    assert!(
        !result.is_denied(),
        "allow_unauthenticated must serve a no-identity request"
    );
    assert_eq!(t.call_count_for("/check"), 0, "no identity means no probe");
}

#[tokio::test]
async fn report_skips_the_debit_without_a_resolved_identity() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let ext = Extensions {
        completion: Some(Arc::new(CompletionExtension {
            tokens: Some(TokenUsage {
                total_tokens: 99,
                ..Default::default()
            }),
            ..Default::default()
        })),
        http_transport: HttpTransportSlot::installed(as_transport(&t)),
        ..Default::default()
    };
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&output_payload("done"), &ext, &mut ctx)
        .await;
    assert!(!result.is_denied());
    assert_eq!(t.call_count_for("/report"), 0, "no identity means no debit");
}

#[tokio::test]
async fn check_fails_closed_on_a_server_error_under_on_error_deny() {
    let t = Arc::new(FakeTransport::new().json("/check", 500, ""));
    let handler = QuotaCheck::new(core("deny"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(result.is_denied(), "a 500 under on_error: deny must refuse");
}

#[tokio::test]
async fn check_fails_open_on_a_server_error_under_on_error_allow() {
    let t = Arc::new(FakeTransport::new().json("/check", 500, ""));
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(
        !result.is_denied(),
        "a 500 under on_error: allow must serve"
    );
}

#[tokio::test]
async fn check_fails_closed_on_a_config_error_4xx_even_under_on_error_allow() {
    // A 400 is a config-class fault (bad namespace/path/body). It must NOT ride
    // on_error: allow and silently disable enforcement; it denies regardless.
    let t = Arc::new(FakeTransport::new().json("/check", 400, ""));
    let handler = QuotaCheck::new(core("allow"));
    let mut ctx = PluginContext::new();
    let result = handler
        .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(
        result.is_denied(),
        "a config-error 4xx must fail closed even under on_error: allow"
    );
    let violation = result.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.backend_unavailable");
}

#[tokio::test]
async fn check_fails_closed_on_a_redirect_even_under_on_error_allow() {
    // The host transport does not follow redirects, so an http-to-https
    // redirect answers every /check with a 3xx. It must deny, not ride
    // on_error: allow and serve every request unmetered.
    for status in [301_u16, 308] {
        let t = Arc::new(FakeTransport::new().json("/check", status, ""));
        let handler = QuotaCheck::new(core("allow"));
        let mut ctx = PluginContext::new();
        let result = handler
            .handle(&input_payload(), &ext_with_sub("bob", t), &mut ctx)
            .await;
        assert!(
            result.is_denied(),
            "a {status} must fail closed even under on_error: allow"
        );
        let violation = result.violation.expect("a denial carries a violation");
        assert_eq!(violation.code, "quota.backend_unavailable");
    }
}

/// A stateful in-process transport that models the real Limitador counter:
/// `/check` with the plugin's probe delta of 1 refuses once the counter would
/// exceed `max`, and `/report` increments unconditionally. This is what a
/// fixed-response script cannot express, and it is what proves the debit path
/// accumulates.
#[derive(Debug)]
struct CountingLimitador {
    counter: Mutex<u64>,
    max: u64,
    reports: std::sync::atomic::AtomicU64,
    latency: Option<std::time::Duration>,
}

impl CountingLimitador {
    fn new(max: u64) -> Self {
        Self {
            counter: Mutex::new(0),
            max,
            reports: std::sync::atomic::AtomicU64::new(0),
            latency: None,
        }
    }

    /// Answer each call only after `latency`, counting a /report once it lands.
    fn with_latency(mut self, latency: std::time::Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// How many /report calls have landed, so a test can wait for the spawned
    /// debit before the next check reads the counter.
    fn reports_seen(&self) -> u64 {
        self.reports.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn delta(body: &Bytes) -> u64 {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("delta").and_then(serde_json::Value::as_u64))
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl HttpTransport for CountingLimitador {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        if let Some(latency) = self.latency {
            tokio::time::sleep(latency).await;
        }
        let delta = Self::delta(&req.body);
        // No await while the guard is held: compute the status, then answer.
        let status = {
            let mut counter = self
                .counter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if req.url.contains("/report") {
                *counter += delta;
                self.reports
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                200
            } else if *counter + delta > self.max {
                429
            } else {
                200
            }
        };
        Ok(HttpResponse::new(status, Bytes::new()))
    }
}

#[tokio::test]
async fn a_principal_is_denied_once_cumulative_debits_reach_the_budget() {
    // Budget 100, debit 40 per round. The check runs before each round's
    // debit, so counters 0, 40, 80 all admit. The debits carry the counter
    // to 120, and the fourth check refuses. This drives the whole loop the
    // plugin exists to close, against a Limitador that counts.
    let lim = Arc::new(CountingLimitador::new(100));
    let t: Arc<dyn HttpTransport> = lim.clone();
    let check = QuotaCheck::new(core("deny"));
    let report = QuotaReport::new(core("deny"));
    let mut ctx = PluginContext::new();

    for round in 0..3_u64 {
        let admitted = check
            .handle(
                &input_payload(),
                &ext_with_sub("bob", Arc::clone(&t)),
                &mut ctx,
            )
            .await;
        assert!(!admitted.is_denied(), "round {round} must be admitted");
        let debit = report
            .handle(
                &output_payload("done"),
                &ext_with_sub_and_usage("bob", 40, Arc::clone(&t)),
                &mut ctx,
            )
            .await;
        assert!(!debit.is_denied(), "the report hook never denies");
        // The debit is spawned; the counter must catch up before the next check.
        eventually(|| lim.reports_seen() == round + 1).await;
    }

    let denied = check
        .handle(
            &input_payload(),
            &ext_with_sub("bob", Arc::clone(&t)),
            &mut ctx,
        )
        .await;
    assert!(denied.is_denied(), "a principal over budget must be denied");
    let violation = denied.violation.expect("a denial carries a violation");
    assert_eq!(violation.code, "quota.exhausted");
}

#[tokio::test]
async fn shutdown_drains_an_in_flight_debit_so_it_lands() {
    // A debit still in flight at shutdown must land, not be dropped with the
    // task. shutdown returns only after the slow /report has been counted.
    let lim =
        Arc::new(CountingLimitador::new(100).with_latency(std::time::Duration::from_millis(100)));
    let core = core("deny");
    let out = QuotaReport::new(Arc::clone(&core))
        .handle(
            &output_payload("done"),
            &ext_with_sub_and_usage("bob", 40, lim.clone()),
            &mut PluginContext::new(),
        )
        .await;
    assert!(!out.is_denied());
    assert_eq!(lim.reports_seen(), 0, "the debit is still in flight");

    core.shutdown().await.expect("shutdown succeeds");
    assert_eq!(
        lim.reports_seen(),
        1,
        "shutdown must drain the in-flight debit"
    );
}

#[tokio::test]
async fn shutdown_drains_a_failing_debit_so_it_is_recorded_pending() {
    // A debit that fails while shutdown drains it must still be recorded as
    // pending, so the principal is denied until it settles.
    let core = core("deny");
    let t_fail = Arc::new(
        FakeTransport::new()
            .with_latency(std::time::Duration::from_millis(100))
            .json("/report", 500, ""),
    );
    let out = QuotaReport::new(Arc::clone(&core))
        .handle(
            &output_payload("done"),
            &ext_with_sub_and_usage("bob", 11, as_transport(&t_fail)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(!out.is_denied());

    core.shutdown().await.expect("shutdown succeeds");

    let t_still = Arc::new(
        FakeTransport::new()
            .json("/report", 500, "")
            .json("/check", 200, ""),
    );
    let denied = QuotaCheck::new(Arc::clone(&core))
        .handle(
            &input_payload(),
            &ext_with_sub("bob", as_transport(&t_still)),
            &mut PluginContext::new(),
        )
        .await;
    assert!(
        denied.is_denied(),
        "the drained failed debit must be pending"
    );
    assert_eq!(
        denied.violation.expect("a denial carries a violation").code,
        "quota.unsettled_debit"
    );
}
