// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end behavior of the two hook handlers against a scripted Limitador.
//!
//! The rows the plugin exists to get right: over budget denies, under budget
//! allows, an unreachable or ungranted Limitador honors `on_error`, and an
//! output with no usage debits nothing and never denies. Limitador is scripted
//! through the host transport rather than a mock server, so the same
//! `perform_http` seam the plugin uses in production is what the tests drive.

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

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
use praxis_policy_core::plugin::PluginConfig;
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
async fn report_debits_the_parsed_total() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    let body = r#"{"choices":[],"usage":{"prompt_tokens":5,"total_tokens":11}}"#;
    let result = handler
        .handle(
            &output_payload(body),
            &ext_with_sub("bob", as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied(), "the report hook never denies");
    let sent =
        String::from_utf8_lossy(&t.last_request().expect("a debit was posted").body).into_owned();
    assert!(sent.contains(r#""delta":11"#), "{sent}");
    assert!(sent.contains(r#""sub":"bob""#), "{sent}");
}

#[tokio::test]
async fn report_debits_nothing_when_usage_absent() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    // Streaming chunk with no usage object.
    let body = r#"{"choices":[{"delta":{"content":"hi"}}]}"#;
    let result = handler
        .handle(
            &output_payload(body),
            &ext_with_sub("bob", as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied(), "an absent total must never deny");
    assert_eq!(t.call_count_for("/report"), 0, "no usage means no debit");
}

#[tokio::test]
async fn report_never_denies_even_when_the_debit_fails() {
    // Limitador answers the debit with a 500. The response is already out,
    // so this must be swallowed, not turned into a denial.
    let t = Arc::new(FakeTransport::new().json("/report", 500, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    let body = r#"{"usage":{"total_tokens":11}}"#;
    let result = handler
        .handle(&output_payload(body), &ext_with_sub("bob", t), &mut ctx)
        .await;
    assert!(!result.is_denied(), "a failed debit must never deny");
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
    let sent = String::from_utf8_lossy(&t.last_request().expect("a debit").body).into_owned();
    assert!(sent.contains(r#""delta":25"#), "{sent}");
    assert!(sent.contains(r#""sub":"alice""#), "{sent}");
}

#[tokio::test]
async fn report_prefers_the_typed_usage_over_a_body_total() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    // A hostile body claiming a tiny cost must not win over the typed slot.
    let body = r#"{"usage":{"total_tokens":1}}"#;
    let result = handler
        .handle(
            &output_payload(body),
            &ext_with_sub_and_usage("alice", 25, as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied());
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
async fn report_refuses_a_fractional_body_total() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    // No typed slot; a fractional body total is not a token count.
    let body = r#"{"usage":{"total_tokens":1.5}}"#;
    let result = handler
        .handle(
            &output_payload(body),
            &ext_with_sub("bob", as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied());
    assert_eq!(t.call_count_for("/report"), 0, "a float is not a debit");
}

#[tokio::test]
async fn report_ignores_a_negative_body_total() {
    let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
    let handler = QuotaReport::new(core("allow"));
    let mut ctx = PluginContext::new();
    let body = r#"{"usage":{"total_tokens":-5}}"#;
    let result = handler
        .handle(
            &output_payload(body),
            &ext_with_sub("bob", as_transport(&t)),
            &mut ctx,
        )
        .await;
    assert!(!result.is_denied());
    assert_eq!(t.call_count_for("/report"), 0, "a negative is not a debit");
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

/// A stateful in-process transport that models the real Limitador counter:
/// `/check` with the plugin's probe delta of 1 refuses once the counter would
/// exceed `max`, and `/report` increments unconditionally. This is what a
/// fixed-response script cannot express, and it is what proves the debit path
/// accumulates.
#[derive(Debug)]
struct CountingLimitador {
    counter: Mutex<u64>,
    max: u64,
}

impl CountingLimitador {
    fn new(max: u64) -> Self {
        Self {
            counter: Mutex::new(0),
            max,
        }
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
        let delta = Self::delta(&req.body);
        // No await while the guard is held: compute the status, then answer.
        let status = {
            let mut counter = self
                .counter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if req.url.contains("/report") {
                *counter += delta;
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
    let t: Arc<dyn HttpTransport> = Arc::new(CountingLimitador::new(100));
    let check = QuotaCheck::new(core("deny"));
    let report = QuotaReport::new(core("deny"));
    let mut ctx = PluginContext::new();

    for round in 0..3 {
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
