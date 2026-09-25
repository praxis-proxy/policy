// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// LimitadorClient, a QuotaBackend over Limitador's HTTP API. `check` probes
// {endpoint}/check with a delta of one (200 within limit, 429 over) and
// `report` debits via {endpoint}/report. /check_and_report is avoided: it
// skips the increment on a 429, freezing the counter at the limit.
//
// The client owns no HTTP stack. Every call goes through the host transport
// reached from `Extensions`, gated by the `perform_http` capability, so the
// connection pool and TLS live in the host and not in this plugin.

use async_trait::async_trait;
use bytes::Bytes;
use praxis_policy_core::hooks::Extensions;
use praxis_policy_core::host::HostServices as _;
use praxis_policy_core::http::HttpRequest;
use praxis_policy_core::http_retry::RetryPolicy;
use serde_json::json;

use praxis_policy_core::host::HttpRequestError;
use praxis_policy_core::http::HttpTransportError;

use super::backend::{BackendError, BackendErrorKind, CheckOutcome, QuotaBackend};

/// The check probes with a delta of one, so it denies once the counter
/// reaches the limit. It charges nothing. The debit happens in `report`.
const CHECK_PROBE_DELTA: u64 = 1;

/// Limitador answers `/check` and `/report` with a bare 200, and 429 for an
/// over-budget `/check`. Only the status is read; the body is ignored.
const STATUS_OK: u16 = 200;

/// Over-budget verdict from `/check`.
const STATUS_TOO_MANY_REQUESTS: u16 = 429;

/// Bound to one Limitador endpoint and namespace. Holds no HTTP client: the
/// transport arrives per call as `&Extensions`.
#[derive(Debug)]
pub(crate) struct LimitadorClient {
    namespace: String,
    check_url: String,
    report_url: String,
    timeout: std::time::Duration,
}

impl LimitadorClient {
    /// Build the client for `endpoint`/`namespace` with a per-call `timeout`.
    /// A trailing slash on `endpoint` is trimmed.
    pub(crate) fn new(endpoint: &str, namespace: &str, timeout: std::time::Duration) -> Self {
        let endpoint = endpoint.trim_end_matches('/');
        Self {
            namespace: namespace.to_owned(),
            check_url: format!("{endpoint}/check"),
            report_url: format!("{endpoint}/report"),
            timeout,
        }
    }

    /// POST `body` as JSON to `url` through the host transport, returning the
    /// response status.
    async fn send(
        &self,
        ext: &Extensions,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<u16, BackendError> {
        let encoded = serde_json::to_vec(body).map_err(|e| BackendError {
            message: format!("Limitador request body could not be encoded: {e}"),
            kind: BackendErrorKind::Unavailable,
        })?;
        let request = HttpRequest::post(url, Bytes::from(encoded))
            .timeout(self.timeout)
            .header("content-type", "application/json")
            .map_err(|e| BackendError {
                message: format!("Limitador request to {url} could not be built: {e}"),
                kind: BackendErrorKind::Unavailable,
            })?;
        // One attempt per call. `/report` increments unconditionally, so a
        // repeated POST would double-charge; `/check` only probes (delta=1,
        // charges nothing), but retrying it on the admission hot path adds tail
        // latency for no correctness gain. So neither call retries.
        ext.http_request(request, RetryPolicy::none())
            .await
            .map(|response| response.status)
            .map_err(|e| BackendError {
                message: format!("Limitador POST {url} failed: {e}"),
                kind: classify(&e),
            })
    }
}

/// Sort a failed host call into a [`BackendErrorKind`].
///
/// The distinction the handler acts on is "does `on_error` apply?" Only a
/// genuine transient failure to a reachable-or-maybe-reachable peer (timeout,
/// refused connection, dropped socket, oversize response) does. A withheld
/// capability, an uninstalled transport, or a request the host refused to send
/// never reached Limitador and no retry fixes it, so those fail closed
/// regardless of `on_error`. `Rejected` is called out on its own so the denial
/// names egress.
///
/// The transient set is enumerated rather than caught with a wildcard:
/// [`HttpTransportError`] is `#[non_exhaustive]`, so a future variant this
/// crate has not seen falls to the final arm and fails closed, never serving
/// unmetered under `on_error: allow` on a failure whose meaning is unknown.
fn classify(err: &HttpRequestError) -> BackendErrorKind {
    match err {
        HttpRequestError::Unavailable(_) => BackendErrorKind::Unavailable,
        HttpRequestError::Transport(HttpTransportError::Rejected(_)) => {
            BackendErrorKind::EgressDenied
        },
        HttpRequestError::Transport(
            HttpTransportError::Timeout
            | HttpTransportError::Connect(_)
            | HttpTransportError::Io(_)
            | HttpTransportError::ResponseTooLarge { .. },
        ) => BackendErrorKind::Transport,
        // A malformed request (permanent local fault) and any variant this
        // crate does not yet model both fail closed.
        HttpRequestError::Transport(_) => BackendErrorKind::Unavailable,
    }
}

#[async_trait]
impl QuotaBackend for LimitadorClient {
    async fn check(
        &self,
        ext: &Extensions,
        descriptor_key: &str,
        descriptor_value: &str,
    ) -> Result<CheckOutcome, BackendError> {
        let body = json!({
            "namespace": self.namespace,
            "values": { descriptor_key: descriptor_value },
            "delta": CHECK_PROBE_DELTA,
        });
        let status = self.send(ext, &self.check_url, &body).await?;
        match status {
            STATUS_OK => Ok(CheckOutcome::WithinLimit),
            STATUS_TOO_MANY_REQUESTS => Ok(CheckOutcome::OverLimit),
            other => Err(BackendError {
                message: format!("Limitador /check returned unexpected status {other}"),
                kind: BackendErrorKind::Transport,
            }),
        }
    }

    async fn report(
        &self,
        ext: &Extensions,
        descriptor_key: &str,
        descriptor_value: &str,
        delta: u64,
    ) -> Result<(), BackendError> {
        let body = json!({
            "namespace": self.namespace,
            "values": { descriptor_key: descriptor_value },
            "delta": delta,
        });
        let status = self.send(ext, &self.report_url, &body).await?;
        if status == STATUS_OK {
            return Ok(());
        }
        Err(BackendError {
            message: format!("Limitador /report returned unexpected status {status}"),
            kind: BackendErrorKind::Transport,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use praxis_policy_core::host::HttpTransportSlot;
    use praxis_policy_core::http::HttpTransport;
    use praxis_policy_core::http_testing::FakeTransport;

    fn client() -> LimitadorClient {
        LimitadorClient::new(
            "http://limitador.test",
            "grid-tokens",
            Duration::from_secs(5),
        )
    }

    /// An `Extensions` whose `perform_http` slot holds `transport`.
    fn ext_with(transport: &Arc<FakeTransport>) -> Extensions {
        let http: Arc<dyn HttpTransport> = transport.clone();
        Extensions {
            http_transport: HttpTransportSlot::installed(http),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn check_200_is_within_limit() {
        let t = Arc::new(FakeTransport::new().json("/check", 200, ""));
        let outcome = client().check(&ext_with(&t), "sub", "bob").await.unwrap();
        assert_eq!(outcome, CheckOutcome::WithinLimit);
        assert_eq!(t.call_count_for("/check"), 1, "check must issue one POST");
    }

    #[tokio::test]
    async fn check_429_is_over_limit() {
        let t = Arc::new(FakeTransport::new().json("/check", 429, ""));
        let outcome = client().check(&ext_with(&t), "sub", "bob").await.unwrap();
        assert_eq!(outcome, CheckOutcome::OverLimit);
    }

    #[tokio::test]
    async fn check_sends_namespace_and_descriptor() {
        let t = Arc::new(FakeTransport::new().json("/check", 200, ""));
        client().check(&ext_with(&t), "sub", "bob").await.unwrap();
        let req = t.last_request().expect("a request was sent");
        let body = String::from_utf8_lossy(&req.body);
        assert!(body.contains(r#""namespace":"grid-tokens""#), "{body}");
        assert!(body.contains(r#""sub":"bob""#), "{body}");
        assert!(body.contains(r#""delta":1"#), "{body}");
        assert_eq!(
            req.headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "the JSON body must carry a JSON content type"
        );
    }

    #[tokio::test]
    async fn check_unexpected_status_is_an_error() {
        let t = Arc::new(FakeTransport::new().json("/check", 500, ""));
        let err = client()
            .check(&ext_with(&t), "sub", "bob")
            .await
            .unwrap_err();
        assert!(err.message.contains("500"), "{}", err.message);
        // An unrecognized status is the backend answering oddly, so on_error
        // governs it.
        assert_eq!(err.kind, BackendErrorKind::Transport);
    }

    #[tokio::test]
    async fn report_sends_delta() {
        let t = Arc::new(FakeTransport::new().json("/report", 200, ""));
        client()
            .report(&ext_with(&t), "sub", "bob", 42)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&t.last_request().expect("a request").body).into_owned();
        assert!(body.contains(r#""delta":42"#), "{body}");
        assert!(body.contains(r#""sub":"bob""#), "{body}");
    }

    #[tokio::test]
    async fn report_treats_a_non_200_as_an_error() {
        // /report increments unconditionally and answers 200. Anything else
        // is a real failure the caller logs.
        let t = Arc::new(FakeTransport::new().json("/report", 500, ""));
        let err = client()
            .report(&ext_with(&t), "sub", "bob", 10)
            .await
            .unwrap_err();
        assert!(err.message.contains("500"), "{}", err.message);
    }

    #[tokio::test]
    async fn a_transport_failure_errors() {
        // A connect failure from the host transport must surface as a backend
        // error rather than a panic, so the caller can apply `on_error`.
        let t = Arc::new(
            FakeTransport::new().fail("/check", HttpTransportError::Connect("refused".to_owned())),
        );
        let err = client()
            .check(&ext_with(&t), "sub", "bob")
            .await
            .unwrap_err();
        assert!(err.message.contains("failed"), "{}", err.message);
        // A reachable-but-failing Limitador is transient, so on_error governs.
        assert_eq!(err.kind, BackendErrorKind::Transport);
    }

    #[tokio::test]
    async fn a_withheld_transport_errors_and_names_the_capability() {
        // No `perform_http` grant: the call must fail (so the caller's
        // fail-closed posture applies) and the message must name the fix.
        let ext = Extensions {
            http_transport: HttpTransportSlot::withheld(),
            ..Default::default()
        };
        let err = client().check(&ext, "sub", "bob").await.unwrap_err();
        assert!(err.message.contains("perform_http"), "{}", err.message);
        // A withheld capability is a permanent misconfiguration: on_error must
        // not apply, so the kind is Unavailable, not Transport.
        assert_eq!(err.kind, BackendErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn an_egress_denied_call_is_classified_distinctly() {
        // The host refusing the call (egress policy / SSRF guard) never reaches
        // Limitador, so it must fail closed like a withheld capability, but with
        // its own kind so the denial can name egress rather than the backend.
        let t = Arc::new(
            FakeTransport::new().fail("/check", HttpTransportError::Rejected("egress".to_owned())),
        );
        let err = client()
            .check(&ext_with(&t), "sub", "bob")
            .await
            .unwrap_err();
        assert_eq!(err.kind, BackendErrorKind::EgressDenied);
    }

    #[tokio::test]
    async fn a_malformed_request_fails_closed() {
        // InvalidRequest is a permanent local fault, not a transient peer
        // problem, so it classifies as Unavailable (fail closed), never
        // Transport, and never rides on_error.
        let t = Arc::new(FakeTransport::new().fail(
            "/check",
            HttpTransportError::InvalidRequest("bad".to_owned()),
        ));
        let err = client()
            .check(&ext_with(&t), "sub", "bob")
            .await
            .unwrap_err();
        assert_eq!(err.kind, BackendErrorKind::Unavailable);
    }
}
