// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A dependency endpoint on loopback, reached through the bundled
//! `HyperTransport` with private destinations disallowed.
//!
//! The reference host does not reproduce praxis's SSRF-checking transport,
//! so this is the one full-engine SSRF check. It drives the engine directly:
//! identity and `cmf.tool_pre_invoke` in the host's order, with JWKS served
//! by the scripted `IdP` and every other call going through the real
//! transport.
//!
//! Transport-level mapping: `loopback_is_rejected_unless_the_hatch_is_set`
//! in `crates/ppe/src/http_hyper.rs`. Plugin-level:
//! `a_host_refusal_is_reported_as_egress_denied_and_not_retried` in
//! `crates/builtins/tests/oauth/oauth_e2e.rs` and
//! `a_host_refusal_is_reported_as_egress_denied` in
//! `crates/builtins/tests/ciba/ciba_e2e.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use praxis_policy::HyperTransport;
use praxis_policy_core::cmf::CmfHook;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_test_utils::fixtures::{CLIENT_SECRET, Fixture};
use praxis_policy_test_utils::idp::{self, CIBA_BACKCHANNEL_URL, Persona, TOKEN_EXCHANGE_URL};
use praxis_policy_test_utils::secrets::Planted;
use praxis_policy_test_utils::{host, mcp};
use serde_json::json;

/// The scripted `IdP` for JWKS, the real transport for everything else.
#[derive(Debug)]
struct Split {
    jwks: FakeTransport,
    real: HyperTransport,
}

#[async_trait]
impl HttpTransport for Split {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        if req.url.starts_with(idp::JWKS_URL) {
            self.jwks.execute(req).await
        } else {
            self.real.execute(req).await
        }
    }
}

#[tokio::test]
async fn a_dependency_on_loopback_is_refused_with_the_egress_code() {
    let rows = [
        (
            "token endpoint on 127.0.0.1",
            TOKEN_EXCHANGE_URL,
            "https://127.0.0.1:9/token",
            "get_compensation",
            json!({ "employee_id": "EMP-001234" }),
            "delegation.egress_denied",
        ),
        (
            "token endpoint on localhost",
            TOKEN_EXCHANGE_URL,
            "https://localhost:9/token",
            "get_compensation",
            json!({ "employee_id": "EMP-001234" }),
            "delegation.egress_denied",
        ),
        (
            "CIBA backchannel on [::1]",
            CIBA_BACKCHANNEL_URL,
            "https://[::1]:9/ciba",
            "adjust_compensation",
            json!({ "employee_id": "EMP-001234", "amount": 25_000 }),
            "elicitation.egress_denied",
        ),
    ];
    for (row, from, to, tool, args, code) in rows {
        let yaml = Fixture::Cedar.hermetic().replace(from, to);
        let jwks = FakeTransport::new().json(idp::JWKS_URL, 200, &idp::jwks().to_string());
        let engine = host::engine(Vec::new());
        engine.set_http_transport(Arc::new(Split {
            jwks,
            real: HyperTransport::new(),
        }));
        engine.load_config_yaml(&yaml).expect("load");
        engine.initialize().await.expect("initialize");

        let headers: HashMap<String, String> = [
            ("content-type", "application/json".to_owned()),
            ("x-user-token", Persona::Bob.token()),
            (
                "authorization",
                format!("Bearer {}", Persona::HrCopilot.token()),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let payload =
            IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers.clone());
        let ext = mcp::tool_extensions(Extensions::default(), tool, &headers, None);
        let (resolved, _bg) = engine
            .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, ext, None)
            .await;
        assert!(
            resolved.continue_processing,
            "{row}: {:?}",
            resolved.violation
        );
        let identity = IdentityPayload::from_pipeline_result(&resolved).expect("an identity");

        let ext = mcp::tool_extensions(
            identity.apply_to_extensions(Extensions::default()),
            tool,
            &headers,
            None,
        );
        let (pre, _bg) = engine
            .invoke_named::<CmfHook>(
                "cmf.tool_pre_invoke",
                mcp::tool_call("call-1", tool, &args),
                ext,
                None,
            )
            .await;
        assert!(!pre.continue_processing, "{row}: the call was allowed");
        let violation = pre.violation.as_ref().expect("a violation");
        assert_eq!(violation.code, code, "{row}: {violation:?}");
        assert_ne!(
            violation.proto_error_code,
            Some(-32_120),
            "{row}: not pending"
        );
        let minted = pre
            .modified_extensions
            .as_ref()
            .and_then(|e| e.raw_credentials.as_deref())
            .map_or(0, |raw| raw.delegated_tokens.len());
        assert_eq!(minted, 0, "{row}: no token to attach");
        let mut planted = Planted::new();
        planted.plant("user token", headers["x-user-token"].clone());
        planted.plant("client secret", CLIENT_SECRET);
        planted.assert_absent_json(
            "the violation",
            &serde_json::to_value(violation).expect("serialize the violation for leak checking"),
        );
    }
}
