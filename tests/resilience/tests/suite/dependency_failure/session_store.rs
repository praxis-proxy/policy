// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The session store fails at request time, on loading a session's taint
//! labels or on appending to them.
//!
//! Engine-level mapping: `route_handler.rs` in `ppe-apl-runtime` denies with
//! `session.load_failed` or `session.persist_failed`. The Valkey store's own
//! error mapping is in `crates/builtins/tests/valkey`.

use std::sync::Arc;

use async_trait::async_trait;
use praxis_policy::praxis_policy_apl_runtime::SessionStoreError;
use praxis_policy::{SessionStore, SessionStoreFactory};
use praxis_policy_test_utils::fixtures::{CLIENT_SECRET, Fixture};
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{Persona, TOKEN_EXCHANGE_URL};
use serde_json::json;

use super::assert_fail_closed;

const KIND: &str = "test/failing-store";

/// Which operation fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fails {
    Load,
    Append,
}

/// A store that reaches its backend at build time and loses it on `fails`.
struct FailingStore(Fails);

#[async_trait]
impl SessionStore for FailingStore {
    async fn load_labels(&self, _session_id: &str) -> Result<Vec<String>, SessionStoreError> {
        match self.0 {
            Fails::Load => Err(SessionStoreError::Backend("connection reset".to_owned())),
            Fails::Append => Ok(Vec::new()),
        }
    }

    async fn append_labels(
        &self,
        _session_id: &str,
        _labels: &[String],
    ) -> Result<(), SessionStoreError> {
        match self.0 {
            Fails::Load => Ok(()),
            Fails::Append => Err(SessionStoreError::Backend("READONLY replica".to_owned())),
        }
    }
}

/// Builds a [`FailingStore`] from `fail: load` or `fail: append`.
struct FailingStoreFactory;

impl SessionStoreFactory for FailingStoreFactory {
    fn kind(&self) -> &str {
        KIND
    }

    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn SessionStore>, Box<dyn std::error::Error + Send + Sync>> {
        let fails = match config.get("fail").and_then(serde_yaml::Value::as_str) {
            Some("load") => Fails::Load,
            Some("append") => Fails::Append,
            other => return Err(format!("fail: {other:?}").into()),
        };
        Ok(Arc::new(FailingStore(fails)))
    }
}

async fn host_whose_store_fails(fails: Fails) -> RefHost {
    let op = match fails {
        Fails::Load => "load",
        Fails::Append => "append",
    };
    let yaml = Fixture::Cedar.hermetic().replacen(
        "\nroutes:",
        &format!("\n  session_store:\n    kind: {KIND}\n    fail: {op}\n\nroutes:"),
        1,
    );
    RefHost::builder()
        .session_store(Arc::new(FailingStoreFactory))
        .start(&yaml)
        .await
        .expect("the store builds; it fails per request")
}

fn compensation() -> Call {
    Call::new(Persona::Bob, "get_compensation").args(json!({ "employee_id": "EMP-001234" }))
}

fn email() -> Call {
    Call::new(Persona::Bob, "send_email")
        .args(json!({ "to": "partner@example.com", "body": "hello" }))
}

/// A session whose labels cannot be loaded denies before any policy step,
/// on the route that taints and on the route that checks the taint. Neither
/// proceeds as an untainted session. Without `X-Session-Id` the session is
/// derived from the identity, so an authenticated call always has one.
#[tokio::test]
async fn a_failed_label_load_denies_every_session_bearing_call() {
    let rows = [
        ("tainting route", compensation().session("s-load")),
        ("taint check", email().session("s-load")),
        ("identity-derived session", email()),
    ];
    for (row, call) in rows {
        let host = host_whose_store_fails(Fails::Load).await;
        let mut planted = call.planted();
        planted.plant("client secret", CLIENT_SECRET);
        let out = host.call(call).await;
        assert_fail_closed(
            &host,
            &out,
            Stage::Request,
            "session.load_failed",
            &planted,
            row,
        );
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{row}: nothing delegates before the load"
        );
    }
}

/// A taint that cannot be persisted flips an allow to deny. The exchange
/// already minted a token, and it is withheld from the upstream.
#[tokio::test]
async fn a_failed_taint_append_denies_and_withholds_the_minted_token() {
    let host = host_whose_store_fails(Fails::Append).await;
    let call = compensation().session("s-append");
    let mut planted = call.planted();
    planted.plant("client secret", CLIENT_SECRET);
    let out = host.call(call).await;
    assert_fail_closed(
        &host,
        &out,
        Stage::Request,
        "session.persist_failed",
        &planted,
        "append",
    );
    assert_eq!(
        host.transport().call_count_for(TOKEN_EXCHANGE_URL),
        1,
        "the token was minted before the append"
    );
}
