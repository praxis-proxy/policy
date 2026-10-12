// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The policy-engine demo scenarios 01 to 12, each run against the Cedar,
//! CEL and OPA fixtures.
//!
//! Source of truth: `praxis-demos/demos/policy-engine/scenarios/*.sh` and
//! their `_lib.sh`. Arguments, personas and expected codes match the
//! scripts.

use praxis_policy_test_utils::fixtures::{CLIENT_SECRET, Fixture};
use praxis_policy_test_utils::host::{Call, Outcome, RefHost};
use praxis_policy_test_utils::idp::GATEWAY_AUDIENCE;
use praxis_policy_test_utils::secrets::Planted;
use serde_json::{Value, json};

mod adjust_compensation;
mod alice_deny;
mod assertions;
mod bob_allow;
mod ciba_approval;
mod eve_redact;
mod live;
mod pii;
mod repo_access;
mod taint;

/// The value `_lib.sh` sends as `args.ssn`, so a redact is visible upstream.
const SSN_PROBE: &str = "would-be-removed-if-redact-fires";

/// Run `scenario` once per PDP fixture, in order. A failure is re-raised
/// with the PDP name in front of its message.
///
/// Each run is a task on the test's current-thread runtime, so the
/// reference host's log capture still sees the plugin tasks it spawns.
async fn each_pdp<F, Fut>(scenario: F)
where
    F: Fn(Fixture) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    for fixture in Fixture::ALL {
        if let Err(err) = tokio::spawn(scenario(fixture)).await {
            let payload = err.into_panic();
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "non-string panic".to_owned());
            panic!("[{}] {message}", fixture.name());
        }
    }
}

/// `call_get_compensation` for Jane Smith.
fn jane(include_ssn: bool) -> Value {
    json!({ "employee_id": "EMP-001234", "include_ssn": include_ssn, "ssn": SSN_PROBE })
}

/// `call_send_email` with its default, clean body.
fn clean_email() -> Value {
    json!({
        "to": "partner@example.com",
        "subject": "FYI",
        "body": "Quarterly planning notes, nothing sensitive here.",
    })
}

/// `adjust_compensation_body` for Jane Smith.
fn adjust(amount: i64) -> Value {
    json!({ "employee_id": "EMP-001234", "amount": amount })
}

/// The call's own tokens plus the gateway's client secret.
fn planted(call: &Call) -> Planted {
    let mut planted = call.planted();
    planted.plant("client secret", CLIENT_SECRET);
    planted
}

/// Plant the bearer the upstream received when the identity provider minted
/// it, that is when its audience is not the gateway's own.
fn plant_minted(planted: &mut Planted, outcome: &Outcome) {
    let Some(seen) = &outcome.upstream else {
        return;
    };
    let minted = seen
        .jwt_claims("authorization")
        .is_some_and(|c| c["aud"] != GATEWAY_AUDIENCE);
    if minted && let Some(bearer) = seen.headers.get("authorization") {
        planted.plant("minted token", bearer.trim_start_matches("Bearer "));
    }
}

/// How many requests the upstream has received so far.
fn upstream_calls(host: &RefHost) -> usize {
    host.upstream().requests().len()
}

/// The audit records `outcome` captured for `tool`.
fn audit_for(outcome: &Outcome, tool: &str) -> Vec<Value> {
    outcome
        .events
        .audit_records()
        .into_iter()
        .filter(|r| r["entity"]["name"] == tool)
        .collect()
}
