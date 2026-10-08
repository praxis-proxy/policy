// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! In-process request ID mapping contract tests (issue #156). The current
//! fixtures use synthetic host metadata and source-derived Authorino decision
//! expectations, not captured reference results. They do not establish live
//! parity. This module runs each predicate through the real CEL and OPA
//! resolvers with Kuadrant compat enabled and checks PPE's `expected` decision.
//! Test-only (the loader and structs
//! are used solely by the tests below, and this crate denies `dead_code`).
//!
//! Vertical slice: the committed fixtures cover `request.id` only.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only Authorino fixture loader and differential"
)]

use std::path::PathBuf;

use serde::Deserialize;

/// Source-derived Authorino expectation; current fixtures are not live captures.
#[derive(Debug, Deserialize)]
struct Authorino {
    decision: String,
    #[serde(default)]
    #[allow(dead_code, reason = "documentation field, read by humans not tests")]
    reference: String,
}

/// One Authorino reference fixture.
#[derive(Debug, Deserialize)]
struct Fixture {
    attribute: String,
    status: String,
    request: serde_json::Value,
    predicate_cel: String,
    predicate_opa: String,
    authorino: Authorino,
    expected: String,
}

/// Load every `*.json` fixture under `fixtures/authorino/request/`. A missing
/// field is a hard deserialize error (no silent skip).
fn load_fixtures() -> Vec<Fixture> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/authorino/request");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixtures/authorino/request must exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let fixture: Fixture =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        out.push(fixture);
    }
    assert!(
        !out.is_empty(),
        "no Authorino fixtures found in {}",
        dir.display()
    );
    out
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    use praxis_policy_apl_core::attributes::AttributeBag;
    use praxis_policy_apl_core::evaluator::Decision;
    use praxis_policy_apl_core::step::{PdpCall, PdpDialect, PdpResolver as _};

    /// Build a bag from the fixture's `request` object. `id` represents the
    /// host-supplied request metadata, the source of Kuadrant `request.id`;
    /// request-line and headers land on `http.*`.
    fn bag_from_fixture(req: &serde_json::Value) -> AttributeBag {
        let mut bag = AttributeBag::new();
        if let Some(m) = req.get("method").and_then(|v| v.as_str()) {
            bag.set("http.method", m);
        }
        if let Some(p) = req.get("path").and_then(|v| v.as_str()) {
            bag.set("http.path", p);
        }
        if let Some(h) = req.get("host").and_then(|v| v.as_str()) {
            bag.set("http.host", h);
        }
        if let Some(s) = req.get("scheme").and_then(|v| v.as_str()) {
            bag.set("http.scheme", s);
        }
        if let Some(id) = req.get("id").and_then(|v| v.as_str()) {
            bag.set("request.request_id", id);
        }
        if let Some(hdrs) = req.get("headers").and_then(|v| v.as_object()) {
            for (k, v) in hdrs {
                if let Some(s) = v.as_str() {
                    bag.set(format!("http.request_headers.{k}"), s);
                }
            }
        }
        bag
    }

    async fn eval_cel(expr: &str, bag: &AttributeBag) -> Decision {
        let r = praxis_policy_builtins::pdps::cel::CelResolver::new().with_kuadrant_compat(true);
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("expr".into()),
            serde_yaml::Value::String(expr.to_owned()),
        );
        r.evaluate(
            &PdpCall {
                dialect: PdpDialect::Cel,
                args: serde_yaml::Value::Mapping(m),
            },
            bag,
        )
        .await
        .unwrap()
        .decision
    }

    async fn eval_opa(module: &str, bag: &AttributeBag) -> Decision {
        let r = praxis_policy_builtins::pdps::opa::OpaResolver::from_config(
            &serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        )
        .unwrap()
        .with_kuadrant_compat(true);
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            serde_yaml::Value::String("query".into()),
            serde_yaml::Value::String("data.t.allow".into()),
        );
        m.insert(
            serde_yaml::Value::String("module".into()),
            serde_yaml::Value::String(module.to_owned()),
        );
        r.evaluate(
            &PdpCall {
                dialect: PdpDialect::Opa,
                args: serde_yaml::Value::Mapping(m),
            },
            bag,
        )
        .await
        .unwrap()
        .decision
    }

    fn is_allow(d: &Decision) -> bool {
        matches!(d, Decision::Allow)
    }

    /// Check fixture expectations for internal consistency. Agreement with a
    /// source-derived expectation does not establish observed Authorino parity.
    #[test]
    fn every_fixture_has_both_decisions() {
        for f in load_fixtures() {
            assert!(
                matches!(f.authorino.decision.as_str(), "allow" | "deny"),
                "fixture {} authorino.decision must be allow|deny",
                f.attribute
            );
            assert!(
                matches!(f.expected.as_str(), "allow" | "deny"),
                "fixture {} expected must be allow|deny",
                f.attribute
            );
            if f.status == "Gap" {
                assert_ne!(
                    f.expected, f.authorino.decision,
                    "Gap fixture {} must diverge from Authorino",
                    f.attribute
                );
            } else {
                assert_eq!(
                    f.expected, f.authorino.decision,
                    "Mapped fixture {} must agree with its Authorino expectation",
                    f.attribute
                );
            }
        }
    }

    #[tokio::test]
    async fn cel_pipeline_matches_expected() {
        for f in load_fixtures() {
            let got = is_allow(&eval_cel(&f.predicate_cel, &bag_from_fixture(&f.request)).await);
            assert_eq!(
                got,
                f.expected == "allow",
                "CEL fixture {} ({}): expected PPE={}, authorino={}",
                f.attribute,
                f.status,
                f.expected,
                f.authorino.decision
            );
        }
    }

    #[tokio::test]
    async fn opa_pipeline_matches_expected() {
        for f in load_fixtures() {
            let got = is_allow(&eval_opa(&f.predicate_opa, &bag_from_fixture(&f.request)).await);
            assert_eq!(
                got,
                f.expected == "allow",
                "OPA fixture {} ({}): expected PPE={}, authorino={}",
                f.attribute,
                f.status,
                f.expected,
                f.authorino.decision
            );
        }
    }
}
