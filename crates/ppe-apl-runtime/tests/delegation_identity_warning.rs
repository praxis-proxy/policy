// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `delegation_without_identity_resolution` alarm fires while the
// config is being loaded, not when a route first takes traffic.
//
// The distinction is the whole point of the check. A route that
// delegates the caller's own credential with nothing validating it is a
// configuration mistake, and the operator who can still fix it cheaply
// is the one watching the process come up. Raised from
// `RouteDispatchPlan::build` instead, it would wait for a request to
// arrive on that specific route — so a misconfigured route that is
// merely unpopular stays silent indefinitely, and the alarm arrives, if
// at all, interleaved with the traffic it was supposed to precede.
//
// `load_config_yaml` is synchronous, so the assertion is simply that
// the event landed inside the call.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::sync::{Arc, Mutex};

use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

const ALARM: &str = "delegation_without_identity_resolution";

/// Declares the identity plugin used by the configuration fixture.
struct Inert(PluginConfig);

impl Plugin for Inert {
    fn config(&self) -> &PluginConfig {
        &self.0
    }
}

struct InertFactory;

impl PluginFactory for InertFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        Ok(PluginInstance {
            plugin: Arc::new(Inert(config.clone())),
            handlers: Vec::new(),
        })
    }
}

/// A route delegating the caller's credential, with nothing configured
/// to validate it.
const NO_IDENTITY: &str = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
"#;

/// The same route with an `authentication:` block, which is what
/// identity resolution keys on.
const WITH_IDENTITY: &str = r#"
engine_settings:
  dispatch: policy
plugins:
  - name: corp-jwt
    kind: builtin
    hooks: [identity.resolve]
routes:
  - tool: get_compensation
    authentication:
      - corp-jwt
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
"#;

/// The delegation carries no caller credential, so identity resolution
/// has nothing to say about it and a warning would be noise.
const THIS_WORKLOAD: &str = r#"
engine_settings:
  dispatch: policy
plugins: []
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, subject: this_workload)"
"#;

/// Collects the `alarm` field of every event emitted while it is
/// installed.
///
/// Hand-rolled on `tracing` itself rather than pulled in from
/// `tracing-subscriber`: the whole of what this needs is one field off
/// one event, and that is not worth a new dependency tree on a crate
/// that has none today.
struct AlarmCollector {
    alarms: Arc<Mutex<Vec<String>>>,
}

impl Subscriber for AlarmCollector {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = AlarmField(None);
        event.record(&mut visitor);
        if let Some(alarm) = visitor.0 {
            self.alarms.lock().unwrap().push(alarm);
        }
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

struct AlarmField(Option<String>);

impl Visit for AlarmField {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "alarm" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "alarm" && self.0.is_none() {
            self.0 = Some(format!("{value:?}").trim_matches('"').to_owned());
        }
    }
}

/// Load `yaml` with the APL visitor registered, returning every alarm
/// raised during the load itself. Nothing is invoked, so any alarm here
/// came from the config walk.
fn alarms_raised_by_loading(yaml: &str) -> Vec<String> {
    let alarms = Arc::new(Mutex::new(Vec::new()));
    let collector = AlarmCollector {
        alarms: Arc::clone(&alarms),
    };

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_factory("builtin", Box::new(InertFactory));
    praxis_policy_apl_runtime::register_apl(
        &mgr,
        praxis_policy_apl_runtime::AplOptions::in_process(),
    );
    tracing::subscriber::with_default(collector, || {
        mgr.load_config_yaml(yaml).expect("load_config_yaml");
    });

    alarms.lock().unwrap().clone()
}

#[test]
fn a_route_delegating_without_identity_warns_during_the_config_load() {
    assert!(
        alarms_raised_by_loading(NO_IDENTITY).contains(&ALARM.to_owned()),
        "the alarm must be raised by the load itself, not deferred to the \
         route's first request"
    );
}

#[test]
fn a_route_with_identity_resolution_is_silent() {
    // Also pins the ordering this check depends on: `load_config` has
    // installed the policy config on the engine snapshot before the
    // visitors walk, so the identity lookup sees the config being
    // loaded rather than the previous one.
    assert!(
        !alarms_raised_by_loading(WITH_IDENTITY).contains(&ALARM.to_owned()),
        "a route with an `authentication:` block resolves identity, so \
         warning about it is a false alarm"
    );
}

#[test]
fn a_this_workload_delegation_is_silent() {
    assert!(
        !alarms_raised_by_loading(THIS_WORKLOAD).contains(&ALARM.to_owned()),
        "`subject: this_workload` carries no caller credential"
    );
}
