// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Test utilities: child-process isolation, resolver construction, alarm
//! capture.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use praxis_policy_builtins::plugins::identity_jwt::{JwtIdentityResolver, KIND};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler as _, PluginResult};
use praxis_policy_core::identity::{HOOK_IDENTITY_RESOLVE, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;
use serde_json::{Value, json};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const CHILD: &str = "PPE_JWT_FIPS_CHILD";

/// An OpenSSL configuration a case runs under.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Openssl {
    /// The FIPS provider is the process default.
    FipsDefault,
    /// The FIPS provider is loaded but not the default.
    FipsLoaded,
    /// Only the default provider is loaded.
    NoFips,
}

impl Openssl {
    fn config(self) -> &'static str {
        match self {
            Self::FipsDefault => "fips-default.cnf",
            Self::FipsLoaded => "fips-provider.cnf",
            Self::NoFips => "fips-no-provider.cnf",
        }
    }

    fn needs_provider(self) -> bool {
        !matches!(self, Self::NoFips)
    }
}

/// Run `body` in a child process under `openssl`, from the parent test
/// `name`. The child re-enters the same test and runs `body`.
///
/// A configuration that needs the FIPS provider is run only where
/// `PRAXIS_REQUIRE_FIPS_PROVIDER` says one is installed, and one that needs it
/// absent only where the variable is unset, so a misconfigured job fails
/// rather than passing vacuously.
pub(crate) fn isolated(name: &str, openssl: Openssl, body: impl FnOnce()) {
    if std::env::var_os(CHILD).is_some() {
        body();
        return;
    }
    let provider = std::env::var_os("PRAXIS_REQUIRE_FIPS_PROVIDER").is_some();
    assert_eq!(
        provider,
        openssl.needs_provider(),
        "{name} needs PRAXIS_REQUIRE_FIPS_PROVIDER {}",
        if openssl.needs_provider() {
            "set with a FIPS provider"
        } else {
            "unset"
        }
    );
    let config = format!(
        "{}/../../.github/{}",
        env!("CARGO_MANIFEST_DIR"),
        openssl.config()
    );
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--test-threads=1", "--color=never"])
        .env(CHILD, "1")
        .env("OPENSSL_CONF", config)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "isolated case {name} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("test result: ok. 1 passed;"),
        "the child must run exactly {name}: {stdout}"
    );
}

/// A resolver config for one issuer with the given key source.
pub(crate) fn config(issuer: &str, audience: &str, algorithms: &[&str], key: Value) -> Value {
    json!({
        "trusted_issuers": [{
            "issuer": issuer,
            "audiences": [audience],
            "algorithms": algorithms,
            "decoding_key": key,
        }],
        "claim_mapper": "standard",
    })
}

pub(crate) fn plugin_config(settings: Value) -> PluginConfig {
    PluginConfig {
        name: "jwt".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.to_owned()],
        capabilities: ["read_headers", "perform_http"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        config: Some(settings),
        ..Default::default()
    }
}

pub(crate) fn build(settings: Value) -> Result<JwtIdentityResolver, Box<PluginError>> {
    JwtIdentityResolver::new(plugin_config(settings))
}

/// The config error message, failing if the resolver built or failed
/// otherwise.
pub(crate) fn config_error(settings: Value) -> String {
    match build(settings).map(drop).map_err(|e| *e) {
        Err(PluginError::Config { message }) => message,
        other => panic!("expected a config error, got {other:?}"),
    }
}

pub(crate) async fn resolve(
    resolver: &JwtIdentityResolver,
    token: &str,
) -> PluginResult<IdentityPayload> {
    let payload = IdentityPayload::new(token, TokenSource::Bearer);
    resolver
        .handle(&payload, &Extensions::default(), &mut PluginContext::new())
        .await
}

pub(crate) fn denial_code(result: &PluginResult<IdentityPayload>) -> Option<String> {
    result.violation.as_ref().map(|v| v.code.clone())
}

// -----------------------------------------------------------------------------
// Alarm Capture
// -----------------------------------------------------------------------------

/// Formatted error events, recorded on the test's thread.
#[derive(Clone, Default)]
pub(crate) struct Events(Arc<Mutex<Vec<String>>>);

impl Events {
    pub(crate) fn matching(&self, needle: &str) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|event| event.contains(needle))
            .cloned()
            .collect()
    }

    /// Assert one crypto alarm for `op`, at error level.
    pub(crate) fn assert_crypto_alarm(&self, op: &str) {
        let alarms = self.matching("policy_crypto_failure");
        assert!(
            alarms
                .iter()
                .any(|alarm| alarm.contains(&format!("op={op}"))),
            "expected a crypto alarm for {op}: {alarms:?}"
        );
    }
}

thread_local! {
    static SINK: RefCell<Option<Events>> = const { RefCell::new(None) };
}

/// Capture error events on this thread until the returned guard drops.
pub(crate) fn capturing() -> (Events, impl Drop) {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(Capture).expect("one subscriber per process");
    });
    let events = Events::default();
    SINK.with_borrow_mut(|sink| *sink = Some(events.clone()));
    (events, Guard)
}

struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        SINK.with_borrow_mut(|sink| *sink = None);
    }
}

struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::ERROR
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Fields(&mut line));
        SINK.with_borrow(|sink| {
            if let Some(events) = sink {
                events
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(line);
            }
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={value} ", field.name());
    }
}
