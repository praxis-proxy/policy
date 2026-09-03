// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A plugin that panics, returns an error, or hangs, on demand.
//!
//! The executor's safety invariants are a property of every phase, not of
//! one mock in one test module. This is the reusable seam: script a failure,
//! drive [`crate::executor::Executor::execute`], and assert the decision.
//! `docs/safety-invariants.md` is the catalog.
//!
//! Behind `test-util` (and `cfg(test)`), so it stays out of the published
//! surface. A `FaultHandler` that reached production would either halt
//! every request or hang it.

#![allow(clippy::panic, reason = "the harness panics on demand")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;

use crate::context::PluginContext;
use crate::error::PluginError;
use crate::executor::erase_result;
use crate::hooks::PluginResult;
use crate::hooks::payload::{Extensions, PluginPayload};
use crate::plugin::{OnError, Plugin, PluginConfig, PluginMode};
use crate::registry::{AnyHookHandler, HookEntry, PluginRef};

/// How the handler fails. `None` is the control: the handler allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedFailure {
    /// Return `PluginResult::allow`.
    None,
    /// Return `PluginError::Execution`.
    Error,
    /// Sleep longer than any timeout the suite configures.
    Hang,
    /// `panic!` inside the handler.
    Panic,
}

impl InjectedFailure {
    /// Violation code a blocking `on_error: fail` phase records for this
    /// failure. `None` has no violation.
    pub const fn halt_code(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Error => Some("plugin_error"),
            Self::Hang => Some("plugin_timeout"),
            Self::Panic => Some("plugin_panic"),
        }
    }

    /// `PluginErrorRecord.code` when the phase continues and records.
    pub const fn record_code(self) -> Option<&'static str> {
        match self {
            Self::None | Self::Error => None,
            Self::Hang => Some("timeout"),
            Self::Panic => Some("panic"),
        }
    }

    /// Every injected failure the catalog drives, including the control.
    pub const fn all() -> [Self; 4] {
        [Self::None, Self::Error, Self::Hang, Self::Panic]
    }
}

/// Payload type the harness returns on the allow path. The executor
/// type-erases results, so this need not match the pipeline payload.
#[derive(Debug, Clone, Default)]
pub struct FaultPayload;

crate::impl_plugin_payload!(FaultPayload);

/// Lifecycle stub whose trusted config is the scheduling source of truth.
pub struct FaultPlugin(pub PluginConfig);

#[async_trait]
impl Plugin for FaultPlugin {
    fn config(&self) -> &PluginConfig {
        &self.0
    }
}

/// Handler that injects [`InjectedFailure`].
pub struct FaultHandler(pub InjectedFailure);

#[async_trait]
impl AnyHookHandler for FaultHandler {
    async fn invoke(
        &self,
        _payload: &dyn PluginPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        match self.0 {
            InjectedFailure::Error => Err(Box::new(PluginError::Execution {
                plugin_name: "fault".into(),
                message: "injected failure".into(),
                source: None,
                code: None,
                details: std::collections::HashMap::new(),
                proto_error_code: None,
            })),
            InjectedFailure::Hang => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(erase_result(PluginResult::<FaultPayload>::allow()))
            },
            InjectedFailure::Panic => panic!("injected panic inside a plugin"),
            InjectedFailure::None => Ok(erase_result(PluginResult::<FaultPayload>::allow())),
        }
    }

    fn hook_type_name(&self) -> &'static str {
        "fault"
    }
}

/// One registry entry: the named plugin in `mode` with `on_error`, injecting
/// `failure`.
pub fn fault_entry(
    name: &str,
    mode: PluginMode,
    on_error: OnError,
    failure: InjectedFailure,
) -> HookEntry {
    let cfg = PluginConfig {
        name: name.into(),
        mode,
        on_error,
        ..Default::default()
    };
    HookEntry {
        plugin_ref: Arc::new(PluginRef::new(Arc::new(FaultPlugin(cfg.clone())), cfg)),
        handler: Arc::new(FaultHandler(failure)),
    }
}

/// Handler that always allows and counts how many times it ran.
///
/// Used to assert a later phase still dispatched after a contained failure.
pub struct ProbeHandler(pub Arc<AtomicUsize>);

#[async_trait]
impl AnyHookHandler for ProbeHandler {
    async fn invoke(
        &self,
        _payload: &dyn PluginPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(erase_result(PluginResult::<FaultPayload>::allow()))
    }

    fn hook_type_name(&self) -> &'static str {
        "probe"
    }
}

/// An allowing plugin in `mode`, counting invocations on `calls`.
pub fn probe_entry(name: &str, mode: PluginMode, calls: Arc<AtomicUsize>) -> HookEntry {
    let cfg = PluginConfig {
        name: name.into(),
        mode,
        ..Default::default()
    };
    HookEntry {
        plugin_ref: Arc::new(PluginRef::new(Arc::new(FaultPlugin(cfg.clone())), cfg)),
        handler: Arc::new(ProbeHandler(calls)),
    }
}

/// Decision the catalog asserts for `mode` × `failure` under `on_error: fail`.
///
/// Lives here so the match on [`PluginMode`] is exhaustive inside this crate.
/// An integration test cannot match a `#[non_exhaustive]` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedVerdict {
    /// Pipeline allows; no violation and no recorded error.
    Allow,
    /// Pipeline halts with this violation code.
    Halt {
        /// `PluginViolation.code`.
        code: &'static str,
    },
    /// Pipeline continues; the failure is recorded.
    Continue {
        /// `PluginErrorRecord.code`, when the phase stamps one.
        record_code: Option<&'static str>,
    },
    /// Pipeline allows; `wait_for_background_tasks` observes the panic.
    AllowThenBackgroundPanic,
}

/// Every [`PluginMode`] variant, including `Disabled`.
///
/// The match is exhaustive so a new variant is a compile error until this
/// list and [`expected_plugin_verdict`] are updated together. Catalog
/// iteration is this list filtered by [`PluginMode::is_dispatch_phase`].
pub fn all_plugin_modes() -> [PluginMode; 6] {
    match PluginMode::Sequential {
        PluginMode::Sequential
        | PluginMode::Transform
        | PluginMode::Audit
        | PluginMode::Concurrent
        | PluginMode::FireAndForget
        | PluginMode::Disabled => {},
    }
    [
        PluginMode::Sequential,
        PluginMode::Transform,
        PluginMode::Audit,
        PluginMode::Concurrent,
        PluginMode::FireAndForget,
        PluginMode::Disabled,
    ]
}

/// Every mode the executor dispatches. `Disabled` is omitted.
pub fn dispatch_modes() -> Vec<PluginMode> {
    all_plugin_modes()
        .into_iter()
        .filter(PluginMode::is_dispatch_phase)
        .collect()
}

/// Safe verdict for one catalog cell. Exhaustive on [`PluginMode`].
pub fn expected_plugin_verdict(mode: PluginMode, failure: InjectedFailure) -> ExpectedVerdict {
    match mode {
        PluginMode::Disabled => ExpectedVerdict::Allow,
        PluginMode::Sequential | PluginMode::Concurrent => match failure.halt_code() {
            None => ExpectedVerdict::Allow,
            Some(code) => ExpectedVerdict::Halt { code },
        },
        PluginMode::Transform | PluginMode::Audit => match failure {
            InjectedFailure::None => ExpectedVerdict::Allow,
            InjectedFailure::Error | InjectedFailure::Hang | InjectedFailure::Panic => {
                ExpectedVerdict::Continue {
                    record_code: failure.record_code(),
                }
            },
        },
        PluginMode::FireAndForget => match failure {
            InjectedFailure::None | InjectedFailure::Error | InjectedFailure::Hang => {
                ExpectedVerdict::Allow
            },
            InjectedFailure::Panic => ExpectedVerdict::AllowThenBackgroundPanic,
        },
    }
}
