// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The audit sink: an observation-only consumer invoked at the pipeline's
// verdict with the decision log.
//
// An `AuditHandler` is not a `HookHandler<H>`. A hook handler returns a
// `PluginResult` and can therefore allow, deny or modify; this returns
// nothing, so a sink sees the verdict and every plugin's action but cannot
// influence either. The type carries that property, which is why sinks are
// their own family rather than a special case inside the engine.
//
// The engine attaches sinks; the engine invokes them once per pipeline
// run, at the verdict, with the final payload, extensions and decision log.
//
// A sink observes the pipeline, so it sees the pipeline's data — but it is
// still a plugin, and it is filtered on the same terms as one. `AttachedSink`
// below pairs each handler with the capability set its plugin declared, and
// every call site builds the sink's view through `filter_extensions` rather
// than handing over the executor's unfiltered working copy.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::decision::DecisionLog;
use crate::effect::EffectRecord;
use crate::extensions::filter_extensions;
use crate::hooks::payload::{Extensions, PluginPayload};

/// An observation-only consumer of pipeline decisions.
///
/// Implemented by audit plugins. The executor calls [`AuditHandler::handle`]
/// once per pipeline invocation, after the verdict is decided, for allowed
/// and denied requests alike.
#[async_trait]
pub trait AuditHandler: Send + Sync {
    /// Observe one finished pipeline invocation.
    ///
    /// The executor awaits this before returning the pipeline result, so a
    /// verdict that was emitted cannot be lost to a crash and a consumer
    /// needs no drop-detection for the steady state. Changing this to
    /// fire-and-forget would weaken that guarantee without any signal at the
    /// call sites that rely on it.
    ///
    /// The cost is that sink latency sits on the request path, bounded per
    /// sink by the plugin timeout and run sequentially. Keep `handle` cheap:
    /// serialize, hash, append. A sink writing to a network destination
    /// should hand off to its own queue rather than block here.
    ///
    /// * `payload` is the message as it stood at the verdict.
    /// * `extensions` are the final extensions.
    /// * `decisions` is what each plugin did and how the pipeline ruled.
    async fn handle(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    );

    /// Observe an irreversible external act a plugin caused, as its own event
    /// separate from the per-invocation decision.
    ///
    /// Fired at each lifecycle transition, so a sink sees the intent before
    /// the act and the outcome after. `extensions` carries the same ambient
    /// context a decision gets, so a sink can correlate the effect with the
    /// request that caused it rather than working from the record alone.
    ///
    /// The view is filtered to this sink's own capabilities, not the acting
    /// plugin's, and its effect slot is detached: a sink observing an effect
    /// cannot perform one, least of all under the name of the plugin it is
    /// watching.
    ///
    /// The default ignores effects, for a sink that only cares about verdicts.
    async fn on_effect(&self, _effect: &EffectRecord, _extensions: &Extensions) {}

    /// A short identifier used in error logs when a sink panics or times out.
    fn name(&self) -> &str {
        "audit"
    }
}

/// An audit sink together with the capability set its plugin declared.
///
/// Sinks reach every invocation, allowed and denied alike, and the extensions
/// at that point are the executor's working copy: the host's HTTP transport is
/// installed on it and `raw_credentials` is unfiltered, because the plugins
/// that ran needed those and were each filtered on the way in. Handing that
/// copy to a sink would let it read inbound bearer material and reach outside
/// the process without holding `read_inbound_credentials` or `perform_http`.
///
/// So a sink is filtered like any other plugin. [`Self::view`] runs the same
/// `filter_extensions` the executor runs per handler, against the capabilities
/// this sink's own `plugins:` entry declared. A sink that declares nothing
/// sees the ungated slots and nothing else, which is enough to record a
/// verdict.
///
/// The filtered view's effect slot is `Detached`, which is
/// [`Extensions`]'s default and what filtering therefore produces. That is the
/// second half of the gate: without it a sink observing an effect would hold
/// the acting plugin's live slot and could append records under that plugin's
/// name.
#[derive(Clone)]
pub struct AttachedSink {
    handler: Arc<dyn AuditHandler>,
    /// `Arc` because the executor clones its sink list into the effect sink on
    /// every registry mutation, and a capability set is read-only once built.
    capabilities: Arc<HashSet<String>>,
}

impl std::fmt::Debug for AttachedSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedSink")
            .field("handler", &self.handler.name())
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

impl AttachedSink {
    /// Pair a handler with the capabilities its plugin entry declared.
    #[must_use]
    pub fn new(handler: Arc<dyn AuditHandler>, capabilities: HashSet<String>) -> Self {
        Self {
            handler,
            capabilities: Arc::new(capabilities),
        }
    }

    /// The handler, for a caller that has already built the view.
    #[must_use]
    pub fn handler(&self) -> &Arc<dyn AuditHandler> {
        &self.handler
    }

    /// This sink's identifier, for error logs.
    #[must_use]
    pub fn name(&self) -> &str {
        self.handler.name()
    }

    /// The extensions this sink is entitled to see.
    #[must_use]
    pub fn view(&self, extensions: &Extensions) -> Extensions {
        filter_extensions(extensions, &self.capabilities)
    }
}
