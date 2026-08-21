// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Host-provided services, and the two carriers that hand them to a plugin.
//
// Some things a plugin needs cannot be compiled into PPE, because the
// embedding host already owns them: an HTTP stack with its pool and
// egress policy, and later a durable effect log. PPE defines the shape,
// the host installs an implementation, and a plugin borrows it.
//
// A plugin borrows per call and stores nothing. Two reasons, and the
// first is the load-bearing one:
//
//   * The capability gate is recomputed per invocation. A plugin that
//     stashed a handle at startup would keep the authority after an
//     operator removed the capability and reloaded config, turning
//     "is allowed now" into "was allowed once".
//   * The carrier can attach per-request context a stored handle could
//     never know: the request's trace span, its remaining deadline, its
//     subrequest depth.
//
// Two carriers, because a plugin needs services at two points in its
// life and only one of them has a request:
//
//   * [`InitExtensions`] — during `Plugin::initialize_with`. No request
//     exists, so it carries services and nothing else. A JWKS fetch at
//     startup runs through this.
//   * `Extensions` — during hook dispatch. Already flows to every
//     plugin, already filtered by capability. A token exchange or an
//     on-demand JWKS refresh runs through this.
//
// Both implement [`HostServices`], so a plugin writes the work once
// against `&dyn HostServices` and the carrier becomes incidental:
//
// ```ignore
// async fn fetch_jwks(&self, svc: &dyn HostServices) -> Result<KeyStore, String> {
//     let http = svc.http()?;
//     ...
// }
// ```
//
// `InitExtensions` is a distinct type rather than an `Extensions` with
// every slot empty. Handing a plugin a request context when there is no
// request invites reading `ext.security` at startup and getting a
// confusing `None`; here there is nothing to reach for.

use std::fmt;
use std::sync::Arc;

use crate::http::HttpTransport;

/// Why a host service was not available to a plugin.
///
/// The two variants have different fixes and different owners, so they
/// are reported separately. Collapsing them would send an operator
/// looking at their config when the host forgot to wire something, or
/// the reverse.
///
/// Neither names the plugin. Both places these surface already tag the
/// plugin: the engine logs `Failed to initialize plugin '{name}'`, and
/// the executor wraps a request-time failure in `PluginError` carrying
/// the name. Repeating it here would render as "plugin 'x': plugin 'x'
/// needs...".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// The host never installed this service.
    ///
    /// A wiring problem in the embedding program, not in policy config.
    /// Nothing an operator can fix from YAML.
    NotInstalled {
        /// Service name, e.g. `"http"`.
        service: &'static str,
    },

    /// The service exists but this plugin does not hold the capability
    /// that gates it.
    ///
    /// A config problem, and the message names the capability to add.
    NotPermitted {
        /// Service name, e.g. `"http"`.
        service: &'static str,
        /// The capability that would grant it, e.g. `"perform_http"`.
        capability: &'static str,
    },
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled { service } => write!(
                f,
                "needs the '{service}' host service, but none is installed; the embedding \
                 host must install one before initializing the engine"
            ),
            Self::NotPermitted {
                service,
                capability,
            } => write!(
                f,
                "needs the '{service}' host service but does not declare '{capability}'; \
                 add it to the plugin's `capabilities` in config"
            ),
        }
    }
}

impl std::error::Error for ServiceError {}

/// One host service as seen by a plugin: present, absent, or withheld.
///
/// Keeping "withheld" distinct from "absent" is what lets
/// [`ServiceError`] name the right fix. An `Option` would collapse them.
#[derive(Debug, Clone, Default)]
pub enum ServiceSlot<T> {
    /// Installed and permitted.
    Available(T),
    /// The host installed nothing.
    #[default]
    NotInstalled,
    /// Installed, but the plugin lacks the gating capability.
    NotPermitted,
}

impl<T> ServiceSlot<T> {
    /// Resolve to the service, or to the error that says why not.
    pub(crate) fn get(
        &self,
        service: &'static str,
        capability: &'static str,
    ) -> Result<&T, ServiceError> {
        match self {
            Self::Available(v) => Ok(v),
            Self::NotInstalled => Err(ServiceError::NotInstalled { service }),
            Self::NotPermitted => Err(ServiceError::NotPermitted {
                service,
                capability,
            }),
        }
    }

    /// Whether the service is available.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }
}

/// The host services a plugin may borrow.
///
/// Implemented by the carriers ([`InitExtensions`] and `Extensions`),
/// never by a host. A host implements the individual service traits —
/// [`HttpTransport`] and, in time, the effect log — and installs them on
/// the engine.
///
/// Every accessor returns a `Result` rather than an `Option` so a plugin
/// that needs a service it cannot have fails with a message naming the
/// fix, instead of silently taking a degraded path.
pub trait HostServices {
    /// The host's HTTP transport.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotInstalled`] when the host wired none, or
    /// [`ServiceError::NotPermitted`] when the plugin lacks
    /// `perform_http`.
    fn http(&self) -> Result<&dyn HttpTransport, ServiceError>;
}

/// Host services during `Plugin::initialize_with`, before any request.
///
/// The engine builds one per plugin, applying that plugin's capability
/// grants, and drops it when initialization returns. A plugin must not
/// retain anything from it; see the module note on borrowing per call.
#[derive(Debug, Clone, Default)]
pub struct InitExtensions {
    http: ServiceSlot<Arc<dyn HttpTransport>>,
}

impl InitExtensions {
    /// An empty set of services, as a host that installed nothing would
    /// produce. Also the shape a test wants when the plugin under test
    /// needs none.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the HTTP transport, having already decided the plugin may
    /// have it.
    ///
    /// The capability check belongs to the caller (the engine) because
    /// only it holds the plugin's authoritative grants; this type just
    /// carries the verdict.
    #[must_use]
    pub fn with_http(mut self, http: Arc<dyn HttpTransport>) -> Self {
        self.http = ServiceSlot::Available(http);
        self
    }

    /// Record that a transport exists but this plugin may not use it.
    #[must_use]
    pub fn with_http_withheld(mut self) -> Self {
        self.http = ServiceSlot::NotPermitted;
        self
    }
}

impl HostServices for InitExtensions {
    fn http(&self) -> Result<&dyn HttpTransport, ServiceError> {
        self.http
            .get(HTTP_SERVICE, HTTP_CAPABILITY)
            .map(|arc| &**arc)
    }
}

/// Service name used in [`ServiceError`] messages.
pub const HTTP_SERVICE: &str = "http";

/// Capability that gates the HTTP service, matching
/// `Capability::PerformHttp`'s serialized form.
pub const HTTP_CAPABILITY: &str = "perform_http";

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, HttpResponse, HttpTransportError};
    use async_trait::async_trait;
    use bytes::Bytes;

    #[derive(Debug)]
    struct StubTransport;

    #[async_trait]
    impl HttpTransport for StubTransport {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            Ok(HttpResponse::new(200, Bytes::from_static(b"{}")))
        }
    }

    #[test]
    fn an_uninstalled_service_names_the_host_not_the_operator() {
        // The distinction matters operationally: nothing in policy YAML
        // fixes a host that forgot to wire a transport, so the message
        // must not send an operator looking there.
        let ext = InitExtensions::new();
        let err = ext.http().expect_err("nothing was installed");
        assert!(matches!(err, ServiceError::NotInstalled { .. }));
        let msg = err.to_string();
        assert!(msg.contains("embedding host"), "{msg}");
    }

    #[test]
    fn a_withheld_service_names_the_capability_to_add() {
        // The opposite case: the host did its part, and the fix is one
        // line of config. The message has to say which line.
        let ext = InitExtensions::new().with_http_withheld();
        let err = ext.http().expect_err("the capability was not granted");
        assert!(matches!(err, ServiceError::NotPermitted { .. }));
        let msg = err.to_string();
        assert!(msg.contains("perform_http"), "{msg}");
        assert!(msg.contains("capabilities"), "{msg}");
    }

    #[tokio::test]
    async fn an_available_service_is_usable_through_the_trait() {
        let ext = InitExtensions::new().with_http(Arc::new(StubTransport));
        let svc: &dyn HostServices = &ext;
        let resp = svc
            .http()
            .expect("installed and permitted")
            .execute(HttpRequest::get("https://example.com/jwks"))
            .await
            .expect("the stub answers");
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn withheld_and_uninstalled_are_distinguishable() {
        // The whole reason ServiceSlot is not an Option.
        let uninstalled = InitExtensions::new();
        let withheld = InitExtensions::new().with_http_withheld();
        assert_ne!(
            uninstalled.http().unwrap_err(),
            withheld.http().unwrap_err()
        );
        assert!(!uninstalled.http.is_available());
        assert!(!withheld.http.is_available());
    }
}
