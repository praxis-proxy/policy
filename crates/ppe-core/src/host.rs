// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Host-provided services, and the two carriers that hand them to a plugin.
//
// Some things a plugin needs cannot be compiled into PPE, because the
// embedding host already owns them: an HTTP stack with its pool and
// egress policy, and later a durable effect log. PPE defines the shape,
// the host installs an implementation, and a plugin borrows it.
//
// These are operations, not accessors: nothing hands the underlying
// service back, so a plugin has no handle to keep. Two reasons, and the
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
// The corollary is that background work cannot use these services at
// all: a `'static` task outlives the carrier by construction, so it has
// no invocation to borrow from and no gate to be checked against. That
// is a feature. `identity-jwt` used to refresh JWKS on a spawned ticker
// and it was silently dead under any host that dropped the runtime it
// initialized on; refreshing from the verify path needs no retained
// handle and no runtime of its own.
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
//     let http = svc.http_transport()?;
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

use async_trait::async_trait;

use crate::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
use crate::http_retry::RetryPolicy;

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

/// The host services a plugin may use.
///
/// Implemented by the carriers ([`InitExtensions`] and `Extensions`),
/// never by a host. A host implements the individual service traits —
/// [`HttpTransport`] and, in time, the effect log — and installs them on
/// the engine.
///
/// These are *operations*, not accessors. Nothing hands back the
/// underlying service, so there is no handle for a plugin to keep and
/// the capability check cannot be performed once and then skipped: the
/// call is the check. It also leaves the carrier free to enrich a
/// request with context only it has — a trace span, a remaining
/// deadline, a subrequest depth — which a plugin driving the transport
/// itself would bypass.
///
/// Every operation returns a `Result` so a plugin that needs a service it
/// cannot have fails with a message naming the fix, instead of silently
/// taking a degraded path.
#[async_trait]
pub trait HostServices: Send + Sync {
    /// Perform one outbound HTTP request through the host's transport.
    ///
    /// `retry` is required rather than defaulted because whether a
    /// repeat is safe depends on what the request *does*, and only the
    /// caller knows that. A JWKS `GET` takes
    /// [`RetryPolicy::idempotent`]; a token mint or an approval prompt
    /// takes [`RetryPolicy::undelivered_only`], where repeating a
    /// timed-out call could issue a second credential or ask a human
    /// twice. Making it an argument means the question gets answered at
    /// every call site.
    ///
    /// # Errors
    ///
    /// [`HttpRequestError::Unavailable`] when no transport is installed
    /// or the plugin lacks `perform_http`, and
    /// [`HttpRequestError::Transport`] when the call itself failed.
    async fn http_request(
        &self,
        req: HttpRequest,
        retry: RetryPolicy,
    ) -> Result<HttpResponse, HttpRequestError>;
}

/// Why an outbound request did not produce a response.
///
/// Two distinct failures with different owners: the service was not
/// available to this plugin at all, or it was and the call failed. An
/// operator fixes the first in config or host wiring and the second at
/// the peer, so collapsing them would send them to the wrong place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpRequestError {
    /// No transport is installed, or this plugin may not use it.
    Unavailable(ServiceError),
    /// The transport ran and the call failed.
    Transport(HttpTransportError),
}

impl fmt::Display for HttpRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "{e}"),
            Self::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HttpRequestError {}

impl From<ServiceError> for HttpRequestError {
    fn from(e: ServiceError) -> Self {
        Self::Unavailable(e)
    }
}

impl From<HttpTransportError> for HttpRequestError {
    fn from(e: HttpTransportError) -> Self {
        Self::Transport(e)
    }
}

/// Shared body for both carriers: resolve the gated transport, then run
/// the request through the retry policy.
pub(crate) async fn run_request(
    slot: &HttpTransportSlot,
    req: HttpRequest,
    retry: RetryPolicy,
) -> Result<HttpResponse, HttpRequestError> {
    let transport = slot.slot().get(HTTP_SERVICE, HTTP_CAPABILITY)?;
    crate::http_retry::execute_with_retry(transport.as_ref(), req, retry)
        .await
        .map_err(HttpRequestError::Transport)
}

/// The host's HTTP transport as one carrier sees it.
///
/// A newtype over the slot rather than the slot itself, so the `Arc`
/// inside cannot be taken out. The field on `Extensions` has to stay
/// public — Rust forbids `..Default::default()` when any field is
/// invisible, and nearly four hundred construction sites rely on it —
/// but a public *field* need not imply a public *payload*.
///
/// Without this, a plugin could `match ext.http_transport { Available(t)
/// => Arc::clone(t) }` and keep the transport for the life of the
/// process, which is exactly what the operation-shaped API exists to
/// prevent: the grant is re-evaluated per request, so a retained handle
/// outlives a capability an operator has since revoked.
#[derive(Debug, Clone, Default)]
pub struct HttpTransportSlot(ServiceSlot<Arc<dyn HttpTransport>>);

impl HttpTransportSlot {
    /// A slot holding `transport`, for a host or test wiring one in.
    #[must_use]
    pub fn installed(transport: Arc<dyn HttpTransport>) -> Self {
        Self(ServiceSlot::Available(transport))
    }

    /// A slot recording that a transport exists but this plugin may not
    /// use it, so the error names the capability rather than blaming the
    /// host for installing nothing.
    #[must_use]
    pub fn withheld() -> Self {
        Self(ServiceSlot::NotPermitted)
    }

    /// Whether a transport is present and permitted.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.0.is_available()
    }

    pub(crate) fn slot(&self) -> &ServiceSlot<Arc<dyn HttpTransport>> {
        &self.0
    }
}

/// Host services during `Plugin::initialize_with`, before any request.
///
/// The engine builds one per plugin, applying that plugin's capability
/// grants, and drops it when initialization returns. A plugin must not
/// retain anything from it; see the module note on borrowing per call.
#[derive(Debug, Clone, Default)]
pub struct InitExtensions {
    http: HttpTransportSlot,
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
        self.http = HttpTransportSlot::installed(http);
        self
    }

    /// Record that a transport exists but this plugin may not use it.
    #[must_use]
    pub fn with_http_withheld(mut self) -> Self {
        self.http = HttpTransportSlot::withheld();
        self
    }
}

#[async_trait]
impl HostServices for InitExtensions {
    async fn http_request(
        &self,
        req: HttpRequest,
        retry: RetryPolicy,
    ) -> Result<HttpResponse, HttpRequestError> {
        run_request(&self.http, req, retry).await
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
    use async_trait::async_trait;
    use bytes::Bytes;

    /// Ask for the service the only way a plugin can: by using it.
    async fn probe(ext: &InitExtensions) -> Result<HttpResponse, HttpRequestError> {
        ext.http_request(
            HttpRequest::get("https://example.test/probe"),
            RetryPolicy::none(),
        )
        .await
    }

    #[derive(Debug)]
    struct StubTransport;

    #[async_trait]
    impl HttpTransport for StubTransport {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            Ok(HttpResponse::new(200, Bytes::from_static(b"{}")))
        }
    }

    #[tokio::test]
    async fn an_uninstalled_service_names_the_host_not_the_operator() {
        // The distinction matters operationally: nothing in policy YAML
        // fixes a host that forgot to wire a transport, so the message
        // must not send an operator looking there.
        let ext = InitExtensions::new();
        let err = probe(&ext).await.expect_err("nothing was installed");
        assert!(matches!(
            err,
            HttpRequestError::Unavailable(ServiceError::NotInstalled { .. })
        ));
        let msg = err.to_string();
        assert!(msg.contains("embedding host"), "{msg}");
    }

    #[tokio::test]
    async fn a_withheld_service_names_the_capability_to_add() {
        // The opposite case: the host did its part, and the fix is one
        // line of config. The message has to say which line.
        let ext = InitExtensions::new().with_http_withheld();
        let err = probe(&ext)
            .await
            .expect_err("the capability was not granted");
        assert!(matches!(
            err,
            HttpRequestError::Unavailable(ServiceError::NotPermitted { .. })
        ));
        let msg = err.to_string();
        assert!(msg.contains("perform_http"), "{msg}");
        assert!(msg.contains("capabilities"), "{msg}");
    }

    #[tokio::test]
    async fn an_available_service_is_usable_through_the_trait() {
        let ext = InitExtensions::new().with_http(Arc::new(StubTransport));
        let svc: &dyn HostServices = &ext;
        let resp = svc
            .http_request(
                HttpRequest::get("https://example.com/jwks"),
                RetryPolicy::none(),
            )
            .await
            .expect("the stub answers");
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn withheld_and_uninstalled_are_distinguishable() {
        // The whole reason ServiceSlot is not an Option.
        let uninstalled = InitExtensions::new();
        let withheld = InitExtensions::new().with_http_withheld();
        assert_ne!(
            probe(&uninstalled).await.unwrap_err(),
            probe(&withheld).await.unwrap_err()
        );
        assert!(!uninstalled.http.is_available());
        assert!(!withheld.http.is_available());
    }
}
