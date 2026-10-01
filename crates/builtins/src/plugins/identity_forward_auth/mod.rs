// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Resolves an opaque session credential to an identity by delegating to an
//! external authentication endpoint.
//!
//! # Why this is a delegation and not a validation
//!
//! A JWT is self describing: it carries signed claims, so verifying one is local
//! and stateless. A session cookie minted by a BFF is an opaque handle that
//! carries nothing PPE can read — its contents are the BFF's secret. Validating
//! one means asking the party that issued it, which is the Traefik `ForwardAuth`
//! / nginx `auth_request` pattern: PPE forwards the credential to a sub-request
//! endpoint (`/oauth2/auth`), the endpoint answers valid or not, and on a valid
//! answer its identity headers become the subject. PPE never parses the cookie,
//! never runs the OAuth code flow, and never holds a token.
//!
//! # Unauthenticated, error, and deny
//!
//! Three outcomes, and keeping them apart is the point of the plugin:
//!
//!   * **Unauthenticated** — the endpoint is reachable and says the session is
//!     not valid (or the request carried no credential to begin with). No
//!     subject, and crucially **no `deny`**: a deny takes the host's fixed-401
//!     rejection path and skips a route's `denyWith`, whereas an unresolved
//!     identity lets the authorization layer emit a 302 bounce to login. This is
//!     what lets the plugin front a browser.
//!   * **Error** — the endpoint cannot be reached. Fail-closed: the handler
//!     denies, because `on_error: fail` is required of an identity resolver.
//!   * **Mapped** — a success status, and the identity headers project onto the
//!     subject.
//!
//! The session never leaves this plugin. It is not written to `raw_credentials`,
//! so no downstream step can forward a caller's own cookie to an upstream that
//! never authenticated it.

/// Plugin configuration and its validation.
pub mod config;
/// Constructs the resolver from configuration.
pub mod factory;
/// The identity hook handler.
pub mod resolver;
/// Response identity headers onto the identity slots.
pub mod response_map;

pub use config::ForwardAuthConfig;
pub use factory::{ForwardAuthFactory, KIND};
pub use resolver::{ForwardAuthResolver, codes};
