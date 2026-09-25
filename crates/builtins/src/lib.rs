// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bundled extensions for the Praxis Policy Engine: decision points, identity
//! and delegation plugins, a session store, and a secret provider.
//!
//! Every extension sits behind its own Cargo feature and nothing is enabled by
//! default. Hosts normally reach these through the `praxis-policy` facade,
//! which maps its own feature of the same name onto each one and registers the
//! factories; depend on this crate directly only to use an extension without
//! the facade.
//!
//! Module paths are written as plain code spans rather than intra-doc links.
//! They cannot be links: every module here is feature-gated and `make doc` runs
//! a default-features pass under `-D warnings`, where most of them are absent.
//! docs.rs builds with all features, so the modules are reachable from the
//! sidebar.
//!
//! | Feature | Module |
//! |---|---|
//! | `jwt` | `plugins::identity_jwt` |
//! | `api-key` | `plugins::identity_api_key` |
//! | `oauth` | `plugins::delegator_oauth` |
//! | `elicitation-ciba` | `plugins::elicitation_ciba` |
//! | `quota` | `plugins::quota` |
//! | `cedar` | `pdps::cedar_direct` |
//! | `cel` | `pdps::cel` |
//! | `opa` | `pdps::opa` |
//! | `valkey` | `session::valkey` |
//! | `secrets-vault` | `secrets::vault` |

// Each group is gated on a private marker feature that every extension in it
// implies, rather than on an `any(feature = ...)` list. `unexpected_cfgs`
// catches a `cfg` naming a feature that does not exist, but not an alternative
// missing from such a list, so a marker is what keeps a tenth extension from
// silently failing to declare its module.
#[cfg(feature = "_plugins")]
pub mod plugins;

#[cfg(feature = "_pdps")]
pub mod pdps;

#[cfg(feature = "_secrets")]
pub mod secrets;

#[cfg(feature = "_session")]
pub mod session;
