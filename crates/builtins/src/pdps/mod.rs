// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Policy decision points an APL route selects with a `cedar:`, `cel:` or
//! `opa:` step.
//!
//! Module paths are fixed here rather than per extension as it lands: these are
//! public API from first publish, so a later rename is a breaking change.
//!
//! - `cedar_direct` (`cedar`) — kind `cedar-direct`
//! - `cel` (`cel`) — kind `cel`
//! - `opa` (`opa`) — kind `opa`
//!
//! Each resolver depends only on `praxis-policy-apl-core`. Its factory
//! implements the runtime's `PdpFactory`, so enabling a PDP also compiles
//! `praxis-policy-apl-runtime`.

#[cfg(feature = "cedar")]
pub mod cedar_direct;

#[cfg(feature = "cel")]
pub mod cel;

#[cfg(feature = "opa")]
pub mod opa;

#[cfg(any(feature = "cedar", feature = "cel", feature = "opa"))]
mod stack;
