// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Policy decision points an APL route selects with a `cedar:`, `cel:`,
//! `opa:` or `pdp(kubernetes-sar):` step.
//!
//! Module paths are fixed here rather than per extension as it lands: these are
//! public API from first publish, so a later rename is a breaking change.
//!
//! - `cedar_direct` (`cedar`) — kind `cedar-direct`
//! - `cel` (`cel`) — kind `cel`
//! - `kubernetes_sar` (`kubernetes-sar`) — kind `kubernetes-sar`
//! - `opa` (`opa`) — kind `opa`
//!
//! Every factory implements the runtime's `PdpFactory`, so enabling a PDP
//! also compiles `praxis-policy-apl-runtime`. Cedar, CEL and OPA evaluate in
//! process; `kubernetes_sar` calls out through the host's HTTP transport and
//! builds its review with the CEL module's bag mapping.

#[cfg(feature = "cedar")]
pub mod cedar_direct;

#[cfg(feature = "cel")]
pub mod cel;

#[cfg(feature = "kubernetes-sar")]
pub mod kubernetes_sar;

#[cfg(feature = "opa")]
pub mod opa;

#[cfg(any(feature = "cedar", feature = "cel", feature = "opa"))]
mod stack;
