// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Revocation hook family: the engine asks every checker on a route whether
// the identities authentication resolved still hold authority. Checkers deny
// through the ordinary violation path and report on allow which identity
// slots they verified with an issuer, so the engine can deny a slot no
// checker covered.

/// The engine's check: run a route's checkers and decide pass or deny.
mod check;
/// The revocation hook.
pub mod hook;
/// The request a checker answers and the slots it vouched for.
pub mod payload;

pub(crate) use check::{check_points, question, verdict};
pub use hook::{HOOK_REVOCATION_CHECK, RevocationHook};
pub use payload::{CheckPoint, IdentitySlot, RevocationCheck};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Violation code for an identity or credential that has been revoked.
pub const REVOKED_CODE: &str = "auth.revoked";

/// Caller-facing reason for [`REVOKED_CODE`]. Fixed so a denial names no
/// issuer, realm, client or upstream failure.
pub const REVOKED_REASON: &str = "credential revoked";

/// Violation code for a revocation status that could not be established:
/// the checker covering a slot failed or timed out, or no checker covered
/// it. Never a pass.
pub const REVOCATION_UNAVAILABLE_CODE: &str = "auth.revocation_unavailable";

/// Caller-facing reason for [`REVOCATION_UNAVAILABLE_CODE`].
pub const REVOCATION_UNAVAILABLE_REASON: &str = "revocation status unavailable";
