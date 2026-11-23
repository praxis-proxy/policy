// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Config checks more than one builtin needs.
//!
//! Each check runs at config load and returns the operator-facing message on
//! failure, naming the setting it rejected. A plugin adds its own rules on top
//! of what a check returns rather than widening the check for one caller.

/// HTTPS endpoint URLs.
pub(crate) mod https;
