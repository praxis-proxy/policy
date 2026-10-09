// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Security suite: adversarial inputs against the full engine.
//!
//! Only engine-owned defenses: the engine receives an already-parsed
//! payload and header map and decides. Host-owned ones (body parsing,
//! size ceilings, header joining) are tested in praxis.
//! Every case ends with the leak assertion.
//!
//! Known gaps follow the convention in the integration suite.

#![expect(clippy::expect_used, clippy::indexing_slicing, reason = "test code")]

mod delegation_abuse;
mod elicitation_abuse;
mod match_evasion;
mod payloads;
mod redaction;
mod smoke;
mod support;
mod tokens;
