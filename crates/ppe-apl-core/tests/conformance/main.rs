// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The conformance corpus: one accepted and one rejected case per rule the
//! grammar states.
//!
//! `docs/apl-grammar.md` is the normative document and this is what holds it to
//! account. Every production, every breaking change, and every documented wart the
//! *parser* decides has a case in one of the modules below, and every rejected
//! case asserts on the *message* rather than only on being an error. A tightening
//! that fails for the wrong reason passes an `is_err` test and tells an operator
//! nothing, which is the failure mode this work exists to remove.
//!
//! Two of the document's warts are out of scope here, settled after the parse
//! rather than by it: the elicitation `scope:` parsed at request time, and
//! static-tags-only inheritance. Both belong to a runtime or config suite.
//!
//! # Why this file exists at all
//!
//! Cargo auto-discovers `tests/*.rs` and `tests/<dir>/main.rs`, and ignores loose
//! files under `tests/<dir>/`. Without this entry point the modules below would
//! compile never and run never, while the suite stayed green: exactly the silent
//! gap the corpus is here to close. If you add a case module, declare it here.
//!
//! One binary rather than three also costs one process launch rather than three,
//! which on macOS with an endpoint-security agent installed is the difference
//! between a fast test run and a slow one. See AGENTS.md.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "test and example code"
)]

/// Quoting, escapes, attribute paths, numbers, operators, positions.
mod lexical;
/// What may appear in which position, and the one verb that invokes a plugin.
mod positional;
/// `require(P)` as a predicate, and the desugaring it must preserve.
mod require;
/// One rule, written three ways, put through the same assertion.
mod spellings;
/// The step-map key set, and the two spellings a PDP call takes.
mod step_maps;
