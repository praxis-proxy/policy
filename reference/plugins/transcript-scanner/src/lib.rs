// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-plugin-transcript-scanner — CMF `HookHandler` that walks the
// prior turns carried on `AgentExtension.conversation.history` and tests each
// string they hold against operator-supplied patterns. A match denies with
// `transcript.detected`.
//
// History is not flattened into the APL attribute bag, so this is the way a
// policy reasons about it:
//
//   policy:
//     - "run(transcript-scan)"
//
// The plugin must declare `read_agent`. Without it the engine filters the
// agent extension out of the plugin's view, the history reads as empty, and
// every request would pass as clean; the factory refuses that config instead.
//
// Only history is scanned. The current turn is the hook payload, which is what
// `pii-scanner` covers; wire both to cover the whole transcript.

//! Scans typed conversation history for configured patterns.
//!
//! Reads `AgentExtension.conversation.history`, which requires the
//! `read_agent` capability, and denies the request when any prior turn holds
//! a string matching one of the configured patterns.

/// Plugin configuration: the patterns and the roles to scan.
pub mod config;
/// Constructs the scanner from configuration.
pub mod factory;
/// The CMF hook handler that walks history and applies the patterns.
pub mod scanner;

pub use config::{TranscriptPattern, TranscriptScannerConfig};
pub use factory::{KIND, TranscriptScannerFactory};
pub use scanner::TranscriptScanner;
