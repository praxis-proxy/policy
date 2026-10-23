// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-plugin-transcript-scanner — CMF `HookHandler` that walks the
// prior turns carried on `AgentExtension.conversation.history` and tests
// supported content against operator-supplied patterns. A match denies with
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
//! supported text matching one of the configured patterns. This includes text,
//! reasoning, argument and result values, resource content and blobs decoded
//! as UTF-8 with replacement, and rendered prompt content and messages.
//! Metadata, JSON object keys, URIs, and encoded media are outside scope.
//! `roles` filters outer turns, including turns with nested prompt messages.
//! Missing history is treated as empty and allowed; the host must report
//! history for this scanner to provide coverage.

/// Plugin configuration: the patterns and the roles to scan.
pub mod config;
/// Constructs the scanner from configuration.
pub mod factory;
/// The CMF hook handler that walks history and applies the patterns.
pub mod scanner;

pub use config::{TranscriptPattern, TranscriptScannerConfig};
pub use factory::{KIND, TranscriptScannerFactory};
pub use scanner::TranscriptScanner;
