// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Build-time errors for the OPA PDP. These surface at config-load time (when
// the praxis-policy-apl-runtime visitor calls the factory), so an operator sees bad policy or
// malformed config at deploy rather than on the first request. Mirrors the
// shape of `praxis-policy-pdp-cedar-direct`'s `BuildError`.

use thiserror::Error;

/// Errors produced while building an `OpaResolver` from its config block.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The config block is not shaped as expected (not a mapping, unknown key,
    /// wrong value type for a known key).
    #[error("invalid OPA PDP config: {0}")]
    ConfigShape(String),

    /// A `module_files` entry could not be read from disk.
    #[error("failed to read OPA module file '{path}': {source}")]
    ModuleFile {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// A Rego module (inline or from a file) failed to parse/compile. This is
    /// an author bug surfaced at load time so it never reaches evaluation. The
    /// regorus cause is stringified (its error is a type-erased `anyhow::Error`,
    /// so there is no variant to carry).
    #[error("failed to load Rego module '{name}': {cause}")]
    ModuleParse {
        /// The module, named by file path or by the step that carried it inline.
        name: String,
        /// The interpreter's message, stringified.
        cause: String,
    },

    /// A `data_files` entry could not be read from disk.
    #[error("failed to read OPA data file '{path}': {source}")]
    DataFile {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// A `data` document (inline or from a file) could not be parsed or merged
    /// into the engine's `data` root.
    #[error("failed to load OPA data '{name}': {cause}")]
    DataParse {
        /// The document, named by file path or `inline`.
        name: String,
        /// The parse or merge failure.
        cause: String,
    },
}
