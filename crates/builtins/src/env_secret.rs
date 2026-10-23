// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Format environment lookup failures without exposing the non-Unicode value
// carried inside VarError::NotUnicode.
pub(crate) fn error(label: &str, name: &str, error: std::env::VarError) -> String {
    let reason = match error {
        std::env::VarError::NotPresent => "is not set",
        std::env::VarError::NotUnicode(_) => "is not valid Unicode",
    };
    format!("{label} env var '{name}' {reason}")
}
