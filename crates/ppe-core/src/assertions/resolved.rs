// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// One direction's contract, accumulated over the four config levels.
//
// Owned rather than borrowed from a level, because the result is a merge of up
// to four of them and no single level owns it. Rendering and removal read this,
// so neither sees the layering.

use super::AssertionLevel;
use super::config::{Encoding, OnMissing, StripPattern};
use super::source::SourcePath;

/// An entry's source, with its slot paths parsed.
#[derive(Debug, Clone)]
pub enum ResolvedSource {
    /// One slot, rendered as the header's whole value.
    From(SourcePath),

    /// Named members, rendered as one JSON object, in key order.
    Members(Vec<(String, SourcePath)>),

    /// A source config load accepted and resolution could not parse.
    ///
    /// Unreachable: validation parses every source before a request is served.
    /// It exists so an impossible case still removes the entry's target rather
    /// than dropping the entry whole, which would leave a client-supplied value
    /// under an asserted name.
    Unresolvable,
}

/// One header the accumulated contract asserts, with where it came from.
#[derive(Debug, Clone)]
pub struct ResolvedHeader {
    /// The target header name, as the winning level wrote it.
    pub name: String,

    /// The same name lowercased, which is what removal compares against.
    pub lowercase: String,

    /// Where the value comes from.
    pub source: ResolvedSource,

    /// What an absent source does.
    pub on_missing: OnMissing,

    /// How a value that is not a scalar renders.
    pub encode: Option<Encoding>,

    /// The level that declared this entry, as a diagnostic names it.
    pub declared_in: String,

    /// Which of the four levels that is.
    pub level: AssertionLevel,

    /// The level whose entry on this header this one replaced, when it
    /// replaced one. Rendered by the artifact so an inherited entry that stops
    /// applying is visible.
    pub overrode: Option<String>,
}

/// One direction's accumulated contract.
#[derive(Debug, Clone, Default)]
pub struct ResolvedContract {
    /// The headers to assert, in the order the levels contributed them. A
    /// repeated name keeps its first position and takes the later level's
    /// entry whole.
    pub headers: Vec<ResolvedHeader>,

    /// The accumulated `strip:` patterns, deduplicated.
    pub strip: Vec<StripPattern>,
}

impl ResolvedContract {
    /// Whether the contract asserts nothing and removes nothing beyond it.
    ///
    /// An empty contract is not the same as no contract: a level can clear
    /// what it inherited and contribute nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty() && self.strip.is_empty()
    }

    /// Whether a wire header is removed before injection.
    ///
    /// True for a name any entry targets, whether or not that entry's source
    /// resolved to anything, and for a name any `strip:` pattern matches. The
    /// first half is unconditional on purpose: a target whose source resolved
    /// to nothing must not leave the wire value standing under a name the
    /// other side reads as ours.
    #[must_use]
    pub fn removes(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.headers.iter().any(|header| header.lowercase == lower)
            || self
                .strip
                .iter()
                .any(|pattern| pattern.matches_lowercase(&lower))
    }
}
