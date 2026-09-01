// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What the engine asserts on a request and a response, as headers.
//
// The block holds two contracts. `request:` renders engine-derived state onto
// the upstream request and removes the client-supplied headers that would
// collide with it. `response:` removes what an upstream should not be telling
// the client and adds what it should.
//
// The two directions do not share semantics, and the asymmetry is deliberate.
// The engine originates every value a request entry asserts, so the legitimate
// set is finite and anything unnamed can be withheld. A response is a
// passthrough of an upstream's own output, which the engine originates none of
// and cannot enumerate, so a response entry removes what it names and
// everything else reaches the client. `floor` is what keeps a greedy glob off
// the headers a client needs in order to read the response at all.
//
// Whatever crosses either boundary is an unsigned statement. Whoever receives
// it believes it because they believe the network path, not because they can
// verify anything.

/// Applying a rendered contract to the wire header maps.
pub mod apply;
/// What crosses the boundary, as one document.
pub mod artifact;
/// The typed `assertions:` block and its validation.
pub mod config;
/// The response headers a `strip:` entry can never remove.
pub mod floor;
/// Turning a resolved contract and request state into header values.
pub mod render;
/// One direction's contract, accumulated over the four config levels.
pub mod resolved;
/// The slots an entry may read, and what reading one yields.
pub mod source;

pub use apply::apply;
pub use artifact::effective_policy;
pub use config::{
    AssertionsConfig, AuthoredSource, DirectionBlock, Encoding, HeaderEntry, OnMissing,
    StripPattern,
};
pub use floor::{
    FloorEntry, REQUEST_FLOOR, RESPONSE_FLOOR, floor_for, glob_would_match_floor, is_floor,
};
pub use render::{MissingSource, render};
pub use resolved::{ResolvedContract, ResolvedHeader, ResolvedSource};
pub use source::{SourceError, SourcePath, SourceRejection};

/// Which of the two contracts is in force.
///
/// Derived from the hook's registered phase rather than from a list of hook
/// names: a `Pre` hook applies the request contract, a `Post` hook the
/// response one, and an unphased hook neither. That is why this feature names
/// no hook anywhere, and why a hook family added later needs no change here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Toward the upstream, on the way in.
    Request,

    /// Toward the client, on the way out.
    Response,
}

impl Direction {
    /// The direction as a config path, for a diagnostic and for the artifact.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Request => "assertions.request",
            Self::Response => "assertions.response",
        }
    }

    /// The contract this direction reads out of a block, if the block declares
    /// one.
    #[must_use]
    pub fn block_of(self, assertions: &AssertionsConfig) -> Option<&DirectionBlock> {
        match self {
            Self::Request => assertions.request.as_ref(),
            Self::Response => assertions.response.as_ref(),
        }
    }

    /// The phase a hook must carry for this direction to apply.
    #[must_use]
    pub fn from_phase(phase: crate::hooks::HookPhase) -> Option<Self> {
        match phase {
            crate::hooks::HookPhase::Pre => Some(Self::Request),
            crate::hooks::HookPhase::Post => Some(Self::Response),
            // Not a wire boundary: identity, delegation and elicitation fire
            // once per request without a side of the exchange to act on.
            crate::hooks::HookPhase::Unphased => None,
        }
    }
}

/// Which of the four config levels a resolved header entry came from.
///
/// Carried on the resolved contract so the artifact can say where a header was
/// declared, and so resolution can assert in debug that two bundles never
/// override each other, which config load already refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionLevel {
    /// The `global:` block.
    Global,
    /// A `global.defaults.<entity>:` block.
    EntityDefault,
    /// A `groups.<name>:` bundle.
    Bundle,
    /// A `routes[]` entry's own block.
    Route,
}
