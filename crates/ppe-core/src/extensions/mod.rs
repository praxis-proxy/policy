// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Typed extension models for the PPE framework.
//
// Each extension carries contextual metadata with an explicit
// mutability tier enforced by the processing pipeline. Extensions
// are always passed separately from the payload to handlers.
//

/// Agent session, conversation, and lineage.
pub mod agent;
/// RFC 9396 rich authorization request detail.
pub mod authorization;
/// LLM completion metadata.
pub mod completion;
/// Typed containers holding every extension for one request.
pub mod container;
/// The token delegation chain.
pub mod delegation;
/// Capability-gated filtering of extension visibility.
pub mod filter;
/// Agentic framework context.
pub mod framework;
/// Capability-gated write access to a value.
pub mod guarded;
/// HTTP request and response headers.
pub mod http;
/// Model identity and capabilities.
pub mod llm;
/// Tool, resource, and prompt metadata.
pub mod mcp;
/// Host-provided operational metadata.
pub mod meta;
/// An add-only set, enforced by the type.
pub mod monotonic;
/// Message origin and threading.
pub mod provenance;
/// Raw token material, kept separate from derived identity.
pub mod raw_credentials;
/// Execution environment and tracing identifiers.
pub mod request;
/// Backend candidate constraints for a request.
pub mod routing;
/// Labels, classification, identity, and data policy.
pub mod security;
/// Mutability tiers and capability definitions.
pub mod tiers;

// Re-export containers
pub use container::{Extensions, OwnedExtensions};

// Re-export all extension types
pub use agent::{AgentExtension, ConversationContext};
pub use authorization::AuthorizationDetail;
pub use completion::{CompletionExtension, StopReason, TokenUsage};
pub use delegation::{DelegationExtension, DelegationHop, DelegationStrategy};
pub use filter::{SlotName, filter_extensions};
pub use framework::FrameworkExtension;
pub use guarded::{Guarded, WriteToken};
pub use http::HttpExtension;
pub use llm::LLMExtension;
pub use mcp::{MCPExtension, PromptMetadata, ResourceMetadata, ToolMetadata};
pub use meta::MetaExtension;
pub use monotonic::{DeclassifierToken, MonotonicSet};
pub use provenance::ProvenanceExtension;
pub use raw_credentials::{
    Credential, DelegationKey, DelegationMode, RawCredentialsExtension, RawDelegatedToken,
    RawInboundToken, TokenKind, TokenRole,
};
pub use request::RequestExtension;
pub use routing::{
    BackendLabels, CAP_WRITE_CANDIDATE_CONSTRAINT, CandidateConstraintExtension, OnEmpty,
};
pub use security::{
    ClientExtension, ClientTrustLevel, DataPolicy, ObjectSecurityProfile, RetentionPolicy,
    SecurityExtension, SubjectExtension, SubjectType, WorkloadIdentity,
};
pub use tiers::{AccessPolicy, Capability, MutabilityTier, SlotPolicy};
