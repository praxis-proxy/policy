// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Unified entry point: take an `Extensions` container, dispatch each
// present slot to its per-extension extractor.
//
// This is the function `praxis-policy-apl-runtime` will call at hook time after assembling
// `Extensions` from the request. It guarantees every slot that's present
// gets bridged, so a new extension type that adds an extractor module
// shows up in the bag automatically.

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::Extensions;

use crate::{
    agent::extract_agent, completion::extract_completion, custom::extract_custom,
    delegation::extract_delegation, framework::extract_framework, http::extract_http,
    llm::extract_llm, mcp::extract_mcp, meta::extract_meta, provenance::extract_provenance,
    request::extract_request, security::extract_security,
};

/// Flatten every present slot in `Extensions` into `bag`.
///
/// An absent slot writes nothing. A present slot follows the per-type
/// absent-value contract in `docs/cmf-extensions.md`: `StringSet` keys are
/// present-empty, optional scalars are omitted, flattened member booleans
/// are presence-only.
pub fn extract_extensions(ext: &Extensions, bag: &mut AttributeBag) {
    if let Some(v) = &ext.security {
        extract_security(v, bag);
    }
    if let Some(v) = &ext.delegation {
        extract_delegation(v, bag);
    }
    if let Some(v) = &ext.agent {
        extract_agent(v, bag);
    }
    if let Some(v) = &ext.meta {
        extract_meta(v, bag);
    }
    if let Some(v) = &ext.request {
        extract_request(v, bag);
    }
    if let Some(v) = &ext.http {
        extract_http(v, bag);
    }
    if let Some(v) = &ext.llm {
        extract_llm(v, bag);
    }
    if let Some(v) = &ext.mcp {
        extract_mcp(v, bag);
    }
    if let Some(v) = &ext.completion {
        extract_completion(v, bag);
    }
    if let Some(v) = &ext.provenance {
        extract_provenance(v, bag);
    }
    if let Some(v) = &ext.framework {
        extract_framework(v, bag);
    }
    if let Some(v) = &ext.custom {
        extract_custom(v, bag);
    }
}

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;
    use praxis_policy_core::extensions::{
        AgentExtension, ClientExtension, CompletionExtension, ConversationContext,
        DelegationExtension, FrameworkExtension, HttpExtension, LLMExtension, MCPExtension,
        MetaExtension, ProvenanceExtension, RequestExtension, SecurityExtension, SubjectExtension,
        WorkloadIdentity,
    };
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    #[test]
    fn dispatches_every_present_slot() {
        let mut ext = Extensions::default();
        ext.security = Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice".into()),
                roles: HashSet::from(["hr".to_owned()]),
                ..Default::default()
            }),
            ..Default::default()
        }));
        ext.delegation = Some(Arc::new(DelegationExtension::default()));
        ext.agent = Some(Arc::new(AgentExtension {
            session_id: Some("sess-1".into()),
            ..Default::default()
        }));
        ext.meta = Some(Arc::new(MetaExtension {
            tags: HashSet::from(["pii".to_owned()]),
            ..Default::default()
        }));
        ext.llm = Some(Arc::new(LLMExtension {
            model_id: Some("gpt-4".into()),
            ..Default::default()
        }));

        let mut bag = AttributeBag::new();
        extract_extensions(&ext, &mut bag);

        // One assertion per namespace — proves the dispatch reached each.
        assert_eq!(bag.get_string("subject.id"), Some("alice"));
        assert_eq!(bag.get_bool("role.hr"), Some(true));
        assert_eq!(bag.get_int("delegation.depth"), Some(0));
        assert_eq!(bag.get_string("agent.session_id"), Some("sess-1"));
        assert!(bag.set_contains("meta.tags", "pii"));
        assert_eq!(bag.get_string("llm.model_id"), Some("gpt-4"));
    }

    #[test]
    fn absent_slots_skipped_no_panic() {
        let ext = Extensions::default();
        let mut bag = AttributeBag::new();
        extract_extensions(&ext, &mut bag);
        assert!(bag.is_empty());
    }

    fn empty() -> HashSet<String> {
        HashSet::new()
    }

    fn bag_of(ext: Extensions) -> AttributeBag {
        let mut bag = AttributeBag::new();
        extract_extensions(&ext, &mut bag);
        bag
    }

    /// The per-type contract in `docs/cmf-extensions.md`: inside a present
    /// slot, `StringSet` is present-empty, optional scalars are omitted,
    /// non-option scalars are written, flattened member bools are absent.
    #[test]
    fn present_slots_follow_the_absent_value_contract() {
        let mut ext = Extensions::default();
        ext.security = Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension::default()),
            client: Some(ClientExtension {
                client_id: "app".into(),
                ..Default::default()
            }),
            caller_workload: Some(WorkloadIdentity::default()),
            this_workload: Some(WorkloadIdentity::default()),
            ..Default::default()
        }));
        ext.delegation = Some(Arc::new(DelegationExtension::default()));
        ext.agent = Some(Arc::new(AgentExtension {
            conversation: Some(ConversationContext::default()),
            ..Default::default()
        }));
        ext.meta = Some(Arc::new(MetaExtension::default()));
        ext.request = Some(Arc::new(RequestExtension::default()));
        ext.http = Some(Arc::new(HttpExtension::default()));
        ext.llm = Some(Arc::new(LLMExtension::default()));
        ext.mcp = Some(Arc::new(MCPExtension::default()));
        ext.completion = Some(Arc::new(CompletionExtension::default()));
        ext.provenance = Some(Arc::new(ProvenanceExtension::default()));
        ext.framework = Some(Arc::new(FrameworkExtension::default()));
        ext.custom = Some(Arc::new(HashMap::new()));

        let bag = bag_of(ext);

        // StringSet: present and empty.
        for key in [
            "subject.roles",
            "subject.permissions",
            "subject.teams",
            "client.roles",
            "client.permissions",
            "client.authorized_scopes",
            "client.authorized_audiences",
            "client.teams",
            "caller_workload.selectors",
            "this_workload.selectors",
            "security.labels",
            "agent.conversation.topics",
            "meta.tags",
            "llm.capabilities",
        ] {
            assert_eq!(
                bag.get_string_set(key),
                Some(&empty()),
                "{key} must be present-empty, not omitted"
            );
        }

        // Optional strings / ints / derived bools: omitted.
        for key in [
            "subject.id",
            "subject.type",
            "authenticated",
            "client.client_name",
            "auth_method",
            "security.classification",
            "delegation.origin_subject_id",
            "agent.session_id",
            "agent.turn",
            "meta.entity_type",
            "request.environment",
            "http.method",
            "http.status",
            "llm.model_id",
            "mcp.tool.name",
            "completion.latency_ms",
            "provenance.source",
            "framework.framework",
        ] {
            assert!(
                !bag.contains(key),
                "{key} is optional and must be omitted when unset"
            );
        }

        // Flattened member bools: presence-only.
        assert_eq!(bag.get_bool("role.hr"), None);
        assert_eq!(bag.get_bool("perm.read"), None);
        assert_eq!(bag.get_bool("team.eng"), None);
        assert_eq!(bag.get_bool("client.role.partner"), None);

        // Non-option scalars on a present slot: written, including zero/false.
        assert_eq!(bag.get_int("delegation.depth"), Some(0));
        assert_eq!(bag.get_bool("delegation.delegated"), Some(false));
        assert_eq!(bag.get_bool("delegated"), Some(false));
        assert_eq!(bag.get_float("delegation.age_seconds"), Some(0.0));
        assert_eq!(bag.get_string("client.client_id"), Some("app"));
        assert!(bag.get_string("client.trust_level").is_some());

        // Empty claims / custom / framework metadata: no parent object key.
        assert!(!bag.contains("subject.claims"));
        assert!(!bag.contains("claim"));
        assert!(!bag.contains("custom"));
        assert!(!bag.contains("framework.metadata"));
    }

    #[test]
    fn original_set_and_flattened_bools_stay_paired() {
        let mut ext = Extensions::default();
        ext.security = Some(Arc::new(SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice".into()),
                roles: HashSet::from(["hr".to_owned(), "reader".to_owned()]),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let bag = bag_of(ext);
        assert!(bag.set_contains("subject.roles", "hr"));
        assert!(bag.set_contains("subject.roles", "reader"));
        assert_eq!(bag.get_bool("role.hr"), Some(true));
        assert_eq!(bag.get_bool("role.reader"), Some(true));
        assert_eq!(bag.get_bool("role.admin"), None);
        assert!(
            !bag.set_contains("subject.roles", "admin"),
            "a name missing from the set must not appear as a flattened true"
        );
    }
}
