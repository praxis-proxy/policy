// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The bag keys the extension bridge emits, as data.
//
// This lives in the test harness rather than in the crate because nothing in
// the crate reads it. Moving it into `src/` would add a published module whose
// only consumer is a test, which is the shape `dead_code` is denied to
// prevent. The export the Cedar schema generator and the CEL load-time check
// need is what gives it a caller, and it moves when that lands.
//
// Three hand-maintained lists used to describe the same vocabulary and could
// disagree: the extractor modules that write keys, the capability to prefix
// table in `capability_namespaces`, and the per-slot catalog in
// `docs/content/cmf-extensions.md`. Nothing bound them together, so an
// extension field could land unbridged, a capability could name a prefix
// nothing writes, and the document could go stale, each without failing a
// test.
//
// This is the one declaration the other three are checked against. A field
// added to an extension reaches a policy author only by being written here,
// which is what makes the omission a test failure rather than a key nobody
// discovers is missing.
//
// It carries the key universe rather than the per-slot presence rules. Whether
// `subject.roles` is present-empty or omitted when unset is the absent-value
// contract, which `extensions_bridge` tests separately against a slot
// populated with defaults.

use praxis_policy_apl_cmf::constants::{
    CAP_READ_AGENT, CAP_READ_CLAIMS, CAP_READ_CLIENT, CAP_READ_COMPLETION, CAP_READ_CUSTOM,
    CAP_READ_DELEGATION, CAP_READ_FRAMEWORK, CAP_READ_HEADERS, CAP_READ_LABELS, CAP_READ_LLM,
    CAP_READ_MCP, CAP_READ_META, CAP_READ_PERMISSIONS, CAP_READ_PROVENANCE, CAP_READ_REQUEST,
    CAP_READ_ROLES, CAP_READ_SUBJECT, CAP_READ_TEAMS, CAP_READ_WORKLOAD,
};

/// The value type a bag key carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyType {
    /// `AttributeValue::Bool`.
    Bool,
    /// `AttributeValue::Int`.
    Int,
    /// `AttributeValue::Float`.
    Float,
    /// `AttributeValue::String`.
    String,
    /// `AttributeValue::StringSet`.
    StringSet,
    /// Whatever the host's JSON flattens to, so the type is the value's and
    /// not the key's. A claim holding a string writes a `String` and one
    /// holding a number writes an `Int` or a `Float` under the same key.
    Flattened,
}

impl KeyType {
    /// The spelling the documented tables use, so a doc check compares the
    /// same vocabulary an author reads.
    #[must_use]
    pub(crate) const fn documented(self) -> &'static str {
        match self {
            Self::Bool => "Bool",
            Self::Int => "Int",
            Self::Float => "Float",
            Self::String => "String",
            Self::StringSet => "StringSet",
            Self::Flattened => "flattened JSON",
        }
    }
}

/// The `Extensions` slot a key comes from, as `docs/content/cmf-extensions.md`
/// titles its section.
///
/// Recorded so the document check can hold a key to the right table rather
/// than to the page as a whole: a key listed under the wrong slot describes a
/// field that does not exist, and a reader looking under the right one does not
/// find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Slot {
    /// `security` — `SecurityExtension`, including the subject, client and
    /// both workload namespaces.
    Security,
    /// `delegation` — `DelegationExtension`.
    Delegation,
    /// `agent` — `AgentExtension`.
    Agent,
    /// `meta` — `MetaExtension`.
    Meta,
    /// `request` — `RequestExtension`.
    Request,
    /// `http` — `HttpExtension`.
    Http,
    /// `llm` — `LLMExtension`.
    Llm,
    /// `mcp` — `MCPExtension`.
    Mcp,
    /// `completion` — `CompletionExtension`.
    Completion,
    /// `provenance` — `ProvenanceExtension`.
    Provenance,
    /// `framework` — `FrameworkExtension`.
    Framework,
    /// `custom` — the host's own map.
    Custom,
}

impl Slot {
    /// The slot's name as the document's section heading spells it.
    #[must_use]
    pub(crate) const fn documented(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Delegation => "delegation",
            Self::Agent => "agent",
            Self::Meta => "meta",
            Self::Request => "request",
            Self::Http => "http",
            Self::Llm => "llm",
            Self::Mcp => "mcp",
            Self::Completion => "completion",
            Self::Provenance => "provenance",
            Self::Framework => "framework",
            Self::Custom => "custom",
        }
    }
}

/// Which capability a plugin needs before the key reaches it, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gating {
    /// Reading the typed field behind this key needs this capability, so the
    /// capability's bag prefixes have to cover the key.
    Capability(&'static str),

    /// An unrestricted sub-field: `filter_extensions` includes it whatever a
    /// plugin declared, so no capability gates the key either. Naming one here
    /// would tell an operator a grant they could withhold.
    Ungated,
}

/// Whether a key is one name or a family of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// One exact key, as in `subject.id`.
    Exact,

    /// A family, written here with a trailing `<name>` and emitted once per
    /// member of the underlying map or set. The part before `<name>` is the
    /// prefix a capability covers.
    Family,
}

/// One bag key, or one family of them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyEntry {
    /// The key as a policy author writes it. A family ends in `<name>`.
    pub(crate) key: &'static str,

    /// The value type.
    pub(crate) ty: KeyType,

    /// Whether this is one key or a family.
    pub(crate) shape: Shape,

    /// What a plugin must hold to read it.
    pub(crate) gating: Gating,

    /// Which slot it comes from, and so which section documents it.
    pub(crate) slot: Slot,
}

impl KeyEntry {
    /// The literal prefix a family's emitted keys start with, or the whole key
    /// for an exact one. What a capability prefix has to cover.
    #[must_use]
    pub(crate) fn literal_prefix(&self) -> &'static str {
        match self.shape {
            Shape::Exact => self.key,
            // `<name>` is always the trailing segment, so the prefix is what
            // precedes it, including the dot.
            Shape::Family => match self.key.find("<name>") {
                Some(at) => {
                    let (prefix, _) = self.key.split_at(at);
                    prefix
                },
                None => self.key,
            },
        }
    }
}

const fn exact(key: &'static str, ty: KeyType, gating: Gating, slot: Slot) -> KeyEntry {
    KeyEntry {
        key,
        ty,
        shape: Shape::Exact,
        gating,
        slot,
    }
}

const fn family(key: &'static str, ty: KeyType, gating: Gating, slot: Slot) -> KeyEntry {
    KeyEntry {
        key,
        ty,
        shape: Shape::Family,
        gating,
        slot,
    }
}

/// Every key the bridge emits, in the order the document lists them.
///
/// Fields deliberately left off the bag are absent from here too, and
/// `docs/content/cmf-extensions.md` records the reason for each: the
/// conversation transcript, both workloads' `attested_at`, the per-hop
/// delegation chain, MCP `annotations`, the tool schemas, the prompt
/// arguments, and `security.objects` / `security.data`.
pub(crate) const CATALOG: &[KeyEntry] = &[
    // 1. security — subject
    exact(
        "subject.id",
        KeyType::String,
        Gating::Capability(CAP_READ_SUBJECT),
        Slot::Security,
    ),
    exact(
        "subject.type",
        KeyType::String,
        Gating::Capability(CAP_READ_SUBJECT),
        Slot::Security,
    ),
    exact(
        "subject.roles",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_ROLES),
        Slot::Security,
    ),
    family(
        "role.<name>",
        KeyType::Bool,
        Gating::Capability(CAP_READ_ROLES),
        Slot::Security,
    ),
    exact(
        "subject.permissions",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_PERMISSIONS),
        Slot::Security,
    ),
    family(
        "perm.<name>",
        KeyType::Bool,
        Gating::Capability(CAP_READ_PERMISSIONS),
        Slot::Security,
    ),
    exact(
        "subject.teams",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_TEAMS),
        Slot::Security,
    ),
    family(
        "team.<name>",
        KeyType::Bool,
        Gating::Capability(CAP_READ_TEAMS),
        Slot::Security,
    ),
    family(
        "claim.<name>",
        KeyType::Flattened,
        Gating::Capability(CAP_READ_CLAIMS),
        Slot::Security,
    ),
    exact(
        "authenticated",
        KeyType::Bool,
        Gating::Capability(CAP_READ_SUBJECT),
        Slot::Security,
    ),
    // 1. security — client
    exact(
        "client.client_id",
        KeyType::String,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    exact(
        "client.client_name",
        KeyType::String,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    exact(
        "client.trust_level",
        KeyType::String,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    exact(
        "client.roles",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    family(
        "client.role.<name>",
        KeyType::Bool,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    exact(
        "client.permissions",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    family(
        "client.perm.<name>",
        KeyType::Bool,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    exact(
        "client.authorized_scopes",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    exact(
        "client.authorized_audiences",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    exact(
        "client.teams",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    family(
        "client.claim.<name>",
        KeyType::Flattened,
        Gating::Capability(CAP_READ_CLIENT),
        Slot::Security,
    ),
    // 1. security — workload, one namespace each
    exact(
        "caller_workload.spiffe_id",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "caller_workload.trust_domain",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "caller_workload.attestor",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "caller_workload.selectors",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "caller_workload.client_id",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "this_workload.spiffe_id",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "this_workload.trust_domain",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "this_workload.attestor",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "this_workload.selectors",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    exact(
        "this_workload.client_id",
        KeyType::String,
        Gating::Capability(CAP_READ_WORKLOAD),
        Slot::Security,
    ),
    // 1. security — other
    exact(
        "auth_method",
        KeyType::String,
        Gating::Ungated,
        Slot::Security,
    ),
    exact(
        "security.labels",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_LABELS),
        Slot::Security,
    ),
    exact(
        "security.classification",
        KeyType::String,
        Gating::Ungated,
        Slot::Security,
    ),
    // 2. delegation
    exact(
        "delegation.depth",
        KeyType::Int,
        Gating::Capability(CAP_READ_DELEGATION),
        Slot::Delegation,
    ),
    exact(
        "delegation.delegated",
        KeyType::Bool,
        Gating::Capability(CAP_READ_DELEGATION),
        Slot::Delegation,
    ),
    exact(
        "delegated",
        KeyType::Bool,
        Gating::Capability(CAP_READ_DELEGATION),
        Slot::Delegation,
    ),
    exact(
        "delegation.origin_subject_id",
        KeyType::String,
        Gating::Capability(CAP_READ_DELEGATION),
        Slot::Delegation,
    ),
    exact(
        "delegation.actor_subject_id",
        KeyType::String,
        Gating::Capability(CAP_READ_DELEGATION),
        Slot::Delegation,
    ),
    exact(
        "delegation.age_seconds",
        KeyType::Float,
        Gating::Capability(CAP_READ_DELEGATION),
        Slot::Delegation,
    ),
    // 3. agent
    exact(
        "agent.input",
        KeyType::String,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    exact(
        "agent.session_id",
        KeyType::String,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    exact(
        "agent.conversation_id",
        KeyType::String,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    exact(
        "agent.turn",
        KeyType::Int,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    exact(
        "agent.agent_id",
        KeyType::String,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    exact(
        "agent.parent_agent_id",
        KeyType::String,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    exact(
        "agent.conversation.summary",
        KeyType::String,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    exact(
        "agent.conversation.topics",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_AGENT),
        Slot::Agent,
    ),
    // 4. meta
    exact(
        "meta.entity_type",
        KeyType::String,
        Gating::Capability(CAP_READ_META),
        Slot::Meta,
    ),
    exact(
        "meta.entity_name",
        KeyType::String,
        Gating::Capability(CAP_READ_META),
        Slot::Meta,
    ),
    exact(
        "meta.tags",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_META),
        Slot::Meta,
    ),
    exact(
        "meta.scope",
        KeyType::String,
        Gating::Capability(CAP_READ_META),
        Slot::Meta,
    ),
    family(
        "meta.properties.<name>",
        KeyType::String,
        Gating::Capability(CAP_READ_META),
        Slot::Meta,
    ),
    // 5. request
    exact(
        "request.environment",
        KeyType::String,
        Gating::Capability(CAP_READ_REQUEST),
        Slot::Request,
    ),
    exact(
        "request.request_id",
        KeyType::String,
        Gating::Capability(CAP_READ_REQUEST),
        Slot::Request,
    ),
    exact(
        "request.timestamp",
        KeyType::String,
        Gating::Capability(CAP_READ_REQUEST),
        Slot::Request,
    ),
    exact(
        "request.trace_id",
        KeyType::String,
        Gating::Capability(CAP_READ_REQUEST),
        Slot::Request,
    ),
    exact(
        "request.span_id",
        KeyType::String,
        Gating::Capability(CAP_READ_REQUEST),
        Slot::Request,
    ),
    // 6. http
    exact(
        "http.method",
        KeyType::String,
        Gating::Capability(CAP_READ_HEADERS),
        Slot::Http,
    ),
    exact(
        "http.path",
        KeyType::String,
        Gating::Capability(CAP_READ_HEADERS),
        Slot::Http,
    ),
    exact(
        "http.host",
        KeyType::String,
        Gating::Capability(CAP_READ_HEADERS),
        Slot::Http,
    ),
    exact(
        "http.scheme",
        KeyType::String,
        Gating::Capability(CAP_READ_HEADERS),
        Slot::Http,
    ),
    exact(
        "http.status",
        KeyType::Int,
        Gating::Capability(CAP_READ_HEADERS),
        Slot::Http,
    ),
    family(
        "http.request_headers.<name>",
        KeyType::String,
        Gating::Capability(CAP_READ_HEADERS),
        Slot::Http,
    ),
    family(
        "http.response_headers.<name>",
        KeyType::String,
        Gating::Capability(CAP_READ_HEADERS),
        Slot::Http,
    ),
    // 7. llm
    exact(
        "llm.model_id",
        KeyType::String,
        Gating::Capability(CAP_READ_LLM),
        Slot::Llm,
    ),
    exact(
        "llm.provider",
        KeyType::String,
        Gating::Capability(CAP_READ_LLM),
        Slot::Llm,
    ),
    exact(
        "llm.capabilities",
        KeyType::StringSet,
        Gating::Capability(CAP_READ_LLM),
        Slot::Llm,
    ),
    // 8. mcp
    exact(
        "mcp.tool.name",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.tool.title",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.tool.description",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.tool.server_id",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.tool.namespace",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.resource.uri",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.resource.name",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.resource.description",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.resource.mime_type",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.resource.server_id",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.prompt.name",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.prompt.description",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    exact(
        "mcp.prompt.server_id",
        KeyType::String,
        Gating::Capability(CAP_READ_MCP),
        Slot::Mcp,
    ),
    // 9. completion
    exact(
        "completion.stop_reason",
        KeyType::String,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    exact(
        "completion.tokens.input",
        KeyType::Int,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    exact(
        "completion.tokens.output",
        KeyType::Int,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    exact(
        "completion.tokens.total",
        KeyType::Int,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    exact(
        "completion.model",
        KeyType::String,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    exact(
        "completion.raw_format",
        KeyType::String,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    exact(
        "completion.created_at",
        KeyType::String,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    exact(
        "completion.latency_ms",
        KeyType::Int,
        Gating::Capability(CAP_READ_COMPLETION),
        Slot::Completion,
    ),
    // 10. provenance
    exact(
        "provenance.source",
        KeyType::String,
        Gating::Capability(CAP_READ_PROVENANCE),
        Slot::Provenance,
    ),
    exact(
        "provenance.message_id",
        KeyType::String,
        Gating::Capability(CAP_READ_PROVENANCE),
        Slot::Provenance,
    ),
    exact(
        "provenance.parent_id",
        KeyType::String,
        Gating::Capability(CAP_READ_PROVENANCE),
        Slot::Provenance,
    ),
    // 11. framework
    exact(
        "framework.framework",
        KeyType::String,
        Gating::Capability(CAP_READ_FRAMEWORK),
        Slot::Framework,
    ),
    exact(
        "framework.framework_version",
        KeyType::String,
        Gating::Capability(CAP_READ_FRAMEWORK),
        Slot::Framework,
    ),
    exact(
        "framework.node_id",
        KeyType::String,
        Gating::Capability(CAP_READ_FRAMEWORK),
        Slot::Framework,
    ),
    exact(
        "framework.graph_id",
        KeyType::String,
        Gating::Capability(CAP_READ_FRAMEWORK),
        Slot::Framework,
    ),
    family(
        "framework.metadata.<name>",
        KeyType::Flattened,
        Gating::Capability(CAP_READ_FRAMEWORK),
        Slot::Framework,
    ),
    // 12. custom
    family(
        "custom.<name>",
        KeyType::Flattened,
        Gating::Capability(CAP_READ_CUSTOM),
        Slot::Custom,
    ),
];

/// Look a key up, matching a family by its literal prefix.
///
/// An emitted key belongs to at most one entry: no family's prefix is a prefix
/// of another's, and no exact key falls inside one, both of which
/// `the_catalog_is_unambiguous` holds.
#[must_use]
pub(crate) fn entry_for(key: &str) -> Option<&'static KeyEntry> {
    CATALOG.iter().find(|entry| match entry.shape {
        Shape::Exact => entry.key == key,
        Shape::Family => {
            let prefix = entry.literal_prefix();
            // A family emits one key per member, so a bare prefix with nothing
            // after it is not a member of it.
            key.len() > prefix.len() && key.starts_with(prefix)
        },
    })
}

#[cfg(test)]
#[allow(clippy::panic, reason = "tests")]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_catalog_is_unambiguous() {
        let mut seen: HashSet<&str> = HashSet::new();
        for entry in CATALOG {
            assert!(
                seen.insert(entry.key),
                "{} is listed twice; a duplicate would make the key set assertion \
                 pass with one of them missing from the bridge",
                entry.key
            );
        }
        // A key resolving through two entries would let a type mismatch hide
        // behind whichever the lookup found first.
        for entry in CATALOG {
            for other in CATALOG {
                if std::ptr::eq(entry, other) {
                    continue;
                }
                if other.shape == Shape::Family {
                    let prefix = other.literal_prefix();
                    assert!(
                        !(entry.literal_prefix().len() > prefix.len()
                            && entry.literal_prefix().starts_with(prefix)),
                        "{} falls inside the family {}",
                        entry.key,
                        other.key
                    );
                }
            }
        }
    }

    #[test]
    fn a_family_resolves_its_members_and_not_its_bare_prefix() {
        assert_eq!(entry_for("role.hr").map(|e| e.key), Some("role.<name>"));
        assert_eq!(
            entry_for("http.request_headers.x-a").map(|e| e.key),
            Some("http.request_headers.<name>")
        );
        // `role` alone is not a key the bridge writes.
        assert!(entry_for("role.").is_none());
        assert!(entry_for("role").is_none());
    }

    #[test]
    fn an_exact_key_resolves_to_itself() {
        assert_eq!(entry_for("subject.id").map(|e| e.ty), Some(KeyType::String));
        assert_eq!(entry_for("delegated").map(|e| e.ty), Some(KeyType::Bool));
        assert!(entry_for("subject.nonsense").is_none());
    }
}
