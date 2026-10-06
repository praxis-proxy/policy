// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What binds the three descriptions of the bag vocabulary together.
//
// `catalog::CATALOG` declares the keys. This file checks the other three
// against it: the bridge emits exactly them with the declared types, the
// capability table reaches exactly them, and the documented tables list
// exactly them, with the right type, under the slot they come from. Before
// this, each was maintained by hand and nothing failed when they disagreed:
// `SecurityExtension.objects` and `.data` were unbridged and absent from the
// document, and `read_workload` named a `workload.` prefix nothing wrote.
//
// Two things make a new extension field hard to leave unbridged. The fixture
// names every field of every slot and every slot of the container, with no
// `..Default::default()` anywhere, so adding either stops this file compiling
// and the author has to decide whether the bridge carries it. Then
// `the_bridge_emits_exactly_the_catalog` fails until the catalog and the
// document agree with what the bridge writes.
//
// Two things in the document stay unchecked. The absent-value contract, which
// is whether a key is present-empty or omitted when its field is unset:
// `extensions_bridge` covers that against slots populated with defaults,
// because this fixture populates everything and never exercises an absent one.
// And the "When" column, which is prose rather than a closed vocabulary.

#![allow(missing_docs, clippy::expect_used, reason = "test code")]

mod catalog;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use catalog::{CATALOG, Gating, KeyEntry, KeyType, Shape, entry_for};
use praxis_policy_apl_cmf::capability_namespaces::{
    capability_namespaces, known_read_capabilities,
};
use praxis_policy_apl_cmf::extract_extensions;
use praxis_policy_apl_core::{AttributeBag, AttributeValue};
use praxis_policy_core::extensions::{
    AgentExtension, ClientExtension, ClientTrustLevel, CompletionExtension, ConversationContext,
    DelegationExtension, DelegationHop, Extensions, FrameworkExtension, HttpExtension,
    LLMExtension, MCPExtension, MetaExtension, MonotonicSet, PromptMetadata, ProvenanceExtension,
    RequestExtension, ResourceMetadata, SecurityExtension, StopReason, SubjectExtension,
    SubjectType, TokenUsage, ToolMetadata, WorkloadIdentity,
};

/// One of every slot, with every field carrying a value.
///
/// Every field is written out rather than spread from `Default`, so adding one
/// to an extension breaks this file and the author has to decide whether the
/// bridge should carry it. That is the drift this whole file exists to catch,
/// and a `..Default::default()` here would reopen it.
fn fully_populated() -> Extensions {
    let mut annotations = HashMap::new();
    annotations.insert("readOnlyHint".to_owned(), serde_json::json!(true));

    let workload = |id: &str| WorkloadIdentity {
        spiffe_id: Some(format!("spiffe://td/{id}")),
        trust_domain: Some("td".to_owned()),
        // Emitted as `<ns>.attested_at`, RFC3339 at second precision with a
        // literal `Z`. The rendering is asserted in `security.rs`; here it only
        // has to be `Some` for the key to appear.
        attested_at: Some(
            "2026-10-01T12:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .expect("a literal RFC3339 instant"),
        ),
        attestor: Some("spire".to_owned()),
        selectors: vec![format!("k8s:ns:{id}")],
        client_id: Some(id.to_owned()),
    };

    let security = SecurityExtension {
        labels: MonotonicSet::from_set(HashSet::from(["PII".to_owned()])),
        classification: Some("secret".to_owned()),
        subject: Some(SubjectExtension {
            id: Some("alice".to_owned()),
            subject_type: Some(SubjectType::User),
            roles: HashSet::from(["hr".to_owned()]),
            permissions: HashSet::from(["read".to_owned()]),
            teams: HashSet::from(["eng".to_owned()]),
            claims: HashMap::from([("tenant".to_owned(), serde_json::json!("acme"))]),
        }),
        client: Some(ClientExtension {
            client_id: "app".to_owned(),
            client_name: Some("App".to_owned()),
            trust_level: ClientTrustLevel::FirstParty,
            authorized_scopes: vec!["s1".to_owned()],
            authorized_audiences: vec!["a1".to_owned()],
            roles: vec!["partner".to_owned()],
            permissions: vec!["write".to_owned()],
            teams: vec!["platform".to_owned()],
            claims: HashMap::from([("region".to_owned(), serde_json::json!("eu"))]),
        }),
        caller_workload: Some(workload("caller")),
        this_workload: Some(workload("self")),
        auth_method: Some("jwt".to_owned()),
        // Host-only by design, asserted in `extensions_bridge`.
        objects: HashMap::new(),
        data: HashMap::new(),
    };
    let delegation = DelegationExtension {
        // Per-hop state stays on the typed chain and reaches no key.
        chain: vec![DelegationHop {
            subject_id: "alice".to_owned(),
            subject_type: Some(SubjectType::User),
            audience: Some("aud".to_owned()),
            scopes_granted: vec!["write:payroll".to_owned()],
            authorization_details: Vec::new(),
            timestamp: Default::default(),
            ttl_seconds: Some(60),
            strategy: None,
            from_cache: true,
        }],
        depth: 1,
        origin_subject_id: Some("alice".to_owned()),
        actor_subject_id: Some("svc".to_owned()),
        delegated: true,
        age_seconds: 1.5,
    };
    let agent = AgentExtension {
        input: Some("hi".to_owned()),
        session_id: Some("sess".to_owned()),
        conversation_id: Some("conv".to_owned()),
        turn: Some(3),
        agent_id: Some("ag".to_owned()),
        parent_agent_id: Some("pag".to_owned()),
        conversation: Some(ConversationContext {
            // The transcript is deliberately off the bag.
            history: vec![serde_json::json!({"role": "user"})],
            summary: Some("sum".to_owned()),
            topics: vec!["t1".to_owned()],
        }),
    };
    let meta = MetaExtension {
        entity_type: Some("tool".to_owned()),
        entity_name: Some("search".to_owned()),
        tags: HashSet::from(["pii".to_owned()]),
        scope: Some("sc".to_owned()),
        properties: HashMap::from([("p".to_owned(), "v".to_owned())]),
    };
    let request = RequestExtension {
        environment: Some("prod".to_owned()),
        request_id: Some("rid".to_owned()),
        timestamp: Some("2026-01-01T00:00:00Z".to_owned()),
        trace_id: Some("tid".to_owned()),
        span_id: Some("sid".to_owned()),
    };
    let http = HttpExtension {
        request_headers: HashMap::from([("x-req".to_owned(), "1".to_owned())]),
        response_headers: HashMap::from([("x-res".to_owned(), "2".to_owned())]),
        status: Some(200),
        method: Some("POST".to_owned()),
        path: Some("/v1".to_owned()),
        host: Some("h".to_owned()),
        scheme: Some("https".to_owned()),
    };
    let llm = LLMExtension {
        model_id: Some("gpt-4".to_owned()),
        provider: Some("openai".to_owned()),
        capabilities: vec!["tools".to_owned()],
    };
    let mcp = MCPExtension {
        tool: Some(ToolMetadata {
            name: "search".to_owned(),
            title: Some("Search".to_owned()),
            description: Some("d".to_owned()),
            // The schemas stay off the bag; the annotations below flatten.
            input_schema: Some(serde_json::json!({"type": "object"})),
            output_schema: Some(serde_json::json!({"type": "object"})),
            server_id: Some("srv".to_owned()),
            namespace: Some("ns".to_owned()),
            annotations: annotations.clone(),
        }),
        resource: Some(ResourceMetadata {
            uri: "file:///x".to_owned(),
            name: Some("x".to_owned()),
            description: Some("d".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            server_id: Some("srv".to_owned()),
            annotations: annotations.clone(),
        }),
        prompt: Some(PromptMetadata {
            name: "p".to_owned(),
            description: Some("d".to_owned()),
            arguments: Some(vec![serde_json::json!({"name": "a"})]),
            server_id: Some("srv".to_owned()),
            annotations,
        }),
    };
    let completion = CompletionExtension {
        stop_reason: Some(StopReason::End),
        tokens: Some(TokenUsage {
            input_tokens: 1,
            output_tokens: 2,
            total_tokens: 3,
        }),
        model: Some("gpt-4".to_owned()),
        raw_format: Some("json".to_owned()),
        created_at: Some("2026-01-01T00:00:00Z".to_owned()),
        latency_ms: Some(42),
    };
    let provenance = ProvenanceExtension {
        source: Some("client".to_owned()),
        message_id: Some("mid".to_owned()),
        parent_id: Some("pid".to_owned()),
    };
    let framework = FrameworkExtension {
        framework: Some("langgraph".to_owned()),
        framework_version: Some("1".to_owned()),
        node_id: Some("n".to_owned()),
        graph_id: Some("g".to_owned()),
        metadata: HashMap::from([("m".to_owned(), serde_json::json!(1))]),
    };
    let custom = HashMap::from([("c".to_owned(), serde_json::json!("v"))]);

    // Named field by field rather than spread from `Default`, so a slot added
    // to the container also breaks this file. The three non-slot fields carry
    // write tokens and host handles, which the bridge never reads.
    Extensions {
        security: Some(Arc::new(security)),
        delegation: Some(Arc::new(delegation)),
        agent: Some(Arc::new(agent)),
        meta: Some(Arc::new(meta)),
        request: Some(Arc::new(request)),
        http: Some(Arc::new(http)),
        llm: Some(Arc::new(llm)),
        mcp: Some(Arc::new(mcp)),
        completion: Some(Arc::new(completion)),
        provenance: Some(Arc::new(provenance)),
        framework: Some(Arc::new(framework)),
        custom: Some(Arc::new(custom)),
        // Slots the bridge deliberately does not flatten. `llm_request`
        // reaches a PDP through a structured side channel and
        // `raw_credentials` through plugin payloads; neither becomes a key.
        candidate_constraint: None,
        raw_credentials: None,
        llm_request: None,
        http_write_token: None,
        labels_write_token: None,
        delegation_write_token: None,
        http_transport: Default::default(),
        effect_log: Default::default(),
    }
}

fn emitted() -> AttributeBag {
    let mut bag = AttributeBag::new();
    extract_extensions(&fully_populated(), &mut bag);
    bag
}

fn type_of(value: &AttributeValue) -> KeyType {
    match value {
        AttributeValue::Bool(_) => KeyType::Bool,
        AttributeValue::Int(_) => KeyType::Int,
        AttributeValue::Float(_) => KeyType::Float,
        AttributeValue::String(_) => KeyType::String,
        AttributeValue::StringSet(_) => KeyType::StringSet,
    }
}

// =====================================================================
// AC 1: the bridge emits exactly the catalog
// =====================================================================

#[test]
fn the_bridge_emits_exactly_the_catalog() {
    let bag = emitted();

    let mut unlisted: Vec<&str> = bag
        .iter()
        .filter(|(key, _)| entry_for(key).is_none())
        .map(|(key, _)| key)
        .collect();
    unlisted.sort_unstable();
    assert!(
        unlisted.is_empty(),
        "the bridge emits keys the catalog does not declare: {unlisted:?}. \
         Add them to `catalog::CATALOG` and to the per-slot table in \
         docs/content/cmf-extensions.md, or stop writing them."
    );

    // Every entry has to be reached by something, or the catalog is declaring
    // a key no author can read and the document is promising one.
    let mut unemitted: Vec<&str> = CATALOG
        .iter()
        .filter(|entry| match entry.shape {
            Shape::Exact => !bag.contains(entry.key),
            Shape::Family => !bag.iter().any(|(key, _)| {
                let prefix = entry.literal_prefix();
                key.len() > prefix.len() && key.starts_with(prefix)
            }),
        })
        .map(|entry| entry.key)
        .collect();
    unemitted.sort_unstable();
    assert!(
        unemitted.is_empty(),
        "the catalog declares keys a fully populated container does not emit: \
         {unemitted:?}. Either the bridge stopped writing them or the fixture \
         above stopped populating the field they come from."
    );
}

#[test]
fn every_emitted_value_has_the_documented_type() {
    let mut wrong: Vec<String> = Vec::new();
    for (key, value) in emitted().iter() {
        let entry = entry_for(key).expect("checked by the key set test");
        let actual = type_of(value);
        // A flattened family takes the host JSON's type, so the key does not
        // fix one. Everything else does.
        if entry.ty != KeyType::Flattened && entry.ty != actual {
            wrong.push(format!(
                "{key} is {} but the catalog says {}",
                actual.documented(),
                entry.ty.documented()
            ));
        }
    }
    wrong.sort();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

// =====================================================================
// AC 7: the capability table agrees with the catalog
// =====================================================================

/// Whether a capability prefix covers a key. A prefix ending in `.` covers
/// anything beneath it; one without covers only itself.
fn prefix_covers(prefix: &str, key: &str) -> bool {
    if prefix.ends_with('.') {
        key.starts_with(prefix)
    } else {
        key == prefix
    }
}

/// A key to test a prefix against. A family's `<name>` spelling is not a key
/// anything emits, so a member is appended.
fn probe_key(entry: &KeyEntry) -> String {
    match entry.shape {
        Shape::Exact => entry.key.to_owned(),
        Shape::Family => format!("{}x", entry.literal_prefix()),
    }
}

#[test]
fn each_gated_key_is_unlocked_by_the_capability_it_declares() {
    let mut unreachable: Vec<(&str, &str)> = Vec::new();
    for entry in CATALOG {
        let Gating::Capability(cap) = entry.gating else {
            continue;
        };
        let probe = probe_key(entry);
        if !capability_namespaces(cap)
            .iter()
            .any(|p| prefix_covers(p, &probe))
        {
            unreachable.push((entry.key, cap));
        }
    }
    unreachable.sort_unstable();
    assert!(
        unreachable.is_empty(),
        "the bridge writes these keys but the capability they are gated on \
         names no prefix covering them, so `capability_namespaces` understates \
         what a plugin holding it can see: {unreachable:?}"
    );
}

#[test]
fn an_ungated_key_is_unlocked_by_no_capability() {
    let prefixes: Vec<&str> = known_read_capabilities()
        .flat_map(capability_namespaces)
        .copied()
        .collect();

    let mut gated: Vec<&str> = CATALOG
        .iter()
        .filter(|entry| entry.gating == Gating::Ungated)
        .filter(|entry| {
            let probe = probe_key(entry);
            prefixes.iter().any(|p| prefix_covers(p, &probe))
        })
        .map(|entry| entry.key)
        .collect();
    gated.sort_unstable();
    assert!(
        gated.is_empty(),
        "`filter_extensions` includes these whatever a plugin declared, so a \
         capability naming them would promise an operator a grant they could \
         withhold: {gated:?}"
    );
}

#[test]
fn no_capability_names_a_prefix_nothing_writes() {
    let mut dead: Vec<(&str, &str)> = Vec::new();
    for cap in known_read_capabilities() {
        for prefix in capability_namespaces(cap) {
            let covers_something = CATALOG
                .iter()
                .any(|entry| prefix_covers(prefix, &probe_key(entry)));
            if !covers_something {
                dead.push((cap, prefix));
            }
        }
    }
    dead.sort_unstable();
    assert!(
        dead.is_empty(),
        "these capability prefixes cover no key the bridge writes, so the \
         table promises an operator a namespace that does not exist: {dead:?}"
    );
}

// =====================================================================
// AC 2: the documented tables match the catalog
// =====================================================================

fn docs_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/content/cmf-extensions.md")
        .canonicalize()
        .expect("docs/content/cmf-extensions.md exists")
}

/// What one documented row says about a key.
struct Documented {
    /// The Type column, with any parenthesized qualifier dropped.
    ty: String,

    /// The `### N. <slot>` section the row appears under.
    slot: String,
}

/// Each key the per-slot tables list, with the type and the section they give
/// it, normalized to the catalog's spelling.
///
/// Only the tables under "The twelve slots" are read. The payload tables after
/// it describe `args.*`, `result.*` and `data.*`, which the payload flattener
/// writes and this bridge does not.
fn documented() -> HashMap<String, Documented> {
    let text = std::fs::read_to_string(docs_path()).expect("the catalog page reads");
    let section = text
        .split_once("## The twelve slots")
        .expect("the per-slot section is still titled 'The twelve slots'")
        .1
        .split_once("## Payloads that are not slots")
        .expect("the payload section still follows the slots")
        .0;

    let mut rows = HashMap::new();
    let mut slot = String::new();
    for line in section.lines() {
        let line = line.trim();
        // `### 7. `llm` — `LLMExtension``: the first backticked word is the
        // slot, which is what the catalog records against each key.
        if let Some(heading) = line.strip_prefix("### ") {
            slot = heading
                .split_once('`')
                .and_then(|(_, rest)| rest.split('`').next())
                .unwrap_or_default()
                .to_owned();
            continue;
        }
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        let Some(first) = cells.first() else { continue };
        // A header row or the `|---|` separator carries no backticked key.
        let Some(key) = first
            .strip_prefix('`')
            .and_then(|rest| rest.split('`').next())
        else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        // The Type column qualifies some types with the values they can take,
        // as in "Bool (`true`)". The type itself is what precedes that.
        let ty = cells
            .get(1)
            .map_or("", |cell| cell.split_once(" (").map_or(*cell, |(ty, _)| ty))
            .trim()
            .to_owned();
        // The document writes one workload table for two namespaces, and
        // spells a claim's member `<dotted>` to say a dotted name is taken
        // whole. The catalog spells both namespaces and uses one placeholder.
        let key = key.replace("<dotted>", "<name>");
        if let Some(rest) = key.strip_prefix("<ns>.") {
            for ns in ["caller_workload", "this_workload"] {
                rows.insert(
                    format!("{ns}.{rest}"),
                    Documented {
                        ty: ty.clone(),
                        slot: slot.clone(),
                    },
                );
            }
        } else {
            rows.insert(
                key,
                Documented {
                    ty,
                    slot: slot.clone(),
                },
            );
        }
    }
    rows
}

#[test]
fn the_documented_tables_list_exactly_the_catalog() {
    let documented: HashSet<String> = documented().into_keys().collect();
    let declared: HashSet<String> = CATALOG.iter().map(|e| e.key.to_owned()).collect();

    let mut missing_from_docs: Vec<&String> = declared.difference(&documented).collect();
    missing_from_docs.sort();
    let mut missing_from_catalog: Vec<&String> = documented.difference(&declared).collect();
    missing_from_catalog.sort();

    assert!(
        missing_from_docs.is_empty() && missing_from_catalog.is_empty(),
        "docs/content/cmf-extensions.md and `catalog::CATALOG` disagree.\n\
         declared but undocumented: {missing_from_docs:?}\n\
         documented but not declared: {missing_from_catalog:?}"
    );
}

#[test]
fn the_documented_types_match_the_catalog() {
    let documented = documented();
    let mut wrong: Vec<String> = Vec::new();
    for entry in CATALOG {
        let Some(doc) = documented.get(entry.key) else {
            // Absence is the other test's failure, reported there.
            continue;
        };
        if doc.ty != entry.ty.documented() {
            wrong.push(format!(
                "{}: the table says {}, the catalog says {}",
                entry.key,
                doc.ty,
                entry.ty.documented()
            ));
        }
    }
    wrong.sort();
    assert!(
        wrong.is_empty(),
        "the documented Type column disagrees with the catalog, so an author \
         reading the page would write a predicate against the wrong type: {wrong:#?}"
    );
}

#[test]
fn each_key_is_documented_under_the_slot_it_comes_from() {
    let documented = documented();
    let mut misplaced: Vec<String> = Vec::new();
    for entry in CATALOG {
        let Some(doc) = documented.get(entry.key) else {
            continue;
        };
        if doc.slot != entry.slot.documented() {
            misplaced.push(format!(
                "{} is documented under `{}` but comes from `{}`",
                entry.key,
                doc.slot,
                entry.slot.documented()
            ));
        }
    }
    misplaced.sort();
    assert!(
        misplaced.is_empty(),
        "a key under the wrong section describes a field that slot does not \
         have, and a reader looking under the right one does not find it:          {misplaced:#?}"
    );
}
