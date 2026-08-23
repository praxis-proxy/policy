// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `ClaimMapper` a compiled claim map drives. One resolution routine serves
// all three roles: walk a field's candidates in the order they were authored,
// take what each contributes, and stop at the first that resolves unless the
// field asked for a union.
//
// A candidate whose value is present but the wrong shape counts as not
// resolving, so the chain keeps looking. That is what the Rust standard mapper
// does (`and_then(Value::as_array)` returning `None` runs the `else if`), and it
// is what makes an unusable shape ignorable rather than fatal.

use std::collections::{HashMap, HashSet};

use praxis_policy_core::extensions::raw_credentials::TokenRole;
use praxis_policy_core::extensions::{ClientExtension, SubjectExtension, WorkloadIdentity};
use serde_json::Value;

use crate::claim_map::{ClaimMap, ClaimMapper, is_spiffe_id, trust_domain_of};
use crate::claim_map_config::{
    CompiledCandidate, CompiledClaimMap, CompiledField, CompiledRoleMap, MergeMode, OnMissing,
    SplitMode,
};

/// The registered JWT claims, which the claims bag drops unless a map asks for
/// one back. They are properties of token validation rather than subject
/// attributes.
const REGISTERED_CLAIMS: &[&str] = &["aud", "exp", "iat", "iss", "jti", "nbf", "sub"];

/// A `ClaimMapper` driven by a compiled claim map.
///
/// Holds no mutable state and parses nothing: every path was parsed when the map
/// compiled, so a request only walks claims.
#[derive(Debug, Clone)]
pub struct ConfiguredClaimMap {
    map: CompiledClaimMap,
}

impl ConfiguredClaimMap {
    /// Wrap a compiled map as a mapper.
    pub fn new(map: CompiledClaimMap) -> Self {
        Self { map }
    }

    /// The compiled map this mapper runs.
    pub fn compiled(&self) -> &CompiledClaimMap {
        &self.map
    }

    /// The policy-visible claims for a role, after the inferred exclusions and
    /// the map's overrides.
    ///
    /// Exclusion is computed from *declared* paths, not resolved ones, which is
    /// what the Rust mapper's static reserved lists do: `azp` is dropped whether
    /// or not the token carries it, and `scope` is dropped even when
    /// `permissions` won. Only a single-segment path consumes its claim, so a
    /// nested path leaves its parent whole.
    fn claims_bag(&self, section: &CompiledRoleMap, claims: &ClaimMap) -> HashMap<String, Value> {
        let mut excluded: HashSet<&str> = REGISTERED_CLAIMS.iter().copied().collect();
        for (_, field) in section.fields() {
            for candidate in field.candidates() {
                if let Some(name) = candidate.path().single_segment() {
                    excluded.insert(name);
                }
            }
        }
        let overrides = self.map.claims();
        for name in overrides.exclude() {
            excluded.insert(name);
        }
        for name in overrides.include() {
            excluded.remove(name);
        }

        claims
            .iter()
            .filter(|(name, _)| !excluded.contains(name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

// =====================================================================
// Resolution
// =====================================================================

/// What a field's candidates produced.
struct FieldOutcome {
    values: Vec<String>,
    /// Whether any candidate resolved. Distinct from `values` being empty: a
    /// claim holding `[]` resolves and contributes nothing, which is not the
    /// same as a path that led nowhere.
    resolved: bool,
    /// How many candidates were reached, so a diagnostic can name them. A count
    /// rather than rendered paths: rendering re-escapes every path, and the
    /// request path pays that only when something actually missed.
    tried: usize,
}

/// Append what one value contributes, or report that its shape cannot serve
/// this field.
fn contribute(
    value: &Value,
    candidate: &CompiledCandidate,
    split: Option<SplitMode>,
    out: &mut Vec<String>,
) -> bool {
    match value {
        // An array already says where its elements end, so `split` does not
        // apply to them. Splitting them too would change what a claim carrying
        // an element with a space in it produces, and one field-level `split`
        // covers a delimited-string candidate and an array candidate at once
        // precisely because it leaves the array alone.
        Value::Array(items) => {
            if candidate.string_only() {
                return false;
            }
            for item in items {
                if let Some(text) = item.as_str() {
                    out.push(text.to_owned());
                }
            }
            true
        },
        Value::String(text) => {
            if candidate.array_only() {
                return false;
            }
            match split {
                Some(SplitMode::Whitespace) => {
                    out.extend(text.split_whitespace().map(str::to_owned));
                },
                None => out.push(text.to_owned()),
            }
            true
        },
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => false,
    }
}

fn resolve_collection(field: &CompiledField, claims: &ClaimMap) -> FieldOutcome {
    let mut values = Vec::new();
    let mut resolved = false;
    let mut tried = 0_usize;

    for candidate in field.candidates() {
        tried += 1;
        let Some(value) = candidate.path().resolve(claims) else {
            continue;
        };
        if !contribute(value, candidate, field.split(), &mut values) {
            // A present value the candidate cannot use leaves the chain running,
            // which is what the Rust mapper's collection accessors do. Only a
            // field holding one value can declare otherwise, so there is no
            // `stop_if_present` case here.
            continue;
        }
        resolved = true;
        if field.merge() == MergeMode::FirstMatch {
            break;
        }
    }

    // A union merges candidate lists, so a value both of them carry arrives
    // twice: Keycloak naming the same role under `realm_access` and
    // `resource_access.<client>` is the ordinary case. The subject fields are
    // sets downstream and would swallow it, but the client fields are `Vec`s and
    // would carry it into audit logs and serialized output, so the same map
    // would behave differently per role. Deduped here, first-seen order kept, so
    // it behaves the same everywhere. The dedupe covers the whole result rather
    // than just the seam between candidates, so a lone candidate's own repeats
    // go too, which is the "each value once" the union is documented to give.
    // `first_match` never dedupes: it selects one candidate instead of combining
    // any, so a repeat reaching it is the claim's own content, and passing it
    // through is what the Rust standard mapper does.
    if field.merge() == MergeMode::Union {
        let mut seen: HashSet<String> = HashSet::with_capacity(values.len());
        values.retain(|value| seen.insert(value.clone()));
    }

    FieldOutcome {
        values,
        resolved,
        tried,
    }
}

/// Resolve a field holding one value: the first candidate resolving to a string
/// `accept` allows.
///
/// `accept` is how the SPIFFE prefix is enforced per candidate rather than after
/// the fact, so a non-SPIFFE `sub` is skipped and a later SPIFFE-shaped claim
/// still wins.
fn resolve_scalar(
    field: &CompiledField,
    claims: &ClaimMap,
    accept: impl Fn(&str) -> bool,
) -> (Option<String>, usize) {
    let mut tried = 0_usize;
    for candidate in field.candidates() {
        tried += 1;
        let Some(value) = candidate.path().resolve(claims) else {
            continue;
        };
        match value.as_str() {
            Some(text) if accept(text) => return (Some(text.to_owned()), tried),
            // Present but unusable. The chain continues unless this candidate
            // claims the field the moment its path resolves at all.
            _ if candidate.stop_if_present() => break,
            _ => {},
        }
    }
    (None, tried)
}

/// Render the paths a field reached, for a diagnostic. Called only for a field
/// that missed while something is listening at `debug`, since the escaping cost
/// buys nothing otherwise.
fn paths_tried(field: &CompiledField, tried: usize) -> Vec<String> {
    field
        .candidates()
        .iter()
        .take(tried)
        .map(|candidate| candidate.path().to_string())
        .collect()
}

// =====================================================================
// Diagnostics
// =====================================================================

/// A mapping call's misses, gathered so a badly configured map costs one event
/// per request rather than one per field.
struct Diagnostics {
    role: &'static str,
    /// Whether anything is listening at `debug`, checked once per mapping call.
    ///
    /// A miss is the common case rather than the rare one: a plain `{sub, email}`
    /// token under the standard preset misses `roles`, `permissions` and
    /// `teams`, so rendering every path tried would cost every request a handful
    /// of allocations the subscriber then drops. The `deny` bookkeeping below is
    /// not gated: it decides the answer, not what gets logged.
    detailed: bool,
    missed: Vec<(&'static str, Vec<String>)>,
    empty: Vec<&'static str>,
    denied: Vec<&'static str>,
}

impl Diagnostics {
    fn new(role: &'static str) -> Self {
        Self {
            role,
            detailed: tracing::enabled!(tracing::Level::DEBUG),
            missed: Vec::new(),
            empty: Vec::new(),
            denied: Vec::new(),
        }
    }

    fn record(
        &mut self,
        name: &'static str,
        field: &CompiledField,
        outcome: &FieldOutcome,
    ) -> bool {
        if outcome.resolved {
            if outcome.values.is_empty() && self.detailed {
                self.empty.push(name);
            }
            return true;
        }
        if self.detailed {
            self.missed.push((name, paths_tried(field, outcome.tried)));
        }
        if field.on_missing() == OnMissing::Deny {
            self.denied.push(name);
        }
        false
    }

    fn record_scalar_miss(&mut self, name: &'static str, field: &CompiledField, tried: usize) {
        if self.detailed {
            self.missed.push((name, paths_tried(field, tried)));
        }
        if field.on_missing() == OnMissing::Deny {
            self.denied.push(name);
        }
    }

    /// An anchor the section declares no path for, which denies every token.
    ///
    /// Recorded so the miss event names it: without this the denial says to raise
    /// the log level and the raised log says nothing, because a field nothing
    /// asked for never reaches the resolution path. The condition is static, so
    /// the loud warning belongs at construction rather than once per request.
    fn record_undeclared_anchor(&mut self, name: &'static str) {
        if self.detailed {
            self.missed.push((name, Vec::new()));
        }
    }

    /// Whether a field declared `on_missing: deny` and did not resolve.
    fn declined(&self) -> bool {
        !self.denied.is_empty()
    }

    fn emit(&self) {
        if !self.missed.is_empty() {
            let fields: Vec<&str> = self.missed.iter().map(|(name, _)| *name).collect();
            let tried: Vec<String> = self
                .missed
                .iter()
                .map(|(name, paths)| format!("{name}: {}", paths.join(", ")))
                .collect();
            tracing::debug!(
                role = self.role,
                fields = ?fields,
                paths_tried = ?tried,
                "claim map: no candidate resolved for these fields",
            );
        }
        if !self.empty.is_empty() {
            tracing::debug!(
                role = self.role,
                fields = ?self.empty,
                "claim map: these fields resolved to an empty collection",
            );
        }
        if !self.denied.is_empty() {
            tracing::warn!(
                role = self.role,
                fields = ?self.denied,
                "claim map: declining the token because a field declared `on_missing: deny` and \
                 no candidate resolved",
            );
        }
    }
}

/// Resolve a collection field, or an empty list when the section declares none.
fn collection(
    section: &CompiledRoleMap,
    name: &'static str,
    claims: &ClaimMap,
    diag: &mut Diagnostics,
) -> Vec<String> {
    let Some(field) = section.field(name) else {
        return Vec::new();
    };
    let outcome = resolve_collection(field, claims);
    diag.record(name, field, &outcome);
    outcome.values
}

/// Resolve a field holding one value, or `None` when the section declares none.
fn scalar(
    section: &CompiledRoleMap,
    name: &'static str,
    claims: &ClaimMap,
    diag: &mut Diagnostics,
    accept: impl Fn(&str) -> bool,
) -> Option<String> {
    let field = section.field(name)?;
    let (value, tried) = resolve_scalar(field, claims, accept);
    if value.is_none() {
        diag.record_scalar_miss(name, field, tried);
    }
    value
}

/// Resolve a role's anchor, reporting an undeclared one rather than silently
/// declining every token.
fn anchor(
    section: &CompiledRoleMap,
    name: &'static str,
    claims: &ClaimMap,
    diag: &mut Diagnostics,
    accept: impl Fn(&str) -> bool,
) -> Option<String> {
    if section.field(name).is_none() {
        diag.record_undeclared_anchor(name);
        return None;
    }
    scalar(section, name, claims, diag, accept)
}

fn accept_any(_: &str) -> bool {
    true
}

// =====================================================================
// The mapper
// =====================================================================

impl ClaimMapper for ConfiguredClaimMap {
    fn map_subject(&self, claims: &ClaimMap) -> Option<SubjectExtension> {
        let section = self.map.role(&TokenRole::User).ok()?;
        let mut diag = Diagnostics::new("subject");

        let id = anchor(section, "id", claims, &mut diag, accept_any);
        let roles = collection(section, "roles", claims, &mut diag);
        let permissions = collection(section, "permissions", claims, &mut diag);
        let teams = collection(section, "teams", claims, &mut diag);

        diag.emit();
        if diag.declined() {
            return None;
        }

        Some(SubjectExtension {
            id: Some(id?),
            roles: roles.into_iter().collect(),
            permissions: permissions.into_iter().collect(),
            teams: teams.into_iter().collect(),
            claims: self.claims_bag(section, claims),
            ..Default::default()
        })
    }

    fn map_client(&self, claims: &ClaimMap) -> Option<ClientExtension> {
        let section = self.map.role(&TokenRole::Client).ok()?;
        let mut diag = Diagnostics::new("client");

        let client_id = anchor(section, "client_id", claims, &mut diag, accept_any);
        let client_name = scalar(section, "client_name", claims, &mut diag, accept_any);
        let authorized_scopes = collection(section, "authorized_scopes", claims, &mut diag);
        let authorized_audiences = collection(section, "authorized_audiences", claims, &mut diag);
        let roles = collection(section, "roles", claims, &mut diag);
        let permissions = collection(section, "permissions", claims, &mut diag);
        let teams = collection(section, "teams", claims, &mut diag);

        diag.emit();
        if diag.declined() {
            return None;
        }

        Some(ClientExtension {
            client_id: client_id?,
            client_name,
            authorized_scopes,
            authorized_audiences,
            roles,
            permissions,
            teams,
            claims: self.claims_bag(section, claims),
            ..Default::default()
        })
    }

    fn map_workload(&self, claims: &ClaimMap) -> Option<WorkloadIdentity> {
        let section = self.map.role(&TokenRole::CallerWorkload).ok()?;
        let mut diag = Diagnostics::new("workload");

        // Check every candidate before it counts as resolving: a non-SPIFFE
        // `sub` must not smuggle in an arbitrary `spiffe_id` claim, and a later
        // SPIFFE-shaped candidate must still win.
        let spiffe_id = anchor(section, "spiffe_id", claims, &mut diag, is_spiffe_id);
        let client_id = scalar(section, "client_id", claims, &mut diag, accept_any);
        let selectors = collection(section, "selectors", claims, &mut diag);

        diag.emit();
        if diag.declined() {
            return None;
        }

        let spiffe_id = spiffe_id?;
        // `is_spiffe_id` already required the authority, so this cannot be
        // `None`.
        let trust_domain = trust_domain_of(&spiffe_id);

        Some(WorkloadIdentity {
            spiffe_id: Some(spiffe_id),
            trust_domain,
            attested_at: None,
            attestor: Some("jwt".to_owned()),
            selectors,
            client_id,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex, OnceLock};

    use serde_json::json;

    use super::*;
    use crate::claim_map_config::{ClaimMapConfig, ClaimsOverrides};

    fn claims(value: Value) -> ClaimMap {
        value.as_object().unwrap().clone().into_iter().collect()
    }

    fn config(map: Value) -> ClaimMapConfig {
        serde_json::from_value(map).expect("the map deserializes")
    }

    fn mapper(map: Value) -> ConfiguredClaimMap {
        let config: ClaimMapConfig = serde_json::from_value(map).expect("the map deserializes");
        ConfiguredClaimMap::new(config.compile().expect("the map compiles"))
    }

    /// A mapper with the plugin-level claims-bag overrides attached, which is how
    /// the resolver assembles one.
    fn mapper_with_claims(map: Value, claims: Value) -> ConfiguredClaimMap {
        let config: ClaimMapConfig = serde_json::from_value(map).expect("the map deserializes");
        let overrides: ClaimsOverrides =
            serde_json::from_value(claims).expect("the overrides deserialize");
        ConfiguredClaimMap::new(
            config
                .compile()
                .expect("the map compiles")
                .with_claims(overrides.compile().expect("the overrides are coherent")),
        )
    }

    fn sorted(values: &HashSet<String>) -> Vec<&str> {
        let mut items: Vec<&str> = values.iter().map(String::as_str).collect();
        items.sort_unstable();
        items
    }

    // ---- tracing capture --------------------------------------------------
    //
    // A minimal subscriber rather than a dev-dependency: the diagnostics are
    // asserted on, so they need capturing, and `tracing` alone is enough to do
    // it.
    //
    // One global subscriber with a thread-local sink, not `with_default` per
    // test. Callsite interest is cached process-wide, so a thread-local
    // subscriber does not own whether an event fires: installing one rebuilds
    // the cache, and a test running in parallel can have its callsite recached
    // as disabled between the `debug!` and the assertion. A subscriber that is
    // installed once and always interested takes the cache out of the race, and
    // the sink keeps each test reading only its own events.

    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<String>>>);

    impl Events {
        fn recorded(&self) -> Vec<String> {
            self.0
                .lock()
                .expect("the event log is not poisoned")
                .clone()
        }

        fn matching(&self, needle: &str) -> Vec<String> {
            self.recorded()
                .into_iter()
                .filter(|event| event.contains(needle))
                .collect()
        }
    }

    thread_local! {
        static SINK: RefCell<Option<Events>> = const { RefCell::new(None) };
    }

    struct Capture;

    /// Clears the sink even if the body panics, so a failing test cannot leak
    /// its events into whichever test the runner puts on this thread next.
    struct Sink;

    impl Drop for Sink {
        fn drop(&mut self) {
            SINK.with_borrow_mut(|sink| *sink = None);
        }
    }

    struct Render(String);

    impl tracing::field::Visit for Render {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }

    impl tracing::Subscriber for Capture {
        /// Always, so the cached interest never depends on which thread first
        /// reached the callsite.
        fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            SINK.with_borrow(|sink| {
                let Some(events) = sink.as_ref() else {
                    return;
                };
                let mut render = Render(format!("[{}]", event.metadata().level()));
                event.record(&mut render);
                events
                    .0
                    .lock()
                    .expect("the event log is not poisoned")
                    .push(render.0);
            });
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Run `body` with events captured.
    fn capturing<T>(body: impl FnOnce() -> T) -> (T, Events) {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            tracing::subscriber::set_global_default(Capture)
                .expect("no other subscriber is installed in this test binary");
        });

        let events = Events::default();
        SINK.with_borrow_mut(|sink| *sink = Some(events.clone()));
        let _guard = Sink;
        (body(), events)
    }

    // ---- candidate resolution and merge -----------------------------------

    /// Nested realm roles and per-client roles, the shape that motivates the
    /// whole map. `union` takes both; `first_match` takes only the first.
    #[test]
    fn union_takes_every_resolving_candidate_and_first_match_takes_one() {
        let token = claims(json!({
            "sub": "alice",
            "realm_access": {"roles": ["realm-admin"]},
            "resource_access": {"my-api": {"roles": ["viewer", "editor"]}},
        }));
        let paths = ["realm_access.roles", "resource_access.my-api.roles"];

        let union = mapper(json!({
            "subject": {"id": "sub", "roles": {"paths": paths, "merge": "union"}}
        }))
        .map_subject(&token)
        .unwrap();
        assert_eq!(
            sorted(&union.roles),
            vec!["editor", "realm-admin", "viewer"]
        );

        let first = mapper(json!({
            "subject": {"id": "sub", "roles": {"paths": paths}}
        }))
        .map_subject(&token)
        .unwrap();
        assert_eq!(sorted(&first.roles), vec!["realm-admin"]);
    }

    /// Order is candidate-declaration order, then in-array order, and a value two
    /// candidates carry appears once, at its first position. A `Vec` destination
    /// is where this is visible at all: a set would have hidden it, which is
    /// exactly why the engine cannot leave it to the destination.
    #[test]
    fn union_preserves_declaration_order_and_deduplicates() {
        let token = claims(json!({
            "client_id": "svc",
            "primary": ["a", "b"],
            "secondary": ["b", "c"],
        }));
        let client = mapper(json!({
            "client": {
                "client_id": "client_id",
                "roles": {"paths": ["primary", "secondary"], "merge": "union"},
            }
        }))
        .map_client(&token)
        .unwrap();
        assert_eq!(client.roles, vec!["a", "b", "c"]);
    }

    /// The union case a Keycloak realm actually hits: a role granted both at the
    /// realm and on the client reaches `client.roles` once.
    #[test]
    fn a_role_in_both_unioned_candidates_reaches_a_client_once() {
        let token = claims(json!({
            "client_id": "svc",
            "realm_access": {"roles": ["admin", "viewer"]},
            "resource_access": {"api": {"roles": ["admin", "auditor"]}},
        }));
        let client = mapper(json!({
            "client": {
                "client_id": "client_id",
                "roles": {
                    "paths": ["realm_access.roles", "resource_access.api.roles"],
                    "merge": "union",
                },
            }
        }))
        .map_client(&token)
        .unwrap();
        assert_eq!(client.roles, vec!["admin", "viewer", "auditor"]);
    }

    /// Under `first_match` a repeated value is the claim's own content, not an
    /// artifact of merging, so it is carried through as authored.
    #[test]
    fn a_set_destination_deduplicates_where_a_vec_destination_does_not() {
        let token = claims(json!({
            "sub": "alice",
            "client_id": "svc",
            "primary": ["a", "a", "b"],
        }));
        let subject = mapper(json!({"subject": {"id": "sub", "roles": "primary"}}))
            .map_subject(&token)
            .unwrap();
        assert_eq!(sorted(&subject.roles), vec!["a", "b"]);

        let client = mapper(json!({"client": {"client_id": "client_id", "roles": "primary"}}))
            .map_client(&token)
            .unwrap();
        assert_eq!(client.roles, vec!["a", "a", "b"]);
    }

    // ---- shape handling ---------------------------------------------------

    #[test]
    fn split_breaks_a_delimited_string_and_its_absence_keeps_it_whole() {
        let token = claims(json!({"sub": "alice", "scope": "read write delete"}));

        let split = mapper(json!({
            "subject": {
                "id": "sub",
                "permissions": {"paths": ["scope"], "split": "whitespace"},
            }
        }))
        .map_subject(&token)
        .unwrap();
        assert_eq!(sorted(&split.permissions), vec!["delete", "read", "write"]);

        let whole = mapper(json!({"subject": {"id": "sub", "permissions": "scope"}}))
            .map_subject(&token)
            .unwrap();
        assert_eq!(sorted(&whole.permissions), vec!["read write delete"]);
    }

    /// One field-level `split` serves an array candidate and a delimited-string
    /// candidate at once: splitting a whitespace-free array element is a no-op.
    #[test]
    fn one_split_declaration_serves_both_an_array_and_a_delimited_string() {
        let map = json!({
            "subject": {
                "id": "sub",
                "permissions": {
                    "paths": [{"path": "permissions", "array_only": true}, "scope"],
                    "split": "whitespace",
                },
            }
        });
        let from_array = mapper(map.clone())
            .map_subject(&claims(json!({
                "sub": "alice", "permissions": ["read:all", "write all reports"],
            })))
            .unwrap();
        assert_eq!(
            sorted(&from_array.permissions),
            vec!["read:all", "write all reports"],
            "an array says where its elements end, so `split` leaves them whole"
        );

        let from_string = mapper(map)
            .map_subject(&claims(json!({"sub": "alice", "scope": "read write"})))
            .unwrap();
        assert_eq!(sorted(&from_string.permissions), vec!["read", "write"]);
    }

    /// The shape matrix, one row per resolved JSON kind, on a default candidate
    /// and on an `array_only` one.
    #[test]
    fn the_shape_matrix_holds_for_every_resolved_kind() {
        for (value, default_expected, array_only_expected) in [
            (json!(["a", "b"]), vec!["a", "b"], vec!["a", "b"]),
            (json!("a b"), vec!["a b"], vec!["fallback"]),
            (json!("a"), vec!["a"], vec!["fallback"]),
            (json!(42), vec!["fallback"], vec!["fallback"]),
            (json!(true), vec!["fallback"], vec!["fallback"]),
            (json!({"nested": true}), vec!["fallback"], vec!["fallback"]),
            (json!(null), vec!["fallback"], vec!["fallback"]),
            (json!(["a", 42, {"n": 1}]), vec!["a"], vec!["a"]),
        ] {
            let token = claims(json!({
                "sub": "alice", "primary": value, "backup": ["fallback"],
            }));

            let default = mapper(json!({
                "subject": {"id": "sub", "roles": ["primary", "backup"]}
            }))
            .map_subject(&token)
            .unwrap();
            assert_eq!(
                sorted(&default.roles),
                default_expected,
                "default candidate over {:?}",
                token.get("primary")
            );

            let array_only = mapper(json!({
                "subject": {
                    "id": "sub",
                    "roles": [{"path": "primary", "array_only": true}, "backup"],
                }
            }))
            .map_subject(&token)
            .unwrap();
            assert_eq!(
                sorted(&array_only.roles),
                array_only_expected,
                "array_only candidate over {:?}",
                token.get("primary")
            );
        }
    }

    /// An absent claim, a scalar crossed mid-path, and a numeric or object value
    /// are each ignored, so the map produces an identity rather than failing.
    #[test]
    fn an_unusable_shape_is_ignored_rather_than_rejected() {
        let token = claims(json!({
            "client_id": "svc",
            "aud": 42,
            "roles": {"not": "a list"},
            "teams": ["ok", 7, null],
        }));
        let client = mapper(json!({
            "client": {
                "client_id": "client_id",
                "authorized_audiences": "aud",
                "roles": "roles",
                "teams": "teams",
            }
        }))
        .map_client(&token)
        .unwrap();
        assert!(client.authorized_audiences.is_empty());
        assert!(client.roles.is_empty());
        assert_eq!(client.teams, vec!["ok"]);
    }

    /// A bare `aud` accepts both shapes on one path, which is what a provider
    /// that flips between them by audience count needs.
    #[test]
    fn one_path_accepts_aud_as_a_string_and_as_an_array() {
        let map = json!({
            "client": {"client_id": "client_id", "authorized_audiences": "aud"}
        });
        let one = mapper(map.clone())
            .map_client(&claims(json!({"client_id": "svc", "aud": "gateway"})))
            .unwrap();
        assert_eq!(one.authorized_audiences, vec!["gateway"]);

        let many = mapper(map)
            .map_client(&claims(
                json!({"client_id": "svc", "aud": ["gateway", "api"]}),
            ))
            .unwrap();
        assert_eq!(many.authorized_audiences, vec!["gateway", "api"]);
    }

    // ---- claims bag -------------------------------------------------------

    /// A single-segment path consumes its claim; a nested path leaves the parent
    /// whole, which is what keeps a policy reading the nested object working.
    #[test]
    fn a_nested_path_leaves_its_parent_in_the_bag_and_a_single_segment_does_not() {
        let token = claims(json!({
            "sub": "alice",
            "realm_access": {"roles": ["admin"]},
            "groups": ["eng"],
        }));
        let subject = mapper(json!({
            "subject": {"id": "sub", "roles": "realm_access.roles", "teams": "groups"}
        }))
        .map_subject(&token)
        .unwrap();

        assert_eq!(
            subject.claims.get("realm_access"),
            Some(&json!({"roles": ["admin"]})),
            "a traversed parent stays policy-visible"
        );
        assert!(
            !subject.claims.contains_key("groups"),
            "a single-segment path consumed `groups`"
        );
    }

    /// The inference reproduces the Rust mapper's static reserved lists exactly,
    /// which is what makes an unchanged config produce an unchanged bag.
    #[test]
    fn the_inferred_exclusions_reproduce_the_rust_mappers_reserved_lists() {
        let every_claim = json!({
            "sub": "alice", "roles": [], "permissions": [], "scope": "", "teams": [],
            "groups": [], "iss": "i", "aud": "a", "exp": 1, "nbf": 1, "iat": 1, "jti": "j",
            "client_id": "c", "azp": "z", "client_name": "n", "authorized_scopes": [],
            "kept": "yes",
        });

        let subject = mapper(json!({
            "subject": {
                "id": "sub",
                "roles": "roles",
                "permissions": ["permissions", "scope"],
                "teams": ["teams", "groups"],
            }
        }))
        .map_subject(&claims(every_claim.clone()))
        .unwrap();
        let mut visible: Vec<&str> = subject.claims.keys().map(String::as_str).collect();
        visible.sort_unstable();
        assert_eq!(
            visible,
            vec![
                "authorized_scopes",
                "azp",
                "client_id",
                "client_name",
                "kept"
            ],
            "the subject bag drops exactly sub/roles/permissions/scope/teams/groups plus the \
             registered claims"
        );

        let client = mapper(json!({
            "client": {
                "client_id": ["client_id", "azp"],
                "client_name": "client_name",
                "authorized_scopes": ["authorized_scopes", "scope"],
                "authorized_audiences": "aud",
                "roles": "roles",
            }
        }))
        .map_client(&claims(every_claim))
        .unwrap();
        let mut visible: Vec<&str> = client.claims.keys().map(String::as_str).collect();
        visible.sort_unstable();
        assert_eq!(
            visible,
            vec!["groups", "kept", "permissions", "teams"],
            "the client bag drops exactly the claims its declarations name plus the registered \
             claims"
        );
    }

    #[test]
    fn exclude_drops_a_visible_claim_and_include_restores_a_dropped_one() {
        let token = claims(json!({
            "sub": "alice", "groups": ["eng"], "internal_debug": "noisy", "tenant": "acme",
        }));
        let subject = mapper_with_claims(
            json!({"subject": {"id": "sub", "teams": "groups"}}),
            json!({"exclude": ["internal_debug"], "include": ["groups"]}),
        )
        .map_subject(&token)
        .unwrap();

        assert!(!subject.claims.contains_key("internal_debug"));
        assert_eq!(
            subject.claims.get("groups"),
            Some(&json!(["eng"])),
            "include restores a claim a path consumed"
        );
        assert_eq!(subject.claims.get("tenant"), Some(&json!("acme")));
    }

    /// A registered claim is reachable through `include`, with no allowlist.
    /// This is what makes gating on which `IdP` minted the token expressible: the
    /// subject claims bag is the only route from a claim to a policy.
    #[test]
    fn include_restores_any_registered_claim() {
        let token = claims(json!({
            "sub": "alice", "iss": "https://internal.idp", "jti": "abc", "exp": 2_000_000_000_i64,
        }));
        let subject = mapper_with_claims(
            json!({"subject": {"id": "sub"}}),
            json!({"include": ["iss", "jti", "exp"]}),
        )
        .map_subject(&token)
        .unwrap();
        assert_eq!(
            subject.claims.get("iss"),
            Some(&json!("https://internal.idp"))
        );
        assert_eq!(subject.claims.get("jti"), Some(&json!("abc")));
        assert_eq!(subject.claims.get("exp"), Some(&json!(2_000_000_000_i64)));
    }

    /// The override names reach the bag unescaped, so a claim whose name holds a
    /// dot is dropped by the escaped spelling and not by the literal one.
    #[test]
    fn an_escaped_override_name_matches_the_claim_it_names() {
        let token = claims(json!({
            "sub": "alice",
            "https://my-app.example.com/roles": ["admin"],
            "tenant": "acme",
        }));
        let subject = mapper_with_claims(
            json!({"subject": {"id": "sub"}}),
            json!({"exclude": ["https://my-app\\.example\\.com/roles"]}),
        )
        .map_subject(&token)
        .unwrap();

        assert!(
            !subject
                .claims
                .contains_key("https://my-app.example.com/roles")
        );
        assert_eq!(subject.claims.get("tenant"), Some(&json!("acme")));
    }

    // ---- diagnostics ------------------------------------------------------

    /// A mistyped path leaves the field empty and says so, naming the field and
    /// every path it tried. Without the paths an operator cannot tell a typo
    /// from a claim the `IdP` never minted.
    #[test]
    fn a_field_that_resolved_nothing_names_itself_and_every_path_tried() {
        let (subject, events) = capturing(|| {
            mapper(json!({
                "subject": {"id": "sub", "roles": ["realm_access.rolez", "rolez"]}
            }))
            .map_subject(&claims(json!({
                "sub": "alice", "realm_access": {"roles": ["admin"]},
            })))
        });

        assert!(
            subject.unwrap().roles.is_empty(),
            "a mistyped path leaves the field empty rather than denying"
        );
        let misses = events.matching("no candidate resolved");
        assert_eq!(misses.len(), 1, "one aggregated event per call: {misses:?}");
        let event = misses.first().expect("one miss event");
        assert!(event.contains("roles"), "{event}");
        assert!(event.contains("realm_access.rolez"), "{event}");
        assert!(event.contains("rolez"), "{event}");
    }

    /// A field that resolved to nothing and a field that resolved to an empty
    /// collection are different states, and an operator reading one flag's worth
    /// of output has to be able to tell them apart.
    #[test]
    fn an_empty_collection_is_a_different_event_from_a_miss() {
        let (_, events) = capturing(|| {
            mapper(json!({
                "subject": {"id": "sub", "roles": "roles", "teams": "absent"}
            }))
            .map_subject(&claims(json!({"sub": "alice", "roles": []})))
        });

        let empty = events.matching("empty collection");
        assert_eq!(empty.len(), 1, "{:?}", events.recorded());
        let event = empty.first().expect("one empty event");
        assert!(event.contains("roles"), "{event}");
        assert!(
            !event.contains("paths_tried"),
            "the empty event names the field only: {event}"
        );

        let misses = events.matching("no candidate resolved");
        let event = misses.first().expect("the absent field is a miss");
        assert!(event.contains("teams"), "{event}");
        assert!(
            !event.contains("roles"),
            "a field that resolved is not a miss: {event}"
        );
    }

    /// Every missed field lands in one event, so a wholly mistyped map costs one
    /// event per request rather than one per field.
    #[test]
    fn every_missed_field_shares_one_event() {
        let (_, events) = capturing(|| {
            mapper(json!({
                "subject": {"id": "sub", "roles": "nope", "teams": "also-nope", "permissions": "neither"}
            }))
            .map_subject(&claims(json!({"sub": "alice"})))
        });
        let misses = events.matching("no candidate resolved");
        assert_eq!(misses.len(), 1, "{misses:?}");
        let event = misses.first().expect("one miss event");
        for field in ["roles", "teams", "permissions"] {
            assert!(event.contains(field), "{field} missing from {event}");
        }
    }

    #[test]
    fn a_map_that_resolves_everything_emits_neither_event() {
        let (_, events) = capturing(|| {
            mapper(json!({"subject": {"id": "sub", "roles": "roles"}}))
                .map_subject(&claims(json!({"sub": "alice", "roles": ["admin"]})))
        });
        assert!(
            events.matching("claim map").is_empty(),
            "{:?}",
            events.recorded()
        );
    }

    // ---- on_missing -------------------------------------------------------

    /// The same mistyped path is permissive by default and fatal on request.
    #[test]
    fn on_missing_deny_declines_where_the_default_leaves_the_field_empty() {
        let token = claims(json!({"sub": "alice"}));

        let permissive = mapper(json!({"subject": {"id": "sub", "roles": "rolez"}}))
            .map_subject(&token)
            .expect("the default leaves the field empty");
        assert!(permissive.roles.is_empty());

        let (strict, events) = capturing(|| {
            mapper(json!({
                "subject": {"id": "sub", "roles": {"paths": ["rolez"], "on_missing": "deny"}}
            }))
            .map_subject(&token)
        });
        assert!(strict.is_none(), "`on_missing: deny` declines the mapping");
        let warning = events.matching("on_missing");
        let event = warning.first().expect("the field is named in a warning");
        assert!(event.contains("WARN"), "{event}");
        assert!(event.contains("roles"), "{event}");
    }

    /// `on_missing: deny` on a field holding one value takes the scalar miss path,
    /// which is a different branch from the collection one and reports through the
    /// same warning.
    #[test]
    fn on_missing_deny_on_a_field_holding_one_value_declines_and_names_it() {
        let (declined, events) = capturing(|| {
            mapper(json!({
                "client": {
                    "client_id": ["client_id", "azp"],
                    "client_name": {"paths": ["client_name", "app_name"], "on_missing": "deny"},
                }
            }))
            .map_client(&claims(json!({"client_id": "svc"})))
        });
        assert!(
            declined.is_none(),
            "a strict field holding one value declines when nothing resolves"
        );

        let warning = events.matching("on_missing");
        let event = warning.first().expect("the field is named in a warning");
        assert!(event.contains("client_name"), "{event}");

        let misses = events.matching("no candidate resolved");
        let miss = misses.first().expect("the miss names every path tried");
        assert!(miss.contains("client_name"), "{miss}");
        assert!(miss.contains("app_name"), "both paths are named: {miss}");
    }

    /// An empty collection satisfies `on_missing: deny`: the claim was there.
    #[test]
    fn on_missing_deny_accepts_a_claim_that_resolved_to_an_empty_collection() {
        let subject = mapper(json!({
            "subject": {"id": "sub", "roles": {"paths": ["roles"], "on_missing": "deny"}}
        }))
        .map_subject(&claims(json!({"sub": "alice", "roles": []})))
        .expect("a present-but-empty claim resolved");
        assert!(subject.roles.is_empty());
    }

    // ---- anchors ----------------------------------------------------------

    #[test]
    fn a_missing_anchor_declines_for_each_role() {
        let map = mapper(json!({
            "subject": {"id": "sub"},
            "client": {"client_id": ["client_id", "azp"]},
            "workload": {"spiffe_id": "sub"},
        }));
        let empty = claims(json!({"unrelated": "value"}));
        assert!(map.map_subject(&empty).is_none());
        assert!(map.map_client(&empty).is_none());
        assert!(map.map_workload(&empty).is_none());
    }

    /// A section that declares the role but no anchor path compiles, and then
    /// declines every token. The role check is about the section existing; the
    /// anchor is a runtime denial.
    #[test]
    fn a_section_declaring_no_anchor_declines_at_runtime() {
        let map = mapper(json!({"subject": {"roles": "roles"}}));
        assert!(
            map.map_subject(&claims(json!({"sub": "alice", "roles": ["admin"]})))
                .is_none()
        );
    }

    #[test]
    fn a_role_the_map_does_not_declare_declines() {
        let map = mapper(json!({"subject": {"id": "sub"}}));
        let token = claims(json!({"sub": "alice", "client_id": "svc"}));
        assert!(map.map_client(&token).is_none());
        assert!(map.map_workload(&token).is_none());
    }

    // ---- workload invariants ----------------------------------------------

    /// The prefix check applies per candidate, so a non-SPIFFE `sub` is skipped
    /// rather than accepted, and a valid SPIFFE candidate behind it still wins.
    #[test]
    fn the_spiffe_prefix_is_checked_on_every_candidate() {
        let map = mapper(json!({"workload": {"spiffe_id": ["sub", "spiffe_id"]}}));

        let bogus = claims(json!({"sub": "alice@corp.example", "spiffe_id": "not-a-spiffe-id"}));
        assert!(
            map.map_workload(&bogus).is_none(),
            "a non-SPIFFE sub must not be rescued by a bogus spiffe_id claim"
        );

        let rescued = claims(json!({
            "sub": "alice@corp.example",
            "spiffe_id": "spiffe://corp.example/ns/default/sa/agent",
        }));
        let workload = map
            .map_workload(&rescued)
            .expect("a valid SPIFFE candidate behind a non-SPIFFE one still resolves");
        assert_eq!(
            workload.spiffe_id.as_deref(),
            Some("spiffe://corp.example/ns/default/sa/agent")
        );
    }

    /// The scheme alone is not a SPIFFE ID: the authority carries the trust
    /// domain the standard makes mandatory. An authority-less candidate is
    /// unusable like any other, so it is skipped and a valid one behind it wins.
    #[test]
    fn a_spiffe_id_with_no_authority_declines() {
        let map = mapper(json!({"workload": {"spiffe_id": ["sub", "spiffe_id"]}}));

        for id in ["spiffe:///ns/default/sa/agent", "spiffe://", "spiffe:///"] {
            assert!(
                map.map_workload(&claims(json!({"sub": id}))).is_none(),
                "`{id}` names no trust domain, so it is not an identity"
            );
        }

        let workload = map
            .map_workload(&claims(json!({
                "sub": "spiffe:///ns/default/sa/agent",
                "spiffe_id": "spiffe://corp.example/ns/default/sa/agent",
            })))
            .expect("a valid SPIFFE candidate behind an authority-less one resolves");
        assert_eq!(workload.trust_domain.as_deref(), Some("corp.example"));
    }

    /// There is no configuration that turns the prefix check off: it is not a
    /// field, an option, or a candidate key, so every one of these is rejected
    /// or has no bearing on it.
    #[test]
    fn no_config_surface_can_disable_the_spiffe_prefix_check() {
        for attempt in [
            json!({"workload": {"spiffe_id": "sub", "spiffe_prefix": "none"}}),
            json!({"workload": {"require_spiffe": false, "spiffe_id": "sub"}}),
        ] {
            let config: ClaimMapConfig =
                serde_json::from_value(attempt).expect("the shape deserializes");
            assert!(
                config.compile().is_err(),
                "an invented field must be rejected rather than quietly ignored"
            );
        }

        let permissive = mapper(json!({
            "workload": {"spiffe_id": {"paths": ["sub"], "on_missing": "ignore"}}
        }));
        assert!(
            permissive
                .map_workload(&claims(json!({"sub": "alice@corp.example"})))
                .is_none(),
            "`on_missing: ignore` does not make a non-SPIFFE subject acceptable"
        );
    }

    /// The trust domain is the SPIFFE URI's authority, always. It is not a
    /// mappable field, so no claim can decouple the trust boundary a policy gates
    /// on from the identity it belongs to.
    #[test]
    fn the_trust_domain_is_always_the_spiffe_authority() {
        let workload = mapper(json!({"workload": {"spiffe_id": "sub"}}))
            .map_workload(&claims(json!({
                "sub": "spiffe://corp.example/ns/a/sa/b",
                "trust_domain": "attacker.example",
            })))
            .expect("the token resolves");
        assert_eq!(
            workload.trust_domain.as_deref(),
            Some("corp.example"),
            "a trust_domain claim must not displace the SPIFFE authority"
        );

        let err = config(json!({"workload": {"spiffe_id": "sub", "trust_domain": "td"}}))
            .compile()
            .expect_err("trust_domain is not a mappable field");
        assert!(err.contains("trust_domain"), "{err}");
        assert!(err.contains("workload"), "{err}");
    }

    /// The mirror of `array_only`: what a claim read as a delimited string needs,
    /// so an array-valued `scope` contributes nothing rather than contributing
    /// each element as a permission.
    #[test]
    fn string_only_rejects_an_array_and_lets_the_chain_continue() {
        let map = json!({
            "subject": {
                "id": "sub",
                "permissions": {
                    "paths": [{"path": "scope", "string_only": true}, "backup"],
                    "split": "whitespace",
                },
            }
        });

        let from_string = mapper(map.clone())
            .map_subject(&claims(json!({"sub": "alice", "scope": "read write"})))
            .unwrap();
        assert_eq!(sorted(&from_string.permissions), vec!["read", "write"]);

        let array_falls_through = mapper(map)
            .map_subject(&claims(json!({
                "sub": "alice", "scope": ["admin", "root"], "backup": ["safe"],
            })))
            .unwrap();
        assert_eq!(
            sorted(&array_falls_through.permissions),
            vec!["safe"],
            "an array-valued scope must not grant its elements as permissions"
        );
    }

    /// A chain that picks the first claim that *exists* and then requires a shape
    /// of it, rather than skipping to the next candidate. Without this a
    /// present-but-unusable anchor falls through and accepts an identity the
    /// stricter reading refuses.
    #[test]
    fn stop_if_present_ends_the_chain_on_a_present_but_unusable_value() {
        let map = json!({
            "client": {"client_id": [{"path": "client_id", "stop_if_present": true}, "azp"]}
        });

        for unusable in [json!(null), json!(42), json!(["svc"]), json!({})] {
            assert!(
                mapper(map.clone())
                    .map_client(&claims(
                        json!({"client_id": unusable, "azp": "svc-billing"})
                    ))
                    .is_none(),
                "a present but unusable client_id must not fall through to azp"
            );
        }

        let absent = mapper(map.clone())
            .map_client(&claims(json!({"azp": "svc-billing"})))
            .expect("an absent candidate still falls through");
        assert_eq!(absent.client_id, "svc-billing");

        let usable = mapper(map)
            .map_client(&claims(json!({"client_id": "explicit", "azp": "ignored"})))
            .expect("a usable value wins");
        assert_eq!(usable.client_id, "explicit");
    }

    /// The chain flag decides which whole claim wins, which only a field holding
    /// one value has. On a collection it would truncate a union and drop the
    /// candidates behind it, so it is a construction error there.
    #[test]
    fn stop_if_present_is_rejected_on_a_field_holding_a_collection() {
        let config: ClaimMapConfig = serde_json::from_value(json!({
            "subject": {
                "id": "sub",
                "roles": {
                    "paths": ["a", {"path": "b", "stop_if_present": true}, "c"],
                    "merge": "union",
                },
            }
        }))
        .expect("the shape deserializes");
        let err = config
            .compile()
            .expect_err("a collection field cannot stop on presence");
        assert!(err.contains("subject.roles"), "{err}");
        assert!(err.contains("stop_if_present"), "{err}");
    }

    /// A section that declares no path for its anchor denies every token. The
    /// denial tells the operator to raise the log level, so the raised log has to
    /// say something.
    #[test]
    fn an_undeclared_anchor_names_itself_in_a_warning() {
        for (role, section, anchor) in [
            ("subject", json!({"subject": {"roles": "roles"}}), "id"),
            ("client", json!({"client": {"roles": "roles"}}), "client_id"),
            (
                "workload",
                json!({"workload": {"selectors": "sel"}}),
                "spiffe_id",
            ),
        ] {
            let (identity, events) = capturing(|| {
                let map = mapper(section.clone());
                let token = claims(json!({"sub": "alice", "roles": ["admin"], "sel": ["a"]}));
                match role {
                    "subject" => map.map_subject(&token).is_some(),
                    "client" => map.map_client(&token).is_some(),
                    _ => map.map_workload(&token).is_some(),
                }
            });
            assert!(!identity, "{role}: an undeclared anchor declines");
            // The loud warning is emitted once at construction, since the
            // condition is static. Per request the anchor is named in the miss
            // event, which is what the denial reason points an operator at.
            let misses = events.matching("no candidate resolved");
            let event = misses
                .first()
                .unwrap_or_else(|| panic!("{role}: the undeclared anchor must be named"));
            assert!(event.contains(anchor), "{role}: {event}");
        }
    }

    #[test]
    fn a_workload_carries_its_selectors_and_client_id_when_mapped() {
        let workload = mapper(json!({
            "workload": {
                "spiffe_id": "sub",
                "selectors": "selectors",
                "client_id": "client_id",
            }
        }))
        .map_workload(&claims(json!({
            "sub": "spiffe://corp.example/w",
            "selectors": ["k8s:ns:prod", "unix:uid:1000"],
            "client_id": "svc",
        })))
        .unwrap();
        assert_eq!(workload.selectors, vec!["k8s:ns:prod", "unix:uid:1000"]);
        assert_eq!(workload.client_id.as_deref(), Some("svc"));
        assert_eq!(workload.attestor.as_deref(), Some("jwt"));
        assert!(workload.attested_at.is_none());
    }

    // ---- escaped and prefixed claim names end to end ----------------------

    /// An escaped URL-named claim and a colon-prefixed one each populate their
    /// field through the mapper, which is the pair a policy language cannot
    /// address directly.
    #[test]
    fn escaped_and_colon_prefixed_claim_names_populate_their_fields() {
        let subject = mapper(json!({
            "subject": {
                "id": "sub",
                "roles": "https://my-app\\.example\\.com/roles",
                "teams": "cognito:groups",
            }
        }))
        .map_subject(&claims(json!({
            "sub": "alice",
            "https://my-app.example.com/roles": ["editor"],
            "cognito:groups": ["admins"],
        })))
        .unwrap();
        assert_eq!(sorted(&subject.roles), vec!["editor"]);
        assert_eq!(sorted(&subject.teams), vec!["admins"]);
    }
}
