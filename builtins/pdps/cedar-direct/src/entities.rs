// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Build a `cedar_policy::Entities` set from:
//
//   - The `AttributeBag` — APL's view of `SecurityExtension` etc.
//     populated upstream by praxis-policy-apl-cmf. Source of the **principal** entity.
//   - `PdpCall.args.resource` — the resource description the policy
//     author wrote in the `cedar:(...)` step. Source of the **resource**
//     entity.
//
// v0 builds a minimum-viable entity set: just principal + resource,
// no hierarchy (no `User in Team`, no `Document in Folder`). Operators
// who need that plug an `EntityProvider` trait we'll add later — when
// there's a real use case driving the design.
//
// # Why JSON-shaped construction
//
// Cedar's `Entity::from_json_value(json, schema)` accepts a record
// with `uid`, `attrs`, `parents` keys. We build that record from the
// bag / args and let Cedar's parser handle the attribute-value
// translation (string → String, JSON array of strings → Set<String>,
// nested object → Record, etc.). Avoids fighting with
// `RestrictedExpression` directly.

use std::collections::HashSet;

use cedar_policy::{Entities, Entity, Schema};
use praxis_policy_apl_core::attributes::{AttributeBag, AttributeValue};
use praxis_policy_apl_core::step::PdpError;
use serde_json::{Map, Value, json};

use crate::cedar_attrs::{
    ATTR_CLAIMS, ATTR_ID, ATTR_PERMISSIONS, ATTR_ROLES, ATTR_TEAMS, ATTR_TYPE, KEY_ATTRS,
    KEY_PARENTS, KEY_UID,
};

/// Build the entity set for one Cedar request. Returns owned
/// `Entities` (Cedar takes them by reference at authorization time).
/// # Errors
///
/// Returns `PdpError::Dispatch` when the principal or resource cannot be built,
/// and `PdpError::Schema` when an entity does not satisfy the configured schema.
pub fn build(
    bag: &AttributeBag,
    resource_args: &serde_yaml::Value,
    schema: Option<&Schema>,
    entity_namespace: Option<&str>,
) -> Result<Entities, PdpError> {
    let principal = build_principal(bag, schema, entity_namespace)?;
    let resource = build_resource(resource_args, schema)?;
    Entities::from_entities([principal, resource], schema)
        .map_err(|e| PdpError::Dispatch(format!("failed to assemble Cedar entity set: {e}")))
}

/// Build the principal `Entity` from the bag. Reads:
///
///   - `subject.id`        → entity id (required)
///   - `subject.type`      → entity type (`User`, `Agent`, `Service`, or
///     `System`), defaulting to `User` when absent
///   - `role.<name>=true`  → `attrs.roles : Set<String>`
///   - `perm.<name>=true`  → `attrs.permissions : Set<String>`
///   - `claim.<name>=v`    → `attrs.claims.<name>` (record)
///   - `subject.teams`     → `attrs.teams : Set<String>`
///
/// Operators with custom claim attributes write their Cedar policies
/// against `principal.claims.foo` — those land via the `claim.foo` bag
/// key, populated upstream by praxis-policy-apl-cmf from `SubjectExtension.claims`.
/// A nested claim arrives already flattened by that bridge, so
/// `realm_access: {roles: [...]}` becomes the bag key
/// `claim.realm_access.roles` and therefore the record key
/// `realm_access.roles`, which Cedar reaches with bracket syntax:
/// `principal.claims["realm_access.roles"]`.
///
/// # Errors
///
/// Returns `PdpError::Dispatch` when `subject.id` is absent, since Cedar cannot
/// authorize without a principal.
pub fn build_principal(
    bag: &AttributeBag,
    schema: Option<&Schema>,
    entity_namespace: Option<&str>,
) -> Result<Entity, PdpError> {
    let id = bag
        .get_string("subject.id")
        .ok_or_else(|| {
            PdpError::Dispatch(
                "Cedar request needs a principal but bag has no `subject.id` — \
                 install an identity-hook plugin upstream of APL policy"
                    .to_owned(),
            )
        })?
        .to_owned();

    let kind = bag.get_string("subject.type").unwrap_or("User");
    let entity_type = qualify_type(kind, entity_namespace);

    // Collect attributes from the bag. We pick the well-known shapes;
    // arbitrary `subject.*` keys beyond these are intentionally NOT
    // surfaced — operators with custom shapes use `claim.*` or extend
    // the bridge.
    //
    // Empty defaults matter: Cedar's strict-evaluation mode raises a
    // runtime error when a policy probes a missing attribute
    // (`principal.roles.contains(...)` against a principal without
    // `roles`). The resolver's fail-closed logic would then deny —
    // surprising for policy authors who expect missing-attribute →
    // empty-set semantics. Populating empty sets / records by default
    // gives clean "attribute exists, just empty" behavior.
    let mut attrs = Map::new();
    attrs.insert(ATTR_ID.to_owned(), json!(id));
    attrs.insert(ATTR_TYPE.to_owned(), json!(kind));

    // TODO(vocab consolidation, Phase C): `"role."`, `"perm."`, and
    // `"subject.teams"` are praxis-policy-apl-cmf bag-key conventions. The cedar
    // crate would need a dependency on praxis-policy-apl-cmf (or the BAG_* constants
    // need to move into praxis-policy-apl-core / a shared crate) before we can
    // reference them by symbol here. Left literal for now — the gap is
    // tracked in the `project_vocab_consolidation` memory.
    let roles = collect_prefixed_bools(bag, "role.");
    attrs.insert(ATTR_ROLES.to_owned(), json!(roles));

    let permissions = collect_prefixed_bools(bag, "perm.");
    attrs.insert(ATTR_PERMISSIONS.to_owned(), json!(permissions));

    let teams: Vec<String> = bag
        .get_string_set("subject.teams")
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    attrs.insert(ATTR_TEAMS.to_owned(), json!(teams));

    attrs.insert(ATTR_CLAIMS.to_owned(), Value::Object(collect_claims(bag)));

    let mut uid_obj = Map::new();
    uid_obj.insert(ATTR_TYPE.to_owned(), json!(entity_type));
    uid_obj.insert(ATTR_ID.to_owned(), json!(id));
    let mut entity_obj = Map::new();
    entity_obj.insert(KEY_UID.to_owned(), Value::Object(uid_obj));
    entity_obj.insert(KEY_ATTRS.to_owned(), Value::Object(attrs));
    entity_obj.insert(KEY_PARENTS.to_owned(), Value::Array(vec![]));
    let entity_json = Value::Object(entity_obj);

    Entity::from_json_value(entity_json, schema).map_err(|e| {
        PdpError::Dispatch(format!(
            "failed to construct principal entity '{entity_type}::\"{id}\"': {e}"
        ))
    })
}

/// Build the resource `Entity` from the policy author's `args.resource`
/// block. Shape:
///
/// ```yaml
/// resource:
///   type: Document          # required, Cedar entity type
///   id: doc-42              # required, entity id (string)
///   attributes:              # optional, key → JSON value
///     classification: internal
///     owner: 'User::"alice"'
/// ```
/// # Errors
///
/// Returns `PdpError::Dispatch` when the argument is not a map, when `type` or
/// `id` is missing, or when an attribute value has no Cedar equivalent.
pub fn build_resource(
    resource_args: &serde_yaml::Value,
    schema: Option<&Schema>,
) -> Result<Entity, PdpError> {
    let map = resource_args.as_mapping().ok_or_else(|| {
        PdpError::Dispatch(
            "cedar:() `resource` must be a mapping with `type` and `id` keys".to_owned(),
        )
    })?;

    let entity_type = yaml_string(map, "type").ok_or_else(|| {
        PdpError::Dispatch("cedar:() `resource.type` missing or not a string".to_owned())
    })?;
    let id = yaml_string(map, "id").ok_or_else(|| {
        PdpError::Dispatch("cedar:() `resource.id` missing or not a string".to_owned())
    })?;

    let attrs_value = map
        .get(serde_yaml::Value::String("attributes".to_owned()))
        .cloned()
        .unwrap_or(serde_yaml::Value::Mapping(Default::default()));
    let attrs_json: Value = serde_json::to_value(&attrs_value).map_err(|e| {
        PdpError::Dispatch(format!(
            "cedar:() `resource.attributes` not JSON-representable: {e}"
        ))
    })?;
    // The same floating-point limitation `collect_claims` works around, but the
    // opposite call is right here: this block is operator-authored YAML, so
    // `score: 1.5` is an easy thing to write and the operator can fix it. Cedar
    // rejects it with "error during entity deserialization" and the resolver
    // fails closed, so without this check the operator sees every request
    // through the step denied and nothing that says which value to change.
    if let Some(key) = first_float_key(&attrs_json) {
        return Err(PdpError::Dispatch(format!(
            "cedar:() `resource.attributes.{key}` holds a floating-point value, and Cedar's value \
             model has no floating-point type; use an integer or quote it as a string"
        )));
    }

    let mut uid_obj = Map::new();
    uid_obj.insert(ATTR_TYPE.to_owned(), json!(entity_type));
    uid_obj.insert(ATTR_ID.to_owned(), json!(id));
    let mut entity_obj = Map::new();
    entity_obj.insert(KEY_UID.to_owned(), Value::Object(uid_obj));
    entity_obj.insert(KEY_ATTRS.to_owned(), attrs_json);
    entity_obj.insert(KEY_PARENTS.to_owned(), Value::Array(vec![]));
    let entity_json = Value::Object(entity_obj);

    Entity::from_json_value(entity_json, schema).map_err(|e| {
        PdpError::Dispatch(format!(
            "failed to construct resource entity '{entity_type}::\"{id}\"': {e}"
        ))
    })
}

/// Apply the optional namespace to a bare entity type. `Some("Acme")` +
/// `"User"` → `"Acme::User"`. `None` → `"User"`. Lets operators with
/// namespaced schemas (`Acme::User`, `Acme::Document`) work without
/// each policy author having to hand-prefix everywhere.
fn qualify_type(bare: &str, namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) if !ns.is_empty() => format!("{ns}::{bare}"),
        _ => bare.to_owned(),
    }
}

/// Read every `<prefix>X = true` key from the bag and return `[X, ...]`.
/// Used for `role.*` → roles and `perm.*` → permissions, matching
/// praxis-policy-apl-cmf's presence-only encoding for role / permission membership.
fn collect_prefixed_bools(bag: &AttributeBag, prefix: &str) -> Vec<String> {
    let mut out: HashSet<String> = HashSet::new();
    for (key, value) in bag.iter() {
        if let Some(name) = key.strip_prefix(prefix)
            && matches!(value, AttributeValue::Bool(true))
        {
            out.insert(name.to_owned());
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v
}

/// Read every `claim.<name>` key and assemble a JSON record of the
/// values. Each claim's value type comes through as JSON (`Bool`,
/// `String`, etc.) so Cedar's record-of-records story works.
///
/// Cedar's value model has no floating-point type, so a float claim is carried
/// as its string form rather than rejected. Claims come from an `IdP`'s token,
/// not from anything the operator authored, so failing the request would deny
/// every user whose provider happens to mint a non-integer number — a fault the
/// operator cannot fix from this side. Compare `resource.attributes`, which
/// *is* operator-authored YAML and still rejects a float outright
/// (`first_float_key`), because there the fix is to edit the value.
fn collect_claims(bag: &AttributeBag) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in bag.iter() {
        if let Some(name) = key.strip_prefix("claim.") {
            let v = match value {
                AttributeValue::Bool(b) => json!(*b),
                AttributeValue::Int(i) => json!(*i),
                // Cedar has no float type — carry the string form so the
                // claim stays visible to policy instead of failing the
                // request. `principal.claims.<name>` compares as a string.
                AttributeValue::Float(f) => json!(f.to_string()),
                AttributeValue::String(s) => json!(s),
                AttributeValue::StringSet(set) => json!(set.iter().collect::<Vec<_>>()),
            };
            out.insert(name.to_owned(), v);
        }
    }
    out
}

/// Name the first key holding a floating-point value, searching nested objects
/// and arrays. Returns `None` when every value is Cedar-representable.
fn first_float_key(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) if n.as_i64().is_none() => Some(String::new()),
        Value::Object(map) => map.iter().find_map(|(k, sub)| {
            first_float_key(sub).map(|rest| {
                if rest.is_empty() {
                    k.clone()
                } else {
                    format!("{k}.{rest}")
                }
            })
        }),
        Value::Array(items) => items.iter().enumerate().find_map(|(i, sub)| {
            first_float_key(sub).map(|rest| {
                if rest.is_empty() {
                    i.to_string()
                } else {
                    format!("{i}.{rest}")
                }
            })
        }),
        _ => None,
    }
}

fn yaml_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.to_owned()))?
        .as_str()
        .map(std::borrow::ToOwned::to_owned)
}
