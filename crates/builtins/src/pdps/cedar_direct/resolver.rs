// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `CedarDirectResolver` — the `PdpResolver` implementation. Wraps a
// loaded `PolicySet`, an `Authorizer`, and an optional `Schema`, and
// translates each APL `PdpCall` into a Cedar request → decision.
//
// # Construction surface
//
// Three constructors covering the typical sources of Cedar policy:
//
//   - `from_policy_text(text)`   — for inline policy in code or
//                                   unified-config YAML.
//   - `from_policy_file(path)`   — for ops-managed policy files.
//   - `from_config(value)`       — for the unified-config block the
//                                   `AplConfigVisitor` parses. Accepts
//                                   either `policy_text` or
//                                   `policy_file` (or both — policy_text
//                                   wins). Also accepts `schema_text` /
//                                   `schema_file` for optional schema
//                                   loading, plus `structured_context`,
//                                   `entity_namespace` and `dialect`.
//
// Construction errors carry rich Cedar-specific messages via
// [`BuildError`]; the visitor wraps these into `VisitorError` →
// `PluginError::Config` at the engine boundary.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{Authorizer, EntityId, EntityTypeName, EntityUid, PolicySet, Schema};

use praxis_policy_apl_core::attributes::AttributeBag;
use praxis_policy_apl_core::route::StructuredInput;
use praxis_policy_apl_core::step::{
    PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver, StructuredInputAvailability,
};

use crate::pdps::cedar_direct::decision::{translate, withheld};
use crate::pdps::cedar_direct::entities::build as build_entities;
use crate::pdps::cedar_direct::error::BuildError;
use crate::pdps::cedar_direct::request::{
    CedarStructured, parse as parse_call, request_error_category, reserved_context_key,
    reserved_key_message, sanitize_structured,
};
use crate::pdps::stack;

/// `PdpResolver` wrapping a bare `cedar-policy` engine. Constructed from
/// policy text / file / config block at startup; evaluates each call
/// against the loaded `PolicySet`.
pub struct CedarDirectResolver {
    policies: Arc<PolicySet>,
    schema: Option<Arc<Schema>>,
    authorizer: Authorizer,
    dialect: PdpDialect,
    /// Optional namespace applied to subject types: `Some("Acme")`
    /// turns "User" into "`Acme::User`" when building the principal
    /// entity. Lets schemas that namespace their entity types work
    /// without policy authors having to hand-prefix every reference.
    entity_namespace: Option<String>,
    /// Add structured input to the context even when a schema is set. Off by
    /// default, since a schema must declare `args` and `llm` in each action's
    /// context type or every request fails validation.
    structured_context: bool,
}

impl CedarDirectResolver {
    /// Build a resolver from inline Cedar policy text. Use this for
    /// tests, demos, and configs where the policy is small enough to
    /// embed in YAML.
    /// # Errors
    ///
    /// Returns `BuildError` when the policy text does not parse as a Cedar
    /// policy set.
    pub fn from_policy_text(policies: &str) -> Result<Self, BuildError> {
        let policy_set: PolicySet = policies
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| BuildError::PolicyParse(e.to_string()))?;
        Ok(Self {
            policies: Arc::new(policy_set),
            schema: None,
            authorizer: Authorizer::new(),
            dialect: PdpDialect::Cedar,
            entity_namespace: None,
            structured_context: false,
        })
    }

    /// Build a resolver from a Cedar policy file on disk. Convenience
    /// over `from_policy_text` for the production layout where policies
    /// live in their own versioned files.
    /// # Errors
    ///
    /// Returns `BuildError` when the file cannot be read or its contents do not
    /// parse as a Cedar policy set.
    pub fn from_policy_file(path: impl AsRef<Path>) -> Result<Self, BuildError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| BuildError::PolicyFile {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_policy_text(&text)
    }

    /// Build a resolver from a unified-config block. Shape:
    ///
    /// ```yaml
    /// dialect: cedar              # optional; default PdpDialect::Cedar
    /// entity_namespace: Acme      # optional; prefixes subject types
    /// policy_text: |              # required (or policy_file)
    ///   @id("owner-override")
    ///   permit(...);
    /// policy_file: /etc/...       # alternative to policy_text
    /// schema_text: |              # optional
    ///   ...
    /// schema_file: /etc/...       # alternative to schema_text
    /// structured_context: true    # optional; default false
    /// ```
    ///
    /// `policy_text` wins over `policy_file` when both are present.
    /// Same for `schema_text` over `schema_file`. Without a schema, structured
    /// input always reaches the context. With one, it does only when
    /// `structured_context` is `true`. Called by
    /// `AplConfigVisitor` when it sees a Cedar PDP block in the
    /// unified-config YAML.
    /// # Errors
    ///
    /// Returns `BuildError` when the block names neither inline policies nor a
    /// policy file, when the file cannot be read, when the policies or schema
    /// do not parse, or when `structured_context` is not a bool.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Self, BuildError> {
        let map = value
            .as_mapping()
            .ok_or_else(|| BuildError::ConfigShape("Cedar PDP config must be a mapping".into()))?;

        let policy_text = read_yaml_string(map, "policy_text");
        let policy_file = read_yaml_string(map, "policy_file");
        let policies = match (policy_text, policy_file) {
            (Some(text), _) => text,
            (None, Some(path)) => {
                std::fs::read_to_string(&path).map_err(|source| BuildError::PolicyFile {
                    path: path.clone(),
                    source,
                })?
            },
            (None, None) => {
                return Err(BuildError::ConfigShape(
                    "Cedar PDP config requires `policy_text` or `policy_file`".into(),
                ));
            },
        };
        let policy_set: PolicySet = policies
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| BuildError::PolicyParse(e.to_string()))?;

        let schema_text = read_yaml_string(map, "schema_text");
        let schema_file = read_yaml_string(map, "schema_file");
        let schema = match (schema_text, schema_file) {
            (Some(text), _) => Some(parse_schema(&text)?),
            (None, Some(path)) => {
                let text =
                    std::fs::read_to_string(&path).map_err(|source| BuildError::SchemaFile {
                        path: path.clone(),
                        source,
                    })?;
                Some(parse_schema(&text)?)
            },
            (None, None) => None,
        };

        let dialect = match read_yaml_string(map, "dialect").as_deref() {
            None | Some("cedar") => PdpDialect::Cedar,
            Some(other) => PdpDialect::Custom(other.to_owned()),
        };

        let entity_namespace = read_yaml_string(map, "entity_namespace");

        let structured_context =
            match map.get(serde_yaml::Value::String("structured_context".to_owned())) {
                None => false,
                Some(serde_yaml::Value::Bool(flag)) => *flag,
                Some(_) => {
                    return Err(BuildError::ConfigShape(
                        "Cedar PDP config `structured_context` must be a bool".into(),
                    ));
                },
            };

        Ok(Self {
            policies: Arc::new(policy_set),
            schema: schema.map(Arc::new),
            authorizer: Authorizer::new(),
            dialect,
            entity_namespace,
            structured_context,
        })
    }

    /// Override the resolver's dialect. Lets operators register a Cedar
    /// engine under a custom name (e.g. `PdpDialect::Custom("workload")`)
    /// so they can coexist with another Cedar engine on the same
    /// `PdpRouter`.
    pub fn with_dialect(mut self, dialect: PdpDialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Attach an `entity_namespace`. Applied at request time to
    /// subject types: `Some("Acme")` + bag `subject.type=User` →
    /// principal UID `Acme::User::"<id>"`.
    pub fn with_entity_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.entity_namespace = Some(namespace.into());
        self
    }

    /// Attach a schema after construction. Useful when the schema
    /// comes from a separate source than the policy text.
    pub fn with_schema(mut self, schema: Schema) -> Self {
        self.schema = Some(Arc::new(schema));
        self
    }

    /// Add structured input to the context even when a schema is set. The
    /// schema must then declare `args` and `llm` in each affected action's
    /// context type. Has no effect without a schema, where structured input is
    /// always added.
    pub fn with_structured_context(mut self, enabled: bool) -> Self {
        self.structured_context = enabled;
        self
    }

    /// Whether structured input reaches the Cedar context.
    fn injects_structured(&self) -> bool {
        self.schema.is_none() || self.structured_context
    }
}

#[async_trait]
impl PdpResolver for CedarDirectResolver {
    fn dialect(&self) -> PdpDialect {
        self.dialect.clone()
    }

    async fn evaluate(&self, call: &PdpCall, bag: &AttributeBag) -> Result<PdpDecision, PdpError> {
        self.evaluate_structured(call, bag, &StructuredInput::default())
            .await
    }

    /// Rejects an operator `context:` that defines a key reserved for
    /// structured input.
    fn validate_call(&self, call: &PdpCall) -> Result<(), String> {
        call.validate_input_options()?;
        reserved_context_key(call).map_or(Ok(()), |key| Err(reserved_key_message(key)))
    }

    fn validate_call_with_input(
        &self,
        call: &PdpCall,
        input: StructuredInputAvailability,
    ) -> Result<(), String> {
        self.validate_call(call)?;
        if self.schema.is_some() && !self.structured_context && (input.llm_request || input.args) {
            return Err(
                "schema-backed Cedar on a route that can carry structured input requires \
                 `structured_context: true` and matching optional context fields"
                    .to_owned(),
            );
        }
        Ok(())
    }

    async fn evaluate_structured(
        &self,
        call: &PdpCall,
        bag: &AttributeBag,
        structured: &StructuredInput,
    ) -> Result<PdpDecision, PdpError> {
        // Resolve `${bag-key}` placeholders in the call's args against
        // the bag before any parsing. The author writes things like
        // `id: ${args.repo_name}`; this pass turns them into concrete
        // values so downstream entity / UID builders can stay literal.
        let resolved_args = crate::pdps::cedar_direct::template::resolve_refs(&call.args, bag)?;
        let resolved_call = PdpCall {
            dialect: call.dialect.clone(),
            args: resolved_args,
        };

        // Everything below recurses through cedar (context/entity JSON parsing
        // and policy evaluation), which self-aborts with "recursion limit
        // reached" when the running thread's remaining stack drops under
        // cedar's 100 KiB floor. The FFI host decides that thread's stack size,
        // and musl's 128 KiB default trips the floor on inputs glibc handles
        // fine. `maybe_grow` runs this block on a fresh, generously-sized stack
        // segment when headroom is low (a no-op when there's already room, so
        // glibc pays nothing), making cedar host-stack-agnostic. The block is
        // fully synchronous — no `.await` — so it is safe to run inside the
        // grown segment. See `pdps::stack`.
        //
        // Sanitizing recurses too, so it runs inside the grown segment. Input
        // holding a Cedar escape key denies here, before Cedar sees it. When a
        // schema is set without `structured_context`, the input is not added,
        // so it is neither sanitized nor checked.
        stack::guarded(|| {
            let sanitized = if self.injects_structured() {
                let Ok(sanitized) = sanitize_structured(structured) else {
                    return Ok(withheld());
                };
                sanitized
            } else {
                CedarStructured::default()
            };
            let parsed = parse_call(&resolved_call, bag, sanitized, self.schema.as_deref())?;
            let entities = build_entities(
                bag,
                parsed.resource_args,
                self.schema.as_deref(),
                self.entity_namespace.as_deref(),
            )?;

            let principal_uid = build_principal_uid(bag, self.entity_namespace.as_deref())?;
            let resource_uid = build_resource_uid(parsed.resource_args)?;

            let request = cedar_policy::Request::new(
                principal_uid,
                parsed.action,
                resource_uid,
                parsed.context,
                self.schema.as_deref(),
            )
            .map_err(|e| {
                PdpError::Dispatch(format!(
                    "Cedar request validation failed: {}",
                    request_error_category(&e)
                ))
            })?;

            let response = self
                .authorizer
                .is_authorized(&request, &self.policies, &entities);

            Ok(translate(&response, &self.policies))
        })
    }
}

fn parse_schema(text: &str) -> Result<Schema, BuildError> {
    Schema::from_cedarschema_str(text)
        .map(|(schema, _warnings)| schema)
        .map_err(|e| BuildError::SchemaParse(e.to_string()))
}

fn read_yaml_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.to_owned()))?
        .as_str()
        .map(std::borrow::ToOwned::to_owned)
}

/// Build the principal `EntityUid` for the Cedar request. Returns the
/// SAME UID that `entities::build_principal` produces; both have to
/// agree on type + id since Cedar resolves the request's principal
/// reference into the entity set by UID equality.
fn build_principal_uid(bag: &AttributeBag, namespace: Option<&str>) -> Result<EntityUid, PdpError> {
    let id = bag
        .get_string("subject.id")
        .ok_or_else(|| PdpError::Dispatch("bag missing `subject.id`".to_owned()))?;
    // Same default as `entities::build_principal`: PascalCase `User` when
    // the key is absent. The CMF bridge writes lowercase (`user`).
    let kind = bag.get_string("subject.type").unwrap_or("User");
    let entity_type = match namespace {
        Some(ns) if !ns.is_empty() => format!("{ns}::{kind}"),
        _ => kind.to_owned(),
    };
    let type_name: EntityTypeName = entity_type.parse().map_err(|_value_text| {
        PdpError::Dispatch("principal type is not a valid Cedar entity type name".to_owned())
    })?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

/// Build the resource `EntityUid`. The type and id may be filled from
/// `${args.X}`, so a parse error names neither.
fn build_resource_uid(resource_args: &serde_yaml::Value) -> Result<EntityUid, PdpError> {
    let map = resource_args
        .as_mapping()
        .ok_or_else(|| PdpError::Dispatch("cedar:() `resource` must be a mapping".to_owned()))?;
    let type_name = read_yaml_string(map, "type")
        .ok_or_else(|| PdpError::Dispatch("cedar:() `resource.type` missing".to_owned()))?;
    let id = read_yaml_string(map, "id")
        .ok_or_else(|| PdpError::Dispatch("cedar:() `resource.id` missing".to_owned()))?;
    let type_name: EntityTypeName = type_name.parse().map_err(|_value_text| {
        PdpError::Dispatch(
            "cedar:() `resource.type` is not a valid Cedar entity type name".to_owned(),
        )
    })?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}
