// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Policy edits must return to the same typed content part that was inspected.
// Resource and prompt projections use fixed object envelopes; tool results
// retain their JSON shape, and text-only messages retain the string fallback.
// These projections omit other parts, so payload mutation tracking must use
// the executor's mutation signal instead of comparing projected values.

use std::collections::HashMap;

use praxis_policy_apl_core::route::field_parents;
use praxis_policy_apl_core::step::FieldParent;
use serde_json::{Value, json};

use praxis_policy_core::cmf::{ContentPart, Message, PromptResult, Resource, ResourceReference};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Denial code for a structured result that cannot be written safely.
pub(crate) const ENVELOPE_REPLACED_CODE: &str = "policy.envelope_replaced";

/// Every field of the [`ResourceReference`] `args` envelope.
///
/// [`ResourceReference`]: ResourceReference
pub(crate) const RESOURCE_REF_FIELDS: &[&str] = &[
    "uri",
    "name",
    "resource_type",
    "range_start",
    "range_end",
    "selector",
];

/// Every field of the [`Resource`] `result` envelope.
///
/// [`Resource`]: Resource
pub(crate) const RESOURCE_FIELDS: &[&str] = &[
    "uri",
    "name",
    "title",
    "description",
    "resource_type",
    "content",
    "mime_type",
    "size_bytes",
    "version",
    "annotations",
    "icons",
];

/// Every field of the [`PromptResult`] `result` envelope.
///
/// [`PromptResult`]: PromptResult
pub(crate) const PROMPT_RESULT_FIELDS: &[&str] = &[
    "prompt_name",
    "description",
    "content",
    "is_error",
    "error_message",
];

/// Envelope fields that hold an open map, so a path may continue inside them.
/// Every other field holds a single value.
pub(crate) const OPEN_MAP_FIELDS: &[&str] = &["annotations"];

/// Envelope fields of a [`ResourceReference`] that write-back never changes.
///
/// [`ResourceReference`]: ResourceReference
pub(crate) const RESOURCE_REF_READ_ONLY: &[&str] = &["uri", "resource_type"];

/// Envelope fields of a [`Resource`] that write-back never changes.
///
/// [`Resource`]: Resource
pub(crate) const RESOURCE_READ_ONLY: &[&str] = &["uri", "resource_type", "icons"];

/// Envelope fields of a [`PromptResult`] that write-back never changes.
///
/// [`PromptResult`]: PromptResult
pub(crate) const PROMPT_RESULT_READ_ONLY: &[&str] = &["prompt_name", "is_error"];

// -----------------------------------------------------------------------------
// Projection
// -----------------------------------------------------------------------------

/// Selects the content parts addressed by a route's field pipelines.
///
/// Prompt routes prefer prompt requests, tool routes prefer tool calls, and
/// resource routes address resource parts. Missing structured parts fall back
/// to the message's concatenated text.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Projection {
    /// Prompt arguments and rendered results; tool-call arguments are a fallback.
    Prompt,
    /// A `resource:` route: args from the first `ResourceRef`, result from the
    /// first `Resource`.
    Resource,
    /// Tool arguments and results; prompt-request arguments are a fallback.
    #[default]
    Tool,
}

impl Projection {
    /// Select the projection for an entity type.
    ///
    /// Unrecognized entity types use the tool projection.
    pub fn for_entity(entity_type: &str) -> Self {
        match entity_type {
            praxis_policy_core::cmf::constants::ENTITY_PROMPT => Self::Prompt,
            praxis_policy_core::cmf::constants::ENTITY_RESOURCE => Self::Resource,
            _ => Self::Tool,
        }
    }
}

/// Replace the first text part, or append one when the message has no text part.
pub(crate) fn rewrite_message_text(msg: &mut Message, new_text: &str) {
    for part in &mut msg.content {
        if let ContentPart::Text { text } = part {
            *text = new_text.to_owned();
            return;
        }
    }
    msg.content.push(ContentPart::Text {
        text: new_text.to_owned(),
    });
}

/// Return the arguments addressed by `projection`.
///
/// Tool and prompt routes prefer their own request kind and use the other kind
/// only when their preferred part is absent. Resource routes return the fixed
/// resource-reference envelope. A message without a matching request returns
/// its concatenated text.
pub(crate) fn extract_args_from_message(msg: &Message, projection: Projection) -> Value {
    match projection {
        Projection::Tool => {
            if let Some(v) = find_args::<true>(msg) {
                return v;
            }
        },
        Projection::Prompt => {
            if let Some(v) = find_args::<false>(msg) {
                return v;
            }
        },
        Projection::Resource => {
            for part in &msg.content {
                if let ContentPart::ResourceRef { content } = part {
                    return project_resource_ref_args(content);
                }
            }
        },
    }
    Value::String(msg.get_text_content())
}

/// Return arguments from the preferred request kind, using the other kind as fallback.
fn find_args<const TOOL_FIRST: bool>(msg: &Message) -> Option<Value> {
    find_argument_map::<TOOL_FIRST>(msg).map(clone_arguments)
}

pub(crate) fn arguments_for_projection(
    msg: &Message,
    projection: Projection,
) -> Option<&HashMap<String, Value>> {
    match projection {
        Projection::Tool => find_argument_map::<true>(msg),
        Projection::Prompt => find_argument_map::<false>(msg),
        Projection::Resource => None,
    }
}

fn find_argument_map<const TOOL_FIRST: bool>(msg: &Message) -> Option<&HashMap<String, Value>> {
    let mut fallback = None;
    for part in &msg.content {
        let (arguments, preferred) = match part {
            ContentPart::ToolCall { content } => (&content.arguments, TOOL_FIRST),
            ContentPart::PromptRequest { content } => (&content.arguments, !TOOL_FIRST),
            _ => continue,
        };
        if preferred {
            return Some(arguments);
        }
        fallback = fallback.or(Some(arguments));
    }
    fallback
}

fn clone_arguments(arguments: &HashMap<String, Value>) -> Value {
    Value::Object(
        arguments
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

/// Return the fixed resource-reference argument envelope.
///
/// Every field is present; unset optional fields are `null`.
pub(crate) fn project_resource_ref_args(resource_ref: &ResourceReference) -> Value {
    json!({
        "uri": resource_ref.uri,
        "name": resource_ref.name,
        "resource_type": resource_ref.resource_type,
        "range_start": resource_ref.range_start,
        "range_end": resource_ref.range_end,
        "selector": resource_ref.selector,
    })
}

/// Return the fixed fetched-resource result envelope.
///
/// Content is an opaque string or `null`. Blob data is excluded, and every
/// projected field is present even when unset.
pub(crate) fn project_resource_result(resource: &Resource) -> Value {
    json!({
        "uri": resource.uri,
        "name": resource.name,
        "title": resource.title,
        "description": resource.description,
        "resource_type": resource.resource_type,
        "content": resource.content,
        "mime_type": resource.mime_type,
        "size_bytes": resource.size_bytes,
        "version": resource.version,
        "annotations": resource.annotations,
        "icons": resource.icons,
    })
}

/// Return the fixed rendered-prompt result envelope.
///
/// Policy addresses flat content rather than the message list. Every projected
/// field is present; unset optional fields are `null`.
pub(crate) fn project_prompt_result(prompt: &PromptResult) -> Value {
    json!({
        "prompt_name": prompt.prompt_name,
        "description": prompt.description,
        "content": prompt.content,
        "is_error": prompt.is_error,
        "error_message": prompt.error_message,
    })
}

/// Which content part's envelope was replaced by a non-object value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplacedPart {
    ToolCall,
    ToolResult,
    PromptRequest,
    ResourceRef,
    Resource,
    PromptResult,
}

impl ReplacedPart {
    /// A representative field name the error message can suggest instead of
    /// the whole-envelope replacement.
    pub(crate) fn suggested_field(self) -> &'static str {
        match self {
            Self::Resource | Self::PromptResult => "content",
            _ => "<field>",
        }
    }
}

impl std::fmt::Display for ReplacedPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolCall => f.write_str("ToolCall"),
            Self::ToolResult => f.write_str("ToolResult"),
            Self::PromptRequest => f.write_str("PromptRequest"),
            Self::ResourceRef => f.write_str("ResourceRef"),
            Self::Resource => f.write_str("Resource"),
            Self::PromptResult => f.write_str("PromptResult"),
        }
    }
}

/// A selected envelope cannot accept a result edit.
///
/// Callers must deny the request when its envelope was replaced with a
/// non-object or its resource target is missing or ambiguous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EnvelopeReplaced {
    /// The content part whose envelope could not be written.
    pub(crate) part: ReplacedPart,
    /// Why write-back could not apply the result.
    pub(crate) error: EnvelopeError,
}

/// Why an [`EnvelopeReplaced`] write-back failed. The caller denies the
/// request either way; the error only picks the denial's wording.
///
/// [`EnvelopeReplaced`]: EnvelopeReplaced
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnvelopeError {
    /// The pipeline replaced the envelope as a whole with a non-object value.
    Replaced,
    /// The part the route projected is no longer in the message, for
    /// example because a plugin removed it.
    Removed,
    /// Several parts share the selected identity.
    Ambiguous,
    /// Plugin edits changed the shape needed to locate a field write.
    ShapeChanged,
}

impl EnvelopeReplaced {
    pub(crate) fn shape_changed(projection: Projection, args: bool) -> Self {
        let part = match (projection, args) {
            (Projection::Resource, true) => ReplacedPart::ResourceRef,
            (Projection::Resource, false) => ReplacedPart::Resource,
            (Projection::Prompt, true) => ReplacedPart::PromptRequest,
            (Projection::Prompt, false) => ReplacedPart::PromptResult,
            (Projection::Tool, true) => ReplacedPart::ToolCall,
            (Projection::Tool, false) => ReplacedPart::ToolResult,
        };
        Self {
            part,
            error: EnvelopeError::ShapeChanged,
        }
    }

    /// Explain why the selected envelope cannot be safely written.
    pub(crate) fn reason(self, block: &str) -> String {
        let part = self.part;
        match self.error {
            EnvelopeError::Replaced => {
                let example = part.suggested_field();
                format!(
                    "the `{block}:` pipeline replaced the whole `{part}` envelope, which \
                     cannot be applied; address a field instead, such as `{example}: \
                     redact` or `\"**.<field>\": redact`"
                )
            },
            EnvelopeError::Removed => format!(
                "the `{part}` that the `{block}:` pipeline checked is no longer in the \
                 message, so its result cannot be written back; a plugin may have removed it"
            ),
            EnvelopeError::ShapeChanged => format!(
                "the `{block}:` pipeline and plugin payload disagree on parent structure or array indexes"
            ),
            EnvelopeError::Ambiguous => format!(
                "the `{block}:` pipeline cannot identify a unique `{part}` because several \
                 parts share its identity; emit one part per message or use unique identities"
            ),
        }
    }
}

/// Inverse of [`extract_args_from_message`]: write `args` back into the part
/// the same `projection` reads. Each projection prefers its own part kind
/// ([`Projection::Tool`] → `ToolCall`, [`Projection::Prompt`] →
/// `PromptRequest`) and falls back to the other only when its preferred
/// kind is absent, mirroring the read ordering in
/// [`extract_args_from_message`].
///
/// Args replaced as a whole with a value that is not an object (such as a bare
/// `**` redaction turning them into a string) are refused with
/// [`EnvelopeReplaced`] and the part is left untouched, for a `ToolCall` and
/// `PromptRequest` as for a `ResourceRef`. Forwarding the original instead
/// would send the arguments the pipeline meant to hide.
///
/// [`Projection::Tool`]: Projection::Tool
/// [`Projection::Prompt`]: Projection::Prompt
/// [`extract_args_from_message`]: extract_args_from_message
/// [`EnvelopeReplaced`]: EnvelopeReplaced
pub(crate) fn write_args_back_to_message(
    msg: &mut Message,
    args: &Value,
    projection: Projection,
) -> Result<(), EnvelopeReplaced> {
    match projection {
        Projection::Tool => {
            if let Some(r) = write_args_to_part::<true>(msg, args) {
                return r;
            }
        },
        Projection::Prompt => {
            if let Some(r) = write_args_to_part::<false>(msg, args) {
                return r;
            }
        },
        Projection::Resource => {
            for part in &mut msg.content {
                if let ContentPart::ResourceRef { content } = part {
                    return write_resource_ref(content, args);
                }
            }
        },
    }
    if let Some(text) = args.as_str() {
        rewrite_message_text(msg, text);
    }
    Ok(())
}

/// Read arguments from the originally selected reference.
pub(crate) fn extract_args_by_identity(
    msg: &Message,
    projection: Projection,
    identity: &ResultIdentity,
) -> Result<Value, EnvelopeReplaced> {
    if let Some(ContentPart::ResourceRef { content }) = identity.part(msg)? {
        return Ok(project_resource_ref_args(content));
    }
    Ok(if projection == Projection::Resource {
        Value::String(msg.get_text_content())
    } else {
        extract_args_from_message(msg, projection)
    })
}

/// Write arguments to the originally selected reference.
pub(crate) fn write_args_by_identity(
    msg: &mut Message,
    args: &Value,
    projection: Projection,
    identity: &ResultIdentity,
) -> Result<(), EnvelopeReplaced> {
    if let Some(index) = identity.index(msg)?
        && let Some(ContentPart::ResourceRef { content }) = msg.content.get_mut(index)
    {
        return write_resource_ref(content, args);
    }
    if projection == Projection::Resource {
        if let Some(text) = args.as_str() {
            rewrite_message_text(msg, text);
        }
        return Ok(());
    }
    write_args_back_to_message(msg, args, projection)
}

/// Write arguments back to the preferred part kind. When `TOOL_FIRST` is
/// true, `ToolCall` is preferred with `PromptRequest` as fallback; when
/// false the preference is reversed. Returns `None` when neither kind
/// exists in the message.
fn write_args_to_part<const TOOL_FIRST: bool>(
    msg: &mut Message,
    args: &Value,
) -> Option<Result<(), EnvelopeReplaced>> {
    let mut preferred: Option<(usize, ReplacedPart)> = None;
    let mut fallback: Option<(usize, ReplacedPart)> = None;
    for (i, part) in msg.content.iter().enumerate() {
        match part {
            ContentPart::ToolCall { .. } => {
                if TOOL_FIRST {
                    preferred = preferred.or(Some((i, ReplacedPart::ToolCall)));
                } else {
                    fallback = fallback.or(Some((i, ReplacedPart::ToolCall)));
                }
            },
            ContentPart::PromptRequest { .. } => {
                if TOOL_FIRST {
                    fallback = fallback.or(Some((i, ReplacedPart::PromptRequest)));
                } else {
                    preferred = preferred.or(Some((i, ReplacedPart::PromptRequest)));
                }
            },
            _ => {},
        }
    }
    let (idx, replaced) = preferred.or(fallback)?;
    Some(write_arguments_at(msg, idx, args, replaced))
}

fn write_arguments_at(
    msg: &mut Message,
    idx: usize,
    args: &Value,
    replaced: ReplacedPart,
) -> Result<(), EnvelopeReplaced> {
    let Some(obj) = args.as_object() else {
        return Err(EnvelopeReplaced {
            part: replaced,
            error: EnvelopeError::Replaced,
        });
    };
    let new_args: HashMap<String, Value> =
        obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let Some(part) = msg.content.get_mut(idx) else {
        return Ok(());
    };
    match part {
        ContentPart::ToolCall { content } => content.arguments = new_args,
        ContentPart::PromptRequest { content } => content.arguments = new_args,
        _ => {},
    }
    Ok(())
}

/// The selected part must remain unique before and after plugin execution.
#[derive(Clone, Debug, Default)]
pub(crate) struct ResultIdentity {
    ambiguous: bool,
    key: Option<PartKey>,
}

impl ResultIdentity {
    /// Identify the first resource and record whether its URI is unique.
    pub(crate) fn from_resource_message(msg: &Message) -> Self {
        Self::select(msg, ReplacedPart::Resource)
    }

    /// Identify the first resource reference by URI.
    pub(crate) fn from_reference_message(msg: &Message) -> Self {
        Self::select(msg, ReplacedPart::ResourceRef)
    }

    /// Identify the first prompt result by request ID and prompt name.
    pub(crate) fn from_prompt_message(msg: &Message) -> Self {
        Self::select(msg, ReplacedPart::PromptResult)
    }

    fn select(msg: &Message, kind: ReplacedPart) -> Self {
        let key = msg
            .content
            .iter()
            .find_map(|part| PartKey::from_part(part, kind));
        let ambiguous = key.as_ref().is_some_and(|key| {
            msg.content
                .iter()
                .filter(|part| key.same_address(part))
                .take(2)
                .count()
                > 1
        });
        Self { ambiguous, key }
    }

    /// Return the selected resource, or `None` when no resource was selected.
    ///
    /// # Errors
    ///
    /// Refuses a removed target or a URI that was or became ambiguous.
    pub(crate) fn resource<'a>(
        &self,
        msg: &'a Message,
    ) -> Result<Option<&'a Resource>, EnvelopeReplaced> {
        if !matches!(self.key, Some(PartKey::Resource { .. })) {
            return Ok(None);
        }
        let Some(index) = self.index(msg)? else {
            return Ok(None);
        };
        match msg.content.get(index) {
            Some(ContentPart::Resource { content }) => Ok(Some(content)),
            _ => Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Removed,
            }),
        }
    }

    pub(crate) fn part<'a>(
        &self,
        msg: &'a Message,
    ) -> Result<Option<&'a ContentPart>, EnvelopeReplaced> {
        self.index(msg)
            .map(|index| index.and_then(|index| msg.content.get(index)))
    }

    fn index(&self, msg: &Message) -> Result<Option<usize>, EnvelopeReplaced> {
        let Some(key) = &self.key else {
            return Ok(None);
        };
        let part = key.kind();
        if self.ambiguous {
            return Err(EnvelopeReplaced {
                part,
                error: EnvelopeError::Ambiguous,
            });
        }
        let mut matches = msg
            .content
            .iter()
            .enumerate()
            .filter_map(|(index, part)| key.same_address(part).then_some(index));
        let Some(index) = matches.next() else {
            return Err(EnvelopeReplaced {
                part,
                error: EnvelopeError::Removed,
            });
        };
        if matches.next().is_some() {
            return Err(EnvelopeReplaced {
                part,
                error: EnvelopeError::Ambiguous,
            });
        }
        if !msg.content.get(index).is_some_and(|part| key.matches(part)) {
            return Err(EnvelopeReplaced {
                part,
                error: EnvelopeError::Removed,
            });
        }
        Ok(Some(index))
    }
}

#[derive(Clone, Debug)]
enum PartKey {
    Resource { uri: String, request_id: String },
    ResourceRef { uri: String, request_id: String },
    PromptResult { request_id: String, name: String },
}

impl PartKey {
    fn same_address(&self, part: &ContentPart) -> bool {
        match (self, part) {
            (Self::Resource { uri, .. }, ContentPart::Resource { content }) => content.uri == *uri,
            (Self::ResourceRef { uri, .. }, ContentPart::ResourceRef { content }) => {
                content.uri == *uri
            },
            _ => self.matches(part),
        }
    }

    fn from_part(part: &ContentPart, kind: ReplacedPart) -> Option<Self> {
        match (kind, part) {
            (ReplacedPart::Resource, ContentPart::Resource { content }) => Some(Self::Resource {
                uri: content.uri.clone(),
                request_id: content.resource_request_id.clone(),
            }),
            (ReplacedPart::ResourceRef, ContentPart::ResourceRef { content }) => {
                Some(Self::ResourceRef {
                    uri: content.uri.clone(),
                    request_id: content.resource_request_id.clone(),
                })
            },
            (ReplacedPart::PromptResult, ContentPart::PromptResult { content }) => {
                Some(Self::PromptResult {
                    request_id: content.prompt_request_id.clone(),
                    name: content.prompt_name.clone(),
                })
            },
            _ => None,
        }
    }

    fn kind(&self) -> ReplacedPart {
        match self {
            Self::Resource { .. } => ReplacedPart::Resource,
            Self::ResourceRef { .. } => ReplacedPart::ResourceRef,
            Self::PromptResult { .. } => ReplacedPart::PromptResult,
        }
    }

    fn matches(&self, part: &ContentPart) -> bool {
        match (self, part) {
            (Self::Resource { uri, request_id }, ContentPart::Resource { content }) => {
                content.uri == *uri && content.resource_request_id == *request_id
            },
            (Self::ResourceRef { uri, request_id }, ContentPart::ResourceRef { content }) => {
                content.uri == *uri && content.resource_request_id == *request_id
            },
            (Self::PromptResult { request_id, name }, ContentPart::PromptResult { content }) => {
                content.prompt_request_id == *request_id && content.prompt_name == *name
            },
            _ => false,
        }
    }
}

/// Return the result addressed by `projection` and its structured-part identity.
///
/// Tool results retain their JSON value. Resource and prompt results use fixed
/// object envelopes. Missing structured results return concatenated text.
pub(crate) fn extract_result_from_message(
    msg: &Message,
    projection: Projection,
) -> (Value, ResultIdentity) {
    for part in &msg.content {
        match (projection, part) {
            (Projection::Tool, ContentPart::ToolResult { content }) => {
                return (content.content.clone(), ResultIdentity::default());
            },
            (Projection::Resource, ContentPart::Resource { content }) => {
                let identity = ResultIdentity::from_resource_message(msg);
                return (project_resource_result(content), identity);
            },
            (Projection::Prompt, ContentPart::PromptResult { content }) => {
                return (
                    project_prompt_result(content),
                    ResultIdentity::from_prompt_message(msg),
                );
            },
            _ => {},
        }
    }
    (
        Value::String(msg.get_text_content()),
        ResultIdentity::default(),
    )
}

/// Return a field from the result addressed by `projection`.
///
/// Resource annotation paths support dotted descendants. A scalar tool result
/// or a text-only message returns the scalar value itself.
pub(crate) fn extract_result_field(
    msg: &Message,
    projection: Projection,
    field: &str,
) -> Option<Value> {
    if projection == Projection::Tool
        && let Some(value) = msg
            .content
            .iter()
            .find_map(|part| match part {
                ContentPart::ToolResult { content } => Some(&content.content),
                _ => None,
            })
            .filter(|value| value.is_array())
    {
        return Some(value.clone());
    }
    let path: Vec<String> = field.split('.').map(str::to_owned).collect();
    extract_result_field_at(msg, projection, &path)
}

/// Read one result field without splitting literal object keys.
pub(crate) fn extract_result_field_at(
    msg: &Message,
    projection: Projection,
    path: &[String],
) -> Option<Value> {
    for part in &msg.content {
        match (projection, part) {
            (Projection::Tool, ContentPart::ToolResult { content }) => {
                return if content.content.is_object() || content.content.is_array() {
                    value_at(&content.content, path).cloned()
                } else {
                    Some(content.content.clone())
                };
            },
            (Projection::Resource, ContentPart::Resource { content }) => {
                return resource_field_value_at(content, path);
            },
            (Projection::Prompt, ContentPart::PromptResult { content }) => {
                return path
                    .first()
                    .filter(|_| path.len() == 1)
                    .and_then(|field| prompt_result_field(content, field));
            },
            _ => {},
        }
    }
    Some(Value::String(msg.get_text_content()))
}

/// Read one resource field using expanded path segments.
pub(crate) fn resource_field_value_at(resource: &Resource, path: &[String]) -> Option<Value> {
    let (head, rest) = path.split_first()?;
    if head == "annotations"
        && let Some((key, inner)) = rest.split_first()
    {
        return value_at(resource.annotations.get(key)?, inner).cloned();
    }
    if head == "icons"
        && let Some((index, fields)) = rest.split_first()
    {
        let icon = resource.icons.as_ref()?.get(index.parse::<usize>().ok()?)?;
        let Some((field, tail)) = fields.split_first() else {
            return Some(json!(icon));
        };
        return match (field.as_str(), tail) {
            ("src", []) => Some(json!(icon.src)),
            ("mime_type", []) => icon.mime_type.as_ref().map(|value| json!(value)),
            ("sizes", []) => icon.sizes.as_ref().map(|value| json!(value)),
            ("sizes", [index]) => icon
                .sizes
                .as_ref()?
                .get(index.parse::<usize>().ok()?)
                .map(|value| json!(value)),
            _ => None,
        };
    }
    rest.is_empty()
        .then(|| resource_field(resource, head))
        .flatten()
}

/// Resolve segments without splitting object keys that contain dots.
pub(crate) fn value_at<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(value, |value, segment| match value {
        Value::Object(map) => map.get(segment),
        Value::Array(items) => segment
            .parse::<usize>()
            .ok()
            .and_then(|index| items.get(index)),
        _ => None,
    })
}

/// One top-level field of the [`project_resource_result`] envelope, or `None`
/// for a name the envelope does not have.
///
/// [`project_resource_result`]: project_resource_result
fn resource_field(resource: &Resource, name: &str) -> Option<Value> {
    Some(match name {
        "uri" => json!(resource.uri),
        "name" => json!(resource.name),
        "title" => json!(resource.title),
        "description" => json!(resource.description),
        "resource_type" => json!(resource.resource_type),
        "content" => json!(resource.content),
        "mime_type" => json!(resource.mime_type),
        "size_bytes" => json!(resource.size_bytes),
        "version" => json!(resource.version),
        "annotations" => json!(resource.annotations),
        "icons" => json!(resource.icons),
        _ => return None,
    })
}

/// One top-level field of the [`project_prompt_result`] envelope, or `None`
/// for a name the envelope does not have.
///
/// [`project_prompt_result`]: project_prompt_result
pub(crate) fn prompt_result_field(prompt: &PromptResult, name: &str) -> Option<Value> {
    Some(match name {
        "prompt_name" => json!(prompt.prompt_name),
        "description" => json!(prompt.description),
        "content" => json!(prompt.content),
        "is_error" => json!(prompt.is_error),
        "error_message" => json!(prompt.error_message),
        _ => return None,
    })
}

/// Return the originally selected resource or prompt result.
///
/// # Errors
///
/// Refuses a removed or ambiguous structured target.
pub(crate) fn extract_result_by_identity(
    msg: &Message,
    projection: Projection,
    identity: &ResultIdentity,
) -> Result<Value, EnvelopeReplaced> {
    if let Some(part) = identity.part(msg)? {
        return Ok(match part {
            ContentPart::Resource { content } => project_resource_result(content),
            ContentPart::PromptResult { content } => project_prompt_result(content),
            _ => Value::Null,
        });
    }
    Ok(if projection == Projection::Tool {
        extract_result_from_message(msg, projection).0
    } else {
        Value::String(msg.get_text_content())
    })
}

/// Apply a result edit to the selected content part.
///
/// Resource and prompt edits require the original identity to remain unique.
/// Tool projections address their first matching result part.
///
/// # Errors
///
/// Refuses a non-object fixed envelope or a removed or ambiguous structured target.
pub(crate) fn write_result_back_to_message(
    msg: &mut Message,
    result: &Value,
    projection: Projection,
    identity: &ResultIdentity,
) -> Result<(), EnvelopeReplaced> {
    if let Some(index) = identity.index(msg)? {
        return match msg.content.get_mut(index) {
            Some(ContentPart::Resource { content }) => write_resource(content, result),
            Some(ContentPart::PromptResult { content }) => write_prompt_result(content, result),
            _ => Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Removed,
            }),
        };
    }
    if projection != Projection::Tool {
        if let Some(text) = result.as_str() {
            rewrite_message_text(msg, text);
        }
        return Ok(());
    }
    for part in &mut msg.content {
        match (projection, part) {
            (Projection::Tool, ContentPart::ToolResult { content }) => {
                content.content = result.clone();
                return Ok(());
            },
            (Projection::Resource, ContentPart::Resource { content }) => {
                return write_resource(content, result);
            },
            (Projection::Prompt, ContentPart::PromptResult { content }) => {
                return write_prompt_result(content, result);
            },
            _ => {},
        }
    }
    if let Some(text) = result.as_str() {
        rewrite_message_text(msg, text);
    }
    Ok(())
}

/// Apply a complete resource-reference argument envelope.
///
/// URI and resource type remain fixed. Missing optional fields are cleared.
///
/// # Errors
///
/// Refuses a non-object envelope without changing the resource reference.
pub(crate) fn write_resource_ref(
    resource_ref: &mut ResourceReference,
    args: &Value,
) -> Result<(), EnvelopeReplaced> {
    let Some(obj) = args.as_object() else {
        return Err(EnvelopeReplaced {
            part: ReplacedPart::ResourceRef,
            error: EnvelopeError::Replaced,
        });
    };
    write_opt_string(&mut resource_ref.name, obj.get("name"));
    write_opt_u64(
        &mut resource_ref.range_start,
        obj.get("range_start"),
        "range_start",
    );
    write_opt_u64(
        &mut resource_ref.range_end,
        obj.get("range_end"),
        "range_end",
    );
    write_opt_string(&mut resource_ref.selector, obj.get("selector"));
    Ok(())
}

/// Apply a complete fetched-resource result envelope.
///
/// URI, resource type, icons, request ID and blob data remain fixed.
/// Missing optional fields are cleared.
///
/// # Errors
///
/// Refuses a non-object envelope without changing the resource.
pub(crate) fn write_resource(
    resource: &mut Resource,
    result: &Value,
) -> Result<(), EnvelopeReplaced> {
    let Some(obj) = result.as_object() else {
        return Err(EnvelopeReplaced {
            part: ReplacedPart::Resource,
            error: EnvelopeError::Replaced,
        });
    };
    write_opt_string(&mut resource.name, obj.get("name"));
    write_opt_string(&mut resource.title, obj.get("title"));
    write_opt_string(&mut resource.description, obj.get("description"));
    write_opt_string(&mut resource.content, obj.get("content"));
    write_opt_string(&mut resource.mime_type, obj.get("mime_type"));
    write_opt_u64(
        &mut resource.size_bytes,
        obj.get("size_bytes"),
        "size_bytes",
    );
    write_opt_string(&mut resource.version, obj.get("version"));
    write_annotations(&mut resource.annotations, obj.get("annotations"));
    Ok(())
}

/// Apply a complete rendered-prompt result envelope.
///
/// Prompt identity, error status and the message list remain fixed.
/// Missing optional fields are cleared.
///
/// # Errors
///
/// Refuses a non-object envelope without changing the prompt result.
pub(crate) fn write_prompt_result(
    prompt: &mut PromptResult,
    result: &Value,
) -> Result<(), EnvelopeReplaced> {
    let Some(obj) = result.as_object() else {
        return Err(EnvelopeReplaced {
            part: ReplacedPart::PromptResult,
            error: EnvelopeError::Replaced,
        });
    };
    write_opt_string(&mut prompt.description, obj.get("description"));
    write_opt_string(&mut prompt.content, obj.get("content"));
    write_opt_string(&mut prompt.error_message, obj.get("error_message"));
    Ok(())
}

/// One field write made by policy, including writes equal to their input.
#[derive(Clone, Debug)]
pub(crate) struct FieldWrite {
    pub(crate) parents: Vec<FieldParent>,
    pub(crate) path: Vec<String>,
    pub(crate) value: Option<Value>,
}

/// Replay leaf writes without replacing siblings changed by plugins.
///
/// A changed array shape or a removed parent refuses reconciliation.
pub(crate) fn apply_written_paths(
    base: &mut Value,
    writes: &[FieldWrite],
    projection: Projection,
    args: bool,
) -> Result<(), EnvelopeReplaced> {
    fn apply(base: &mut Value, path: &[String], value: Option<&Value>) -> bool {
        let Some((key, rest)) = path.split_first() else {
            if let Some(value) = value {
                *base = value.clone();
                return true;
            }
            return false;
        };
        match base {
            Value::Object(map) => {
                if rest.is_empty() {
                    if let Some(value) = value {
                        map.insert(key.clone(), value.clone());
                    } else {
                        map.remove(key);
                    }
                    true
                } else {
                    map.get_mut(key)
                        .is_some_and(|child| apply(child, rest, value))
                }
            },
            Value::Array(items) => {
                let Some(index) = key
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < items.len())
                else {
                    return false;
                };
                if rest.is_empty() {
                    if let Some(value) = value {
                        if let Some(slot) = items.get_mut(index) {
                            *slot = value.clone();
                        }
                    } else {
                        items.remove(index);
                    }
                    true
                } else {
                    items
                        .get_mut(index)
                        .is_some_and(|child| apply(child, rest, value))
                }
            },
            _ => false,
        }
    }
    let error = EnvelopeReplaced::shape_changed(projection, args);
    for write in writes {
        if field_parents(base, &write.path).as_deref() != Some(write.parents.as_slice()) {
            return Err(error);
        }
        if !apply(base, &write.path, write.value.as_ref()) {
            return Err(error);
        }
    }
    Ok(())
}

fn write_opt_string(target: &mut Option<String>, value: Option<&Value>) {
    let new = match value {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(other) => {
            *target = Some(other.to_string());
            return;
        },
    };
    if target.as_deref() != new {
        *target = new.map(str::to_owned);
    }
}

/// A value that is not a non-negative integer within `u64` clears the field.
/// It is usually a redaction (`redact` writes a string), and keeping the old
/// value would forward what the redaction meant to hide.
fn write_opt_u64(target: &mut Option<u64>, value: Option<&Value>, field: &str) {
    *target = match value {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v.as_u64();
            if n.is_none() {
                tracing::warn!(field, "clearing an unsigned field given a non-u64 value");
            }
            n
        },
    };
}

/// Preserve unchanged annotations; a non-object replacement clears the map
/// so the original data cannot survive a whole-field redaction.
fn write_annotations(target: &mut HashMap<String, Value>, value: Option<&Value>) {
    match value {
        None | Some(Value::Null) => target.clear(),
        Some(Value::Object(map)) => {
            if target.len() == map.len()
                && map
                    .iter()
                    .all(|(key, value)| target.get(key) == Some(value))
            {
                return;
            }
            *target = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        },
        Some(_) => {
            tracing::warn!("clearing annotations given a non-object value");
            target.clear();
        },
    }
}

#[cfg(test)]
#[allow(
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
    use praxis_policy_apl_core::get_dotted;

    use praxis_policy_core::cmf::enums::{ResourceType, Role};

    use praxis_policy_core::cmf::{ToolCall, ToolResult};

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn mixed_argument_parts_use_route_preference_in_both_orders() {
        for prompt_first in [false, true] {
            for projection in [Projection::Tool, Projection::Prompt] {
                let tool = tool_call_message().content.remove(0);
                let prompt = prompt_request_message().content.remove(0);
                let mut msg = Message::with_content(
                    Role::User,
                    if prompt_first {
                        vec![prompt, tool]
                    } else {
                        vec![tool, prompt]
                    },
                );
                let expected_args = match projection {
                    Projection::Tool => serde_json::json!({"city": "London", "units": "metric"}),
                    Projection::Prompt => serde_json::json!({"tone": "terse", "length": 200}),
                    Projection::Resource => panic!("only tool and prompt routes are included"),
                };
                assert_eq!(
                    super::extract_args_from_message(&msg, projection),
                    expected_args,
                    "route preference must hold regardless of part order"
                );
                let mut expected = msg.clone();
                let index = match projection {
                    Projection::Tool => usize::from(prompt_first),
                    Projection::Prompt => usize::from(!prompt_first),
                    Projection::Resource => panic!("only tool and prompt routes are included"),
                };
                let rewritten = serde_json::json!({"topic": "rewritten"});
                let arguments = [("topic".to_owned(), serde_json::json!("rewritten"))].into();
                match expected.content.get_mut(index) {
                    Some(ContentPart::ToolCall { content }) => content.arguments = arguments,
                    Some(ContentPart::PromptRequest { content }) => content.arguments = arguments,
                    _ => panic!("the selected index must hold the route's own part"),
                }
                super::write_args_back_to_message(&mut msg, &rewritten, projection)
                    .expect("argument write-back must apply");
                assert_eq!(
                    serde_json::to_value(&msg).expect("message serializes"),
                    serde_json::to_value(&expected).expect("expected message serializes"),
                    "write-back must change only the route's preferred part"
                );
            }
        }
    }

    #[test]
    fn result_identity_follows_a_unique_resource_after_reordering() {
        let mut msg = resource_message();
        let identity = ResultIdentity::from_resource_message(&msg);
        let mut other = resource_message().content.remove(0);
        if let ContentPart::Resource { content } = &mut other {
            content.uri = "hr://employees/99".to_owned();
            content.content = Some("public".to_owned());
        }
        msg.content.insert(0, other);
        let selected = identity
            .resource(&msg)
            .expect("unique target remains")
            .expect("resource is selected");
        assert_eq!(
            selected.uri, "hr://employees/42",
            "inserting a different resource must not change the selected target"
        );
    }

    #[test]
    fn an_originally_ambiguous_resource_stays_refused_after_one_part_is_removed() {
        let mut msg = resource_message();
        msg.content.extend(resource_message().content);
        let identity = ResultIdentity::from_resource_message(&msg);
        msg.content.remove(0);
        let original = serde_json::to_value(&msg).expect("message serializes");
        let result = super::write_result_back_to_message(
            &mut msg,
            &serde_json::json!({"content": "[REDACTED]"}),
            Projection::Resource,
            &identity,
        );
        assert!(
            matches!(
                result,
                Err(EnvelopeReplaced {
                    error: EnvelopeError::Ambiguous,
                    ..
                })
            ),
            "removing a duplicate cannot identify which original resource remains"
        );
        assert_eq!(
            serde_json::to_value(&msg).expect("message serializes"),
            original,
            "an ambiguous write must not change the remaining resource"
        );
    }

    #[test]
    fn a_resource_write_is_refused_when_a_plugin_introduces_a_duplicate_uri() {
        let mut msg = resource_message();
        let identity = ResultIdentity::from_resource_message(&msg);
        msg.content.extend(resource_message().content);
        let original = serde_json::to_value(&msg).expect("message serializes");
        let result = super::write_result_back_to_message(
            &mut msg,
            &serde_json::json!({"content": "[REDACTED]"}),
            Projection::Resource,
            &identity,
        );
        assert!(
            matches!(
                result,
                Err(EnvelopeReplaced {
                    error: EnvelopeError::Ambiguous,
                    ..
                })
            ),
            "a newly duplicated URI must make the selected resource ambiguous"
        );
        assert_eq!(
            serde_json::to_value(&msg).expect("message serializes"),
            original,
            "neither ambiguous resource may receive the other one's edit"
        );
    }

    #[test]
    fn args_round_trip_leaves_a_tool_call_unchanged() {
        let mut msg = tool_call_message();
        let args = extract_args_from_message(&msg);
        write_args_back_to_message(&mut msg, &args).expect("write-back applies");
        assert_eq!(extract_args_from_message(&msg), args);
    }

    #[test]
    fn result_round_trip_leaves_a_tool_result_unchanged() {
        let mut msg = tool_result_message();
        let result = extract_result_from_message(&msg);
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_eq!(extract_result_from_message(&msg), result);
    }

    #[test]
    fn text_message_projects_to_its_whole_text_both_ways() {
        let mut msg = Message::text(Role::User, "hello");
        assert_eq!(
            extract_args_from_message(&msg),
            serde_json::json!("hello"),
            "a text-only message has no structured args, so args are the text"
        );
        write_args_back_to_message(&mut msg, &serde_json::json!("goodbye"))
            .expect("write-back applies");
        assert_eq!(msg.get_text_content(), "goodbye");
    }

    #[test]
    fn field_writes_apply_over_an_untouched_base() {
        let pre = serde_json::json!({"city": "London", "units": "metric"});
        let post = serde_json::json!({"city": "[REDACTED]", "units": "metric"});
        let mut base = pre.clone();
        apply_test_writes(&mut base, &pre, &post, &["city"]).expect("field write applies");
        assert_eq!(base, post);
    }

    #[test]
    fn field_writes_preserve_another_editors_keys() {
        let pre = serde_json::json!({"city": "London", "token": "sk-secret"});
        let post = serde_json::json!({"city": "[REDACTED]", "token": "sk-secret"});
        let mut base = serde_json::json!({"city": "London", "token": "[SCRUBBED]"});
        apply_test_writes(&mut base, &pre, &post, &["city"]).expect("field write applies");
        assert_eq!(
            base,
            serde_json::json!({"city": "[REDACTED]", "token": "[SCRUBBED]"}),
            "both editors' work must survive"
        );
    }

    #[test]
    fn field_writes_apply_removals() {
        let pre = serde_json::json!({"city": "London", "debug": true});
        let post = serde_json::json!({"city": "London"});
        let mut base = serde_json::json!({"city": "Paris", "debug": true});
        apply_test_writes(&mut base, &pre, &post, &["debug"]).expect("field write applies");
        assert_eq!(base, serde_json::json!({"city": "Paris"}));
    }

    #[test]
    fn field_writes_omit_a_key_the_plugin_rewrote() {
        let pre = serde_json::json!({"city": "London", "ssn": "123-45-6789"});
        let post = serde_json::json!({"city": "London"});
        let mut base = serde_json::json!({"city": "London", "ssn": "[REDACTED]"});
        apply_test_writes(&mut base, &pre, &post, &["ssn"]).expect("field write applies");
        assert_eq!(
            base,
            serde_json::json!({"city": "London"}),
            "an omitted key must not survive because a plugin rewrote it"
        );
    }

    #[test]
    fn field_writes_recurse_into_nested_objects() {
        let pre = serde_json::json!({"user": {"name": "ada", "ssn": "123-45-6789"}});
        let post = serde_json::json!({"user": {"name": "ada", "ssn": "[REDACTED]"}});
        let mut base = serde_json::json!({"user": {"name": "ADA", "ssn": "123-45-6789"}});
        apply_test_writes(&mut base, &pre, &post, &["user.ssn"]).expect("field write applies");
        assert_eq!(
            base,
            serde_json::json!({"user": {"name": "ADA", "ssn": "[REDACTED]"}}),
            "a sibling edit inside the same object must not be clobbered"
        );
    }

    #[test]
    fn field_writes_let_the_pipeline_win_a_same_key_conflict() {
        let pre = serde_json::json!({"ssn": "123-45-6789"});
        let post = serde_json::json!({"ssn": "***-**-6789"});
        let mut base = serde_json::json!({"ssn": "[REDACTED]"});
        apply_test_writes(&mut base, &pre, &post, &["ssn"]).expect("field write applies");
        assert_eq!(base, serde_json::json!({"ssn": "***-**-6789"}));
    }

    #[test]
    fn field_writes_reinstate_a_key_the_plugin_removed() {
        let pre = serde_json::json!({"ssn": "123-45-6789", "name": "Ada"});
        let post = serde_json::json!({"ssn": "[REDACTED]", "name": "Ada"});
        let mut base = serde_json::json!({"name": "Ada"});
        apply_test_writes(&mut base, &pre, &post, &["ssn"]).expect("field write applies");
        assert_eq!(
            base,
            serde_json::json!({"ssn": "[REDACTED]", "name": "Ada"}),
            "the pipeline's redaction lands even though the plugin dropped the key"
        );
    }

    #[test]
    fn field_writes_replace_a_scalar_projection_whole() {
        let mut base = serde_json::json!("plugin text");
        apply_test_writes(
            &mut base,
            &serde_json::json!("original"),
            &serde_json::json!("pipeline text"),
            &[""],
        )
        .expect("whole-value write applies");
        assert_eq!(base, serde_json::json!("pipeline text"));
    }

    #[test]
    fn field_writes_refuse_a_changed_parent_shape() {
        let pre = serde_json::json!({"city": "London"});
        let post = serde_json::json!({"city": "[REDACTED]"});
        let mut base = serde_json::json!("no longer an object");
        assert!(matches!(
            apply_test_writes(&mut base, &pre, &post, &["city"]),
            Err(EnvelopeReplaced {
                error: EnvelopeError::ShapeChanged,
                ..
            })
        ));
        assert_eq!(base, serde_json::json!("no longer an object"));
    }

    #[test]
    fn a_whole_value_write_to_tool_call_args_is_refused_and_leaves_them_unchanged() {
        let mut msg = tool_call_message();
        let before = extract_args_from_message(&msg);
        assert_eq!(
            write_args_back_to_message(&mut msg, &serde_json::json!("[REDACTED]")),
            Err(EnvelopeReplaced {
                part: ReplacedPart::ToolCall,
                error: EnvelopeError::Replaced,
            }),
            "forwarding the original arguments would undo the redaction"
        );
        assert_eq!(extract_args_from_message(&msg), before);
    }

    #[test]
    fn a_prompt_request_projects_its_arguments_not_its_text() {
        let args = extract_args_from_message(&prompt_request_message());
        assert_eq!(
            args,
            serde_json::json!({ "tone": "terse", "length": 200 }),
            "prompt arguments must project as an object, not as text"
        );
    }

    #[test]
    fn a_rewritten_prompt_argument_survives_the_round_trip() {
        let mut msg = prompt_request_message();
        write_args_back_to_message(&mut msg, &serde_json::json!({ "tone": "formal" }))
            .expect("write-back applies");
        assert_eq!(
            extract_args_from_message(&msg),
            serde_json::json!({ "tone": "formal" }),
            "the rewritten arguments must be what the next read sees"
        );
    }

    #[test]
    fn a_whole_value_write_to_prompt_request_args_is_refused_and_leaves_them_unchanged() {
        let mut msg = prompt_request_message();
        let before = extract_args_from_message(&msg);
        assert_eq!(
            write_args_back_to_message(&mut msg, &serde_json::json!("[REDACTED]")),
            Err(EnvelopeReplaced {
                part: ReplacedPart::PromptRequest,
                error: EnvelopeError::Replaced,
            }),
            "forwarding the original arguments would undo the redaction"
        );
        assert_eq!(extract_args_from_message(&msg), before);
    }

    #[test]
    fn a_redacted_result_survives_the_round_trip() {
        let mut msg = tool_result_message();
        write_result_back_to_message(&mut msg, &serde_json::json!({ "temp": "[REDACTED]" }))
            .expect("write-back applies");
        assert_eq!(
            extract_result_from_message(&msg),
            serde_json::json!({ "temp": "[REDACTED]" }),
            "the redacted value must be what the response carries"
        );
    }

    #[test]
    fn a_text_only_message_projects_and_accepts_text_as_its_result() {
        let mut msg = Message::text(Role::Assistant, "salary is 100000");
        assert_eq!(
            extract_result_from_message(&msg),
            Value::String("salary is 100000".to_owned())
        );

        write_result_back_to_message(&mut msg, &serde_json::json!("salary is [REDACTED]"))
            .expect("write-back applies");
        assert_eq!(
            extract_result_from_message(&msg),
            Value::String("salary is [REDACTED]".to_owned())
        );
    }

    #[test]
    fn a_non_string_result_leaves_a_text_only_message_untouched() {
        let mut msg = Message::text(Role::Assistant, "unchanged");
        write_result_back_to_message(&mut msg, &serde_json::json!({ "salary": 1 }))
            .expect("write-back applies");
        assert_eq!(
            extract_result_from_message(&msg),
            Value::String("unchanged".to_owned())
        );
    }

    #[test]
    fn rewriting_text_on_a_message_with_no_text_part_appends_one() {
        let mut msg = Message::with_content(Role::User, vec![]);
        rewrite_message_text(&mut msg, "added");
        assert_eq!(msg.content.len(), 1, "a text part must be appended");
        assert_eq!(
            extract_result_from_message(&msg),
            Value::String("added".to_owned())
        );

        rewrite_message_text(&mut msg, "replaced");
        assert_eq!(msg.content.len(), 1, "the existing part must be reused");
        assert_eq!(
            extract_result_from_message(&msg),
            Value::String("replaced".to_owned())
        );
    }

    #[test]
    fn a_resource_ref_projects_its_fields_not_its_text() {
        assert_eq!(
            extract_args_from_message(&resource_ref_message()),
            serde_json::json!({
                "uri": "hr://employees/42",
                "name": "employee 42",
                "resource_type": "uri",
                "range_start": 10,
                "range_end": 20,
                "selector": "$.salary",
            }),
            "args must be the ResourceRef envelope, not the empty text fallback"
        );
    }

    #[test]
    fn a_resource_projects_its_envelope_not_its_text() {
        assert_eq!(
            extract_result_from_message(&resource_message()),
            serde_json::json!({
                "uri": "hr://employees/42",
                "name": "employee 42",
                "title": "Employee Record",
                "description": "HR employee record",
                "resource_type": "uri",
                "content": "SSN 123-45-6789",
                "mime_type": "text/plain",
                "size_bytes": 15,
                "version": "v3",
                "annotations": { "tier": "gold" },
                "icons": null,
            }),
            "result must be the Resource envelope, not the empty text fallback"
        );
    }

    #[test]
    fn a_prompt_result_projects_its_fields_not_its_text() {
        assert_eq!(
            extract_result_from_message(&prompt_result_message()),
            serde_json::json!({
                "prompt_name": "summarize",
                "description": "Summary prompt",
                "content": "Summarize this: SSN 123-45-6789",
                "is_error": false,
                "error_message": "partial result",
            }),
            "result must be the PromptResult envelope, not the empty text fallback"
        );
    }

    #[test]
    fn a_resource_ref_with_no_optional_fields_still_projects_every_key() {
        let msg = Message::with_content(
            Role::User,
            vec![ContentPart::ResourceRef {
                content: ResourceReference {
                    resource_request_id: "rr_002".to_owned(),
                    uri: "file:///x".to_owned(),
                    name: None,
                    resource_type: ResourceType::File,
                    range_start: None,
                    range_end: None,
                    selector: None,
                },
            }],
        );
        let args = extract_args_from_message(&msg);
        let keys: Vec<&str> = args
            .as_object()
            .expect("envelope is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys.len(),
            6,
            "unset fields must project as null, not be left out: {keys:?}"
        );
        assert_eq!(args["selector"], Value::Null, "unset selector is null");
    }

    #[test]
    fn args_round_trip_leaves_a_resource_ref_unchanged() {
        let original = resource_ref_message();
        let mut msg = original.clone();
        let args = extract_args_from_message(&msg);
        write_args_back_to_message(&mut msg, &args).expect("write-back applies");
        assert_eq!(
            serde_json::to_value(&msg).expect("serialize"),
            serde_json::to_value(&original).expect("serialize"),
            "extract then write back must leave the ResourceRef identical"
        );
    }

    #[test]
    fn result_round_trip_leaves_a_resource_unchanged() {
        let original = resource_message();
        let mut msg = original.clone();
        let result = extract_result_from_message(&msg);
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_eq!(
            serde_json::to_value(&msg).expect("serialize"),
            serde_json::to_value(&original).expect("serialize"),
            "extract then write back must leave the Resource identical"
        );
    }

    #[test]
    fn result_round_trip_leaves_a_prompt_result_unchanged() {
        let original = prompt_result_message();
        let mut msg = original.clone();
        let result = extract_result_from_message(&msg);
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_eq!(
            serde_json::to_value(&msg).expect("serialize"),
            serde_json::to_value(&original).expect("serialize"),
            "extract then write back must leave the PromptResult identical"
        );
    }

    #[test]
    fn a_rewritten_resource_ref_field_differs_in_that_field_only() {
        let original = resource_ref_message();
        let mut msg = original.clone();
        let mut args = extract_args_from_message(&msg);
        args["selector"] = serde_json::json!("$.name");
        write_args_back_to_message(&mut msg, &args).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_ref_mut(m).selector = Some("$.name".to_owned());
        });
    }

    #[test]
    fn resource_ref_uri_is_not_overwritten_on_write_back() {
        let original = resource_ref_message();
        let mut msg = original.clone();
        let mut args = extract_args_from_message(&msg);
        args["uri"] = serde_json::json!("hr://employees/restricted");
        write_args_back_to_message(&mut msg, &args).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn resource_ref_resource_type_is_not_overwritten_on_write_back() {
        let original = resource_ref_message();
        let mut msg = original.clone();
        let mut args = extract_args_from_message(&msg);
        args["resource_type"] = serde_json::json!("database");
        write_args_back_to_message(&mut msg, &args).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn resource_ref_range_u64_fidelity_above_2_53() {
        let big: u64 = 9_007_199_254_740_993;
        let original = resource_ref_message();
        let mut msg = original.clone();
        let mut args = extract_args_from_message(&msg);
        args["range_end"] = serde_json::json!(big);
        write_args_back_to_message(&mut msg, &args).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_ref_mut(m).range_end = Some(big);
        });
    }

    #[test]
    fn resource_ref_range_clears_on_a_non_u64_write() {
        for bad in [
            serde_json::json!(-5),
            serde_json::json!(1.5),
            serde_json::json!("12"),
            serde_json::json!(true),
            serde_json::json!("[REDACTED]"),
        ] {
            let original = resource_ref_message();
            let mut msg = original.clone();
            let mut args = extract_args_from_message(&msg);
            args["range_start"] = bad.clone();
            write_args_back_to_message(&mut msg, &args).expect("write-back applies");
            assert_differs_only_in(&original, &msg, |m| {
                resource_ref_mut(m).range_start = None;
            });
        }
    }

    #[test]
    fn a_redacted_resource_size_bytes_is_cleared() {
        let original = resource_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["size_bytes"] = serde_json::json!("[REDACTED]");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_mut(m).size_bytes = None;
        });
    }

    #[test]
    fn a_redacted_resource_content_differs_in_that_field_only() {
        let original = resource_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["content"] = serde_json::json!("SSN [REDACTED]");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_mut(m).content = Some("SSN [REDACTED]".to_owned());
        });
    }

    #[test]
    fn resource_uri_and_type_are_not_overwritten_on_write_back() {
        let original = resource_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["uri"] = serde_json::json!("hr://elsewhere");
        result["resource_type"] = serde_json::json!("database");
        result["icons"] = serde_json::json!([{ "src": "https://evil.example/i.png" }]);
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn a_removed_resource_field_is_cleared_on_write_back() {
        let original = resource_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result
            .as_object_mut()
            .expect("envelope is an object")
            .remove("content");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_mut(m).content = None;
        });
    }

    #[test]
    fn editing_one_annotation_keeps_the_others() {
        let mut original = resource_message();
        resource_mut(&mut original)
            .annotations
            .insert("owner".to_owned(), serde_json::json!("hr"));
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["annotations"]["tier"] = serde_json::json!("silver");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_mut(m)
                .annotations
                .insert("tier".to_owned(), serde_json::json!("silver"));
        });
    }

    #[test]
    fn null_annotations_clear_the_map() {
        let original = resource_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["annotations"] = Value::Null;
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_mut(m).annotations.clear();
        });
    }

    #[test]
    fn redacted_annotations_clear_the_map() {
        let original = resource_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["annotations"] = serde_json::json!("[REDACTED]");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            resource_mut(m).annotations.clear();
        });
    }

    #[test]
    fn a_redacted_prompt_result_content_differs_in_that_field_only() {
        let original = prompt_result_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["content"] = serde_json::json!("Summarize this: SSN [REDACTED]");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            prompt_result_mut(m).content = Some("Summarize this: SSN [REDACTED]".to_owned());
        });
    }

    #[test]
    fn prompt_name_is_not_overwritten_on_write_back() {
        let original = prompt_result_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["prompt_name"] = serde_json::json!("something_else");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn prompt_is_error_is_not_overwritten_on_write_back() {
        let original = prompt_result_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["is_error"] = serde_json::json!(true);
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn prompt_result_description_differs_in_that_field_only() {
        let original = prompt_result_message();
        let mut msg = original.clone();
        let mut result = extract_result_from_message(&msg);
        result["description"] = serde_json::json!("[REDACTED]");
        write_result_back_to_message(&mut msg, &result).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            prompt_result_mut(m).description = Some("[REDACTED]".to_owned());
        });
    }

    #[test]
    fn string_field_write_back_converts_every_value_type() {
        for (written, stored) in [
            (serde_json::json!(true), "true"),
            (serde_json::json!(42), "42"),
            (serde_json::json!({ "a": 1 }), r#"{"a":1}"#),
            (serde_json::json!([1, 2]), "[1,2]"),
        ] {
            let original = resource_message();
            let mut msg = original.clone();
            let mut result = extract_result_from_message(&msg);
            result["content"] = written;
            write_result_back_to_message(&mut msg, &result).expect("write-back applies");
            assert_differs_only_in(&original, &msg, |m| {
                resource_mut(m).content = Some(stored.to_owned());
            });
        }
    }

    #[test]
    fn prompt_request_args_round_trip() {
        let original = prompt_request_message();
        let mut msg = original.clone();
        let mut args = extract_args_from_message(&msg);
        args["tone"] = serde_json::json!("formal");
        write_args_back_to_message(&mut msg, &args).expect("write-back applies");
        assert_differs_only_in(&original, &msg, |m| {
            let ContentPart::PromptRequest { content } = &mut m.content[0] else {
                panic!("fixture must hold a PromptRequest part");
            };
            content
                .arguments
                .insert("tone".to_owned(), serde_json::json!("formal"));
        });
    }

    #[test]
    fn a_resource_size_above_2_53_projects_exactly() {
        let big: u64 = 9_007_199_254_740_993;
        let mut msg = resource_message();
        let ContentPart::Resource { content } = &mut msg.content[0] else {
            panic!("fixture must hold a Resource part");
        };
        content.size_bytes = Some(big);
        assert_eq!(
            extract_result_from_message(&msg)["size_bytes"].as_u64(),
            Some(big),
            "a u64 above 2^53 must project without float rounding"
        );
    }

    #[test]
    fn a_whole_value_write_to_a_resource_ref_is_refused_and_leaves_it_unchanged() {
        let original = resource_ref_message();
        let mut msg = original.clone();
        assert_eq!(
            write_args_back_to_message(&mut msg, &serde_json::json!("[REDACTED]")),
            Err(EnvelopeReplaced {
                part: ReplacedPart::ResourceRef,
                error: EnvelopeError::Replaced,
            }),
            "a non-object args envelope must be refused, not silently dropped"
        );
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn a_whole_value_write_to_a_resource_is_refused_and_leaves_it_unchanged() {
        let original = resource_message();
        let mut msg = original.clone();
        assert_eq!(
            write_result_back_to_message(&mut msg, &serde_json::json!("[REDACTED]")),
            Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Replaced,
            }),
            "a non-object result envelope must be refused, not silently dropped"
        );
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn a_whole_value_write_to_a_prompt_result_is_refused_and_leaves_it_unchanged() {
        let original = prompt_result_message();
        let mut msg = original.clone();
        assert_eq!(
            write_result_back_to_message(&mut msg, &serde_json::json!("[REDACTED]")),
            Err(EnvelopeReplaced {
                part: ReplacedPart::PromptResult,
                error: EnvelopeError::Replaced,
            }),
            "a non-object result envelope must be refused, not silently dropped"
        );
        assert_differs_only_in(&original, &msg, |_| {});
    }

    #[test]
    fn extract_result_field_matches_a_lookup_on_the_full_envelope() {
        fn via_envelope(msg: &Message, projection: Projection, field: &str) -> Option<Value> {
            let projected = super::extract_result_from_message(msg, projection).0;
            if projected.is_object() {
                get_dotted(&projected, field).cloned()
            } else {
                Some(projected)
            }
        }

        let mut resource = resource_message();
        if let ContentPart::Resource { content } = &mut resource.content[0] {
            content.annotations.insert(
                "reviewer".to_owned(),
                serde_json::json!({ "name": "Ada", "ids": [7, 8] }),
            );
            content
                .annotations
                .insert("audience".to_owned(), serde_json::json!("hr"));
        }
        let mut resource_paths: Vec<&str> = RESOURCE_FIELDS.to_vec();
        resource_paths.extend([
            "annotations.audience",
            "annotations.reviewer",
            "annotations.reviewer.name",
            "annotations.reviewer.ids.1",
            "annotations.missing",
            "annotations.audience.deeper",
            "content.inner",
            "no_such_field",
        ]);
        let mut prompt_paths: Vec<&str> = PROMPT_RESULT_FIELDS.to_vec();
        prompt_paths.extend(["content.inner", "no_such_field"]);

        let mut scalar_tool = tool_result_message();
        if let ContentPart::ToolResult { content } = &mut scalar_tool.content[0] {
            content.content = serde_json::json!("plain text result");
        }
        let cases: Vec<(Message, Projection, Vec<&str>)> = vec![
            (resource, Projection::Resource, resource_paths),
            (prompt_result_message(), Projection::Prompt, prompt_paths),
            (
                tool_result_message(),
                Projection::Tool,
                vec!["temp", "missing", "temp.x"],
            ),
            (scalar_tool, Projection::Tool, vec!["anything"]),
            (
                Message::text(Role::User, "just text"),
                Projection::Resource,
                vec!["content"],
            ),
        ];
        for (msg, projection, paths) in &cases {
            for path in paths {
                assert_eq!(
                    super::extract_result_field(msg, *projection, path),
                    via_envelope(msg, *projection, path),
                    "{projection:?} `{path}` must read the same as a lookup on the full envelope"
                );
            }
        }
    }

    #[test]
    fn a_write_to_a_removed_resource_is_refused_as_removed() {
        let mut msg = resource_message();
        let (result, identity) = super::extract_result_from_message(&msg, Projection::Resource);
        msg.content
            .retain(|part| !matches!(part, ContentPart::Resource { .. }));
        assert_eq!(
            super::write_result_back_to_message(&mut msg, &result, Projection::Resource, &identity),
            Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Removed,
            }),
            "a projected resource that is gone must be refused as removed, not as replaced"
        );
    }

    #[test]
    fn static_field_sets_match_the_projected_keys() {
        let resource_ref = ResourceReference {
            resource_request_id: String::new(),
            uri: String::new(),
            name: None,
            resource_type: ResourceType::File,
            range_start: None,
            range_end: None,
            selector: None,
        };
        let prompt = PromptResult {
            prompt_request_id: String::new(),
            prompt_name: String::new(),
            description: None,
            messages: vec![],
            content: None,
            is_error: false,
            error_message: None,
        };
        for (kind, projected, fields, read_only) in [
            (
                "ResourceRef",
                project_resource_ref_args(&resource_ref),
                RESOURCE_REF_FIELDS,
                RESOURCE_REF_READ_ONLY,
            ),
            (
                "Resource",
                project_resource_result(&Resource::default()),
                RESOURCE_FIELDS,
                RESOURCE_READ_ONLY,
            ),
            (
                "PromptResult",
                project_prompt_result(&prompt),
                PROMPT_RESULT_FIELDS,
                PROMPT_RESULT_READ_ONLY,
            ),
        ] {
            let mut keys: Vec<&str> = projected
                .as_object()
                .expect("envelope is an object")
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            let mut declared = fields.to_vec();
            declared.sort_unstable();
            assert_eq!(
                keys, declared,
                "{kind}: the field set config validation uses must equal the projected keys"
            );
            assert!(
                read_only.iter().all(|f| fields.contains(f)),
                "{kind}: every read-only field must be an envelope field"
            );
        }
        assert!(
            OPEN_MAP_FIELDS.iter().all(|f| RESOURCE_FIELDS.contains(f)),
            "every open-map field must be an envelope field"
        );
    }

    #[test]
    fn projection_follows_the_route_entity_type() {
        assert_eq!(Projection::for_entity("resource"), Projection::Resource);
        assert_eq!(Projection::for_entity("prompt"), Projection::Prompt);
        assert_eq!(Projection::for_entity("tool"), Projection::Tool);
        assert_eq!(Projection::for_entity("llm"), Projection::Tool);
    }

    #[test]
    fn a_tool_route_reads_the_tool_result_past_an_embedded_resource() {
        let msg = resource_then_tool_result();
        let (value, _) = super::extract_result_from_message(&msg, Projection::Tool);
        assert_eq!(value, serde_json::json!({"temp": 12, "sky": "grey"}));
    }

    #[test]
    fn a_tool_route_writes_the_tool_result_and_leaves_the_embedded_resource() {
        let original = resource_then_tool_result();
        let mut msg = original.clone();
        let (mut result, identity) = super::extract_result_from_message(&msg, Projection::Tool);
        result["temp"] = serde_json::json!("[REDACTED]");
        super::write_result_back_to_message(&mut msg, &result, Projection::Tool, &identity)
            .expect("write-back applies");
        let as_json = |part: &ContentPart| serde_json::to_value(part).expect("part serializes");
        assert_eq!(
            as_json(&msg.content[0]),
            as_json(&original.content[0]),
            "the resource is untouched"
        );
        let ContentPart::ToolResult { content } = &msg.content[1] else {
            panic!("second part is the tool result");
        };
        assert_eq!(content.content["temp"], serde_json::json!("[REDACTED]"));
    }

    #[test]
    fn a_resource_route_reads_the_resource_past_a_tool_result() {
        let mut msg = tool_result_message();
        msg.content.extend(resource_message().content);
        let (result, identity) = extract_result_with_identity(&msg);
        assert_eq!(result["uri"], serde_json::json!("hr://employees/42"));
        assert_eq!(
            identity
                .resource(&msg)
                .expect("unique resource")
                .map(|resource| resource.uri.as_str()),
            Some("hr://employees/42"),
            "identity captures the projected resource's uri"
        );
    }

    #[test]
    fn a_tool_route_reads_the_tool_call_past_a_resource_ref() {
        let mut msg = resource_ref_message();
        msg.content.extend(tool_call_message().content);
        let args = super::extract_args_from_message(&msg, Projection::Tool);
        assert_eq!(args["city"], serde_json::json!("London"));
    }

    #[test]
    fn a_tool_route_reads_text_from_a_message_with_only_a_resource() {
        let msg = resource_message();
        assert!(
            super::extract_result_from_message(&msg, Projection::Tool)
                .0
                .is_string(),
            "a tool route must not project a resource envelope"
        );
    }

    #[test]
    fn field_writes_preserve_plugin_edits_to_array_siblings() {
        let pre = json!({"rows": [{"ssn": "[REDACTED]"}, {"note": "secret"}]});
        let mut base = json!({"rows": [{"ssn": "[REDACTED]"}, {"note": "[REDACTED]"}]});
        apply_test_writes(&mut base, &pre, &pre, &["rows.0.ssn"]).expect("stable array");
        assert_eq!(
            base["rows"][1]["note"],
            json!("[REDACTED]"),
            "leaf replay must retain another element's plugin edit"
        );
    }

    #[test]
    fn field_writes_refuse_array_length_changes() {
        let pre = json!({"rows": [{"id": 1, "ssn": "first"}, {"id": 2, "ssn": "second"}]});
        let post = json!({"rows": [{"id": 1, "ssn": "[REDACTED]"}, {"id": 2, "ssn": "second"}]});
        for mut base in [
            json!({"rows": [{"id": 2, "ssn": "second"}]}),
            json!({"rows": [{"id": 1, "ssn": "first"}, {"id": 2, "ssn": "second"}, {"id": 3, "ssn": "third"}]}),
        ] {
            let before = base.clone();
            assert!(
                matches!(
                    apply_test_writes(&mut base, &pre, &post, &["rows.0.ssn"]),
                    Err(EnvelopeReplaced {
                        error: EnvelopeError::ShapeChanged,
                        ..
                    })
                ),
                "an unmappable leaf must deny"
            );
            assert_eq!(
                base, before,
                "an error must not resurrect an element or change its siblings"
            );
        }
    }

    #[test]
    fn an_explicit_array_write_replaces_the_array() {
        let pre = json!({"rows": [1, 2]});
        let post = json!({"rows": []});
        let mut base = json!({"rows": [2]});
        apply_test_writes(&mut base, &pre, &post, &["rows"])
            .expect("the policy addressed the whole array");
        assert_eq!(base, post);
    }

    #[test]
    fn redaction_can_make_array_elements_equal() {
        let pre = json!({"rows": [{"ssn": "raw"}, {"ssn": "[REDACTED]"}]});
        let mut base = json!({"rows": [{"ssn": "[REDACTED]"}, {"ssn": "[REDACTED]"}]});
        let post = base.clone();
        apply_test_writes(&mut base, &pre, &post, &["rows.0.ssn"])
            .expect("the element positions did not change");
        assert_eq!(base, post);
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn projection_for(msg: &Message) -> Projection {
        let has = |pred: fn(&ContentPart) -> bool| msg.content.iter().any(pred);
        if has(|p| {
            matches!(
                p,
                ContentPart::ResourceRef { .. } | ContentPart::Resource { .. }
            )
        }) {
            Projection::Resource
        } else if has(|p| matches!(p, ContentPart::PromptResult { .. })) {
            Projection::Prompt
        } else {
            Projection::Tool
        }
    }

    fn extract_args_from_message(msg: &Message) -> Value {
        super::extract_args_from_message(msg, projection_for(msg))
    }

    fn extract_result_from_message(msg: &Message) -> Value {
        super::extract_result_from_message(msg, projection_for(msg)).0
    }

    fn extract_result_with_identity(msg: &Message) -> (Value, super::ResultIdentity) {
        super::extract_result_from_message(msg, projection_for(msg))
    }

    fn write_args_back_to_message(msg: &mut Message, args: &Value) -> Result<(), EnvelopeReplaced> {
        let projection = projection_for(msg);
        super::write_args_back_to_message(msg, args, projection)
    }

    fn write_result_back_to_message(
        msg: &mut Message,
        result: &Value,
    ) -> Result<(), EnvelopeReplaced> {
        let projection = projection_for(msg);
        let identity = super::extract_result_from_message(msg, projection).1;
        super::write_result_back_to_message(msg, result, projection, &identity)
    }

    fn tool_call_message() -> Message {
        Message::with_content(
            Role::User,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "tc_001".to_owned(),
                    name: "get_weather".to_owned(),
                    arguments: [
                        ("city".to_owned(), serde_json::json!("London")),
                        ("units".to_owned(), serde_json::json!("metric")),
                    ]
                    .into_iter()
                    .collect(),
                    namespace: None,
                },
            }],
        )
    }

    fn tool_result_message() -> Message {
        Message::with_content(
            Role::Tool,
            vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "tc_001".to_owned(),
                    tool_name: "get_weather".to_owned(),
                    content: serde_json::json!({"temp": 12, "sky": "grey"}),
                    is_error: false,
                },
            }],
        )
    }

    fn prompt_request_message() -> Message {
        Message::with_content(
            Role::User,
            vec![ContentPart::PromptRequest {
                content: praxis_policy_core::cmf::content::PromptRequest {
                    prompt_request_id: "pr_1".into(),
                    name: "summarize".into(),
                    arguments: [
                        ("tone".to_owned(), serde_json::json!("terse")),
                        ("length".to_owned(), serde_json::json!(200)),
                    ]
                    .into(),
                    server_id: None,
                },
            }],
        )
    }

    fn resource_ref_message() -> Message {
        Message::with_content(
            Role::User,
            vec![ContentPart::ResourceRef {
                content: ResourceReference {
                    resource_request_id: "rr_001".to_owned(),
                    uri: "hr://employees/42".to_owned(),
                    name: Some("employee 42".to_owned()),
                    resource_type: ResourceType::Uri,
                    range_start: Some(10),
                    range_end: Some(20),
                    selector: Some("$.salary".to_owned()),
                },
            }],
        )
    }

    fn resource_message() -> Message {
        Message::with_content(
            Role::Tool,
            vec![ContentPart::Resource {
                content: Resource {
                    resource_request_id: "rr_001".to_owned(),
                    uri: "hr://employees/42".to_owned(),
                    name: Some("employee 42".to_owned()),
                    title: Some("Employee Record".to_owned()),
                    description: Some("HR employee record".to_owned()),
                    content: Some("SSN 123-45-6789".to_owned()),
                    mime_type: Some("text/plain".to_owned()),
                    size_bytes: Some(15),
                    version: Some("v3".to_owned()),
                    resource_type: ResourceType::Uri,
                    annotations: [("tier".to_owned(), serde_json::json!("gold"))]
                        .into_iter()
                        .collect(),
                    ..Resource::default()
                },
            }],
        )
    }

    fn prompt_result_message() -> Message {
        Message::with_content(
            Role::Assistant,
            vec![ContentPart::PromptResult {
                content: PromptResult {
                    prompt_request_id: "pr_001".to_owned(),
                    prompt_name: "summarize".to_owned(),
                    description: Some("Summary prompt".to_owned()),
                    messages: vec![],
                    content: Some("Summarize this: SSN 123-45-6789".to_owned()),
                    is_error: false,
                    error_message: Some("partial result".to_owned()),
                },
            }],
        )
    }

    fn assert_differs_only_in(
        original: &Message,
        written_back: &Message,
        edit: impl FnOnce(&mut Message),
    ) {
        let mut expected = original.clone();
        edit(&mut expected);
        assert_eq!(
            serde_json::to_value(written_back).expect("serialize"),
            serde_json::to_value(&expected).expect("serialize"),
            "the message must differ from the original in the edited field and nowhere else"
        );
        assert_eq!(
            written_back.content.len(),
            original.content.len(),
            "write-back must not add or remove content parts"
        );
        let is_text = |p: &ContentPart| matches!(p, ContentPart::Text { .. });
        assert!(
            original.content.iter().any(is_text) || !written_back.content.iter().any(is_text),
            "write-back must not introduce a Text part"
        );
    }

    fn resource_ref_mut(msg: &mut Message) -> &mut ResourceReference {
        let Some(ContentPart::ResourceRef { content }) = msg.content.first_mut() else {
            panic!("fixture must hold a ResourceRef part");
        };
        content
    }

    fn resource_mut(msg: &mut Message) -> &mut Resource {
        let Some(ContentPart::Resource { content }) = msg.content.first_mut() else {
            panic!("fixture must hold a Resource part");
        };
        content
    }

    fn prompt_result_mut(msg: &mut Message) -> &mut PromptResult {
        let Some(ContentPart::PromptResult { content }) = msg.content.first_mut() else {
            panic!("fixture must hold a PromptResult part");
        };
        content
    }

    fn resource_then_tool_result() -> Message {
        let mut msg = resource_message();
        msg.content.extend(tool_result_message().content);
        msg
    }

    fn apply_test_writes(
        base: &mut Value,
        pre: &Value,
        post: &Value,
        paths: &[&str],
    ) -> Result<(), EnvelopeReplaced> {
        let writes: Vec<_> = paths
            .iter()
            .map(|path| {
                let path = if path.is_empty() {
                    Vec::new()
                } else {
                    path.split('.').map(str::to_owned).collect()
                };
                let value = value_at(post, &path).cloned();
                let parents = field_parents(pre, &path).unwrap_or_default();
                FieldWrite {
                    parents,
                    path,
                    value,
                }
            })
            .collect();
        apply_written_paths(base, &writes, Projection::Tool, false)
    }
}
