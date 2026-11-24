// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Policy edits must return to the same typed content part that was inspected.
// Resource and prompt projections use fixed object envelopes; tool results
// retain their JSON shape, and text-only messages retain the string fallback.
// These projections omit other parts, so payload mutation tracking must use
// the executor's mutation signal instead of comparing projected values.

use std::collections::HashMap;

use serde_json::{Value, json};

use praxis_policy_core::cmf::{ContentPart, Message, PromptResult, Resource, ResourceReference};

use praxis_policy_apl_core::get_dotted;

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
    let mut fallback: Option<&HashMap<String, Value>> = None;
    for part in &msg.content {
        let (arguments, preferred) = match part {
            ContentPart::ToolCall { content } => (&content.arguments, TOOL_FIRST),
            ContentPart::PromptRequest { content } => (&content.arguments, !TOOL_FIRST),
            _ => continue,
        };
        if preferred {
            return Some(clone_arguments(arguments));
        }
        fallback = fallback.or(Some(arguments));
    }
    fallback.map(clone_arguments)
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
    /// Several resource parts share the selected URI.
    Ambiguous,
}

impl EnvelopeReplaced {
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
            EnvelopeError::Ambiguous => format!(
                "the `{block}:` pipeline cannot identify a unique `{part}` because several \
                 parts share its URI; emit one resource per message or use unique URIs"
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

/// The selected resource URI and whether its original message was ambiguous.
///
/// The selected URI must remain unique before and after plugin execution.
#[derive(Clone, Debug, Default)]
pub(crate) struct ResultIdentity {
    ambiguous: bool,
    pub(crate) resource_uri: Option<String>,
}

impl ResultIdentity {
    /// Identify the first resource and record whether its URI is unique.
    pub(crate) fn from_resource_message(msg: &Message) -> Self {
        let Some(resource) = msg.content.iter().find_map(|part| match part {
            ContentPart::Resource { content } => Some(content),
            _ => None,
        }) else {
            return Self::default();
        };
        let ambiguous = msg
            .content
            .iter()
            .filter(|part| matches!(part, ContentPart::Resource { content } if content.uri == resource.uri))
            .take(2)
            .count() > 1;
        Self {
            ambiguous,
            resource_uri: Some(resource.uri.clone()),
        }
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
        let Some(index) = self.resource_index(msg)? else {
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

    fn resource_index(&self, msg: &Message) -> Result<Option<usize>, EnvelopeReplaced> {
        let Some(uri) = &self.resource_uri else {
            return Ok(None);
        };
        if self.ambiguous {
            return Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Ambiguous,
            });
        }
        let mut matches = msg.content.iter().enumerate().filter_map(|(index, part)| {
            matches!(part, ContentPart::Resource { content } if content.uri == *uri)
                .then_some(index)
        });
        let Some(index) = matches.next() else {
            return Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Removed,
            });
        };
        if matches.next().is_some() {
            return Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Ambiguous,
            });
        }
        Ok(Some(index))
    }
}

/// Return the result addressed by `projection` and its resource identity.
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
                return (project_prompt_result(content), ResultIdentity::default());
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
    for part in &msg.content {
        match (projection, part) {
            (Projection::Tool, ContentPart::ToolResult { content }) => {
                return if content.content.is_object() {
                    get_dotted(&content.content, field).cloned()
                } else {
                    Some(content.content.clone())
                };
            },
            (Projection::Resource, ContentPart::Resource { content }) => {
                return resource_field_value(content, field);
            },
            (Projection::Prompt, ContentPart::PromptResult { content }) => {
                return (!field.contains('.'))
                    .then(|| prompt_result_field(content, field))
                    .flatten();
            },
            _ => {},
        }
    }
    Some(Value::String(msg.get_text_content()))
}

/// Return a resource field or a dotted annotation descendant.
pub(crate) fn resource_field_value(resource: &Resource, field: &str) -> Option<Value> {
    let (head, rest) = match field.split_once('.') {
        Some((head, rest)) => (head, Some(rest)),
        None => (field, None),
    };
    if head == "annotations"
        && let Some(rest) = rest
    {
        let (key, inner) = match rest.split_once('.') {
            Some((key, inner)) => (key, Some(inner)),
            None => (rest, None),
        };
        let value = resource.annotations.get(key)?;
        return match inner {
            Some(inner) => get_dotted(value, inner).cloned(),
            None => Some(value.clone()),
        };
    }
    rest.is_none()
        .then(|| resource_field(resource, head))
        .flatten()
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
fn prompt_result_field(prompt: &PromptResult, name: &str) -> Option<Value> {
    Some(match name {
        "prompt_name" => json!(prompt.prompt_name),
        "description" => json!(prompt.description),
        "content" => json!(prompt.content),
        "is_error" => json!(prompt.is_error),
        "error_message" => json!(prompt.error_message),
        _ => return None,
    })
}

/// Return the originally selected resource result.
///
/// Other projections use the result selected by `projection`.
///
/// # Errors
///
/// Refuses a removed or ambiguous resource target.
pub(crate) fn extract_result_by_identity(
    msg: &Message,
    projection: Projection,
    identity: &ResultIdentity,
) -> Result<Value, EnvelopeReplaced> {
    if let Some(resource) = identity.resource(msg)? {
        return Ok(project_resource_result(resource));
    }
    Ok(extract_result_from_message(msg, projection).0)
}

/// Apply a result edit to the selected content part.
///
/// Resource edits require the originally selected URI to remain unique.
/// Tool and prompt projections address their first matching result part.
///
/// # Errors
///
/// Refuses a non-object fixed envelope or a removed or ambiguous resource target.
pub(crate) fn write_result_back_to_message(
    msg: &mut Message,
    result: &Value,
    projection: Projection,
    identity: &ResultIdentity,
) -> Result<(), EnvelopeReplaced> {
    if let Some(index) = identity.resource_index(msg)? {
        return match msg.content.get_mut(index) {
            Some(ContentPart::Resource { content }) => write_resource(content, result),
            _ => Err(EnvelopeReplaced {
                part: ReplacedPart::Resource,
                error: EnvelopeError::Removed,
            }),
        };
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

/// Apply the differences between `pre` and `post` to `base`.
///
/// Unchanged paths retain independent edits already present in `base`.
/// Objects merge by key; arrays and scalars are replaced as whole values.
/// Keys removed from `post` are removed from `base`.
pub(crate) fn apply_changed_paths(base: &mut Value, pre: &Value, post: &Value) {
    let (Some(pre_map), Some(post_map)) = (pre.as_object(), post.as_object()) else {
        if pre != post {
            *base = post.clone();
        }
        return;
    };
    let Some(base_map) = base.as_object_mut() else {
        // A scalar replacement has no safe per-key reconciliation.
        tracing::warn!(
            "payload projection changed shape under a field pipeline; \
             applying the pipeline's view and discarding the other edit"
        );
        *base = post.clone();
        return;
    };

    for (key, pre_value) in pre_map {
        if !post_map.contains_key(key) {
            if base_map
                .get(key)
                .is_some_and(|base_value| base_value != pre_value)
            {
                tracing::warn!(
                    field = %key,
                    "pipeline omitted this field, discarding a plugin's edit to it"
                );
            }
            base_map.remove(key);
        }
    }

    for (key, post_value) in post_map {
        match pre_map.get(key) {
            Some(pre_value) if pre_value == post_value => {},
            Some(pre_value) => {
                let nested = base_map
                    .get_mut(key)
                    .filter(|base_value| base_value.is_object())
                    .filter(|_| pre_value.is_object() && post_value.is_object());
                if let Some(base_value) = nested {
                    apply_changed_paths(base_value, pre_value, post_value);
                } else {
                    warn_on_conflict(base_map.get(key), pre_value, key);
                    base_map.insert(key.clone(), post_value.clone());
                }
            },
            None => {
                if base_map.contains_key(key) {
                    tracing::warn!(
                        field = %key,
                        "pipeline and plugin both added this field; keeping the pipeline's value"
                    );
                }
                base_map.insert(key.clone(), post_value.clone());
            },
        }
    }
}

/// Log the two ways a pipeline edit can override a plugin's work on the
/// same key: the plugin changed it too, or the plugin removed it. Silent
/// in the common case where the plugin left the key alone.
fn warn_on_conflict(base_value: Option<&Value>, pre_value: &Value, key: &str) {
    match base_value {
        Some(base_value) if base_value != pre_value => tracing::warn!(
            field = %key,
            "pipeline edit overrides a plugin's edit to the same field; \
             keeping the pipeline's value"
        ),
        Some(_) => {},
        None => tracing::warn!(
            field = %key,
            "pipeline edit reinstates a field the plugin removed"
        ),
    }
}

// -----------------------------------------------------------------------------
// Write-back Value Conversion
// -----------------------------------------------------------------------------

/// A missing field was removed by the pipeline, so it clears like `null` does:
/// keeping the old value would leak what an `omit` meant to drop. Every other
/// value type is stored as its JSON text rather than dropped, because a
/// redaction that produced an unexpected type must still replace the original.
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

/// `apply_changed_paths` has already merged the pipeline's per-key changes into
/// the map, so the merged object replaces it whole. A non-object value clears
/// the map: it is usually a redaction of the whole field, and keeping the old
/// map would forward what the redaction meant to hide.
fn write_annotations(target: &mut HashMap<String, Value>, value: Option<&Value>) {
    match value {
        None | Some(Value::Null) => target.clear(),
        Some(Value::Object(map)) => {
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
    fn changed_paths_apply_over_an_untouched_base() {
        let pre = serde_json::json!({"city": "London", "units": "metric"});
        let post = serde_json::json!({"city": "[REDACTED]", "units": "metric"});
        let mut base = pre.clone();
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, post);
    }

    #[test]
    fn changed_paths_preserve_another_editors_keys() {
        let pre = serde_json::json!({"city": "London", "token": "sk-secret"});
        let post = serde_json::json!({"city": "[REDACTED]", "token": "sk-secret"});
        let mut base = serde_json::json!({"city": "London", "token": "[SCRUBBED]"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"city": "[REDACTED]", "token": "[SCRUBBED]"}),
            "both editors' work must survive"
        );
    }

    #[test]
    fn changed_paths_apply_removals() {
        let pre = serde_json::json!({"city": "London", "debug": true});
        let post = serde_json::json!({"city": "London"});
        let mut base = serde_json::json!({"city": "Paris", "debug": true});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, serde_json::json!({"city": "Paris"}));
    }

    #[test]
    fn changed_paths_omit_a_key_the_plugin_rewrote() {
        let pre = serde_json::json!({"city": "London", "ssn": "123-45-6789"});
        let post = serde_json::json!({"city": "London"});
        let mut base = serde_json::json!({"city": "London", "ssn": "[REDACTED]"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"city": "London"}),
            "an omitted key must not survive because a plugin rewrote it"
        );
    }

    #[test]
    fn changed_paths_recurse_into_nested_objects() {
        let pre = serde_json::json!({"user": {"name": "ada", "ssn": "123-45-6789"}});
        let post = serde_json::json!({"user": {"name": "ada", "ssn": "[REDACTED]"}});
        let mut base = serde_json::json!({"user": {"name": "ADA", "ssn": "123-45-6789"}});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"user": {"name": "ADA", "ssn": "[REDACTED]"}}),
            "a sibling edit inside the same object must not be clobbered"
        );
    }

    #[test]
    fn changed_paths_let_the_pipeline_win_a_same_key_conflict() {
        let pre = serde_json::json!({"ssn": "123-45-6789"});
        let post = serde_json::json!({"ssn": "***-**-6789"});
        let mut base = serde_json::json!({"ssn": "[REDACTED]"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, serde_json::json!({"ssn": "***-**-6789"}));
    }

    #[test]
    fn changed_paths_reinstate_a_key_the_plugin_removed() {
        let pre = serde_json::json!({"ssn": "123-45-6789", "name": "Ada"});
        let post = serde_json::json!({"ssn": "[REDACTED]", "name": "Ada"});
        let mut base = serde_json::json!({"name": "Ada"});
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(
            base,
            serde_json::json!({"ssn": "[REDACTED]", "name": "Ada"}),
            "the pipeline's redaction lands even though the plugin dropped the key"
        );
    }

    #[test]
    fn changed_paths_replace_a_scalar_projection_whole() {
        let mut base = serde_json::json!("plugin text");
        apply_changed_paths(
            &mut base,
            &serde_json::json!("original"),
            &serde_json::json!("pipeline text"),
        );
        assert_eq!(base, serde_json::json!("pipeline text"));
    }

    #[test]
    fn changed_paths_take_the_pipeline_view_when_base_shape_differs() {
        let pre = serde_json::json!({"city": "London"});
        let post = serde_json::json!({"city": "[REDACTED]"});
        let mut base = serde_json::json!("no longer an object");
        apply_changed_paths(&mut base, &pre, &post);
        assert_eq!(base, post);
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
            identity.resource_uri.as_deref(),
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
}
