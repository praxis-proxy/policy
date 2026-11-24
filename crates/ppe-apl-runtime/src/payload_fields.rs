// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Dispatch phases belong to APL, so payload field projection stays in the
// runtime instead of adding an APL dependency to the leaf core crate.

use praxis_policy_core::cmf::MessagePayload;
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::http_hook::HttpPayload;

use praxis_policy_apl_core::step::{DispatchPhase, FieldLocation, FieldParent};

use crate::message_projection::{EnvelopeReplaced, Projection, ResultIdentity};

/// Reads one pipeline field off a hook payload.
///
/// # Examples
///
/// Hosts can keep their existing two-argument field method:
///
/// ```
/// use praxis_policy_apl_core::step::DispatchPhase;
/// use praxis_policy_apl_runtime::{PayloadFields, Projection};
///
/// #[derive(Clone)]
/// struct HostPayload;
/// praxis_policy_core::impl_plugin_payload!(HostPayload);
///
/// impl PayloadFields for HostPayload {
///     fn field_value(&self, field: &str, _phase: DispatchPhase) -> Option<serde_json::Value> {
///         Some(serde_json::json!(field))
///     }
/// }
///
/// assert_eq!(
///     HostPayload.field_value_with_projection("body", DispatchPhase::Post, Projection::Resource),
///     Some(serde_json::json!("body")),
/// );
/// ```
pub trait PayloadFields: PluginPayload + Clone {
    /// The value this payload holds for `field` in `phase`, or `None` when
    /// the payload has no such field.
    ///
    /// `field` is relative to the args or result root, never prefixed with
    /// `args.` / `result.`. Pre addresses args, Post addresses result.
    fn field_value(&self, _field: &str, _phase: DispatchPhase) -> Option<serde_json::Value> {
        None
    }

    /// Read a field using the route's content-part projection.
    ///
    /// The default delegates to [`Self::field_value`] so existing host
    /// implementations keep their field behavior without a signature change.
    ///
    /// [`Self::field_value`]: Self::field_value
    fn field_value_with_projection(
        &self,
        field: &str,
        phase: DispatchPhase,
        _projection: Projection,
    ) -> Option<serde_json::Value> {
        self.field_value(field, phase)
    }

    /// Read an expanded field path while retaining `field` for legacy hosts.
    /// The default delegates using the configured field name.
    fn field_value_at(
        &self,
        field: &str,
        phase: DispatchPhase,
        projection: Projection,
        _path: &[String],
    ) -> Option<serde_json::Value> {
        self.field_value_with_projection(field, phase, projection)
    }
}

impl PayloadFields for MessagePayload {
    fn field_value(&self, field: &str, phase: DispatchPhase) -> Option<serde_json::Value> {
        self.field_value_with_projection(field, phase, Projection::Tool)
    }

    fn field_value_with_projection(
        &self,
        field: &str,
        phase: DispatchPhase,
        projection: Projection,
    ) -> Option<serde_json::Value> {
        field_value_from_message(&self.message, field, phase, projection)
    }

    fn field_value_at(
        &self,
        _field: &str,
        phase: DispatchPhase,
        projection: Projection,
        path: &[String],
    ) -> Option<serde_json::Value> {
        match phase {
            DispatchPhase::Pre => {
                if projection != Projection::Resource {
                    return match crate::message_projection::arguments_for_projection(
                        &self.message,
                        projection,
                    ) {
                        Some(arguments) => argument_field(arguments, path),
                        None => Some(serde_json::Value::String(self.message.get_text_content())),
                    };
                }
                let args =
                    crate::message_projection::extract_args_from_message(&self.message, projection);
                if args.is_object() || args.is_array() {
                    crate::message_projection::value_at(&args, path).cloned()
                } else {
                    Some(args)
                }
            },
            DispatchPhase::Post => {
                crate::message_projection::extract_result_field_at(&self.message, projection, path)
            },
        }
    }
}

/// HTTP exchanges expose attributes through extensions rather than payload fields.
impl PayloadFields for HttpPayload {}

/// Identify the reference, resource and prompt selected before plugins run.
pub(crate) fn payload_identities<P: PayloadFields>(payload: &P) -> [ResultIdentity; 5] {
    payload
        .as_any()
        .downcast_ref::<MessagePayload>()
        .map_or_else(
            || std::array::from_fn(|_| ResultIdentity::default()),
            |message| {
                [
                    ResultIdentity::from_reference_message(&message.message),
                    ResultIdentity::from_resource_message(&message.message),
                    ResultIdentity::from_prompt_message(&message.message),
                    ResultIdentity::from_prompt_request_message(&message.message),
                    ResultIdentity::default(),
                ]
            },
        )
}

/// Return the field associated with the route's selected part and expanded path.
///
/// Other projections use the payload's projection-aware field contract.
///
/// # Errors
///
/// Refuses a removed or ambiguous structured target.
pub(crate) fn field_value_for_identity<P: PayloadFields>(
    payload: &P,
    field: &str,
    phase: DispatchPhase,
    projection: Projection,
    identity: &ResultIdentity,
    location: Option<FieldLocation<'_>>,
) -> Result<Option<serde_json::Value>, EnvelopeReplaced> {
    let path = location.map(|location| location.path);
    if let Some(message) = payload.as_any().downcast_ref::<MessagePayload>() {
        let segments;
        let path = if let Some(path) = path {
            path
        } else {
            segments = field.split('.').map(str::to_owned).collect::<Vec<_>>();
            &segments
        };
        if let Some(location) = location {
            let parents =
                message_field_parents(&message.message, phase, projection, identity, path)?;
            if parents.as_slice() != location.parents {
                return Err(EnvelopeReplaced::shape_changed(
                    projection,
                    phase == DispatchPhase::Pre,
                ));
            }
        }
        if phase == DispatchPhase::Pre && projection == Projection::Prompt {
            return Ok(match identity.part(&message.message)? {
                Some(praxis_policy_core::cmf::ContentPart::PromptRequest { content }) => {
                    argument_field(&content.arguments, path)
                },
                Some(praxis_policy_core::cmf::ContentPart::ToolCall { content }) => {
                    argument_field(&content.arguments, path)
                },
                _ => Some(serde_json::Value::String(
                    message.message.get_text_content(),
                )),
            });
        }
        if phase == DispatchPhase::Post && projection == Projection::Resource {
            return Ok(match identity.resource(&message.message)? {
                Some(resource) => {
                    crate::message_projection::resource_field_value_at(resource, path)
                },
                None => Some(serde_json::Value::String(
                    message.message.get_text_content(),
                )),
            });
        }
        if phase == DispatchPhase::Post && projection == Projection::Prompt {
            return Ok(match identity.part(&message.message)? {
                Some(praxis_policy_core::cmf::ContentPart::PromptResult { content }) => {
                    path.first().filter(|_| path.len() == 1).and_then(|field| {
                        crate::message_projection::prompt_result_field(content, field)
                    })
                },
                _ => Some(serde_json::Value::String(
                    message.message.get_text_content(),
                )),
            });
        }
        let projected = match (phase, projection) {
            (DispatchPhase::Pre, Projection::Resource) => {
                Some(crate::message_projection::extract_args_by_identity(
                    &message.message,
                    projection,
                    identity,
                )?)
            },
            _ => None,
        };
        if let Some(projected) = projected {
            return Ok(if projected.is_object() {
                crate::message_projection::value_at(&projected, path).cloned()
            } else {
                Some(projected)
            });
        }
    }
    Ok(if let Some(path) = path {
        payload.field_value_at(field, phase, projection, path)
    } else {
        payload.field_value_with_projection(field, phase, projection)
    })
}

fn message_field_parents(
    message: &praxis_policy_core::cmf::Message,
    phase: DispatchPhase,
    projection: Projection,
    identity: &ResultIdentity,
    path: &[String],
) -> Result<Vec<FieldParent>, EnvelopeReplaced> {
    use crate::message_projection::arguments_for_projection;
    use praxis_policy_apl_core::route::field_parents;
    use praxis_policy_core::cmf::ContentPart;

    fn map_parents(
        map: &std::collections::HashMap<String, serde_json::Value>,
        path: &[String],
    ) -> Option<Vec<FieldParent>> {
        if path.is_empty() {
            return Some(Vec::new());
        }
        let mut parents = vec![FieldParent::Object];
        if let Some((key, rest)) = path.split_first()
            && !rest.is_empty()
        {
            parents.extend(field_parents(map.get(key)?, rest)?);
        }
        Some(parents)
    }
    fn fixed_parents(path: &[String]) -> Option<Vec<FieldParent>> {
        match path.len() {
            0 => Some(Vec::new()),
            1 => Some(vec![FieldParent::Object]),
            _ => None,
        }
    }
    fn resource_parents(
        resource: &praxis_policy_core::cmf::Resource,
        path: &[String],
    ) -> Option<Vec<FieldParent>> {
        if path.len() <= 1 {
            return fixed_parents(path);
        }
        let (field, rest) = path.split_first()?;
        let mut parents = vec![FieldParent::Object];
        if field == "annotations" {
            parents.extend(map_parents(&resource.annotations, rest)?);
            return Some(parents);
        }
        if field != "icons" {
            return None;
        }
        let icons = resource.icons.as_ref()?;
        parents.push(FieldParent::Array { len: icons.len() });
        let (index, fields) = rest.split_first()?;
        if !fields.is_empty() {
            let icon = icons.get(index.parse::<usize>().ok()?)?;
            parents.push(FieldParent::Object);
            if fields.len() > 1 {
                if fields.first()?.as_str() != "sizes" || fields.len() != 2 {
                    return None;
                }
                parents.push(FieldParent::Array {
                    len: icon.sizes.as_ref()?.len(),
                });
            }
        }
        Some(parents)
    }
    let parents = match (phase, projection) {
        (DispatchPhase::Pre, Projection::Resource) => match identity.part(message)? {
            Some(ContentPart::ResourceRef { .. }) => fixed_parents(path),
            _ => path.is_empty().then(Vec::new),
        },
        (DispatchPhase::Pre, Projection::Prompt) => match identity.part(message)? {
            Some(ContentPart::PromptRequest { content }) => map_parents(&content.arguments, path),
            Some(ContentPart::ToolCall { content }) => map_parents(&content.arguments, path),
            _ => path.is_empty().then(Vec::new),
        },
        (DispatchPhase::Pre, _) => arguments_for_projection(message, projection)
            .and_then(|map| map_parents(map, path))
            .or_else(|| path.is_empty().then(Vec::new)),
        (DispatchPhase::Post, Projection::Resource) => match identity.resource(message)? {
            Some(resource) => resource_parents(resource, path),
            None => path.is_empty().then(Vec::new),
        },
        (DispatchPhase::Post, Projection::Prompt) => match identity.part(message)? {
            Some(ContentPart::PromptResult { .. }) => fixed_parents(path),
            _ => path.is_empty().then(Vec::new),
        },
        (DispatchPhase::Post, Projection::Tool) => message
            .content
            .iter()
            .find_map(|part| match part {
                ContentPart::ToolResult { content } => Some(&content.content),
                _ => None,
            })
            .and_then(|value| field_parents(value, path))
            .or_else(|| path.is_empty().then(Vec::new)),
    };
    parents.ok_or_else(|| EnvelopeReplaced::shape_changed(projection, phase == DispatchPhase::Pre))
}

fn argument_field(
    arguments: &std::collections::HashMap<String, serde_json::Value>,
    path: &[String],
) -> Option<serde_json::Value> {
    let Some((key, rest)) = path.split_first() else {
        return Some(serde_json::Value::Object(
            arguments
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ));
    };
    crate::message_projection::value_at(arguments.get(key)?, rest).cloned()
}

/// Return the argument or result field addressed by the dispatch phase.
fn field_value_from_message(
    message: &praxis_policy_core::cmf::Message,
    field: &str,
    phase: DispatchPhase,
    projection: Projection,
) -> Option<serde_json::Value> {
    let projected = match phase {
        DispatchPhase::Pre => {
            crate::message_projection::extract_args_from_message(message, projection)
        },
        DispatchPhase::Post => {
            return crate::message_projection::extract_result_field(message, projection, field);
        },
    };
    if projected.is_object() {
        praxis_policy_apl_core::get_dotted(&projected, field).cloned()
    } else {
        Some(projected)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    use praxis_policy_core::cmf::enums::Role;

    use praxis_policy_core::cmf::{ContentPart, Message, ToolCall};

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn projection_aware_readback_delegates_to_the_existing_host_method() {
        assert_eq!(
            LegacyPayload.field_value_with_projection(
                "body",
                DispatchPhase::Post,
                Projection::Resource
            ),
            Some(serde_json::json!("body")),
            "a host's existing field_value implementation must remain in use",
        );
    }

    #[test]
    fn the_existing_message_field_method_keeps_tool_argument_behavior() {
        assert_eq!(
            tool_call_payload().field_value("city", DispatchPhase::Pre),
            Some(serde_json::json!("Boston")),
            "existing message callers must still read their tool arguments",
        );
    }

    #[test]
    fn a_message_projects_the_named_argument() {
        let payload = tool_call_payload();
        assert_eq!(
            payload.field_value_with_projection("city", DispatchPhase::Pre, Projection::Tool),
            Some(serde_json::json!("Boston")),
        );
        assert_eq!(
            payload.field_value_with_projection("absent", DispatchPhase::Pre, Projection::Tool),
            None
        );
    }

    #[test]
    fn a_text_only_message_projects_its_whole_content() {
        let payload = MessagePayload {
            message: Message::text(Role::User, "hello"),
        };
        assert_eq!(
            payload.field_value_with_projection("anything", DispatchPhase::Pre, Projection::Tool),
            Some(serde_json::json!("hello")),
        );
    }

    #[test]
    fn a_resource_projects_its_result_content_field() {
        let payload = resource_payload();
        assert_eq!(
            payload.field_value_with_projection(
                "content",
                DispatchPhase::Post,
                Projection::Resource
            ),
            Some(serde_json::json!("SSN 123-45-6789")),
        );
        assert_eq!(
            payload.field_value_with_projection("uri", DispatchPhase::Post, Projection::Resource),
            Some(serde_json::json!("hr://employees/42")),
        );
        assert_eq!(
            payload.field_value_with_projection(
                "nonexistent",
                DispatchPhase::Post,
                Projection::Resource
            ),
            None,
        );
    }

    #[test]
    fn a_prompt_result_projects_its_result_content_field() {
        let payload = prompt_result_payload();
        assert_eq!(
            payload.field_value_with_projection("content", DispatchPhase::Post, Projection::Prompt),
            Some(serde_json::json!("The summary text")),
        );
        assert_eq!(
            payload.field_value_with_projection(
                "prompt_name",
                DispatchPhase::Post,
                Projection::Prompt
            ),
            Some(serde_json::json!("summarize")),
        );
        assert_eq!(
            payload.field_value_with_projection(
                "nonexistent",
                DispatchPhase::Post,
                Projection::Prompt
            ),
            None,
        );
    }

    #[test]
    fn the_http_payload_has_no_fields_in_either_phase() {
        let payload = HttpPayload;
        assert_eq!(
            payload.field_value_with_projection("city", DispatchPhase::Pre, Projection::Tool),
            None
        );
        assert_eq!(
            payload.field_value_with_projection("city", DispatchPhase::Post, Projection::Tool),
            None
        );
    }

    #[test]
    fn concrete_readback_keeps_legacy_field_names() {
        let path = vec!["rows".to_owned(), "0".to_owned(), "name".to_owned()];
        let value = field_value_for_identity(
            &LegacyPayload,
            "rows.name",
            DispatchPhase::Post,
            Projection::Resource,
            &ResultIdentity::default(),
            Some(FieldLocation {
                path: &path,
                parents: &[],
            }),
        )
        .expect("legacy readback");
        assert_eq!(value, Some(serde_json::json!("rows.name")));
    }

    #[test]
    fn resource_readback_addresses_icon_fields() {
        let mut payload = resource_payload();
        let Some(ContentPart::Resource { content }) = payload.message.content.first_mut() else {
            panic!("resource")
        };
        content
            .icons
            .get_or_insert_with(Vec::new)
            .push(praxis_policy_core::extensions::Icon {
                src: "icon.svg".to_owned(),
                mime_type: Some("image/svg+xml".to_owned()),
                sizes: Some(vec!["any".to_owned()]),
            });
        for (field, expected) in [
            ("icons.0.src", serde_json::json!("icon.svg")),
            ("icons.0.mime_type", serde_json::json!("image/svg+xml")),
            ("icons.0.sizes.0", serde_json::json!("any")),
            ("icons.0.sizes", serde_json::json!(["any"])),
        ] {
            assert_eq!(
                payload.field_value_with_projection(
                    field,
                    DispatchPhase::Post,
                    Projection::Resource
                ),
                Some(expected),
                "{field}"
            );
        }
        assert_eq!(
            payload.field_value_with_projection(
                "icons.0.src.extra",
                DispatchPhase::Post,
                Projection::Resource
            ),
            None
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    fn tool_call_payload() -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".to_owned(),
                        name: "get_weather".to_owned(),
                        arguments: [("city".to_owned(), serde_json::json!("Boston"))]
                            .into_iter()
                            .collect(),
                        namespace: None,
                    },
                }],
            ),
        }
    }

    fn resource_payload() -> MessagePayload {
        use praxis_policy_core::cmf::Resource;
        use praxis_policy_core::cmf::enums::ResourceType;
        MessagePayload {
            message: Message::with_content(
                Role::Tool,
                vec![ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "rr_001".to_owned(),
                        uri: "hr://employees/42".to_owned(),
                        content: Some("SSN 123-45-6789".to_owned()),
                        mime_type: Some("text/plain".to_owned()),
                        size_bytes: Some(15),
                        resource_type: ResourceType::Uri,
                        ..Resource::default()
                    },
                }],
            ),
        }
    }

    fn prompt_result_payload() -> MessagePayload {
        use praxis_policy_core::cmf::PromptResult;
        MessagePayload {
            message: Message::with_content(
                Role::Assistant,
                vec![ContentPart::PromptResult {
                    content: PromptResult {
                        prompt_request_id: "pr_001".to_owned(),
                        prompt_name: "summarize".to_owned(),
                        description: Some("Summary prompt".to_owned()),
                        messages: vec![],
                        content: Some("The summary text".to_owned()),
                        is_error: false,
                        error_message: None,
                    },
                }],
            ),
        }
    }

    #[derive(Clone)]
    struct LegacyPayload;

    praxis_policy_core::impl_plugin_payload!(LegacyPayload);

    impl PayloadFields for LegacyPayload {
        fn field_value(&self, field: &str, _phase: DispatchPhase) -> Option<serde_json::Value> {
            Some(serde_json::json!(field))
        }
    }
}
