// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Dispatch phases belong to APL, so payload field projection stays in the
// runtime instead of adding an APL dependency to the leaf core crate.

use praxis_policy_core::cmf::MessagePayload;
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::http_hook::HttpPayload;

use praxis_policy_apl_core::step::DispatchPhase;

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
}

/// HTTP exchanges expose attributes through extensions rather than payload fields.
impl PayloadFields for HttpPayload {}

/// Identify the reference, resource and prompt selected before plugins run.
pub(crate) fn payload_identities<P: PayloadFields>(payload: &P) -> [ResultIdentity; 4] {
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
    path: Option<&[String]>,
) -> Result<Option<serde_json::Value>, EnvelopeReplaced> {
    if let Some(message) = payload.as_any().downcast_ref::<MessagePayload>() {
        let segments;
        let path = if let Some(path) = path {
            path
        } else {
            segments = field.split('.').map(str::to_owned).collect::<Vec<_>>();
            &segments
        };
        if phase == DispatchPhase::Post
            && projection == Projection::Resource
            && let Some(resource) = identity.resource(&message.message)?
        {
            return Ok(crate::message_projection::resource_field_value_at(
                resource, path,
            ));
        }
        let projected = match (phase, projection) {
            (DispatchPhase::Pre, Projection::Resource) => {
                Some(crate::message_projection::extract_args_by_identity(
                    &message.message,
                    projection,
                    identity,
                )?)
            },
            (DispatchPhase::Post, Projection::Prompt) => {
                Some(crate::message_projection::extract_result_by_identity(
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
    let concrete;
    let field = if let Some(path) = path {
        concrete = path.join(".");
        &concrete
    } else {
        field
    };
    Ok(payload.field_value_with_projection(field, phase, projection))
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
