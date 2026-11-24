// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PayloadFields` — what an `args:` / `result:` pipeline can address on a
// hook payload.
//
// A field stage hands a plugin the whole payload, not the field, so the
// invoker has to read the field back out afterwards to learn whether the
// plugin rewrote it. That readback is payload-shaped: a CMF message
// projects its arguments or its result, and a payload with no content
// projects nothing.
//
// # Why the method is not on `PluginPayload`
//
// The signature needs `DispatchPhase`, which lives in
// `praxis-policy-apl-core`, and `praxis-policy-core` is a leaf crate that
// depends on no APL crate. Putting it there would either move an APL
// concept into the leaf or duplicate it, and it would oblige the identity,
// delegation, and elicitation payloads to answer a question about args and
// result projection that means nothing to them. The trait is local
// instead, which is also what makes implementing it for those payloads
// allowed if one ever needs it.
//
// # Why the default body returns nothing
//
// A blanket `impl<T: PluginPayload>` is not available: it collides with
// `MessagePayload`'s real implementation under E0119, and specialization
// is unstable. A default body gives the same ergonomics. The direction it
// defaults to is the safe one: a payload that wrongly claims no fields
// loses a pipeline stage it never had, where the reverse would hand a
// plugin a field that does not exist. A new payload still has to name the
// trait to be carried by the invoker at all, so the default is
// low-friction rather than silent.

use praxis_policy_core::cmf::MessagePayload;
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::http_hook::HttpPayload;

use praxis_policy_apl_core::step::DispatchPhase;

use crate::message_projection::{EnvelopeReplaced, Projection, ResultIdentity};

/// Reads one pipeline field off a hook payload.
///
/// The invoker is bound to a payload implementing this trait, and calls it
/// twice per field-stage dispatch: once before the plugin runs, for the
/// baseline, and once after, to see whether the plugin's mutation touched
/// this field.
///
/// `Clone` is a supertrait because the invoker keeps the request's payload
/// under interior mutability and clones it for each dispatch.
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
    ///
    /// Defaults to `None` for a payload that carries no fields.
    fn field_value(&self, _field: &str, _phase: DispatchPhase) -> Option<serde_json::Value> {
        None
    }

    /// Read a field using the route's content-part projection.
    ///
    /// The default delegates to [`Self::field_value`] so existing host
    /// implementations keep their field behavior without a signature change.
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

/// The HTTP payload carries no fields, so the default body is the whole
/// implementation. Everything a handler reads about an HTTP exchange is on
/// the `Extensions` it is passed, and a body is not a payload field.
impl PayloadFields for HttpPayload {}

/// Capture the request's resource selection without copying its body.
pub(crate) fn resource_identity<P: PayloadFields>(payload: &P) -> ResultIdentity {
    payload
        .as_any()
        .downcast_ref::<MessagePayload>()
        .map_or_else(ResultIdentity::default, |message| {
            ResultIdentity::from_resource_message(&message.message)
        })
}

/// Read a field from the selected resource throughout one route invocation.
pub(crate) fn field_value_for_identity<P: PayloadFields>(
    payload: &P,
    field: &str,
    phase: DispatchPhase,
    projection: Projection,
    identity: &ResultIdentity,
) -> Result<Option<serde_json::Value>, EnvelopeReplaced> {
    if phase == DispatchPhase::Post
        && projection == Projection::Resource
        && let Some(message) = payload.as_any().downcast_ref::<MessagePayload>()
        && let Some(resource) = identity.resource(&message.message)?
    {
        return Ok(crate::message_projection::resource_field_value(
            resource, field,
        ));
    }
    Ok(payload.field_value_with_projection(field, phase, projection))
}

/// Read the value of one pipeline field out of a message.
///
/// The projection matches what APL evaluated against: Pre addresses args,
/// Post addresses result. `field` is relative to that root.
///
/// Two shapes:
///   * object projection (a tool call's arguments, a structured tool
///     result) → look up `field` in it, `None` when absent.
///   * scalar projection (a text-only message, whose whole content is
///     the field) → the projection itself.
///
/// The caller compares the result against the value the pipeline is
/// holding: equal, or `None` here, both mean "this plugin didn't change
/// this field". The plugin's payload mutation is recorded separately, so
/// reporting no field change never drops it.
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
        // The default body is the whole implementation, so this is what an
        // `args:` / `result:` stage would read if one could reach an HTTP
        // route. The load-time refusal is what keeps it unreachable.
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

    #[derive(Clone)]
    struct LegacyPayload;
    praxis_policy_core::impl_plugin_payload!(LegacyPayload);

    impl PayloadFields for LegacyPayload {
        fn field_value(&self, field: &str, _phase: DispatchPhase) -> Option<serde_json::Value> {
            Some(serde_json::json!(field))
        }
    }
}
