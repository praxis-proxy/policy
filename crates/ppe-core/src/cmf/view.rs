// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// MessageView — read-only projection for policy evaluation.
//
// Decomposes a Message into individually addressable views with a
// uniform interface regardless of content type. Zero-copy design —
// properties are computed on-demand by borrowing the underlying
// content part and extensions directly.

use serde::{Deserialize, Serialize};

#[allow(
    clippy::wildcard_imports,
    reason = "sibling module in one logical unit split across files; naming each \
              item would be a hand-maintained list with no reader benefit"
)]
use super::content::*;
use super::enums::{ContentType, Role};
use super::message::Message;
use crate::hooks::payload::Extensions;
use crate::hooks::{HookPhase, lookup_hook_metadata};

/// Type of content a view represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    /// Plain text.
    Text,
    /// Model reasoning, not addressed to the user.
    Thinking,
    /// A request to invoke a tool.
    ToolCall,
    /// What a tool returned.
    ToolResult,
    /// Inline resource content.
    Resource,
    /// A reference to a resource, without its content.
    ResourceRef,
    /// A request to render a prompt.
    PromptRequest,
    /// A rendered prompt.
    PromptResult,
    /// An image.
    Image,
    /// A video.
    Video,
    /// Audio.
    Audio,
    /// A document.
    Document,
}

/// The action this content represents in the data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewAction {
    /// Reading existing data.
    Read,
    /// Writing data.
    Write,
    /// Running code.
    Execute,
    /// Calling a tool.
    Invoke,
    /// Sending data outward.
    Send,
    /// Receiving data inward.
    Receive,
    /// Producing new content.
    Generate,
}

impl ViewKind {
    /// Map `ContentType` to `ViewKind`.
    pub fn from_content_type(ct: ContentType) -> Self {
        match ct {
            ContentType::Text => ViewKind::Text,
            ContentType::Thinking => ViewKind::Thinking,
            ContentType::ToolCall => ViewKind::ToolCall,
            ContentType::ToolResult => ViewKind::ToolResult,
            ContentType::Resource => ViewKind::Resource,
            ContentType::ResourceRef => ViewKind::ResourceRef,
            ContentType::PromptRequest => ViewKind::PromptRequest,
            ContentType::PromptResult => ViewKind::PromptResult,
            ContentType::Image => ViewKind::Image,
            ContentType::Video => ViewKind::Video,
            ContentType::Audio => ViewKind::Audio,
            ContentType::Document => ViewKind::Document,
        }
    }

    /// The default action for this kind of content.
    pub fn default_action(&self, role: Role) -> ViewAction {
        match self {
            ViewKind::ToolCall => ViewAction::Execute,
            ViewKind::ToolResult => ViewAction::Receive,
            ViewKind::Resource | ViewKind::ResourceRef => ViewAction::Read,
            ViewKind::PromptRequest => ViewAction::Invoke,
            ViewKind::PromptResult => ViewAction::Receive,
            // Direction-dependent kinds
            ViewKind::Text
            | ViewKind::Thinking
            | ViewKind::Image
            | ViewKind::Video
            | ViewKind::Audio
            | ViewKind::Document => match role {
                Role::User => ViewAction::Send,
                Role::Assistant => ViewAction::Generate,
                Role::Tool => ViewAction::Receive,
                Role::System | Role::Developer => ViewAction::Write,
            },
        }
    }

    /// Whether this is a tool-related kind.
    pub fn is_tool(&self) -> bool {
        matches!(self, ViewKind::ToolCall | ViewKind::ToolResult)
    }

    /// Whether this is a resource-related kind.
    pub fn is_resource(&self) -> bool {
        matches!(self, ViewKind::Resource | ViewKind::ResourceRef)
    }

    /// Whether this is a prompt-related kind.
    pub fn is_prompt(&self) -> bool {
        matches!(self, ViewKind::PromptRequest | ViewKind::PromptResult)
    }

    /// Whether this is a media kind (image, video, audio, document).
    pub fn is_media(&self) -> bool {
        matches!(
            self,
            ViewKind::Image | ViewKind::Video | ViewKind::Audio | ViewKind::Document
        )
    }

    /// Whether this is a text kind (text or thinking).
    pub fn is_text(&self) -> bool {
        matches!(self, ViewKind::Text | ViewKind::Thinking)
    }
}

/// Read-only, zero-copy view over a single content part.
///
/// Provides a uniform interface for policy evaluation regardless
/// of content type. Properties are computed on-demand by borrowing
/// the underlying content part and extensions.
///
/// Produced by `Message::iter_views()` or the standalone `iter_views()`.
pub struct MessageView<'a> {
    /// The underlying content part.
    part: &'a ContentPart,
    /// The kind of content.
    kind: ViewKind,
    /// The parent message role.
    role: Role,
    /// Optional hook location (e.g., "`cmf.tool_pre_invoke`").
    hook: Option<&'a str>,
    /// Optional extensions (for security/http context).
    extensions: Option<&'a Extensions>,
}

impl<'a> MessageView<'a> {
    /// Create a new view over a content part.
    pub fn new(
        part: &'a ContentPart,
        role: Role,
        hook: Option<&'a str>,
        extensions: Option<&'a Extensions>,
    ) -> Self {
        let kind = match part {
            ContentPart::Text { .. } => ViewKind::Text,
            ContentPart::Thinking { .. } => ViewKind::Thinking,
            ContentPart::ToolCall { .. } => ViewKind::ToolCall,
            ContentPart::ToolResult { .. } => ViewKind::ToolResult,
            ContentPart::Resource { .. } => ViewKind::Resource,
            ContentPart::ResourceRef { .. } => ViewKind::ResourceRef,
            ContentPart::PromptRequest { .. } => ViewKind::PromptRequest,
            ContentPart::PromptResult { .. } => ViewKind::PromptResult,
            ContentPart::Image { .. } => ViewKind::Image,
            ContentPart::Video { .. } => ViewKind::Video,
            ContentPart::Audio { .. } => ViewKind::Audio,
            ContentPart::Document { .. } => ViewKind::Document,
        };

        Self {
            part,
            kind,
            role,
            hook,
            extensions,
        }
    }

    // -- Core properties --

    /// The kind of content this view represents.
    pub fn kind(&self) -> ViewKind {
        self.kind
    }

    /// The role of the parent message.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The underlying content part.
    pub fn raw(&self) -> &'a ContentPart {
        self.part
    }

    /// The hook location, if set.
    pub fn hook(&self) -> Option<&str> {
        self.hook
    }

    /// The action this content represents.
    pub fn action(&self) -> ViewAction {
        self.kind.default_action(self.role)
    }

    // -- Phase helpers --

    /// Whether this view's hook is registered under `phase`.
    ///
    /// Reads the metadata registry, not the name: `cmf.llm_input` is
    /// `Pre` without spelling it, and `express_lane` spells it without
    /// being it. An unregistered name has no phase.
    fn phase_is(&self, phase: HookPhase) -> bool {
        self.hook
            .is_some_and(|h| lookup_hook_metadata(h).is_some_and(|meta| meta.phase == phase))
    }

    /// Whether this is a pre-execution hook (`cmf.tool_pre_invoke`,
    /// `cmf.llm_input`, `cmf.http_request`, etc.).
    pub fn is_pre(&self) -> bool {
        self.phase_is(HookPhase::Pre)
    }

    /// Whether this is a post-execution hook.
    pub fn is_post(&self) -> bool {
        self.phase_is(HookPhase::Post)
    }

    // -- Universal properties --

    /// Text content (for text, thinking, tool result content).
    pub fn content(&self) -> Option<&str> {
        match self.part {
            ContentPart::Text { text } | ContentPart::Thinking { text } => Some(text),
            ContentPart::ToolResult { content: tr } => {
                tr.content.as_str().map(Some).unwrap_or(None)
            },
            ContentPart::Resource { content: r } => r.content.as_deref(),
            ContentPart::PromptResult { content: pr } => pr.content.as_deref(),
            _ => None,
        }
    }

    /// Entity name (tool name, resource URI, prompt name).
    pub fn name(&self) -> Option<&str> {
        match self.part {
            ContentPart::ToolCall { content: tc } => Some(&tc.name),
            ContentPart::ToolResult { content: tr } => Some(&tr.tool_name),
            ContentPart::Resource { content: r } => r.name.as_deref().or(Some(&r.uri)),
            ContentPart::ResourceRef { content: rr } => rr.name.as_deref().or(Some(&rr.uri)),
            ContentPart::PromptRequest { content: pr } => Some(&pr.name),
            ContentPart::PromptResult { content: pr } => Some(&pr.prompt_name),
            _ => None,
        }
    }

    /// URI for the entity.
    pub fn uri(&self) -> Option<String> {
        match self.part {
            ContentPart::ToolCall { content: tc } => Some(format!("tool://_/{}", tc.name)),
            ContentPart::Resource { content: r } => Some(r.uri.clone()),
            ContentPart::ResourceRef { content: rr } => Some(rr.uri.clone()),
            ContentPart::PromptRequest { content: pr } => Some(format!("prompt://_/{}", pr.name)),
            _ => None,
        }
    }

    /// Arguments (for tool calls and prompt requests).
    pub fn args(&self) -> Option<&std::collections::HashMap<String, serde_json::Value>> {
        match self.part {
            ContentPart::ToolCall { content: tc } => Some(&tc.arguments),
            ContentPart::PromptRequest { content: pr } => Some(&pr.arguments),
            _ => None,
        }
    }

    /// Get a specific argument by name.
    pub fn get_arg(&self, name: &str) -> Option<&serde_json::Value> {
        self.args().and_then(|a| a.get(name))
    }

    /// Whether this content has arguments.
    pub fn has_arg(&self, name: &str) -> bool {
        self.get_arg(name).is_some()
    }

    /// MIME type (for resources, media).
    pub fn mime_type(&self) -> Option<&str> {
        match self.part {
            ContentPart::Resource { content: r } => r.mime_type.as_deref(),
            ContentPart::Image { content: img } => img.media_type.as_deref(),
            ContentPart::Video { content: vid } => vid.media_type.as_deref(),
            ContentPart::Audio { content: aud } => aud.media_type.as_deref(),
            ContentPart::Document { content: doc } => doc.media_type.as_deref(),
            _ => None,
        }
    }

    /// Whether the result is an error (tool results, prompt results).
    pub fn is_error(&self) -> bool {
        match self.part {
            ContentPart::ToolResult { content: tr } => tr.is_error,
            ContentPart::PromptResult { content: pr } => pr.is_error,
            _ => false,
        }
    }

    // -- Type helpers --

    /// Whether this view is a tool call or its result.
    pub fn is_tool(&self) -> bool {
        self.kind.is_tool()
    }
    /// Whether this view is resource content or a reference to it.
    pub fn is_resource(&self) -> bool {
        self.kind.is_resource()
    }
    /// Whether this view is a prompt request or its result.
    pub fn is_prompt(&self) -> bool {
        self.kind.is_prompt()
    }
    /// Whether this view carries an image, video, audio, or document.
    pub fn is_media(&self) -> bool {
        self.kind.is_media()
    }
    /// Whether this view carries text or model reasoning.
    pub fn is_text(&self) -> bool {
        self.kind.is_text()
    }

    // -- Extension accessors --

    /// Get the extensions, if provided.
    pub fn extensions(&self) -> Option<&'a Extensions> {
        self.extensions
    }

    /// Check if a security label exists.
    pub fn has_label(&self, label: &str) -> bool {
        self.extensions
            .and_then(|e| e.security.as_ref())
            .map(|s| s.has_label(label))
            .unwrap_or(false)
    }

    /// Get an HTTP header value.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.extensions
            .and_then(|e| e.http.as_ref())
            .and_then(|h| h.get_header(name))
    }

    // -- Serialization --

    /// Sensitive headers stripped during serialization.
    const SENSITIVE_HEADERS: &'static [&'static str] = &["authorization", "cookie", "x-api-key"];

    /// Serialize the view to a JSON-compatible map.
    ///
    /// Includes the view's properties, arguments, and optionally
    /// text content and extension context. Sensitive headers
    /// (Authorization, Cookie, X-API-Key) are stripped.
    pub fn to_dict(&self, include_content: bool, include_context: bool) -> serde_json::Value {
        #[allow(
            clippy::wildcard_imports,
            reason = "sibling module in one logical unit split across files; naming each \
              item would be a hand-maintained list with no reader benefit"
        )]
        use super::constants::*;

        let mut result = serde_json::Map::new();

        // Core fields
        result.insert(FIELD_KIND.into(), serde_json::json!(self.kind));
        result.insert(FIELD_ROLE.into(), serde_json::json!(self.role));
        result.insert(FIELD_IS_PRE.into(), serde_json::json!(self.is_pre()));
        result.insert(FIELD_IS_POST.into(), serde_json::json!(self.is_post()));
        result.insert(FIELD_ACTION.into(), serde_json::json!(self.action()));

        if let Some(hook) = self.hook {
            result.insert(FIELD_HOOK.into(), serde_json::json!(hook));
        }

        if let Some(uri) = self.uri() {
            result.insert(FIELD_URI.into(), serde_json::json!(uri));
        }

        if let Some(name) = self.name() {
            result.insert(FIELD_NAME.into(), serde_json::json!(name));
        }

        // Content
        if include_content && let Some(text) = self.content() {
            result.insert(FIELD_SIZE_BYTES.into(), serde_json::json!(text.len()));
            result.insert(FIELD_CONTENT.into(), serde_json::json!(text));
        }

        if let Some(mime) = self.mime_type() {
            result.insert(FIELD_MIME_TYPE.into(), serde_json::json!(mime));
        }

        // Arguments
        if let Some(args) = self.args() {
            result.insert(FIELD_ARGUMENTS.into(), serde_json::json!(args));
        }

        // Extensions context
        if include_context && let Some(ext) = self.extensions {
            let mut ext_map = serde_json::Map::new();

            // Subject
            if let Some(ref sec) = ext.security {
                if let Some(ref subject) = sec.subject {
                    let mut sub_map = serde_json::Map::new();
                    if let Some(ref id) = subject.id {
                        sub_map.insert(FIELD_ID.into(), serde_json::json!(id));
                    }
                    if let Some(ref st) = subject.subject_type {
                        sub_map.insert(FIELD_TYPE.into(), serde_json::json!(st));
                    }
                    if !subject.roles.is_empty() {
                        let mut roles: Vec<&String> = subject.roles.iter().collect();
                        roles.sort();
                        sub_map.insert(FIELD_ROLES.into(), serde_json::json!(roles));
                    }
                    if !subject.permissions.is_empty() {
                        let mut perms: Vec<&String> = subject.permissions.iter().collect();
                        perms.sort();
                        sub_map.insert(FIELD_PERMISSIONS.into(), serde_json::json!(perms));
                    }
                    if !subject.teams.is_empty() {
                        let mut teams: Vec<&String> = subject.teams.iter().collect();
                        teams.sort();
                        sub_map.insert(FIELD_TEAMS.into(), serde_json::json!(teams));
                    }
                    if !sub_map.is_empty() {
                        ext_map.insert(FIELD_SUBJECT.into(), serde_json::Value::Object(sub_map));
                    }
                }

                // Labels
                if !sec.labels.is_empty() {
                    let mut labels: Vec<&String> = sec.labels.iter().collect();
                    labels.sort();
                    ext_map.insert(FIELD_LABELS.into(), serde_json::json!(labels));
                }
            }

            // Environment
            if let Some(ref req) = ext.request
                && let Some(ref env) = req.environment
            {
                ext_map.insert(FIELD_ENVIRONMENT.into(), serde_json::json!(env));
            }

            // Request headers (strip sensitive)
            if let Some(ref http) = ext.http {
                let safe: std::collections::HashMap<&String, &String> = http
                    .request_headers
                    .iter()
                    .filter(|(k, _)| !Self::SENSITIVE_HEADERS.contains(&k.to_lowercase().as_str()))
                    .collect();
                if !safe.is_empty() {
                    ext_map.insert(FIELD_HEADERS.into(), serde_json::json!(safe));
                }
            }

            // Agent context
            if let Some(ref agent) = ext.agent {
                let mut agent_map = serde_json::Map::new();
                if let Some(ref input) = agent.input {
                    agent_map.insert(FIELD_INPUT.into(), serde_json::json!(input));
                }
                if let Some(ref sid) = agent.session_id {
                    agent_map.insert(FIELD_SESSION_ID.into(), serde_json::json!(sid));
                }
                if let Some(ref cid) = agent.conversation_id {
                    agent_map.insert(FIELD_CONVERSATION_ID.into(), serde_json::json!(cid));
                }
                if let Some(turn) = agent.turn {
                    agent_map.insert(FIELD_TURN.into(), serde_json::json!(turn));
                }
                if let Some(ref aid) = agent.agent_id {
                    agent_map.insert(FIELD_AGENT_ID.into(), serde_json::json!(aid));
                }
                if let Some(ref paid) = agent.parent_agent_id {
                    agent_map.insert(FIELD_PARENT_AGENT_ID.into(), serde_json::json!(paid));
                }
                if !agent_map.is_empty() {
                    ext_map.insert(FIELD_AGENT.into(), serde_json::Value::Object(agent_map));
                }
            }

            // Meta
            if let Some(ref meta) = ext.meta {
                let mut meta_map = serde_json::Map::new();
                if let Some(ref et) = meta.entity_type {
                    meta_map.insert(FIELD_ENTITY_TYPE.into(), serde_json::json!(et));
                }
                if let Some(ref en) = meta.entity_name {
                    meta_map.insert(FIELD_ENTITY_NAME.into(), serde_json::json!(en));
                }
                if !meta.tags.is_empty() {
                    let mut tags: Vec<&String> = meta.tags.iter().collect();
                    tags.sort();
                    meta_map.insert(FIELD_TAGS.into(), serde_json::json!(tags));
                }
                if !meta_map.is_empty() {
                    ext_map.insert(FIELD_META.into(), serde_json::Value::Object(meta_map));
                }
            }

            if !ext_map.is_empty() {
                result.insert(FIELD_EXTENSIONS.into(), serde_json::Value::Object(ext_map));
            }
        }

        serde_json::Value::Object(result)
    }

    /// Serialize to OPA-compatible input format.
    ///
    /// Wraps the view in the standard OPA input envelope:
    /// `{"input": {...view data...}}`.
    pub fn to_opa_input(&self, include_content: bool) -> serde_json::Value {
        use super::constants::FIELD_OPA_INPUT;
        serde_json::json!({
            FIELD_OPA_INPUT: self.to_dict(include_content, true)
        })
    }
}

impl<'a> std::fmt::Debug for MessageView<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageView")
            .field("kind", &self.kind)
            .field("role", &self.role)
            .field("name", &self.name())
            .field("hook", &self.hook)
            .finish()
    }
}

/// Decompose a Message into individually addressable `MessageViews`.
///
/// Yields one view per content part. Each view provides a uniform
/// interface for policy evaluation regardless of content type.
pub fn iter_views<'a>(
    message: &'a Message,
    hook: Option<&'a str>,
    extensions: Option<&'a Extensions>,
) -> impl Iterator<Item = MessageView<'a>> {
    message
        .content
        .iter()
        .map(move |part| MessageView::new(part, message.role, hook, extensions))
}

// Also add iter_views to Message
impl Message {
    /// Decompose this message into individually addressable `MessageViews`.
    ///
    /// Yields one view per content part. Each view provides a uniform
    /// interface for policy evaluation regardless of content type.
    pub fn iter_views<'a>(
        &'a self,
        hook: Option<&'a str>,
        extensions: Option<&'a Extensions>,
    ) -> impl Iterator<Item = MessageView<'a>> {
        iter_views(self, hook, extensions)
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
    use crate::hooks::payload::MetaExtension;

    fn make_test_message() -> Message {
        Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Thinking {
                    text: "Let me think...".into(),
                },
                ContentPart::Text {
                    text: "Here's the answer.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_weather".into(),
                        arguments: [("city".to_owned(), serde_json::json!("London"))].into(),
                        namespace: None,
                    },
                },
                ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "rr_001".into(),
                        uri: "file:///data.csv".into(),
                        name: Some("Data File".into()),
                        resource_type: crate::cmf::enums::ResourceType::File,
                        content: Some("col1,col2".into()),
                        mime_type: Some("text/csv".into()),
                        ..Default::default()
                    },
                },
            ],
            channel: None,
        }
    }

    #[test]
    fn test_iter_views_count() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views.len(), 4);
    }

    #[test]
    fn test_view_kinds() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].kind(), ViewKind::Thinking);
        assert_eq!(views[1].kind(), ViewKind::Text);
        assert_eq!(views[2].kind(), ViewKind::ToolCall);
        assert_eq!(views[3].kind(), ViewKind::Resource);
    }

    #[test]
    fn test_view_content() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].content(), Some("Let me think..."));
        assert_eq!(views[1].content(), Some("Here's the answer."));
        assert!(views[2].content().is_none()); // tool call has no text content
        assert_eq!(views[3].content(), Some("col1,col2")); // resource has text content
    }

    #[test]
    fn test_view_name() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert!(views[0].name().is_none()); // thinking has no name
        assert!(views[1].name().is_none()); // text has no name
        assert_eq!(views[2].name(), Some("get_weather"));
        assert_eq!(views[3].name(), Some("Data File"));
    }

    #[test]
    fn test_view_uri() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[2].uri(), Some("tool://_/get_weather".to_owned()));
        assert_eq!(views[3].uri(), Some("file:///data.csv".to_owned()));
    }

    #[test]
    fn test_view_args() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        let tool_view = &views[2];
        assert!(tool_view.has_arg("city"));
        assert_eq!(tool_view.get_arg("city").unwrap(), "London");
        assert!(!tool_view.has_arg("nonexistent"));
    }

    #[test]
    fn test_view_action() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].action(), ViewAction::Generate); // thinking from assistant
        assert_eq!(views[1].action(), ViewAction::Generate); // text from assistant
        assert_eq!(views[2].action(), ViewAction::Execute); // tool call
        assert_eq!(views[3].action(), ViewAction::Read); // resource
    }

    #[test]
    fn test_view_action_user_role() {
        let msg = Message::text(Role::User, "Hello");
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[0].action(), ViewAction::Send); // text from user
    }

    #[test]
    fn test_view_hook_pre_post() {
        let msg = make_test_message();
        let pre_views: Vec<_> = msg.iter_views(Some("cmf.tool_pre_invoke"), None).collect();
        assert!(pre_views[0].is_pre());
        assert!(!pre_views[0].is_post());

        let post_views: Vec<_> = msg.iter_views(Some("cmf.tool_post_invoke"), None).collect();
        assert!(post_views[0].is_post());
        assert!(!post_views[0].is_pre());
    }

    /// The four hooks whose name does not spell their phase, which is
    /// what the substring match got wrong. Written out rather than read
    /// from the table, so this fails if either the accessor or the
    /// registered phase moves.
    #[test]
    fn phase_accessors_hold_for_the_hooks_no_name_spells() {
        let msg = make_test_message();
        for (name, pre, post) in [
            ("cmf.llm_input", true, false),
            ("cmf.llm_output", false, true),
            ("cmf.http_request", true, false),
            ("cmf.http_response", false, true),
        ] {
            let views: Vec<_> = msg.iter_views(Some(name), None).collect();
            assert_eq!(views[0].is_pre(), pre, "is_pre for {name}");
            assert_eq!(views[0].is_post(), post, "is_post for {name}");
        }
    }

    /// Every dispatched hook reports the phase it is registered under.
    ///
    /// Both sides read the registry, so this cannot catch a hook whose
    /// name disagrees with its row. What it does catch is the accessors
    /// themselves: an inverted phase, a hook name not threaded into the
    /// view, or `Unphased` reported as a phase.
    #[test]
    fn phase_accessors_agree_with_the_hook_authority() {
        let msg = make_test_message();
        for hook in crate::hooks::builtin_hook_types() {
            let name = hook.to_string();
            let meta = lookup_hook_metadata(&name).expect("a built-in hook is registered");
            let views: Vec<_> = msg.iter_views(Some(&name), None).collect();
            let view = &views[0];
            let (pre, post) = match meta.phase {
                HookPhase::Pre => (true, false),
                HookPhase::Post => (false, true),
                // Outside the request lifecycle: neither half applies.
                HookPhase::Unphased => (false, false),
            };
            assert_eq!(view.is_pre(), pre, "is_pre for {name} ({:?})", meta.phase);
            assert_eq!(
                view.is_post(),
                post,
                "is_post for {name} ({:?})",
                meta.phase
            );
        }
    }

    /// A name that spells a phase without being registered under one
    /// reports neither half.
    #[test]
    fn a_name_merely_spelling_a_phase_carries_none() {
        let msg = make_test_message();
        for name in ["host.express_lane", "cmf.tool_pre_invoke_typo", "post_hoc"] {
            let views: Vec<_> = msg.iter_views(Some(name), None).collect();
            assert!(!views[0].is_pre(), "{name} must not read as pre-phase");
            assert!(!views[0].is_post(), "{name} must not read as post-phase");
        }
    }

    #[test]
    fn test_view_type_helpers() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert!(views[0].is_text()); // thinking
        assert!(views[1].is_text()); // text
        assert!(views[2].is_tool()); // tool call
        assert!(views[3].is_resource()); // resource
    }

    #[test]
    fn test_view_mime_type() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, None).collect();
        assert_eq!(views[3].mime_type(), Some("text/csv"));
    }

    #[test]
    fn test_view_with_extensions() {
        use crate::extensions::{HttpExtension, SecurityExtension};
        use std::sync::Arc;

        let mut security = SecurityExtension::default();
        security.add_label("PII");

        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer tok");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            ..Default::default()
        };

        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();

        assert!(views[0].has_label("PII"));
        assert!(!views[0].has_label("HIPAA"));
        assert_eq!(views[0].get_header("Authorization"), Some("Bearer tok"));
    }

    #[test]
    fn test_to_dict_basic() {
        let msg = Message::text(Role::User, "Hello world");
        let views: Vec<_> = msg.iter_views(Some("llm_input"), None).collect();
        let dict = views[0].to_dict(true, false);

        assert_eq!(dict["kind"], "text");
        assert_eq!(dict["role"], "user");
        assert_eq!(dict["action"], "send");
        assert_eq!(dict["hook"], "llm_input");
        assert_eq!(dict["content"], "Hello world");
        assert_eq!(dict["size_bytes"], 11);
        assert_eq!(dict["is_pre"], false);
        assert_eq!(dict["is_post"], false);
    }

    #[test]
    fn test_to_dict_tool_call() {
        let msg = make_test_message();
        let views: Vec<_> = msg.iter_views(Some("cmf.tool_pre_invoke"), None).collect();
        let dict = views[2].to_dict(true, false); // tool call

        assert_eq!(dict["kind"], "tool_call");
        assert_eq!(dict["name"], "get_weather");
        assert_eq!(dict["uri"], "tool://_/get_weather");
        assert_eq!(dict["action"], "execute");
        assert_eq!(dict["is_pre"], true);
        assert!(dict["arguments"].is_object());
        assert_eq!(dict["arguments"]["city"], "London");
    }

    #[test]
    fn test_to_dict_without_content() {
        let msg = Message::text(Role::User, "Secret message");
        let views: Vec<_> = msg.iter_views(None, None).collect();
        let dict = views[0].to_dict(false, false);

        assert!(dict.get("content").is_none());
        assert!(dict.get("size_bytes").is_none());
    }

    #[test]
    fn test_to_dict_with_extensions() {
        use crate::extensions::{
            AgentExtension, HttpExtension, RequestExtension, SecurityExtension,
        };
        use std::sync::Arc;

        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.subject = Some(crate::extensions::security::SubjectExtension {
            id: Some("alice".into()),
            subject_type: Some(crate::extensions::security::SubjectType::User),
            roles: ["admin".to_owned()].into(),
            ..Default::default()
        });

        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer secret");
        http.set_header("X-Request-ID", "req-123");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            request: Some(Arc::new(RequestExtension {
                environment: Some("production".into()),
                ..Default::default()
            })),
            agent: Some(Arc::new(AgentExtension {
                session_id: Some("sess-001".into()),
                agent_id: Some("agent-x".into()),
                ..Default::default()
            })),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                tags: ["pii".to_owned()].into(),
                ..Default::default()
            })),
            ..Default::default()
        };

        let msg = Message::text(Role::User, "test");
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();
        let dict = views[0].to_dict(true, true);

        let extensions = &dict["extensions"];

        // Subject visible
        assert_eq!(extensions["subject"]["id"], "alice");
        assert!(
            extensions["subject"]["roles"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("admin"))
        );

        // Labels visible
        assert!(
            extensions["labels"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("PII"))
        );

        // Environment visible
        assert_eq!(extensions["environment"], "production");

        // Headers visible — but Authorization stripped (sensitive)
        assert!(extensions["headers"].get("Authorization").is_none());
        assert_eq!(extensions["headers"]["X-Request-ID"], "req-123");

        // Agent context visible
        assert_eq!(extensions["agent"]["session_id"], "sess-001");
        assert_eq!(extensions["agent"]["agent_id"], "agent-x");

        // Meta visible
        assert_eq!(extensions["meta"]["entity_type"], "tool");
        assert_eq!(extensions["meta"]["entity_name"], "get_compensation");
    }

    #[test]
    fn test_to_opa_input() {
        let msg = Message::text(Role::User, "Hello");
        let views: Vec<_> = msg.iter_views(None, None).collect();
        let opa = views[0].to_opa_input(true);

        assert!(opa.get("input").is_some());
        assert_eq!(opa["input"]["kind"], "text");
        assert_eq!(opa["input"]["role"], "user");
        assert_eq!(opa["input"]["content"], "Hello");
    }

    // ---- ViewKind classification ------------------------------------------

    /// Every `ContentType` has to reach a distinct `ViewKind`. The mapping is
    /// what a policy condition dispatches on, so two content types collapsing to
    /// one kind would make them indistinguishable to a rule.
    #[test]
    fn every_content_type_maps_to_a_distinct_view_kind() {
        let pairs = [
            (ContentType::Text, ViewKind::Text),
            (ContentType::Thinking, ViewKind::Thinking),
            (ContentType::ToolCall, ViewKind::ToolCall),
            (ContentType::ToolResult, ViewKind::ToolResult),
            (ContentType::Resource, ViewKind::Resource),
            (ContentType::ResourceRef, ViewKind::ResourceRef),
            (ContentType::PromptRequest, ViewKind::PromptRequest),
            (ContentType::PromptResult, ViewKind::PromptResult),
            (ContentType::Image, ViewKind::Image),
            (ContentType::Video, ViewKind::Video),
            (ContentType::Audio, ViewKind::Audio),
            (ContentType::Document, ViewKind::Document),
        ];
        let mut seen = std::collections::HashSet::new();
        for (ct, expected) in pairs {
            let got = ViewKind::from_content_type(ct);
            assert_eq!(got, expected, "{ct:?} mapped to {got:?}");
            assert!(
                seen.insert(got),
                "{got:?} was produced by two content types"
            );
        }
    }

    /// The classification predicates group kinds for rules like "redact any
    /// media part". Each has to claim its own group and nothing else, or a rule
    /// scoped to one family would silently cover another.
    #[test]
    fn the_kind_predicates_partition_the_kinds_they_claim() {
        let all = [
            ViewKind::Text,
            ViewKind::Thinking,
            ViewKind::ToolCall,
            ViewKind::ToolResult,
            ViewKind::Resource,
            ViewKind::ResourceRef,
            ViewKind::PromptRequest,
            ViewKind::PromptResult,
            ViewKind::Image,
            ViewKind::Video,
            ViewKind::Audio,
            ViewKind::Document,
        ];
        for kind in all {
            let expect_text = matches!(kind, ViewKind::Text | ViewKind::Thinking);
            let expect_tool = matches!(kind, ViewKind::ToolCall | ViewKind::ToolResult);
            let expect_resource = matches!(kind, ViewKind::Resource | ViewKind::ResourceRef);
            let expect_prompt = matches!(kind, ViewKind::PromptRequest | ViewKind::PromptResult);
            let expect_media = matches!(
                kind,
                ViewKind::Image | ViewKind::Video | ViewKind::Audio | ViewKind::Document
            );
            assert_eq!(kind.is_text(), expect_text, "is_text on {kind:?}");
            assert_eq!(kind.is_tool(), expect_tool, "is_tool on {kind:?}");
            assert_eq!(
                kind.is_resource(),
                expect_resource,
                "is_resource on {kind:?}"
            );
            assert_eq!(kind.is_prompt(), expect_prompt, "is_prompt on {kind:?}");
            assert_eq!(kind.is_media(), expect_media, "is_media on {kind:?}");

            // Exactly one family claims each kind.
            let claims = [
                expect_text,
                expect_tool,
                expect_resource,
                expect_prompt,
                expect_media,
            ]
            .iter()
            .filter(|c| **c)
            .count();
            assert_eq!(claims, 1, "{kind:?} is claimed by {claims} families");
        }
    }

    // ---- view accessors ---------------------------------------------------

    /// The accessors are the read surface a policy uses. Several had no caller,
    /// so nothing checked they report the part they were built from.
    #[test]
    fn a_view_reports_the_part_role_and_hook_it_was_built_from() {
        let msg = make_test_message();
        let part = &msg.content[2]; // the ToolCall
        let view = MessageView::new(part, Role::Assistant, Some("cmf.tool_pre_invoke"), None);

        assert_eq!(view.kind(), ViewKind::ToolCall);
        assert_eq!(view.role(), Role::Assistant);
        assert_eq!(view.hook(), Some("cmf.tool_pre_invoke"));
        assert_eq!(view.name(), Some("get_weather"));
        assert_eq!(view.action(), ViewAction::Execute);
        assert!(view.is_tool());
        assert!(!view.is_media());
        assert!(
            matches!(view.raw(), ContentPart::ToolCall { .. }),
            "raw() must hand back the same part"
        );
        assert!(
            view.extensions().is_none(),
            "no extensions were supplied, so none are reported"
        );
    }

    #[test]
    fn tool_call_arguments_are_readable_through_the_view() {
        let msg = make_test_message();
        let view = MessageView::new(&msg.content[2], Role::Assistant, None, None);
        assert_eq!(view.get_arg("city"), Some(&serde_json::json!("London")));
        assert!(view.has_arg("city"));
        assert!(!view.has_arg("country"), "an absent arg must report absent");
        assert!(
            view.get_arg("country").is_none(),
            "an absent arg has no value"
        );
    }

    /// A view over a part with no hook reports none rather than a placeholder,
    /// since the phase helpers branch on it.
    #[test]
    fn a_view_with_no_hook_reports_no_hook() {
        let msg = make_test_message();
        let view = MessageView::new(&msg.content[1], Role::Assistant, None, None);
        assert_eq!(view.hook(), None);
        assert!(view.is_text());
    }

    /// `Debug` on a view exists so a failing assertion prints something useful.
    #[test]
    fn a_view_is_debug_printable() {
        let msg = make_test_message();
        let view = MessageView::new(&msg.content[1], Role::Assistant, None, None);
        let s = format!("{view:?}");
        assert!(s.contains("MessageView"), "{s}");
    }

    // ---- every content variant --------------------------------------------

    /// One of each `ContentPart`, paired with the `ContentType` that names it.
    ///
    /// The accessors below match on the variant and fall through to `_ => None`.
    /// A variant nobody constructs therefore reads as "no name, no uri, no mime"
    /// without failing to compile, and a rule scoped to it silently matches
    /// nothing. Building all twelve is what makes those arms assert anything.
    fn one_of_each_variant() -> Vec<(ContentType, ContentPart)> {
        vec![
            (
                ContentType::Text,
                ContentPart::Text {
                    text: "plain".into(),
                },
            ),
            (
                ContentType::Thinking,
                ContentPart::Thinking {
                    text: "reasoning".into(),
                },
            ),
            (
                ContentType::ToolCall,
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_1".into(),
                        name: "transfer".into(),
                        arguments: [("amount".to_owned(), serde_json::json!(10))].into(),
                        namespace: None,
                    },
                },
            ),
            (
                ContentType::ToolResult,
                ContentPart::ToolResult {
                    content: ToolResult {
                        tool_call_id: "tc_1".into(),
                        tool_name: "transfer".into(),
                        content: serde_json::json!("moved 10"),
                        is_error: false,
                    },
                },
            ),
            (
                ContentType::Resource,
                ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "rr_1".into(),
                        uri: "file:///ledger.csv".into(),
                        name: Some("Ledger".into()),
                        content: Some("a,b".into()),
                        mime_type: Some("text/csv".into()),
                        ..Default::default()
                    },
                },
            ),
            (
                ContentType::ResourceRef,
                ContentPart::ResourceRef {
                    content: crate::cmf::content::ResourceReference {
                        resource_request_id: "rr_2".into(),
                        uri: "file:///pointer.txt".into(),
                        name: Some("Pointer".into()),
                        resource_type: crate::cmf::enums::ResourceType::File,
                        range_start: None,
                        range_end: None,
                        selector: None,
                    },
                },
            ),
            (
                ContentType::PromptRequest,
                ContentPart::PromptRequest {
                    content: crate::cmf::content::PromptRequest {
                        prompt_request_id: "pr_1".into(),
                        name: "summarize".into(),
                        arguments: [("tone".to_owned(), serde_json::json!("terse"))].into(),
                        server_id: None,
                    },
                },
            ),
            (
                ContentType::PromptResult,
                ContentPart::PromptResult {
                    content: crate::cmf::content::PromptResult {
                        prompt_request_id: "pr_1".into(),
                        prompt_name: "summarize".into(),
                        messages: vec![],
                        content: Some("a summary".into()),
                        is_error: false,
                        error_message: None,
                    },
                },
            ),
            (
                ContentType::Image,
                ContentPart::Image {
                    content: crate::cmf::content::ImageSource {
                        source_type: "base64".into(),
                        data: "AAAA".into(),
                        media_type: Some("image/png".into()),
                    },
                },
            ),
            (
                ContentType::Video,
                ContentPart::Video {
                    content: crate::cmf::content::VideoSource {
                        source_type: "base64".into(),
                        data: "BBBB".into(),
                        media_type: Some("video/mp4".into()),
                        duration_ms: Some(1_000),
                    },
                },
            ),
            (
                ContentType::Audio,
                ContentPart::Audio {
                    content: crate::cmf::content::AudioSource {
                        source_type: "base64".into(),
                        data: "CCCC".into(),
                        media_type: Some("audio/mpeg".into()),
                        duration_ms: Some(2_000),
                    },
                },
            ),
            (
                ContentType::Document,
                ContentPart::Document {
                    content: crate::cmf::content::DocumentSource {
                        source_type: "base64".into(),
                        data: "DDDD".into(),
                        media_type: Some("application/pdf".into()),
                        title: Some("Report".into()),
                    },
                },
            ),
        ]
    }

    /// `MessageView::new` matches on the variant to pick a kind, and
    /// `ViewKind::from_content_type` maps the type tag to the same kind. They are
    /// two hand-written twelve-arm tables for one relationship, so they can
    /// disagree. If they do, a part deserialized as one type would evaluate under
    /// another kind's rules. This asserts they agree on every variant.
    #[test]
    fn the_two_kind_mappings_agree_on_every_variant() {
        for (ct, part) in one_of_each_variant() {
            let from_part = MessageView::new(&part, Role::Assistant, None, None).kind();
            let from_type = ViewKind::from_content_type(ct);
            assert_eq!(
                from_part, from_type,
                "{ct:?}: the part maps to {from_part:?} but the type tag maps to {from_type:?}"
            );
        }
    }

    /// What each variant exposes as text, name, uri and mime type. These four
    /// feed `content contains`, `name ==`, `uri startswith` and `mime_type ==`
    /// conditions, so a wrong `None` makes a rule quietly match nothing.
    #[test]
    fn each_variant_exposes_the_fields_a_rule_can_match_on() {
        // (content, name, uri, mime_type) expected per variant, in the order
        // `one_of_each_variant` returns them.
        let expected: [(Option<&str>, Option<&str>, Option<&str>, Option<&str>); 12] = [
            (Some("plain"), None, None, None),
            (Some("reasoning"), None, None, None),
            (None, Some("transfer"), Some("tool://_/transfer"), None),
            (Some("moved 10"), Some("transfer"), None, None),
            (
                Some("a,b"),
                Some("Ledger"),
                Some("file:///ledger.csv"),
                Some("text/csv"),
            ),
            (None, Some("Pointer"), Some("file:///pointer.txt"), None),
            (None, Some("summarize"), Some("prompt://_/summarize"), None),
            (Some("a summary"), Some("summarize"), None, None),
            (None, None, None, Some("image/png")),
            (None, None, None, Some("video/mp4")),
            (None, None, None, Some("audio/mpeg")),
            (None, None, None, Some("application/pdf")),
        ];

        for ((ct, part), (content, name, uri, mime)) in
            one_of_each_variant().into_iter().zip(expected)
        {
            let view = MessageView::new(&part, Role::Assistant, None, None);
            assert_eq!(view.content(), content, "content() on {ct:?}");
            assert_eq!(view.name(), name, "name() on {ct:?}");
            assert_eq!(view.uri().as_deref(), uri, "uri() on {ct:?}");
            assert_eq!(view.mime_type(), mime, "mime_type() on {ct:?}");
        }
    }

    /// Only tool calls and prompt requests carry arguments. Everything else has
    /// to report none rather than an empty map, because `has_arg` is how a rule
    /// asks whether a parameter was supplied at all.
    #[test]
    fn only_tool_calls_and_prompt_requests_carry_arguments() {
        for (ct, part) in one_of_each_variant() {
            let view = MessageView::new(&part, Role::Assistant, None, None);
            let expect_args = matches!(ct, ContentType::ToolCall | ContentType::PromptRequest);
            assert_eq!(view.args().is_some(), expect_args, "args() on {ct:?}");
        }
    }

    /// A resource whose `name` is unset falls back to its uri, so `name ==` has
    /// something to match either way. The fallback is per-variant, so both
    /// resource kinds are checked.
    #[test]
    fn a_resource_with_no_name_falls_back_to_its_uri() {
        let res = ContentPart::Resource {
            content: Resource {
                resource_request_id: "rr".into(),
                uri: "file:///anon.bin".into(),
                name: None,
                ..Default::default()
            },
        };
        let view = MessageView::new(&res, Role::Assistant, None, None);
        assert_eq!(view.name(), Some("file:///anon.bin"));

        let reference = ContentPart::ResourceRef {
            content: crate::cmf::content::ResourceReference {
                resource_request_id: "rr".into(),
                uri: "file:///anon-ref.bin".into(),
                name: None,
                resource_type: crate::cmf::enums::ResourceType::File,
                range_start: None,
                range_end: None,
                selector: None,
            },
        };
        let view = MessageView::new(&reference, Role::Assistant, None, None);
        assert_eq!(view.name(), Some("file:///anon-ref.bin"));
    }

    /// A tool returning structured JSON has no text content, because `content()`
    /// only unwraps a JSON string. A rule written as `content contains "..."`
    /// therefore cannot inspect an object result, which is worth pinning: it is a
    /// real gap in what such a rule can see, not an accident of this test.
    #[test]
    fn a_tool_result_holding_an_object_exposes_no_text_content() {
        let structured = ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: "tc".into(),
                tool_name: "lookup".into(),
                content: serde_json::json!({"ssn": "123-45-6789"}),
                is_error: false,
            },
        };
        let view = MessageView::new(&structured, Role::Tool, None, None);
        assert_eq!(
            view.content(),
            None,
            "an object result exposes no text to match on"
        );

        let textual = ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: "tc".into(),
                tool_name: "lookup".into(),
                content: serde_json::json!("123-45-6789"),
                is_error: false,
            },
        };
        let view = MessageView::new(&textual, Role::Tool, None, None);
        assert_eq!(
            view.content(),
            Some("123-45-6789"),
            "a string result is the case that does expose text"
        );
    }

    /// `is_error` distinguishes a failed call from a successful one, which is
    /// what an audit rule keys on. Only the two result kinds can be errors;
    /// everything else must report false rather than inheriting a default.
    #[test]
    fn only_result_kinds_can_report_an_error() {
        for (ct, part) in one_of_each_variant() {
            let view = MessageView::new(&part, Role::Assistant, None, None);
            assert!(
                !view.is_error(),
                "{ct:?} was built as a success and must not report an error"
            );
        }

        let failed_tool = ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: "tc".into(),
                tool_name: "transfer".into(),
                content: serde_json::json!("denied"),
                is_error: true,
            },
        };
        assert!(
            MessageView::new(&failed_tool, Role::Tool, None, None).is_error(),
            "a failed tool result must report an error"
        );

        let failed_prompt = ContentPart::PromptResult {
            content: crate::cmf::content::PromptResult {
                prompt_request_id: "pr".into(),
                prompt_name: "summarize".into(),
                messages: vec![],
                content: None,
                is_error: true,
                error_message: Some("template missing".into()),
            },
        };
        assert!(
            MessageView::new(&failed_prompt, Role::Assistant, None, None).is_error(),
            "a failed prompt result must report an error"
        );
    }

    /// The view's type helpers delegate to the kind's, so they have to agree.
    /// Checked over every variant because the delegation is one method per
    /// family and a single wrong forward would misclassify one family only.
    #[test]
    fn the_view_type_helpers_agree_with_the_kind_they_delegate_to() {
        for (ct, part) in one_of_each_variant() {
            let view = MessageView::new(&part, Role::Assistant, None, None);
            let kind = view.kind();
            assert_eq!(view.is_tool(), kind.is_tool(), "is_tool on {ct:?}");
            assert_eq!(view.is_resource(), kind.is_resource(), "is_resource {ct:?}");
            assert_eq!(view.is_prompt(), kind.is_prompt(), "is_prompt on {ct:?}");
            assert_eq!(view.is_media(), kind.is_media(), "is_media on {ct:?}");
            assert_eq!(view.is_text(), kind.is_text(), "is_text on {ct:?}");
        }
    }

    // ---- the action matrix ------------------------------------------------

    /// `action()` is what an `action == "execute"` rule matches. Six kinds fix
    /// their action; the other six derive it from the message role, so each cell
    /// is a separate arm. A wrong cell silently rescopes every rule written
    /// against that action.
    #[test]
    fn the_action_matrix_is_fixed_for_entity_kinds_and_directional_otherwise() {
        let fixed = [
            (ViewKind::ToolCall, ViewAction::Execute),
            (ViewKind::ToolResult, ViewAction::Receive),
            (ViewKind::Resource, ViewAction::Read),
            (ViewKind::ResourceRef, ViewAction::Read),
            (ViewKind::PromptRequest, ViewAction::Invoke),
            (ViewKind::PromptResult, ViewAction::Receive),
        ];
        let roles = [
            Role::User,
            Role::Assistant,
            Role::Tool,
            Role::System,
            Role::Developer,
        ];

        for (kind, expected) in fixed {
            for role in roles {
                assert_eq!(
                    kind.default_action(role),
                    expected,
                    "{kind:?} must be {expected:?} regardless of role, got role {role:?}"
                );
            }
        }

        // The directional kinds: the role decides.
        let directional = [
            ViewKind::Text,
            ViewKind::Thinking,
            ViewKind::Image,
            ViewKind::Video,
            ViewKind::Audio,
            ViewKind::Document,
        ];
        let by_role = [
            (Role::User, ViewAction::Send),
            (Role::Assistant, ViewAction::Generate),
            (Role::Tool, ViewAction::Receive),
            (Role::System, ViewAction::Write),
            (Role::Developer, ViewAction::Write),
        ];
        for kind in directional {
            for (role, expected) in by_role {
                assert_eq!(
                    kind.default_action(role),
                    expected,
                    "{kind:?} as {role:?} must be {expected:?}"
                );
            }
        }
    }

    // ---- the context projection -------------------------------------------

    /// Everything `to_dict` can emit, emitted at once.
    ///
    /// Each optional field is its own `if let`, so a field nobody populates in a
    /// test is a field that could be dropped from the projection without any
    /// test noticing. A rule referencing it would then never match. The existing
    /// extensions test leaves permissions, teams, four agent fields and the meta
    /// tags unset; this sets all of them.
    #[test]
    fn to_dict_emits_every_context_field_it_is_given() {
        use std::sync::Arc;

        use crate::extensions::{
            AgentExtension, HttpExtension, RequestExtension, SecurityExtension,
        };

        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.add_label("CONFIDENTIAL");
        security.subject = Some(crate::extensions::security::SubjectExtension {
            id: Some("alice".into()),
            subject_type: Some(crate::extensions::security::SubjectType::User),
            roles: ["admin".to_owned(), "auditor".to_owned()].into(),
            permissions: ["ledger:read".to_owned(), "ledger:write".to_owned()].into(),
            teams: ["finance".to_owned(), "platform".to_owned()].into(),
            // Listed rather than filled by `..Default::default()` so that adding
            // a subject field breaks this test, which is the prompt to decide
            // whether a policy should be able to see it. `claims` deliberately
            // is not projected: it holds raw token claims.
            claims: std::collections::HashMap::new(),
        });

        let mut http = HttpExtension::default();
        http.set_header("X-Request-ID", "req-9");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            request: Some(Arc::new(RequestExtension {
                environment: Some("staging".into()),
                ..Default::default()
            })),
            agent: Some(Arc::new(AgentExtension {
                input: Some("move the money".into()),
                session_id: Some("sess-1".into()),
                conversation_id: Some("conv-1".into()),
                turn: Some(7),
                agent_id: Some("agent-a".into()),
                parent_agent_id: Some("agent-root".into()),
                ..Default::default()
            })),
            meta: Some(Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("transfer".into()),
                tags: ["pii".to_owned(), "financial".to_owned()].into(),
                ..Default::default()
            })),
            ..Default::default()
        };

        let part = ContentPart::Resource {
            content: Resource {
                resource_request_id: "rr".into(),
                uri: "file:///ledger.csv".into(),
                name: Some("Ledger".into()),
                content: Some("a,b".into()),
                mime_type: Some("text/csv".into()),
                ..Default::default()
            },
        };
        let view = MessageView::new(
            &part,
            Role::User,
            Some("cmf.resource_pre_fetch"),
            Some(&ext),
        );
        let dict = view.to_dict(true, true);

        // Core fields, including the mime type only a resource or media part has.
        assert_eq!(dict["kind"], "resource");
        assert_eq!(dict["role"], "user");
        assert_eq!(dict["action"], "read");
        assert_eq!(dict["hook"], "cmf.resource_pre_fetch");
        assert_eq!(dict["is_pre"], true);
        assert_eq!(dict["is_post"], false);
        assert_eq!(dict["uri"], "file:///ledger.csv");
        assert_eq!(dict["name"], "Ledger");
        assert_eq!(dict["mime_type"], "text/csv");
        assert_eq!(dict["content"], "a,b");
        assert_eq!(dict["size_bytes"], 3);

        let sub = &dict["extensions"]["subject"];
        assert_eq!(sub["id"], "alice");
        assert_eq!(sub["type"], "user");

        // The three subject collections are sorted on the way out, so a policy
        // comparing against a literal list has a stable order to match.
        assert_eq!(
            sub["roles"],
            serde_json::json!(["admin", "auditor"]),
            "roles must be present and sorted"
        );
        assert_eq!(
            sub["permissions"],
            serde_json::json!(["ledger:read", "ledger:write"]),
            "permissions must be present and sorted"
        );
        assert_eq!(
            sub["teams"],
            serde_json::json!(["finance", "platform"]),
            "teams must be present and sorted"
        );
        assert_eq!(
            dict["extensions"]["labels"],
            serde_json::json!(["CONFIDENTIAL", "PII"]),
            "labels must be present and sorted"
        );
        assert_eq!(dict["extensions"]["environment"], "staging");
        assert_eq!(dict["extensions"]["headers"]["X-Request-ID"], "req-9");

        let agent = &dict["extensions"]["agent"];
        assert_eq!(agent["input"], "move the money");
        assert_eq!(agent["session_id"], "sess-1");
        assert_eq!(agent["conversation_id"], "conv-1");
        assert_eq!(agent["turn"], 7);
        assert_eq!(agent["agent_id"], "agent-a");
        assert_eq!(agent["parent_agent_id"], "agent-root");

        let meta = &dict["extensions"]["meta"];
        assert_eq!(meta["entity_type"], "tool");
        assert_eq!(meta["entity_name"], "transfer");
        assert_eq!(
            meta["tags"],
            serde_json::json!(["financial", "pii"]),
            "tags must be present and sorted"
        );
    }

    /// Sensitive headers are stripped before the projection leaves the process.
    /// For a remote PDP that projection crosses the network, so a leak here
    /// hands a bearer token to a third party. The filter lowercases the header
    /// name, and headers arrive in whatever case the client sent, so the
    /// canonical spellings are not enough on their own.
    #[test]
    fn sensitive_headers_are_stripped_whatever_their_case() {
        use std::sync::Arc;

        use crate::extensions::HttpExtension;

        let mut http = HttpExtension::default();
        for name in [
            "Authorization",
            "authorization",
            "AUTHORIZATION",
            "Cookie",
            "COOKIE",
            "X-API-Key",
            "x-api-key",
        ] {
            http.set_header(name, "secret");
        }
        http.set_header("X-Request-ID", "req-1");

        let ext = Extensions {
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        let msg = Message::text(Role::User, "hello");
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();
        let dict = views[0].to_dict(true, true);
        let headers = &dict["extensions"]["headers"];

        let leaked: Vec<&String> = headers
            .as_object()
            .expect("headers must be an object")
            .keys()
            .filter(|k| {
                let k = k.to_lowercase();
                k == "authorization" || k == "cookie" || k == "x-api-key"
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "these headers must never reach a PDP: {leaked:?}"
        );
        assert_eq!(
            headers["X-Request-ID"], "req-1",
            "a non-sensitive header must still be projected, or this test would \
             pass with the whole header map dropped"
        );
    }

    /// With no context requested, nothing from the extensions is projected even
    /// though they are attached. This is the flag a caller uses to keep subject
    /// and header data out of a remote PDP request.
    #[test]
    fn withholding_context_drops_the_extensions_entirely() {
        use std::sync::Arc;

        use crate::extensions::{HttpExtension, SecurityExtension};

        let mut security = SecurityExtension::default();
        security.add_label("PII");
        let mut http = HttpExtension::default();
        http.set_header("X-Request-ID", "req-1");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        let msg = Message::text(Role::User, "hello");
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();

        assert!(
            views[0].to_dict(true, false).get("extensions").is_none(),
            "include_context = false must withhold the whole block"
        );
        assert!(
            views[0].to_dict(true, true).get("extensions").is_some(),
            "and the same view with context on must include it, or the \
             assertion above proves nothing"
        );
    }

    /// Extensions that hold nothing produce no `extensions` key rather than an
    /// empty object, so a rule testing for the key's presence is not misled.
    #[test]
    fn empty_extensions_produce_no_extensions_key() {
        let ext = Extensions::default();
        let msg = Message::text(Role::User, "hello");
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();
        let dict = views[0].to_dict(true, true);
        assert!(
            dict.get("extensions").is_none(),
            "an empty context must be absent, not an empty object: {dict}"
        );
    }

    /// A subject present but holding nothing is omitted for the same reason, and
    /// an http extension whose only headers are sensitive projects no headers
    /// key rather than an empty map.
    #[test]
    fn context_blocks_with_nothing_to_say_are_omitted() {
        use std::sync::Arc;

        use crate::extensions::{HttpExtension, SecurityExtension};

        let mut security = SecurityExtension::default();
        security.subject = Some(crate::extensions::security::SubjectExtension::default());
        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer secret");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        let msg = Message::text(Role::User, "hello");
        let views: Vec<_> = msg.iter_views(None, Some(&ext)).collect();
        let dict = views[0].to_dict(true, true);

        assert!(
            dict.get("extensions").is_none(),
            "an empty subject and an all-sensitive header map leave nothing to \
             project: {dict}"
        );
    }
}
