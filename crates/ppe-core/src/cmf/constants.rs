// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// CMF constants — schema version, serialization field names, and defaults.

/// Current CMF message schema version.
pub const SCHEMA_VERSION: &str = "2.0";

// Core view fields
/// Serialized field name `kind`.
pub const FIELD_KIND: &str = "kind";
/// Serialized field name `role`.
pub const FIELD_ROLE: &str = "role";
/// Serialized field name `is_pre`.
pub const FIELD_IS_PRE: &str = "is_pre";
/// Serialized field name `is_post`.
pub const FIELD_IS_POST: &str = "is_post";
/// Serialized field name `action`.
pub const FIELD_ACTION: &str = "action";
/// Serialized field name `hook`.
pub const FIELD_HOOK: &str = "hook";
/// Serialized field name `uri`.
pub const FIELD_URI: &str = "uri";
/// Serialized field name `name`.
pub const FIELD_NAME: &str = "name";
/// Serialized field name `content`.
pub const FIELD_CONTENT: &str = "content";
/// Serialized field name `size_bytes`.
pub const FIELD_SIZE_BYTES: &str = "size_bytes";
/// Serialized field name `mime_type`.
pub const FIELD_MIME_TYPE: &str = "mime_type";
/// Serialized field name `arguments`.
pub const FIELD_ARGUMENTS: &str = "arguments";

// Extensions container
/// Serialized field name `extensions`.
pub const FIELD_EXTENSIONS: &str = "extensions";

// Subject fields
/// Serialized field name `subject`.
pub const FIELD_SUBJECT: &str = "subject";
/// Serialized field name `id`.
pub const FIELD_ID: &str = "id";
/// Serialized field name `type`.
pub const FIELD_TYPE: &str = "type";
/// Serialized field name `roles`.
pub const FIELD_ROLES: &str = "roles";
/// Serialized field name `permissions`.
pub const FIELD_PERMISSIONS: &str = "permissions";
/// Serialized field name `teams`.
pub const FIELD_TEAMS: &str = "teams";

// Security fields
/// Serialized field name `labels`.
pub const FIELD_LABELS: &str = "labels";

// Request fields
/// Serialized field name `environment`.
pub const FIELD_ENVIRONMENT: &str = "environment";

// HTTP fields
/// Serialized field name `headers`.
pub const FIELD_HEADERS: &str = "headers";

// Agent fields
/// Serialized field name `agent`.
pub const FIELD_AGENT: &str = "agent";
/// Serialized field name `input`.
pub const FIELD_INPUT: &str = "input";
/// Serialized field name `session_id`.
pub const FIELD_SESSION_ID: &str = "session_id";
/// Serialized field name `conversation_id`.
pub const FIELD_CONVERSATION_ID: &str = "conversation_id";
/// Serialized field name `turn`.
pub const FIELD_TURN: &str = "turn";
/// Serialized field name `agent_id`.
pub const FIELD_AGENT_ID: &str = "agent_id";
/// Serialized field name `parent_agent_id`.
pub const FIELD_PARENT_AGENT_ID: &str = "parent_agent_id";

// Meta fields
/// Serialized field name `meta`.
pub const FIELD_META: &str = "meta";
/// Serialized field name `entity_type`.
pub const FIELD_ENTITY_TYPE: &str = "entity_type";
/// Serialized field name `entity_name`.
pub const FIELD_ENTITY_NAME: &str = "entity_name";
/// Serialized field name `tags`.
pub const FIELD_TAGS: &str = "tags";

// OPA envelope
/// Serialized field name `input`.
pub const FIELD_OPA_INPUT: &str = "input";

// Entity type identifiers — used in MetaExtension.entity_type and as the
// keys for `global.defaults` per-entity-type policy groups. These are the
// MCP entity taxonomy: tools (callable functions), LLMs (model
// invocations), prompts (template fills), resources (URI fetches).
/// Entity type `tool`.
pub const ENTITY_TOOL: &str = "tool";
/// Entity type `llm`.
pub const ENTITY_LLM: &str = "llm";
/// Entity type `prompt`.
pub const ENTITY_PROMPT: &str = "prompt";
/// Entity type `resource`.
pub const ENTITY_RESOURCE: &str = "resource";

/// Reserved entity type for generic (non-MCP/A2A) HTTP requests. The
/// catch-all `global` policy is dispatched under this entity so an
/// entity-less request can be authorized; hosts set `meta.entity_type` to
/// this and `meta.entity_name` to [`ENTITY_NAME_GLOBAL`].
pub const ENTITY_HTTP: &str = "http";

/// Reserved entity name for the global catch-all policy annotation.
pub const ENTITY_NAME_GLOBAL: &str = "*";

// CMF hook names — the canonical names plugins register under and hosts
// pass to `PolicyEngine::invoke_named::<CmfHook>(...)`. Two per entity
// type — pre-invocation (called from APL's policy / args phase) and
// post-invocation (called from APL's post_policy / result phase).
//
// Declared with `define_hooks!` so each name arrives with the routing
// metadata `hooks::metadata` needs. Plugin declarations name these
// strings in `hooks:`, and the config loader validates against the
// table these rows seed.
crate::define_hooks! {
    /// The CMF family's rows in the built-in hook metadata table.
    CMF_HOOK_METADATA;

    /// Hook name `cmf.tool_pre_invoke`.
    HOOK_CMF_TOOL_PRE_INVOKE: "cmf.tool_pre_invoke" => entity: Some(ENTITY_TOOL), phase: Pre;
    /// Hook name `cmf.tool_post_invoke`.
    HOOK_CMF_TOOL_POST_INVOKE: "cmf.tool_post_invoke" => entity: Some(ENTITY_TOOL), phase: Post;
    /// Hook name `cmf.llm_input`.
    HOOK_CMF_LLM_INPUT: "cmf.llm_input" => entity: Some(ENTITY_LLM), phase: Pre;
    /// Hook name `cmf.llm_output`.
    HOOK_CMF_LLM_OUTPUT: "cmf.llm_output" => entity: Some(ENTITY_LLM), phase: Post;
    /// Hook name `cmf.prompt_pre_invoke`.
    HOOK_CMF_PROMPT_PRE_INVOKE: "cmf.prompt_pre_invoke" => entity: Some(ENTITY_PROMPT), phase: Pre;
    /// Hook name `cmf.prompt_post_invoke`.
    HOOK_CMF_PROMPT_POST_INVOKE: "cmf.prompt_post_invoke" => entity: Some(ENTITY_PROMPT), phase: Post;
    /// Hook name `cmf.resource_pre_fetch`.
    HOOK_CMF_RESOURCE_PRE_FETCH: "cmf.resource_pre_fetch" => entity: Some(ENTITY_RESOURCE), phase: Pre;
    /// Hook name `cmf.resource_post_fetch`.
    HOOK_CMF_RESOURCE_POST_FETCH: "cmf.resource_post_fetch" => entity: Some(ENTITY_RESOURCE), phase: Post;

    /// Generic HTTP request hook, fired for non-MCP/A2A HTTP requests on
    /// the way in. The catch-all `global` policy (if any) is annotated
    /// under it via [`ENTITY_HTTP`] / [`ENTITY_NAME_GLOBAL`]. This half
    /// carries authorization, which is an admission check and so belongs
    /// entirely before the request is forwarded.
    HOOK_CMF_HTTP_REQUEST: "cmf.http_request" => entity: Some(ENTITY_HTTP), phase: Pre;
    /// Generic HTTP response hook, the return half of
    /// [`HOOK_CMF_HTTP_REQUEST`]. Authorization cannot live here, but
    /// response filtering can: a handler reads the response headers and
    /// the extensions, which covers stripping a header, enforcing a
    /// content type, and attaching labels. Not body redaction, since
    /// [`HttpExtension`][crate::extensions::http::HttpExtension] carries
    /// no body and the payload on this path is unused. A host that only
    /// authorizes never fires it, and nothing changes for it.
    HOOK_CMF_HTTP_RESPONSE: "cmf.http_response" => entity: Some(ENTITY_HTTP), phase: Post;
}
