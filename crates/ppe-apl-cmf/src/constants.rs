// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// String constants used across praxis-policy-apl-cmf — capability names praxis-policy-core
// recognizes for `filter_extensions`, plus the bag-attribute
// prefixes APL extractors write under. Centralizing both makes the
// capability → bag namespace mapping in `capability_namespaces` a
// straight reference rather than a soup of inline strings, and
// gives operators / docs / tools one canonical place to read them
// from.
//
// # Source-of-truth invariants
//
// * `CAP_*` names match `praxis_policy_core::extensions::filter::filter_extensions`
//   verbatim. praxis-policy-core is authoritative — if it changes a cap name,
//   bump here and update the mapping table.
// * `BAG_*` prefixes match what the per-extension extractor modules
//   (`security.rs`, `delegation.rs`, etc.) actually write into the
//   bag. The extractor files still use string literals today; a
//   future cleanup can refactor them to consume these constants to
//   prevent drift. Tests in `capability_namespaces` flag the
//   contract.

/// Capability permitting a plugin to read subject identity.
pub const CAP_READ_SUBJECT: &str = "read_subject";
/// Capability permitting a plugin to read role membership.
pub const CAP_READ_ROLES: &str = "read_roles";
/// Capability permitting a plugin to read permissions.
pub const CAP_READ_PERMISSIONS: &str = "read_permissions";
/// Capability permitting a plugin to read team membership.
pub const CAP_READ_TEAMS: &str = "read_teams";
/// Capability permitting a plugin to read raw token claims.
pub const CAP_READ_CLAIMS: &str = "read_claims";

/// Capability permitting a plugin to read session security labels.
pub const CAP_READ_LABELS: &str = "read_labels";
/// Capability permitting a plugin to read the OAuth client.
pub const CAP_READ_CLIENT: &str = "read_client";
/// Capability permitting a plugin to read workload identity.
pub const CAP_READ_WORKLOAD: &str = "read_workload";

/// Capability permitting a plugin to read the raw inbound token.
pub const CAP_READ_INBOUND_CREDENTIALS: &str = "read_inbound_credentials";
/// Capability permitting a plugin to read minted delegated tokens.
pub const CAP_READ_DELEGATED_TOKENS: &str = "read_delegated_tokens";

/// Capability permitting a plugin to read the delegation chain.
pub const CAP_READ_DELEGATION: &str = "read_delegation";
/// Capability permitting a plugin to read agent session and lineage.
pub const CAP_READ_AGENT: &str = "read_agent";
/// Capability permitting a plugin to read host operational metadata.
pub const CAP_READ_META: &str = "read_meta";
/// Capability permitting a plugin to read request environment.
pub const CAP_READ_REQUEST: &str = "read_request";
/// Capability permitting a plugin to read HTTP headers.
pub const CAP_READ_HEADERS: &str = "read_headers";
/// Capability permitting a plugin to read model identity.
pub const CAP_READ_LLM: &str = "read_llm";
/// Capability permitting a plugin to read tool and resource metadata.
pub const CAP_READ_MCP: &str = "read_mcp";
/// Capability permitting a plugin to read completion metadata.
pub const CAP_READ_COMPLETION: &str = "read_completion";
/// Capability permitting a plugin to read message origin.
pub const CAP_READ_PROVENANCE: &str = "read_provenance";
/// Capability permitting a plugin to read framework context.
pub const CAP_READ_FRAMEWORK: &str = "read_framework";
/// Capability permitting a plugin to read host-supplied custom values.
pub const CAP_READ_CUSTOM: &str = "read_custom";

/// Capability permitting a plugin to append to session security labels.
pub const CAP_APPEND_LABELS: &str = "append_labels";
/// Capability permitting a plugin to append to the delegation chain.
pub const CAP_APPEND_DELEGATION: &str = "append_delegation";
/// Capability permitting a plugin to write HTTP headers.
pub const CAP_WRITE_HEADERS: &str = "write_headers";

// Bag-attribute prefixes (and exact-match keys) — must match what
// the praxis-policy-apl-cmf extractor modules write.
//
// Prefixes ending in `.` match any key starting with them
// (e.g. `BAG_ROLE_PREFIX` matches `role.hr`, `role.admin`).
// Prefixes WITHOUT a trailing `.` match the exact bag key
// (e.g. `BAG_AUTHENTICATED` matches only `authenticated`).
/// Bag key `subject.id`.
pub const BAG_SUBJECT_ID: &str = "subject.id";
/// Bag key `subject.type`.
pub const BAG_SUBJECT_TYPE: &str = "subject.type";
/// Bag key `subject.teams`.
pub const BAG_SUBJECT_TEAMS: &str = "subject.teams";
/// Bag key `subject.roles` — the full role set, mirroring the
/// flattened `role.<name>` keys as one `StringSet` for `in`/`contains`
/// membership tests (e.g. OPA `"hr" in input.subject.roles`).
pub const BAG_SUBJECT_ROLES: &str = "subject.roles";
/// Bag key `subject.permissions` — the full permission set, mirroring
/// the flattened `perm.<name>` keys as one `StringSet`.
pub const BAG_SUBJECT_PERMISSIONS: &str = "subject.permissions";
/// Bag key `authenticated`.
pub const BAG_AUTHENTICATED: &str = "authenticated";
/// Key prefix for role, as in `role.<name>`.
pub const BAG_ROLE_PREFIX: &str = "role.";
/// Key prefix for perm, as in `perm.<name>`.
pub const BAG_PERM_PREFIX: &str = "perm.";
/// Key prefix for team, as in `team.<name>`.
pub const BAG_TEAM_PREFIX: &str = "team.";
/// Key prefix for claim, as in `claim.<name>`.
pub const BAG_CLAIM_PREFIX: &str = "claim.";

// Payload (args / result).
//
// These are the dotted-prefix forms used when praxis-policy-apl-cmf::payload flattens
// the request's args object and the upstream's result object into the
// bag. APL predicates / Cedar `${args.X}` substitutions / OPA `input.X`
// paths all resolve through these.
/// Key prefix for args, as in `args.<name>`.
pub const BAG_ARGS_PREFIX: &str = "args.";
/// Key prefix for result, as in `result.<name>`.
pub const BAG_RESULT_PREFIX: &str = "result.";

/// Key prefix for the OAuth client, as in `client.<name>`.
pub const BAG_CLIENT_PREFIX: &str = "client.";
/// Bag key `client.roles` — the client's full role set, mirroring the
/// flattened `client.role.<name>` keys as one `StringSet`. Symmetric
/// with [`BAG_SUBJECT_ROLES`] so the same membership idiom works on
/// either principal.
pub const BAG_CLIENT_ROLES: &str = "client.roles";
/// Bag key `client.permissions` — the client's full permission set,
/// mirroring the flattened `client.perm.<name>` keys as one `StringSet`.
pub const BAG_CLIENT_PERMISSIONS: &str = "client.permissions";
/// Key prefix for workload identity, as in `workload.<name>`.
pub const BAG_WORKLOAD_PREFIX: &str = "workload.";
/// Key prefix for caller workload, as in `caller_workload.<name>`.
pub const BAG_CALLER_WORKLOAD_PREFIX: &str = "caller_workload.";

/// Key prefix for the delegation chain, as in `delegation.<name>`.
pub const BAG_DELEGATION_PREFIX: &str = "delegation.";
/// Bag key `delegated`.
pub const BAG_DELEGATED: &str = "delegated";

/// Key prefix for agent session and lineage, as in `agent.<name>`.
pub const BAG_AGENT_PREFIX: &str = "agent.";
/// Key prefix for host operational metadata, as in `meta.<name>`.
pub const BAG_META_PREFIX: &str = "meta.";
/// Key prefix for request environment, as in `request.<name>`.
pub const BAG_REQUEST_PREFIX: &str = "request.";
/// Key prefix for http request headers, as in `http.request_headers.<name>`.
pub const BAG_HTTP_REQUEST_HEADERS_PREFIX: &str = "http.request_headers.";
/// Key prefix for http response headers, as in `http.response_headers.<name>`.
pub const BAG_HTTP_RESPONSE_HEADERS_PREFIX: &str = "http.response_headers.";
// HTTP request line — exact keys. These ride the same `read_headers`
// capability as headers (the whole `http` slot is gated together in
// `praxis-policy-core::extensions::filter`).
/// Bag key `http.method`.
pub const BAG_HTTP_METHOD: &str = "http.method";
/// Bag key `http.path`.
pub const BAG_HTTP_PATH: &str = "http.path";
/// Bag key `http.host`.
pub const BAG_HTTP_HOST: &str = "http.host";
/// Bag key `http.scheme`.
pub const BAG_HTTP_SCHEME: &str = "http.scheme";
// Violation `details` keys carrying a transpiled `denyWith` (custom HTTP
// denial response). Shared between the producer (praxis-policy-apl-runtime route handler)
// and any consumer (host renderer / tests) so the stringly-typed contract
// stays coupled to one definition.
/// Bag key `http.status`.
pub const DETAIL_HTTP_STATUS: &str = "http.status";
/// Bag key `http.body`.
pub const DETAIL_HTTP_BODY: &str = "http.body";
/// Bag key `http.headers`.
pub const DETAIL_HTTP_HEADERS: &str = "http.headers";
/// Key prefix for model identity, as in `llm.<name>`.
pub const BAG_LLM_PREFIX: &str = "llm.";
/// Key prefix for tool and resource metadata, as in `mcp.<name>`.
pub const BAG_MCP_PREFIX: &str = "mcp.";
/// Key prefix for completion metadata, as in `completion.<name>`.
pub const BAG_COMPLETION_PREFIX: &str = "completion.";
/// Key prefix for message origin, as in `provenance.<name>`.
pub const BAG_PROVENANCE_PREFIX: &str = "provenance.";
/// Key prefix for framework context, as in `framework.<name>`.
pub const BAG_FRAMEWORK_PREFIX: &str = "framework.";
/// Key prefix for host-supplied custom values, as in `custom.<name>`.
pub const BAG_CUSTOM_PREFIX: &str = "custom.";
