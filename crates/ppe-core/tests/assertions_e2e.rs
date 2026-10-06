// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `assertions:` contract, driven through the real engine.
//
// Two concerns share this binary because they share a harness. The first is
// coverage: the contract is an always-on control and every entry point returns
// before the executor on at least one path, so there is one test per return
// site. A wrapper that only covered the pipeline through the executor is how
// this ships broken, and every uncovered path is an absence of code rather than
// a wrong line, which no amount of reading finds.
//
// The second is the properties an operator is promised: what reaches the
// upstream, what reaches the client, and what a level's flag can and cannot
// reach.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_string_hashes,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use praxis_policy_core::cmf::constants::{
    ENTITY_NAME_GLOBAL, HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
};
use praxis_policy_core::cmf::enums::Role;
use praxis_policy_core::cmf::{CmfHook, Message, MessagePayload};
use praxis_policy_core::config;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::executor::erase_result;
use praxis_policy_core::extensions::{
    HttpExtension, MetaExtension, SecurityExtension, SubjectExtension,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::hooks::trait_def::PluginResult;
use praxis_policy_core::http_hook::{HOOK_HTTP_REQUEST, HOOK_HTTP_RESPONSE, HttpHook, HttpPayload};
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{Plugin, PluginConfig, PluginMode};
use praxis_policy_core::registry::AnyHookHandler;

// =====================================================================
// Harness
// =====================================================================

/// What a handler saw, and what it should do.
#[derive(Default)]
struct Probe {
    /// The request headers the handler was shown, so a test can assert the
    /// policy phase reads the client's values rather than the engine's.
    seen_request: Mutex<Option<HashMap<String, String>>>,
    /// Deny, to exercise the already-denied paths.
    deny: bool,
}

/// A handler over the CMF and HTTP families, recording and optionally denying.
///
/// Erased rather than typed because an annotated handler is the lineup for its
/// coordinates, and the engine takes one that is both a plugin and a dispatch
/// target. That is the shape the APL route handler has too.
struct ProbeHandler {
    cfg: PluginConfig,
    probe: Arc<Probe>,
    /// The hook family this instance was installed for. Registration reads it,
    /// so a CMF annotation and an HTTP one need different values.
    family: &'static str,
}

#[async_trait]
impl Plugin for ProbeHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

fn record(probe: &Probe, ext: &Extensions) {
    *probe.seen_request.lock().unwrap() =
        ext.http.as_deref().map(|http| http.request_headers.clone());
}

#[async_trait]
impl AnyHookHandler for ProbeHandler {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        record(&self.probe, ext);
        if let Some(message) = payload.as_any().downcast_ref::<MessagePayload>() {
            let result = if self.probe.deny {
                PluginResult::<MessagePayload>::deny(PluginViolation::new(
                    "test.denied",
                    "the probe denied",
                ))
            } else {
                PluginResult::modify_payload(message.clone())
            };
            return Ok(erase_result(result));
        }
        if let Some(http) = payload.as_any().downcast_ref::<HttpPayload>() {
            let result = if self.probe.deny {
                PluginResult::<HttpPayload>::deny(PluginViolation::new(
                    "test.denied",
                    "the probe denied",
                ))
            } else {
                PluginResult::modify_payload(*http)
            };
            return Ok(erase_result(result));
        }
        Err(Box::new(PluginError::Config {
            message: "the probe was handed a payload it does not serve".to_owned(),
        }))
    }

    fn hook_type_name(&self) -> &'static str {
        self.family
    }
}

/// A handler that re-enters the engine through the nested dispatch primitive,
/// which is the shape every real caller of it has: inside a handler the executor
/// is running.
struct NestedHandler {
    cfg: PluginConfig,
    engine: std::sync::Weak<PolicyEngine>,
    /// The header map the nested dispatch returned, and the one it was given.
    observed: Arc<Mutex<Option<(HashMap<String, String>, HashMap<String, String>)>>>,
    /// Whether to hand the nested call an empty entry slice, which is its other
    /// return site.
    empty_entries: bool,
}

#[async_trait]
impl Plugin for NestedHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

#[async_trait]
impl AnyHookHandler for NestedHandler {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        let Some(engine) = self.engine.upgrade() else {
            return Ok(erase_result(PluginResult::<HttpPayload>::allow()));
        };
        let before = ext
            .http
            .as_deref()
            .map(|http| http.request_headers.clone())
            .unwrap_or_default();
        let entries: Vec<praxis_policy_core::registry::HookEntry> = if self.empty_entries {
            Vec::new()
        } else {
            engine
                .find_plugin_entries("probe")
                .into_iter()
                .map(|(_, entry)| entry)
                .collect()
        };
        // The nested call runs while the executor is running this handler, which
        // is the shape every real caller of it has.
        let (nested, _bg) = engine
            .invoke_entries::<HttpHook>(&entries, HttpPayload, ext.clone(), None)
            .await;
        let after = nested
            .modified_extensions
            .as_ref()
            .and_then(|ext| ext.http.as_deref())
            .map(|http| http.request_headers.clone())
            .unwrap_or_default();
        *self.observed.lock().unwrap() = Some((before, after));
        let _ = payload;
        Ok(erase_result(PluginResult::<HttpPayload>::allow()))
    }

    fn hook_type_name(&self) -> &'static str {
        "http"
    }
}

fn probe_config(name: &str, hook: &str) -> PluginConfig {
    PluginConfig {
        name: name.to_owned(),
        kind: "builtin".to_owned(),
        hooks: vec![hook.to_owned()],
        mode: PluginMode::Sequential,
        capabilities: [
            "read_headers",
            "write_headers",
            "read_subject",
            "read_roles",
            "read_claims",
        ]
        .iter()
        .map(|c| (*c).to_owned())
        .collect(),
        ..Default::default()
    }
}

/// The hook family a hook name belongs to, which registration reads.
fn family_of(hook: &str) -> &'static str {
    if hook.starts_with("http.") {
        "http"
    } else {
        "cmf"
    }
}

/// An engine with the config loaded and an annotated handler on the coordinates
/// the request will resolve to, so the pipeline reaches the executor. Policy
/// mode dispatches nothing structurally, so an annotation is how a plugin runs
/// at all, which is what the APL runtime installs too.
async fn engine_with(yaml: &str) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    let parsed = config::parse_config(yaml).expect("the config loads");
    engine.load_config(parsed).expect("the config installs");
    engine.initialize().await.expect("initialize");
    engine
}

/// Annotate one set of coordinates with a probe on the named hooks.
fn annotate(
    engine: &Arc<PolicyEngine>,
    entity_type: &str,
    entity_name: &str,
    hooks: &[&str],
    probe: &Arc<Probe>,
) {
    for hook in hooks {
        let cfg = probe_config("probe", hook);
        let handler = Arc::new(ProbeHandler {
            cfg: cfg.clone(),
            probe: Arc::clone(probe),
            family: family_of(hook),
        });
        engine.annotate_route(entity_type, entity_name, None, *hook, handler, cfg);
    }
}

fn tool_meta(name: &str) -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".to_owned()),
            entity_name: Some(name.to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn http_meta() -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("http".to_owned()),
            entity_name: Some(ENTITY_NAME_GLOBAL.to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Alice, with the claims the worked example projects.
fn alice() -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some("alice".to_owned()),
            roles: ["ml-engineer", "viewer"]
                .iter()
                .map(|r| (*r).to_owned())
                .collect(),
            claims: [
                ("tenant".to_owned(), serde_json::json!("acme")),
                ("teams".to_owned(), serde_json::json!(["platform"])),
                (
                    "projects".to_owned(),
                    serde_json::json!(["team-prod", "team-stage"]),
                ),
                ("namespace".to_owned(), serde_json::json!(["team-ml"])),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A subject with no tenant claim, for the `on_missing: deny` cases.
fn tenantless() -> SecurityExtension {
    SecurityExtension {
        subject: Some(SubjectExtension {
            id: Some("alice".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

struct Wire {
    request: Vec<(&'static str, &'static str)>,
    response: Vec<(&'static str, &'static str)>,
    status: Option<u16>,
    line: Option<(&'static str, &'static str)>,
}

impl Wire {
    fn request(headers: &[(&'static str, &'static str)]) -> Self {
        Self {
            request: headers.to_vec(),
            response: Vec::new(),
            status: None,
            line: Some(("POST", "/v1/files")),
        }
    }

    fn response(headers: &[(&'static str, &'static str)]) -> Self {
        Self {
            request: Vec::new(),
            response: headers.to_vec(),
            status: Some(200),
            line: Some(("POST", "/v1/files")),
        }
    }

    fn without_request_line(mut self) -> Self {
        self.line = None;
        self
    }

    fn onto(self, mut ext: Extensions, security: SecurityExtension) -> Extensions {
        let map = |pairs: Vec<(&str, &str)>| -> HashMap<String, String> {
            pairs
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        };
        ext.http = Some(Arc::new(HttpExtension {
            request_headers: map(self.request),
            response_headers: map(self.response),
            status: self.status,
            method: self.line.map(|(m, _)| m.to_owned()),
            path: self.line.map(|(_, p)| p.to_owned()),
            ..Default::default()
        }));
        ext.security = Some(Arc::new(security));
        ext
    }
}

fn request_headers(result: &PipelineResult) -> HashMap<String, String> {
    result
        .modified_extensions
        .as_ref()
        .and_then(|ext| ext.http.as_deref())
        .map(|http| http.request_headers.clone())
        .unwrap_or_default()
}

fn response_headers(result: &PipelineResult) -> HashMap<String, String> {
    result
        .modified_extensions
        .as_ref()
        .and_then(|ext| ext.http.as_deref())
        .map(|http| http.response_headers.clone())
        .unwrap_or_default()
}

fn message() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "hello"),
    }
}

/// The worked example's contract, trimmed to what these tests drive.
const CONTRACT: &str = "
engine_settings:
  dispatch: policy
global:
  assertions:
    request:
      headers:
        - name: x-auth-user-id
          from: subject.id
          on_missing: deny
        - name: x-auth-tenant-id
          from: claim.tenant
          on_missing: deny
        - name: x-auth-attributes
          members:
            roles: subject.roles
            teams: claim.teams
            projects: claim.projects
            namespaces: claim.namespace
      strip:
        - x-auth-*
        - x-user-id
        - x-tenant-id
    response:
      strip:
        - x-auth-*
        - server
        - x-powered-by
        - x-debug-*
        - set-cookie
      headers:
        - name: x-served-tenant
          from: claim.tenant
  defaults:
    http:
      assertions:
        request:
          headers:
            - name: x-served-by
              from: claim.namespace
groups:
  files-backend:
    assertions:
      request:
        headers:
          - name: x-auth-scope
            from: claim.projects
            encode: csv
        strip:
          - x-files-*
routes:
  - tool: search
  - tool: files
    groups: files-backend
  - tool: analytics
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-auth-user-id
            from: subject.id
        strip:
          - x-auth-*
          - x-user-id
          - x-tenant-id
  - http:
      path_prefix: /v1/files
      method: [GET, POST]
    assertions:
      request:
        headers:
          - name: x-auth-path-scope
            from: claim.namespace
      response:
        strip:
          - x-upstream-*
";

/// A client's hopeful headers, all of which the contract removes.
const SPOOFED: &[(&str, &str)] = &[
    ("x-auth-user-id", "root"),
    ("x-auth-attributes", r#"{"roles":["admin"]}"#),
    ("x-auth-projects", "prod"),
    ("x-user-id", "root"),
    ("x-tenant-id", "evil"),
];

// =====================================================================
// One test per return site
// =====================================================================

mod return_sites {
    use super::*;

    /// `invoke_by_name`, first site: no registered entry and no annotation, so
    /// the call returns before route filtering. A deployment whose route has no
    /// plugin on this hook still has its headers replaced.
    #[tokio::test]
    async fn invoke_by_name_with_no_entries_still_applies() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let headers = request_headers(&result);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert!(!headers.contains_key("x-auth-projects"));
        assert!(!headers.contains_key("x-user-id"));
    }

    /// `invoke_by_name`, second site: an unreadable path denies before the
    /// executor. Removal happens, injection does not.
    #[tokio::test]
    async fn invoke_by_name_on_a_route_resolution_failure_strips_without_injecting() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "http",
            ENTITY_NAME_GLOBAL,
            &[HOOK_HTTP_REQUEST],
            &probe,
        );
        let mut ext = Wire::request(SPOOFED).onto(http_meta(), alice());
        // A path the engine refuses to read, with an `http:` route declared.
        ext.http = Some(Arc::new(HttpExtension {
            request_headers: ext
                .http
                .as_deref()
                .map(|http| http.request_headers.clone())
                .unwrap_or_default(),
            method: Some("POST".to_owned()),
            path: Some("/v1/files%zz".to_owned()),
            ..Default::default()
        }));
        let (result, _bg) = engine
            .invoke_by_name(HOOK_HTTP_REQUEST, Box::new(HttpPayload), ext, None)
            .await;
        assert!(result.is_denied(), "an unreadable path denies");
        let headers = request_headers(&result);
        assert!(
            !headers.contains_key("x-auth-user-id"),
            "the client's value is removed: {headers:?}"
        );
        assert!(
            headers.iter().all(|(name, _)| name != "x-auth-tenant-id"),
            "and nothing is asserted onto a refused request: {headers:?}"
        );
    }

    /// `invoke_by_name`, third site: entries exist for the hook but the route
    /// filters them all out.
    #[tokio::test]
    async fn invoke_by_name_with_entries_filtered_away_still_applies() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        // Annotated on other coordinates, so this request's own resolve to none.
        annotate(
            &engine,
            "tool",
            "other",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let headers = request_headers(&result);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert!(!headers.contains_key("x-auth-projects"));
    }

    /// `invoke_by_name`, tail: the pipeline through the executor.
    #[tokio::test]
    async fn invoke_by_name_through_the_executor_applies() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let headers = request_headers(&result);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            headers.get("x-auth-tenant-id").map(String::as_str),
            Some("acme")
        );
    }

    /// `invoke_named`, all four sites, one test each in a loop over what makes
    /// them reachable.
    #[tokio::test]
    async fn invoke_named_applies_at_its_first_site() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        let headers = request_headers(&result);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert!(!headers.contains_key("x-user-id"));
    }

    #[tokio::test]
    async fn invoke_named_applies_on_a_route_resolution_failure() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "http",
            ENTITY_NAME_GLOBAL,
            &[HOOK_HTTP_REQUEST],
            &probe,
        );
        let mut ext = Wire::request(SPOOFED).onto(http_meta(), alice());
        ext.http = Some(Arc::new(HttpExtension {
            request_headers: ext
                .http
                .as_deref()
                .map(|http| http.request_headers.clone())
                .unwrap_or_default(),
            method: Some("POST".to_owned()),
            path: Some("/v1/files%zz".to_owned()),
            ..Default::default()
        }));
        let (result, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None)
            .await;
        assert!(result.is_denied());
        assert!(!request_headers(&result).contains_key("x-auth-user-id"));
    }

    #[tokio::test]
    async fn invoke_named_applies_when_entries_filter_away() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "other",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert_eq!(
            request_headers(&result)
                .get("x-auth-user-id")
                .map(String::as_str),
            Some("alice")
        );
    }

    #[tokio::test]
    async fn invoke_named_applies_through_the_executor() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert_eq!(
            request_headers(&result)
                .get("x-auth-tenant-id")
                .map(String::as_str),
            Some("acme")
        );
    }

    /// `invoke::<H>` with a single-name hook type: `H::NAME` is a hook name, so
    /// the phase resolves and the contract applies. `HttpHook` serves two names,
    /// so a single-name type is what this needs; `IdentityHook` is one, and it
    /// is unphased, which the next test covers. A host hook is the realistic
    /// single-name case, so one is registered here.
    #[tokio::test]
    async fn invoke_with_a_family_type_dispatches_nothing_and_applies_nothing() {
        let engine = engine_with(CONTRACT).await;
        let before = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let expected = before
            .http
            .as_deref()
            .map(|http| http.request_headers.clone())
            .unwrap_or_default();
        let (result, _bg) = engine.invoke::<CmfHook>(message(), before, None).await;
        assert_eq!(
            request_headers(&result),
            expected,
            "a family name resolves no phase, and that call dispatches nothing either"
        );
    }

    /// `invoke::<H>` with an unphased hook type: no direction, so neither
    /// contract applies, at every one of its sites.
    #[tokio::test]
    async fn invoke_with_an_unphased_hook_applies_neither_contract() {
        let engine = engine_with(CONTRACT).await;
        let before = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let expected = before
            .http
            .as_deref()
            .map(|http| http.request_headers.clone())
            .unwrap_or_default();
        let (result, _bg) = engine
            .invoke::<IdentityHook>(
                IdentityPayload::new("eyJ.fake.jwt", TokenSource::Bearer),
                before,
                None,
            )
            .await;
        assert_eq!(request_headers(&result), expected);
    }

    /// The unphased family again, through the named entry point and through the
    /// by-name one, so the phase rule holds wherever it is dispatched from.
    #[tokio::test]
    async fn an_unphased_hook_applies_nothing_at_every_entry_point() {
        let engine = engine_with(CONTRACT).await;
        for named in [true, false] {
            let before = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
            let expected = before
                .http
                .as_deref()
                .map(|http| http.request_headers.clone())
                .unwrap_or_default();
            let (result, _bg) = if named {
                engine
                    .invoke_named::<IdentityHook>(
                        HOOK_IDENTITY_RESOLVE,
                        IdentityPayload::new("eyJ.fake.jwt", TokenSource::Bearer),
                        before,
                        None,
                    )
                    .await
            } else {
                engine
                    .invoke_by_name(
                        HOOK_IDENTITY_RESOLVE,
                        Box::new(IdentityPayload::new("eyJ.fake.jwt", TokenSource::Bearer)),
                        before,
                        None,
                    )
                    .await
            };
            assert_eq!(request_headers(&result), expected, "named={named}");
        }
    }

    /// The nested dispatch primitive, both sites, from inside a handler the
    /// executor is running, which is the shape every real caller has. It applies
    /// nothing: the contract belongs at the outer boundary, after policy
    /// evaluation, and applying it here would let a later step read an asserted
    /// header where the client's value is promised.
    #[tokio::test]
    async fn nested_dispatch_applies_nothing_at_either_site() {
        for empty_entries in [true, false] {
            let engine = engine_with(CONTRACT).await;
            let observed = Arc::new(Mutex::new(None));
            let cfg = probe_config("nested", HOOK_HTTP_REQUEST);
            let handler = Arc::new(NestedHandler {
                cfg: cfg.clone(),
                engine: Arc::downgrade(&engine),
                observed: Arc::clone(&observed),
                empty_entries,
            });
            engine.annotate_route(
                "http",
                ENTITY_NAME_GLOBAL,
                None,
                HOOK_HTTP_REQUEST,
                handler,
                cfg,
            );
            let ext = Wire::request(SPOOFED)
                .without_request_line()
                .onto(http_meta(), alice());
            let (result, _bg) = engine
                .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None)
                .await;
            let (before, after) = observed
                .lock()
                .unwrap()
                .clone()
                .expect("the handler ran and dispatched a nested call");
            assert_eq!(
                before, after,
                "empty_entries={empty_entries}: the nested dispatch must change no header"
            );
            // And the outer boundary did apply it.
            assert_eq!(
                request_headers(&result)
                    .get("x-auth-user-id")
                    .map(String::as_str),
                Some("alice"),
                "empty_entries={empty_entries}"
            );
        }
    }

    /// The primitive driven directly, with no executor above it. It applies
    /// nothing, the same as when nested, and does not fault: a caller that wants
    /// no boundary is entitled to one, so the engine warns on each such call
    /// rather than refusing.
    #[tokio::test]
    async fn an_outermost_nested_dispatch_applies_nothing_and_does_not_fault() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let entries: Vec<praxis_policy_core::registry::HookEntry> = engine
            .find_plugin_entries("probe")
            .into_iter()
            .map(|(_, entry)| entry)
            .collect();
        for slice in [entries.as_slice(), &[]] {
            let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
            let expected = ext
                .http
                .as_deref()
                .map(|http| http.request_headers.clone())
                .unwrap_or_default();
            let (result, _bg) = engine
                .invoke_entries::<CmfHook>(slice, message(), ext, None)
                .await;
            assert_eq!(
                request_headers(&result),
                expected,
                "entries={}: an outermost nested dispatch has no boundary, so the \
                 header map comes back as it went in",
                slice.len()
            );
        }
    }

    /// The nested step observes the client's header value, not the engine's,
    /// because the contract is applied after the handler returns.
    #[tokio::test]
    async fn a_nested_step_reads_the_clients_value_and_the_upstream_gets_the_engines() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        let seen = probe
            .seen_request
            .lock()
            .unwrap()
            .clone()
            .expect("the handler ran");
        assert_eq!(
            seen.get("x-auth-user-id").map(String::as_str),
            Some("root"),
            "policy reads the client's value, unchanged"
        );
        assert_eq!(
            request_headers(&result)
                .get("x-auth-user-id")
                .map(String::as_str),
            Some("alice"),
            "the upstream receives the engine's"
        );
    }
}

// =====================================================================
// Phases, denials, and the absent-config case
// =====================================================================

mod behavior {
    use super::*;

    /// A pre-phase hook applies the request contract and leaves the response
    /// map alone; a post-phase hook does the reverse. No hook name appears in
    /// the feature: the registered phase is what decides.
    #[tokio::test]
    async fn the_registered_phase_decides_which_contract_applies() {
        let engine = engine_with(CONTRACT).await;

        let ext = Wire {
            request: SPOOFED.to_vec(),
            response: vec![
                ("x-auth-attributes", r#"{"roles":["admin"]}"#),
                ("server", "gunicorn"),
            ],
            status: None,
            line: Some(("POST", "/v1/files")),
        }
        .onto(tool_meta("search"), alice());
        let (pre, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert_eq!(
            request_headers(&pre)
                .get("x-auth-user-id")
                .map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            response_headers(&pre).get("server").map(String::as_str),
            Some("gunicorn"),
            "a pre-phase hook leaves the response map alone"
        );

        let ext = Wire {
            request: SPOOFED.to_vec(),
            response: vec![
                ("x-auth-attributes", r#"{"roles":["admin"]}"#),
                ("server", "gunicorn"),
            ],
            status: Some(200),
            line: Some(("POST", "/v1/files")),
        }
        .onto(tool_meta("search"), alice());
        let (post, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), ext, None)
            .await;
        assert!(
            !response_headers(&post).contains_key("server"),
            "a post-phase hook applies the response contract"
        );
        assert_eq!(
            request_headers(&post)
                .get("x-auth-user-id")
                .map(String::as_str),
            Some("root"),
            "and leaves the request map alone"
        );
    }

    /// The generic-HTTP pair carries its phases in the same table, so it applies
    /// the two contracts with no name written anywhere in this feature.
    #[tokio::test]
    async fn the_generic_http_pair_applies_both_directions() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire::request(SPOOFED).onto(http_meta(), alice());
        let (request, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None)
            .await;
        let headers = request_headers(&request);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            headers.get("x-served-by").map(String::as_str),
            Some(r#"["team-ml"]"#),
            "the generic-HTTP entity default applies too"
        );
        assert_eq!(
            headers.get("x-auth-path-scope").map(String::as_str),
            Some(r#"["team-ml"]"#),
            "and the http: route's own contract"
        );

        let ext = Wire::response(&[("x-upstream-node", "b7"), ("etag", "\"abc\"")])
            .onto(http_meta(), alice());
        let (response, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, ext, None)
            .await;
        let headers = response_headers(&response);
        assert!(!headers.contains_key("x-upstream-node"), "{headers:?}");
        assert_eq!(headers.get("etag").map(String::as_str), Some("\"abc\""));
    }

    /// An HTTP-transported tool call fires two pre-phase hooks. Applying the
    /// contract twice produces what applying it once does.
    #[tokio::test]
    async fn two_pre_phase_hooks_on_one_exchange_produce_one_set_of_headers() {
        let engine = engine_with(CONTRACT).await;
        let once = {
            let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
            let (result, _bg) = engine
                .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
                .await;
            request_headers(&result)
        };
        let twice = {
            let ext = Wire::request(SPOOFED).onto(http_meta(), alice());
            let (first, _bg) = engine
                .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None)
                .await;
            let mut carried = first.modified_extensions.expect("extensions come back");
            carried.meta = Some(Arc::new(MetaExtension {
                entity_type: Some("tool".to_owned()),
                entity_name: Some("search".to_owned()),
                ..Default::default()
            }));
            let (second, _bg) = engine
                .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), carried, None)
                .await;
            request_headers(&second)
        };
        // The HTTP half adds two headers the tool half's scope does not, so
        // compare on what both scopes assert.
        for name in ["x-auth-user-id", "x-auth-tenant-id", "x-auth-attributes"] {
            assert_eq!(
                once.get(name),
                twice.get(name),
                "{name} differs between one application and two"
            );
        }
        assert!(!twice.contains_key("x-auth-projects"));
    }

    /// A missing source under `on_missing: deny` refuses the request, and the
    /// header does not appear.
    #[tokio::test]
    async fn on_missing_deny_denies_and_names_the_header() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), tenantless());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert!(result.is_denied(), "a missing tenant claim denies");
        let violation = result.violation.as_ref().expect("a violation");
        assert_eq!(violation.code, "auth.assertion_missing");
        assert!(
            violation.reason.contains("x-auth-tenant-id"),
            "{}",
            violation.reason
        );
        assert_eq!(
            violation.details.get("source").and_then(|v| v.as_str()),
            Some("claim.tenant")
        );
        let headers = request_headers(&result);
        assert!(!headers.contains_key("x-auth-tenant-id"));
        assert!(
            !headers.contains_key("x-auth-user-id"),
            "and the client's value under a target name is still gone: {headers:?}"
        );
    }

    /// A pipeline a plugin already denied: removal happens, injection does not,
    /// and `on_missing` is not evaluated.
    #[tokio::test]
    async fn a_denied_pipeline_strips_without_injecting() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe {
            deny: true,
            ..Default::default()
        });
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert!(result.is_denied());
        assert_eq!(
            result.violation.as_ref().map(|v| v.code.as_str()),
            Some("test.denied"),
            "the plugin's denial stands rather than being replaced"
        );
        let headers = request_headers(&result);
        assert!(
            headers.is_empty(),
            "everything the contract names is gone: {headers:?}"
        );
    }

    /// The response direction does not run on a denied pipeline: no upstream
    /// response exists to filter.
    #[tokio::test]
    async fn a_denied_pipeline_does_no_response_filtering() {
        let engine = engine_with(CONTRACT).await;
        let probe = Arc::new(Probe {
            deny: true,
            ..Default::default()
        });
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_POST_INVOKE],
            &probe,
        );
        let ext = Wire::response(&[("server", "gunicorn"), ("content-type", "application/json")])
            .onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), ext, None)
            .await;
        assert!(result.is_denied());
        let headers = response_headers(&result);
        assert_eq!(
            headers.get("server").map(String::as_str),
            Some("gunicorn"),
            "nothing is filtered: {headers:?}"
        );
    }

    /// With no block declared, the header map comes back byte-identical.
    #[tokio::test]
    async fn no_block_leaves_the_header_map_untouched() {
        let engine =
            engine_with("engine_settings:\n  dispatch: policy\nroutes:\n  - tool: search\n").await;
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let expected = ext
            .http
            .as_deref()
            .map(|http| http.request_headers.clone())
            .unwrap_or_default();
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert_eq!(request_headers(&result), expected);
    }
}

// =====================================================================
// The properties an operator is promised
// =====================================================================

mod promises {
    use super::*;

    /// The worked example on the wire. The client's three `x-auth-*` headers are
    /// gone, including the one no entry targets, and the upstream receives the
    /// engine's values.
    #[tokio::test]
    async fn the_upstream_receives_the_engines_values_and_none_of_the_clients() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire {
            request: [SPOOFED, &[("Authorization", "Bearer eyJ.fake.jwt")]]
                .concat()
                .clone(),
            response: Vec::new(),
            status: None,
            line: Some(("POST", "/v1/files")),
        }
        .onto(tool_meta("files"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        let headers = request_headers(&result);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            headers.get("x-auth-tenant-id").map(String::as_str),
            Some("acme")
        );
        assert_eq!(
            headers.get("x-auth-attributes").map(String::as_str),
            Some(
                r#"{"namespaces":["team-ml"],"projects":["team-prod","team-stage"],"roles":["ml-engineer","viewer"],"teams":["platform"]}"#
            ),
            "structure survives, keys are sorted, and arrays stay arrays"
        );
        assert_eq!(
            headers.get("x-auth-scope").map(String::as_str),
            Some("team-prod,team-stage"),
            "the bundle's header, from a level global did not have to know about"
        );
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer eyJ.fake.jwt"),
            "this feature neither forwards nor removes the credential"
        );
        for gone in ["x-auth-projects", "x-user-id", "x-tenant-id"] {
            assert!(!headers.contains_key(gone), "{gone} survived: {headers:?}");
        }
    }

    /// Assert on the whole map rather than on named absences, so a source added
    /// later cannot leak past this test.
    #[tokio::test]
    async fn a_default_config_puts_nothing_of_the_credential_on_the_wire() {
        let engine =
            engine_with("engine_settings:\n  dispatch: policy\nroutes:\n  - tool: search\n").await;
        let mut ext = Wire::request(&[("Authorization", "Bearer eyJ.secret.jwt")])
            .onto(tool_meta("search"), alice());
        ext.raw_credentials = None;
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        let headers = request_headers(&result);
        assert_eq!(
            headers.len(),
            1,
            "nothing was added to the one header the client sent: {headers:?}"
        );
        assert!(headers.contains_key("Authorization"));
    }

    /// A route cannot escape an inherited `on_missing: deny` by declaring a
    /// contract of its own; only the flag does that, and the flag still cannot
    /// let a client header through under an asserted name.
    #[tokio::test]
    async fn a_route_escapes_an_inherited_deny_floor_only_with_the_flag() {
        let engine = engine_with(CONTRACT).await;

        let ext = Wire::request(SPOOFED).onto(tool_meta("files"), tenantless());
        let (inherited, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert!(
            inherited.is_denied(),
            "a route declaring its own headers still inherits the deny floor"
        );

        let ext = Wire::request(SPOOFED).onto(tool_meta("analytics"), tenantless());
        let (opted_out, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert!(!opted_out.is_denied(), "the flag drops the inherited floor");
        let headers = request_headers(&opted_out);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        for gone in ["x-auth-projects", "x-user-id", "x-tenant-id"] {
            assert!(
                !headers.contains_key(gone),
                "the flag cannot let {gone} through: {headers:?}"
            );
        }
    }

    /// A plugin holding `write_headers` that writes an entry target is
    /// overwritten rather than merged: the contract is applied after the
    /// executor returns.
    #[tokio::test]
    async fn a_plugin_writing_an_entry_target_is_overwritten() {
        struct Writer {
            cfg: PluginConfig,
        }
        #[async_trait]
        impl Plugin for Writer {
            fn config(&self) -> &PluginConfig {
                &self.cfg
            }
        }
        #[async_trait]
        impl AnyHookHandler for Writer {
            async fn invoke(
                &self,
                payload: &dyn PluginPayload,
                ext: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
                let message = payload
                    .as_any()
                    .downcast_ref::<MessagePayload>()
                    .expect("the cmf family carries a message");
                let mut owned = ext.cow_copy();
                let token = owned.http_write_token.take();
                if let (Some(http), Some(token)) = (owned.http.as_mut(), token.as_ref()) {
                    http.write(token)
                        .set_request_header("x-auth-user-id", "written-by-a-plugin");
                }
                owned.http_write_token = token;
                Ok(erase_result(PluginResult::modify(message.clone(), owned)))
            }

            fn hook_type_name(&self) -> &'static str {
                "cmf"
            }
        }

        let engine = engine_with(CONTRACT).await;
        let cfg = probe_config("writer", HOOK_CMF_TOOL_PRE_INVOKE);
        let handler = Arc::new(Writer { cfg: cfg.clone() });
        engine.annotate_route(
            "tool",
            "search",
            None,
            HOOK_CMF_TOOL_PRE_INVOKE,
            handler,
            cfg,
        );
        let ext = Wire::request(SPOOFED).onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_PRE_INVOKE, message(), ext, None)
            .await;
        assert_eq!(
            request_headers(&result)
                .get("x-auth-user-id")
                .map(String::as_str),
            Some("alice"),
        );
    }

    /// The response direction: the banner and the cookie go, the floor header
    /// stays, and the upstream's echo of an asserted name does not reach the
    /// client.
    #[tokio::test]
    async fn the_client_receives_the_filtered_response() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire::response(&[
            ("content-type", "application/json"),
            ("etag", "\"abc123\""),
            ("server", "gunicorn/21.2.0"),
            ("x-debug-query-time", "41ms"),
            ("x-auth-attributes", r#"{"roles":["admin"]}"#),
            ("set-cookie", "backend_session=1"),
        ])
        .onto(tool_meta("search"), alice());
        let (result, _bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), ext, None)
            .await;
        let headers = response_headers(&result);
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/json"),
            "a floor header no strip: entry can remove"
        );
        assert_eq!(headers.get("etag").map(String::as_str), Some("\"abc123\""));
        assert_eq!(
            headers.get("x-served-tenant").map(String::as_str),
            Some("acme")
        );
        for gone in [
            "server",
            "x-debug-query-time",
            "x-auth-attributes",
            "set-cookie",
        ] {
            assert!(
                !headers.contains_key(gone),
                "{gone} reached the client: {headers:?}"
            );
        }
    }

    /// Without the request line no `http:` route matches, so the levels above
    /// govern and the route's own contract does not apply. Nothing errors, which
    /// is why the engine reports it.
    #[tokio::test]
    async fn an_http_route_contract_needs_the_request_line() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire::request(SPOOFED)
            .without_request_line()
            .onto(http_meta(), alice());
        let (result, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None)
            .await;
        let headers = request_headers(&result);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert!(
            !headers.contains_key("x-auth-path-scope"),
            "the route's own header needs the request line: {headers:?}"
        );
        assert_eq!(
            headers.get("x-served-by").map(String::as_str),
            Some(r#"["team-ml"]"#),
            "but the entity default still governs: it covers an entity type rather \
             than a route, which is what the finding says governs instead: {headers:?}"
        );

        let findings = config::parse_config(CONTRACT)
            .map(|cfg| praxis_policy_core::assertions::effective_policy(&cfg))
            .expect("the config loads");
        assert!(
            findings.contains("x-auth-path-scope"),
            "the artifact names it"
        );
    }

    /// The two halves are separate invocations, so a host can supply the request
    /// line on one and not the other. The route's `request:` then pairs with the
    /// global `response:`, a contract nobody wrote.
    #[tokio::test]
    async fn one_half_with_a_request_line_and_one_without_mix_two_contracts() {
        let engine = engine_with(CONTRACT).await;
        let ext = Wire::request(SPOOFED).onto(http_meta(), alice());
        let (request, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, ext, None)
            .await;
        assert!(
            request_headers(&request).contains_key("x-auth-path-scope"),
            "the route's request contract applied on the way in"
        );

        let ext = Wire::response(&[("x-upstream-node", "b7")])
            .without_request_line()
            .onto(http_meta(), alice());
        let (response, _bg) = engine
            .invoke_named::<HttpHook>(HOOK_HTTP_RESPONSE, HttpPayload, ext, None)
            .await;
        assert_eq!(
            response_headers(&response)
                .get("x-upstream-node")
                .map(String::as_str),
            Some("b7"),
            "and the global response contract applied on the way out, which does not \
             strip x-upstream-*"
        );
    }
}

// =====================================================================
// A secret rendered onto the upstream request
// =====================================================================

/// A target behind a static API key, reached without a token delegator.
///
/// The engine renders the header from a value declared in `secrets.values`.
/// No plugin and no PDP is on this path, and the assertion names the declared
/// value rather than a provider and a reference, so what the process can reach
/// stays readable from the document.
mod secret_source {
    use praxis_policy_core::audit::AuditHandler;
    use praxis_policy_core::decision::DecisionLog;
    use praxis_policy_core::effect::EffectRecord;
    use praxis_policy_core::secrets::SecretProviderRegistry;

    use super::*;

    /// A directory holding one secret file, and the config that reads it.
    ///
    /// The file backend is what makes rotation testable without a network:
    /// it rereads on refresh, so rewriting the file is a rotation.
    struct Fixture {
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(contents: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ppe-assert-secret-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let fixture = Self { dir };
            fixture.write(contents);
            fixture
        }

        fn write(&self, contents: &str) {
            std::fs::write(self.dir.join("legacy.key"), contents).expect("write");
        }

        /// A document declaring the secret, plus whatever assertions the test
        /// wants over it.
        fn config(&self, assertions: &str) -> String {
            format!(
                "
engine_settings:
  dispatch: policy
secrets:
  providers:
    local: {{ kind: file, base_dir: {} }}
  values:
    legacy_api_key: {{ provider: local, ref: legacy.key }}
global:
  assertions:
{assertions}
routes:
  - tool: search
",
                self.dir.display()
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The engine builds the store before it serves, so this is the wiring a
    /// host does. Without it a document declaring secrets fails to initialize.
    async fn engine_reading_secrets(yaml: &str) -> Arc<PolicyEngine> {
        let engine = Arc::new(PolicyEngine::default());
        let parsed = config::parse_config(yaml).expect("the config loads");
        engine.load_config(parsed).expect("the config installs");
        assert!(
            engine.set_secret_providers(SecretProviderRegistry::with_builtin_backends()),
            "the factories install once; a second registration would be ignored and the \
             document's `file` provider would have nothing to build it"
        );
        engine.initialize().await.expect("initialize");
        engine
    }

    const ASSERTS_THE_KEY: &str = "    request:
      headers:
        - name: X-API-Key
          from: secret.legacy_api_key
      strip:
        - x-api-*
";

    /// What the issue asks for: the header reaches the upstream carrying the
    /// declared value, and the client's own attempt at the same name is gone.
    #[tokio::test]
    async fn a_secret_is_injected_onto_the_upstream_request() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_THE_KEY)).await;
        let ext = Wire::request(&[("x-api-key", "spoofed"), ("x-api-version", "1")])
            .onto(tool_meta("search"), alice());

        let (result, _bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;

        let headers = request_headers(&result);
        assert_eq!(
            headers.get("X-API-Key").map(String::as_str),
            Some("sk-live-abc123"),
            "the trailing newline is the file backend's to trim: {headers:?}"
        );
        assert!(
            !headers.values().any(|v| v == "spoofed"),
            "the client's own value is removed before injection: {headers:?}"
        );
        assert!(
            !headers.contains_key("x-api-version"),
            "and the strip glob still applies: {headers:?}"
        );
    }

    /// A consumer that copies the value out at startup would pass every test
    /// with a static secret and silently never rotate. Driving a real refresh
    /// and re-invoking is what tells the two apart.
    #[tokio::test]
    async fn a_rotated_secret_reaches_the_wire_after_a_refresh() {
        let fixture = Fixture::new("first-key\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_THE_KEY)).await;

        let invoke = || {
            let engine = Arc::clone(&engine);
            async move {
                let ext = Wire::request(&[]).onto(tool_meta("search"), alice());
                let (result, _bg) = engine
                    .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
                    .await;
                request_headers(&result)
                    .get("X-API-Key")
                    .cloned()
                    .unwrap_or_default()
            }
        };

        assert_eq!(invoke().await, "first-key");

        fixture.write("second-key\n");
        let report = engine.refresh_secrets().await;
        assert!(report.is_ok(), "{report:?}");
        assert_eq!(report.updated, vec!["legacy_api_key".to_owned()]);

        assert_eq!(
            invoke().await,
            "second-key",
            "the render path reads the store at the point of use, not once at startup"
        );
    }

    /// The artifact is what an operator and a security reviewer read to learn
    /// what crosses the boundary. It has to name the secret and never print it.
    #[test]
    fn the_artifact_prints_the_secret_name_and_never_its_value() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let parsed =
            config::parse_config(&fixture.config(ASSERTS_THE_KEY)).expect("the config loads");
        let artifact = praxis_policy_core::assertions::effective_policy(&parsed);

        assert!(
            artifact.contains("secret.legacy_api_key"),
            "the artifact names the declared secret: {artifact}"
        );
        assert!(
            !artifact.contains("sk-live-abc123"),
            "and never its value: {artifact}"
        );
        // The value is not in the parsed config either, so this holds for
        // anything else that renders one. Resolution happens at initialize.
        assert!(
            !format!("{parsed:?}").contains("sk-live-abc123"),
            "a parsed document carries the reference, not the bytes"
        );
        assert!(
            artifact.contains("no plugin capability reads this"),
            "the capability column says no grant reaches it: {artifact}"
        );
    }

    /// The value reaches the header it was asserted onto and nothing else: not
    /// another header, not the extensions the audit path would read, and not
    /// the payload a plugin is handed.
    #[tokio::test]
    async fn the_value_reaches_the_asserted_header_and_nothing_else() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_THE_KEY)).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(&[]).onto(tool_meta("search"), alice());

        let (result, _bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;

        let seen = probe
            .seen_request
            .lock()
            .expect("not poisoned")
            .clone()
            .expect("the probe ran");
        assert!(
            !seen.values().any(|v| v.contains("sk-live")),
            "the plugin phase runs before injection and sees the client's headers: {seen:?}"
        );

        let extensions = result
            .modified_extensions
            .as_ref()
            .expect("the pipeline carried extensions");
        let http = extensions.http.as_deref().expect("an http slot");
        assert_eq!(
            http.request_headers
                .iter()
                .filter(|(_, v)| v.contains("sk-live"))
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>(),
            vec!["X-API-Key"],
            "exactly one header carries it"
        );
        assert!(
            !http
                .response_headers
                .values()
                .any(|v| v.contains("sk-live")),
            "and nothing put it on the response"
        );
    }

    /// An entry naming a secret in the response direction is refused at load,
    /// so this never becomes a request-time question.
    #[test]
    fn a_response_entry_naming_a_secret_does_not_load() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let err = config::parse_config(&fixture.config(
            "    response:
      headers:
        - name: X-API-Key
          from: secret.legacy_api_key
",
        ))
        .expect_err("the config must not load")
        .to_string();
        assert!(err.contains("request-direction"), "{err}");
    }

    /// An unknown name is a config error rather than a header that renders
    /// nothing, so a typo fails startup instead of quietly dropping the key.
    #[test]
    fn an_undeclared_secret_name_does_not_load() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let err = config::parse_config(&fixture.config(
            "    request:
      headers:
        - name: X-API-Key
          from: secret.legacy_api_kye
",
        ))
        .expect_err("the config must not load")
        .to_string();
        assert!(err.contains("secret.legacy_api_kye"), "{err}");
        assert!(
            err.contains("legacy_api_key"),
            "names what is declared: {err}"
        );
    }

    // Audit handlers use the same filtered HTTP view as pipeline plugins.

    /// The request header map each of a sink's filtered views carried, one
    /// entry per emit, in call order.
    #[derive(Default)]
    struct SinkRecorder {
        views: Mutex<Vec<Option<HashMap<String, String>>>>,
        /// The same, for each effect the sink was shown.
        effect_views: Mutex<Vec<Option<HashMap<String, String>>>>,
    }

    impl SinkRecorder {
        /// The view from one emit, by call index.
        fn view(&self, nth: usize) -> Option<HashMap<String, String>> {
            let views = self.views.lock().unwrap();
            assert!(
                views.len() > nth,
                "the sink was called {} times, wanted at least {}",
                views.len(),
                nth + 1
            );
            views[nth].clone()
        }

        fn calls(&self) -> usize {
            self.views.lock().unwrap().len()
        }
    }

    struct Sink {
        cfg: PluginConfig,
        rec: Arc<SinkRecorder>,
    }

    #[async_trait]
    impl Plugin for Sink {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }

        fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
            Some(self)
        }
    }

    #[async_trait]
    impl AuditHandler for Sink {
        async fn handle(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _decisions: &DecisionLog,
        ) {
            self.rec.views.lock().unwrap().push(
                extensions
                    .http
                    .as_deref()
                    .map(|http| http.request_headers.clone()),
            );
        }

        async fn on_effect(&self, _effect: &EffectRecord, extensions: &Extensions) {
            self.rec.effect_views.lock().unwrap().push(
                extensions
                    .http
                    .as_deref()
                    .map(|http| http.request_headers.clone()),
            );
        }

        fn name(&self) -> &str {
            "secret-watcher"
        }
    }

    /// A plugin that performs an irreversible effect, so a sink has one to
    /// observe on the same request the contract asserts a secret onto.
    struct Actor {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for Actor {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    #[async_trait]
    impl AnyHookHandler for Actor {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            let effect = EffectRecord::prepared("token_mint", "a test mint", "k1");
            ext.perform_effect(&effect, || async { Ok(()) }).await?;
            Ok(erase_result(PluginResult::<MessagePayload>::allow()))
        }

        fn hook_type_name(&self) -> &'static str {
            "cmf"
        }
    }

    /// The actor declares `read_headers` as well, because an effect view is
    /// filtered from the *acting* plugin's view: without it the sink's view
    /// carries no `http` slot at all and a test over it proves nothing.
    fn attach_actor(engine: &Arc<PolicyEngine>) {
        let cfg = PluginConfig {
            name: "actor".to_owned(),
            kind: "builtin".to_owned(),
            hooks: vec![HOOK_CMF_TOOL_PRE_INVOKE.to_owned()],
            mode: PluginMode::Sequential,
            capabilities: ["read_headers".to_owned()].into_iter().collect(),
            ..Default::default()
        };
        engine.annotate_route(
            "tool",
            "search",
            None,
            HOOK_CMF_TOOL_PRE_INVOKE,
            Arc::new(Actor { cfg: cfg.clone() }),
            cfg,
        );
    }

    /// A sink is collected off the registry, so it has to be registered as a
    /// dispatch target as well. This one allows and records nothing.
    struct SinkPassthrough;

    #[async_trait]
    impl AnyHookHandler for SinkPassthrough {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _ext: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            Ok(erase_result(PluginResult::<MessagePayload>::allow()))
        }

        fn hook_type_name(&self) -> &'static str {
            "cmf"
        }
    }

    fn attach_sink(
        engine: &Arc<PolicyEngine>,
        capabilities: &[&str],
        hooks: &[&str],
    ) -> Arc<SinkRecorder> {
        let rec = Arc::new(SinkRecorder::default());
        let cfg = PluginConfig {
            name: "secret-watcher".to_owned(),
            kind: "builtin".to_owned(),
            hooks: hooks.iter().map(|h| (*h).to_owned()).collect(),
            mode: PluginMode::Audit,
            capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
            ..Default::default()
        };
        let plugin = Arc::new(Sink {
            cfg: cfg.clone(),
            rec: Arc::clone(&rec),
        });
        engine
            .register_raw::<CmfHook>(plugin, cfg, Arc::new(SinkPassthrough))
            .expect("the sink registers");
        rec
    }

    /// A contract asserting one secret header and one ordinary one, so a test
    /// can tell a targeted redaction from a blanket one.
    const ASSERTS_A_KEY_AND_AN_ID: &str = "    request:
      headers:
        - name: X-API-Key
          from: secret.legacy_api_key
        - name: x-auth-user-id
          from: subject.id
";

    /// What one audited invocation showed the sink, and what it left on the
    /// wire.
    struct Audited {
        sink_view: Option<HashMap<String, String>>,
        wire: HashMap<String, String>,
    }

    /// Drive one audited invocation and report both sides of it.
    async fn audited_invocation(assertions: &str, capabilities: &[&str]) -> Audited {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(assertions)).await;
        let rec = attach_sink(&engine, capabilities, &[HOOK_CMF_TOOL_PRE_INVOKE]);
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let ext = Wire::request(&[("content-type", "application/json")])
            .onto(tool_meta("search"), alice());

        let (result, _bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;

        assert_eq!(rec.calls(), 1, "the sink was called once");
        Audited {
            sink_view: rec.view(0),
            wire: request_headers(&result),
        }
    }

    /// The acceptance criterion: the value never reaches the audit record. A
    /// sink holding `read_headers` is handed the `http` slot, and by the time
    /// the emit runs the asserted header is in it, so the emit is handed a
    /// slot whose secret-sourced entries carry a marker instead.
    ///
    /// The marker names the declared secret, which is the same split the
    /// effective-policy artifact prints under: a name is not sensitive and a
    /// value is.
    #[tokio::test]
    async fn an_audit_sink_reading_headers_sees_the_name_and_not_the_value() {
        let audited = audited_invocation(ASSERTS_THE_KEY, &["read_headers"]).await;
        let seen = audited
            .sink_view
            .expect("a sink declaring read_headers is handed the http slot");
        assert!(
            !seen.values().any(|v| v.contains("sk-live")),
            "an audit sink must not receive the asserted credential: {seen:?}"
        );
        assert_eq!(
            seen.get("X-API-Key").map(String::as_str),
            Some("<redacted secret.legacy_api_key>"),
            "the record still says which header was asserted, and from what: {seen:?}"
        );
    }

    /// Only the secret-sourced entry is withheld. An asserted identity value
    /// and the client's own headers are what a sink holding `read_headers` is
    /// there to see, and redacting by header name rather than by source would
    /// take them too.
    #[tokio::test]
    async fn redaction_covers_the_secret_entry_and_no_other_header() {
        let audited = audited_invocation(ASSERTS_A_KEY_AND_AN_ID, &["read_headers"]).await;
        let seen = audited.sink_view.expect("the http slot");
        assert_eq!(
            seen.get("X-API-Key").map(String::as_str),
            Some("<redacted secret.legacy_api_key>")
        );
        assert_eq!(
            seen.get("x-auth-user-id").map(String::as_str),
            Some("alice"),
            "an asserted identity value is not a secret: {seen:?}"
        );
        assert_eq!(
            seen.get("content-type").map(String::as_str),
            Some("application/json"),
            "and neither is the client's own header: {seen:?}"
        );
    }

    /// Audit filtering preserves the canonical headers forwarded upstream.
    #[tokio::test]
    async fn the_upstream_still_receives_the_value_after_the_emit() {
        let audited = audited_invocation(ASSERTS_A_KEY_AND_AN_ID, &["read_headers"]).await;
        assert_eq!(
            audited.wire.get("X-API-Key").map(String::as_str),
            Some("sk-live-abc123"),
            "the wire carries the secret, not the marker: {:?}",
            audited.wire
        );
        assert_eq!(
            audited.wire.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
    }

    /// The capability filter itself, so a failure above is read as the emit
    /// seeing post-injection extensions rather than as the filter being open.
    #[tokio::test]
    async fn a_sink_declaring_nothing_is_handed_no_header_map() {
        let audited = audited_invocation(ASSERTS_THE_KEY, &[]).await;
        assert!(
            audited.sink_view.is_none(),
            "the http slot is gated on read_headers"
        );
    }

    /// A secret on the request side and an ordinary assertion on the response
    /// side, which is what a response contract can hold: the direction asserts
    /// and strips like the request one, and only `secret.<name>` is refused in
    /// it.
    const ASSERTS_BOTH_DIRECTIONS: &str = "    request:
      headers:
        - name: X-API-Key
          from: secret.legacy_api_key
    response:
      headers:
        - name: x-served-tenant
          from: claim.tenant
";

    /// The response pass carries the same `http` slot, which still holds what
    /// the request pass injected.
    ///
    /// A response contract cannot name a secret, so nothing on that pass
    /// computes a redaction of its own. The request-side entries have to stay
    /// withheld anyway, because `request_headers` travels with the exchange and
    /// the response emit reads the same map.
    #[tokio::test]
    async fn the_response_pass_does_not_show_a_sink_the_request_secret() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_BOTH_DIRECTIONS)).await;
        let rec = attach_sink(
            &engine,
            &["read_headers"],
            &[HOOK_CMF_TOOL_PRE_INVOKE, HOOK_CMF_TOOL_POST_INVOKE],
        );

        let ext = Wire::request(&[]).onto(tool_meta("search"), alice());
        let (first, _bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let carried = first
            .modified_extensions
            .expect("the request pass carried extensions");
        assert_eq!(
            carried
                .http
                .as_deref()
                .and_then(|http| http.request_headers.get("X-API-Key"))
                .map(String::as_str),
            Some("sk-live-abc123"),
            "the request pass injected, so the response pass inherits the value"
        );

        // The way a proxy drives the second half: the same extensions, carried
        // from the request pass to the response one.
        let (_second, _bg2) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), carried, None)
            .await;

        assert_eq!(rec.calls(), 2, "one emit per pass");
        let on_response = rec.view(1).expect("the http slot");
        assert!(
            !on_response.values().any(|v| v.contains("sk-live")),
            "the response emit must withhold it too: {on_response:?}"
        );
    }

    /// Effects on the first request pass see only the client headers.
    #[tokio::test]
    async fn an_effect_view_never_carries_the_secret() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_THE_KEY)).await;
        let rec = attach_sink(&engine, &["read_headers"], &[HOOK_CMF_TOOL_PRE_INVOKE]);
        attach_actor(&engine);
        let ext = Wire::request(&[("x-api-version", "1")]).onto(tool_meta("search"), alice());

        let (result, bg) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        bg.wait_for_background_tasks().await;

        assert_eq!(
            request_headers(&result)
                .get("X-API-Key")
                .map(String::as_str),
            Some("sk-live-abc123"),
            "the contract fired, so there was something to leak"
        );
        let effect_views = rec.effect_views.lock().unwrap().clone();
        assert!(
            !effect_views.is_empty(),
            "the sink observed no effect, so this asserts nothing"
        );
        for view in &effect_views {
            let seen = view.as_ref().expect("the http slot");
            assert_eq!(
                seen.get("x-api-version").map(String::as_str),
                Some("1"),
                "the view carries the client's headers, so an absent secret is \
                 the ordering and not an empty slot: {seen:?}"
            );
            assert!(
                !seen.values().any(|v| v.contains("sk-live")),
                "an effect view must not carry the asserted credential: {seen:?}"
            );
        }
    }

    #[tokio::test]
    async fn response_plugin_must_not_read_request_secret() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_BOTH_DIRECTIONS)).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_POST_INVOKE],
            &probe,
        );
        let ext = Wire::request(&[]).onto(tool_meta("search"), alice());
        let (first, _) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let carried = first.modified_extensions.unwrap();
        let _ = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), carried, None)
            .await;
        let seen = probe
            .seen_request
            .lock()
            .unwrap()
            .clone()
            .expect("response plugin ran");
        assert!(
            !seen.values().any(|v| v.contains("sk-live")),
            "response plugin received secret: {seen:?}"
        );
    }

    #[tokio::test]
    async fn response_effect_must_not_read_request_secret() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_BOTH_DIRECTIONS)).await;
        let rec = attach_sink(&engine, &["read_headers"], &[HOOK_CMF_TOOL_POST_INVOKE]);
        let cfg = PluginConfig {
            name: "actor".to_owned(),
            kind: "builtin".to_owned(),
            hooks: vec![HOOK_CMF_TOOL_POST_INVOKE.to_owned()],
            mode: PluginMode::Sequential,
            capabilities: ["read_headers".to_owned()].into_iter().collect(),
            ..Default::default()
        };
        engine.annotate_route(
            "tool",
            "search",
            None,
            HOOK_CMF_TOOL_POST_INVOKE,
            Arc::new(Actor { cfg: cfg.clone() }),
            cfg,
        );
        let ext = Wire::request(&[]).onto(tool_meta("search"), alice());
        let (first, _) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let carried = first.modified_extensions.unwrap();
        let (_, bg) = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), carried, None)
            .await;
        bg.wait_for_background_tasks().await;
        let views = rec.effect_views.lock().unwrap();
        assert!(!views.is_empty(), "effect sink ran");
        for view in views.iter() {
            let seen = view.as_ref().expect("read_headers view");
            assert!(
                !seen.values().any(|v| v.contains("sk-live")),
                "response effect sink received secret: {seen:?}"
            );
        }
    }

    #[tokio::test]
    async fn reload_must_not_unredact_inflight_secret() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_BOTH_DIRECTIONS)).await;
        let rec = attach_sink(
            &engine,
            &["read_headers"],
            &[HOOK_CMF_TOOL_PRE_INVOKE, HOOK_CMF_TOOL_POST_INVOKE],
        );
        let ext = Wire::request(&[]).onto(tool_meta("search"), alice());
        let (first, _) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let carried = first.modified_extensions.unwrap();
        let new_config = fixture.config(ASSERTS_BOTH_DIRECTIONS).replace(
            "          from: secret.legacy_api_key",
            "          from: subject.id",
        );
        engine
            .load_config(config::parse_config(&new_config).unwrap())
            .unwrap();
        let _ = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), carried, None)
            .await;
        assert_eq!(rec.calls(), 2);
        let seen = rec.view(1).expect("response audit view");
        assert!(
            !seen.values().any(|v| v.contains("sk-live")),
            "audit leaked after reload: {seen:?}"
        );
    }

    #[tokio::test]
    async fn normalized_headers_must_stay_redacted() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_BOTH_DIRECTIONS)).await;
        let rec = attach_sink(
            &engine,
            &["read_headers"],
            &[HOOK_CMF_TOOL_PRE_INVOKE, HOOK_CMF_TOOL_POST_INVOKE],
        );
        let ext = Wire::request(&[]).onto(tool_meta("search"), alice());
        let (first, _) = engine
            .invoke_by_name(HOOK_CMF_TOOL_PRE_INVOKE, Box::new(message()), ext, None)
            .await;
        let mut carried = first.modified_extensions.unwrap();
        let http = Arc::make_mut(carried.http.as_mut().unwrap());
        http.request_headers = http
            .request_headers
            .drain()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        http.request_headers
            .insert("X-API-Key".into(), "sk-live-abc123".into());
        let _ = engine
            .invoke_named::<CmfHook>(HOOK_CMF_TOOL_POST_INVOKE, message(), carried, None)
            .await;
        let seen = rec.view(1).expect("response audit view");
        assert_eq!(seen.len(), 2);
        assert!(
            seen.values()
                .all(|v| v == "<redacted secret.legacy_api_key>"),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn repeated_pre_hooks_filter_the_previous_injection() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let engine = engine_reading_secrets(&fixture.config(ASSERTS_THE_KEY)).await;
        let probe = Arc::new(Probe::default());
        annotate(
            &engine,
            "tool",
            "search",
            &[HOOK_CMF_TOOL_PRE_INVOKE],
            &probe,
        );
        let (first, _) = engine
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                message(),
                Wire::request(&[]).onto(tool_meta("search"), alice()),
                None,
            )
            .await;
        fixture.write("rotated-key\n");
        assert!(engine.refresh_secrets().await.is_ok());
        let (second, _) = engine
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                message(),
                first.modified_extensions.unwrap(),
                None,
            )
            .await;
        let seen = probe.seen_request.lock().unwrap();
        assert_eq!(
            seen.as_ref().unwrap()["X-API-Key"],
            "<redacted secret.legacy_api_key>"
        );
        assert_eq!(request_headers(&second)["X-API-Key"], "rotated-key");
    }

    #[tokio::test]
    async fn nested_dispatch_keeps_route_secret_provenance() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let mut config: serde_yaml::Value =
            serde_yaml::from_str(&fixture.config(ASSERTS_THE_KEY)).unwrap();
        config["routes"][0]["assertions"] = std::mem::take(&mut config["global"]["assertions"]);
        let engine = engine_reading_secrets(&serde_yaml::to_string(&config).unwrap()).await;
        let rec = attach_sink(&engine, &["read_headers"], &[HOOK_CMF_TOOL_PRE_INVOKE]);
        let (first, _) = engine
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                message(),
                Wire::request(&[]).onto(tool_meta("search"), alice()),
                None,
            )
            .await;
        let (nested, _) = engine
            .invoke_entries::<CmfHook>(&[], message(), first.modified_extensions.unwrap(), None)
            .await;
        assert_eq!(
            rec.view(1).unwrap()["X-API-Key"],
            "<redacted secret.legacy_api_key>"
        );
        assert_eq!(request_headers(&nested)["X-API-Key"], "sk-live-abc123");
    }

    #[tokio::test]
    async fn members_redaction_is_idempotent_and_leaves_other_headers_visible() {
        let fixture = Fixture::new("sk-live-abc123\n");
        let assertions = "    request:\n      headers:\n        - name: x-context\n          members:\n            key: secret.legacy_api_key\n            user: subject.id\n";
        let engine = engine_reading_secrets(&fixture.config(assertions)).await;
        let (result, _) = engine
            .invoke_named::<CmfHook>(
                HOOK_CMF_TOOL_PRE_INVOKE,
                message(),
                Wire::request(&[("X-API-Key", "client-owned")]).onto(tool_meta("search"), alice()),
                None,
            )
            .await;
        let canonical = result.modified_extensions.unwrap();
        let caps = ["read_headers".to_owned()].into_iter().collect();
        let once = praxis_policy_core::extensions::filter_extensions(&canonical, &caps);
        let twice = praxis_policy_core::extensions::filter_extensions(&once, &caps);
        assert_eq!(
            once.http.as_ref().unwrap().request_headers,
            twice.http.as_ref().unwrap().request_headers
        );
        assert_eq!(
            twice.http.as_ref().unwrap().get_request_header("x-context"),
            Some("<redacted secret.legacy_api_key>")
        );
        assert_eq!(
            twice.http.as_ref().unwrap().get_request_header("x-api-key"),
            Some("client-owned")
        );
        assert!(
            canonical
                .http
                .as_ref()
                .unwrap()
                .get_request_header("x-context")
                .unwrap()
                .contains("sk-live")
        );
    }
}
