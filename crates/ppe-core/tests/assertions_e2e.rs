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
// U7: one test per return site
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
// U7: phases, denials, and the absent-config case
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
// U9: the properties an operator is promised
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
