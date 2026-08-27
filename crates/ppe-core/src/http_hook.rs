// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// HTTP hook family — the two generic-HTTP hook names, the payload they
// carry, and the `HookTypeDef` marker for handlers written against them.
//
// Distinct from `crate::http`, which is the outbound-transport seam. This
// module is about inbound L7 requests PPE is asked to decide on.
//
// The family exists because generic HTTP carries no LLM chat message. A
// handler written for a `cmf.*` hook reads `MessagePayload`, and on the
// HTTP path there is nothing in it to read, so a content scanner
// registered there would report clean on every request. `HttpPayload`
// gives the family a payload of its own that does not pretend to hold
// content.

use crate::cmf::constants::ENTITY_HTTP;
use crate::hooks::trait_def::PluginResult;

crate::define_hooks! {
    /// The HTTP family's rows in the built-in hook metadata table.
    HTTP_HOOK_METADATA;

    /// Generic HTTP request hook, fired for non-MCP/A2A HTTP requests on
    /// the way in. The catch-all `global` policy (if any) is annotated
    /// under it via [`ENTITY_HTTP`] / [`ENTITY_NAME_GLOBAL`]. This half
    /// carries authorization, which is an admission check and so belongs
    /// entirely before the request is forwarded.
    ///
    /// A route selecting on `http:` is matched from the request line once
    /// `plugin_settings.routing_enabled: true` is set, which defaults to false,
    /// so a host that also puts `method` and `path` on the HTTP extension at the
    /// identity invocation unlocks that route's own `authentication:` list. A
    /// host that supplies no request line there behaves exactly as it does
    /// today, with the global list governing, and the engine warns once when
    /// a route's list could not apply so a deployment can tell which of the
    /// two it is in.
    ///
    /// [`ENTITY_NAME_GLOBAL`]: crate::cmf::constants::ENTITY_NAME_GLOBAL
    HOOK_HTTP_REQUEST: "http.request" => family: HttpHook, entity: Some(ENTITY_HTTP), phase: Pre;
    /// Generic HTTP response hook, the return half of
    /// [`HOOK_HTTP_REQUEST`]. Authorization cannot live here, but
    /// response filtering can: a handler reads the response headers and
    /// the extensions, which covers stripping a header, enforcing a
    /// content type, and attaching labels. Not body redaction, since
    /// [`HttpExtension`][crate::extensions::http::HttpExtension] carries
    /// no body and [`HttpPayload`] carries no fields.
    ///
    /// The request line on this invocation is what makes both halves of one
    /// exchange resolve one route. Without it the response half resolves
    /// nothing and the global policy governs the way out, which is what a
    /// host that never set it gets today.
    HOOK_HTTP_RESPONSE: "http.response" => family: HttpHook, entity: Some(ENTITY_HTTP), phase: Post;
}

/// The payload the HTTP hooks carry.
///
/// Empty on purpose. Everything a handler reads about an HTTP exchange
/// lives on [`HttpExtension`][crate::extensions::http::HttpExtension]:
/// the request line, both header maps, and the response status. What a
/// payload would hold is a body, and a body is not a payload field,
/// because an owned body forces the proxy to buffer a response before
/// policy runs.
///
/// A struct rather than `()` so a bounded body chunk can land here later
/// without changing the hook type a second time. [`PluginPayload`]
/// requires only `Clone + Send + Sync + 'static`, so the empty shape
/// costs nothing.
///
/// [`PluginPayload`]: crate::hooks::payload::PluginPayload
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpPayload;

crate::impl_plugin_payload!(HttpPayload);

crate::define_hook! {
    /// Generic HTTP hook, one type for both halves.
    ///
    /// **Payload** ([`HttpPayload`]) carries no fields. A handler reads
    /// the exchange from the `Extensions` it is passed, principally
    /// [`HttpExtension`][crate::extensions::http::HttpExtension].
    ///
    /// **Result** ([`PluginResult<HttpPayload>`][PluginResult]) is the
    /// executor's standard envelope. `modified_extensions` is how a
    /// handler mutates headers or attaches labels;
    /// `continue_processing = false` halts the pipeline.
    ///
    /// **Two names, one type**, the way [`CmfHook`][crate::cmf::CmfHook]
    /// serves a dozen: [`HOOK_HTTP_REQUEST`] and [`HOOK_HTTP_RESPONSE`]
    /// share this payload. A handler that cares which half it is on reads
    /// [`HttpExtension::status`][status], which the host populates on the
    /// response invocation only. There is no hook name on
    /// [`PluginContext`][ctx] to read instead.
    ///
    /// A host fires both names as `invoke_named::<HttpHook>(name, ...)`,
    /// and an APL route selecting on `http:` dispatches the plugins its
    /// policy steps name through this type too, so a plugin on that path
    /// receives [`HttpPayload`] rather than a message nothing filled.
    ///
    /// [ctx]: crate::context::PluginContext
    /// [PluginResult]: crate::hooks::trait_def::PluginResult
    /// [status]: crate::extensions::http::HttpExtension::status
    HttpHook, "http" => {
        payload: HttpPayload,
        result: PluginResult<HttpPayload>,
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
    use crate::hooks::payload::PluginPayload;
    use crate::hooks::trait_def::HookTypeDef;
    use std::any::TypeId;

    #[test]
    fn the_hook_type_names_the_family_and_carries_the_http_payload() {
        assert_eq!(HttpHook::NAME, "http");
        assert_eq!(
            TypeId::of::<<HttpHook as HookTypeDef>::Payload>(),
            TypeId::of::<HttpPayload>(),
        );
    }

    #[test]
    fn the_payload_is_a_plugin_payload() {
        // The bound is what lets the executor carry it. Exercised through
        // the trait object so a missing impl fails to compile here rather
        // than at the first dispatch site.
        let payload = HttpPayload;
        let boxed: Box<dyn PluginPayload> = Box::new(payload);
        let cloned = boxed.clone_boxed();
        assert!(cloned.as_any().downcast_ref::<HttpPayload>().is_some());
    }

    #[test]
    fn the_family_declares_exactly_the_two_http_names() {
        let names: Vec<&str> = HTTP_HOOK_METADATA.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, vec!["http.request", "http.response"]);
        assert_eq!(HOOK_HTTP_REQUEST, "http.request");
        assert_eq!(HOOK_HTTP_RESPONSE, "http.response");
    }
}
