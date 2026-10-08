// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Kuadrant `request.*` compatibility projection (issue #156).
//!
//! Pure producers: given the fully-populated policy bag, return the Kuadrant
//! Well-Known Attribute key/value pairs supported by PPE. The caller (each
//! per-PDP input builder) inserts these into its engine-specific input; the
//! shared [`AttributeBag`] is never mutated, so native PPE rules and other PDPs
//! are unaffected. An absent source produces no alias. Each language retains
//! its missing-value semantics: in particular, Rego negation can allow when an
//! alias is absent. Policies must explicitly require the values they need.
//!
//! Scope is the RFC 0002 "Request attributes" family only. Gap attributes
//! (`protocol`, `size`) have no PPE source and are deliberately not produced —
//! `size` is Envoy's measured `bytesReceived()` (a Praxis → PPE follow-up), NOT
//! the `content-length` header. `body` / `raw_body` / `context_extensions` are
//! removed from the compat surface. The supported mapping and presence contract
//! are documented in `docs/content/apl/pdp.md#kuadrant-authpolicy-compatibility`.
//!
//! This is the first vertical slice: only `request.id` is mapped so far
//! (`request.id` → host-supplied `request.request_id`). The remaining request-line,
//! header, and derived attributes land in later slices.

use praxis_policy_apl_core::attributes::{AttributeBag, AttributeValue};

/// WKA `request.*` scalar leaves derived from HTTP and host request metadata.
///
/// Scalar only; header mapping is outside this slice. Leaf names here never
/// contain a dot, so they are safe for the per-PDP dotted-path tree builders.
///
/// Mapped so far:
/// - `request.id` ← PPE `request.request_id`, supplied by the host.
pub(crate) fn request_aliases(bag: &AttributeBag) -> Vec<(String, AttributeValue)> {
    let mut out: Vec<(String, AttributeValue)> = Vec::new();

    // Authorino reads ext_authz HttpRequest.Id, which Envoy sets from its stream
    // ID. Use host request metadata; a client header must not supply this alias.
    if let Some(v) = bag.get("request.request_id") {
        out.push(("request.id".to_owned(), v.clone()));
    }

    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn pairs(v: &[(String, AttributeValue)]) -> std::collections::HashMap<String, AttributeValue> {
        v.iter().cloned().collect()
    }

    #[test]
    fn request_id_aliased_from_host_request_id() {
        let mut bag = AttributeBag::new();
        bag.set("request.request_id", "req-abc");
        let m = pairs(&request_aliases(&bag));
        assert_eq!(
            m.get("request.id"),
            Some(&AttributeValue::String("req-abc".into()))
        );
    }

    #[test]
    fn header_without_host_request_id_yields_no_alias() {
        let mut bag = AttributeBag::new();
        bag.set("http.request_headers.x-request-id", "header-id");
        assert!(request_aliases(&bag).is_empty());
    }

    #[test]
    fn request_id_ignores_header_when_host_request_id_is_present() {
        let mut bag = AttributeBag::new();
        bag.set("request.request_id", "host-id");
        bag.set("http.request_headers.x-request-id", "header-id");
        let m = pairs(&request_aliases(&bag));
        assert_eq!(
            m.get("request.id"),
            Some(&AttributeValue::String("host-id".into()))
        );
    }

    #[test]
    fn absent_source_yields_no_alias() {
        let bag = AttributeBag::new();
        assert!(request_aliases(&bag).is_empty());
    }
}
