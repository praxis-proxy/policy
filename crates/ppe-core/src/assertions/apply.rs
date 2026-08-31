// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Applying a rendered contract to the wire header maps.
//
// Removal and injection are one replacement of the direction's header map, so
// there is no state in between where a client-supplied value and an asserted
// one both exist.
//
// Both directions run the same operation on a different map. The asymmetry
// between them lives in the config surface, not here: a request entry
// originates its value while a response entry filters someone else's, and
// either way what an entry targets is removed and what nothing names survives.

use std::sync::Arc;

use super::Direction;
use super::resolved::ResolvedContract;
use crate::extensions::{Extensions, HttpExtension};

/// Remove what the contract removes and inject what it rendered, as one
/// replacement of the direction's header map.
///
/// Every name an entry targets is removed whether or not `rendered` carries a
/// value for it. That is not an optimization waiting to happen: an entry whose
/// source resolved to nothing must not leave the wire value standing under a
/// name the other side reads as the engine's, so the removal cannot be made
/// conditional on there being something to put back.
///
/// A request with no `http` slot is a no-op. A non-HTTP transport has no header
/// map to write, so nothing is asserted and nothing is denied over it.
pub fn apply(
    contract: &ResolvedContract,
    rendered: &[(String, String)],
    ext: &mut Extensions,
    direction: Direction,
) {
    let Some(current) = ext.http.as_deref() else {
        return;
    };
    if contract.is_empty() && rendered.is_empty() {
        return;
    }
    let mut updated: HttpExtension = current.clone();
    let map = match direction {
        Direction::Request => &mut updated.request_headers,
        Direction::Response => &mut updated.response_headers,
    };
    // `retain` rather than a keyed remove, so a map carrying two casings of
    // one name loses both.
    map.retain(|name, _| !contract.removes(name));
    for (name, value) in rendered {
        map.insert(name.clone(), value.clone());
    }
    // One assignment. The request line and the status ride along untouched:
    // nothing here reads or writes them.
    ext.http = Some(Arc::new(updated));
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::assertions::AssertionLevel;
    use crate::assertions::config::{OnMissing, StripPattern};
    use crate::assertions::resolved::{ResolvedHeader, ResolvedSource};
    use crate::assertions::source::SourcePath;

    fn target(name: &str) -> ResolvedHeader {
        ResolvedHeader {
            name: name.to_owned(),
            lowercase: name.to_lowercase(),
            source: ResolvedSource::From(SourcePath::SubjectId),
            on_missing: OnMissing::Omit,
            encode: None,
            declared_in: "global".to_owned(),
            level: AssertionLevel::Global,
            overrode: None,
        }
    }

    fn contract(targets: &[&str], strip: &[&str]) -> ResolvedContract {
        ResolvedContract {
            headers: targets.iter().map(|name| target(name)).collect(),
            strip: strip.iter().map(|p| StripPattern::new(*p)).collect(),
        }
    }

    fn wire(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn request(pairs: &[(&str, &str)]) -> Extensions {
        Extensions {
            http: Some(Arc::new(HttpExtension {
                request_headers: wire(pairs),
                method: Some("POST".to_owned()),
                path: Some("/v1/files".to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn response(pairs: &[(&str, &str)]) -> Extensions {
        Extensions {
            http: Some(Arc::new(HttpExtension {
                response_headers: wire(pairs),
                status: Some(200),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn request_headers(ext: &Extensions) -> HashMap<String, String> {
        ext.http
            .as_deref()
            .expect("an http slot")
            .request_headers
            .clone()
    }

    fn response_headers(ext: &Extensions) -> HashMap<String, String> {
        ext.http
            .as_deref()
            .expect("an http slot")
            .response_headers
            .clone()
    }

    #[test]
    fn rendered_headers_appear_and_unrelated_ones_survive() {
        let mut ext = request(&[("Authorization", "Bearer tok"), ("accept", "*/*")]);
        apply(
            &contract(&["x-auth-user-id"], &[]),
            &[("x-auth-user-id".to_owned(), "alice".to_owned())],
            &mut ext,
            Direction::Request,
        );
        let headers = request_headers(&ext);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer tok")
        );
        assert_eq!(headers.get("accept").map(String::as_str), Some("*/*"));
    }

    /// The removal cannot be made conditional on there being a value to put
    /// back: a target the engine derived nothing for must not keep the client's.
    #[test]
    fn a_client_value_under_a_target_name_is_removed_even_when_nothing_rendered() {
        let mut ext = request(&[("x-auth-user-id", "root")]);
        apply(
            &contract(&["x-auth-user-id"], &[]),
            &[],
            &mut ext,
            Direction::Request,
        );
        assert!(request_headers(&ext).is_empty());
    }

    #[test]
    fn a_glob_removes_a_name_no_entry_targets() {
        let mut ext = request(&[("x-auth-projects", "prod"), ("x-other", "keep")]);
        apply(
            &contract(&["x-auth-user-id"], &["x-auth-*"]),
            &[("x-auth-user-id".to_owned(), "alice".to_owned())],
            &mut ext,
            Direction::Request,
        );
        let headers = request_headers(&ext);
        assert!(!headers.contains_key("x-auth-projects"));
        assert_eq!(headers.get("x-other").map(String::as_str), Some("keep"));
    }

    /// A map holding two casings of one name loses both, which a keyed remove
    /// would not do.
    #[test]
    fn removal_is_case_insensitive_and_reaches_every_casing() {
        let mut ext = request(&[
            ("X-Auth-User-Id", "root"),
            ("x-auth-user-id", "root2"),
            ("X-Auth-Projects", "prod"),
        ]);
        apply(
            &contract(&["x-auth-user-id"], &["x-auth-*"]),
            &[("x-auth-user-id".to_owned(), "alice".to_owned())],
            &mut ext,
            Direction::Request,
        );
        let headers = request_headers(&ext);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get("x-auth-user-id").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn authorization_is_untouched_by_a_contract_that_does_not_name_it() {
        let mut ext = request(&[("Authorization", "Bearer tok")]);
        apply(
            &contract(&["x-auth-user-id"], &["x-auth-*", "x-user-id"]),
            &[("x-auth-user-id".to_owned(), "alice".to_owned())],
            &mut ext,
            Direction::Request,
        );
        assert_eq!(
            request_headers(&ext)
                .get("Authorization")
                .map(String::as_str),
            Some("Bearer tok")
        );
    }

    #[test]
    fn a_request_with_no_http_slot_applies_nothing() {
        let mut ext = Extensions::default();
        apply(
            &contract(&["x-auth-user-id"], &["x-auth-*"]),
            &[("x-auth-user-id".to_owned(), "alice".to_owned())],
            &mut ext,
            Direction::Request,
        );
        assert!(ext.http.is_none());
    }

    #[test]
    fn the_request_line_and_the_status_are_unchanged_in_either_direction() {
        let mut ext = Extensions {
            http: Some(Arc::new(HttpExtension {
                request_headers: wire(&[("x-auth-user-id", "root")]),
                response_headers: wire(&[("server", "gunicorn")]),
                status: Some(502),
                method: Some("POST".to_owned()),
                path: Some("/v1/files".to_owned()),
                host: Some("api.example.com".to_owned()),
                scheme: Some("https".to_owned()),
            })),
            ..Default::default()
        };
        for direction in [Direction::Request, Direction::Response] {
            apply(
                &contract(&["x-auth-user-id"], &["server"]),
                &[("x-auth-user-id".to_owned(), "alice".to_owned())],
                &mut ext,
                direction,
            );
        }
        let http = ext.http.as_deref().expect("an http slot");
        assert_eq!(http.status, Some(502));
        assert_eq!(http.method.as_deref(), Some("POST"));
        assert_eq!(http.path.as_deref(), Some("/v1/files"));
        assert_eq!(http.host.as_deref(), Some("api.example.com"));
        assert_eq!(http.scheme.as_deref(), Some("https"));
    }

    /// An HTTP-transported tool call fires two pre-phase hooks, so the second
    /// application has to be a no-op by construction.
    #[test]
    fn applying_twice_leaves_the_same_map_as_applying_once() {
        let build = || request(&[("x-auth-user-id", "root"), ("accept", "*/*")]);
        let rendered = vec![("x-auth-user-id".to_owned(), "alice".to_owned())];
        let mut once = build();
        apply(
            &contract(&["x-auth-user-id"], &["x-auth-*"]),
            &rendered,
            &mut once,
            Direction::Request,
        );
        let mut twice = build();
        for _ in 0..2 {
            apply(
                &contract(&["x-auth-user-id"], &["x-auth-*"]),
                &rendered,
                &mut twice,
                Direction::Request,
            );
        }
        assert_eq!(request_headers(&once), request_headers(&twice));
    }

    #[test]
    fn the_request_direction_leaves_response_headers_alone() {
        let mut ext = Extensions {
            http: Some(Arc::new(HttpExtension {
                request_headers: wire(&[("x-auth-user-id", "root")]),
                response_headers: wire(&[("x-auth-user-id", "root")]),
                ..Default::default()
            })),
            ..Default::default()
        };
        apply(
            &contract(&["x-auth-user-id"], &[]),
            &[("x-auth-user-id".to_owned(), "alice".to_owned())],
            &mut ext,
            Direction::Request,
        );
        assert_eq!(
            response_headers(&ext)
                .get("x-auth-user-id")
                .map(String::as_str),
            Some("root")
        );
    }

    /// The response direction is a denylist: a header nothing names reaches the
    /// client as the upstream sent it.
    #[test]
    fn a_response_header_nothing_names_survives() {
        let mut ext = response(&[
            ("content-type", "application/json"),
            ("etag", "\"abc123\""),
            ("server", "gunicorn/21.2.0"),
        ]);
        apply(
            &contract(&["x-served-tenant"], &["server"]),
            &[("x-served-tenant".to_owned(), "acme".to_owned())],
            &mut ext,
            Direction::Response,
        );
        let headers = response_headers(&ext);
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(headers.get("etag").map(String::as_str), Some("\"abc123\""));
        assert!(!headers.contains_key("server"));
        assert_eq!(
            headers.get("x-served-tenant").map(String::as_str),
            Some("acme")
        );
    }

    /// An upstream echoing an asserted name back does not reach the client with
    /// its own value, whether or not the engine had one to put in its place.
    #[test]
    fn an_upstream_echoing_a_target_name_does_not_reach_the_client() {
        let mut ext = response(&[("x-served-tenant", r#"{"roles":["admin"]}"#)]);
        apply(
            &contract(&["x-served-tenant"], &[]),
            &[],
            &mut ext,
            Direction::Response,
        );
        assert!(response_headers(&ext).is_empty());

        let mut replaced = response(&[("x-served-tenant", "spoofed")]);
        apply(
            &contract(&["x-served-tenant"], &[]),
            &[("x-served-tenant".to_owned(), "acme".to_owned())],
            &mut replaced,
            Direction::Response,
        );
        assert_eq!(
            response_headers(&replaced)
                .get("x-served-tenant")
                .map(String::as_str),
            Some("acme")
        );
    }

    #[test]
    fn an_empty_contract_with_nothing_rendered_touches_nothing() {
        let before = request(&[("x-auth-user-id", "root")]);
        let mut after = request(&[("x-auth-user-id", "root")]);
        apply(
            &ResolvedContract::default(),
            &[],
            &mut after,
            Direction::Request,
        );
        assert_eq!(request_headers(&before), request_headers(&after));
    }
}
