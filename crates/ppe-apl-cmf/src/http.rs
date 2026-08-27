// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// HttpExtension → AttributeBag.
//
// Header names are lowercased in the bag (HTTP is case-insensitive). A
// policy author writing `http.request_headers.authorization` doesn't need
// to remember the original case.
//
// Namespace:
//   http.method                    : String  (request line)
//   http.path                      : String
//   http.host                      : String
//   http.scheme                    : String
//   http.status                    : Int     (response half only)
//   http.request_headers.<name>    : String  (lowercased name)
//   http.response_headers.<name>   : String  (lowercased name)

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::HttpExtension;

use crate::constants::{
    BAG_HTTP_HOST, BAG_HTTP_METHOD, BAG_HTTP_PATH, BAG_HTTP_SCHEME, BAG_HTTP_STATUS,
};

/// Write the request line, the response status, and both header maps into the
/// bag.
///
/// `http.status` lands as an `Int` so an ordering predicate such as
/// `http.status >= 500` compares numerically. The host sets it on the response
/// invocation only, so the key is absent on the request half.
pub fn extract_http(http: &HttpExtension, bag: &mut AttributeBag) {
    if let Some(method) = &http.method {
        bag.set(BAG_HTTP_METHOD.to_owned(), method.clone());
    }
    if let Some(path) = &http.path {
        bag.set(BAG_HTTP_PATH.to_owned(), path.clone());
    }
    if let Some(host) = &http.host {
        bag.set(BAG_HTTP_HOST.to_owned(), host.clone());
    }
    if let Some(scheme) = &http.scheme {
        bag.set(BAG_HTTP_SCHEME.to_owned(), scheme.clone());
    }
    if let Some(status) = http.status {
        bag.set(BAG_HTTP_STATUS.to_owned(), i64::from(status));
    }
    for (k, v) in &http.request_headers {
        bag.set(
            format!("http.request_headers.{}", k.to_lowercase()),
            v.clone(),
        );
    }
    for (k, v) in &http.response_headers {
        bag.set(
            format!("http.response_headers.{}", k.to_lowercase()),
            v.clone(),
        );
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

    #[test]
    fn request_line_surfaced_in_bag() {
        let http = HttpExtension {
            method: Some("POST".to_owned()),
            path: Some("/api/widgets".to_owned()),
            host: Some("api.example.com".to_owned()),
            scheme: Some("https".to_owned()),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert_eq!(bag.get_string("http.method"), Some("POST"));
        assert_eq!(bag.get_string("http.path"), Some("/api/widgets"));
        assert_eq!(bag.get_string("http.host"), Some("api.example.com"));
        assert_eq!(bag.get_string("http.scheme"), Some("https"));
    }

    #[test]
    fn request_line_absent_when_unset() {
        let http = HttpExtension::default();
        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert_eq!(bag.get_string("http.method"), None);
    }

    #[test]
    fn response_status_lands_as_an_integer() {
        // Int rather than String: an ordering predicate compares integer pairs
        // exactly, and `http.status == 502` needs both sides numeric.
        let http = HttpExtension {
            status: Some(502),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert_eq!(bag.get_int("http.status"), Some(502));
    }

    #[test]
    fn response_status_absent_on_the_request_half() {
        // The request half carries no status, so the key is missing rather
        // than present and zero.
        let http = HttpExtension {
            method: Some("GET".to_owned()),
            path: Some("/api/widgets".to_owned()),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert!(!bag.contains("http.status"));
    }

    #[test]
    fn headers_lowercased_in_bag() {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer xyz");
        http.set_request_header("X-Trace-Id", "abc-123");
        http.set_response_header("Content-Type", "application/json");

        let mut bag = AttributeBag::new();
        extract_http(&http, &mut bag);
        assert_eq!(
            bag.get_string("http.request_headers.authorization"),
            Some("Bearer xyz")
        );
        assert_eq!(
            bag.get_string("http.request_headers.x-trace-id"),
            Some("abc-123")
        );
        assert_eq!(
            bag.get_string("http.response_headers.content-type"),
            Some("application/json")
        );
    }
}
