// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The RFC 7662 call both hooks make: one POST to the issuer's introspection
// endpoint, authenticated with `client_secret_basic`, behind the answer cache.

use std::time::Duration;

use base64::Engine as _;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::host::HostServices as _;
use praxis_policy_core::http::{HttpRequest, form_urlencode, form_urlencode_component};
use praxis_policy_core::http_retry::RetryPolicy;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::plugins::oauth_introspection::cache::{Answer, StatusCache};
use crate::plugins::oauth_introspection::config::IntrospectionConfig;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// An introspection response is a small JSON object. The ceiling stops a
/// broken endpoint streaming without end.
const RESPONSE_MAX_BYTES: usize = 16 * 1024;

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

/// The RFC 7662 response fields read here. `exp` only bounds how long the
/// answer is cached.
#[derive(Deserialize)]
struct IntrospectionResponse {
    active: bool,
    exp: Option<f64>,
}

/// The claims read from a token before it is sent anywhere.
#[derive(Deserialize)]
struct Issuer {
    iss: String,
}

/// One issuer's introspection endpoint, with the credentials to call it and
/// the cache in front of it.
pub(crate) struct IntrospectionClient {
    endpoint: String,
    authorization: Zeroizing<String>,
    timeout: Duration,
    cache: Option<StatusCache>,
}

impl IntrospectionClient {
    /// Build the client from the plugin's settings.
    ///
    /// # Errors
    ///
    /// Returns a message when the endpoint is not `https://` without
    /// `insecure_http`, or the client secret cannot be read.
    pub(crate) fn new(settings: &IntrospectionConfig) -> Result<Self, String> {
        require_https(&settings.introspection_endpoint, settings.insecure_http)
            .map_err(|e| format!("introspection_endpoint {e}"))?;
        let secret = Zeroizing::new(settings.client_secret_source.resolve()?);
        Ok(Self {
            endpoint: settings.introspection_endpoint.clone(),
            authorization: basic_authorization(&settings.client_id, &secret),
            timeout: settings.timeout(),
            cache: StatusCache::new(settings.cache_ttl(), settings.cache_max_entries),
        })
    }

    /// The endpoint, for logs.
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The issuer's answer for `token`, reused from the cache when caching is
    /// on and the answer has not expired.
    ///
    /// # Errors
    ///
    /// Returns a message, never shown to the caller, when the call fails, the
    /// endpoint answers anything but 200, or the body is not an RFC 7662
    /// response.
    pub(crate) async fn answer(&self, ext: &Extensions, token: &str) -> Result<Answer, String> {
        match &self.cache {
            Some(cache) => cache.get_or_fetch(token, self.introspect(ext, token)).await,
            None => self.introspect(ext, token).await,
        }
    }

    /// POST the token to the introspection endpoint and read `active` and
    /// `exp`.
    async fn introspect(&self, ext: &Extensions, token: &str) -> Result<Answer, String> {
        let body = form_urlencode(&[("token", token), ("token_type_hint", "access_token")]);
        let request = HttpRequest::post(&self.endpoint, body)
            .timeout(self.timeout)
            .max_response_bytes(RESPONSE_MAX_BYTES)
            .header("content-type", "application/x-www-form-urlencoded")
            .and_then(|r| r.header("accept", "application/json"))
            .and_then(|r| r.header("authorization", self.authorization.as_str()))
            .map_err(|e| format!("request could not be built: {e}"))?;
        let response = ext
            .http_request(request, RetryPolicy::undelivered_only())
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if response.status != 200 {
            return Err(format!("status {}", response.status));
        }
        serde_json::from_slice::<IntrospectionResponse>(&response.body)
            .map(|parsed| Answer {
                active: parsed.active,
                exp: parsed.exp,
            })
            .map_err(|e| format!("malformed response: {e}"))
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// The `iss` claim of a JWT, read without verifying it.
///
/// This only decides whether a token belongs to the configured issuer, so a
/// token is never sent to an issuer that did not mint it. An opaque token has
/// no readable issuer.
pub(crate) fn issuer_of(token: &str) -> Option<String> {
    let claims = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims)
        .ok()?;
    serde_json::from_slice::<Issuer>(&decoded)
        .ok()
        .map(|issuer| issuer.iss)
}

/// `client_secret_basic` (RFC 6749 section 2.3.1): each part form-encoded,
/// joined with `:`, then base64. Encoding first keeps a `:` in the client ID
/// from splitting the pair, and a `+` or `%` in the secret from decoding to
/// different bytes at the server.
fn basic_authorization(client_id: &str, secret: &str) -> Zeroizing<String> {
    let secret = Zeroizing::new(form_urlencode_component(secret));
    let raw = Zeroizing::new(format!(
        "{}:{}",
        form_urlencode_component(client_id),
        secret.as_str()
    ));
    Zeroizing::new(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    ))
}

/// Accept `https://`, and `http://` only with `insecure_http`.
fn require_https(url: &str, insecure_http: bool) -> Result<(), String> {
    let lowered = url.trim_start().to_ascii_lowercase();
    if lowered.starts_with("https://") || (insecure_http && lowered.starts_with("http://")) {
        return Ok(());
    }
    Err(format!(
        "must use https:// (got '{url}'); `insecure_http: true` allows http:// for local \
         development only"
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use praxis_policy_core::http_testing::FakeTransport;
    use praxis_policy_core::revocation::IdentitySlot;
    use serde_json::json;

    use super::*;
    use crate::plugins::oauth_introspection::test_support::{ISSUER, ext, jwt, plugin};

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn the_request_carries_the_token_and_client_credentials() {
        let token = jwt(ISSUER);
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let ext = ext(&transport, &[(IdentitySlot::Client, token.clone())]);

        let answer = plugin(json!({})).client.answer(&ext, &token).await;

        assert!(answer.is_ok_and(|answer| answer.active), "active");
        let request = transport.last_request().expect("a request was sent");
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        assert_eq!(
            String::from_utf8_lossy(&request.body),
            String::from_utf8_lossy(&form_urlencode(&[
                ("token", &token),
                ("token_type_hint", "access_token"),
            ])),
            "body"
        );
        assert_eq!(
            header("authorization").as_deref(),
            Some("Basic cHBlOnMzY3JldA=="),
            "client_secret_basic for ppe:s3cret"
        );
        assert_eq!(
            header("content-type").as_deref(),
            Some("application/x-www-form-urlencoded"),
            "content type"
        );
        assert_eq!(request.timeout, Duration::from_millis(500), "timeout");
    }

    #[tokio::test]
    async fn client_credentials_are_form_encoded_before_basic() {
        let token = jwt(ISSUER);
        let transport =
            Arc::new(FakeTransport::new().json("/introspect", 200, r#"{"active":true}"#));
        let ext = ext(&transport, &[(IdentitySlot::Client, token.clone())]);
        let plugin = plugin(json!({
            "client_id": "ppe:svc",
            "client_secret_source": { "kind": "literal", "secret": "a+b c%&" },
        }));

        let _ = plugin.client.answer(&ext, &token).await;

        let request = transport.last_request().expect("a request was sent");
        assert_eq!(
            request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Basic cHBlJTNBc3ZjOmElMkJiK2MlMjUlMjY="),
            "RFC 6749 section 2.3.1: base64 of ppe%3Asvc:a%2Bb+c%25%26"
        );
    }
}
