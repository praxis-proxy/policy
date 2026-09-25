// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// A directory behind an HTTP API.
//
// Written against `maas-api`'s validate contract, because that one is real and
// running. It is the tier 3 case from the design note: the records live in a
// service, PPE presents the credential, and the service answers with an
// identity or a refusal.
//
// # What talks to what
//
// The request goes out over the host's transport, reached through
// `HostServices` on the `Extensions` of the request being resolved. PPE does
// not own the connection, which is why nothing here configures TLS: trust
// roots, client certificates and protocol floors belong to the host that
// injects the transport. A `ca_bundle:` key in this config would look natural
// and do nothing.
//
// Nor does anything here configure a credential. `maas-api` puts no
// authentication on `/internal/v1` at all (`maas-api/cmd/main.go`, read
// 2026-09-22: "Internal routes (no auth required - called by Authorino /
// CronJob)"), so the endpoint is protected by not being routable rather than
// by a secret. When a deployment does need one, it is a credential PPE holds
// and renders outbound, which is the secret provider's job rather than an
// inline literal in this block.
//
// # That endpoint is a key oracle
//
// Anything that can reach it can test candidate keys as fast as it will
// answer. That is upstream's posture to hold, not ours, but it is the reason
// negative caching is a requirement here rather than a nicety: without it a
// guessing flood against PPE becomes the same flood against the directory.
// The cache is not in this slice.

use std::collections::HashMap;
use std::time::Duration;

use praxis_policy_core::host::{HostServices, HttpRequestError};
use praxis_policy_core::http::HttpRequest;
use praxis_policy_core::http_retry::RetryPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::directory::{DirectoryError, KeyDirectory, KeyRecord, PresentedKey};

/// The `kind:` string an operator writes under `provider:`.
pub const KIND: &str = "http";

/// A ceiling on the response body a lookup will buffer.
///
/// A validate answer is a handful of fields. Anything larger is a directory
/// that has gone wrong or one that has been replaced, and neither should be
/// able to spend a request's memory.
const RESPONSE_MAX_BYTES: usize = 64 * 1024;

/// Response fields that describe the answer rather than the subject.
///
/// Stripped before the record reaches the map. `valid` is the verdict and
/// `reason` explains a refusal; neither is an attribute of whoever presented
/// the key, and leaving them in means an operator can project `subject.claim.valid`
/// and render it upstream as though the identity carried it.
pub const ENVELOPE_FIELDS: &[&str] = &["valid", "reason"];

fn default_url_field() -> String {
    "key".to_owned()
}

fn default_valid_field() -> String {
    "valid".to_owned()
}

fn default_timeout_secs() -> u64 {
    5
}

/// The HTTP backend's config block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpDirectoryConfig {
    /// Where to send the lookup.
    pub url: String,

    /// The JSON field the presented credential is sent as.
    ///
    /// `maas-api` reads `{"key": "..."}`, which is the default.
    #[serde(default = "default_url_field")]
    pub key_field: String,

    /// The boolean field in the response that says whether the credential
    /// resolved.
    ///
    /// A directory answering 200 for both outcomes needs this to tell them
    /// apart, which is what `maas-api` does: its handler cites their design doc
    /// section 7.7 for returning 200 with `valid: false`.
    #[serde(default = "default_valid_field")]
    pub valid_field: String,

    /// Overall deadline for the call, covering connect and I/O.
    ///
    /// A lookup sits on the request path, so this is a ceiling on how long a
    /// caller waits for a directory that has stopped answering.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Bound on connection establishment alone. Left to the transport when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,
}

impl HttpDirectoryConfig {
    /// Reject settings that cannot work, at config load.
    ///
    /// # Errors
    ///
    /// A URL that is not absolute HTTP(S), an empty field name, or a zero
    /// timeout, which would fail every lookup before it left the process.
    pub fn validate(&self) -> Result<(), String> {
        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            return Err(format!(
                "`url` must be an absolute http or https URL, got '{}'",
                self.url
            ));
        }
        if self.key_field.trim().is_empty() {
            return Err("`key_field` is empty".to_owned());
        }
        if self.valid_field.trim().is_empty() {
            return Err("`valid_field` is empty".to_owned());
        }
        if self.timeout_secs == 0 {
            return Err("`timeout_secs` is zero, so every lookup would time out".to_owned());
        }
        Ok(())
    }
}

/// Records held by a service, reached over HTTP.
#[derive(Debug)]
pub struct HttpDirectory {
    config: HttpDirectoryConfig,
}

impl HttpDirectory {
    /// Build the backend.
    ///
    /// # Errors
    ///
    /// Whatever [`HttpDirectoryConfig::validate`] rejects.
    pub fn new(config: HttpDirectoryConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The request body for a credential.
    ///
    /// Built through `serde_json` rather than by formatting a string, so a
    /// credential containing a quote or a backslash cannot alter the shape of
    /// the JSON around it.
    fn body(&self, presented: &PresentedKey) -> Result<Vec<u8>, DirectoryError> {
        // The directory speaks JSON, so a credential that is not UTF-8 cannot
        // be asked about at all. Refusing here rather than lossily converting:
        // a replacement character would be a lookup for a different key, and
        // would answer "unknown" about a credential nobody ever issued.
        // The `Utf8Error` is dropped rather than carried into the message: it
        // reports the byte offset where the credential stopped being valid
        // UTF-8, and a denial reason is an operator-facing string that has no
        // business describing the shape of what someone presented.
        let text = std::str::from_utf8(presented.as_bytes()).map_err(|_offset_in_credential| {
            DirectoryError::Malformed(
                "the presented credential is not UTF-8, so it cannot be sent as JSON".to_owned(),
            )
        })?;
        let mut body = serde_json::Map::new();
        body.insert(
            self.config.key_field.clone(),
            Value::String(text.to_owned()),
        );
        serde_json::to_vec(&Value::Object(body)).map_err(|e| {
            DirectoryError::Malformed(format!("could not encode the lookup body: {e}"))
        })
    }

    /// Turn a response body into an outcome.
    fn read_response(&self, body: &[u8]) -> Result<Option<KeyRecord>, DirectoryError> {
        let parsed: Value = serde_json::from_slice(body)
            .map_err(|e| DirectoryError::Malformed(format!("the response is not JSON: {e}")))?;
        let Value::Object(object) = parsed else {
            return Err(DirectoryError::Malformed(
                "the response is not a JSON object".to_owned(),
            ));
        };

        // A missing verdict field is unreadable rather than a refusal.
        // Defaulting it either way guesses: to `false` denies a caller the
        // directory may have accepted, and to `true` admits one it may not.
        let verdict = object.get(&self.config.valid_field).ok_or_else(|| {
            DirectoryError::Malformed(format!(
                "the response carries no `{}` field",
                self.config.valid_field
            ))
        })?;
        let Some(valid) = verdict.as_bool() else {
            return Err(DirectoryError::Malformed(format!(
                "`{}` is {} where a boolean was expected",
                self.config.valid_field,
                kind_of(verdict)
            )));
        };
        if !valid {
            return Ok(None);
        }

        let fields: HashMap<String, Value> = object
            .into_iter()
            .filter(|(name, _)| {
                name != &self.config.valid_field && !ENVELOPE_FIELDS.contains(&name.as_str())
            })
            .collect();
        Ok(Some(KeyRecord {
            fields,
            // The directory holding the records enforces its own expiry, and
            // `maas-api` answers `key revoked or expired` rather than handing
            // back a date. A backend that does return one can populate this.
            expires_at: None,
        }))
    }
}

/// A JSON value's kind, for an error that has to say what was wrong.
fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[async_trait::async_trait]
impl KeyDirectory for HttpDirectory {
    async fn lookup(
        &self,
        presented: &PresentedKey,
        services: &dyn HostServices,
    ) -> Result<Option<KeyRecord>, DirectoryError> {
        if presented.is_empty() {
            return Ok(None);
        }

        let mut request = HttpRequest::post(&self.config.url, self.body(presented)?.into())
            .timeout(Duration::from_secs(self.config.timeout_secs))
            // A validate response is a small JSON object. The ceiling stops a
            // compromised or broken directory streaming without end into a
            // buffer on the request path.
            .max_response_bytes(RESPONSE_MAX_BYTES)
            .header("content-type", "application/json")
            .and_then(|r| r.header("accept", "application/json"))
            .map_err(|e| {
                DirectoryError::Unavailable(format!("could not build the lookup request: {e}"))
            })?;
        if let Some(secs) = self.config.connect_timeout_secs {
            request = request.connect_timeout(Duration::from_secs(secs));
        }

        // Undelivered only. A lookup is not idempotent from the directory's
        // side: `maas-api` stamps `lastUsedAt` on every successful validate, so
        // replaying a request that may have arrived rewrites that. Retrying
        // only what provably never landed keeps the audit trail honest.
        let response = services
            .http_request(request, RetryPolicy::undelivered_only())
            .await
            .map_err(|error| match error {
                // The host wired no transport, or withheld it from this
                // plugin. That is a deployment fault, not a credential one,
                // and it denies as a directory failure so an operator is sent
                // to the right place.
                HttpRequestError::Unavailable(detail) => DirectoryError::Unavailable(format!(
                    "no HTTP transport for the key directory: {detail}"
                )),
                other => DirectoryError::Unavailable(other.to_string()),
            })?;

        match response.status {
            200 => self.read_response(&response.body),
            // Upstream answers 400 when the request body is wrong and 500 when
            // its own validation errors. Both mean the directory did not
            // answer about this credential, so both are unavailable rather than
            // an unknown key: the difference matters to whoever is paged.
            status => Err(DirectoryError::Unavailable(format!(
                "the directory answered {status}"
            ))),
        }
    }

    fn kind(&self) -> &'static str {
        KIND
    }
}
