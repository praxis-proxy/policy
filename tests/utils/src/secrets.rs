// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Planted secrets and the check that none of them leaks.
//!
//! A test plants every value that must never reach a diagnostic (inbound
//! tokens, client secrets, minted tokens, the SSN) and then
//! asserts over everything the caller can observe. A failure names the
//! secret by label, never by value.

use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use praxis_policy_core::http::{HttpRequest, HttpResponse, HttpTransport, HttpTransportError};
use serde_json::Value;

use crate::capture::Events;

/// The secrets one test planted.
#[derive(Clone, Default)]
pub struct Planted(Vec<(String, String)>);

impl std::fmt::Debug for Planted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(label, _)| label))
            .finish()
    }
}

impl Planted {
    /// No secrets yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Plant `value` under `label`. An empty value is ignored, since it
    /// would match everything.
    pub fn plant(&mut self, label: &str, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.0.push((label.to_owned(), value));
        }
    }

    /// Plant everything `other` planted.
    pub fn extend(&mut self, other: &Self) {
        self.0.extend(other.0.iter().cloned());
    }

    /// The labels of the secrets found in `text`.
    fn found_in(&self, text: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(_, value)| text.contains(value.as_str()))
            .map(|(label, _)| label.as_str())
            .collect()
    }

    /// Assert no planted secret appears in `text`, described as `place`.
    ///
    /// # Panics
    ///
    /// Naming `place` and the labels of every secret found.
    pub fn assert_absent(&self, place: &str, text: &str) {
        let found = self.found_in(text);
        assert!(
            found.is_empty(),
            "planted secrets leaked into {place}: {found:?}"
        );
    }

    /// Assert no planted secret appears in any key or string of `value`.
    ///
    /// # Panics
    ///
    /// As [`Planted::assert_absent`].
    pub fn assert_absent_json(&self, place: &str, value: &Value) {
        let mut strings = Vec::new();
        collect_strings(value, &mut strings);
        self.assert_absent(place, &strings.join("\n"));
    }

    /// Assert no planted secret appears in captured logs or audit records.
    ///
    /// # Panics
    ///
    /// As [`Planted::assert_absent`].
    pub fn assert_absent_events(&self, events: &Events) {
        self.assert_absent("captured logs", &events.logs().join("\n"));
        for record in events.audit_records() {
            self.assert_absent_json("an audit record", &record);
        }
    }
}

fn collect_strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => {
            for (k, v) in map {
                out.push(k);
                collect_strings(v, out);
            }
        },
        Value::Null | Value::Bool(_) | Value::Number(_) => {},
    }
}

#[derive(Clone, Default)]
pub(crate) struct IssuedTokens(Arc<Mutex<Planted>>);

impl std::fmt::Debug for IssuedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuedTokens(<redacted>)")
    }
}

impl IssuedTokens {
    pub(crate) fn snapshot(&self) -> Planted {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn record(&self, transport: Arc<dyn HttpTransport>) -> Arc<dyn HttpTransport> {
        Arc::new(TokenRecorder {
            transport,
            tokens: self.clone(),
        })
    }
}

#[derive(Debug)]
struct TokenRecorder {
    transport: Arc<dyn HttpTransport>,
    tokens: IssuedTokens,
}

#[async_trait]
impl HttpTransport for TokenRecorder {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let response = self.transport.execute(request).await?;
        if let Ok(body) = serde_json::from_slice::<Value>(&response.body) {
            let mut tokens = self.tokens.0.lock().unwrap_or_else(PoisonError::into_inner);
            for field in ["access_token", "id_token", "refresh_token"] {
                if let Some(token) = body.get(field).and_then(Value::as_str) {
                    tokens.plant(field, token);
                }
            }
        }
        Ok(response)
    }
}
