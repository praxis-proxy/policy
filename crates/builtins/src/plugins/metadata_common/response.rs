// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::HashSet;

use chrono::Utc;
use praxis_policy_core::extensions::{AcquiredFacts, MetadataCacheDisposition};
use praxis_policy_core::http::HttpResponse;
use praxis_policy_core::metadata_callout::MetadataCalloutErrorCode;
use serde::de::{DeserializeSeed as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::CalloutFailure;

const DEFAULT_MAX_DEPTH: usize = 8;
const HARD_MAX_DEPTH: usize = 16;
const DEFAULT_MAX_NODES: usize = 256;
const HARD_MAX_NODES: usize = 1_024;
const DEFAULT_MAX_KEY_BYTES: usize = 128;
const HARD_MAX_KEY_BYTES: usize = 256;
const DEFAULT_MAX_STRING_BYTES: usize = 4 * 1024;
const HARD_MAX_STRING_BYTES: usize = 16 * 1024;

fn default_max_depth() -> usize {
    DEFAULT_MAX_DEPTH
}

fn default_max_nodes() -> usize {
    DEFAULT_MAX_NODES
}

fn default_max_key_bytes() -> usize {
    DEFAULT_MAX_KEY_BYTES
}

fn default_max_string_bytes() -> usize {
    DEFAULT_MAX_STRING_BYTES
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseType {
    #[default]
    Json,
    Text,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseConfig {
    #[serde(default, rename = "type")]
    pub(crate) response_type: ResponseType,
    #[serde(default)]
    pub(crate) accepted_statuses: Vec<u16>,
    #[serde(default)]
    pub(crate) expose_status: bool,
    #[serde(default = "default_max_depth")]
    pub(crate) max_depth: usize,
    #[serde(default = "default_max_nodes")]
    pub(crate) max_nodes: usize,
    #[serde(default = "default_max_key_bytes")]
    pub(crate) max_key_bytes: usize,
    #[serde(default = "default_max_string_bytes")]
    pub(crate) max_string_bytes: usize,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            response_type: ResponseType::Json,
            accepted_statuses: Vec::new(),
            expose_status: false,
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
            max_key_bytes: DEFAULT_MAX_KEY_BYTES,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseParser {
    config: ResponseConfig,
}

impl ResponseParser {
    pub(crate) fn compile(config: &ResponseConfig) -> Result<Self, String> {
        validate_limit("response.max_depth", config.max_depth, HARD_MAX_DEPTH)?;
        validate_limit("response.max_nodes", config.max_nodes, HARD_MAX_NODES)?;
        validate_limit(
            "response.max_key_bytes",
            config.max_key_bytes,
            HARD_MAX_KEY_BYTES,
        )?;
        validate_limit(
            "response.max_string_bytes",
            config.max_string_bytes,
            HARD_MAX_STRING_BYTES,
        )?;
        if config
            .accepted_statuses
            .iter()
            .any(|status| !(100..=599).contains(status))
        {
            return Err("`response.accepted_statuses` contains an invalid HTTP status".to_owned());
        }
        let unique: HashSet<_> = config.accepted_statuses.iter().copied().collect();
        if unique.len() != config.accepted_statuses.len() {
            return Err("`response.accepted_statuses` contains a duplicate status".to_owned());
        }
        Ok(Self {
            config: config.clone(),
        })
    }

    pub(crate) fn parse(&self, response: &HttpResponse) -> Result<AcquiredFacts, CalloutFailure> {
        if !self.accepts_status(response.status) {
            return Err(CalloutFailure::new(match response.status {
                401 | 403 => MetadataCalloutErrorCode::AuthFailed,
                500..=599 => MetadataCalloutErrorCode::UpstreamError,
                _ => MetadataCalloutErrorCode::BadResponse,
            }));
        }
        self.validate_content_type(response)?;
        let mut facts = match self.config.response_type {
            ResponseType::Json => self.parse_json(&response.body)?,
            ResponseType::Text => self.parse_text(&response.body)?,
        };
        if self.config.expose_status {
            facts = facts.with_status(response.status);
        }
        Ok(facts)
    }

    fn accepts_status(&self, status: u16) -> bool {
        (200..300).contains(&status) || self.config.accepted_statuses.contains(&status)
    }

    fn validate_content_type(&self, response: &HttpResponse) -> Result<(), CalloutFailure> {
        let mut content_types = response.headers.get_all("content-type").iter();
        let raw = content_types
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or_else(bad_response)?;
        if content_types.next().is_some() {
            return Err(bad_response());
        }
        let mut parts = raw.split(';');
        let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        for parameter in parts {
            let parameter = parameter.trim();
            if parameter.is_empty() {
                return Err(bad_response());
            }
            let (name, value) = parameter.split_once('=').ok_or_else(bad_response)?;
            let name = name.trim();
            if name.is_empty() {
                return Err(bad_response());
            }
            let value = value.trim();
            if value.is_empty() {
                return Err(bad_response());
            }
            if !value.contains('"')
                || (value.starts_with('"') && value.ends_with('"') && value.len() > 1)
            {
                continue;
            }
            return Err(bad_response());
        }
        if let Some((mtype, msubtype)) = media.split_once('/') {
            if mtype.is_empty() || msubtype.is_empty() {
                return Err(bad_response());
            }
            let matches = match self.config.response_type {
                ResponseType::Json => {
                    mtype == "application" && (msubtype == "json" || msubtype.ends_with("+json"))
                },
                ResponseType::Text => mtype == "text" && msubtype == "plain",
            };
            if matches { Ok(()) } else { Err(bad_response()) }
        } else {
            Err(bad_response())
        }
    }

    fn parse_json(&self, body: &[u8]) -> Result<AcquiredFacts, CalloutFailure> {
        let json = std::str::from_utf8(body).map_err(|_error| bad_response())?;
        if json.trim().is_empty() {
            return Err(bad_response());
        }
        validate_json_structure(json, &self.config).map_err(|_error| bad_response())?;
        AcquiredFacts::success_json(json, Utc::now(), MetadataCacheDisposition::Disabled)
            .map_err(|_error| bad_response())
    }

    fn parse_text(&self, body: &[u8]) -> Result<AcquiredFacts, CalloutFailure> {
        let text = std::str::from_utf8(body).map_err(|_error| bad_response())?;
        if text.len() > self.config.max_string_bytes {
            return Err(bad_response());
        }
        Ok(AcquiredFacts::success(
            Value::String(text.to_owned()),
            Utc::now(),
            MetadataCacheDisposition::Disabled,
        ))
    }
}

fn validate_limit(name: &str, value: usize, hard: usize) -> Result<(), String> {
    if !(1..=hard).contains(&value) {
        return Err(format!("`{name}` must be between 1 and {hard}"));
    }
    Ok(())
}

fn validate_json_structure(json: &str, config: &ResponseConfig) -> Result<(), String> {
    let mut state = ValidationState { config, nodes: 0 };
    let mut deserializer = serde_json::Deserializer::from_str(json);
    NodeSeed {
        state: &mut state,
        depth: 1,
        root: true,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())
}

struct ValidationState<'a> {
    config: &'a ResponseConfig,
    nodes: usize,
}

impl ValidationState<'_> {
    fn enter<E: serde::de::Error>(&mut self, depth: usize) -> Result<(), E> {
        if depth > self.config.max_depth {
            return Err(E::custom("JSON depth limit exceeded"));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.config.max_nodes {
            return Err(E::custom("JSON node limit exceeded"));
        }
        Ok(())
    }
}

struct NodeSeed<'a, 'config> {
    state: &'a mut ValidationState<'config>,
    depth: usize,
    root: bool,
}

impl<'de> serde::de::DeserializeSeed<'de> for NodeSeed<'_, '_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.state.enter::<D::Error>(self.depth)?;
        deserializer.deserialize_any(NodeVisitor {
            state: self.state,
            depth: self.depth,
            root: self.root,
        })
    }
}

struct NodeVisitor<'a, 'config> {
    state: &'a mut ValidationState<'config>,
    depth: usize,
    root: bool,
}

impl<'de> Visitor<'de> for NodeVisitor<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > self.state.config.max_string_bytes {
            return Err(E::custom("JSON string limit exceeded"));
        }
        Ok(())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(NodeSeed {
                state: self.state,
                depth: self.depth + 1,
                root: false,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.is_empty()
                || key.len() > self.state.config.max_key_bytes
                || key.contains('.')
                || key.starts_with('$')
                || (self.root && key == "value")
            {
                return Err(serde::de::Error::custom("JSON object key is not permitted"));
            }
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(NodeSeed {
                state: self.state,
                depth: self.depth + 1,
                root: false,
            })?;
        }
        Ok(())
    }
}

const fn bad_response() -> CalloutFailure {
    CalloutFailure::new(MetadataCalloutErrorCode::BadResponse)
}

#[cfg(test)]
#[expect(
    clippy::assertions_on_result_states,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use bytes::Bytes;
    use praxis_policy_core::http::HeaderMap;
    use serde_json::json;

    use super::*;

    fn response(content_type: &str, status: u16, body: &str) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", content_type.parse().unwrap());
        HttpResponse::new(status, Bytes::copy_from_slice(body.as_bytes())).with_headers(headers)
    }

    fn parser() -> ResponseParser {
        ResponseParser::compile(&ResponseConfig::default()).expect("default response config")
    }

    #[test]
    fn accepts_every_json_root_and_preserves_nested_value() {
        for (body, expected) in [
            (
                r#"{"active":true,"nested":{"value":"kept"}}"#,
                json!({"active": true, "nested": {"value": "kept"}}),
            ),
            (r#""text""#, json!("text")),
            ("[\"a\",\"b\"]", json!(["a", "b"])),
            ("null", Value::Null),
            ("42", json!(42)),
        ] {
            let facts = parser()
                .parse(&response("Application/JSON; charset=utf-8", 200, body))
                .expect("valid JSON response");
            assert_eq!(facts.value(), Some(&expected));
            assert_eq!(facts.status(), None);
        }
    }

    #[test]
    fn rejects_duplicate_ambiguous_and_reserved_keys_atomically() {
        for body in [
            r#"{"a":1,"a":2}"#,
            r#"{"a.b":1}"#,
            r#"{"$source":1}"#,
            r#"{"value":1}"#,
            r#"{"":1}"#,
        ] {
            assert_eq!(
                parser().parse(&response("application/json", 200, body)),
                Err(CalloutFailure::new(MetadataCalloutErrorCode::BadResponse)),
                "{body} must be rejected"
            );
        }
    }

    #[test]
    fn validates_original_numeric_tokens_before_rounding() {
        for body in [
            "-9223372036854775808",
            "9223372036854775807",
            "0.5",
            "9007199254740992.0",
        ] {
            assert!(
                parser()
                    .parse(&response("application/json", 200, body))
                    .is_ok(),
                "{body} is in the lossless domain"
            );
        }
        for body in ["9223372036854775808", "0.1", "9007199254740993.0"] {
            assert_eq!(
                parser().parse(&response("application/json", 200, body)),
                Err(CalloutFailure::new(MetadataCalloutErrorCode::BadResponse)),
                "{body} must not be rounded into the accepted domain"
            );
        }
    }

    #[test]
    fn enforces_structural_limits() {
        let cases = [
            (
                ResponseConfig {
                    max_depth: 2,
                    ..ResponseConfig::default()
                },
                r#"{"a":{"b":1}}"#,
            ),
            (
                ResponseConfig {
                    max_nodes: 2,
                    ..ResponseConfig::default()
                },
                "[1,2]",
            ),
            (
                ResponseConfig {
                    max_key_bytes: 2,
                    ..ResponseConfig::default()
                },
                r#"{"abc":1}"#,
            ),
            (
                ResponseConfig {
                    max_string_bytes: 2,
                    ..ResponseConfig::default()
                },
                r#""abc""#,
            ),
        ];
        for (config, body) in cases {
            let parser = ResponseParser::compile(&config).expect("limits are below hard ceilings");
            assert_eq!(
                parser.parse(&response("application/json", 200, body)),
                Err(CalloutFailure::new(MetadataCalloutErrorCode::BadResponse))
            );
        }
    }

    #[test]
    fn status_media_type_and_empty_body_rules_are_exact() {
        assert!(parser().parse(&response("text/plain", 200, "{}")).is_err());
        assert!(
            parser()
                .parse(&response("application/json", 404, "{}"))
                .is_err()
        );
        assert!(
            parser()
                .parse(&response("application/json", 200, ""))
                .is_err()
        );

        let config = ResponseConfig {
            response_type: ResponseType::Text,
            accepted_statuses: vec![404],
            expose_status: true,
            ..ResponseConfig::default()
        };
        let facts = ResponseParser::compile(&config)
            .expect("text config")
            .parse(&response("text/plain; charset=UTF-8", 404, ""))
            .expect("empty text and configured status are valid");
        assert_eq!(facts.value(), Some(&json!("")));
        assert_eq!(facts.status(), Some(404));
    }

    #[test]
    fn duplicate_content_type_fields_are_rejected() {
        let mut duplicate = response("application/json", 200, "{}");
        duplicate
            .headers
            .append("content-type", "application/json".parse().unwrap());

        assert_eq!(
            parser().parse(&duplicate),
            Err(CalloutFailure::new(MetadataCalloutErrorCode::BadResponse))
        );
    }

    #[test]
    fn hard_limit_overrides_are_rejected_at_load() {
        for config in [
            ResponseConfig {
                max_depth: HARD_MAX_DEPTH + 1,
                ..ResponseConfig::default()
            },
            ResponseConfig {
                max_nodes: HARD_MAX_NODES + 1,
                ..ResponseConfig::default()
            },
            ResponseConfig {
                max_key_bytes: HARD_MAX_KEY_BYTES + 1,
                ..ResponseConfig::default()
            },
            ResponseConfig {
                max_string_bytes: HARD_MAX_STRING_BYTES + 1,
                ..ResponseConfig::default()
            },
        ] {
            assert!(ResponseParser::compile(&config).is_err());
        }
    }
}
