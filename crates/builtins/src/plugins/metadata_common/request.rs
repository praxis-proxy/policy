// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Duration;

use praxis_policy_apl_cmf::{BagBuilder, capability_namespaces, known_read_capabilities};
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::http::{HttpRequest, form_urlencode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::CalloutFailure;
use super::template::Template;
use praxis_policy_core::metadata_callout::MetadataCalloutErrorCode;

pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub(crate) const HARD_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

fn default_timeout_milliseconds() -> u64 {
    1_500
}

fn default_connect_timeout_milliseconds() -> u64 {
    500
}

fn default_max_response_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BYTES
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum RequestMethod {
    Get,
    Post,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestConfig {
    pub(crate) method: RequestMethod,
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) path_segments: Vec<String>,
    #[serde(default)]
    pub(crate) query: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) json: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) form: Option<BTreeMap<String, String>>,
    #[serde(default = "default_timeout_milliseconds")]
    pub(crate) timeout_milliseconds: u64,
    #[serde(default = "default_connect_timeout_milliseconds")]
    pub(crate) connect_timeout_milliseconds: u64,
    #[serde(default = "default_max_response_bytes")]
    pub(crate) max_response_bytes: usize,
    #[serde(default)]
    pub(crate) insecure_http: bool,
}

#[derive(Clone, Debug)]
enum JsonTemplate {
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
    Template(Template),
    Literal(Value),
}

impl JsonTemplate {
    fn compile(
        value: &Value,
        destination: &str,
        references: &mut BTreeSet<String>,
        uses: &mut Vec<ReferenceUse>,
    ) -> Result<Self, String> {
        match value {
            Value::Array(values) => values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    Self::compile(
                        value,
                        &format!("{destination}[{index}]"),
                        references,
                        uses,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Array),
            Value::Object(values) => values
                .iter()
                .map(|(key, value)| {
                    if key.contains(['{', '}']) {
                        return Err(format!(
                            "`{destination}` has a templated JSON field name; field names must be static"
                        ));
                    }
                    Self::compile(
                        value,
                        &format!("{destination}.{key}"),
                        references,
                        uses,
                    )
                    .map(|value| (key.clone(), value))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map(Self::Object),
            Value::String(value) => {
                let template = compile_template(value, destination, references, uses)?;
                if value.contains(['{', '}']) && !template.is_exact_reference() {
                    return Err(format!(
                        "`{destination}` must use one whole-field template so its JSON type is preserved"
                    ));
                }
                Ok(Self::Template(template))
            },
            value => Ok(Self::Literal(value.clone())),
        }
    }

    fn render(
        &self,
        bag: &praxis_policy_apl_core::AttributeBag,
        extensions: &Extensions,
    ) -> Result<Value, CalloutFailure> {
        match self {
            Self::Array(values) => values
                .iter()
                .map(|value| value.render(bag, extensions))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Self::Object(values) => values
                .iter()
                .map(|(key, value)| {
                    value
                        .render(bag, extensions)
                        .map(|value| (key.clone(), value))
                })
                .collect::<Result<serde_json::Map<_, _>, _>>()
                .map(Value::Object),
            Self::Template(template) => template.render_json(bag, extensions),
            Self::Literal(value) => Ok(value.clone()),
        }
    }
}

#[derive(Clone, Debug)]
struct ReferenceUse {
    reference: String,
    destination: String,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledRequest {
    method: RequestMethod,
    authority: http::uri::Authority,
    base_url: Url,
    credential_interpolation: bool,
    path_segments: Vec<Template>,
    query: BTreeMap<String, Template>,
    headers: BTreeMap<String, Template>,
    json: Option<JsonTemplate>,
    form: Option<BTreeMap<String, Template>>,
    timeout: Duration,
    connect_timeout: Duration,
    max_response_bytes: usize,
}

impl CompiledRequest {
    pub(crate) fn compile(
        config: &RequestConfig,
        capabilities: &HashSet<String>,
        allow_credential_interpolation: bool,
        credential_fields: &BTreeSet<String>,
    ) -> Result<Self, String> {
        validate_bounds(config)?;
        let base_url = validate_url(config)?;
        let authority = authority(&base_url)?;
        let mut references = BTreeSet::new();
        let mut uses = Vec::new();

        let path_segments = config
            .path_segments
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                compile_template(
                    raw,
                    &format!("request.path_segments[{index}]"),
                    &mut references,
                    &mut uses,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let query = config
            .query
            .iter()
            .map(|(name, raw)| {
                if name.is_empty() || name.contains(['{', '}']) {
                    return Err("query parameter names must be nonempty and static".to_owned());
                }
                compile_template(
                    raw,
                    &format!("request.query.{name}"),
                    &mut references,
                    &mut uses,
                )
                .map(|template| (name.clone(), template))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let mut normalized_header_names = HashSet::new();
        let headers = config
            .headers
            .iter()
            .map(|(name, raw)| {
                validate_header_name(name)?;
                if !normalized_header_names.insert(name.to_ascii_lowercase()) {
                    return Err(format!(
                        "`request.headers` repeats `{name}` with different casing"
                    ));
                }
                if raw.contains(['\r', '\n', '\0']) {
                    return Err(format!(
                        "`request.headers.{name}` contains a forbidden control character"
                    ));
                }
                compile_template(
                    raw,
                    &format!("request.headers.{name}"),
                    &mut references,
                    &mut uses,
                )
                .map(|template| (name.clone(), template))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let json = config
            .json
            .as_ref()
            .map(|value| JsonTemplate::compile(value, "request.json", &mut references, &mut uses))
            .transpose()?;
        let form = config
            .form
            .as_ref()
            .map(|fields| {
                fields
                    .iter()
                    .map(|(name, raw)| {
                        if name.is_empty() || name.contains(['{', '}']) {
                            return Err("form field names must be nonempty and static".to_owned());
                        }
                        compile_template(
                            raw,
                            &format!("request.form.{name}"),
                            &mut references,
                            &mut uses,
                        )
                        .map(|template| (name.clone(), template))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()
            })
            .transpose()?;

        if json.is_some() && form.is_some() {
            return Err("`request.json` and `request.form` are mutually exclusive".to_owned());
        }
        if config.method == RequestMethod::Get && (json.is_some() || form.is_some()) {
            return Err("GET metadata requests cannot carry `json` or `form` bodies".to_owned());
        }
        if (json.is_some() || form.is_some())
            && headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("content-type"))
        {
            return Err(
                "`request.headers` cannot set `Content-Type` when `json` or `form` generates it"
                    .to_owned(),
            );
        }

        validate_reference_capabilities(&references, capabilities)?;
        validate_credential_uses(
            &uses,
            capabilities,
            allow_credential_interpolation,
            credential_fields,
        )?;
        let credential_interpolation = uses.iter().any(ReferenceUse::is_credential);

        Ok(Self {
            method: config.method,
            authority,
            base_url,
            credential_interpolation,
            path_segments,
            query,
            headers,
            json,
            form,
            timeout: Duration::from_millis(config.timeout_milliseconds),
            connect_timeout: Duration::from_millis(config.connect_timeout_milliseconds),
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub(crate) fn build(&self, extensions: &Extensions) -> Result<HttpRequest, CalloutFailure> {
        let bag = BagBuilder::new()
            .with_extensions(extensions)
            .map_err(|_error| bad_response())?
            .build();
        let mut url = self.base_url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|()| bad_response())?;
            for segment in &self.path_segments {
                let rendered = segment.render_text(&bag, extensions)?;
                if rendered == "." || rendered == ".." {
                    return Err(CalloutFailure::new(
                        MetadataCalloutErrorCode::RejectedDestination,
                    ));
                }
                if rendered.contains(['\t', '\n', '\r']) {
                    return Err(CalloutFailure::new(
                        MetadataCalloutErrorCode::RejectedDestination,
                    ));
                }
                segments.push(&rendered);
            }
        }
        if !self.query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, template) in &self.query {
                for value in template.render_repeated(&bag, extensions)? {
                    pairs.append_pair(name, &value);
                }
            }
        }

        let body = if let Some(json) = &self.json {
            serde_json::to_vec(&json.render(&bag, extensions)?).map_err(|_error| bad_response())?
        } else if let Some(form) = &self.form {
            let mut values = Vec::new();
            for (name, template) in form {
                for value in template.render_repeated(&bag, extensions)? {
                    values.push((name.as_str(), value));
                }
            }
            let borrowed: Vec<_> = values
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect();
            form_urlencode(&borrowed).to_vec()
        } else {
            Vec::new()
        };

        let mut request = match self.method {
            RequestMethod::Get => HttpRequest::get(url.to_string()),
            RequestMethod::Post => HttpRequest::post(url.to_string(), body.into()),
        }
        .timeout(self.timeout)
        .connect_timeout(self.connect_timeout)
        .max_response_bytes(self.max_response_bytes);

        if self.json.is_some() {
            request = request
                .header("content-type", "application/json")
                .map_err(|_error| bad_response())?;
        } else if self.form.is_some() {
            request = request
                .header("content-type", "application/x-www-form-urlencoded")
                .map_err(|_error| bad_response())?;
        }
        for (name, template) in &self.headers {
            let value = template.render_text(&bag, extensions)?;
            if value.contains(['\r', '\n', '\0']) {
                return Err(bad_response());
            }
            request = request
                .header(name, value)
                .map_err(|_error| bad_response())?;
        }
        Ok(request)
    }

    pub(crate) const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub(crate) const fn authority(&self) -> &http::uri::Authority {
        &self.authority
    }

    pub(crate) const fn uses_credential_interpolation(&self) -> bool {
        self.credential_interpolation
    }
}

impl ReferenceUse {
    fn is_credential(&self) -> bool {
        self.reference
            .eq_ignore_ascii_case("http.request_headers.authorization")
            || self.reference.starts_with("raw_credentials.")
    }
}

fn compile_template(
    raw: &str,
    destination: &str,
    references: &mut BTreeSet<String>,
    uses: &mut Vec<ReferenceUse>,
) -> Result<Template, String> {
    let template = Template::compile(raw, references)
        .map_err(|error| format!("invalid template at `{destination}`: {error}"))?;
    uses.extend(template.references().map(|reference| ReferenceUse {
        reference: reference.to_owned(),
        destination: destination.to_owned(),
    }));
    Ok(template)
}

fn validate_url(config: &RequestConfig) -> Result<Url, String> {
    if config.url.contains(['{', '}']) {
        return Err("`request.url` must have a static scheme, host, and port".to_owned());
    }
    let url =
        Url::parse(&config.url).map_err(|_error| "`request.url` is not a valid URL".to_owned())?;
    if url.host_str().is_none() || url.cannot_be_a_base() {
        return Err("`request.url` must be an absolute URL with a host".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("`request.url` must not contain user-info".to_owned());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("`request.url` must not contain a query or fragment".to_owned());
    }
    match url.scheme() {
        "https" => {},
        "http" if config.insecure_http => {},
        "http" => {
            return Err(
                "plain HTTP requires `request.insecure_http: true`; use HTTPS otherwise".to_owned(),
            );
        },
        _ => return Err("`request.url` scheme must be `https` or `http`".to_owned()),
    }
    Ok(url)
}

fn authority(url: &Url) -> Result<http::uri::Authority, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "`request.url` must have a host".to_owned())?;
    let authority = url
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    authority
        .parse()
        .map_err(|_error| "`request.url` has an invalid HTTP authority".to_owned())
}

fn validate_bounds(config: &RequestConfig) -> Result<(), String> {
    if config.timeout_milliseconds == 0 {
        return Err("`request.timeout_milliseconds` must be greater than zero".to_owned());
    }
    if config.connect_timeout_milliseconds == 0
        || config.connect_timeout_milliseconds > config.timeout_milliseconds
    {
        return Err(
            "`request.connect_timeout_milliseconds` must be greater than zero and no larger than the request timeout"
                .to_owned(),
        );
    }
    if !(1..=HARD_MAX_RESPONSE_BYTES).contains(&config.max_response_bytes) {
        return Err(format!(
            "`request.max_response_bytes` must be between 1 and {HARD_MAX_RESPONSE_BYTES}"
        ));
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<(), String> {
    if name.eq_ignore_ascii_case("host") {
        return Err("`Host` is transport-owned and cannot be configured".to_owned());
    }
    if name.contains(['{', '}']) {
        return Err("request header names must be static".to_owned());
    }
    HttpRequest::get("https://header-validation.invalid")
        .header(name, "value")
        .map(|_| ())
        .map_err(|_error| format!("`{name}` is not a valid request header name"))
}

fn validate_reference_capabilities(
    references: &BTreeSet<String>,
    capabilities: &HashSet<String>,
) -> Result<(), String> {
    for reference in references {
        if reference.starts_with("raw_credentials.") {
            validate_raw_credential_reference(reference)?;
        }
        let required: Vec<_> = known_read_capabilities()
            .filter(|capability| {
                capability_namespaces(capability).iter().any(|prefix| {
                    prefix
                        .strip_suffix('.')
                        .map_or(reference == *prefix, |root| {
                            reference == root || reference.starts_with(prefix)
                        })
                })
            })
            .collect();
        if !required.is_empty()
            && !required
                .iter()
                .any(|capability| capabilities.contains(*capability))
        {
            return Err(format!(
                "template reference `{reference}` requires capability `{}`",
                required.join("` or `")
            ));
        }
        let raw_capability = reference
            .starts_with("raw_credentials.")
            .then_some("read_inbound_credentials");
        if let Some(capability) = raw_capability
            && !capabilities.contains(capability)
        {
            return Err(format!(
                "template reference `{reference}` requires capability `{capability}`"
            ));
        }
    }
    Ok(())
}

fn validate_raw_credential_reference(reference: &str) -> Result<(), String> {
    let Some(role) = reference
        .strip_prefix("raw_credentials.inbound_tokens.")
        .and_then(|reference| reference.strip_suffix(".token"))
    else {
        return Err(format!(
            "template reference `{reference}` is not supported; use `raw_credentials.inbound_tokens.<role>.token`"
        ));
    };
    if role.is_empty()
        || role.contains('.')
        || !role
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(format!(
            "template reference `{reference}` has an invalid inbound credential role"
        ));
    }
    Ok(())
}

fn validate_credential_uses(
    uses: &[ReferenceUse],
    capabilities: &HashSet<String>,
    allow: bool,
    destinations: &BTreeSet<String>,
) -> Result<(), String> {
    for use_ in uses {
        if !use_.is_credential() {
            continue;
        }
        let source_capability = if use_.reference.starts_with("raw_credentials.") {
            "read_inbound_credentials"
        } else {
            "read_headers"
        };
        if !capabilities.contains(source_capability) {
            return Err(format!(
                "credential template reference `{}` requires capability `{source_capability}`",
                use_.reference
            ));
        }
        if !allow {
            return Err(format!(
                "credential template reference `{}` requires `allow_credential_interpolation: true`",
                use_.reference
            ));
        }
        if !destinations.contains(&use_.destination) {
            return Err(format!(
                "credential template reference `{}` targets `{}`; add that exact destination to `credential_fields`",
                use_.reference, use_.destination
            ));
        }
    }
    Ok(())
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
    use std::collections::HashMap;
    use std::sync::Arc;

    use praxis_policy_core::extensions::MetaExtension;
    use praxis_policy_core::extensions::raw_credentials::{
        Credential, RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
    };
    use serde_json::json;

    use super::*;

    fn config(value: Value) -> RequestConfig {
        serde_json::from_value(value).expect("request config")
    }

    fn caps(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn compile(value: Value, capabilities: &[&str]) -> Result<CompiledRequest, String> {
        CompiledRequest::compile(&config(value), &caps(capabilities), false, &BTreeSet::new())
    }

    fn extensions() -> Extensions {
        Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_name: Some("report/export".to_owned()),
                ..MetaExtension::default()
            })),
            custom: Some(Arc::new(HashMap::from([
                ("enabled".to_owned(), json!(true)),
                ("count".to_owned(), json!(7)),
                ("tags".to_owned(), json!(["b", "a"])),
            ]))),
            ..Extensions::default()
        }
    }

    #[test]
    fn builds_typed_get_with_context_specific_encoding() {
        let request = compile(
            json!({
                "method": "GET",
                "url": "https://metadata.example/base",
                "path_segments": ["v1", "{meta.entity_name}"],
                "query": {"tag": "{custom.tags}", "enabled": "{custom.enabled}"},
                "headers": {"x-count": "{custom.count}"}
            }),
            &["perform_http"],
        )
        .expect("meta and custom are unrestricted")
        .build(&extensions())
        .expect("request renders");

        assert!(
            request
                .url
                .starts_with("https://metadata.example/base/v1/report%2Fexport?")
        );
        assert!(request.url.contains("tag=a"));
        assert!(request.url.contains("tag=b"));
        assert!(request.url.contains("enabled=true"));
        assert_eq!(request.headers.get("x-count").unwrap(), "7");
        assert!(request.body.is_empty());
    }

    #[test]
    fn builds_typed_json_and_form_posts() {
        let json_request = compile(
            json!({
                "method": "POST",
                "url": "https://metadata.example",
                "json": {
                    "enabled": "{custom.enabled}",
                    "count": "{custom.count}",
                    "label": "fixed",
                    "tags": "{custom.tags}"
                }
            }),
            &["perform_http"],
        )
        .expect("JSON config")
        .build(&extensions())
        .expect("JSON request renders");
        assert_eq!(
            serde_json::from_slice::<Value>(&json_request.body).unwrap(),
            json!({
                "enabled": true,
                "count": 7,
                "label": "fixed",
                "tags": ["a", "b"]
            })
        );
        assert_eq!(
            json_request.headers.get("content-type").unwrap(),
            "application/json"
        );

        let form_request = compile(
            json!({
                "method": "POST",
                "url": "https://metadata.example",
                "form": {"tag": "{custom.tags}", "resource": "{meta.entity_name}"}
            }),
            &["perform_http"],
        )
        .expect("form config")
        .build(&extensions())
        .expect("form request renders");
        assert_eq!(
            std::str::from_utf8(&form_request.body).unwrap(),
            "resource=report%2Fexport&tag=a&tag=b"
        );
    }

    #[test]
    fn rejects_dynamic_authority_plain_http_host_and_traversal() {
        for value in [
            json!({"method": "GET", "url": "https://{meta.entity_name}.example"}),
            json!({"method": "GET", "url": "http://metadata.example"}),
            json!({"method": "GET", "url": "https://metadata.example", "headers": {"hOsT": "evil.example"}}),
            json!({"method": "GET", "url": "https://metadata.example", "headers": {"x-value": "one\r\ntwo"}}),
        ] {
            assert!(compile(value, &["perform_http"]).is_err());
        }

        let request = compile(
            json!({
                "method": "GET",
                "url": "https://metadata.example",
                "path_segments": ["{meta.entity_name}"]
            }),
            &["perform_http"],
        )
        .expect("template compiles");
        let traversal = Extensions {
            meta: Some(Arc::new(MetaExtension {
                entity_name: Some("..".to_owned()),
                ..MetaExtension::default()
            })),
            ..Extensions::default()
        };
        assert!(matches!(
            request.build(&traversal),
            Err(error)
                if error
                    == CalloutFailure::new(MetadataCalloutErrorCode::RejectedDestination)
        ));

        let request = compile(
            json!({
                "method": "GET",
                "url": "https://metadata.example",
                "headers": {"x-value": "{custom.injected}"}
            }),
            &["perform_http"],
        )
        .expect("header template compiles");
        let injection = Extensions {
            custom: Some(Arc::new(HashMap::from([(
                "injected".to_owned(),
                json!("one\r\ntwo"),
            )]))),
            ..Extensions::default()
        };
        assert!(matches!(
            request.build(&injection),
            Err(error) if error == bad_response()
        ));
    }

    #[test]
    fn generated_body_content_type_cannot_be_overridden() {
        for body in [
            json!({"json": {"active": true}}),
            json!({"form": {"active": "true"}}),
        ] {
            let mut request = json!({
                "method": "POST",
                "url": "https://metadata.example",
                "headers": {"CoNtEnT-TyPe": "text/plain"}
            });
            request
                .as_object_mut()
                .expect("request object")
                .extend(body.as_object().expect("body object").clone());

            let error = compile(request, &["perform_http"])
                .expect_err("generated content type must be authoritative");
            assert!(error.contains("Content-Type"), "unexpected error: {error}");
        }
    }

    #[test]
    fn capability_validation_names_the_reference_and_requirement() {
        let error = compile(
            json!({
                "method": "GET",
                "url": "https://metadata.example",
                "path_segments": ["{subject.id}"]
            }),
            &["perform_http"],
        )
        .expect_err("subject is protected");
        assert!(error.contains("subject.id"));
        assert!(error.contains("read_subject"));

        compile(
            json!({
                "method": "GET",
                "url": "https://metadata.example",
                "query": {"resource": "{meta.entity_name}"}
            }),
            &["perform_http"],
        )
        .expect("meta.* must not create a fictitious capability");
    }

    #[test]
    fn credential_interpolation_requires_all_three_gates() {
        let config = config(json!({
            "method": "POST",
            "url": "https://metadata.example",
            "json": {"token": "{http.request_headers.authorization}"}
        }));
        let destination = "request.json.token".to_owned();

        for (capabilities, allow, fields) in [
            (
                caps(&["perform_http"]),
                true,
                BTreeSet::from([destination.clone()]),
            ),
            (
                caps(&["perform_http", "read_headers"]),
                false,
                BTreeSet::from([destination.clone()]),
            ),
            (
                caps(&["perform_http", "read_headers"]),
                true,
                BTreeSet::new(),
            ),
        ] {
            assert!(CompiledRequest::compile(&config, &capabilities, allow, &fields).is_err());
        }
        CompiledRequest::compile(
            &config,
            &caps(&["perform_http", "read_headers"]),
            true,
            &BTreeSet::from([destination]),
        )
        .expect("all credential gates are present");
    }

    #[test]
    fn raw_inbound_credential_resolves_without_entering_the_policy_bag() {
        let request = config(json!({
            "method": "POST",
            "url": "https://metadata.example",
            "json": {"token": "{raw_credentials.inbound_tokens.user.token}"}
        }));
        let compiled = CompiledRequest::compile(
            &request,
            &caps(&["perform_http", "read_inbound_credentials"]),
            true,
            &BTreeSet::from(["request.json.token".to_owned()]),
        )
        .expect("the exact raw inbound token path is permitted");
        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new(
                "credential-value",
                Credential::Header {
                    name: "authorization".to_owned(),
                },
                TokenKind::Opaque,
            ),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Extensions::default()
        };

        let outbound = compiled
            .build(&extensions)
            .expect("the raw credential is present");
        assert_eq!(
            serde_json::from_slice::<Value>(&outbound.body).unwrap(),
            json!({"token": "credential-value"})
        );
        assert!(compiled.uses_credential_interpolation());
    }

    #[test]
    fn unsupported_and_ambiguous_raw_credential_paths_fail_closed() {
        let invalid = config(json!({
            "method": "POST",
            "url": "https://metadata.example",
            "json": {"token": "{raw_credentials.delegated_tokens.token}"}
        }));
        let error = CompiledRequest::compile(
            &invalid,
            &caps(&["perform_http", "read_delegated_tokens"]),
            true,
            &BTreeSet::from(["request.json.token".to_owned()]),
        )
        .expect_err("delegated-token selection has no stable path contract");
        assert!(error.contains("not supported"), "unexpected error: {error}");

        let request = config(json!({
            "method": "POST",
            "url": "https://metadata.example",
            "json": {"token": "{raw_credentials.inbound_tokens.user.token}"}
        }));
        let compiled = CompiledRequest::compile(
            &request,
            &caps(&["perform_http", "read_inbound_credentials"]),
            true,
            &BTreeSet::from(["request.json.token".to_owned()]),
        )
        .expect("raw credential config");
        let token = || {
            RawInboundToken::new(
                "credential-value",
                Credential::Header {
                    name: "authorization".to_owned(),
                },
                TokenKind::Opaque,
            )
        };
        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(TokenRole::User, token());
        raw.inbound_tokens
            .insert(TokenRole::Custom("user".to_owned()), token());
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Extensions::default()
        };

        assert!(matches!(
            compiled.build(&extensions),
            Err(error) if error == bad_response()
        ));
    }
}
