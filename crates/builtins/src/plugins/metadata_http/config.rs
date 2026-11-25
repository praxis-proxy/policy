// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::BTreeSet;

use praxis_policy_core::plugin::PluginConfig;
use serde::{Deserialize, Serialize};

use crate::plugins::metadata_common::request::{CompiledRequest, RequestConfig};
use crate::plugins::metadata_common::response::{ResponseConfig, ResponseParser};

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SharedSecretScheme {
    Bearer,
    Header,
    Basic,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
enum AuthConfig {
    SharedSecret {
        scheme: SharedSecretScheme,
        secret: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MetadataHttpConfig {
    #[serde(default = "default_true")]
    require_authenticated: bool,
    request: RequestConfig,
    #[serde(default)]
    response: ResponseConfig,
    #[serde(default)]
    allow_credential_interpolation: bool,
    #[serde(default)]
    credential_fields: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<AuthConfig>,
}

pub(super) struct CompiledConfig {
    pub(super) require_authenticated: bool,
    pub(super) request: CompiledRequest,
    pub(super) response: ResponseParser,
}

impl CompiledConfig {
    pub(super) fn compile(plugin: &PluginConfig) -> Result<Self, String> {
        let raw = plugin
            .config
            .clone()
            .ok_or_else(|| "a `config:` block is required".to_owned())?;
        let config: MetadataHttpConfig = serde_json::from_value(raw)
            .map_err(|error| format!("invalid metadata/http config: {error}"))?;
        if config.require_authenticated
            && !plugin.capabilities.iter().any(|capability| {
                praxis_policy_apl_cmf::capability_namespaces(capability).contains(&"authenticated")
            })
        {
            return Err(
                "`require_authenticated: true` requires a capability that exposes the subject baseline, such as `read_subject`"
                    .to_owned(),
            );
        }
        let request = CompiledRequest::compile(
            &config.request,
            &plugin.capabilities,
            config.allow_credential_interpolation,
            &config.credential_fields,
        )?;
        let response = ResponseParser::compile(&config.response)?;
        if let Some(auth) = &config.auth {
            validate_auth(auth, &config.request)?;
            return Err(
                "`auth` requires the exact per-name secret grant from prerequisite PR #384"
                    .to_owned(),
            );
        }
        Ok(Self {
            require_authenticated: config.require_authenticated,
            request,
            response,
        })
    }
}

fn validate_auth(auth: &AuthConfig, request: &RequestConfig) -> Result<(), String> {
    let AuthConfig::SharedSecret {
        scheme,
        secret,
        header,
        username,
    } = auth;
    if secret.trim().is_empty() {
        return Err("`auth.secret` must name a top-level secret value".to_owned());
    }
    let target = match scheme {
        SharedSecretScheme::Bearer => {
            if header.is_some() || username.is_some() {
                return Err("bearer auth does not accept `header` or `username`".to_owned());
            }
            "authorization"
        },
        SharedSecretScheme::Header => {
            if username.is_some() {
                return Err("header auth does not accept `username`".to_owned());
            }
            let header = header
                .as_deref()
                .ok_or_else(|| "header auth requires `header`".to_owned())?;
            if header.eq_ignore_ascii_case("host") {
                return Err("shared-secret auth cannot target `Host`".to_owned());
            }
            praxis_policy_core::http::HttpRequest::get("https://header-validation.invalid")
                .header(header, "value")
                .map_err(|_error| "`auth.header` is not a valid header name".to_owned())?;
            header
        },
        SharedSecretScheme::Basic => {
            if header.is_some() {
                return Err("basic auth does not accept `header`".to_owned());
            }
            let username = username
                .as_deref()
                .ok_or_else(|| "basic auth requires `username`".to_owned())?;
            if username.is_empty()
                || username.contains(':')
                || username.chars().any(char::is_control)
            {
                return Err(
                    "basic auth username must be nonempty and contain no colon or control character"
                        .to_owned(),
                );
            }
            "authorization"
        },
    };
    if request
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case(target))
    {
        return Err(format!(
            "shared-secret auth header `{target}` collides with `request.headers`"
        ));
    }
    Ok(())
}
