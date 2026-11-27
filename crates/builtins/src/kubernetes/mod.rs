// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// What every builtin that calls the Kubernetes API server shares: where the
// server is, and the bearer token PPE presents to it. Crate-private; each
// builtin re-exports the public types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::validation::https::require_https_url;

pub(crate) mod reviewer_token;

fn default_refresh_secs() -> u64 {
    60
}

fn default_timeout_secs() -> u64 {
    5
}

// -----------------------------------------------------------------------------
// ApiServerConfig
// -----------------------------------------------------------------------------

/// Where the API server is, and how PPE authenticates to it. TLS trust belongs
/// to the host's transport.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiServerConfig {
    /// Bound on connection establishment alone. Left to the transport when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,

    /// PPE's own bearer token. Its identity needs `create` on the review the
    /// builtin sends: `tokenreviews` for identity, `subjectaccessreviews` for
    /// authorization.
    pub reviewer_token: ReviewerTokenSource,

    /// Overall deadline for one review, covering connect and I/O.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// The API server's base URL, such as `https://kubernetes.default.svc`.
    pub url: String,
}

impl ApiServerConfig {
    /// The URL of `path` on this API server.
    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url.trim_end_matches('/'))
    }

    /// Validate the connection settings.
    ///
    /// # Errors
    ///
    /// A URL that is not an HTTPS base URL with a host, or a zero timeout or
    /// refresh interval.
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_api_server_url(&self.url)?;
        if self.timeout_secs == 0 {
            return Err("`api_server.timeout_secs` is zero, so every review would time out".into());
        }
        if let ReviewerTokenSource::File {
            refresh_secs: 0, ..
        } = self.reviewer_token
        {
            return Err("`reviewer_token.refresh_secs` is zero; omit it for the default".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// ReviewerTokenSource
// -----------------------------------------------------------------------------

/// Where PPE's own token comes from.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum ReviewerTokenSource {
    /// An environment variable, read once at load.
    Env {
        /// The variable holding the token.
        name: String,
    },
    /// A file, re-read once `refresh_secs` has passed so a projected token
    /// rotates.
    File {
        /// Path to the token, such as
        /// `/var/run/secrets/kubernetes.io/serviceaccount/token`.
        path: PathBuf,
        /// How long a read is reused before the file is read again.
        #[serde(default = "default_refresh_secs")]
        refresh_secs: u64,
    },
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Require an HTTPS base URL the review path can be appended to. A query or
/// fragment would end up in front of the appended path.
fn validate_api_server_url(raw: &str) -> Result<(), String> {
    let url = require_https_url("api_server.url", raw)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "`api_server.url` must be a base URL without a query or fragment, got '{raw}'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_api_server_url;

    // -----------------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------------

    #[test]
    fn an_https_base_url_with_a_host_is_accepted() {
        for url in [
            "https://kubernetes.default.svc",
            "https://localhost:6443",
            "https://proxy.example/k8s/",
        ] {
            assert_eq!(
                validate_api_server_url(url),
                Ok(()),
                "{url} should be accepted"
            );
        }
    }

    #[test]
    fn a_query_or_a_fragment_is_rejected() {
        for url in [
            "https://kubernetes.default.svc?x=1",
            "https://kubernetes.default.svc#frag",
        ] {
            assert!(
                validate_api_server_url(url).is_err(),
                "{url} must be rejected"
            );
        }
    }
}
