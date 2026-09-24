// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Operator-authored settings for one Vault provider instance.
//
// Auth is internally tagged on `method:` with no default: `kubernetes`
// or `approle`. serde_yaml cannot round-trip an externally tagged enum
// as a mapping (`Value::Tagged` is a YAML tag, not a key).

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

use praxis_policy_core::secrets::SecretError;

use crate::KIND;

/// Default Kubernetes auth mount.
fn default_kubernetes_mount() -> String {
    "kubernetes".to_owned()
}

/// Default `AppRole` auth mount.
fn default_approle_mount() -> String {
    "approle".to_owned()
}

/// Projected service-account token path kubelet writes.
fn default_token_path() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

/// Flattened `kind: vault` settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultSettings {
    /// Vault origin, for example `https://vault.example.com:8200`.
    pub address: String,
    /// Vault namespace, sent as `X-Vault-Namespace` when set.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Permit an `http://` address. Required for one; refused on
    /// `https://` because the two together are contradictory.
    #[serde(default)]
    pub insecure_http: bool,
    /// Permit `secret_id: { literal: ... }`. Required for one; a
    /// production document must read the id from the environment or a
    /// file.
    #[serde(default)]
    pub allow_insecure_literal: bool,
    pub auth: VaultAuth,
}

/// How this instance authenticates. No default, no other methods.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "method", rename_all = "snake_case")]
pub(crate) enum VaultAuth {
    Kubernetes {
        role: String,
        #[serde(default = "default_kubernetes_mount")]
        mount: String,
        #[serde(default = "default_token_path")]
        token_path: PathBuf,
    },
    Approle {
        role_id: String,
        #[serde(default = "default_approle_mount")]
        mount: String,
        secret_id: SecretIdSource,
    },
}

/// Where an `AppRole` `secret_id` is read from.
///
/// Untagged so the document writes `{ env: NAME }`, `{ file: PATH }`, or
/// `{ literal: VALUE }` rather than a YAML tag.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub(crate) enum SecretIdSource {
    Env {
        env: String,
    },
    File {
        file: PathBuf,
    },
    /// Development-only. A production document must not use this: the
    /// credential then lives in the config and in every copy of it.
    Literal {
        literal: String,
    },
}

impl VaultSettings {
    /// Parse and validate. Does not contact Vault.
    pub(crate) fn from_config(
        settings: &serde_yaml::Value,
    ) -> Result<ValidatedSettings, SecretError> {
        if settings.is_null() {
            return Err(SecretError::config(
                "kind `vault` requires `address` and `auth`",
            ));
        }
        let parsed: Self = serde_yaml::from_value(settings.clone())
            .map_err(|e| SecretError::config(format!("{e}")))?;
        parsed.validate()
    }

    fn validate(self) -> Result<ValidatedSettings, SecretError> {
        let address = normalize_address(&self.address, self.insecure_http)?;
        let namespace = self.namespace.and_then(|n| {
            let t = n.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_owned())
            }
        });
        match &self.auth {
            VaultAuth::Kubernetes { role, mount, .. } => {
                require_non_empty(role, "auth.kubernetes.role")?;
                require_non_empty(mount, "auth.kubernetes.mount")?;
            },
            VaultAuth::Approle {
                role_id,
                mount,
                secret_id,
            } => {
                require_non_empty(role_id, "auth.approle.role_id")?;
                require_non_empty(mount, "auth.approle.mount")?;
                if matches!(secret_id, SecretIdSource::Literal { .. }) {
                    if !self.allow_insecure_literal {
                        return Err(SecretError::config(
                            "auth.approle.secret_id.literal requires `allow_insecure_literal: true`; \
                             a production document must read the secret_id from an environment \
                             variable or a file",
                        ));
                    }
                    tracing::warn!(
                        kind = KIND,
                        "auth.approle.secret_id.literal is development-only"
                    );
                }
            },
        }
        Ok(ValidatedSettings {
            address,
            namespace,
            auth: self.auth,
        })
    }
}

/// Settings after address and auth checks.
#[derive(Debug)]
pub(crate) struct ValidatedSettings {
    pub address: String,
    pub namespace: Option<String>,
    pub auth: VaultAuth,
}

impl fmt::Debug for VaultAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kubernetes {
                role,
                mount,
                token_path,
            } => f
                .debug_struct("Kubernetes")
                .field("role", role)
                .field("mount", mount)
                .field("token_path", token_path)
                .finish(),
            Self::Approle {
                mount, secret_id, ..
            } => f
                .debug_struct("Approle")
                .field("mount", mount)
                .field("secret_id", secret_id)
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Debug for SecretIdSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env { env: name } => f.debug_tuple("Env").field(name).finish(),
            Self::File { file: path } => f.debug_tuple("File").field(path).finish(),
            Self::Literal { .. } => f.debug_tuple("Literal").field(&"[redacted]").finish(),
        }
    }
}

impl VaultAuth {
    pub(crate) fn kind_name(&self) -> &'static str {
        match self {
            Self::Kubernetes { .. } => "kubernetes",
            Self::Approle { .. } => "approle",
        }
    }
}

impl SecretIdSource {
    /// Read the current `secret_id`. Env and file are re-read on every
    /// login so a rotated credential is picked up without a restart.
    pub(crate) fn read(&self) -> Result<Zeroizing<String>, SecretError> {
        match self {
            Self::Env { env: name } => match std::env::var(name) {
                Ok(value) if value.is_empty() => Err(SecretError::config(format!(
                    "AppRole secret_id environment variable `{name}` is set and empty"
                ))),
                Ok(value) => Ok(Zeroizing::new(value)),
                Err(std::env::VarError::NotPresent) => Err(SecretError::config(format!(
                    "AppRole secret_id environment variable `{name}` is not set"
                ))),
                Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::config(format!(
                    "AppRole secret_id environment variable `{name}` is not valid UTF-8"
                ))),
            },
            Self::File { file: path } => read_trimmed_file(path, "AppRole secret_id file"),
            Self::Literal { literal } if literal.is_empty() => Err(SecretError::config(
                "auth.approle.secret_id.literal is empty",
            )),
            Self::Literal { literal } => Ok(Zeroizing::new(literal.clone())),
        }
    }
}

/// Kubernetes service-account JWT, reread on every login because kubelet
/// rotates a projected token in place.
pub(crate) fn read_service_account_token(path: &Path) -> Result<Zeroizing<String>, SecretError> {
    read_trimmed_file(path, "Kubernetes service-account token")
}

fn read_trimmed_file(path: &Path, what: &str) -> Result<Zeroizing<String>, SecretError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        SecretError::backend(format!(
            "{what} at `{}` could not be read: {e}",
            path.display()
        ))
    })?;
    let trimmed = raw
        .strip_suffix('\n')
        .map_or(raw.as_str(), |v| v.strip_suffix('\r').unwrap_or(v));
    if trimmed.is_empty() {
        return Err(SecretError::backend(format!(
            "{what} at `{}` is empty",
            path.display()
        )));
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

fn normalize_address(address: &str, insecure_http: bool) -> Result<String, SecretError> {
    let trimmed = address.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SecretError::config("`address` is empty"));
    }
    let https = trimmed.starts_with("https://");
    let http = trimmed.starts_with("http://");
    if !https && !http {
        return Err(SecretError::config(
            "`address` must start with `https://`, or with `http://` when `insecure_http` is set",
        ));
    }
    if http && !insecure_http {
        return Err(SecretError::config(
            "`address` is `http://`; set `insecure_http: true` to allow it",
        ));
    }
    if https && insecure_http {
        return Err(SecretError::config(
            "`insecure_http` is set but `address` is `https://`",
        ));
    }
    let rest = if https {
        trimmed.get(8..).unwrap_or("")
    } else {
        trimmed.get(7..).unwrap_or("")
    };
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
    {
        return Err(SecretError::config(
            "`address` is an origin (`https://host[:port]`), not a path, query, \
             fragment, or URL with userinfo; KV paths belong in each value's `ref`",
        ));
    }
    Ok(trimmed.to_owned())
}

fn require_non_empty(value: &str, field: &str) -> Result<(), SecretError> {
    if value.trim().is_empty() {
        return Err(SecretError::config(format!("`{field}` is empty")));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<ValidatedSettings, SecretError> {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).expect("yaml");
        VaultSettings::from_config(&value)
    }

    #[test]
    fn https_is_required_unless_insecure_http_is_set() {
        let err = parse(
            "
address: http://vault.example.com
auth:
  method: kubernetes
  role: ppe
",
        )
        .expect_err("http without the flag");
        assert!(format!("{err}").contains("insecure_http"), "{err}");
    }

    #[test]
    fn insecure_http_allows_http_and_refuses_https() {
        parse(
            "
address: http://vault.example.com
insecure_http: true
auth:
  method: kubernetes
  role: ppe
",
        )
        .expect("flag permits http");
        let err = parse(
            "
address: https://vault.example.com
insecure_http: true
auth:
  method: kubernetes
  role: ppe
",
        )
        .expect_err("flag plus https is contradictory");
        assert!(format!("{err}").contains("insecure_http"), "{err}");
    }

    #[test]
    fn address_must_be_an_origin() {
        let err = parse(
            "
address: https://vault.example.com/v1
auth:
  method: kubernetes
  role: ppe
",
        )
        .expect_err("path on the address");
        assert!(format!("{err}").contains("origin"), "{err}");
    }

    #[test]
    fn address_refuses_userinfo_query_and_fragment() {
        for bad in [
            "https://user:pass@vault.example.com",
            "https://vault.example.com?ns=prod",
            "https://vault.example.com#frag",
        ] {
            let yaml = format!(
                "
address: {bad}
auth:
  method: kubernetes
  role: ppe
"
            );
            let err = parse(&yaml).expect_err(bad);
            assert!(format!("{err}").contains("origin"), "{bad}: {err}");
        }
    }

    #[test]
    fn a_literal_secret_id_requires_the_flag() {
        let err = parse(
            "
address: https://vault.example.com
auth:
  method: approle
  role_id: role-uuid
  secret_id:
    literal: dev-only
",
        )
        .expect_err("literal without the flag");
        assert!(format!("{err}").contains("allow_insecure_literal"), "{err}");
    }

    #[test]
    fn env_secret_id_reports_when_unset() {
        let err = SecretIdSource::Env {
            env: "PPE_VAULT_TEST_UNSET_SECRET_ID_9f3c".into(),
        }
        .read()
        .expect_err("unset");
        assert!(format!("{err}").contains("not set"), "{err}");
    }

    #[test]
    fn file_secret_id_reads_trimmed() {
        let dir = std::env::temp_dir().join(format!("ppe-vault-sid-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("secret_id");
        std::fs::write(&path, "from-file\n").expect("write");
        let value = SecretIdSource::File { file: path }.read().expect("read");
        assert_eq!(value.as_str(), "from-file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_is_required_and_has_no_default() {
        let err = parse("address: https://vault.example.com").expect_err("no auth");
        assert!(format!("{err}").contains("auth"), "{err}");
    }

    #[test]
    fn kubernetes_and_approle_both_parse() {
        let k8s = parse(
            "
address: https://vault.example.com
namespace: prod
auth:
  method: kubernetes
  role: ppe
",
        )
        .expect("k8s");
        assert_eq!(k8s.address, "https://vault.example.com");
        assert_eq!(k8s.namespace.as_deref(), Some("prod"));
        assert_eq!(k8s.auth.kind_name(), "kubernetes");

        let approle = parse(
            "
address: https://vault.example.com:8200/
auth:
  method: approle
  role_id: role-uuid
  secret_id:
    env: VAULT_SECRET_ID
",
        )
        .expect("approle");
        assert_eq!(approle.address, "https://vault.example.com:8200");
        assert_eq!(approle.auth.kind_name(), "approle");
    }

    #[test]
    fn a_literal_secret_id_is_redacted_in_debug() {
        let source = SecretIdSource::Literal {
            literal: "super-secret".into(),
        };
        let rendered = format!("{source:?}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
    }

    #[test]
    fn unknown_settings_are_refused() {
        let err = parse(
            "
address: https://vault.example.com
token: s.something
auth:
  method: kubernetes
  role: ppe
",
        )
        .expect_err("unknown field");
        assert!(matches!(err, SecretError::Config { .. }), "{err}");
    }

    #[test]
    fn unknown_nested_auth_settings_are_refused() {
        for yaml in [
            "
address: https://vault.example.com
auth:
  method: kubernetes
  role: ppe
  token_paht: /wrong
",
            "
address: https://vault.example.com
auth:
  method: approle
  role_id: role-uuid
  secret_id:
    env: VAULT_SECRET_ID
    file: /also-wrong
",
        ] {
            let err = parse(yaml).expect_err("unknown nested field");
            assert!(matches!(err, SecretError::Config { .. }), "{err}");
        }
    }
}
