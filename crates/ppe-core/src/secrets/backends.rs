// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Providers with no dependencies beyond the standard library.
//
// `env` reads a variable, `file` reads a path. Between them they cover the
// deployments that hand a process its secrets through the platform:
// Kubernetes Secret volumes, CSI-projected secrets, container secret mounts,
// and a Vault Agent sidecar templating to disk. A deployment using any of
// those needs no network backend at all.
//
// Both read with blocking calls inside an async method. That is deliberate and
// bounded: a value is read at startup and on a host-driven refresh, never on
// the request path, so the read is never on a latency path and a few
// microseconds of blocking costs less than the machinery to avoid it.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::config::SecretProviderConfig;
use super::error::SecretError;
use super::provider::{SecretProvider, SecretProviderFactory};

/// Reads a value from the process environment, addressed by variable name.
///
/// A refresh re-reads and finds the same bytes: a process's environment is
/// fixed at exec and nothing can change it from outside. Values bound to this
/// provider therefore never rotate without a restart, which is a property of
/// the platform rather than a limitation here.
pub struct EnvSecretProvider;

#[async_trait]
impl SecretProvider for EnvSecretProvider {
    async fn get_secret(&self, reference: &str) -> Result<Zeroizing<String>, SecretError> {
        classify_env(reference, std::env::var(reference))
    }
}

/// Turn one environment read into a result.
///
/// Split from the read so the classification is testable: setting a variable
/// is `unsafe` under edition 2024 and this crate forbids `unsafe`, so a test
/// cannot arrange the three cases through the environment itself.
fn classify_env(
    reference: &str,
    read: Result<String, std::env::VarError>,
) -> Result<Zeroizing<String>, SecretError> {
    match read {
        Ok(value) if value.is_empty() => Err(SecretError::malformed(
            reference,
            "the variable is set and empty",
        )),
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(std::env::VarError::NotPresent) => Err(SecretError::not_found(reference)),
        Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::malformed(
            reference,
            "the variable is not valid UTF-8",
        )),
    }
}

/// Builds [`EnvSecretProvider`].
pub struct EnvSecretProviderFactory;

impl SecretProviderFactory for EnvSecretProviderFactory {
    fn kind(&self) -> &str {
        "env"
    }

    fn build(
        &self,
        _config: &SecretProviderConfig,
    ) -> Result<Arc<dyn SecretProvider>, SecretError> {
        Ok(Arc::new(EnvSecretProvider))
    }
}

/// Settings for [`FileSecretProvider`].
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSettings {
    /// The directory every reference resolves under, if the operator wants
    /// references confined.
    #[serde(default)]
    base_dir: Option<PathBuf>,
}

/// Reads a value from a file, addressed by path.
///
/// With `base_dir` set, a reference must be relative and must not contain
/// `..`, so the set of files this provider can read is the directory an
/// operator named. Without it, a reference is any path the process can open,
/// which is the more convenient default and the less contained one.
pub struct FileSecretProvider {
    base_dir: Option<PathBuf>,
}

impl FileSecretProvider {
    /// Where a reference resolves, refusing one that would leave `base_dir`.
    fn path_for(&self, reference: &str) -> Result<PathBuf, SecretError> {
        let candidate = Path::new(reference);
        let Some(base) = self.base_dir.as_ref() else {
            return Ok(candidate.to_path_buf());
        };
        if candidate.is_absolute() {
            return Err(SecretError::reference(
                reference,
                "the provider declares `base_dir`, so a reference must be relative to it",
            ));
        }
        if candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(SecretError::reference(
                reference,
                "`..` would resolve outside `base_dir`",
            ));
        }
        Ok(base.join(candidate))
    }
}

#[async_trait]
impl SecretProvider for FileSecretProvider {
    async fn get_secret(&self, reference: &str) -> Result<Zeroizing<String>, SecretError> {
        let path = self.path_for(reference)?;
        let raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretError::not_found(reference)
            } else {
                // The path is operator-authored and safe to print; the error
                // text comes from the OS and carries no file content.
                SecretError::backend(format!("reading `{}`: {e}", path.display()))
            }
        })?);

        let value = trim_one_trailing_newline(&raw);
        if value.is_empty() {
            // An empty read is a misconfiguration an operator must see, and on
            // a refresh it is how a half-written file looks. Treating it as a
            // value would replace a working credential with nothing.
            return Err(SecretError::malformed(reference, "the file is empty"));
        }
        Ok(Zeroizing::new(value.to_owned()))
    }
}

/// Strip the trailing newline a text editor or a shell redirect leaves behind.
///
/// Exactly one, and the `\r` in front of it, so a value that deliberately ends
/// in a blank line keeps all but the last. A credential almost never ends in a
/// newline on purpose and almost always acquires one by accident, and sending
/// one upstream fails authentication in a way that is very hard to see.
fn trim_one_trailing_newline(value: &str) -> &str {
    value
        .strip_suffix('\n')
        .map_or(value, |v| v.strip_suffix('\r').unwrap_or(v))
}

/// Builds [`FileSecretProvider`].
pub struct FileSecretProviderFactory;

impl SecretProviderFactory for FileSecretProviderFactory {
    fn kind(&self) -> &str {
        "file"
    }

    fn build(&self, config: &SecretProviderConfig) -> Result<Arc<dyn SecretProvider>, SecretError> {
        let settings: FileSettings = if config.settings.is_null() {
            FileSettings::default()
        } else {
            serde_yaml::from_value(config.settings.clone())
                .map_err(|e| SecretError::config(format!("{e}")))?
        };
        Ok(Arc::new(FileSecretProvider {
            base_dir: settings.base_dir,
        }))
    }
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
    use super::*;

    fn file_provider(base_dir: Option<&str>) -> FileSecretProvider {
        FileSecretProvider {
            base_dir: base_dir.map(PathBuf::from),
        }
    }

    #[test]
    fn one_trailing_newline_goes_and_the_rest_stays() {
        assert_eq!(trim_one_trailing_newline("secret\n"), "secret");
        assert_eq!(trim_one_trailing_newline("secret\r\n"), "secret");
        assert_eq!(trim_one_trailing_newline("secret"), "secret");
        assert_eq!(trim_one_trailing_newline("secret\n\n"), "secret\n");
        assert_eq!(trim_one_trailing_newline(""), "");
    }

    #[test]
    fn base_dir_refuses_a_reference_that_would_leave_it() {
        let provider = file_provider(Some("/etc/ppe"));
        provider
            .path_for("../../etc/shadow")
            .expect_err("`..` escapes base_dir");
        provider
            .path_for("/etc/shadow")
            .expect_err("an absolute path ignores base_dir");
        assert_eq!(
            provider.path_for("upstream.key").expect("relative is fine"),
            PathBuf::from("/etc/ppe/upstream.key")
        );
    }

    #[test]
    fn without_base_dir_any_path_resolves() {
        let provider = file_provider(None);
        assert_eq!(
            provider
                .path_for("/etc/ppe/upstream.key")
                .expect("absolute"),
            PathBuf::from("/etc/ppe/upstream.key")
        );
    }

    #[tokio::test]
    async fn a_missing_file_is_not_found_and_an_empty_one_is_malformed() {
        let dir = std::env::temp_dir().join(format!("ppe-secrets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let provider = file_provider(Some(dir.to_str().expect("utf-8 temp dir")));

        let missing = provider
            .get_secret("absent.key")
            .await
            .expect_err("no file");
        assert!(matches!(missing, SecretError::NotFound { .. }), "{missing}");

        std::fs::write(dir.join("empty.key"), "\n").expect("write");
        let empty = provider
            .get_secret("empty.key")
            .await
            .expect_err("an empty file is not a credential");
        assert!(matches!(empty, SecretError::Malformed { .. }), "{empty}");

        std::fs::write(dir.join("good.key"), "hunter2\n").expect("write");
        let value = provider.get_secret("good.key").await.expect("reads");
        assert_eq!(value.as_str(), "hunter2");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_distinguishes_absent_from_set_and_empty() {
        let absent =
            classify_env("VAR", Err(std::env::VarError::NotPresent)).expect_err("never set");
        assert!(matches!(absent, SecretError::NotFound { .. }), "{absent}");

        let empty = classify_env("VAR", Ok(String::new())).expect_err("set and empty");
        assert!(matches!(empty, SecretError::Malformed { .. }), "{empty}");

        let not_utf8 = classify_env(
            "VAR",
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                "bytes",
            ))),
        )
        .expect_err("not valid UTF-8");
        assert!(
            matches!(not_utf8, SecretError::Malformed { .. }),
            "{not_utf8}"
        );

        let value = classify_env("VAR", Ok("hunter2".to_owned())).expect("reads");
        assert_eq!(value.as_str(), "hunter2");
    }

    #[test]
    fn a_non_string_base_dir_is_a_config_error() {
        let mut settings = serde_yaml::Mapping::new();
        settings.insert("base_dir".into(), serde_yaml::Value::Bool(true));
        let built = FileSecretProviderFactory.build(&SecretProviderConfig {
            kind: "file".to_owned(),
            settings: serde_yaml::Value::Mapping(settings),
        });
        let Err(err) = built else {
            panic!("base_dir is not a path");
        };
        assert!(matches!(err, SecretError::Config { .. }), "{err}");
    }
}
