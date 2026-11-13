// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Providers with no network dependency.
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

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use cap_std::ambient_authority;
use cap_std::fs::Dir;

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

/// Refuse any setting on an `env` provider.
///
/// A key here is one no read will ever consult, since the whole address is the
/// variable name in the value's `ref`. A `base_dir` left behind when a value
/// moved from `file` to `env` would otherwise read as applied while the
/// reference resolved as a variable name.
fn reject_env_settings(settings: &serde_yaml::Value) -> Result<(), SecretError> {
    if settings.is_null() {
        return Ok(());
    }
    let Some(declared) = settings.as_mapping() else {
        return Err(SecretError::config(
            "`env` takes no settings, and this provider declares something that is not a mapping",
        ));
    };
    if declared.is_empty() {
        return Ok(());
    }
    // Sorted so a provider with two stray keys reports them the same way on
    // every run.
    let mut keys: Vec<String> = declared
        .keys()
        .map(|key| {
            key.as_str()
                .map_or_else(|| format!("{key:?}"), str::to_owned)
        })
        .collect();
    keys.sort();
    Err(SecretError::config(format!(
        "`env` takes no settings, and this provider declares [{}]; a value bound to `env` names \
         an environment variable in its `ref` and nothing else",
        keys.join(", ")
    )))
}

/// Builds [`EnvSecretProvider`].
pub struct EnvSecretProviderFactory;

impl SecretProviderFactory for EnvSecretProviderFactory {
    fn kind(&self) -> &str {
        "env"
    }

    fn build(&self, config: &SecretProviderConfig) -> Result<Arc<dyn SecretProvider>, SecretError> {
        // Null or an empty mapping, depending on the path the declaration
        // arrived on. Both mean it carries nothing but `kind`.
        reject_env_settings(&config.settings)?;
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
/// With `base_dir` set, the set of files this provider can read is the
/// directory an operator named: a reference must be relative and free of `..`,
/// and the file is opened *beneath* the directory, so a symlink that leaves it
/// is refused. Links that stay inside, at any component, are followed, which is
/// what a Kubernetes projected mount needs; an absolute link is refused even
/// when its target is inside. Without `base_dir`, a reference is any path the
/// process can open, which is the more convenient default and the less
/// contained one.
pub struct FileSecretProvider {
    base_dir: Option<PathBuf>,
}

impl FileSecretProvider {
    /// Open the file `reference` addresses.
    ///
    /// With `base_dir` the file is opened through a handle on the directory,
    /// with a single `openat2(RESOLVE_BENEATH)` call on Linux and a checked
    /// component-by-component walk elsewhere, so the descriptor returned is the
    /// one the containment decision was made on. Checking containment after an
    /// open, by resolving the path a second time, leaves a window in which a
    /// writer inside the directory swaps a link and the check passes for a file
    /// other than the one opened.
    ///
    /// The directory is opened per read rather than at build time because a
    /// projected mount may not exist yet when the factory runs, and so that a
    /// directory replaced on disk is the one read.
    fn open(&self, reference: &str) -> Result<std::fs::File, SecretError> {
        let candidate = Path::new(reference);
        let Some(base) = self.base_dir.as_ref() else {
            return std::fs::File::open(candidate)
                .map_err(|e| open_error(reference, candidate, &e));
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

        let dir = Dir::open_ambient_dir(base, ambient_authority()).map_err(|e| {
            SecretError::backend(format!("opening `base_dir` `{}`: {e}", base.display()))
        })?;
        dir.open(candidate)
            .map(cap_std::fs::File::into_std)
            .map_err(|e| {
                if left_the_directory(&e) {
                    SecretError::reference(
                        reference,
                        "resolves outside `base_dir` once symlinks are followed",
                    )
                } else {
                    open_error(reference, &base.join(candidate), &e)
                }
            })
    }
}

/// True when `error` is the refusal `cap-std` raises for a path that leaves the
/// directory it was opened beneath.
///
/// It is a `PermissionDenied` with no OS error behind it, which is what tells
/// it from a file the process lacks permission to read, an `EACCES` that
/// carries one.
fn left_the_directory(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied && error.raw_os_error().is_none()
}

/// The error for a file that would not open.
fn open_error(reference: &str, path: &Path, error: &std::io::Error) -> SecretError {
    if error.kind() == std::io::ErrorKind::NotFound {
        SecretError::not_found(reference)
    } else {
        // The path is operator-authored and safe to print; the error text comes
        // from the OS and carries no file content.
        SecretError::backend(format!("opening `{}`: {error}", path.display()))
    }
}

#[async_trait]
impl SecretProvider for FileSecretProvider {
    async fn get_secret(&self, reference: &str) -> Result<Zeroizing<String>, SecretError> {
        let mut opened = self.open(reference)?;

        let mut raw = Zeroizing::new(String::new());
        #[expect(
            clippy::verbose_file_reads,
            reason = "reads the descriptor that was opened beneath `base_dir`; `fs::read_to_string` \
                      would resolve the path a second time and read whatever it resolved to then"
        )]
        opened
            .read_to_string(&mut raw)
            .map_err(|e| SecretError::backend(format!("reading `{reference}`: {e}")))?;

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

    /// A directory nothing else is using, removed by the test that made it.
    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ppe-secrets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn provider_at(base_dir: &Path) -> FileSecretProvider {
        FileSecretProvider {
            base_dir: Some(base_dir.to_path_buf()),
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
        let parent = provider
            .open("../../etc/shadow")
            .expect_err("`..` escapes base_dir");
        assert!(matches!(parent, SecretError::Reference { .. }), "{parent}");
        let absolute = provider
            .open("/etc/shadow")
            .expect_err("an absolute path ignores base_dir");
        assert!(
            matches!(absolute, SecretError::Reference { .. }),
            "{absolute}"
        );
    }

    #[tokio::test]
    async fn without_base_dir_any_path_resolves() {
        let dir = temp_dir();
        let file = dir.join("upstream.key");
        std::fs::write(&file, "hunter2\n").expect("write");

        let value = file_provider(None)
            .get_secret(file.to_str().expect("utf-8 temp path"))
            .await
            .expect("an absolute path reads without base_dir");
        assert_eq!(value.as_str(), "hunter2");

        let _ = std::fs::remove_dir_all(&dir);
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

    /// A link below `base_dir` is the escape the lexical checks do not see:
    /// the reference is relative and `..`-free, and the file is outside.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_leaf_symlink_pointing_outside_base_dir_is_refused() {
        let root = temp_dir();
        let base = root.join("base");
        std::fs::create_dir_all(&base).expect("base dir");
        std::fs::write(root.join("outside.key"), "stolen\n").expect("write");
        std::os::unix::fs::symlink(root.join("outside.key"), base.join("escape.key"))
            .expect("symlink");

        let err = provider_at(&base)
            .get_secret("escape.key")
            .await
            .expect_err("the link leaves base_dir");
        assert!(matches!(err, SecretError::Reference { .. }), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The same escape one component up, where the leaf name is honest and the
    /// directory it sits in is the link.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_directory_symlink_pointing_outside_base_dir_is_refused() {
        let root = temp_dir();
        let base = root.join("base");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&base).expect("base dir");
        std::fs::create_dir_all(&elsewhere).expect("other dir");
        std::fs::write(elsewhere.join("upstream.key"), "stolen\n").expect("write");
        std::os::unix::fs::symlink(&elsewhere, base.join("sub")).expect("symlink");

        let err = provider_at(&base)
            .get_secret("sub/upstream.key")
            .await
            .expect_err("the directory link leaves base_dir");
        assert!(matches!(err, SecretError::Reference { .. }), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The shape a Kubernetes Secret volume and a CSI-projected secret both
    /// have: the reference is a relative link to `..data`, which is a relative
    /// link to a timestamped directory. Every hop stays inside the mount, so
    /// refusing links outright would break every such deployment.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_projected_secret_symlink_farm_reads() {
        let base = temp_dir();
        let generation = base.join("..2026_10_08_00_00_00.0");
        std::fs::create_dir_all(&generation).expect("generation dir");
        std::fs::write(generation.join("upstream.key"), "hunter2\n").expect("write");
        std::os::unix::fs::symlink("..2026_10_08_00_00_00.0", base.join("..data")).expect("..data");
        std::os::unix::fs::symlink(
            PathBuf::from("..data").join("upstream.key"),
            base.join("upstream.key"),
        )
        .expect("key link");

        let value = provider_at(&base)
            .get_secret("upstream.key")
            .await
            .expect("a projected secret reads");
        assert_eq!(value.as_str(), "hunter2");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A link that stays inside `base_dir` is followed whichever component it
    /// is, but an absolute one is refused even when its target is inside: the
    /// confinement cannot tell where an absolute path leads without resolving it
    /// a second time.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_absolute_symlink_is_refused_even_when_its_target_is_inside() {
        let base = temp_dir();
        std::fs::write(base.join("real.key"), "hunter2\n").expect("write");
        std::os::unix::fs::symlink(base.join("real.key"), base.join("absolute.key"))
            .expect("absolute link");
        std::os::unix::fs::symlink("real.key", base.join("relative.key")).expect("relative link");

        let provider = provider_at(&base);
        let err = provider
            .get_secret("absolute.key")
            .await
            .expect_err("an absolute link is refused");
        assert!(matches!(err, SecretError::Reference { .. }), "{err}");
        let value = provider
            .get_secret("relative.key")
            .await
            .expect("a relative link inside reads");
        assert_eq!(value.as_str(), "hunter2");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A relative link that climbs out with `..` is the same escape as an
    /// absolute one, and is refused on every read rather than depending on the
    /// state of the file it reaches, so a writer cannot make it flicker.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_relative_symlink_climbing_out_is_refused_on_every_read() {
        let root = temp_dir();
        let base = root.join("base");
        std::fs::create_dir_all(&base).expect("base dir");
        std::fs::write(root.join("outside.key"), "stolen\n").expect("write");
        std::os::unix::fs::symlink("../outside.key", base.join("escape.key")).expect("link");

        let provider = provider_at(&base);
        for _ in 0..3 {
            let err = provider
                .get_secret("escape.key")
                .await
                .expect_err("the link leaves base_dir");
            assert!(matches!(err, SecretError::Reference { .. }), "{err}");
        }

        // The link replaced by a file and restored, the swap the open-then-check
        // sequence was exposed to: the outside file is still never returned.
        std::fs::remove_file(base.join("escape.key")).expect("remove link");
        std::fs::write(base.join("escape.key"), "inside\n").expect("regular file");
        assert_eq!(
            provider
                .get_secret("escape.key")
                .await
                .expect("reads")
                .as_str(),
            "inside"
        );
        std::fs::remove_file(base.join("escape.key")).expect("remove file");
        std::os::unix::fs::symlink("../outside.key", base.join("escape.key")).expect("restore");
        let err = provider
            .get_secret("escape.key")
            .await
            .expect_err("the restored link still leaves base_dir");
        assert!(matches!(err, SecretError::Reference { .. }), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `base_dir` that does not exist is a backend failure, not a missing
    /// secret and not a containment refusal.
    #[tokio::test]
    async fn a_missing_base_dir_is_a_backend_error() {
        let root = temp_dir();
        let err = provider_at(&root.join("absent"))
            .get_secret("upstream.key")
            .await
            .expect_err("no directory");
        assert!(matches!(err, SecretError::Backend { .. }), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `base_dir` itself may be a link: only what lies beneath it is confined.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_base_dir_reads() {
        let root = temp_dir();
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("real dir");
        std::fs::write(real.join("upstream.key"), "hunter2\n").expect("write");
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&real, &linked).expect("symlink");

        let value = provider_at(&linked)
            .get_secret("upstream.key")
            .await
            .expect("a linked base_dir reads");
        assert_eq!(value.as_str(), "hunter2");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_env_provider_refuses_settings() {
        let mut settings = serde_yaml::Mapping::new();
        settings.insert("base_dir".into(), "/tmp".into());
        let built = EnvSecretProviderFactory.build(&SecretProviderConfig {
            kind: "env".to_owned(),
            settings: serde_yaml::Value::Mapping(settings),
        });
        let Err(err) = built else {
            panic!("`env` reads no settings");
        };
        assert!(matches!(err, SecretError::Config { .. }), "{err}");
        assert!(format!("{err}").contains("base_dir"), "{err}");
    }

    #[test]
    fn an_env_provider_whose_settings_are_not_a_mapping_is_refused() {
        let built = EnvSecretProviderFactory.build(&SecretProviderConfig {
            kind: "env".to_owned(),
            settings: serde_yaml::Value::Bool(true),
        });
        let Err(err) = built else {
            panic!("`env` reads no settings");
        };
        assert!(matches!(err, SecretError::Config { .. }), "{err}");
    }

    #[test]
    fn an_env_provider_declaring_only_its_kind_builds() {
        for settings in [
            serde_yaml::Value::Null,
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        ] {
            EnvSecretProviderFactory
                .build(&SecretProviderConfig {
                    kind: "env".to_owned(),
                    settings,
                })
                .expect("no settings is how `env` is declared");
        }
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
