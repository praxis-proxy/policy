// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The `secrets:` block: declared providers and the values bound to them.
//
// ```yaml
// secrets:
//   providers:
//     local: { kind: file }
//     shell: { kind: env }
//   values:
//     upstream_api_key: { provider: local, ref: /etc/ppe/upstream.key }
//     session_password: { provider: shell, ref: VALKEY_PASSWORD }
// ```
//
// A value names a provider and a reference the provider understands. The
// reference is opaque here: a path for `file`, a variable name for `env`, a
// `<mount>/<path>#<field>` for a vault. Keeping it opaque is what lets a
// deployment move a value between backends by editing one line.

use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::error::SecretError;

/// The `secrets:` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Provider instances by operator-chosen name.
    ///
    /// Keyed by name rather than by kind because one deployment runs several
    /// instances of one kind: two vault clusters, or two mounts reached with
    /// different credentials. Keying by kind would make that unexpressible and
    /// would collapse two blast radii into one.
    #[serde(default, deserialize_with = "unique_keys")]
    pub providers: HashMap<String, SecretProviderConfig>,

    /// Declared values by name. This map is the complete set of secrets the
    /// process can reach: nothing outside it names a provider or a reference.
    #[serde(default, deserialize_with = "unique_keys")]
    pub values: HashMap<String, SecretValueConfig>,
}

/// Collect a mapping, refusing a key that appears twice.
///
/// YAML itself allows a repeated key and `serde_yaml` keeps the last one, which
/// here would bind a name to one of two references with nothing anywhere
/// reporting the other. A consumer would then read a credential meant for
/// something else. The entries are visited in document order, before any
/// deduplication, so the repeat is still visible at this point.
fn unique_keys<'de, D, V>(deserializer: D) -> Result<HashMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct UniqueKeys<V>(PhantomData<V>);

    impl<'de, V: Deserialize<'de>> Visitor<'de> for UniqueKeys<V> {
        type Value = HashMap<String, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a mapping with no repeated key")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut collected = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((key, value)) = access.next_entry::<String, V>()? {
                if collected.insert(key.clone(), value).is_some() {
                    return Err(de::Error::custom(format!(
                        "`{key}` is declared twice; a name binds to one thing"
                    )));
                }
            }
            Ok(collected)
        }
    }

    deserializer.deserialize_map(UniqueKeys(PhantomData))
}

/// One provider instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretProviderConfig {
    /// Which factory builds it.
    pub kind: String,

    /// Everything else, passed to the factory for that kind.
    #[serde(flatten)]
    pub settings: serde_yaml::Value,
}

/// One declared value, bound to a provider and a reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretValueConfig {
    /// The provider name, which must appear in [`SecretsConfig::providers`].
    pub provider: String,

    /// The reference, in whatever grammar that provider reads.
    #[serde(rename = "ref")]
    pub reference: String,
}

impl SecretsConfig {
    /// Check the block describes something resolvable, without resolving it.
    ///
    /// Runs at config load so a typo fails against the document rather than
    /// against a backend, and so the set of legal `secret.<name>` references is
    /// known before anything tries to read one.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Config`] for a value naming an undeclared
    /// provider, or for a name that could not be written in the places a value
    /// is referenced from.
    pub fn validate(&self) -> Result<(), SecretError> {
        for name in self.providers.keys() {
            validate_name(name, "provider")?;
        }
        for (name, value) in &self.values {
            validate_name(name, "secret")?;
            if !self.providers.contains_key(&value.provider) {
                return Err(SecretError::config(format!(
                    "secret `{name}` names provider `{}`, which is not declared under \
                     `secrets.providers`",
                    value.provider
                )));
            }
            if value.reference.is_empty() {
                return Err(SecretError::config(format!(
                    "secret `{name}` has an empty `ref`"
                )));
            }
        }
        Ok(())
    }

    /// Whether any value is declared, which is what decides if the engine
    /// needs a store at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Reject a name that could not be written where it is referenced from, or
/// that has more than one spelling.
///
/// A secret is named in an assertion source as `secret.<name>`, and that path
/// is split on `.`, so a dot in a name would address a slot nobody declared.
/// The restriction is enforced here, against the declaration, so the failure
/// names the `secrets:` block rather than whichever route first referenced it.
///
/// `/` is allowed so a large document can group names by team or by upstream,
/// but a name is an opaque key and not a path: nothing resolves `.` or `..`
/// segments and nothing collapses a repeated separator. A leading, trailing,
/// or doubled `/` is refused so two names that look identical cannot be
/// different keys.
fn validate_name(name: &str, what: &str) -> Result<(), SecretError> {
    if name.is_empty() {
        return Err(SecretError::config(format!(
            "a {what} name cannot be empty"
        )));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '_' | '-' | '/'))
    {
        return Err(SecretError::config(format!(
            "{what} name `{name}` contains `{bad}`; names are limited to letters, digits, `_`, \
             `-` and `/` so they can be written wherever a {what} is referenced"
        )));
    }
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        return Err(SecretError::config(format!(
            "{what} name `{name}` has a leading, trailing, or repeated `/`; a name is a key \
             rather than a path, so only one spelling of it exists"
        )));
    }
    Ok(())
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

    fn config(yaml: &str) -> SecretsConfig {
        serde_yaml::from_str(yaml).expect("valid yaml")
    }

    #[test]
    fn a_value_naming_an_undeclared_provider_is_refused() {
        let cfg = config(
            "
providers:
  local: { kind: file }
values:
  key: { provider: vault-prod, ref: /etc/key }
",
        );
        let err = cfg.validate().expect_err("provider is not declared");
        assert!(format!("{err}").contains("vault-prod"), "{err}");
    }

    #[test]
    fn a_dotted_name_is_refused_because_an_assertion_path_splits_on_dots() {
        let cfg = config(
            "
providers:
  local: { kind: file }
values:
  my.key: { provider: local, ref: /etc/key }
",
        );
        let err = cfg.validate().expect_err("dots are not addressable");
        assert!(format!("{err}").contains("my.key"), "{err}");
    }

    #[test]
    fn an_empty_reference_is_refused() {
        let cfg = config(
            r#"
providers:
  local: { kind: file }
values:
  key: { provider: local, ref: "" }
"#,
        );
        cfg.validate().expect_err("an empty ref addresses nothing");
    }

    #[test]
    fn provider_settings_reach_the_factory_as_written() {
        let cfg = config(
            "
providers:
  local: { kind: file, base_dir: /etc/ppe }
values: {}
",
        );
        let provider = &cfg.providers["local"];
        assert_eq!(provider.kind, "file");
        assert_eq!(
            provider.settings.get("base_dir").and_then(|v| v.as_str()),
            Some("/etc/ppe")
        );
    }

    #[test]
    fn a_slash_groups_names_but_only_in_one_spelling() {
        let grouped = config(
            "
providers:
  local: { kind: file }
values:
  billing/api_key: { provider: local, ref: /etc/billing.key }
",
        );
        grouped.validate().expect("`/` groups a name");

        for spelling in ["/leading", "trailing/", "double//slash"] {
            let cfg = config(&format!(
                "
providers:
  local: {{ kind: file }}
values:
  {spelling}: {{ provider: local, ref: /etc/key }}
"
            ));
            cfg.validate().expect_err("a name has exactly one spelling");
        }
    }

    #[test]
    fn two_values_with_one_name_are_refused_rather_than_last_wins() {
        // The one collision an operator can actually cause. Silently keeping
        // the last would leave a consumer reading a credential meant for
        // something else, with nothing anywhere saying so.
        let duplicated = "
providers:
  local: { kind: file }
values:
  api_key: { provider: local, ref: /etc/first.key }
  api_key: { provider: local, ref: /etc/second.key }
";
        serde_yaml::from_str::<SecretsConfig>(duplicated)
            .expect_err("a repeated key is ambiguous, not a last-one-wins");
    }

    #[test]
    fn a_valid_block_validates() {
        let cfg = config(
            "
providers:
  local: { kind: file }
  shell: { kind: env }
values:
  upstream_api_key: { provider: local, ref: /etc/ppe/upstream.key }
  session_password: { provider: shell, ref: VALKEY_PASSWORD }
",
        );
        cfg.validate().expect("block is resolvable");
        assert!(!cfg.is_empty());
    }
}
