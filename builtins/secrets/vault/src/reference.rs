// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Vault KV v2 reference grammar: `<mount>/<path>#<field>`.
//
// `secret/app/db#password` is `GET /v1/secret/data/app/db` and then the
// `password` key of `data.data`. The `#field` is required: a KV v2 path
// holds a map, and returning the whole map would make every consumer a
// parser.

use praxis_policy_core::secrets::SecretError;

/// One KV v2 lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KvRef {
    pub mount: String,
    pub path: String,
    pub field: String,
}

impl KvRef {
    /// Parse `reference`. The last `#` starts the field so a path may
    /// contain `#` (unusual) without eating the field.
    pub(crate) fn parse(reference: &str) -> Result<Self, SecretError> {
        let (left, field) = reference.rsplit_once('#').ok_or_else(|| {
            SecretError::reference(reference, "expected `<mount>/<path>#<field>`")
        })?;
        if field.is_empty() {
            return Err(SecretError::reference(
                reference,
                "the field after `#` is empty",
            ));
        }
        let (mount, path) = left.split_once('/').ok_or_else(|| {
            SecretError::reference(
                reference,
                "expected `<mount>/<path>#<field>`: the path after the mount is missing",
            )
        })?;
        if mount.is_empty() {
            return Err(SecretError::reference(reference, "the mount is empty"));
        }
        if path.is_empty() {
            return Err(SecretError::reference(
                reference,
                "the path after the mount is empty",
            ));
        }
        if mount == ".." || path.split('/').any(|s| s.is_empty() || s == "..") {
            return Err(SecretError::reference(
                reference,
                "`..` or an empty path segment is not a legal mount or path",
            ));
        }
        Ok(Self {
            mount: mount.to_owned(),
            path: path.to_owned(),
            field: field.to_owned(),
        })
    }

    /// Path on the Vault origin, including the KV v2 `/data/` infix.
    pub(crate) fn kv_url_path(&self) -> String {
        format!("v1/{}/data/{}", self.mount, self.path)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn a_nested_path_maps_onto_the_kv_v2_data_url() {
        let parsed = KvRef::parse("secret/app/db#password").expect("grammar");
        assert_eq!(parsed.mount, "secret");
        assert_eq!(parsed.path, "app/db");
        assert_eq!(parsed.field, "password");
        assert_eq!(parsed.kv_url_path(), "v1/secret/data/app/db");
    }

    #[test]
    fn a_missing_hash_or_path_is_a_reference_error() {
        for bad in [
            "secret/app",
            "secret#field",
            "#field",
            "secret/#x",
            "/app#x",
        ] {
            let err = KvRef::parse(bad).expect_err("not addressable");
            assert!(matches!(err, SecretError::Reference { .. }), "{bad}: {err}");
        }
    }

    #[test]
    fn parent_and_empty_segments_are_refused() {
        for bad in ["secret/../etc#x", "../secret/app#x", "secret//app#x"] {
            let err = KvRef::parse(bad).expect_err("not addressable");
            assert!(matches!(err, SecretError::Reference { .. }), "{bad}: {err}");
        }
    }
}
