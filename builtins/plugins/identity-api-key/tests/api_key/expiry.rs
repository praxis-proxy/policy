// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Who enforces a record's expiry.

use crate::support::{RecordFile, denial_code, file_config, hash, resolve_with_header, resolver};

fn file_with_expiry(expires_at: &str) -> RecordFile {
    RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    expires_at: {expires_at}\n    user: alice\n",
        hash("sk-oai-secret")
    ))
}

/// The default. Nothing else is positioned to enforce it on the file path.
#[tokio::test]
async fn an_expired_record_denies_by_default() {
    let file = file_with_expiry("2020-01-01T00:00:00Z");
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    assert_eq!(denial_code(&result).as_deref(), Some("auth.key_expired"));
}

/// Expired is not unknown. The credential was recognized, and an operator
/// chasing a denial needs to know the record exists.
#[tokio::test]
async fn expired_is_a_different_code_from_unknown() {
    let file = file_with_expiry("2020-01-01T00:00:00Z");
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let expired = resolve_with_header(&resolver, "sk-oai-secret").await;
    let unknown = resolve_with_header(&resolver, "sk-oai-never-issued").await;

    assert_ne!(denial_code(&expired), denial_code(&unknown));
}

#[tokio::test]
async fn a_record_expiring_in_the_future_resolves() {
    let file = file_with_expiry("2099-01-01T00:00:00Z");
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    assert!(
        denial_code(&result).is_none(),
        "an unexpired record must resolve"
    );
}

/// `expiry: directory` hands enforcement to the backend. On the file backend
/// that means nothing enforces it, which is the operator's stated choice and
/// not something to quietly override.
#[tokio::test]
async fn expiry_directory_leaves_an_expired_record_resolving() {
    let file = file_with_expiry("2020-01-01T00:00:00Z");
    let mut config = file_config(file.path(), None);
    config["expiry"] = serde_json::Value::String("directory".to_owned());
    let resolver = resolver(config).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    assert!(
        denial_code(&result).is_none(),
        "under `expiry: directory` this resolver must not apply its own check"
    );
}

/// A record with no expiry is not expired.
#[tokio::test]
async fn a_record_with_no_expiry_resolves() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    assert!(
        denial_code(&result).is_none(),
        "no expiry means no expiry check"
    );
}
