// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Record fields onto the identity slots, through the shared mapper.

use crate::support::{RecordFile, denial_code, file_config, hash, resolve_with_header, resolver};

#[tokio::test]
async fn a_record_fills_the_subject_slot() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n    groups: [reader, writer]\n    tenant: acme\n",
        hash("sk-oai-secret")
    ));
    let mut config = file_config(file.path(), None);
    config["claims"] = serde_json::json!({ "include": ["tenant"] });
    let resolver = resolver(config).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    let payload = result
        .modified_payload
        .expect("a resolved credential modifies the payload");
    let subject = payload.subject.expect("the subject slot is filled");
    assert_eq!(subject.id.as_deref(), Some("alice"));
    let mut roles: Vec<&str> = subject.roles.iter().map(String::as_str).collect();
    roles.sort_unstable();
    assert_eq!(roles, vec!["reader", "writer"]);
    assert_eq!(
        subject
            .claims
            .get("tenant")
            .and_then(serde_json::Value::as_str),
        Some("acme")
    );
}

/// The JWT default drops the registered claim names from the bag. A directory
/// record means its own thing by a field called `iss`, so this resolver clears
/// that list and the field survives.
#[tokio::test]
async fn a_record_field_named_like_a_jwt_claim_survives() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n    iss: maas-api\n",
        hash("sk-oai-secret")
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    let subject = result
        .modified_payload
        .expect("the payload is modified")
        .subject
        .expect("the subject slot is filled");
    assert_eq!(
        subject
            .claims
            .get("iss")
            .and_then(serde_json::Value::as_str),
        Some("maas-api"),
        "a record's own `iss` must not be dropped as though it were a JWT's"
    );
}

/// A policy gating on how an identity was established has to be told the
/// truth: the mapper's default attestor is `jwt`, which is not what this
/// resolver verified.
#[tokio::test]
async fn a_workload_records_this_resolver_as_its_attestor() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    workload_id: \"spiffe://corp.example/ns/prod/sa/batch\"\n",
        hash("sk-oai-secret")
    ));
    let mut config = file_config(file.path(), None);
    config["role"] = serde_json::Value::String("caller_workload".to_owned());
    config["record_map"] = serde_json::json!({ "workload": { "spiffe_id": "workload_id" } });
    let resolver = resolver(config).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    let workload = result
        .modified_payload
        .expect("the payload is modified")
        .caller_workload
        .expect("the workload slot is filled");
    assert_eq!(workload.attestor.as_deref(), Some("api_key"));
    assert_eq!(workload.trust_domain.as_deref(), Some("corp.example"));
}

/// A record the map cannot project denies, and says so as a mapping failure
/// rather than as an unknown credential: the credential was recognized.
#[tokio::test]
async fn a_record_missing_the_anchor_denies_as_a_mapping_failure() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    groups: [reader]\n",
        hash("sk-oai-secret")
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    assert_eq!(denial_code(&result).as_deref(), Some("auth.mapping_failed"));
}

/// A map with no section for the configured role projects nothing on every
/// request. That is a configuration fault, so it fails at load rather than
/// denying each caller with a message that names a record.
#[test]
fn a_map_with_no_section_for_the_role_fails_at_config_load() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let mut config = file_config(file.path(), None);
    config["role"] = serde_json::Value::String("client".to_owned());

    let error = resolver(config).expect_err("a map with no client section must not build");

    assert!(
        error.contains("no section for"),
        "the error must name the missing section: {error}"
    );
}

/// The presented credential stops at this plugin. Nothing downstream can
/// forward a caller's own key to an upstream that never authenticated it.
///
/// Scoped to what this resolver writes. The credential does still reach a
/// serialized `IdentityPayload`, through the inbound header map that the host
/// populates and `IdentityPayload` serializes in full. That is core's, it
/// predates this plugin, and it applies to a Bearer JWT exactly as much as to
/// an API key. See `scratchpad/issues/identity-and-delegation/issue-credentials-as-octets.md`.
#[tokio::test]
async fn the_presented_credential_never_reaches_raw_credentials() {
    let file = RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n",
        hash("sk-oai-secret")
    ));
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    let payload = result.modified_payload.expect("the payload is modified");
    assert!(
        payload.raw_credentials.is_none(),
        "the resolver must not stash the key for forwarding"
    );

    let subject = payload.subject.expect("the subject slot is filled");
    let projected = serde_json::to_string(&subject).expect("the subject serializes");
    assert!(
        !projected.contains("sk-oai-secret"),
        "the credential must not reach anything this resolver writes: {projected}"
    );
}
