// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Reading the credential off the request, and the prefix gate.

use crate::support::{
    RecordFile, denial_code, file_config, hash, resolve, resolve_with_header, resolver,
};

use std::collections::HashMap;

fn one_record() -> RecordFile {
    RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: alice\n    groups: [reader]\n",
        hash("sk-oai-secret")
    ))
}

#[tokio::test]
async fn a_request_with_no_credential_denies_as_missing() {
    let file = one_record();
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve(&resolver, HashMap::new()).await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some("auth.missing_credential")
    );
}

#[tokio::test]
async fn an_empty_credential_denies_separately_from_a_missing_one() {
    let file = one_record();
    let resolver = resolver(file_config(file.path(), None)).expect("the config builds");

    let result = resolve_with_header(&resolver, "").await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some("auth.empty_credential")
    );
}

/// A value carrying only the scheme has no credential after it. It has to read
/// as empty rather than reach the directory as a zero length key and come back
/// reported as unknown.
#[tokio::test]
async fn a_value_that_is_only_the_scheme_is_empty_not_unknown() {
    let file = one_record();
    let resolver = resolver(file_config(file.path(), Some("Bearer "))).expect("the config builds");

    let result = resolve_with_header(&resolver, "Bearer ").await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some("auth.empty_credential")
    );
}

/// The leader after the scheme is part of the credential, not framing. A `MaaS`
/// key is `sk-oai-<random>` and its record is stored under a digest of the
/// whole string, so stripping `sk-oai-` would hash the wrong thing and every
/// credential would come back unknown.
#[tokio::test]
async fn the_leader_after_the_scheme_stays_part_of_the_credential() {
    // The record's digest is of `sk-oai-secret`, leader included.
    let file = one_record();
    let resolver =
        resolver(file_config(file.path(), Some("Bearer sk-oai-"))).expect("the config builds");

    let result = resolve_with_header(&resolver, "Bearer sk-oai-secret").await;

    assert!(
        denial_code(&result).is_none(),
        "the looked-up key must be `sk-oai-secret`, not `secret`: {:?}",
        denial_code(&result)
    );
}

/// The multi-population case. A credential that is not this resolver's is not
/// a denial: another resolver on the chain services it, and denying here would
/// make two key populations on one route impossible.
#[tokio::test]
async fn a_credential_without_this_resolvers_prefix_declines_rather_than_denies() {
    let file = one_record();
    let resolver =
        resolver(file_config(file.path(), Some("Bearer sk-oai-"))).expect("the config builds");

    let result = resolve_with_header(&resolver, "Bearer sk-other-abc").await;

    assert!(
        result.continue_processing,
        "a wrong prefix must not halt the chain"
    );
    assert!(
        denial_code(&result).is_none(),
        "a wrong prefix is not a denial"
    );
    assert!(
        result.modified_payload.is_none(),
        "declining must leave the payload untouched for the resolver that does service it"
    );
}

/// RFC 7235 makes the auth scheme case-insensitive, and the JWT resolver
/// already treats it that way. Two identity plugins disagreeing about whether
/// `bearer` is `Bearer` would be a difference an operator discovers in
/// production.
#[tokio::test]
async fn the_auth_scheme_in_a_prefix_matches_without_case() {
    let file = one_record();
    let resolver =
        resolver(file_config(file.path(), Some("Bearer sk-oai-"))).expect("the config builds");

    for value in [
        "Bearer sk-oai-secret",
        "bearer sk-oai-secret",
        "BEARER sk-oai-secret",
        "BeArEr sk-oai-secret",
        // `1*SP`: any run of spaces separates the scheme from the credential.
        "bearer   sk-oai-secret",
    ] {
        let result = resolve_with_header(&resolver, value).await;
        assert!(
            denial_code(&result).is_none(),
            "'{value}' must resolve: {:?}",
            denial_code(&result)
        );
    }
}

/// The scheme is case-insensitive and the credential after it is not. An API
/// key is opaque, so folding its case would map two different credentials onto
/// one lookup.
#[tokio::test]
async fn the_credential_after_the_scheme_stays_case_sensitive() {
    let file = one_record();
    let resolver =
        resolver(file_config(file.path(), Some("Bearer sk-oai-"))).expect("the config builds");

    let result = resolve_with_header(&resolver, "Bearer SK-OAI-secret").await;

    assert!(
        result.continue_processing && denial_code(&result).is_none(),
        "a credential whose own bytes differ belongs to another population"
    );
}

/// A value merely starting with the scheme's letters is not that scheme.
#[tokio::test]
async fn a_scheme_needs_a_space_after_it() {
    let file = one_record();
    let resolver =
        resolver(file_config(file.path(), Some("Bearer sk-oai-"))).expect("the config builds");

    let result = resolve_with_header(&resolver, "bearerish sk-oai-secret").await;

    assert!(
        denial_code(&result).is_none() && result.modified_payload.is_none(),
        "'bearerish' is not 'bearer'"
    );
}

/// A prefix with no space is all leader: required, kept, and matched exactly.
#[tokio::test]
async fn a_prefix_with_no_scheme_is_required_and_kept() {
    let file = one_record();
    let resolver = resolver(file_config(file.path(), Some("sk-oai-"))).expect("the config builds");

    let exact = resolve_with_header(&resolver, "sk-oai-secret").await;
    assert!(
        denial_code(&exact).is_none(),
        "the leader is kept, so the lookup is of the whole value: {:?}",
        denial_code(&exact)
    );

    let miscased = resolve_with_header(&resolver, "SK-OAI-secret").await;
    assert!(
        miscased.modified_payload.is_none(),
        "a leader is part of the credential and must not fold case"
    );
}

/// The header name is matched however the host cased it.
#[tokio::test]
async fn the_header_name_matches_case_insensitively() {
    let file = one_record();
    let mut config = file_config(file.path(), None);
    config["credential"]["name"] = serde_json::Value::String("AUTHORIZATION".to_owned());
    let resolver = resolver(config).expect("the config builds");

    let result = resolve_with_header(&resolver, "sk-oai-secret").await;

    assert!(
        denial_code(&result).is_none(),
        "the configured name must match the wire name"
    );
}

/// A prefix present and empty gates nothing, which is a config mistake rather
/// than a way of saying there is no prefix.
#[test]
fn an_empty_prefix_is_refused_at_config_load() {
    let file = one_record();
    let error =
        resolver(file_config(file.path(), Some(""))).expect_err("an empty prefix must not build");

    assert!(
        error.contains("gates nothing"),
        "the error must say what is wrong with it: {error}"
    );
}

/// A location with no name can never be satisfied, so it is a config fault
/// rather than a request that always denies.
#[test]
fn an_empty_header_name_is_refused_at_config_load() {
    let file = one_record();
    let mut config = file_config(file.path(), None);
    config["credential"]["name"] = serde_json::Value::String("   ".to_owned());

    let error = resolver(config).expect_err("an empty name must not build");

    assert!(error.contains("empty name"), "got: {error}");
}

/// A leading space would be read as an empty auth scheme, and then no value
/// could match the gate.
#[test]
fn a_prefix_starting_with_a_space_is_refused_at_config_load() {
    let file = one_record();

    let error = resolver(file_config(file.path(), Some(" Bearer ")))
        .expect_err("a leading space must not build");

    assert!(error.contains("starts with a space"), "got: {error}");
}
