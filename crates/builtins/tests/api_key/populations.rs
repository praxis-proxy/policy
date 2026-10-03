// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Several key populations on one route.
//!
//! Each population is its own plugin instance on `identity.resolve`, gated on
//! its own prefix. The executor runs them in priority order and threads each
//! one's payload into the next, so what matters is that a resolver which does
//! not service a credential declines without touching its directory and
//! without disturbing what another resolver has already established.

use std::collections::HashMap;
use std::sync::Arc;

use praxis_policy_builtins::plugins::identity_api_key::{ApiKeyIdentityResolver, KIND};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::identity::{IdentityHook, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;

use crate::support::{RecordFile, denial_code, file_config, hash, resolve_with_header, resolver};

/// A file holding one record for `key`.
fn file_for(key: &str, user: &str) -> RecordFile {
    RecordFile::write(&format!(
        "keys:\n  - hash: \"{}\"\n    user: {user}\n",
        hash(key)
    ))
}

/// A credential from another population costs no directory work.
///
/// The proof is in which answer comes back. This resolver's file does not hold
/// the credential, so a lookup would have produced `auth.key_unknown`. Getting
/// a decline instead means the prefix gate ended it before the directory was
/// consulted, which is what keeps N populations from costing N lookups each.
#[tokio::test]
async fn a_foreign_credential_declines_before_the_directory_is_consulted() {
    let file = file_for("sk-oai-secret", "alice");
    let resolver =
        resolver(file_config(file.path(), Some("Bearer sk-oai-"))).expect("the config builds");

    let result = resolve_with_header(&resolver, "Bearer sk-corp-other").await;

    assert!(
        denial_code(&result).is_none(),
        "a foreign credential must not deny: {:?}",
        denial_code(&result)
    );
    assert!(
        result.continue_processing,
        "declining must leave the chain running for the resolver that services it"
    );
}

/// Two populations, threaded the way the executor threads them.
#[tokio::test]
async fn the_second_population_resolves_what_the_first_declined() {
    let oai = file_for("sk-oai-secret", "alice");
    let corp = file_for("sk-corp-secret", "bob");

    let first =
        resolver(file_config(oai.path(), Some("Bearer sk-oai-"))).expect("the first builds");
    let second =
        resolver(file_config(corp.path(), Some("Bearer sk-corp-"))).expect("the second builds");

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_owned(),
        "Bearer sk-corp-secret".to_owned(),
    );

    // The first carries a decline marker for the executor while preserving
    // every identity slot for the next resolver.
    let declined = crate::support::resolve(&first, headers.clone()).await;
    let payload = declined
        .modified_payload
        .expect("the decline marker must reach the next resolver");
    assert!(payload.subject.is_none());

    let resolved = crate::support::resolve_with_payload(&second, &payload).await;
    let subject = resolved
        .modified_payload
        .expect("the servicing resolver modifies the payload")
        .subject
        .expect("it fills the subject slot");
    assert_eq!(subject.id.as_deref(), Some("bob"));
}

/// A resolver that services a credential does not have its work undone by a
/// later one that does not.
///
/// Sequential-phase semantics thread payload N into handler N+1, so a resolver
/// which declined after another had resolved could otherwise hand the chain a
/// payload with the subject dropped.
#[tokio::test]
async fn a_later_declining_resolver_does_not_erase_a_resolved_subject() {
    let oai = file_for("sk-oai-secret", "alice");
    let corp = file_for("sk-corp-secret", "bob");

    let servicing =
        resolver(file_config(oai.path(), Some("Bearer sk-oai-"))).expect("the first builds");
    let declining =
        resolver(file_config(corp.path(), Some("Bearer sk-corp-"))).expect("the second builds");

    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_owned(),
        "Bearer sk-oai-secret".to_owned(),
    );

    let resolved = crate::support::resolve(&servicing, headers.clone()).await;
    let payload: IdentityPayload = resolved
        .modified_payload
        .expect("the first resolver fills the subject");
    assert_eq!(
        payload.subject.as_ref().and_then(|s| s.id.as_deref()),
        Some("alice")
    );

    // Hand the first resolver's output to the second, as the executor would.
    let after = crate::support::resolve_with_payload(&declining, &payload).await;

    let carried = after
        .modified_payload
        .expect("the decline marker is carried in the payload");
    assert_eq!(
        carried
            .subject
            .as_ref()
            .and_then(|subject| subject.id.as_deref()),
        Some("alice"),
        "declining must preserve the subject a prior resolver established"
    );
    assert!(
        after.continue_processing,
        "and must not halt the chain either"
    );
}

fn register_population(engine: &PolicyEngine, name: &str, file: &RecordFile, prefix: &str) {
    let config = PluginConfig {
        name: name.to_owned(),
        kind: KIND.to_owned(),
        hooks: vec!["identity.resolve".to_owned()],
        config: Some(file_config(file.path(), Some(prefix))),
        ..Default::default()
    };
    let resolver = Arc::new(ApiKeyIdentityResolver::new(config.clone()).expect("valid resolver"));
    engine
        .register_handler::<IdentityHook, _>(resolver, config)
        .expect("the population registers");
}

/// Exercise the complete executor: individual handlers must decline so the
/// next population can run, but the completed authentication hook must deny
/// if no population recognized the presented credential.
#[tokio::test]
async fn the_engine_denies_an_unmatched_population_and_accepts_a_later_match() {
    let oai = file_for("sk-oai-secret", "alice");
    let corp = file_for("sk-corp-secret", "bob");
    let engine = PolicyEngine::default();
    register_population(&engine, "oai", &oai, "Bearer sk-oai-");
    register_population(&engine, "corp", &corp, "Bearer sk-corp-");
    engine.initialize().await.expect("the engine initializes");

    let invoke = |value: &str| {
        IdentityPayload::new("", TokenSource::ApiKey).with_headers(HashMap::from([(
            "authorization".to_owned(),
            value.to_owned(),
        )]))
    };
    let (unmatched, _) = engine
        .invoke::<IdentityHook>(
            invoke("Bearer sk-other-secret"),
            Extensions::default(),
            None,
        )
        .await;
    assert!(!unmatched.continue_processing);
    assert_eq!(
        unmatched.violation.as_ref().map(|v| v.code.as_str()),
        Some("auth.unrecognized_credential")
    );

    let (matched, _) = engine
        .invoke::<IdentityHook>(invoke("Bearer sk-corp-secret"), Extensions::default(), None)
        .await;
    assert!(matched.continue_processing);
    let identity = IdentityPayload::from_pipeline_result(&matched).expect("identity payload");
    assert_eq!(
        identity
            .subject
            .as_ref()
            .and_then(|subject| subject.id.as_deref()),
        Some("bob")
    );
}
