// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The plugin driven through the real engine rather than by calling the hook
//! handler directly.
//!
//! Every other module in this suite invokes `HookHandler::handle` itself, which
//! skips what a host actually does: registering the plugin for the identity
//! hook, running `initialize`, invoking by hook name, and reading the resolved
//! identity back out with `IdentityPayload::from_pipeline_result`. Each of
//! those is a place the plugin can be wired correctly and still not work --
//! a `mode`/`on_error` pair the engine refuses, a payload the engine does not
//! thread back, a denial the engine drops the challenge from.

use std::sync::Arc;

use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::identity::{IdentityHook, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;

use praxis_policy_builtins::plugins::identity_basic::{BasicIdentityResolver, KIND};

use crate::support::{HtpasswdFile, basic_header, bcrypt_line, htpasswd_block};

/// The hook name a host invokes identity resolution by.
const HOOK_IDENTITY_RESOLVE: &str = "identity.resolve";

/// Drive one request through a registered, initialized engine.
async fn invoke_through_engine(block: serde_json::Value, header: &str) -> PipelineResult {
    use praxis_policy_core::engine::PolicyEngine;

    let cfg = PluginConfig {
        name: "basic-auth".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.to_owned()],
        config: Some(block),
        ..Default::default()
    };
    let resolver = BasicIdentityResolver::new(cfg.clone()).expect("the resolver must construct");

    let engine = Arc::new(PolicyEngine::default());
    engine
        .register_handler_for_names::<IdentityHook, _>(
            Arc::new(resolver),
            cfg,
            &[HOOK_IDENTITY_RESOLVE],
        )
        .expect("the engine must accept this plugin's mode and on_error");
    engine.initialize().await.expect("initialize");

    let payload = IdentityPayload::new("", TokenSource::Basic).with_headers(
        std::collections::HashMap::from([("authorization".to_owned(), header.to_owned())]),
    );
    let (result, _background) = engine
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    result
}

#[tokio::test]
async fn a_correct_password_resolves_a_subject_through_the_engine() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let result = invoke_through_engine(
        htpasswd_block(file.path()),
        &basic_header("alice", "correct horse"),
    )
    .await;

    assert!(
        result.continue_processing,
        "a correct password must resolve rather than deny: violation = {:?}",
        result.violation,
    );

    let identity = IdentityPayload::from_pipeline_result(&result)
        .expect("the engine must thread the resolved payload back to the host");
    let subject = identity
        .subject
        .as_ref()
        .expect("the user role fills the subject slot");
    assert_eq!(
        subject.id.as_deref(),
        Some("alice"),
        "the verified user-id is the anchor a bare `.htpasswd` deployment projects"
    );
    assert!(
        identity.raw_credentials.is_none(),
        "the password must stop at this plugin: nothing downstream may forward a caller's own \
         password to an upstream that never authenticated it"
    );
}

#[tokio::test]
async fn a_wrong_password_denies_with_the_challenge_through_the_engine() {
    use praxis_policy_apl_cmf::constants::DETAIL_HTTP_HEADERS;

    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let result = invoke_through_engine(
        htpasswd_block(file.path()),
        &basic_header("alice", "wrong horse"),
    )
    .await;

    assert!(
        !result.continue_processing,
        "a wrong password must stop the pipeline"
    );
    let violation = result
        .violation
        .as_ref()
        .expect("a denial must carry a violation the host can render");
    assert_eq!(
        violation.code, "auth.invalid_credentials",
        "an unknown user and a wrong password share one code, so neither is an enumeration oracle"
    );
    assert_eq!(
        violation
            .details
            .get(DETAIL_HTTP_HEADERS)
            .and_then(|headers| headers.get("WWW-Authenticate"))
            .and_then(serde_json::Value::as_str),
        Some("Basic realm=\"ops\""),
        "the challenge must survive the engine: RFC 7617 needs it on the 401 for a client to \
         know how to retry"
    );
}

#[tokio::test]
async fn a_declined_scheme_becomes_the_executors_own_unchallenged_denial() {
    use praxis_policy_apl_cmf::constants::DETAIL_HTTP_HEADERS;

    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let result = invoke_through_engine(htpasswd_block(file.path()), "Bearer some.jwt.token").await;

    // The resolver declines rather than denying, so a Basic and a Bearer
    // resolver can share one `Authorization` header. With no other resolver
    // registered the executor then synthesizes the denial -- and that one is
    // its own, not this plugin's: a different code, and no challenge, because
    // a declining plugin has no channel to contribute one. Asserted here
    // because calling the handler directly cannot see it.
    let violation = result
        .violation
        .as_ref()
        .expect("every resolver declining must still deny rather than authenticate nobody");
    assert_eq!(
        violation.code, "auth.unrecognized_credential",
        "the executor's own code, distinct from any this plugin raises"
    );
    assert!(
        !violation.details.contains_key(DETAIL_HTTP_HEADERS),
        "a declining plugin contributes no challenge, so a host wanting one on this path must          add it: {:?}",
        violation.details,
    );

    if let Some(identity) = IdentityPayload::from_pipeline_result(&result) {
        assert!(
            identity.subject.is_none(),
            "a declining resolver must not fill a slot it never authenticated"
        );
    }
}
