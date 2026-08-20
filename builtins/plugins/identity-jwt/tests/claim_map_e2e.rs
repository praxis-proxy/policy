// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What an operator authors, proved through the real resolver on signed tokens.
//!
//! Each test wires a plugin config carrying a `claim_map` or a preset name, mints
//! a token matching a provider shape, and asserts the identity that reaches the
//! payload. The unit tests cover the engine; these cover the surface an operator
//! actually writes, including the escaping that is the likeliest thing to get
//! wrong.
//!
//! The harness is copied from `jwt_e2e.rs` rather than shared: integration test
//! binaries do not share code, and that file's helpers are private to it.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::sync::{Arc, OnceLock};

use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::extensions::raw_credentials::{TokenKind, TokenRole};
use praxis_policy_core::factory::PluginFactory as _;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_identity_jwt::{JwtIdentityFactory, JwtIdentityResolver, KIND};

use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

use serde_json::{Value, json};

const TEST_ISSUER: &str = "https://idp.test.local";
const TEST_AUDIENCE: &str = "test-api";

// =====================================================================
// Harness
// =====================================================================

struct Keypair {
    private_pem: String,
    public_pem: String,
}

fn keypair() -> &'static Keypair {
    static KP: OnceLock<Keypair> = OnceLock::new();
    KP.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA");
        let pub_key = RsaPublicKey::from(&priv_key);
        Keypair {
            private_pem: priv_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode private PEM")
                .to_string(),
            public_pem: pub_key
                .to_public_key_pem(LineEnding::LF)
                .expect("encode public PEM"),
        }
    })
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Sign a token carrying `extra` plus the registered claims the resolver
/// validates against.
fn mint(extra: Value) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let mut claims = json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": now_unix() + 300,
        "iat": now_unix(),
    });
    match (claims.as_object_mut(), extra.as_object()) {
        (Some(target), Some(source)) => {
            for (key, value) in source {
                target.insert(key.clone(), value.clone());
            }
        },
        _ => panic!("both claim sets must be JSON objects"),
    }

    let key = EncodingKey::from_rsa_pem(keypair().private_pem.as_bytes())
        .expect("build EncodingKey from the test private PEM");
    encode(&Header::new(Algorithm::RS256), &claims, &key).expect("sign JWT")
}

/// A plugin config wiring the test key, plus whatever mapper and role settings
/// the case needs. Mirrors what an operator writes in unified-config YAML.
fn plugin_config(settings: Value) -> PluginConfig {
    let mut config = json!({
        "trusted_issuers": [{
            "issuer": TEST_ISSUER,
            "audiences": [TEST_AUDIENCE],
            "algorithms": ["RS256"],
            "decoding_key": { "kind": "pem", "pem": keypair().public_pem },
            "leeway_seconds": 60,
        }],
    });
    match (config.as_object_mut(), settings.as_object()) {
        (Some(target), Some(source)) => {
            for (key, value) in source {
                target.insert(key.clone(), value.clone());
            }
        },
        _ => panic!("both config blocks must be JSON objects"),
    }

    PluginConfig {
        name: "jwt-resolver".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(config),
        ..Default::default()
    }
}

async fn invoke(
    settings: Value,
    token: String,
    source: TokenSource,
) -> praxis_policy_core::executor::PipelineResult {
    let cfg = plugin_config(settings);
    let resolver = JwtIdentityResolver::new(cfg.clone()).expect("the resolver must construct");

    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<IdentityHook, _>(
        Arc::new(resolver),
        cfg,
        &[HOOK_IDENTITY_RESOLVE],
    )
    .expect("registration");
    mgr.initialize().await.expect("initialize");

    let (result, _bg) = mgr
        .invoke_named::<IdentityHook>(
            HOOK_IDENTITY_RESOLVE,
            IdentityPayload::new(token, source),
            Extensions::default(),
            None,
        )
        .await;
    result
}

/// Resolve a token and return the identity, failing with the violation when the
/// resolver denied.
async fn identity_from(settings: Value, token: String) -> IdentityPayload {
    let result = invoke(settings, token, TokenSource::Bearer).await;
    assert!(
        result.continue_processing,
        "the token should have resolved: violation = {:?}",
        result.violation
    );
    IdentityPayload::from_pipeline_result(&result).expect("the payload is present")
}

async fn subject_from(
    settings: Value,
    token: String,
) -> praxis_policy_core::extensions::SubjectExtension {
    identity_from(settings, token)
        .await
        .subject
        .expect("the subject slot is populated")
}

fn sorted(values: &std::collections::HashSet<String>) -> Vec<&str> {
    let mut items: Vec<&str> = values.iter().map(String::as_str).collect();
    items.sort_unstable();
    items
}

/// A token the resolver refused, and the violation code it refused with.
async fn denial_code(settings: Value, token: String, source: TokenSource) -> String {
    let result = invoke(settings, token, source).await;
    assert!(
        !result.continue_processing,
        "the token should have been refused"
    );
    result.violation.expect("a violation surfaced").code
}

// =====================================================================
// Nested and per-client roles
// =====================================================================

/// The shape that motivated the work: roles nested under `realm_access` and
/// under a per-client key, neither reachable before without writing Rust.
#[tokio::test]
async fn a_union_map_gathers_realm_and_per_client_roles() {
    let token = mint(json!({
        "sub": "f:2c1b:alice",
        "realm_access": {"roles": ["realm-admin"]},
        "resource_access": {"my-api": {"roles": ["viewer", "editor"]}},
    }));

    let subject = subject_from(
        json!({
            "claim_map": {
                "subject": {
                    "id": "sub",
                    "roles": {
                        "paths": ["realm_access.roles", "resource_access.my-api.roles"],
                        "merge": "union",
                    },
                }
            }
        }),
        token,
    )
    .await;

    assert_eq!(
        sorted(&subject.roles),
        vec!["editor", "realm-admin", "viewer"]
    );
}

/// A nested path consumes only what it addressed, so a policy already reading
/// the whole object through the claims bag keeps working.
#[tokio::test]
async fn a_nested_role_path_leaves_the_parent_claim_whole_in_the_bag() {
    let token = mint(json!({
        "sub": "alice",
        "realm_access": {"roles": ["admin"], "extra": "kept"},
    }));

    let subject = subject_from(
        json!({
            "claim_map": {"subject": {"id": "sub", "roles": "realm_access.roles"}}
        }),
        token,
    )
    .await;

    assert_eq!(sorted(&subject.roles), vec!["admin"]);
    assert_eq!(
        subject.claims.get("realm_access"),
        Some(&json!({"roles": ["admin"], "extra": "kept"})),
        "the traversed parent must reach the policy bag intact"
    );
}

// =====================================================================
// Escaped and prefixed claim names
// =====================================================================

/// Auth0's own documented claim name, where the whole URL is the key. The
/// escaped dots are what does the work: the same path unescaped addresses three
/// segments that do not exist.
#[tokio::test]
async fn an_escaped_url_claim_name_populates_roles_and_the_unescaped_one_does_not() {
    let token = mint(json!({
        "sub": "auth0|507f1f77bcf86cd799439011",
        "https://my-app.example.com/roles": ["editor"],
    }));

    let escaped = subject_from(
        json!({
            "claim_map": {
                "subject": {"id": "sub", "roles": "https://my-app\\.example\\.com/roles"}
            }
        }),
        token.clone(),
    )
    .await;
    assert_eq!(sorted(&escaped.roles), vec!["editor"]);

    let unescaped = subject_from(
        json!({
            "claim_map": {
                "subject": {"id": "sub", "roles": "https://my-app.example.com/roles"}
            }
        }),
        token,
    )
    .await;
    assert!(
        unescaped.roles.is_empty(),
        "unescaped, the dots split the name into segments that do not exist"
    );
}

/// A colon is a literal, so a Cognito claim name needs no escaping at all.
#[tokio::test]
async fn a_cognito_groups_claim_populates_teams_without_escaping() {
    let token = mint(json!({
        "sub": "a1b2c3d4", "cognito:groups": ["admins", "engineering"],
    }));

    let subject = subject_from(
        json!({
            "claim_map": {"subject": {"id": "sub", "teams": "cognito:groups"}}
        }),
        token,
    )
    .await;
    assert_eq!(sorted(&subject.teams), vec!["admins", "engineering"]);
}

// =====================================================================
// Splitting
// =====================================================================

#[tokio::test]
async fn a_delimited_permission_string_splits_when_declared_and_stays_whole_when_not() {
    let token = mint(json!({"sub": "alice", "scope": "read write delete"}));

    let split = subject_from(
        json!({
            "claim_map": {
                "subject": {
                    "id": "sub",
                    "permissions": {"paths": ["scope"], "split": "whitespace"},
                }
            }
        }),
        token.clone(),
    )
    .await;
    assert_eq!(sorted(&split.permissions), vec!["delete", "read", "write"]);

    let whole = subject_from(
        json!({"claim_map": {"subject": {"id": "sub", "permissions": "scope"}}}),
        token,
    )
    .await;
    assert_eq!(sorted(&whole.permissions), vec!["read write delete"]);
}

// =====================================================================
// Presets by name
// =====================================================================

/// A preset named in the existing `claim_mapper` field, end to end. Before this
/// work every name but `standard` was refused at load.
#[tokio::test]
async fn a_preset_named_in_claim_mapper_resolves_a_provider_token() {
    let token = mint(json!({
        "sub": "f:2c1b:alice",
        "realm_access": {"roles": ["viewer"]},
        "scope": "openid profile",
    }));

    let subject = subject_from(json!({"claim_mapper": "keycloak"}), token).await;
    assert_eq!(sorted(&subject.roles), vec!["viewer"]);
    assert_eq!(sorted(&subject.permissions), vec!["openid", "profile"]);
}

/// The default is unchanged: a config naming no mapper maps what it always did.
#[tokio::test]
async fn a_config_naming_no_mapper_resolves_the_standard_shape() {
    let token = mint(json!({
        "sub": "alice@corp.com", "roles": ["hr", "reader"], "email": "alice@corp.com",
    }));

    let subject = subject_from(json!({}), token).await;
    assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
    assert_eq!(sorted(&subject.roles), vec!["hr", "reader"]);
    assert_eq!(
        subject.claims.get("email"),
        Some(&json!("alice@corp.com")),
        "an unconsumed claim still reaches the policy bag"
    );
}

// =====================================================================
// The claims bag
// =====================================================================

/// `iss` is otherwise unreachable from a policy, because the subject claims bag
/// is the only route from a claim to one. A deployment trusting several issuers
/// can now gate on which of them minted the token.
#[tokio::test]
async fn including_iss_makes_the_issuing_idp_visible_to_a_policy() {
    let token = mint(json!({"sub": "alice"}));

    let subject = subject_from(
        json!({
            "claim_map": {
                "subject": {"id": "sub"},
                "claims": {"include": ["iss"]},
            }
        }),
        token.clone(),
    )
    .await;
    assert_eq!(subject.claims.get("iss"), Some(&json!(TEST_ISSUER)));

    let without = subject_from(json!({"claim_map": {"subject": {"id": "sub"}}}), token).await;
    assert!(
        !without.claims.contains_key("iss"),
        "a registered claim stays out of the bag unless the map asks for it"
    );
}

#[tokio::test]
async fn excluding_a_claim_keeps_it_out_of_the_policy_bag() {
    let token = mint(json!({
        "sub": "alice", "internal_debug": "noisy", "tenant": "acme",
    }));

    let subject = subject_from(
        json!({
            "claim_map": {
                "subject": {"id": "sub"},
                "claims": {"exclude": ["internal_debug"]},
            }
        }),
        token,
    )
    .await;
    assert!(!subject.claims.contains_key("internal_debug"));
    assert_eq!(subject.claims.get("tenant"), Some(&json!("acme")));
}

// =====================================================================
// A mistyped path
// =====================================================================

/// The permissive default and the strict opt-in, on the same mistyped path. The
/// default is a resolved request with an empty field; `on_missing: deny` turns
/// the same mistake into a refusal under the existing mapping-failure code.
#[tokio::test]
async fn a_mistyped_path_is_permissive_by_default_and_fatal_on_request() {
    let token = mint(json!({
        "sub": "alice", "realm_access": {"roles": ["admin"]},
    }));

    let permissive = subject_from(
        json!({
            "claim_map": {"subject": {"id": "sub", "roles": "realm_acces.roles"}}
        }),
        token.clone(),
    )
    .await;
    assert!(
        permissive.roles.is_empty(),
        "a typo leaves the field empty rather than refusing the request"
    );
    assert_eq!(permissive.id.as_deref(), Some("alice"));

    let code = denial_code(
        json!({
            "claim_map": {
                "subject": {
                    "id": "sub",
                    "roles": {"paths": ["realm_acces.roles"], "on_missing": "deny"},
                }
            }
        }),
        token,
        TokenSource::Bearer,
    )
    .await;
    assert_eq!(code, "auth.mapping_failed");
}

// =====================================================================
// The workload role
// =====================================================================

/// The prefix check is not configurable, and it applies to every candidate: a
/// map pointing at both a non-SPIFFE `sub` and a bogus `spiffe_id` resolves
/// neither, and the same map accepts as soon as one candidate is a real SPIFFE ID.
#[tokio::test]
async fn the_workload_role_requires_a_spiffe_id_on_whichever_candidate_resolves() {
    let map = json!({
        "role": "workload",
        "header": "X-Workload-Token",
        "claim_map": {"workload": {"spiffe_id": ["sub", "spiffe_id"]}},
    });

    let code = denial_code(
        map.clone(),
        mint(json!({"sub": "alice@corp.example", "spiffe_id": "not-a-spiffe-id"})),
        TokenSource::SpiffeJwtSvid,
    )
    .await;
    assert_eq!(code, "auth.mapping_failed");

    let identity = identity_from(
        map,
        mint(json!({
            "sub": "alice@corp.example",
            "spiffe_id": "spiffe://corp.example/ns/default/sa/agent",
        })),
    )
    .await;
    let workload = identity
        .caller_workload
        .expect("a valid SPIFFE candidate resolves the workload slot");
    assert_eq!(
        workload.spiffe_id.as_deref(),
        Some("spiffe://corp.example/ns/default/sa/agent")
    );
    assert_eq!(
        workload.trust_domain.as_deref(),
        Some("corp.example"),
        "the trust domain is derived from the URI authority"
    );
}

// =====================================================================
// Construction failures reach the host
// =====================================================================

/// A map paired with the wrong role, and a map carrying a malformed path, are
/// both startup failures through the factory. Neither can become a resolver that
/// denies every request.
#[test]
fn a_role_mismatch_and_a_malformed_path_each_fail_at_plugin_construction() {
    for (case, settings, expected) in [
        (
            "a subject-only map on a client resolver",
            json!({
                "claim_map": {"subject": {"id": "sub"}},
                "role": "client",
            }),
            vec!["client"],
        ),
        (
            "a malformed path",
            json!({
                "claim_map": {"subject": {"id": "sub", "roles": "realm_access..roles"}}
            }),
            vec!["subject.roles", "realm_access..roles"],
        ),
    ] {
        let err = JwtIdentityFactory
            .create(&plugin_config(settings))
            .err()
            .unwrap_or_else(|| panic!("{case} must not build"));
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "{case}: expected a config error, got {err:?}"
        );
        let message = format!("{err}");
        for needle in expected {
            assert!(
                message.contains(needle),
                "{case}: '{needle}' missing from: {message}"
            );
        }
    }
}

// =====================================================================
// What the map does not change
// =====================================================================

/// The map decides what is typed, not what is stashed. The raw token still
/// reaches forwarding plugins under the configured role, and the full claim set
/// still passes through, both untouched by any of this.
#[tokio::test]
async fn the_raw_token_and_the_full_claim_set_still_pass_through() {
    let token = mint(json!({
        "sub": "alice",
        "realm_access": {"roles": ["admin"]},
        "internal_debug": "noisy",
    }));

    let identity = identity_from(
        json!({
            "claim_map": {
                "subject": {"id": "sub", "roles": "realm_access.roles"},
                "claims": {"exclude": ["internal_debug"]},
            }
        }),
        token.clone(),
    )
    .await;

    let stash = identity
        .raw_credentials
        .as_ref()
        .expect("the raw credentials slot is populated");
    let stashed = stash
        .inbound_tokens
        .get(&TokenRole::User)
        .expect("the token is stashed under the configured role");
    assert_eq!(*stashed.token, token);
    assert_eq!(stashed.source_header, "Authorization");
    assert!(matches!(stashed.kind, TokenKind::Jwt));

    assert_eq!(
        identity.raw_claims.get("internal_debug"),
        Some(&json!("noisy")),
        "a claim the map excluded from the policy bag still passes through raw_claims"
    );
    assert_eq!(
        identity.raw_claims.get("realm_access"),
        Some(&json!({"roles": ["admin"]})),
    );
}
