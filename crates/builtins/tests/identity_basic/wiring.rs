// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Config validation, registration, and what the plugin refuses at load.

use praxis_policy_builtins::plugins::identity_basic::{
    BasicResolverConfig, ExpiryPolicy, FailureLimitConfig, KIND,
};
use praxis_policy_core::identity::TokenSource;

use crate::support::{HtpasswdFile, argon2_line, bcrypt_line, htpasswd_block, resolver};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn the_kind_string_is_the_documented_one() {
    assert_eq!(
        KIND, "identity/basic",
        "the kind string is public API and operators write it in YAML"
    );
}

#[test]
fn a_header_credential_loads() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));

    resolver(htpasswd_block(file.path())).expect("a header credential is the supported location");
}

#[test]
fn a_cookie_credential_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut block = htpasswd_block(file.path());
    block["credential"] = serde_json::json!({ "kind": "cookie", "name": "auth" });

    let err = resolver(block).expect_err("a cookie location must be refused");
    assert!(
        err.contains("must be `header`"),
        "the error must name the fix, got: {err}"
    );
}

#[test]
fn a_query_param_credential_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut block = htpasswd_block(file.path());
    block["credential"] = serde_json::json!({ "kind": "query_param", "name": "auth" });

    let err = resolver(block).expect_err("a query-param location must be refused");
    assert!(
        err.contains("must be `header`"),
        "the error must name the fix, got: {err}"
    );
}

#[test]
fn a_config_with_no_realm_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut block = htpasswd_block(file.path());
    block
        .as_object_mut()
        .expect("the block is an object")
        .remove("realm");

    let err = resolver(block).expect_err("realm is required");
    assert!(
        err.contains("realm"),
        "the error must name the missing field, got: {err}"
    );
}

#[test]
fn a_realm_that_cannot_be_quoted_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));

    for realm in ["ops\"team", "ops\\team", "ops\nteam", "ops\u{e9}"] {
        let mut block = htpasswd_block(file.path());
        block["realm"] = serde_json::Value::String(realm.to_owned());

        let err = resolver(block).expect_err("a realm that breaks the quoted string is refused");
        assert!(
            err.contains("printable ASCII"),
            "the error must say what a realm may hold, got: {err}"
        );
    }
}

#[test]
fn an_empty_realm_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut block = htpasswd_block(file.path());
    block["realm"] = serde_json::json!("");

    let err = resolver(block).expect_err("an empty realm is refused");
    assert!(
        err.contains("must not be empty"),
        "the error must name the field, got: {err}"
    );
}

#[test]
fn a_non_enforcing_expiry_mode_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut block = htpasswd_block(file.path());
    block["expiry"] = serde_json::json!("directory");

    let err = resolver(block).expect_err("there is no mode delegating expiry to the directory");
    assert!(
        err.contains("expiry") || err.contains("unknown variant"),
        "the error must name the field, got: {err}"
    );
}

#[test]
fn expiry_defaults_to_enforce() {
    assert_eq!(
        ExpiryPolicy::default(),
        ExpiryPolicy::Enforce,
        "expiry enforcement is mandatory; `.htpasswd` has no native expiry and nothing else \
         would be positioned to apply one"
    );
}

#[test]
fn a_missing_config_block_fails_to_load() {
    use praxis_policy_builtins::plugins::identity_basic::BasicIdentityResolver;
    use praxis_policy_core::plugin::PluginConfig;

    let err = BasicIdentityResolver::new(PluginConfig {
        name: "basic-auth".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        config: None,
        ..Default::default()
    })
    .expect_err("a resolver with no settings cannot be built");

    assert!(
        err.to_string().contains("`config:` block is required"),
        "the error must name the missing block, got: {err}"
    );
}

#[test]
fn an_unknown_config_key_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut block = htpasswd_block(file.path());
    block["scheme"] = serde_json::json!("Basic");

    let err = resolver(block).expect_err("an unknown key is a typo, not a no-op");
    assert!(
        err.contains("unknown field"),
        "the error must name the unknown key, got: {err}"
    );
}

#[test]
fn a_wrong_execution_mode_fails_to_load() {
    use praxis_policy_builtins::plugins::identity_basic::BasicIdentityResolver;
    use praxis_policy_core::plugin::{PluginConfig, PluginMode};

    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let err = BasicIdentityResolver::new(PluginConfig {
        name: "basic-auth".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        config: Some(htpasswd_block(file.path())),
        mode: PluginMode::Concurrent,
        ..Default::default()
    })
    .expect_err("an identity resolver cannot run in parallel");

    assert!(
        err.to_string().contains("mode: sequential"),
        "the error must name the fix, got: {err}"
    );
}

#[test]
fn a_role_with_no_record_map_section_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let mut block = htpasswd_block(file.path());
    block["role"] = serde_json::json!("caller_workload");

    let err = resolver(block)
        .expect_err("the workload anchor is a SPIFFE id, which no user-id default can satisfy");
    assert!(
        err.contains("no section") || err.contains("workload"),
        "the error must name the missing section, got: {err}"
    );
}

#[test]
fn a_zero_credential_ceiling_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));

    for field in ["max_password_bytes", "max_user_id_bytes"] {
        let mut block = htpasswd_block(file.path());
        block["limits"] = serde_json::json!({ field: 0 });

        let err = resolver(block).expect_err("a zero ceiling rejects every credential");
        assert!(
            err.contains("greater than zero"),
            "the error must say why zero cannot work, got: {err}"
        );
    }
}

#[test]
fn a_degenerate_failure_limit_fails_to_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));

    for field in ["capacity", "max_failures", "window_secs"] {
        let mut block = htpasswd_block(file.path());
        block["failure_limit"] = serde_json::json!({ field: 0 });

        let err = resolver(block).expect_err("a zero limiter setting denies every request");
        assert!(
            err.contains("greater than zero"),
            "the error must say why zero cannot work, got: {err}"
        );
    }
}

#[test]
fn the_password_ceiling_defaults_to_bcrypts_truncation_point() {
    let limits = praxis_policy_builtins::plugins::identity_basic::CredentialLimits::default();

    assert_eq!(
        limits.max_password_bytes, 72,
        "a longer password would verify on its 72-byte bcrypt prefix, accepting a credential \
         nobody chose"
    );
}

#[test]
fn the_failure_limiter_defaults_are_bounded() {
    let limits = FailureLimitConfig::default();

    assert!(
        limits.capacity > 0 && limits.max_failures > 0 && limits.window_secs > 0,
        "the default limiter must be active, not inert"
    );
}

/// `TokenSource` round-trips the Basic variant per RFC 7617, so a payload
/// naming a Basic credential survives serialization.
#[test]
fn the_basic_token_source_round_trips_through_serialization() {
    let json = serde_json::to_string(&TokenSource::Basic).expect("the variant serializes");

    assert_eq!(json, "\"basic\"", "the wire name is the snake_case variant");
    assert_eq!(
        serde_json::from_str::<TokenSource>(&json).expect("the variant deserializes"),
        TokenSource::Basic,
        "the variant must survive a round trip"
    );
}

#[test]
fn the_challenge_renders_the_configured_realm() {
    let block = serde_json::json!({
        "realm": "ops",
        "credential": { "kind": "header", "name": "Authorization" },
        "provider": { "kind": "htpasswd", "path": "/nonexistent", "refresh_secs": 30,
                      "max_staleness_secs": 300 },
    });
    let settings: BasicResolverConfig =
        serde_json::from_value(block).expect("the block deserializes");

    assert_eq!(
        settings.challenge(),
        "Basic realm=\"ops\"",
        "the challenge carries the realm and nothing else by default"
    );
}

#[test]
fn the_challenge_appends_the_charset_when_configured() {
    let block = serde_json::json!({
        "realm": "ops",
        "charset_utf8": true,
        "credential": { "kind": "header", "name": "Authorization" },
        "provider": { "kind": "htpasswd", "path": "/nonexistent", "refresh_secs": 30,
                      "max_staleness_secs": 300 },
    });
    let settings: BasicResolverConfig =
        serde_json::from_value(block).expect("the block deserializes");

    assert_eq!(
        settings.challenge(),
        "Basic realm=\"ops\", charset=\"UTF-8\"",
        "the charset advertises the client-side expectation when asked for"
    );
}

#[test]
fn an_unreadable_directory_file_fails_at_load_not_at_request_time() {
    let mut block = htpasswd_block("/nonexistent/ppe-basic-missing");
    block["realm"] = serde_json::json!("ops");

    let err = resolver(block).expect_err("an unreadable file must stop startup");
    assert!(
        !err.is_empty(),
        "the error must say the file could not be read"
    );
}

#[test]
fn the_factory_registers_one_handler_on_the_identity_hook() {
    use praxis_policy_builtins::plugins::identity_basic::BasicIdentityFactory;
    use praxis_policy_core::factory::PluginFactory as _;
    use praxis_policy_core::plugin::PluginConfig;

    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "pw", 4)));
    let instance = BasicIdentityFactory
        .create(&PluginConfig {
            name: "basic-auth".into(),
            kind: KIND.into(),
            hooks: vec!["identity.resolve".to_owned()],
            config: Some(htpasswd_block(file.path())),
            ..Default::default()
        })
        .expect("the factory builds a resolver from a valid block");

    let hooks: Vec<_> = instance.handlers.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        hooks,
        vec![praxis_policy_core::identity::HOOK_IDENTITY_RESOLVE],
        "the resolver answers the identity hook and nothing else"
    );
}

#[test]
fn the_factory_surfaces_a_config_error_rather_than_building() {
    use praxis_policy_builtins::plugins::identity_basic::BasicIdentityFactory;
    use praxis_policy_core::factory::PluginFactory as _;
    use praxis_policy_core::plugin::PluginConfig;

    let outcome = BasicIdentityFactory.create(&PluginConfig {
        name: "basic-auth".into(),
        kind: KIND.into(),
        hooks: vec!["identity.resolve".to_owned()],
        config: None,
        ..Default::default()
    });

    let Err(err) = outcome else {
        panic!("a resolver with no settings cannot be built");
    };
    assert!(
        err.to_string().contains("`config:` block is required"),
        "the factory must carry the resolver's own error out, got: {err}"
    );
}

#[test]
fn the_failure_limiter_admits_a_fresh_user_id_when_every_slot_is_live() {
    use praxis_policy_builtins::plugins::identity_basic::FailureLimiter;

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 1, "max_failures": 5, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );
    limiter.record_failure("alice");

    assert_eq!(
        limiter.admit("bob"),
        Ok(()),
        "a full map must not deny a user-id it holds no evidence against, or a spray of junk \
         user-ids becomes a global lockout"
    );
    assert_eq!(
        limiter.admit("alice"),
        Ok(()),
        "alice is tracked and within budget, so she is still admitted"
    );
    assert_eq!(
        limiter.saturations(),
        1,
        "the admitted-but-untracked attempt is still counted, so an operator can see that \
         capacity is too small without a user-id reaching the logs"
    );
}

#[test]
fn a_full_failure_limiter_does_not_displace_a_blocked_counter() {
    use praxis_policy_builtins::plugins::identity_basic::{FailureLimiter, Refusal};

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 1, "max_failures": 1, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );
    limiter.record_failure("alice");
    assert_eq!(
        limiter.admit("alice"),
        Err(Refusal::Blocked),
        "one failure spends a budget of one"
    );

    // The flood that, under an evicting limiter, would buy alice a fresh budget.
    for n in 0..32 {
        let sprayed = format!("junk{n}");
        assert_eq!(
            limiter.admit(&sprayed),
            Ok(()),
            "a sprayed user-id is admitted rather than denied"
        );
        limiter.record_failure(&sprayed);
    }

    assert_eq!(
        limiter.admit("alice"),
        Err(Refusal::Blocked),
        "alice's counter must survive the flood: admitting untracked user-ids must not become a \
         way to clear a blocked one"
    );
    assert_eq!(
        limiter.tracked(),
        1,
        "the flood is uncounted rather than tracked, so capacity still bounds the map"
    );
}

#[test]
fn the_failure_limiter_blocks_a_user_id_past_its_budget() {
    use praxis_policy_builtins::plugins::identity_basic::{FailureLimiter, Refusal};

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 16, "max_failures": 2, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );

    assert_eq!(limiter.admit("alice"), Ok(()), "the first attempt is free");
    limiter.record_failure("alice");
    assert_eq!(limiter.admit("alice"), Ok(()), "one failure is in budget");
    limiter.record_failure("alice");

    assert_eq!(
        limiter.admit("alice"),
        Err(Refusal::Blocked),
        "the budget is spent, so the next attempt costs no verification"
    );
    limiter.record_success("alice");
    assert_eq!(
        limiter.admit("alice"),
        Ok(()),
        "a success clears the counter, so the budget is restored"
    );
    assert_eq!(limiter.tracked(), 0, "the cleared counter frees its slot");
}

#[test]
fn a_password_ceiling_above_bcrypts_truncation_point_fails_at_load() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["limits"] = serde_json::json!({ "max_password_bytes": 128 });

    let Err(err) = resolver(block) else {
        panic!("a ceiling bcrypt cannot honour must not load");
    };
    assert!(
        err.contains("max_password_bytes") && err.contains("72"),
        "the error must name the setting and bcrypt's truncation point so an operator can act \
         on it, got: {err}"
    );
}

#[test]
fn the_bcrypt_password_ceiling_admits_exactly_the_truncation_point() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let mut block = htpasswd_block(file.path());
    block["limits"] = serde_json::json!({ "max_password_bytes": 72 });

    assert!(
        resolver(block).is_ok(),
        "72 is the longest password bcrypt verifies in full, so it is admitted rather than \
         refused one byte early"
    );
}

#[test]
fn a_large_password_ceiling_loads_on_a_directory_that_consumes_whole_passwords() {
    // argon2 has no truncation point, so the ceiling that locks out bcrypt
    // users is a legitimate configuration here.
    let file = HtpasswdFile::write(&format!(
        "{}\n",
        argon2_line("alice", "correct horse", 19_456, 2)
    ));
    let mut block = htpasswd_block(file.path());
    block["limits"] = serde_json::json!({ "max_password_bytes": 128 });

    assert!(
        resolver(block).is_ok(),
        "the ceiling is refused for bcrypt specifically, not for every backend: argon2 consumes \
         the whole password, so a longer one verifies rather than always failing"
    );
}
