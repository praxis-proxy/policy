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
        "advertise_utf8_charset": true,
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

/// The charset flag is a predicate, not the value it advertises.
///
/// `charset_utf8` -- and the `charset: UTF-8` string the plan sketched --
/// must fail at load rather than deserialize into a default. `charset` could
/// only ever take the one value RFC 7617 Section 2.1 defines, so the key is a
/// flag; `deny_unknown_fields` is what stops a config written against either
/// earlier spelling from loading with the charset silently dropped from the
/// challenge.
#[test]
fn an_earlier_spelling_of_the_charset_flag_fails_to_load() {
    for stale in ["charset_utf8", "charset"] {
        let mut block = serde_json::json!({
            "realm": "ops",
            "credential": { "kind": "header", "name": "Authorization" },
            "provider": { "kind": "htpasswd", "path": "/nonexistent", "refresh_secs": 30,
                          "max_staleness_secs": 300 },
        });
        block[stale] = serde_json::json!(true);

        let parsed = serde_json::from_value::<BasicResolverConfig>(block);
        assert!(
            parsed.is_err(),
            "`{stale}` must fail at load rather than deserialize into a default: a config that \
             loaded with the key ignored would serve a challenge missing the charset it asked \
             for, with nothing to tell the operator why"
        );
    }
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
fn the_failure_limiter_tracks_a_fresh_user_id_by_name_while_a_slot_is_live() {
    use praxis_policy_builtins::plugins::identity_basic::FailureLimiter;

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 1, "max_failures": 5, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );
    limiter
        .admit("alice")
        .expect("alice's first attempt is within budget")
        .record_failure();

    let Ok(bob) = limiter.admit("bob") else {
        panic!("a full map must not deny a user-id it holds no evidence against");
    };
    drop(bob);
    let Ok(alice) = limiter.admit("alice") else {
        panic!("alice is tracked and within budget, so she is still admitted");
    };
    drop(alice);

    assert_eq!(
        limiter.saturations(),
        1,
        "bob found no named slot, so his attempt is counted in the overflow table and the \
         operator can see that capacity is too small without a user-id reaching the logs"
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
    limiter
        .admit("alice")
        .expect("the first attempt is within budget")
        .record_failure();
    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "one failure spends a budget of one"
    );

    for n in 0..32 {
        let sprayed = format!("junk{n}");
        if let Ok(admission) = limiter.admit(&sprayed) {
            admission.record_failure();
        }
    }

    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "alice's counter must survive the flood: counting an untracked user-id must not become \
         a way to clear a blocked one"
    );
    assert_eq!(
        limiter.tracked(),
        1,
        "the flood is counted in the fixed overflow table rather than named, so capacity still \
         bounds the map"
    );
}

#[test]
fn an_unsettled_attempt_spends_the_budget_while_it_is_still_in_flight() {
    use praxis_policy_builtins::plugins::identity_basic::{FailureLimiter, Refusal};

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 16, "max_failures": 1, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );

    let in_flight = limiter
        .admit("alice")
        .expect("the first attempt is within a budget of one");

    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "a budget of one must be spent by the attempt already in flight, before it has any \
         verdict to record. Counting only settled failures would admit this second guess, \
         which is how parallel attempts for one user-id used to pass the same \
         pre-verification read"
    );

    in_flight.record_failure();

    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "and the settled failure holds the budget for the rest of the window, so the \
         reservation is not merely swapped for the failure it became"
    );
}

#[test]
fn a_released_in_flight_attempt_returns_its_budget() {
    use praxis_policy_builtins::plugins::identity_basic::FailureLimiter;

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 16, "max_failures": 1, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );

    let abandoned = limiter
        .admit("alice")
        .expect("the first attempt is within a budget of one");
    drop(abandoned);

    assert!(
        limiter.admit("alice").is_ok(),
        "an attempt that reached no verdict must return its reservation rather than spend it: \
         a directory error or a cancelled request is not a failed guess, and charging it would \
         let an unreachable directory lock out every user"
    );
}

#[tokio::test]
async fn an_overflow_attempt_settles_on_the_bucket_it_was_charged_against() {
    use praxis_policy_builtins::plugins::identity_basic::FailureLimiter;

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 1, "max_failures": 2, "window_secs": 1,
        }))
        .expect("the limiter config parses"),
    );

    let holder = limiter
        .admit("junk")
        .expect("the junk name takes the only named slot");
    let overflow = limiter
        .admit("alice")
        .expect("the map is full, so alice is charged to an overflow bucket");
    assert_eq!(
        limiter.saturations(),
        1,
        "alice must have reached the overflow table, or this test proves nothing"
    );

    drop(holder);
    let named = limiter
        .admit("alice")
        .expect("the freed slot now admits alice by name");

    overflow.record_failure();
    named.record_success();

    assert_eq!(
        limiter.tracked(),
        0,
        "the named success clears its own counter rather than leaving a failure recorded \
         against alice by name"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

    let refill = limiter
        .admit("junk")
        .expect("junk takes the only named slot again");
    let mut admitted = 0_u32;
    for _ in 0..8 {
        match limiter.admit("alice") {
            Ok(admission) => {
                admitted = admitted.saturating_add(1);
                admission.record_failure();
            },
            Err(_) => break,
        }
    }
    drop(refill);

    assert_eq!(
        admitted, 2,
        "once the window has passed, alice's overflow bucket must offer its whole budget \
         again. Settling the overflow failure on the named counter instead leaves the bucket \
         holding a reservation, and a reservation never expires -- so part of the budget of \
         every user-id sharing that bucket is spent for the life of the process"
    );
}

/// Filling every overflow bucket must not deny a caller who knows the password.
///
/// The P0 this closes, at the scale that produced it: the reviewer's
/// simulation blocked 1023 of 1024 buckets with ~10k unauthenticated requests
/// and denied 54% of legitimate callers, rising with the spray rate. The
/// earlier spray test filled only the *named* map, so the relocated defect
/// passed underneath it.
///
/// Driven against the limiter rather than a resolver: spraying this many
/// user-ids through real bcrypt verifications would take minutes.
#[test]
fn a_spray_that_blocks_every_overflow_bucket_still_lets_a_proven_caller_through() {
    use praxis_policy_builtins::plugins::identity_basic::{FailureLimiter, Refusal};

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 1, "max_failures": 2, "window_secs": 300,
        }))
        .expect("the limiter config parses"),
    );
    let _squatter = limiter
        .admit("squatter")
        .expect("the squatter takes the only named slot");

    // Spend every bucket several times over, which is what the old refusal
    // needed to lock the route.
    for n in 0..8_192 {
        let name = format!("junk{n}");
        for _ in 0..2 {
            if let Ok(admission) = limiter.admit(&name) {
                admission.record_failure();
            }
        }
    }
    assert!(
        limiter.saturations() > 0,
        "the spray must have been counted in overflow"
    );

    // A caller the saturated map cannot name, whose bucket the spray spent.
    // The refusal is recoverable, not a verdict on this caller.
    assert_eq!(
        limiter.admit("victim").err(),
        Some(Refusal::Unproven),
        "a spent shared bucket must refuse as unproven, not as blocked: the failures in it \
         belong to the spray, not to this caller"
    );

    // Verifying the credential is the evidence the bucket could not supply.
    limiter.admit_proven();
    assert_eq!(
        limiter.proven(),
        1,
        "a cleared shared-bucket refusal must be observable, so an operator can see \
         legitimate callers paying for buckets they do not own"
    );
}

#[test]
fn a_saturated_failure_limiter_still_bounds_a_fresh_target() {
    use praxis_policy_builtins::plugins::identity_basic::FailureLimiter;

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 1, "max_failures": 2, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );
    limiter
        .admit("junk")
        .expect("the junk name takes the only named slot")
        .record_failure();

    let mut admitted = 0_u32;
    for _ in 0..8 {
        match limiter.admit("alice") {
            Ok(admission) => {
                admitted = admitted.saturating_add(1);
                admission.record_failure();
            },
            Err(_) => break,
        }
    }

    assert_eq!(
        admitted, 2,
        "a user-id the saturated map cannot name must still be bounded by max_failures: \
         filling the map with a junk name previously bought an attacker an unlimited budget \
         against any fresh target"
    );
    assert!(
        limiter.saturations() > 0,
        "the attempts must have been counted in the overflow table, or this test is not \
         exercising saturation"
    );
}

#[test]
fn an_outstanding_attempt_is_charged_against_the_budget() {
    use praxis_policy_builtins::plugins::identity_basic::{FailureLimiter, Refusal};

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 16, "max_failures": 1, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );

    let held = limiter
        .admit("alice")
        .expect("the first attempt is within budget");

    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "a budget of one is spent by the attempt already in flight: recording failures only \
         after verification let every parallel guess past this check at once"
    );

    drop(held);
    let Ok(next) = limiter.admit("alice") else {
        panic!("releasing an unsettled attempt must restore the budget it reserved");
    };
    drop(next);
}

#[test]
fn a_released_reservation_records_no_failure() {
    use praxis_policy_builtins::plugins::identity_basic::FailureLimiter;

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 16, "max_failures": 2, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );

    for _ in 0..8 {
        drop(limiter.admit("alice").expect("each attempt is admitted"));
    }

    assert_eq!(
        limiter.tracked(),
        0,
        "an attempt that reached no verdict -- a directory error or a cancelled request -- must \
         leave no failure behind, or anyone able to break the directory could spend a named \
         victim's budget"
    );
}

#[test]
fn a_success_does_not_discharge_the_attempts_running_beside_it() {
    use praxis_policy_builtins::plugins::identity_basic::{FailureLimiter, Refusal};

    let limiter = FailureLimiter::new(
        serde_json::from_value(serde_json::json!({
            "capacity": 16, "max_failures": 2, "window_secs": 60,
        }))
        .expect("the limiter config parses"),
    );

    let first = limiter
        .admit("alice")
        .expect("the first attempt is admitted");
    let second = limiter
        .admit("alice")
        .expect("a second concurrent attempt is within a budget of two");
    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "two attempts in flight spend a budget of two"
    );

    first.record_success();

    let third = limiter
        .admit("alice")
        .expect("the success returns its own reservation, so one slot is free again");
    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "the attempt still running must keep its reservation: removing the counter on a success \
         would discard it and let the concurrent guesses past the budget they were charged \
         against"
    );

    drop(second);
    drop(third);
    assert_eq!(
        limiter.tracked(),
        0,
        "once every reservation is settled the counter frees its slot rather than leaking one \
         per authenticated user-id"
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

    limiter
        .admit("alice")
        .expect("the first attempt is free")
        .record_failure();
    limiter
        .admit("alice")
        .expect("one failure is in budget")
        .record_failure();

    assert_eq!(
        limiter.admit("alice").err(),
        Some(Refusal::Blocked),
        "the budget is spent, so the next attempt costs no verification"
    );

    limiter.tracked();
    let Ok(cleared) = limiter.admit("bob") else {
        panic!("bob has spent nothing, so he is admitted");
    };
    cleared.record_success();
    assert_eq!(
        limiter.tracked(),
        1,
        "a success clears its own counter and frees the slot, leaving only alice tracked"
    );
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
