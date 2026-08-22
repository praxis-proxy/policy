// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// `PluginFactory` impl for the JWT identity resolver. Lives in this
// crate (not in any consuming integration) so that every host —
// Praxis filter, Envoy bridge, CLI test harness — wires it up the
// same way.
//
// Operators declare it in PPE YAML as:
//
//     plugins:
//       - name: jwt-resolver
//         kind: identity/jwt
//         hooks: [identity.resolve]
//         config:
//           trusted_issuers:
//             - issuer: https://idp.example.com
//               audiences: [my-api]
//               algorithms: [RS256]
//               decoding_key: { kind: jwks_url, url: ... }
//
// Claim mapping is configuration. Either name a shipped preset:
//
//           claim_mapper: keycloak
//
// or write a map, for a shape no preset covers. Mutually exclusive with
// `claim_mapper`:
//
//           claim_map:
//             subject:
//               id: sub
//               roles:
//                 paths:
//                   - realm_access.roles
//                   - resource_access.my-api.roles
//                 merge: union
//               teams: 'https://my-app\.example\.com/teams'
//               permissions:
//                 paths: [{ path: permissions, array_only: true }, scope]
//                 split: whitespace
//             claims:
//               include: [iss]
//
// See `ClaimMapConfig` for the field forms and the backslash-quoting rules.
//
// The `kind: identity/jwt` string is part of this crate's public API.
// Hosts call `mgr.register_factory("identity/jwt", Box::new(JwtIdentityFactory))`
// before `load_config_yaml`.

use std::sync::Arc;

use praxis_policy_core::{
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    identity::{HOOK_IDENTITY_RESOLVE, IdentityHook},
    plugin::PluginConfig,
};

use crate::JwtIdentityResolver;

/// The plugin `kind:` string operators write in PPE YAML to declare
/// a JWT identity resolver.
pub const KIND: &str = "identity/jwt";

/// Factory for `kind: identity/jwt` plugins. Instantiates a
/// `JwtIdentityResolver` from the `config:` block and registers it on
/// the `identity.resolve` hook.
pub struct JwtIdentityFactory;

impl PluginFactory for JwtIdentityFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let resolver = Arc::new(JwtIdentityResolver::new(config.clone())?);
        let handler = Arc::new(TypedHandlerAdapter::<IdentityHook, _>::new(Arc::clone(
            &resolver,
        )));
        Ok(PluginInstance {
            plugin: resolver,
            handlers: vec![(HOOK_IDENTITY_RESOLVE, handler)],
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    /// An HS256 shared secret rather than a PEM: this test is about the factory
    /// wiring, and a secret keeps it free of key-generation setup.
    fn cfg(config: serde_json::Value) -> PluginConfig {
        PluginConfig {
            name: "jwt".into(),
            kind: KIND.into(),
            hooks: vec![HOOK_IDENTITY_RESOLVE.to_owned()],
            config: Some(config),
            ..Default::default()
        }
    }

    fn valid_config() -> serde_json::Value {
        serde_json::json!({
            "trusted_issuers": [{
                "issuer": "https://issuer.example",
                "audiences": ["test-aud"],
                "algorithms": ["HS256"],
                "decoding_key": { "kind": "secret", "secret": "test-secret" },
            }],
            "claim_mapper": "standard",
        })
    }

    /// The hook name is fixed in code rather than read from `config.hooks`, so
    /// this pins the registration point an operator's `hooks:` list has to match.
    #[test]
    fn registers_one_handler_on_the_identity_resolve_hook() {
        let inst = JwtIdentityFactory
            .create(&cfg(valid_config()))
            .expect("a valid issuer config must build");
        assert_eq!(inst.handlers.len(), 1, "one resolver, one handler");
        assert_eq!(
            inst.handlers[0].0, HOOK_IDENTITY_RESOLVE,
            "the resolver must land on the identity.resolve hook"
        );
    }

    /// A claim map the resolver rejects has to fail here too. The alternative is
    /// a registered resolver that denies every request, which reads as an outage
    /// rather than as the configuration mistake it is.
    #[test]
    fn a_claim_map_fault_fails_the_factory_rather_than_the_first_request() {
        let base = valid_config();
        let issuers = base
            .get("trusted_issuers")
            .expect("the base config declares issuers")
            .clone();

        for faulty in [
            serde_json::json!({"trusted_issuers": issuers.clone(), "claim_mapper": "made-up"}),
            serde_json::json!({
                "trusted_issuers": issuers.clone(),
                "claim_map": {"subject": {"roles": "realm_access..roles"}},
            }),
            serde_json::json!({
                "trusted_issuers": issuers.clone(),
                "claim_map": {"subject": {"id": "sub"}},
                "role": "client",
            }),
            serde_json::json!({
                "trusted_issuers": issuers,
                "claim_mapper": "standard",
                "claim_map": {"subject": {"id": "sub"}},
            }),
        ] {
            let err = JwtIdentityFactory
                .create(&cfg(faulty.clone()))
                .err()
                .unwrap_or_else(|| panic!("{faulty} must not build"));
            assert!(
                matches!(*err, PluginError::Config { .. }),
                "{faulty}: expected a config error, got {err:?}"
            );
        }
    }

    /// Every shipped preset is nameable through the factory, which is the path a
    /// host actually takes.
    #[test]
    fn every_shipped_preset_is_nameable_through_the_factory() {
        let issuers = valid_config()
            .get("trusted_issuers")
            .expect("the base config declares issuers")
            .clone();
        for name in crate::presets::names() {
            let config = serde_json::json!({
                "trusted_issuers": issuers.clone(),
                "claim_mapper": name,
            });
            JwtIdentityFactory
                .create(&cfg(config))
                .unwrap_or_else(|_| panic!("'{name}' must build through the factory"));
        }
    }

    /// The factory propagates construction failure rather than registering a
    /// resolver that would deny every request at runtime.
    #[test]
    fn a_config_the_resolver_rejects_fails_the_factory() {
        // `.err()` rather than `expect_err`: PluginInstance is not Debug.
        let err = JwtIdentityFactory
            .create(&cfg(serde_json::json!({ "trusted_issuers": [] })))
            .err()
            .expect("an empty issuer list must not build");
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a config error, got {err:?}"
        );
    }
}
