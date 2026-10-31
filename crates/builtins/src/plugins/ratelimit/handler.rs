// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::panic::{AssertUnwindSafe, catch_unwind};

use limitador::RateLimiter;
use limitador::limit::{Context, Expression, Limit, Namespace, Predicate};
use praxis_policy_apl_cmf::BagBuilder;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::{Extensions, HookHandler, PluginResult};
use praxis_policy_core::http_hook::{HttpHook, HttpPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use serde::Deserialize as _;
use tokio::sync::Mutex;

use super::cel::Variables;
use super::config::{RateLimitConfig, Stage, is_caller_controlled, is_identity_derived};

pub(super) struct RateLimit {
    bindings: BTreeMap<String, String>,
    check_lock: Mutex<()>,
    config: PluginConfig,
    limiter: RateLimiter,
    macro_locals: BTreeSet<String>,
    namespace: Namespace,
}

impl RateLimit {
    pub(super) fn new(config: PluginConfig, stage: Stage) -> Result<Self, Box<PluginError>> {
        let name = config.name.as_str();
        let raw = config
            .config
            .as_ref()
            .ok_or_else(|| config_error(name, "ratelimit config is required"))?;
        let mut typed = RateLimitConfig::deserialize(raw)
            .map_err(|error| config_error(name, format!("invalid ratelimit config: {error}")))?;
        typed
            .validate()
            .map_err(|message| config_error(name, message))?;

        let namespace: Namespace = typed.namespace.into();
        let limiter = RateLimiter::new(typed.counter_capacity);
        let mut macro_locals = BTreeSet::new();
        let mut referenced = BTreeSet::new();
        let mut counter_keys = BTreeSet::new();
        for (index, entry) in typed.limits.iter().enumerate() {
            for (source, is_condition) in entry
                .conditions
                .iter()
                .map(|source| (source, true))
                .chain(entry.variables.iter().map(|source| (source, false)))
            {
                let variables = Variables::parse(source).map_err(|error| {
                    config_error(name, format!("limits[{index}] invalid CEL: {error}"))
                })?;
                macro_locals.extend(variables.local);
                for variable in variables.free {
                    if variable == "limit" {
                        if !is_condition {
                            return Err(config_error(
                                name,
                                format!(
                                    "limits[{index}] 'limit' is supported only in conditions, \
                                     not counter expressions"
                                ),
                            ));
                        }
                        continue;
                    }
                    if !typed.bindings.contains_key(&variable) {
                        return Err(config_error(
                            name,
                            format!("limits[{index}] references unbound CEL variable '{variable}'"),
                        ));
                    }
                    if !is_condition {
                        counter_keys.insert(variable.clone());
                    }
                    referenced.insert(variable);
                }
            }
            let conditions: Vec<Predicate> = entry
                .conditions
                .iter()
                .map(|condition| condition.as_str().try_into())
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    config_error(name, format!("limits[{index}] invalid condition: {error}"))
                })?;
            let variables: Vec<Expression> = entry
                .variables
                .iter()
                .map(|variable| variable.as_str().try_into())
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    config_error(name, format!("limits[{index}] invalid variable: {error}"))
                })?;
            if !limiter.add_limit(Limit::new(
                namespace.clone(),
                entry.max,
                entry.seconds,
                conditions,
                variables,
            )) {
                return Err(config_error(
                    name,
                    format!("limits[{index}] duplicates an earlier limit"),
                ));
            }
        }
        // An unreferenced binding is allowed but never resolved, so a request
        // lacking its attribute is not denied for it.
        typed
            .bindings
            .retain(|variable, _| referenced.contains(variable));
        check_stage_bindings(name, stage, &typed.bindings, &counter_keys)?;

        Ok(Self {
            bindings: typed.bindings,
            check_lock: Mutex::new(()),
            config,
            limiter,
            macro_locals,
            namespace,
        })
    }
}

impl Plugin for RateLimit {
    fn config(&self) -> &PluginConfig {
        &self.config
    }
}

impl HookHandler<HttpHook> for RateLimit {
    async fn handle(
        &self,
        _payload: &HttpPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<HttpPayload> {
        // Limitador's Context takes only flat string variables, so each CEL
        // name is bound to one bag attribute.
        let bag = BagBuilder::new().with_extensions(extensions).build();
        let mut values = HashMap::with_capacity(self.bindings.len());
        for (variable, attribute) in &self.bindings {
            let Some(value) = bag.get_string(attribute) else {
                let code = if bag.contains(attribute) {
                    "ratelimit.unsupported_attribute"
                } else {
                    match attribute.as_str() {
                        "subject.id" => "ratelimit.no_identity",
                        "http.method" => "ratelimit.no_http_method",
                        _ => "ratelimit.missing_attribute",
                    }
                };
                return PluginResult::deny(PluginViolation::new(
                    code,
                    format!("PPE attribute '{attribute}' is unavailable as a string"),
                ));
            };
            values.insert(variable.clone(), value.to_owned());
        }
        // Limitador's presence checks include macro locals. Validation above
        // rejects unbound free names; these placeholders satisfy only those
        // checks, while the CEL evaluator supplies the scoped local values.
        for local in &self.macro_locals {
            values.entry(local.clone()).or_default();
        }
        let context: Context<'_> = values.into();
        // Limitador's in-memory check and update are separate operations. Serialize them
        // across this plugin instance so concurrent requests cannot exceed the limit.
        let _guard = self.check_lock.lock().await;
        // Limitador 0.14 unwraps condition evaluation errors. Contain that panic
        // here so it denies instead of reaching the executor, where `on_error:
        // ignore` would admit the request. The limiter's locks are released
        // before conditions run, so no state is left poisoned.
        let checked = catch_unwind(AssertUnwindSafe(|| {
            self.limiter
                .check_rate_limited_and_update(&self.namespace, &context, 1)
        }));
        match checked {
            Ok(Ok(result)) if result.limited => PluginResult::deny(
                PluginViolation::new("ratelimit.exceeded", "request rate limit exceeded")
                    .with_details(HashMap::from([(
                        "http.status".to_owned(),
                        serde_json::json!(429),
                    )]))
                    .with_proto_error_code(429),
            ),
            Ok(Ok(_)) => PluginResult::allow(),
            Ok(Err(error)) => {
                tracing::error!(%error, "ratelimit: Limitador check failed");
                check_failed()
            },
            Err(_) => {
                tracing::error!("ratelimit: Limitador condition evaluation panicked");
                check_failed()
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

fn check_failed() -> PluginResult<HttpPayload> {
    PluginResult::deny(PluginViolation::new(
        "ratelimit.check_failed",
        "request rate limit check failed",
    ))
}

/// Refuse a binding the stage cannot read, and a pre-identity counter a caller
/// could reset by changing a value it controls.
fn check_stage_bindings(
    name: &str,
    stage: Stage,
    bindings: &BTreeMap<String, String>,
    counter_keys: &BTreeSet<String>,
) -> Result<(), Box<PluginError>> {
    for (variable, attribute) in bindings {
        if stage == Stage::PreIdentity && is_identity_derived(attribute) {
            return Err(config_error(
                name,
                format!(
                    "binding '{variable}' reads `{attribute}`, which identity resolution sets, \
                     so it is never present at `{}`; declare `hooks: [{}]` or bind an \
                     attribute present before identity, such as `http.client_address`",
                    Stage::PreIdentity.hook(),
                    Stage::PostIdentity.hook(),
                ),
            ));
        }
        if !counter_keys.contains(variable) || !is_caller_controlled(attribute) {
            continue;
        }
        if stage == Stage::PreIdentity {
            return Err(config_error(
                name,
                format!(
                    "binding '{variable}' keys a counter on `{attribute}`, which the caller \
                     chooses, so at `{}` a caller resets its counter by changing it; key the \
                     counter on `http.client_address`, or use the binding only in `conditions`",
                    Stage::PreIdentity.hook(),
                ),
            ));
        }
        tracing::warn!(
            plugin = name,
            binding = %variable,
            attribute = %attribute,
            "ratelimit: a counter is keyed on a caller-chosen attribute, so a caller can \
             start a fresh counter by changing it; prefer `subject.id`",
        );
    }
    Ok(())
}

pub(super) fn config_error(name: &str, message: impl Display) -> Box<PluginError> {
    PluginError::Config {
        message: format!("plugin '{name}': {message}"),
    }
    .boxed()
}
