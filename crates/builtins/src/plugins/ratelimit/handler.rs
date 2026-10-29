// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
use super::config::RateLimitConfig;

pub(super) struct RateLimit {
    bindings: BTreeMap<String, String>,
    check_lock: Mutex<()>,
    config: PluginConfig,
    limiter: RateLimiter,
    macro_locals: BTreeSet<String>,
    namespace: Namespace,
}

impl RateLimit {
    pub(super) fn new(config: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = config.config.as_ref().ok_or_else(|| {
            PluginError::Config {
                message: format!("plugin '{}': ratelimit config is required", config.name),
            }
            .boxed()
        })?;
        let typed = RateLimitConfig::deserialize(raw).map_err(|error| {
            PluginError::Config {
                message: format!(
                    "plugin '{}': invalid ratelimit config: {error}",
                    config.name
                ),
            }
            .boxed()
        })?;
        typed
            .validate()
            .map_err(|message| PluginError::Config { message }.boxed())?;

        let namespace: Namespace = typed.namespace.into();
        let limiter = RateLimiter::new(typed.counter_capacity);
        let mut macro_locals = BTreeSet::new();
        for (index, entry) in typed.limits.iter().enumerate() {
            for (source, is_condition) in entry
                .conditions
                .iter()
                .map(|source| (source, true))
                .chain(entry.variables.iter().map(|source| (source, false)))
            {
                let variables = Variables::parse(source).map_err(|error| {
                    PluginError::Config {
                        message: format!("ratelimit: limits[{index}] invalid CEL: {error}"),
                    }
                    .boxed()
                })?;
                macro_locals.extend(variables.local);
                for variable in variables.free {
                    if variable == "limit" && !is_condition {
                        return Err(PluginError::Config {
                            message: format!(
                                "ratelimit: limits[{index}] 'limit' is supported only in conditions, \
                                 not counter expressions"
                            ),
                        }
                        .boxed());
                    }
                    if variable != "limit" && !typed.bindings.contains_key(&variable) {
                        return Err(PluginError::Config {
                            message: format!(
                                "ratelimit: limits[{index}] references unbound CEL variable '{variable}'"
                            ),
                        }
                        .boxed());
                    }
                }
            }
            let conditions: Vec<Predicate> = entry
                .conditions
                .iter()
                .map(|condition| condition.as_str().try_into())
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    PluginError::Config {
                        message: format!("ratelimit: limits[{index}] invalid condition: {error}"),
                    }
                    .boxed()
                })?;
            let variables: Vec<Expression> = entry
                .variables
                .iter()
                .map(|variable| variable.as_str().try_into())
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    PluginError::Config {
                        message: format!("ratelimit: limits[{index}] invalid variable: {error}"),
                    }
                    .boxed()
                })?;
            if !limiter.add_limit(Limit::new(
                namespace.clone(),
                entry.max,
                entry.seconds,
                conditions,
                variables,
            )) {
                return Err(PluginError::Config {
                    message: format!("ratelimit: limits[{index}] duplicates an earlier limit"),
                }
                .boxed());
            }
        }

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
        // Build the same PPE attribute vocabulary as APL, using this plugin's
        // capability-filtered view of Extensions. Limitador's public Context
        // accepts flat string variables, so config binds CEL names to bag keys.
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
        match self
            .limiter
            .check_rate_limited_and_update(&self.namespace, &context, 1)
        {
            Ok(result) if result.limited => PluginResult::deny(
                PluginViolation::new("ratelimit.exceeded", "request rate limit exceeded")
                    .with_details(HashMap::from([(
                        "http.status".to_owned(),
                        serde_json::json!(429),
                    )]))
                    .with_proto_error_code(429),
            ),
            Ok(_) => PluginResult::allow(),
            Err(error) => {
                tracing::error!(%error, "ratelimit: Limitador check failed");
                PluginResult::deny(PluginViolation::new(
                    "ratelimit.check_failed",
                    "request rate limit check failed",
                ))
            },
        }
    }
}
