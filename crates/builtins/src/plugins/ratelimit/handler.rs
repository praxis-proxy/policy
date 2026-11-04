// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use limitador::RateLimiter;
use limitador::counter::Counter;
use limitador::limit::{Context, Expression, Limit, Namespace, Predicate};
use limitador_cel::{Context as CelContext, ExecutionError, Value};
use praxis_policy_apl_cmf::constants::{
    BAG_HTTP_CLIENT_ADDRESS, BAG_HTTP_METHOD, BAG_SUBJECT_ID, DETAIL_HTTP_STATUS,
};
use praxis_policy_apl_cmf::{BagBuilder, capability_namespaces, known_read_capabilities};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::hooks::{Extensions, HookHandler, PluginResult};
use praxis_policy_core::http_hook::{HttpHook, HttpPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use serde::Deserialize as _;
use tokio::sync::Mutex;

use super::cel::Variables;
use super::config::{
    DEFAULT_COUNTER_CAPACITY, RateLimitConfig, Stage, is_caller_controlled, is_identity_derived,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The request exceeded a limit. HTTP 429, with `retry_after_seconds`,
/// `limit`, `remaining` and `window_seconds` in `details`.
pub const CODE_EXCEEDED: &str = "ratelimit.exceeded";

/// The limiter could not check the request. HTTP 503.
pub const CODE_CHECK_FAILED: &str = "ratelimit.check_failed";

/// A limit binds `subject.id` and the request has no resolved subject. HTTP 401.
pub const CODE_NO_IDENTITY: &str = "ratelimit.no_identity";

/// A limit binds `http.method` and the request has none. HTTP 400.
pub const CODE_NO_HTTP_METHOD: &str = "ratelimit.no_http_method";

/// A limit binds an attribute the request lacks, or the plugin cannot read.
/// HTTP 400.
pub const CODE_MISSING_ATTRIBUTE: &str = "ratelimit.missing_attribute";

/// A limit binds an attribute whose value is not a string. HTTP 400.
pub const CODE_UNSUPPORTED_ATTRIBUTE: &str = "ratelimit.unsupported_attribute";

/// Details key: whole seconds until the limiting counter resets.
pub const DETAIL_RETRY_AFTER_SECONDS: &str = "retry_after_seconds";

/// Details key: the limiting counter's maximum per window.
pub const DETAIL_LIMIT: &str = "limit";

/// Details key: what the limiting counter has left in this window.
pub const DETAIL_REMAINING: &str = "remaining";

/// Details key: the limiting counter's window length in seconds.
pub const DETAIL_WINDOW_SECONDS: &str = "window_seconds";

const STATUS_TOO_MANY_REQUESTS: i64 = 429;

const STATUS_SERVICE_UNAVAILABLE: i64 = 503;

const STATUS_UNAUTHORIZED: i64 = 401;

const STATUS_BAD_REQUEST: i64 = 400;

/// A failing Limitador, or a host that never sets a bound attribute, fails
/// every request, so each is logged at most once per interval with a count of
/// the ones held back.
const FAILURE_LOG_INTERVAL_SECS: u64 = 60; // 1 minute

pub(super) struct RateLimit {
    bindings: BTreeMap<String, String>,
    check_failure_log: IntervalLog,
    check_lock: Mutex<()>,
    config: PluginConfig,
    condition_rules: Vec<Vec<ConditionCheck>>,
    computed_rules: Vec<ComputedCounterRule>,
    has_limit_conditions: bool,
    limiter: RateLimiter,
    macro_locals: BTreeSet<String>,
    namespace: Namespace,
    unbound_log: IntervalLog,
}

/// A rule with counter expressions that can fail to produce a key at runtime.
struct ComputedCounterRule {
    index: usize,
    variables: Vec<Expression>,
}

struct ConditionCheck {
    predicate: Predicate,
    with_limit: Option<limitador_cel::IdedExpr>,
}

/// Admits one log line per interval and counts the ones it holds back.
#[derive(Default)]
struct IntervalLog {
    next_at: AtomicU64,
    suppressed: AtomicU64,
}

impl IntervalLog {
    /// The count held back since the last admitted line, when a line is due.
    fn admit(&self) -> Option<u64> {
        let now = unix_seconds();
        let next = self.next_at.load(Ordering::Relaxed);
        let due = now >= next
            && self
                .next_at
                .compare_exchange(
                    next,
                    now.saturating_add(FAILURE_LOG_INTERVAL_SECS),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok();
        if due {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
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
        let mut condition_rules = Vec::with_capacity(typed.limits.len());
        let mut computed_rules = Vec::new();
        let mut has_limit_conditions = false;
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
            let mut checks = BTreeMap::new();
            for (source, predicate) in entry.conditions.iter().zip(&conditions) {
                let references_limit = Variables::parse(source)
                    .map_err(|error| config_error(name, error.to_string()))?
                    .free
                    .contains("limit");
                has_limit_conditions |= references_limit;
                let with_limit = if references_limit {
                    Some(
                        limitador_cel::parser::Parser::new()
                            .parse(source)
                            .map_err(|error| config_error(name, error.to_string()))?,
                    )
                } else {
                    None
                };
                checks.insert(
                    source.as_str(),
                    ConditionCheck {
                        predicate: predicate.clone(),
                        with_limit,
                    },
                );
            }
            condition_rules.push(checks.into_values().collect());
            let variables: Vec<Expression> = entry
                .variables
                .iter()
                .map(|variable| variable.as_str().try_into())
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    config_error(name, format!("limits[{index}] invalid variable: {error}"))
                })?;
            // A direct bound name is present in every checked context. CEL
            // expressions can still fail to resolve even when all bindings exist.
            let computed_variables: Vec<Expression> = variables
                .iter()
                .filter(|variable| !typed.bindings.contains_key(variable.source().trim()))
                .cloned()
                .collect();
            let limit = Limit::new(
                namespace.clone(),
                entry.max,
                entry.seconds,
                conditions,
                variables,
            );
            if !limiter.add_limit(limit.clone()) {
                return Err(config_error(
                    name,
                    format!("limits[{index}] duplicates an earlier limit"),
                ));
            }
            if !computed_variables.is_empty() {
                computed_rules.push(ComputedCounterRule {
                    index,
                    variables: computed_variables,
                });
            }
        }
        // An unreferenced binding is allowed but never resolved, so a request
        // lacking its attribute is not denied for it.
        typed
            .bindings
            .retain(|variable, _| referenced.contains(variable));
        check_stage_bindings(name, stage, &typed.bindings, &counter_keys)?;
        warn_on_small_capacity(name, typed.counter_capacity, &typed.bindings, &counter_keys);

        Ok(Self {
            bindings: typed.bindings,
            check_failure_log: IntervalLog::default(),
            check_lock: Mutex::new(()),
            config,
            condition_rules,
            computed_rules,
            has_limit_conditions,
            limiter,
            macro_locals,
            namespace,
            unbound_log: IntervalLog::default(),
        })
    }

    /// Refuse a matching rule that cannot form every configured counter key.
    fn matching_conditions(
        &self,
        context: &Context<'_>,
        values: Option<&HashMap<String, String>>,
    ) -> Result<Vec<bool>, String> {
        let mut cel_context = None;
        let mut matches = Vec::with_capacity(self.condition_rules.len());
        for (index, conditions) in self.condition_rules.iter().enumerate() {
            let mut matched = true;
            for condition in conditions {
                let result = if let Some(expression) = &condition.with_limit {
                    let Some(values) = values else {
                        return Err("limit condition context is unavailable".to_owned());
                    };
                    let scoped = cel_context.get_or_insert_with(|| {
                        let mut scoped = CelContext::default();
                        for (name, value) in values {
                            scoped.add_variable_from_value(name.clone(), value.clone());
                        }
                        scoped.add_variable_from_value(
                            "limit",
                            Value::Map(limitador_cel::objects::Map::from(HashMap::from([
                                ("name", Value::Null),
                                ("id", Value::Null),
                            ]))),
                        );
                        scoped
                    });
                    match scoped.resolve(expression) {
                        Ok(Value::Bool(value)) => Ok(value),
                        Ok(value) => Err(format!("unexpected condition value: {value:?}")),
                        Err(ExecutionError::NoSuchKey(_)) => Ok(false),
                        Err(error) => Err(error.to_string()),
                    }
                } else {
                    condition
                        .predicate
                        .test(context)
                        .map_err(|error| error.to_string())
                };
                match result {
                    Ok(true) => {},
                    Ok(false) => {
                        matched = false;
                        break;
                    },
                    Err(error) => return Err(format!("limits[{index}] condition failed: {error}")),
                }
            }
            matches.push(matched);
        }
        Ok(matches)
    }

    fn check_computed_counter_keys(
        &self,
        context: &Context<'_>,
        matching_conditions: &[bool],
    ) -> Result<(), String> {
        for rule in &self.computed_rules {
            let matches = matching_conditions
                .get(rule.index)
                .ok_or_else(|| format!("limits[{}] condition result is missing", rule.index))?;
            if !matches {
                continue;
            }
            for variable in &rule.variables {
                match variable.eval(context) {
                    Ok(Some(_)) => {},
                    Ok(None) => {
                        return Err(format!(
                            "limits[{}] counter expression '{}' resolved to no key",
                            rule.index,
                            variable.source()
                        ));
                    },
                    Err(error) => {
                        return Err(format!(
                            "limits[{}] counter expression '{}' failed: {error}",
                            rule.index,
                            variable.source()
                        ));
                    },
                }
            }
        }
        Ok(())
    }

    /// Deny a request lacking a bound attribute, telling the operator which
    /// binding failed and what would supply it at most once per interval.
    fn deny_unbound(
        &self,
        bag_has_it: bool,
        variable: &str,
        attribute: &str,
    ) -> PluginResult<HttpPayload> {
        let (code, status, reason) = if bag_has_it {
            (
                CODE_UNSUPPORTED_ATTRIBUTE,
                STATUS_BAD_REQUEST,
                "a request attribute a rate limit requires is not a string",
            )
        } else {
            match attribute {
                BAG_SUBJECT_ID => (
                    CODE_NO_IDENTITY,
                    STATUS_UNAUTHORIZED,
                    "the request has no identity, which a rate limit requires",
                ),
                BAG_HTTP_METHOD => (
                    CODE_NO_HTTP_METHOD,
                    STATUS_BAD_REQUEST,
                    "the request has no HTTP method, which a rate limit requires",
                ),
                _ => (
                    CODE_MISSING_ATTRIBUTE,
                    STATUS_BAD_REQUEST,
                    "the request lacks an attribute a rate limit requires",
                ),
            }
        };
        if let Some(suppressed) = self.unbound_log.admit() {
            let granting = granting_capabilities(attribute);
            let declared = granting
                .iter()
                .any(|capability| self.config.capabilities.contains(*capability));
            let hint = if bag_has_it {
                "bind an attribute with a string value"
            } else if granting.is_empty() || declared {
                "the request did not carry it; check the host or the identity step that sets it"
            } else {
                "the plugin cannot read it; add a capability listed in `grant` to its \
                 `capabilities:`"
            };
            tracing::warn!(
                plugin = %self.config.name,
                code,
                binding = variable,
                attribute,
                grant = ?granting,
                hint,
                suppressed,
                interval_seconds = FAILURE_LOG_INTERVAL_SECS,
                "ratelimit: a bound attribute is unavailable, so the request is denied; repeats \
                 are counted in `suppressed` and logged once per interval",
            );
        }
        PluginResult::deny(with_status(PluginViolation::new(code, reason), status))
    }

    /// Deny a request whose rate limit could not be checked, logging the
    /// cause at most once per interval.
    fn deny_check_failed(&self, cause: &dyn Display) -> PluginResult<HttpPayload> {
        if let Some(suppressed) = self.check_failure_log.admit() {
            tracing::error!(
                plugin = %self.config.name,
                error = %cause,
                suppressed,
                interval_seconds = FAILURE_LOG_INTERVAL_SECS,
                "ratelimit: rate limit check failed, so the request is denied; repeats are \
                 counted in `suppressed` and logged once per interval",
            );
        }
        PluginResult::deny(with_status(
            PluginViolation::new(CODE_CHECK_FAILED, "request rate limit check failed"),
            STATUS_SERVICE_UNAVAILABLE,
        ))
    }

    /// Deny an over-limit request with the client-safe view of its most
    /// restrictive counter, keeping the limit's identity in the log.
    fn deny_exceeded(
        &self,
        counters: &[Counter],
        limit_name: Option<&str>,
    ) -> PluginResult<HttpPayload> {
        let mut details = HashMap::from([(
            DETAIL_HTTP_STATUS.to_owned(),
            serde_json::json!(STATUS_TOO_MANY_REQUESTS),
        )]);
        if let Some(counter) = most_restrictive(counters) {
            let window = counter.limit().seconds();
            let remaining = counter.remaining().unwrap_or_else(|| counter.max_value());
            let retry_after = counter
                .expires_in()
                .map_or(window, ceil_seconds)
                .clamp(1, window.max(1));
            details.extend([
                (
                    DETAIL_RETRY_AFTER_SECONDS.to_owned(),
                    serde_json::json!(retry_after),
                ),
                (
                    DETAIL_LIMIT.to_owned(),
                    serde_json::json!(counter.max_value()),
                ),
                (DETAIL_REMAINING.to_owned(), serde_json::json!(remaining)),
                (DETAIL_WINDOW_SECONDS.to_owned(), serde_json::json!(window)),
            ]);
        }
        tracing::debug!(
            plugin = %self.config.name,
            namespace = self.namespace.as_ref(),
            limit_name,
            "ratelimit: request exceeded a limit",
        );
        PluginResult::deny(
            PluginViolation::new(CODE_EXCEEDED, "request rate limit exceeded")
                .with_details(details)
                .with_proto_error_code(STATUS_TOO_MANY_REQUESTS),
        )
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
        let bag = match BagBuilder::new().with_extensions(extensions) {
            Ok(builder) => builder.build(),
            Err(error) => {
                return self.deny_check_failed(&format_args!("attribute bag hashing: {error}"));
            },
        };
        let mut values = HashMap::with_capacity(self.bindings.len());
        for (variable, attribute) in &self.bindings {
            let Some(value) = bag.get_string(attribute) else {
                return self.deny_unbound(bag.contains(attribute), variable, attribute);
            };
            // HTTP methods are case-sensitive, but limits are written in the
            // canonical uppercase form, and a lowercase method must not skip them.
            let value = if attribute == BAG_HTTP_METHOD {
                value.to_ascii_uppercase()
            } else {
                value.to_owned()
            };
            values.insert(variable.clone(), value);
        }
        // Limitador's presence checks include macro locals. Validation above
        // rejects unbound free names; these placeholders satisfy only those
        // checks, while the CEL evaluator supplies the scoped local values.
        for local in &self.macro_locals {
            values.entry(local.clone()).or_default();
        }
        let cel_values = self.has_limit_conditions.then(|| values.clone());
        let context: Context<'_> = values.into();
        let matching_conditions = match self.matching_conditions(&context, cel_values.as_ref()) {
            Ok(matched) => matched,
            Err(error) => return self.deny_check_failed(&error),
        };
        // Limitador treats a missing key inside a counter expression as no
        // counter, even when the rule's conditions match. Deny before any
        // counter changes, including when another matching rule has a key.
        if !self.computed_rules.is_empty() {
            let resolved = catch_unwind(AssertUnwindSafe(|| {
                self.check_computed_counter_keys(&context, &matching_conditions)
            }));
            match resolved {
                Ok(Ok(())) => {},
                Ok(Err(error)) => return self.deny_check_failed(&error),
                Err(_) => {
                    return self.deny_check_failed(&"Limitador condition evaluation panicked");
                },
            }
        }
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
            Ok(Ok(result)) if result.limited => {
                self.deny_exceeded(&result.counters, result.limit_name.as_deref())
            },
            Ok(Ok(_)) => PluginResult::allow(),
            Ok(Err(error)) => self.deny_check_failed(&error),
            Err(_) => self.deny_check_failed(&"Limitador condition evaluation panicked"),
        }
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

fn with_status(violation: PluginViolation, status: i64) -> PluginViolation {
    violation
        .with_details(HashMap::from([(
            DETAIL_HTTP_STATUS.to_owned(),
            serde_json::json!(status),
        )]))
        .with_proto_error_code(status)
}

/// The counter a client waits longest on: least remaining, then latest reset,
/// so `retry_after_seconds` is when every exhausted counter allows again.
fn most_restrictive(counters: &[Counter]) -> Option<&Counter> {
    counters.iter().min_by_key(|counter| {
        (
            counter.remaining().unwrap_or_else(|| counter.max_value()),
            std::cmp::Reverse(counter.expires_in().unwrap_or_else(|| counter.window())),
        )
    })
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The read capabilities that expose `attribute` in the bag.
fn granting_capabilities(attribute: &str) -> Vec<&'static str> {
    known_read_capabilities()
        .filter(|capability| {
            capability_namespaces(capability).iter().any(|prefix| {
                if prefix.ends_with('.') {
                    attribute.starts_with(prefix)
                } else {
                    attribute == *prefix
                }
            })
        })
        .collect()
}

/// Warn when a counter keyed on a value with no natural bound shares a small
/// store, where a full store resets counters.
fn warn_on_small_capacity(
    name: &str,
    capacity: u64,
    bindings: &BTreeMap<String, String>,
    counter_keys: &BTreeSet<String>,
) {
    if capacity >= DEFAULT_COUNTER_CAPACITY {
        return;
    }
    for (variable, attribute) in bindings {
        if !counter_keys.contains(variable)
            || (attribute != BAG_HTTP_CLIENT_ADDRESS && !is_caller_controlled(attribute))
        {
            continue;
        }
        tracing::warn!(
            plugin = name,
            binding = %variable,
            attribute = %attribute,
            counter_capacity = capacity,
            recommended = DEFAULT_COUNTER_CAPACITY,
            "ratelimit: a counter is keyed on an unbounded attribute but `counter_capacity` is \
             small; once the store is full, a new key evicts a counter or is kept out, and \
             that counter restarts at zero, so raise `counter_capacity`",
        );
    }
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
