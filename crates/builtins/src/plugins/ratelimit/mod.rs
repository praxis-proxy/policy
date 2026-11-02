// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Experimental in-process request rate limiting with Limitador.
//!
//! An instance runs at the one rate-limit hook its `hooks:` declares,
//! `ratelimit.pre_identity` or `ratelimit.post_identity`, for the routes whose
//! `rate_limits:` list it. Limits read flat CEL variables bound to attributes
//! of the capability-filtered PPE extensions, by default `subject_id` and
//! `http_method`. It does not implement the Kuadrant attribute vocabulary.
//! Counters are local to the instance and reset on restart and on every config
//! load. A `rate_limits:` step with a `config:` override has its own instance
//! and counters, built once per loaded config.
//!
//! The counter store holds about `counter_capacity` counters that have
//! `variables`. When it is full, it either evicts a less used counter or keeps
//! the new one out, and either way the affected counter restarts at zero.
//! Limitador reports no eviction, so none is logged; a counter keyed on an
//! unbounded attribute with a small capacity warns at load instead.
//!
//! A denial carries its HTTP status in `proto_error_code` and `details`. The
//! reason names no binding, attribute, capability, limit or namespace; the
//! plugin logs those for the operator.

mod cel;
mod config;
mod factory;
mod handler;

pub use factory::{KIND, RateLimitFactory};
pub use handler::{
    CODE_CHECK_FAILED, CODE_EXCEEDED, CODE_MISSING_ATTRIBUTE, CODE_NO_HTTP_METHOD,
    CODE_NO_IDENTITY, CODE_UNSUPPORTED_ATTRIBUTE, DETAIL_LIMIT, DETAIL_REMAINING,
    DETAIL_RETRY_AFTER_SECONDS, DETAIL_WINDOW_SECONDS,
};
