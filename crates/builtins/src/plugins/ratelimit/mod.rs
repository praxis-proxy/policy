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

mod cel;
mod config;
mod factory;
mod handler;

pub use factory::{KIND, RateLimitFactory};
