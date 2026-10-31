// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Experimental in-process request rate limiting with Limitador.
//!
//! This plugin evaluates `subject_id` and `http_method` from capability-filtered
//! PPE extensions. It does not implement the Kuadrant attribute vocabulary.
//! Counters are local to this plugin instance and reset on restart and on
//! every config reload. A route `config:` override builds its own instance,
//! rebuilt with fresh counters on any config generation bump, including a route
//! annotation change.

mod cel;
mod config;
mod factory;
mod handler;

pub use factory::{KIND, RateLimitFactory};
