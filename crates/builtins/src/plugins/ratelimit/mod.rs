// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Experimental in-process request rate limiting with Limitador.
//!
//! This plugin evaluates `subject_id` and `http_method` from capability-filtered
//! PPE extensions. It does not implement the Kuadrant attribute vocabulary.
//! Counters are local to this plugin instance and disappear on restart.

mod config;
mod factory;
mod handler;

pub use factory::{KIND, RateLimitFactory};
