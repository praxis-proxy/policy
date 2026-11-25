// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP-backed acquired metadata source.

mod config;
mod factory;
mod handler;

pub use factory::{KIND, MetadataHttpFactory};
