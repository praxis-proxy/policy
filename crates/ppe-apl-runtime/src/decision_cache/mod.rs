// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Optional bounded cache around PDP `evaluate`.
//
// This caches Allow/Deny, not CEL programs or OPA engines. Those compile
// caches already exist inside the backends. The wrapper is off until a
// `global.pdp[]` entry names `cache:` with a positive TTL and cap.
//
// External PDP policy (a Rego file, a Cedar set loaded from disk) can
// change without a PPE config reload. Cached decisions then stay until
// the TTL expires. That staleness is the cost of the cache and is
// documented in `docs/pdp-decision-cache.md`.

mod config;
#[cfg(any(test, feature = "test-util"))]
mod contract;
mod key;
mod store;
mod wrapper;

pub use config::{DecisionCacheConfig, DecisionCacheConfigError, split_cache_block};
#[cfg(any(test, feature = "test-util"))]
pub use contract::{CacheContractSamples, run_cache_contract};
pub use wrapper::{CachedPdpResolver, DecisionCacheStats};
