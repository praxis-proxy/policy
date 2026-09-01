// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Concurrent invoke against concurrent mutation of `PolicyEngine`.
//!
//! The engine is shared behind `Arc` the way a host shares it: request
//! threads `invoke_*` while other threads register, unregister, reload
//! config, and annotate routes. These tests run that shape on real OS
//! threads and check two things a single-threaded Tokio runtime cannot:
//!
//! 1. A successful registration is still visible afterwards (lost-update).
//! 2. An invoke that overlaps a snapshot swap sees a complete snapshot,
//!    not a mix of two configs, and after mutators stop the route cache
//!    matches the live snapshot.
//!
//! The stress test is seeded. Override with `PPE_STRESS_SEED`,
//! `PPE_STRESS_OPS`, `PPE_STRESS_INVOKERS`, and `PPE_STRESS_MUTATORS`.
//! A failure prints the seed so the same schedule can be replayed.

#![allow(
    missing_docs,
    dead_code,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::collections::HashSet;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use async_trait::async_trait;
use praxis_policy_core::config::parse_config;
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::executor::erase_result;
use praxis_policy_core::extensions::MetaExtension;
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::metadata::{HookMetadata, register_hook_metadata};
use praxis_policy_core::hooks::payload::{Extensions, PluginPayload};
use praxis_policy_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use praxis_policy_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};
use praxis_policy_core::registry::AnyHookHandler;

const HOOK: &str = "stress_hook";
const BASE_PLUGIN: &str = "base";
const TOOL: &str = "stress_tool";
const KIND: &str = "stress/allow";

const DEFAULT_SEED: u64 = 0xC0_FF_EE;
const DEFAULT_OPS: u32 = 128;
const DEFAULT_INVOKERS: usize = 4;
const DEFAULT_MUTATORS: usize = 4;

#[derive(Debug, Clone)]
struct StressPayload {
    value: String,
}
praxis_policy_core::impl_plugin_payload!(StressPayload);

struct StressHook;
impl HookTypeDef for StressHook {
    type Payload = StressPayload;
    type Result = PluginResult<StressPayload>;
    const NAME: &'static str = HOOK;
}

struct StressPlugin {
    cfg: PluginConfig,
}

impl StressPlugin {
    fn new(cfg: PluginConfig) -> Arc<Self> {
        Arc::new(Self { cfg })
    }
}

#[async_trait]
impl Plugin for StressPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<StressHook> for StressPlugin {
    async fn handle(
        &self,
        _payload: &StressPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<StressPayload> {
        PluginResult::allow()
    }
}

#[async_trait]
impl AnyHookHandler for StressPlugin {
    async fn invoke(
        &self,
        _payload: &dyn PluginPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        Ok(erase_result(PluginResult::<StressPayload>::allow()))
    }

    fn hook_type_name(&self) -> &'static str {
        StressHook::NAME
    }
}

struct StressFactory;

impl PluginFactory for StressFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = StressPlugin::new(config.clone());
        let handler: Arc<dyn AnyHookHandler> = Arc::new(TypedHandlerAdapter::<
            StressHook,
            StressPlugin,
        >::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin,
            handlers: vec![(StressHook::NAME, handler)],
        })
    }
}

fn plugin_config(name: &str) -> PluginConfig {
    PluginConfig {
        name: name.to_owned(),
        kind: KIND.to_owned(),
        description: None,
        author: None,
        version: None,
        hooks: vec![HOOK.to_owned()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: Default::default(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: None,
    }
}

fn register_stress_hook() {
    register_hook_metadata(StressHook::NAME, HookMetadata::permissive());
}

fn tool_extensions() -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(TOOL.into()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn bootstrap() -> Arc<PolicyEngine> {
    register_stress_hook();
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(KIND, Box::new(StressFactory));
    let yaml = format!(
        "
engine_settings:
  dispatch: policy
plugins:
  - name: {BASE_PLUGIN}
    kind: {KIND}
    hooks: [{HOOK}]
    mode: sequential
routes:
  - tool: {TOOL}
"
    );
    let config = parse_config(&yaml).expect("bootstrap config must parse");
    engine
        .load_config(config)
        .expect("bootstrap load_config must succeed");
    engine
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .map(|raw| {
            raw.parse::<u64>().unwrap_or_else(|_| {
                panic!("{name}={raw:?} is not a u64");
            })
        })
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    let default = u64::try_from(default).expect("fits u64");
    usize::try_from(env_u64(name, default)).expect("fits usize")
}

/// `SplitMix64`. One stream per mutator (`seed ^ mix(mutator_id)`) so the
/// schedule is a function of the seed alone.
struct SplitMix64(u64);

impl SplitMix64 {
    fn from_seed(seed: u64, stream: u64) -> Self {
        Self(seed ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn choose(&mut self, n: u32) -> u32 {
        let bound = u64::from(n.max(1));
        u32::try_from(self.next_u64() % bound).expect("bound is a u32")
    }
}

fn register_named(engine: &PolicyEngine, name: &str) -> Result<(), Box<PluginError>> {
    let cfg = plugin_config(name);
    engine.register_handler::<StressHook, _>(StressPlugin::new(cfg.clone()), cfg)
}

/// Distinct names, one per thread, all `register_handler` calls overlapping
/// at a barrier. Last-writer-wins on the snapshot would drop at least one.
#[test]
fn concurrent_writers_do_not_drop_registrations() {
    const N: usize = 8;
    let engine = bootstrap();
    let barrier = Arc::new(Barrier::new(N));
    let mut joins = Vec::with_capacity(N);
    for i in 0..N {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        joins.push(thread::spawn(move || {
            let name = format!("barrier-{i}");
            barrier.wait();
            register_named(&engine, &name).expect("register");
            name
        }));
    }
    let names: Vec<String> = joins
        .into_iter()
        .map(|j| j.join().expect("writer thread"))
        .collect();

    let missing: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| engine.get_plugin(name).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "lost update: register returned Ok but the snapshot is missing {missing:?}; \
         present={:?}",
        engine.plugin_names()
    );
    assert!(
        engine.get_plugin(BASE_PLUGIN).is_some(),
        "a concurrent register must not drop the bootstrap plugin"
    );
}

/// N invoke tasks against M mutator OS threads. Each mutator owns a name
/// prefix, so the expected live set is the union of per-thread logs and
/// does not depend on a global total order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_invoke_against_concurrent_mutation() {
    let seed = env_u64("PPE_STRESS_SEED", DEFAULT_SEED);
    let ops = env_u64("PPE_STRESS_OPS", u64::from(DEFAULT_OPS));
    let invokers = env_usize("PPE_STRESS_INVOKERS", DEFAULT_INVOKERS).max(1);
    let mutators = env_usize("PPE_STRESS_MUTATORS", DEFAULT_MUTATORS).max(1);
    eprintln!(
        "engine concurrency stress seed={seed} ops={ops} invokers={invokers} \
         mutators={mutators}"
    );

    let engine = bootstrap();
    engine.initialize().await.expect("initialize");
    let generation_at_start = engine.config_generation();

    let invoke_ok = Arc::new(AtomicU64::new(0));
    let mut invoke_joins = Vec::with_capacity(invokers);
    for i in 0..invokers {
        let engine = Arc::clone(&engine);
        let invoke_ok = Arc::clone(&invoke_ok);
        invoke_joins.push(tokio::spawn(async move {
            for n in 0..ops {
                let payload: Box<dyn PluginPayload> = Box::new(StressPayload {
                    value: format!("invoker-{i}-{n}"),
                });
                let (result, _) = engine
                    .invoke_by_name(HOOK, payload, tool_extensions(), None)
                    .await;
                assert!(
                    result.continue_processing,
                    "invoke must see a coherent allow snapshot; \
                     seed={seed} invoker={i} op={n} denied={:?}",
                    result.violation
                );
                invoke_ok.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    let mut mutator_joins = Vec::with_capacity(mutators);
    for mutator_id in 0..mutators {
        let engine = Arc::clone(&engine);
        mutator_joins.push(thread::spawn(move || {
            mutator_loop(
                &engine,
                seed,
                u64::try_from(mutator_id).expect("fits u64"),
                ops,
            )
        }));
    }

    let mut expected: HashSet<String> = HashSet::new();
    expected.insert(BASE_PLUGIN.to_owned());
    let mut published = 0_u64;
    for join in mutator_joins {
        let outcome = join.join().expect("mutator thread");
        expected.extend(outcome.live);
        published += outcome.published;
    }
    for join in invoke_joins {
        join.await.expect("invoker task");
    }

    // Annotations installed by mutators short-circuit routing and skip
    // the route cache. Strip them so the quiesced invoke is a cache miss
    // against the live snapshot.
    engine.remove_route_annotation("tool", TOOL, None, HOOK);

    let present: HashSet<String> = engine.plugin_names().into_iter().collect();
    let missing: Vec<&str> = expected
        .iter()
        .map(String::as_str)
        .filter(|name| !present.contains(*name))
        .collect();
    let unexpected: Vec<&str> = present
        .iter()
        .map(String::as_str)
        .filter(|name| mutator_owned_name(name) && !expected.contains(*name))
        .collect();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "lost update under concurrent mutation; seed={seed} missing={missing:?} \
         unexpected={unexpected:?} expected={expected:?} present={present:?}"
    );

    let generation = engine.config_generation();
    // `published` is a lower bound: every counted op published a snapshot.
    // A no-op `unregister` is not counted (generation may still bump). A
    // no-op `remove_route_annotation` is counted because `mutate_runtime`
    // always stores and bumps, even when the key is absent.
    assert!(
        generation >= generation_at_start + published,
        "generation must not go backwards and must count every published \
         snapshot; seed={seed} start={generation_at_start} end={generation} \
         published={published}"
    );

    // Mutators have stopped. A cache filled under their feet must not
    // outlive the snapshot: clear, miss, refill from the live config.
    engine.clear_routing_cache();
    assert_eq!(engine.routing_cache_size(), 0);
    let payload: Box<dyn PluginPayload> = Box::new(StressPayload {
        value: "after-quiesce".into(),
    });
    let (result, _) = engine
        .invoke_by_name(HOOK, payload, tool_extensions(), None)
        .await;
    assert!(
        result.continue_processing,
        "quiesced invoke must still allow; seed={seed}"
    );
    assert!(
        engine.routing_cache_size() >= 1,
        "routing is on, so a tool invoke must memoize the resolved lineup; \
         seed={seed} cache={}",
        engine.routing_cache_size()
    );
    assert_eq!(
        invoke_ok.load(Ordering::Relaxed),
        ops * u64::try_from(invokers).expect("fits u64"),
        "every invoke must have finished; seed={seed}"
    );
}

fn mutator_owned_name(name: &str) -> bool {
    matches!(name.as_bytes().first(), Some(b'm' | b'r')) && name.contains('-')
}

struct MutatorOutcome {
    live: HashSet<String>,
    published: u64,
}

fn mutator_loop(engine: &PolicyEngine, seed: u64, mutator_id: u64, ops: u64) -> MutatorOutcome {
    let mut rng = SplitMix64::from_seed(seed, mutator_id + 1);
    let mut live = HashSet::new();
    let mut owned: Vec<String> = Vec::new();
    let mut published = 0_u64;
    let mut next_id = 0_u64;

    for _ in 0..ops {
        match rng.choose(5) {
            0 => {
                let name = format!("m{mutator_id}-{next_id}");
                next_id += 1;
                if register_named(engine, &name).is_ok() {
                    live.insert(name.clone());
                    owned.push(name);
                    published += 1;
                }
            },
            1 => {
                if let Some(name) = owned.pop()
                    && engine.unregister(&name).is_some()
                {
                    live.remove(&name);
                    published += 1;
                }
            },
            2 => {
                let name = format!("ann-{mutator_id}-{next_id}");
                next_id += 1;
                let cfg = plugin_config(&name);
                engine.annotate_route(
                    "tool",
                    TOOL,
                    None,
                    HOOK,
                    StressPlugin::new(cfg.clone()),
                    cfg,
                );
                published += 1;
            },
            3 => {
                // Shared key: a second mutator may find nothing to remove.
                // `mutate_runtime` still publishes (generation bumps) on that
                // no-op, so this counts a snapshot, not a hit.
                engine.remove_route_annotation("tool", TOOL, None, HOOK);
                published += 1;
            },
            _ => {
                let name = format!("r{mutator_id}-{next_id}");
                next_id += 1;
                let yaml = format!(
                    "
engine_settings:
  dispatch: policy
plugins:
  - name: {name}
    kind: {KIND}
    hooks: [{HOOK}]
    mode: sequential
routes:
  - tool: {TOOL}
"
                );
                if let Ok(()) = parse_config(&yaml).and_then(|cfg| engine.load_config(cfg)) {
                    live.insert(name);
                    published += 1;
                }
            },
        }
    }

    MutatorOutcome { live, published }
}
