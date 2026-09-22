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
//! 2. An invoke that overlaps a snapshot swap sees one complete lineup
//!    (paired plugins from a single `load_config` both fire, or neither
//!    does), not a mix of two snapshots.
//!
//! Route-cache fill needs `dispatch: policy`. Plugin dispatch in this
//! crate needs `dispatch: hooks`. The two stress tests use one fixture
//! each; mixing them in one engine leaves the invoke arm firing nothing.
//!
//! The stress tests are seeded. Override with `PPE_STRESS_SEED`,
//! `PPE_STRESS_OPS`, `PPE_STRESS_INVOKERS`, and `PPE_STRESS_MUTATORS`.
//! A failure prints the seed so the same schedule can be replayed.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used,
    reason = "test and example code"
)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
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

type Ledger = Arc<Mutex<HashMap<u64, Vec<String>>>>;

#[derive(Debug, Clone)]
struct StressPayload {
    invoke_id: u64,
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
    ledger: Ledger,
}

impl StressPlugin {
    fn new(cfg: PluginConfig, ledger: Ledger) -> Arc<Self> {
        Arc::new(Self { cfg, ledger })
    }

    fn record(&self, invoke_id: u64) {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(invoke_id)
            .or_default()
            .push(self.cfg.name.clone());
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
        payload: &StressPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<StressPayload> {
        self.record(payload.invoke_id);
        PluginResult::allow()
    }
}

#[async_trait]
impl AnyHookHandler for StressPlugin {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        if let Some(p) = payload.as_any().downcast_ref::<StressPayload>() {
            self.record(p.invoke_id);
        }
        Ok(erase_result(PluginResult::<StressPayload>::allow()))
    }

    fn hook_type_name(&self) -> &'static str {
        StressHook::NAME
    }
}

struct StressFactory {
    ledger: Ledger,
}

impl PluginFactory for StressFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = StressPlugin::new(config.clone(), Arc::clone(&self.ledger));
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

fn new_ledger() -> Ledger {
    Arc::new(Mutex::new(HashMap::new()))
}

fn new_engine(ledger: &Ledger) -> Arc<PolicyEngine> {
    register_stress_hook();
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(
        KIND,
        Box::new(StressFactory {
            ledger: Arc::clone(ledger),
        }),
    );
    engine
}

fn bootstrap_hooks(ledger: &Ledger) -> Arc<PolicyEngine> {
    let engine = new_engine(ledger);
    let yaml = format!(
        "
engine_settings:
  dispatch: hooks
plugins:
  - name: {BASE_PLUGIN}
    kind: {KIND}
    hooks: [{HOOK}]
    mode: sequential
    priority: 10
"
    );
    let config = parse_config(&yaml).expect("hooks bootstrap config must parse");
    engine
        .load_config(config)
        .expect("hooks bootstrap load_config must succeed");
    engine
}

fn bootstrap_policy(ledger: &Ledger) -> Arc<PolicyEngine> {
    let engine = new_engine(ledger);
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
    let config = parse_config(&yaml).expect("policy bootstrap config must parse");
    engine
        .load_config(config)
        .expect("policy bootstrap load_config must succeed");
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

fn register_named(
    engine: &PolicyEngine,
    ledger: &Ledger,
    name: &str,
) -> Result<(), Box<PluginError>> {
    let cfg = plugin_config(name);
    engine
        .register_handler::<StressHook, _>(StressPlugin::new(cfg.clone(), Arc::clone(ledger)), cfg)
}

fn take_fired(ledger: &Ledger, invoke_id: u64) -> Vec<String> {
    ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&invoke_id)
        .unwrap_or_default()
}

/// `load_config` publishes `*-L` and `*-R` in one snapshot. One invoke
/// that sees only one of the pair mixed two snapshots. An annotation is
/// the entire lineup, so that path is exempt.
fn assert_coherent_lineup(fired: &[String], seed: u64, invoke_id: u64) {
    assert!(
        !fired.is_empty(),
        "invoke fired no plugins; seed={seed} invoke={invoke_id}"
    );
    if fired.iter().any(|name| name.starts_with("ann-")) {
        assert_eq!(
            fired.len(),
            1,
            "an annotation is the whole lineup; seed={seed} invoke={invoke_id} \
             fired={fired:?}"
        );
        return;
    }
    for name in fired {
        if let Some(stem) = name.strip_suffix("-L") {
            let right = format!("{stem}-R");
            assert!(
                fired.iter().any(|n| n == &right),
                "torn snapshot: {name} fired without {right}; seed={seed} \
                 invoke={invoke_id} fired={fired:?}"
            );
        }
        if let Some(stem) = name.strip_suffix("-R") {
            let left = format!("{stem}-L");
            assert!(
                fired.iter().any(|n| n == &left),
                "torn snapshot: {name} fired without {left}; seed={seed} \
                 invoke={invoke_id} fired={fired:?}"
            );
        }
    }
}

fn stress_knobs() -> (u64, u64, usize, usize) {
    let seed = env_u64("PPE_STRESS_SEED", DEFAULT_SEED);
    let ops = env_u64("PPE_STRESS_OPS", u64::from(DEFAULT_OPS));
    let invokers = env_usize("PPE_STRESS_INVOKERS", DEFAULT_INVOKERS).max(1);
    let mutators = env_usize("PPE_STRESS_MUTATORS", DEFAULT_MUTATORS).max(1);
    (seed, ops, invokers, mutators)
}

/// Distinct names, one per thread, all `register_handler` calls overlapping
/// at a barrier. Last-writer-wins on the snapshot would drop at least one.
#[test]
fn concurrent_writers_do_not_drop_registrations() {
    const N: usize = 8;
    let ledger = new_ledger();
    let engine = bootstrap_hooks(&ledger);
    let barrier = Arc::new(Barrier::new(N));
    let mut joins = Vec::with_capacity(N);
    for i in 0..N {
        let engine = Arc::clone(&engine);
        let ledger = Arc::clone(&ledger);
        let barrier = Arc::clone(&barrier);
        joins.push(thread::spawn(move || {
            let name = format!("barrier-{i}");
            barrier.wait();
            register_named(&engine, &ledger, &name).expect("register");
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

/// N invoke tasks against M mutator OS threads under `dispatch: hooks`,
/// so registered plugins actually run. Invokers loop until mutators
/// finish; joining the OS threads happens on a blocking pool so a tokio
/// worker is not stuck in `JoinHandle::join` for the whole mutation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_invoke_against_concurrent_mutation() {
    let (seed, ops, invokers, mutators) = stress_knobs();
    eprintln!(
        "engine concurrency stress seed={seed} ops={ops} invokers={invokers} \
         mutators={mutators}"
    );

    let ledger = new_ledger();
    let engine = bootstrap_hooks(&ledger);
    engine.initialize().await.expect("initialize");
    let generation_at_start = engine.config_generation();
    let done = Arc::new(AtomicBool::new(false));
    let next_invoke = Arc::new(AtomicU64::new(1));
    let invoke_ok = Arc::new(AtomicU64::new(0));

    let mut invoke_joins = Vec::with_capacity(invokers);
    for i in 0..invokers {
        let engine = Arc::clone(&engine);
        let ledger = Arc::clone(&ledger);
        let done = Arc::clone(&done);
        let next_invoke = Arc::clone(&next_invoke);
        let invoke_ok = Arc::clone(&invoke_ok);
        invoke_joins.push(tokio::spawn(async move {
            while !done.load(Ordering::Acquire) {
                let invoke_id = next_invoke.fetch_add(1, Ordering::Relaxed);
                let payload: Box<dyn PluginPayload> = Box::new(StressPayload { invoke_id });
                let (result, _) = engine
                    .invoke_by_name(HOOK, payload, tool_extensions(), None)
                    .await;
                assert!(
                    result.continue_processing,
                    "invoke must see a coherent allow snapshot; \
                     seed={seed} invoker={i} invoke={invoke_id} denied={:?}",
                    result.violation
                );
                let fired = take_fired(&ledger, invoke_id);
                assert_coherent_lineup(&fired, seed, invoke_id);
                invoke_ok.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        }));
    }

    let mut mutator_joins = Vec::with_capacity(mutators);
    for mutator_id in 0..mutators {
        let engine = Arc::clone(&engine);
        let ledger = Arc::clone(&ledger);
        mutator_joins.push(thread::spawn(move || {
            mutator_loop(
                &engine,
                &ledger,
                seed,
                u64::try_from(mutator_id).expect("fits u64"),
                ops,
                true,
            )
        }));
    }

    let outcomes = tokio::task::spawn_blocking(move || {
        mutator_joins
            .into_iter()
            .map(|j| j.join().expect("mutator thread"))
            .collect::<Vec<_>>()
    })
    .await
    .expect("join mutators");
    done.store(true, Ordering::Release);

    let mut expected: HashSet<String> = HashSet::new();
    expected.insert(BASE_PLUGIN.to_owned());
    let mut published = 0_u64;
    for outcome in outcomes {
        expected.extend(outcome.live);
        published += outcome.published;
    }
    for join in invoke_joins {
        join.await.expect("invoker task");
    }

    assert!(
        invoke_ok.load(Ordering::Relaxed) > 0,
        "invokers must overlap the mutation stream; seed={seed}"
    );

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
}

/// Route cache fill is a `dispatch: policy` property. Mutate, quiesce,
/// then miss and refill from the live snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_route_cache_refills_after_concurrent_mutation() {
    let (seed, ops, _, mutators) = stress_knobs();
    eprintln!("engine cache stress seed={seed} ops={ops} mutators={mutators}");

    let ledger = new_ledger();
    let engine = bootstrap_policy(&ledger);
    engine.initialize().await.expect("initialize");
    let generation_at_start = engine.config_generation();

    let mut mutator_joins = Vec::with_capacity(mutators);
    for mutator_id in 0..mutators {
        let engine = Arc::clone(&engine);
        let ledger = Arc::clone(&ledger);
        mutator_joins.push(thread::spawn(move || {
            mutator_loop(
                &engine,
                &ledger,
                seed,
                u64::try_from(mutator_id).expect("fits u64"),
                ops,
                false,
            )
        }));
    }

    let outcomes = tokio::task::spawn_blocking(move || {
        mutator_joins
            .into_iter()
            .map(|j| j.join().expect("mutator thread"))
            .collect::<Vec<_>>()
    })
    .await
    .expect("join mutators");

    let mut expected: HashSet<String> = HashSet::new();
    expected.insert(BASE_PLUGIN.to_owned());
    let mut published = 0_u64;
    for outcome in outcomes {
        expected.extend(outcome.live);
        published += outcome.published;
    }

    engine.remove_route_annotation("tool", TOOL, None, HOOK);

    let present: HashSet<String> = engine.plugin_names().into_iter().collect();
    let missing: Vec<&str> = expected
        .iter()
        .map(String::as_str)
        .filter(|name| !present.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "lost update under concurrent mutation; seed={seed} missing={missing:?} \
         present={present:?}"
    );

    let generation = engine.config_generation();
    assert!(
        generation >= generation_at_start + published,
        "generation must not go backwards; seed={seed} start={generation_at_start} \
         end={generation} published={published}"
    );

    engine.clear_routing_cache();
    assert_eq!(engine.routing_cache_size(), 0);
    let payload: Box<dyn PluginPayload> = Box::new(StressPayload { invoke_id: 0 });
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
}

fn mutator_owned_name(name: &str) -> bool {
    matches!(name.as_bytes().first(), Some(b'm' | b'r')) && name.contains('-')
}

struct MutatorOutcome {
    live: HashSet<String>,
    published: u64,
}

fn mutator_loop(
    engine: &PolicyEngine,
    ledger: &Ledger,
    seed: u64,
    mutator_id: u64,
    ops: u64,
    hooks: bool,
) -> MutatorOutcome {
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
                if register_named(engine, ledger, &name).is_ok() {
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
                    StressPlugin::new(cfg.clone(), Arc::clone(ledger)),
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
                let id = next_id;
                next_id += 1;
                let yaml = if hooks {
                    let left = format!("r{mutator_id}-{id}-L");
                    let right = format!("r{mutator_id}-{id}-R");
                    format!(
                        "
engine_settings:
  dispatch: hooks
plugins:
  - name: {left}
    kind: {KIND}
    hooks: [{HOOK}]
    mode: sequential
    priority: 10
  - name: {right}
    kind: {KIND}
    hooks: [{HOOK}]
    mode: sequential
    priority: 20
"
                    )
                } else {
                    let name = format!("r{mutator_id}-{id}");
                    format!(
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
                    )
                };
                if parse_config(&yaml)
                    .and_then(|cfg| engine.load_config(cfg))
                    .is_ok()
                {
                    if hooks {
                        live.insert(format!("r{mutator_id}-{id}-L"));
                        live.insert(format!("r{mutator_id}-{id}-R"));
                    } else {
                        live.insert(format!("r{mutator_id}-{id}"));
                    }
                    published += 1;
                }
            },
        }
    }

    MutatorOutcome { live, published }
}
