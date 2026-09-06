# Crate Reference

PPE is a Cargo workspace of focused crates. Most hosts depend on `praxis-policy`
(the facade); plugin authors depend on `cpex-sdk`.

| Crate | Role |
|-------|------|
| [`praxis-policy`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe) | Host facade. Re-exports the runtime and, with a feature, the builtins. Start here. |
| [`praxis-policy-core`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-core) | The runtime: `PluginManager`, executor, hooks, config, extensions. |
| [`cpex-sdk`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-sdk) | Plugin author SDK: the `Plugin` and `HookHandler` traits, payloads, results. Depend on this to write a plugin or PDP resolver. |
| [`praxis-policy-orchestration`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-orchestration) | Async concurrency primitives shared by the runtime. |
| [`cpex-builtins`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-builtins) | Feature-gated bundle of builtin plugins, PDP resolvers, and the session store (see [Builtins](builtins.md)). |
| [`cpex-ffi`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-ffi) | C FFI (`cdylib` / `staticlib`) for Go, Python, and WASM host bindings. |
| [`praxis-policy-apl-core`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-apl-core) | APL compiler and evaluator: rules, effects, field pipelines, routes. |
| [`praxis-policy-apl-cmf`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-apl-cmf) | Bridges typed extensions into the flat attribute bag APL reads. |
| [`praxis-policy-apl-runtime`](https://github.com/praxis-proxy/policy/tree/main/crates/ppe-apl-runtime) | Runtime adapter: wires APL routes to hooks, dispatches plugins and PDPs. |

Generated API docs are on [docs.rs/praxis-policy](https://docs.rs/praxis-policy).

## Language bindings

The Rust core is exposed to other languages through `cpex-ffi`. Go bindings live
in [`go/cpex`](https://github.com/praxis-proxy/policy/tree/main/go/cpex). Python
(PyO3) and WASM bindings are planned over the same core.

## Supply-chain integrity

The C FFI is distributed as **signed prebuilt artifacts**. A host that links the
FFI rather than building from source verifies the signature on the artifact
before use, so the binary boundary between the Rust core and a non-Rust host is
not an unverified trust gap. The signing and verification process is documented
in
[`crates/cpex-ffi/RELEASE.md`](https://github.com/praxis-proxy/policy/blob/main/crates/ppe-ffi/RELEASE.md).

