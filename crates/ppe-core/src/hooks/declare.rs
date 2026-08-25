// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// define_hooks! macro.
//
// Co-declares a hook's name constant and its routing-metadata row from
// one source. `define_hook!` (macros.rs) generates the hook *type* and
// its handler trait; this generates the *name* and what the dispatcher
// knows about it. A constant without a metadata row was the drift that
// let `cmf.http_request` reach production unregistered, and there is no
// way to test for it: Rust has no reflection, so any list a test walks
// is a second hand-maintained list. Emitting both from one declaration
// makes the mismatch unrepresentable instead.

/// Declares hook name constants and the metadata table for one module.
///
/// Each hook names its constant, its wire name, the entity type it is
/// tied to (or `None`), and its lifecycle phase. The macro emits a
/// `pub const` per hook plus one `&[(&str, HookMetadata)]` slice named
/// by the first argument.
///
/// # Usage
///
/// ```rust,ignore
/// praxis_policy_core::define_hooks! {
///     /// Doc comment for the module's metadata slice.
///     MY_HOOK_METADATA;
///
///     /// Doc comment for the constant.
///     HOOK_MY_PRE: "my.pre" => entity: Some(ENTITY_TOOL), phase: Pre;
///     /// Doc comment for the constant.
///     HOOK_MY_GATE: "my.gate" => entity: None, phase: Unphased;
/// }
/// ```
///
/// `phase` is required rather than defaulted. A hook a plugin can name
/// in `hooks:` needs a row whether or not it has a phase, so a hook that
/// is genuinely outside the request lifecycle says `Unphased` out loud
/// instead of getting it by omission.
///
/// # Hosts with their own hooks
///
/// `praxis-policy-core`'s table covers the hooks it dispatches. A host
/// declaring its own uses this macro too, then registers the slice
/// before loading config that names those hooks:
///
/// ```rust,ignore
/// for (name, meta) in MY_HOOK_METADATA {
///     praxis_policy_core::hooks::register_hook_metadata(*name, *meta);
/// }
/// ```
#[macro_export]
macro_rules! define_hooks {
    (
        $(#[$slice_meta:meta])*
        $slice:ident;

        $(
            $(#[$hook_meta:meta])*
            $konst:ident: $wire:literal => entity: $entity:expr, phase: $phase:ident;
        )+
    ) => {
        $(
            $(#[$hook_meta])*
            pub const $konst: &str = $wire;
        )+

        $(#[$slice_meta])*
        pub const $slice: &[(&str, $crate::hooks::metadata::HookMetadata)] = &[
            $(
                (
                    $konst,
                    $crate::hooks::metadata::HookMetadata {
                        entity_type: $entity,
                        phase: $crate::hooks::metadata::HookPhase::$phase,
                    },
                ),
            )+
        ];
    };
}
