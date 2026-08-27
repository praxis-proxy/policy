// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// define_hooks! macro.
//
// Co-declares a hook's name constant and its routing-metadata row from
// one source. `define_hook!` (macros.rs) generates the hook *type* and
// its handler trait; this generates the *name* and what the dispatcher
// knows about it. A constant without a metadata row was the drift that
// let an HTTP hook reach production unregistered, and there is no
// way to test for it: Rust has no reflection, so any list a test walks
// is a second hand-maintained list. Emitting both from one declaration
// makes the mismatch unrepresentable instead.

/// Declares hook name constants and the metadata table for one module.
///
/// Each hook names its constant, its wire name, optionally the hook type
/// whose payload it carries, the entity type it is tied to (or `None`),
/// and its lifecycle phase. The macro emits a `pub const` per hook plus
/// one `&[(&str, HookMetadata)]` slice named by the first argument.
///
/// # Usage
///
/// ```rust,ignore
/// praxis_policy_core::define_hooks! {
///     /// Doc comment for the module's metadata slice.
///     MY_HOOK_METADATA;
///
///     /// Doc comment for the constant.
///     HOOK_MY_PRE: "my.pre" => family: MyHook, entity: Some(ENTITY_TOOL), phase: Pre;
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
/// # `family`
///
/// `family` names a hook *type*, not a string, and the row records that
/// type's `NAME`, so the row cannot drift from the type a handler is
/// written against. Registration refuses a handler that reports another
/// family, which is what keeps a plugin off a hook whose payload it
/// cannot read. Omitting it records `None`, which accepts a handler of
/// any family: the hook registry is open, and a host hook that has no
/// type of its own still has to be registrable.
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
            $konst:ident: $wire:literal =>
                $(family: $family:ty,)? entity: $entity:expr, phase: $phase:ident;
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
                        family: $crate::__hook_family!($($family)?),
                        entity_type: $entity,
                        phase: $crate::hooks::metadata::HookPhase::$phase,
                    },
                ),
            )+
        ];
    };
}

/// Turns [`define_hooks!`][crate::define_hooks]'s optional `family:` into
/// the metadata row's field. Reads the name off the hook type so the row
/// and the type cannot disagree; an omitted family records `None`, which
/// accepts a handler of any family.
#[doc(hidden)]
#[macro_export]
macro_rules! __hook_family {
    () => {
        None
    };
    ($hook:ty) => {
        Some(<$hook as $crate::hooks::trait_def::HookTypeDef>::NAME)
    };
}
