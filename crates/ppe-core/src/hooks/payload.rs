// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// PluginPayload trait and Extensions stub.
//
// PluginPayload is the base trait for all hook payloads. Every payload
// implements it, giving the executor and registry a common bound for type
// safety.
//
// The trait is object-safe — the executor works with `Box<dyn PluginPayload>`
// instead of `Box<dyn Any>`, catching type errors at compile time.
// Downcasting to concrete types uses the `as_any()` method.
//
// Extensions is the typed container for all message extensions
// (security, delegation, HTTP, meta, etc.). It is always passed
// as a separate parameter to handlers — never inside the payload.
// This allows per-plugin capability filtering and independent
// modification without copying the payload.

use std::any::Any;
use std::fmt;

// Re-export Extensions and OwnedExtensions from the extensions module.
// These are the typed containers for all extension data. They live in
// extensions/container.rs but are re-exported here for backward
// compatibility with existing code that imports from hooks::payload.
pub use crate::extensions::{Extensions, Guarded, MetaExtension, OwnedExtensions, WriteToken};

/// Base trait for all hook payloads.
///
/// payload type in the framework implements this trait. The executor
/// and registry use `Box<dyn PluginPayload>` (not `Box<dyn Any>`)
/// for type-safe dispatch.
///
/// The trait is **object-safe** — it can be used behind `Box`, `&`,
/// and `Arc` without knowing the concrete type. This is achieved by
/// providing `clone_boxed()` instead of requiring `Clone` directly
/// (which is not object-safe), and `as_any()` / `as_any_mut()` for
/// downcasting to the concrete type when needed.
///
/// Payloads are:
/// - Cloneable via `clone_boxed()` — the executor uses this for COW
///   when a modifying plugin (Sequential or Transform) needs ownership.
/// - `Send + Sync` — payloads may be shared across threads for
///   Concurrent mode plugins.
/// - `'static` — payloads must be owned types (no borrowed references).
///
/// Extensions are **not** part of the payload. They are passed as a
/// separate `&Extensions` parameter to handlers.
///
/// # Examples
///
/// ```
/// use praxis_policy_core::hooks::payload::PluginPayload;
///
/// #[derive(Debug, Clone)]
/// struct RateLimitPayload {
///     client_id: String,
///     request_count: u64,
/// }
///
/// impl PluginPayload for RateLimitPayload {
///     fn clone_boxed(&self) -> Box<dyn PluginPayload> {
///         Box::new(self.clone())
///     }
///     fn as_any(&self) -> &dyn std::any::Any { self }
///     fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
/// }
/// ```
pub trait PluginPayload: Send + Sync + 'static {
    /// Clone this payload into a new `Box<dyn PluginPayload>`.
    ///
    /// Used by the executor for copy-on-write: read-only modes borrow
    /// the payload, modifying modes receive a clone via this method.
    fn clone_boxed(&self) -> Box<dyn PluginPayload>;

    /// Downcast to a concrete type via `&dyn Any`.
    ///
    /// Used by typed handler wrappers to recover the concrete payload
    /// type from `Box<dyn PluginPayload>`.
    fn as_any(&self) -> &dyn Any;

    /// Downcast to a concrete type via `&mut dyn Any`.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Canonical bytes of this payload for content-addressed audit
    /// provenance, or `None` for a payload that cannot or should not be
    /// serialized, which is the default.
    ///
    /// The bytes feed a content hash and only the digest is kept, never the
    /// bytes, so a node's provenance is recorded without re-spilling content
    /// a redaction plugin exists to remove. Computed only when content
    /// provenance is enabled, so the default costs nothing.
    ///
    /// What a consumer may assume: `impl_plugin_payload!(_, audit_serialize)`
    /// derives this through [`canonical_audit_bytes`], which sorts object keys
    /// at every level, so identical content gives identical bytes across runs
    /// and processes and two equal digests mean the same content within a
    /// deployment.
    ///
    /// The sorting is explicit rather than inherited from `serde_json::Map`.
    /// This workspace resolves `serde_json` with `preserve_order`, so its
    /// `Map` keeps insertion order, and a payload holding a `HashMap` would
    /// otherwise serialize differently run to run and read as changed content
    /// when nothing changed.
    ///
    /// This is sorted-key JSON, not RFC 8785. Number formatting follows
    /// `serde_json` and is stable within a version but is not guaranteed
    /// across toolchains, so do not treat a digest as a cross-toolchain
    /// canonical form. A hand-written `audit_bytes` must preserve the same
    /// property or its hashes will not compare.
    fn audit_bytes(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Canonical bytes for a serializable payload: JSON with object keys sorted
/// at every level.
///
/// Sorting cannot be left to `serde_json::Map`. This workspace resolves
/// `serde_json` with `preserve_order`, so a `Map` keeps insertion order and a
/// payload holding a `HashMap` would encode differently on each run. Two
/// digests of identical content would then differ, and a consumer would read
/// a change that never happened.
///
/// Returns `None` when the value does not serialize.
#[must_use]
pub fn canonical_audit_bytes<T: serde::Serialize>(value: &T) -> Option<Vec<u8>> {
    fn sort_keys(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                serde_json::Value::Object(
                    entries
                        .into_iter()
                        .map(|(k, v)| (k, sort_keys(v)))
                        .collect(),
                )
            },
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(sort_keys).collect())
            },
            other => other,
        }
    }

    let value = serde_json::to_value(value).ok()?;
    serde_json::to_vec(&sort_keys(value)).ok()
}

/// Hash bytes for a content reference, as `sha256:<hex>`.
///
/// Only the digest is ever recorded. A reader can tell whether two payloads
/// were identical without the audit trail holding either one.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity("sha256:".len() + 64);
    s.push_str("sha256:");
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl fmt::Debug for dyn PluginPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn PluginPayload")
    }
}

/// Implements `PluginPayload` for a type that is `Clone + Send + Sync + 'static`.
///
/// Saves boilerplate — instead of writing the three methods manually,
/// just invoke this macro:
///
/// ```
/// use praxis_policy_core::impl_plugin_payload;
///
/// #[derive(Debug, Clone)]
/// struct MyPayload { value: i32 }
///
/// impl_plugin_payload!(MyPayload);
/// ```
#[macro_export]
macro_rules! impl_plugin_payload {
    ($ty:ty) => {
        impl $crate::hooks::payload::PluginPayload for $ty {
            fn clone_boxed(&self) -> Box<dyn $crate::hooks::payload::PluginPayload> {
                Box::new(self.clone())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }
        }
    };
    // `audit_serialize` opts a `Serialize` payload into content-provenance
    // hashing. `canonical_audit_bytes` sorts object keys, so the bytes are
    // stable across processes even when the payload holds a `HashMap`.
    // Without that, two identical payloads could hash differently and a
    // consumer comparing digests would read them as different content.
    ($ty:ty, audit_serialize) => {
        impl $crate::hooks::payload::PluginPayload for $ty {
            fn clone_boxed(&self) -> Box<dyn $crate::hooks::payload::PluginPayload> {
                Box::new(self.clone())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }
            fn audit_bytes(&self) -> Option<Vec<u8>> {
                $crate::hooks::payload::canonical_audit_bytes(self)
            }
        }
    };
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[derive(Debug, Clone, serde::Serialize)]
    struct Hashable {
        keys: std::collections::HashMap<String, u32>,
        name: String,
    }
    crate::impl_plugin_payload!(Hashable, audit_serialize);

    #[derive(Debug, Clone)]
    struct Plain;
    crate::impl_plugin_payload!(Plain);

    #[test]
    fn a_content_hash_is_prefixed_deterministic_and_content_dependent() {
        let h = content_hash(b"hello");

        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), "sha256:".len() + 64);
        assert_eq!(content_hash(b"hello"), h, "the same bytes hash the same");
        assert_ne!(content_hash(b"world"), h);
    }

    /// A payload that did not opt in produces no bytes, so provenance costs it
    /// nothing even when an operator turns hashing on.
    #[test]
    fn a_payload_that_did_not_opt_in_has_no_audit_bytes() {
        assert!(Plain.audit_bytes().is_none());
    }

    /// The reason `audit_serialize` round-trips through `Value`: a `HashMap`
    /// iterates in an arbitrary order, so serializing the payload directly
    /// would hash the same content differently from run to run and a consumer
    /// comparing digests would see changes that never happened.
    #[test]
    fn the_same_content_hashes_the_same_despite_map_ordering() {
        let mut a = std::collections::HashMap::new();
        a.insert("zebra".to_owned(), 1);
        a.insert("apple".to_owned(), 2);
        a.insert("mango".to_owned(), 3);
        let mut b = std::collections::HashMap::new();
        b.insert("mango".to_owned(), 3);
        b.insert("apple".to_owned(), 2);
        b.insert("zebra".to_owned(), 1);

        let first = Hashable {
            keys: a,
            name: "x".to_owned(),
        };
        let second = Hashable {
            keys: b,
            name: "x".to_owned(),
        };

        let fh = content_hash(&first.audit_bytes().expect("opted in"));
        let sh = content_hash(&second.audit_bytes().expect("opted in"));
        assert_eq!(fh, sh, "insertion order must not change the digest");
    }

    /// Sorting has to reach nested objects too. A `HashMap` one level down
    /// would otherwise reintroduce exactly the instability the top-level sort
    /// removes.
    #[test]
    fn nested_objects_are_sorted_too() {
        let a = serde_json::json!({ "outer": { "z": 1, "a": 2 } });
        let b = serde_json::json!({ "outer": { "a": 2, "z": 1 } });

        assert_eq!(
            canonical_audit_bytes(&a).unwrap(),
            canonical_audit_bytes(&b).unwrap()
        );
    }

    /// Arrays are ordered data, so their order is content and must survive
    /// canonicalization.
    #[test]
    fn array_order_is_content_and_is_preserved() {
        let a = serde_json::json!({ "items": [1, 2, 3] });
        let b = serde_json::json!({ "items": [3, 2, 1] });

        assert_ne!(
            canonical_audit_bytes(&a).unwrap(),
            canonical_audit_bytes(&b).unwrap(),
            "reordering an array changes the content"
        );
    }

    #[test]
    fn different_content_hashes_differently() {
        let one = Hashable {
            keys: std::collections::HashMap::new(),
            name: "one".to_owned(),
        };
        let two = Hashable {
            keys: std::collections::HashMap::new(),
            name: "two".to_owned(),
        };

        assert_ne!(
            content_hash(&one.audit_bytes().unwrap()),
            content_hash(&two.audit_bytes().unwrap())
        );
    }
}
